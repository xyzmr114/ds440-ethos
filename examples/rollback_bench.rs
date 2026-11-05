//! Measured snapshot / rollback benchmark for the Ethos ACI harness.
//!
//! Drives the real code path an agent session uses: `ACIHarness::snapshot()`
//! (runtime `create_snapshot` + taint-ledger export) followed by a
//! `StateTree::commit()`, and `ACIHarness::rewind()` to a node looked up in
//! the state tree. Edits are applied through the harness `write` tool (walls
//! included) but are NOT timed; only snapshot and rewind are timed.
//!
//! ```text
//! cargo run --release --example rollback_bench -- \
//!     --sizes 100,1000,10000 --turns 20 --repeats 3 --warmup 2 --rewinds 10
//! ```
//!
//! Writes `reports/rollback_bench_<YYYY-MM-DD>.json` (override with
//! `--output`). See `docs/rollback-benchmark.md` for what each field means.
use clap::Parser;
use ethos::aci::{ACIHarness, StateTree};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(about = "Measure Ethos snapshot/rollback latency and per-snapshot storage")]
struct Args {
    /// Workspace sizes (number of files), comma-separated.
    #[arg(long, value_delimiter = ',', default_value = "100,1000,10000")]
    sizes: Vec<usize>,
    /// Edit turns per run; one snapshot is taken after every turn.
    #[arg(long, default_value_t = 20)]
    turns: usize,
    /// Independent runs per size (fresh workspace, different seed each).
    #[arg(long, default_value_t = 3)]
    repeats: usize,
    /// Untimed warm-up snapshots and rewinds per run.
    #[arg(long, default_value_t = 2)]
    warmup: usize,
    /// Timed rewinds per run (targets cycle through earlier tree nodes).
    #[arg(long, default_value_t = 10)]
    rewinds: usize,
    /// Files edited per turn.
    #[arg(long, default_value_t = 3)]
    edits_per_turn: usize,
    /// Timed plain-copy baseline repetitions per run.
    #[arg(long, default_value_t = 3)]
    raw_copy_repeats: usize,
    /// Base RNG seed (run r uses seed + r).
    #[arg(long, default_value_t = 440)]
    seed: u64,
    /// Scratch directory for workspaces (default: system temp). Removed per run.
    #[arg(long)]
    workdir: Option<PathBuf>,
    /// Output JSON path.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Free-text note stored in the report (e.g. concurrent load).
    #[arg(long, default_value = "")]
    note: String,
}

/// SplitMix64: tiny deterministic PRNG so the workload is reproducible
/// without adding a dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

const MIN_FILE: f64 = 128.0;
const MAX_FILE: f64 = 32.0 * 1024.0;

/// Log-uniform file size in [128 B, 32 KiB] (mean ~5.9 KiB): many small
/// source files, a tail of larger ones.
fn file_size(rng: &mut Rng) -> usize {
    (MIN_FILE * (MAX_FILE / MIN_FILE).powf(rng.unit())) as usize
}

fn source_text(rng: &mut Rng, target: usize) -> String {
    let mut s = String::with_capacity(target + 64);
    let mut i = 0usize;
    while s.len() < target {
        s.push_str(&format!("pub fn item_{i}() -> u64 {{ {} }}\n", rng.next() % 1_000_000));
        i += 1;
    }
    s
}

fn file_path(i: usize) -> String {
    let top = if i.is_multiple_of(2) { "src" } else { "lib" };
    format!("{top}/m{:03}/f{:05}.rs", i / 100, i)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn summary(values: &[f64]) -> Value {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = if v.is_empty() { f64::NAN } else { v.iter().sum::<f64>() / v.len() as f64 };
    json!({
        "n": v.len(),
        "median": percentile(&v, 50.0),
        "p95": percentile(&v, 95.0),
        "mean": mean,
        "min": v.first().copied().unwrap_or(f64::NAN),
        "max": v.last().copied().unwrap_or(f64::NAN),
    })
}

/// (logical bytes, bytes rounded up to 4 KiB clusters, file count).
fn dir_usage(dir: &Path) -> (u64, u64, u64) {
    let (mut logical, mut alloc, mut files) = (0u64, 0u64, 0u64);
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                let (l, a, f) = dir_usage(&e.path());
                logical += l;
                alloc += a;
                files += f;
            } else if ft.is_file() {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                logical += len;
                alloc += len.div_ceil(4096) * 4096;
                files += 1;
            }
        }
    }
    (logical, alloc, files)
}

fn workspace_hashes(root: &Path, files: &[String]) -> HashMap<String, String> {
    files
        .iter()
        .map(|rel| {
            let bytes = fs::read(root.join(rel)).unwrap_or_default();
            (rel.clone(), hex::encode(Sha256::digest(&bytes)))
        })
        .collect()
}

/// Snapshot IDs are `snap_<unix millis>`; two snapshots in the same
/// millisecond collide and the second overwrites the first. Wait (untimed)
/// until the clock has moved past the previous snapshot's millisecond.
fn wait_for_fresh_millis(last: i64) {
    while chrono::Utc::now().timestamp_millis() <= last {
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

struct RunResult {
    snapshot_ms: Vec<f64>,
    snapshot_bytes: Vec<f64>,
    snapshot_alloc_bytes: Vec<f64>,
    changed_bytes: Vec<f64>,
    rewind_ms: Vec<f64>,
    rewind_distance: Vec<usize>,
    rewind_verify_failures: usize,
    raw_copy_ms: Vec<f64>,
    workspace_bytes: u64,
    workspace_files: u64,
    total_snapshot_store_bytes: u64,
}

fn run_once(size: usize, args: &Args, seed: u64, ws: &Path) -> anyhow::Result<RunResult> {
    let mut rng = Rng(seed);
    if ws.exists() {
        fs::remove_dir_all(ws)?;
    }
    fs::create_dir_all(ws)?;
    // Populate the workspace directly (untimed); this is the repo the agent opens.
    let mut paths: Vec<String> = Vec::with_capacity(size);
    for i in 0..size {
        let rel = file_path(i);
        let full = ws.join(&rel);
        fs::create_dir_all(full.parent().unwrap())?;
        let target = file_size(&mut rng);
        fs::write(&full, source_text(&mut rng, target))?;
        paths.push(rel);
    }
    fs::write(ws.join(".ethos_sandbox"), "ethos sandbox")?; // rewind invariant
    let (workspace_bytes, _, workspace_files) = dir_usage(ws);

    let mut harness = ACIHarness::new_local_with_dir(ws)?;
    let mut tree = StateTree::new();
    let snap_root = ws.join(".ethos_snapshots");
    let mut last_millis = 0i64;

    let mut take_snapshot = |harness: &mut ACIHarness, tree: &mut StateTree, label: &str| -> anyhow::Result<(String, Duration, HashMap<String, String>)> {
        wait_for_fresh_millis(last_millis);
        let t0 = Instant::now();
        let meta = harness.snapshot(label)?;
        tree.commit(&meta.snapshot_id, label)?;
        let dt = t0.elapsed();
        last_millis = meta.snapshot_id.trim_start_matches("snap_").parse().unwrap_or(last_millis);
        Ok((meta.snapshot_id, dt, meta.file_hashes))
    };

    // Warm-up: same operation, results discarded, snapshot dirs deleted.
    let mut warm_tree = StateTree::new();
    for w in 0..args.warmup {
        let (id, _, _) = take_snapshot(&mut harness, &mut warm_tree, &format!("warmup {w}"))?;
        fs::remove_dir_all(snap_root.join(&id))?;
    }

    let mut out = RunResult {
        snapshot_ms: vec![],
        snapshot_bytes: vec![],
        snapshot_alloc_bytes: vec![],
        changed_bytes: vec![],
        rewind_ms: vec![],
        rewind_distance: vec![],
        rewind_verify_failures: 0,
        raw_copy_ms: vec![],
        workspace_bytes,
        workspace_files,
        total_snapshot_store_bytes: 0,
    };
    let mut expected: Vec<HashMap<String, String>> = Vec::new();

    // Turn 0 = baseline snapshot of the untouched workspace.
    for turn in 0..=args.turns {
        let mut changed = 0usize;
        if turn > 0 {
            for _ in 0..args.edits_per_turn {
                let rel = paths[rng.below(paths.len())].clone();
                let old = fs::read_to_string(ws.join(&rel))?;
                let new_line = format!("pub fn edited_t{turn}_{}() -> u64 {{ {} }}", rng.next() % 997, rng.next() % 1_000_000);
                let mut lines: Vec<&str> = old.lines().collect();
                let at = rng.below(lines.len().max(1));
                if lines.is_empty() { lines.push(&new_line) } else { lines[at] = &new_line }
                let content = lines.join("\n") + "\n";
                changed += content.len();
                let r = harness.write(&rel, &content, None);
                anyhow::ensure!(r.status == "SUCCESS", "edit of {rel} failed: {:?}", r.error);
            }
            if turn.is_multiple_of(5) {
                // Every fifth turn the agent also adds a new file.
                let rel = format!("src/new/t{turn:03}.rs");
                let content = source_text(&mut rng, 2048);
                changed += content.len();
                let r = harness.write(&rel, &content, None);
                anyhow::ensure!(r.status == "SUCCESS", "create of {rel} failed: {:?}", r.error);
                paths.push(rel);
            }
        }
        let (id, dt, hashes) = take_snapshot(&mut harness, &mut tree, &format!("turn {turn}"))?;
        let (logical, alloc, _) = dir_usage(&snap_root.join(&id));
        out.snapshot_ms.push(ms(dt));
        out.snapshot_bytes.push(logical as f64);
        out.snapshot_alloc_bytes.push(alloc as f64);
        out.changed_bytes.push(changed as f64);
        expected.push(hashes);
    }
    out.total_snapshot_store_bytes = dir_usage(&snap_root).0;

    let history = tree.get_branch_history("main");
    anyhow::ensure!(history.len() == args.turns + 1, "state tree has {} nodes, expected {}", history.len(), args.turns + 1);

    // Untimed warm-up rewinds to the head node.
    let head = history.last().unwrap().snapshot_id.clone();
    for _ in 0..args.warmup {
        harness.rewind(&head)?;
    }
    // Timed rewinds. Targets cycle: baseline, midpoint, previous turn, random.
    let mut current = args.turns;
    for k in 0..args.rewinds {
        let target = match k % 4 {
            0 => 0,
            1 => args.turns / 2,
            2 => args.turns.saturating_sub(1),
            _ => rng.below(args.turns + 1),
        };
        let node = &history[target];
        let t0 = Instant::now();
        harness.rewind(&node.snapshot_id)?;
        let dt = t0.elapsed();
        out.rewind_ms.push(ms(dt));
        out.rewind_distance.push(current.abs_diff(target));
        current = target;
        // Correctness check (untimed): restored tree must match the snapshot.
        let mut files = vec![];
        collect(ws, ws, &mut files);
        let got = workspace_hashes(ws, &files);
        if got != expected[target] {
            out.rewind_verify_failures += 1;
        }
    }
    // Baseline: plain recursive fs::copy of the same file set, no path
    // validation, hashing or harness bookkeeping (lower bound for any
    // full-copy snapshot on this disk). One untimed warm-up, then timed.
    let mut files = vec![];
    collect(ws, ws, &mut files);
    let copy_root = ws.with_extension("rawcopy");
    for k in 0..(1 + args.raw_copy_repeats) {
        let _ = fs::remove_dir_all(&copy_root);
        let t0 = Instant::now();
        for rel in &files {
            let dest = copy_root.join(rel);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::copy(ws.join(rel), dest)?;
        }
        let dt = t0.elapsed();
        if k > 0 {
            out.raw_copy_ms.push(ms(dt));
        }
    }
    let _ = fs::remove_dir_all(&copy_root);
    drop(harness);
    fs::remove_dir_all(ws)?;
    Ok(out)
}

/// Same file set `LocalIsolatedRuntime::list_files` snapshots: everything
/// except the snapshot store and provenance sidecars (markers included).
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if name == ".ethos_snapshots" || name == ".ethos_provenance.json" || name.starts_with(".ethos-provenance-") {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            collect(root, &p, out);
        } else if ft.is_file() {
            out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
        }
    }
}

fn cmd_out(program: &str, args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let mut c = Command::new(program);
    c.args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let o = c.output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn machine_info(workdir: &Path) -> Value {
    let mut info = json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "processor_identifier": std::env::var("PROCESSOR_IDENTIFIER").ok(),
        "rustc": cmd_out("rustc", &["--version"], None),
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "workdir": workdir.display().to_string(),
    });
    if cfg!(windows) {
        let ps = "$c=Get-CimInstance Win32_Processor|Select-Object -First 1;\
                  $m=Get-CimInstance Win32_ComputerSystem;\
                  $o=Get-CimInstance Win32_OperatingSystem;\
                  $d=try{(Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled}catch{$null};\
                  @{cpu=$c.Name;ram_bytes=[int64]$m.TotalPhysicalMemory;os_caption=$o.Caption;os_build=$o.BuildNumber;defender_realtime=$d}|ConvertTo-Json -Compress";
        if let Some(s) = cmd_out("powershell", &["-NoProfile", "-NonInteractive", "-Command", ps], None) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                info["windows"] = v;
            }
        }
    }
    info
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workdir = args
        .workdir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(format!("ethos_rollback_bench_{}", std::process::id())));
    fs::create_dir_all(&workdir)?;
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| repo.join("reports").join(format!("rollback_bench_{date}.json")));

    let mut per_size = Vec::new();
    for &size in &args.sizes {
        let mut runs = Vec::new();
        for r in 0..args.repeats {
            let ws = workdir.join(format!("ws_{size}_{r}"));
            let started = Instant::now();
            let res = run_once(size, &args, args.seed + r as u64, &ws)?;
            eprintln!(
                "[size {size:>6} run {r}] snapshot median {:.1} ms, rewind median {:.1} ms, {:.1} MB/snapshot ({:.1}s)",
                percentile(&sorted(&res.snapshot_ms), 50.0),
                percentile(&sorted(&res.rewind_ms), 50.0),
                percentile(&sorted(&res.snapshot_bytes), 50.0) / 1e6,
                started.elapsed().as_secs_f64()
            );
            runs.push(res);
        }
        let all = |f: fn(&RunResult) -> &Vec<f64>| runs.iter().flat_map(|r| f(r).iter().copied()).collect::<Vec<f64>>();
        let edit_turns = |f: fn(&RunResult) -> &Vec<f64>| runs.iter().flat_map(|r| f(r).iter().skip(1).copied()).collect::<Vec<f64>>();
        // Per-turn median across runs (turn 0 = baseline), for plotting.
        let per_turn_median: Vec<f64> = (0..=args.turns)
            .map(|t| percentile(&sorted(&runs.iter().map(|r| r.snapshot_ms[t]).collect::<Vec<_>>()), 50.0))
            .collect();
        let per_turn_bytes: Vec<f64> = (0..=args.turns)
            .map(|t| percentile(&sorted(&runs.iter().map(|r| r.snapshot_bytes[t]).collect::<Vec<_>>()), 50.0))
            .collect();
        per_size.push(json!({
            "files": size,
            "workspace_bytes_median": percentile(&sorted(&runs.iter().map(|r| r.workspace_bytes as f64).collect::<Vec<_>>()), 50.0),
            "workspace_files_on_disk": runs.iter().map(|r| r.workspace_files).collect::<Vec<_>>(),
            "snapshot_latency_ms": summary(&all(|r| &r.snapshot_ms)),
            "snapshot_latency_ms_edit_turns_only": summary(&edit_turns(|r| &r.snapshot_ms)),
            "rollback_latency_ms": summary(&all(|r| &r.rewind_ms)),
            "rollback_distance_turns": runs.iter().flat_map(|r| r.rewind_distance.clone()).collect::<Vec<_>>(),
            "rollback_verify_failures": runs.iter().map(|r| r.rewind_verify_failures).sum::<usize>(),
            "raw_copy_baseline_ms": summary(&all(|r| &r.raw_copy_ms)),
            "bytes_added_per_snapshot": summary(&all(|r| &r.snapshot_bytes)),
            "bytes_added_per_snapshot_alloc_4k": summary(&all(|r| &r.snapshot_alloc_bytes)),
            "bytes_changed_by_agent_per_turn": summary(&edit_turns(|r| &r.changed_bytes)),
            "snapshot_store_bytes_after_run": runs.iter().map(|r| r.total_snapshot_store_bytes).collect::<Vec<_>>(),
            "per_turn_snapshot_ms_median": per_turn_median,
            "per_turn_snapshot_bytes_median": per_turn_bytes,
            "raw": runs.iter().map(|r| json!({
                "snapshot_ms": r.snapshot_ms,
                "snapshot_bytes": r.snapshot_bytes,
                "changed_bytes": r.changed_bytes,
                "rewind_ms": r.rewind_ms,
                "rewind_distance": r.rewind_distance,
            })).collect::<Vec<_>>(),
        }));
    }
    let _ = fs::remove_dir_all(&workdir);

    let dirty = cmd_out("git", &["status", "--porcelain", "--untracked-files=no"], Some(repo)).map(|s| !s.is_empty());
    let report = json!({
        "benchmark": "ethos_rollback_bench",
        "schema_version": 1,
        "generated_at": chrono::Local::now().to_rfc3339(),
        "git_rev": cmd_out("git", &["rev-parse", "HEAD"], Some(repo)),
        "git_branch": cmd_out("git", &["rev-parse", "--abbrev-ref", "HEAD"], Some(repo)),
        "git_dirty": dirty,
        "machine": machine_info(&workdir),
        "note": args.note,
        "config": {
            "sizes": args.sizes, "turns": args.turns, "repeats": args.repeats,
            "warmup": args.warmup, "rewinds": args.rewinds,
            "edits_per_turn": args.edits_per_turn, "new_file_every_n_turns": 5,
            "raw_copy_repeats": args.raw_copy_repeats, "seed": args.seed, "file_size_distribution": "log-uniform 128 B..32 KiB",
        },
        "measured": {
            "snapshot": "wall-clock of ACIHarness::snapshot() + StateTree::commit() after each turn (turn 0 = baseline). Includes runtime create_snapshot (hard-link validation walk, list, SHA-256, full file copy) and taint-ledger export.",
            "rollback": "wall-clock of ACIHarness::rewind(node.snapshot_id) for a node taken from StateTree history: delete workspace, copy snapshot back, restore + persist taint ledger.",
            "bytes_added_per_snapshot": "sum of file lengths written under .ethos_snapshots/<id>; _alloc_4k rounds each file up to a 4 KiB cluster.",
            "bytes_changed_by_agent_per_turn": "bytes of the files the agent rewrote/created that turn (what a delta store would need at most).",
            "raw_copy_baseline": "wall-clock of a plain recursive std::fs::copy of the same files to a sibling directory (no validation, hashing or taint export) - a lower bound for any full-copy snapshot on the same disk.",
            "excluded": "workspace population, edits, the untimed wait that keeps snapshot IDs (unix millis) unique, and post-rewind hash verification.",
        },
        "results": per_size,
    });
    if let Some(p) = output.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(&output, serde_json::to_string_pretty(&report)? + "\n")?;
    eprintln!("wrote {}", output.display());
    Ok(())
}

fn sorted(v: &[f64]) -> Vec<f64> {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}
