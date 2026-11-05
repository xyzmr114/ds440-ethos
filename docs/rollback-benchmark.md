# Rollback benchmark (snapshot / rewind cost)

Paper 1 drafts claimed "sub-50 ms" copy-on-write snapshot/rollback (18–35 ms
per turn) and < 1 MB of storage per turn. Those numbers came from
`18.5 + steps*1.8 + noise` in the figure script, not from a measurement. This
benchmark measures the real code path. **The measured numbers do not support
either claim.** See [Results](#results-2026-11-04).

## Command

```powershell
cargo run --release --example rollback_bench -- `
  --sizes 100,1000,10000 --turns 20 --repeats 3 --warmup 2 --rewinds 10 `
  --note "what else was running"
```

This writes `reports/rollback_bench_<YYYY-MM-DD>.json` (change the path with
`--output`). Workspaces go in the system temp dir (`--workdir` overrides it)
and are deleted after each run. The 10,000-file runs need about 1.3 GB of free
disk for each run, and the full sweep takes about 30 min on the machine below.
For a quick smoke test, use `--sizes 50 --turns 3 --repeats 1 --rewinds 2`.

To build Fig. 3 from the report, so that nothing in it is synthesised:

```powershell
python scripts/plot_rollback_bench.py reports/rollback_bench_2026-11-04.json --out paper/figures/fig3_rollback_latency.png
```

## What is measured

Each run, for each workspace size:

1. **Populate (untimed).** The benchmark writes N files directly under
   `src/` and `lib/`, about 100 per directory. File sizes are log-uniform
   between 128 B and 32 KiB (mean about 5.9 KiB), so the workspace looks like
   a source repo. The seed is deterministic (`--seed`, then `+r` for each
   repeat). Then the `.ethos_sandbox` marker is written, because rewind
   requires it.
2. **Warm-up (untimed).** `--warmup` snapshots are taken and discarded, and
   their directories are deleted.
3. **Turns.** Turn 0 is the baseline snapshot. Each of turns 1..T rewrites
   `--edits-per-turn` (3) random files through the harness `write` tool, with
   all walls active. Every fifth turn also creates a new 2 KiB file. After the
   edits, the timed operation is **`ACIHarness::snapshot()` followed by
   `StateTree::commit()`**. That covers the runtime's `create_snapshot`
   (validation walk, file listing, SHA-256 of every file, full copy into
   `.ethos_snapshots/<id>`) and the taint-ledger export.
4. **Bytes per snapshot.** This is the total size of the files under
   `.ethos_snapshots/<id>`. A second figure, `_alloc_4k`, rounds each file up
   to a 4 KiB cluster. It is reported next to `bytes_changed_by_agent_per_turn`,
   which is the most that a delta or copy-on-write store would need to keep.
5. **Rollback.** First come `--warmup` untimed rewinds to the head. Then
   `--rewinds` timed **`ACIHarness::rewind(id)`** calls run, each to a node
   taken from `StateTree` history. The targets cycle through the baseline, the
   midpoint, the previous turn and a random node. A rewind deletes the
   workspace, copies the snapshot back, and restores and persists the taint
   ledger. After each rewind, an untimed check hashes the workspace and
   compares it with the snapshot's recorded hashes.
6. **Plain-copy baseline.** This times a recursive `std::fs::copy` of the
   same files with no validation, hashing or bookkeeping. One warm-up copy
   comes first, then `--raw-copy-repeats` timed copies. It is a lower bound for
   any full-copy snapshot on the same disk.

Latency is wall-clock time from `std::time::Instant`. The report gives the
median and nearest-rank p95 over all runs, plus the raw per-turn values. It
also records the git rev, the dirty flag, the build profile, and the
CPU/RAM/OS of the machine.

Snapshot IDs are `snap_<unix millis>`. Two snapshots in the same millisecond
get the same ID, and the second overwrites the first. The benchmark waits
(untimed) until the clock moves past the previous ID's millisecond. Real
callers have no such guard (see [Findings](#findings)).

## Results (2026-11-04)

Source: `reports/rollback_bench_2026-11-04.json`, git `3a7b05b`, release
build. Machine: AMD Ryzen 5 7500X3D (6 logical CPUs visible to the
process), 47 GiB RAM, Windows 10 Pro 19045, temp dir on a WD Green SN350 NVMe
(C:, 98% full). **Three live LM Studio eval processes were running at the same
time**, so treat the absolute values as indicative.
Re-run on an idle machine before quoting absolute values in the paper.

Settings: 20 edit turns, 3 repeats, 2 warm-ups, 10 rewinds per run. That gives
n = 63 snapshots and n = 30 rollbacks per size. Every rollback restored the
exact snapshot: 0/90 hash mismatches.

| Files | Workspace | Snapshot median / p95 | Rollback median / p95 | Plain `fs::copy` median / p95 | Stored per snapshot (median) | Changed by agent per turn (median) |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0.57 MB | **127 / 186 ms** | **111 / 170 ms** | 49 / 73 ms | 0.58 MB (0.86 MB at 4 KiB clusters) | 18 KB |
| 1,000 | 5.95 MB | **1,393 / 1,943 ms** | **1,160 / 1,971 ms** | 562 / 626 ms | 5.95 MB (8.6 MB) | 21 KB |
| 10,000 | 59.0 MB | **12,157 / 15,076 ms** | **11,010 / 16,257 ms** | 5,281 / 7,695 ms | 59.0 MB (85.7 MB) | 15 KB |

After 21 snapshots, the snapshot store held about 12 MB, 125 MB and 1.24 GB
for the three sizes.

### Against the paper's claims

- **Sub-50 ms snapshot/rollback: not met at any size tested.** Both
  operations scale linearly with the number of files, at about 1.1–1.4 ms per
  file on this machine. At that rate, only workspaces of about 40 files or
  fewer would come in under 50 ms. The smoke run with 50 files measured 52–55
  ms.
- **< 1 MB per turn: met only when the whole workspace is under 1 MB.** Every
  snapshot stores a full copy of the workspace, about 1× the workspace size,
  even though the agent changed only 15–21 KB per turn. That is roughly
  30× to 4,000× more than a delta store would keep.
- **"Copy-on-write delta tree": not what the code does.**
  `LocalIsolatedRuntime::create_snapshot` (`src/runtime/base.rs`) copies
  every file. `restore_snapshot` deletes the workspace and copies everything
  back. `CommandRuntime` delegates to it. `StateTree`
  (`src/aci/state_tree.rs`) is an in-memory DAG of snapshot IDs. Nothing in
  the runtime or harness uses it. It is re-exported, and this benchmark is
  its only caller apart from its unit tests.

## Findings

- **Ethos validation overhead.** Ethos's snapshot takes about 2.3–2.6× as
  long as a plain copy of the same files. This was not profiled. The likely
  causes, from reading the code: on Windows, every file is opened four times
  for hard-link identity checks (in `validate_snapshot_files`, in the
  `list_files` walk, and twice in `resolve_path`, which checks every path
  component and then the final path), there are repeated `canonicalize` calls, and every file gets a
  SHA-256. The plain-copy baseline itself is
  already about 0.5 ms per file. Windows file-creation cost, plus any
  antivirus scanning of new files, sets a floor that no full-copy design can
  get under.
- **Snapshot ID collisions.** IDs come from wall-clock milliseconds. Two
  `snapshot()` calls in the same millisecond would silently overwrite one
  snapshot directory, which can happen for tiny workspaces or on fast disks.
- **Meeting the paper's targets** would need real incremental snapshots:
  content-addressed blobs keyed by the hashes that are already computed,
  hard-linking or reflinking unchanged files, or a filesystem with native
  snapshots. Rewind would also have to touch only the files that differ.
