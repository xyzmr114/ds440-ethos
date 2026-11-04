use crate::aci::agent_loop::{
    AgentLoop,
};
use crate::aci::ACIHarness;
use crate::api::routes::{create_router, AppState};
use crate::store::SessionManager;
use crate::walls::promptinject::PromptInjectScanner;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod eval_cmd;
pub mod scanner_eval;
pub mod interactive;

#[derive(Parser)]
#[command(name = "ethos", author = "Group 2 Nittany Street", version)]
#[command(about = "Ethos (tbox): Autonomous AI Coding Agent Harness & Taint-Tracked Sandbox Runtime", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Launch the interactive AI coding agent harness session (default)
    Interactive {
        /// Optional sandbox workspace directory
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },
    /// Run the interactive API & provider setup wizard
    Setup,
    /// Launch the Ethos Desktop Application (starts daemon and opens browser)
    App {
        #[arg(short, long, default_value = "8000")]
        port: u16,
    },
    /// Start the Ethos API Daemon (Axum REST server)
    Daemon {
        #[arg(short, long, default_value = "8000")]
        port: u16,
    },
    /// Run an autonomous agent task in a live Ethos sandbox harness
    Run {
        /// The task prompt or goal for the agent
        task: String,
        /// Maximum execution steps allowed
        #[arg(short = 's', long, default_value = "15")]
        max_steps: usize,
        /// Sandbox workspace directory (defaults to isolated tempdir)
        #[arg(short, long)]
        dir: Option<PathBuf>,
        /// Live LLM endpoint URL (e.g. http://localhost:11434/v1 for Ollama)
        #[arg(long, default_value = "http://localhost:11434/v1")]
        api_url: String,
        /// Model name (e.g. qwen2.5-coder, deepseek-coder)
        #[arg(short, long, default_value = "qwen2.5-coder")]
        model: String,
    },
    /// Run the Ethos injection-defense evaluation suite (v2).
    Eval {
        /// Dataset: injecagent | hackaprompt | agenthijack | m365 | evasion |
        /// benign | capability | injected | fetch | tool_output |
        /// injecagent-upstream | attacks | all
        #[arg(short, long, default_value = "all")]
        dataset: String,
        /// Load scenarios from an explicit JSON file instead of a named dataset.
        #[arg(long)]
        dataset_file: Option<String>,
        /// Inference provider: lmstudio | ollama | openai | openrouter | anthropic | scripted
        #[arg(short, long, default_value = "lmstudio")]
        provider: String,
        /// Model identifier (e.g. deepseek-r1, claude-opus-5-5, qwen2.5-coder)
        #[arg(short, long, default_value = "deepseek-r1")]
        model: String,
        /// Override the provider endpoint URL (OpenAI-compatible base, or LM Studio/Ollama host).
        #[arg(long)]
        endpoint: Option<String>,
        /// Enforcement condition: full | rewind | structured | raw-shell
        #[arg(long, default_value = "full")]
        condition: String,
        /// Sandbox runtime: local | gvisor (gvisor fails if runsc is absent)
        #[arg(long, default_value = "local")]
        runtime: String,
        /// Task framing: benign | complicit | both
        #[arg(long, default_value = "benign")]
        variant: String,
        /// 70/20/10 partition: train | eval | test | all
        #[arg(long, default_value = "all")]
        split: String,
        /// Per-run step budget.
        #[arg(long, default_value = "10")]
        max_steps: usize,
        /// Repeat each scenario this many times (for confidence intervals).
        #[arg(long, default_value = "1")]
        repeats: usize,
        /// Run a stratified sample of N scenarios (proportional by source).
        #[arg(long)]
        sample: Option<usize>,
        /// Seed for --sample (same seed, same cases).
        #[arg(long, default_value = "440")]
        seed: u64,
        /// Optional path to export the JSON report.
        #[arg(short, long)]
        output: Option<String>,
        /// Re-score an existing v2 report from its `<report>.traces.jsonl`
        /// with the current oracle, without running a model. Writes
        /// `<report>.rescored.json` (or --output). Scenarios are looked up
        /// by id in --dataset-file / --dataset (`all` = every known file).
        #[arg(long, value_name = "REPORT")]
        rescore: Option<String>,
    },
    /// Run harness and environment diagnostics (Postgres, Git, MinGit, Walls, Sandbox)
    Doctor,
    /// Launch the interactive terminal UI (Ratatui Cyber Dark Dashboard)
    Tui,
    /// Scan a directory for prompt-injection content and write a SARIF 2.1.0 report
    Scan {
        /// Directory to scan
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// SARIF output path
        #[arg(short, long, default_value = "ethos.sarif")]
        output: PathBuf,
        /// Path (relative to DIR) to skip; repeatable
        #[arg(short, long)]
        exclude: Vec<PathBuf>,
        /// Exit non-zero at/above this severity: none, low, medium, high
        #[arg(long, default_value = "none")]
        fail_on: String,
    },
    /// Score the PromptInjectScanner (and optionally SemanticGuard) on a labelled JSONL corpus
    ScannerEval {
        /// Corpus path (defaults to data/semantic_guard/test.jsonl)
        #[arg(short, long)]
        data: Option<String>,
        /// Also score the advisory SemanticGuard tier
        #[arg(long)]
        semantic: bool,
        /// SemanticGuard risk threshold for a positive (0.0–1.0)
        #[arg(long, default_value = "0.7")]
        threshold: f32,
        /// Optional JSON report path
        #[arg(short, long)]
        output: Option<String>,
    },
}

pub async fn run_cli() -> anyhow::Result<()> {
    crate::config::models_dev::ModelCatalog::trigger_background_update_if_needed();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Interactive { dir: None }) {
        Commands::Interactive { dir } => run_interactive(dir).await,
        Commands::Setup => {
            let _ = crate::config::user_config::run_setup_wizard()?;
            Ok(())
        }
        Commands::App { port } => run_app(port).await,
        Commands::Daemon { port } => run_daemon(port).await,
        Commands::Run {
            task,
            max_steps,
            dir,
            api_url,
            model,
        } => run_harness_task(&task, max_steps, dir, &api_url, &model).await,
        Commands::Eval {
            dataset,
            dataset_file,
            provider,
            model,
            endpoint,
            condition,
            runtime,
            variant,
            split,
            max_steps,
            repeats,
            sample,
            seed,
            output,
            rescore,
        } => {
            if let Some(report) = rescore {
                return eval_cmd::rescore_report(&report, &dataset, dataset_file, output);
            }
            eval_cmd::run_eval(
                &dataset, dataset_file, &provider, &model, endpoint, &condition, &runtime,
                &variant, &split, max_steps, repeats, sample, seed, output,
            )
            .await
        }
        Commands::Doctor => run_doctor().await,
        Commands::Tui => run_tui_command().await,
        Commands::Scan {
            dir,
            output,
            exclude,
            fail_on,
        } => run_scan(&dir, &output, &exclude, &fail_on),
        Commands::ScannerEval {
            data,
            semantic,
            threshold,
            output,
        } => scanner_eval::run_scanner_eval(data, semantic, threshold, output),
    }
}

fn run_scan(
    dir: &std::path::Path,
    output: &std::path::Path,
    exclude: &[PathBuf],
    fail_on: &str,
) -> anyhow::Result<()> {
    use crate::walls::promptinject::Severity;
    use crate::walls::sarif;

    let threshold = match fail_on.to_ascii_lowercase().as_str() {
        "none" => None,
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        other => anyhow::bail!("--fail-on must be none, low, medium or high (got '{}')", other),
    };

    let scanner = PromptInjectScanner::new();
    let hits = sarif::scan_directory(&scanner, dir, exclude)?;
    let log = sarif::to_sarif(&scanner, &hits);
    std::fs::write(output, serde_json::to_string_pretty(&log)?)?;

    let count = |s: Severity| hits.iter().filter(|h| h.finding.severity == s).count();
    println!(
        "[ethos scan] {} finding(s) (high: {}, medium: {}, low: {}) -> {}",
        hits.len(),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        output.display()
    );
    // Location + rule only; never the matched text (RT-13).
    for h in &hits {
        println!("  {}:{}  {} [{}]", h.path, h.line, h.finding.pattern_name, h.finding.category);
    }

    if let Some(t) = threshold {
        if hits.iter().any(|h| h.finding.severity >= t) {
            anyhow::bail!("findings at or above '{}' severity", fail_on);
        }
    }
    Ok(())
}

async fn run_interactive(dir: Option<PathBuf>) -> anyhow::Result<()> {
    crate::tui::run_zen_tui(dir).await
}

async fn run_tui_command() -> anyhow::Result<()> {
    let app = crate::tui::TuiApp::default();
    crate::tui::run_tui(app)
}

pub fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

async fn run_app(port: u16) -> anyhow::Result<()> {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state);
    // RT-19: loopback-only bind. The daemon has no authentication layer and
    // exposes provider keys + host exec; it must not accept LAN traffic.
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let browser_url = format!("http://localhost:{}", port);

    println!("============================================================");
    println!("  ETHOS v{} - Cyber Dark Sandbox & ACI Harness", env!("CARGO_PKG_VERSION"));
    println!("  Listening on: http://{}", addr);
    println!("  Opening browser dashboard: {}", browser_url);
    println!("  Press Ctrl+C to stop the harness server.");
    println!("============================================================");

    open_browser(&browser_url);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_daemon(port: u16) -> anyhow::Result<()> {
    let state = AppState::new(SessionManager::new());
    let app = create_router(state);
    // RT-19: loopback-only bind (see run_app).
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    println!("============================================================");
    println!("  ETHOS DAEMON (Rust) - Listening on http://{}", addr);
    println!("  Endpoints: /health, /v1/sandboxes, /v1/schemas/tools");
    println!("============================================================");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_doctor() -> anyhow::Result<()> {
    println!("============================================================");
    println!("  ETHOS HARNESS DIAGNOSTIC DOCTOR");
    println!("============================================================");

    // 1. Check sandbox creation
    print!("[-] Workspace and configured command execution: ");
    match ACIHarness::new_with_temp_dir() {
        Ok(h) => println!("OK (root initialized; command backend: {})", h.runtime.execution_backend()),
        Err(e) => println!("FAIL ({})", e),
    }

    // 2. Check gVisor application-kernel syscall sandbox
    print!("[-] gVisor (runsc) Syscall Isolation: ");
    let gv = crate::runtime::gvisor::GVisorRuntime::new(std::env::temp_dir());
    match gv {
        Ok(g) if g.is_gvisor_available() => println!("AVAILABLE ({:?})", g.runsc_path().unwrap()),
        _ => println!("UNAVAILABLE (no host fallback; configured command backend is independent)"),
    }

    // 3. Check walls subsystem
    print!("[-] Containment Walls (PromptInject, Ouroboros, E-Stop): ");
    let scanner = PromptInjectScanner::new();
    let findings = scanner.scan("ignore previous instructions");
    if !findings.is_empty() {
        println!("OK (active & calibrated)");
    } else {
        println!("WARNING (scanner returned empty)");
    }

    // 4. Check PostgreSQL configuration
    print!("[-] PostgreSQL Store: ");
    if let Ok(db_url) = std::env::var("DATABASE_URL") {
        println!("CONFIGURED ({})", db_url);
    } else {
        println!("NOT CONFIGURED (Using in-memory session manager, set DATABASE_URL to enable)");
    }

    // 5. Check LLM local connectivity
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()?;
    print!("[-] Local LLM (LM Studio): ");
    let mut lm_online = false;
    for port in [2277, 1234] {
        if let Ok(resp) = client.get(format!("http://localhost:{}/v1/models", port)).send().await {
            if resp.status().is_success() {
                println!("ONLINE @ http://localhost:{} (OpenAI API Ready)", port);
                lm_online = true;
                break;
            }
        }
    }
    if !lm_online {
        println!("OFFLINE (Launch LM Studio and start local server)");
    }

    print!("[-] Local LLM (Ollama @ http://localhost:11434): ");
    match client.get("http://localhost:11434/api/tags").send().await {
        Ok(resp) if resp.status().is_success() => println!("ONLINE"),
        _ => println!("OFFLINE (Start Ollama or configure remote API)"),
    }

    println!("============================================================");
    println!("All core subsystems operational.");
    Ok(())
}

async fn run_harness_task(
    task: &str,
    max_steps: usize,
    dir: Option<PathBuf>,
    api_url: &str,
    model: &str,
) -> anyhow::Result<()> {
    println!("============================================================");
    println!("  ETHOS ACI HARNESS");
    println!("  Task: {}", task);
    println!("  Max Steps: {}", max_steps);
    println!("  LLM Backend: {} (model: {})", api_url, model);
    println!("  Containment Walls: [PromptInject, Ouroboros, TaintLedger]");
    println!("============================================================\n");

    let mut harness = match dir {
        Some(d) => ACIHarness::new_with_dir(d)?,
        None => ACIHarness::new_with_temp_dir()?,
    };

    let key = if api_url.contains("api.anthropic.com") {
        std::env::var("ANTHROPIC_API_KEY").ok()
    } else {
        std::env::var("OPENAI_API_KEY")
            .ok()
            .or_else(|| std::env::var("OPENROUTER_API_KEY").ok())
    };
    let driver = crate::aci::drivers::driver_for("auto", api_url, key, model)?;

    let mut agent_loop = AgentLoop::new(max_steps);
    let outcome = agent_loop.run(&mut harness, driver.as_ref(), task).await?;

    println!("\n------------------------------------------------------------");
    println!("Execution Finished");
    println!("Stop Reason: {:?}", outcome.stop_reason);
    println!("Total Steps: {}", outcome.total_steps);
    println!("Taint Violations Intercepted: {}", outcome.taint_violations);
    println!("Final Summary:\n{}", outcome.final_summary);
    println!("------------------------------------------------------------");

    Ok(())
}

