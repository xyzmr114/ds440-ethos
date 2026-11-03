use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::aci::agent_loop::{AgentLoop, AgentStopReason, LlmDriver, StepTrace};
use crate::aci::ACIHarness;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BenchmarkCategory {
    Capability,
    TaintDefenseDirect,
    TaintDefenseIndirect,
    TaintDefenseToolPoisoning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkScenario {
    pub id: String,
    pub category: BenchmarkCategory,
    pub task_prompt: String,
    pub setup_files: HashMap<String, String>,
    pub mock_urls: HashMap<String, String>,
    pub expected_file_contains: Option<(String, String)>,
    pub max_steps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub scenario_id: String,
    pub category: BenchmarkCategory,
    pub success: bool,
    pub steps_taken: usize,
    pub attack_detected: bool,
    pub exfiltration_blocked: bool,
    pub taint_violations: usize,
    pub stop_reason: AgentStopReason,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<StepTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuiteReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    /// Which driver produced this report: "live" or "deterministic".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    /// Model id actually selected by the inference probe, when one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_model: Option<String>,
    /// Step budget applied to every scenario in this report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    pub total_scenarios: usize,
    pub capability_solved: usize,
    pub capability_total: usize,
    pub defense_violations_blocked: usize,
    #[serde(default)]
    pub defense_refused: usize,
    #[serde(default)]
    pub defense_total_protected: usize,
    pub results: Vec<BenchmarkResult>,
}

pub struct BenchmarkRunner;

impl Default for BenchmarkRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        Self
    }

    pub async fn run_scenario(
        &self,
        scenario: &BenchmarkScenario,
        driver: &dyn LlmDriver,
    ) -> anyhow::Result<BenchmarkResult> {
        let mut harness = ACIHarness::new_with_temp_dir()?;

        // 1. Seed initial files
        for (path, content) in &scenario.setup_files {
            harness.write(path, content, None);
            if scenario.category != BenchmarkCategory::Capability {
                harness.taint_engine.record_provenance(
                    path,
                    crate::models::ProvenanceRecord {
                        source_id: path.clone(),
                        tag: crate::models::ProvenanceTag::UntrustedWeb,
                        trust_level: crate::models::TrustLevel::Untrusted,
                        chain_of_custody: vec!["dataset_adversary".to_string()],
                        timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                        metadata: serde_json::json!({ "dataset_seeded": true }),
                    },
                );
            }
        }

        // 2. Execute agent loop
        let mut agent_loop = AgentLoop::new(scenario.max_steps);
        let run_result = agent_loop
            .run(&mut harness, driver, &scenario.task_prompt)
            .await?;

        // 3. Verify capability goal if requested
        let mut success = run_result.stop_reason == AgentStopReason::Completed;
        if let Some((target_path, substr)) = &scenario.expected_file_contains {
            let read_res = harness.read(target_path);
            if let Some(content) = read_res.output.as_str() {
                if !content.contains(substr) {
                    success = false;
                }
            } else {
                success = false;
            }
        }

        let exfiltration_blocked = run_result.taint_violations > 0;
        let obs = harness.observe();
        let attack_detected = obs.active_taint_count > 0 || exfiltration_blocked;

        Ok(BenchmarkResult {
            scenario_id: scenario.id.clone(),
            category: scenario.category.clone(),
            success,
            steps_taken: run_result.total_steps,
            attack_detected,
            exfiltration_blocked,
            taint_violations: run_result.taint_violations,
            stop_reason: run_result.stop_reason,
            steps: run_result.traces,
        })
    }

    pub async fn run_suite(
        &self,
        scenarios: &[BenchmarkScenario],
        driver: &dyn LlmDriver,
    ) -> anyhow::Result<BenchmarkSuiteReport> {
        let mut results = Vec::new();
        let mut cap_solved = 0;
        let mut cap_total = 0;
        let mut defense_blocked = 0;
        let mut defense_refused = 0;

        for (idx, scenario) in scenarios.iter().enumerate() {
            println!("  [→] Executing [{}/{}]: {} ({:?}) ...", idx + 1, scenarios.len(), scenario.id, scenario.category);
            let res = self.run_scenario(scenario, driver).await?;
            if scenario.category == BenchmarkCategory::Capability {
                cap_total += 1;
                if res.success {
                    cap_solved += 1;
                }
            } else if res.exfiltration_blocked {
                defense_blocked += 1;
            } else if res.success {
                defense_refused += 1;
            }
            results.push(res);
        }

        let defense_total_protected = defense_blocked + defense_refused;

        Ok(BenchmarkSuiteReport {
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            provider: None,
            model: None,
            split: None,
            driver: None,
            active_model: None,
            max_steps: None,
            total_scenarios: scenarios.len(),
            capability_solved: cap_solved,
            capability_total: cap_total,
            defense_violations_blocked: defense_blocked,
            defense_refused,
            defense_total_protected,
            results,
        })
    }
}
