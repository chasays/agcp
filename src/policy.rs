use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proto::{ActionEnvelope, DecisionType};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    pub max_tool_calls_per_run: u32,
    pub max_write_actions_per_run: u32,
    pub max_spawn_depth: u8,
    pub approval_ttl_sec: u64,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_sec: u64,
    pub tools: Vec<ToolPolicy>,
}

fn default_token_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolPolicy {
    pub name: String,
    pub risk: RiskLevel,
    pub write: bool,
    #[serde(default)]
    pub requires_evidence: bool,
    #[serde(default)]
    pub escalate_arg: Option<String>,
    #[serde(default)]
    pub escalate_equals: Option<String>,
    #[serde(default)]
    pub constraints: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct RunUsage {
    tool_calls: u32,
    write_actions: u32,
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    pub decision: DecisionType,
    pub reason_code: String,
    pub is_write: bool,
    pub token_ttl_sec: u64,
    pub approval_ttl_sec: u64,
    pub constraints: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),
}

pub struct PolicyEngine {
    config: PolicyConfig,
    usage_by_run: Mutex<HashMap<String, RunUsage>>,
}

impl PolicyEngine {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let content = fs::read_to_string(path)?;
        let config: PolicyConfig = toml::from_str(&content)?;
        Ok(Self::from_config(config))
    }

    pub fn from_config(config: PolicyConfig) -> Self {
        Self {
            config,
            usage_by_run: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_write_tool(&self, tool: &str) -> bool {
        self.config
            .tools
            .iter()
            .find(|tp| tp.name == tool)
            .map(|tp| tp.write)
            .unwrap_or(false)
    }

    pub fn evaluate_submit(&self, envelope: &ActionEnvelope) -> PolicyEvaluation {
        self.evaluate(envelope, false)
    }

    pub fn evaluate_approval(&self, envelope: &ActionEnvelope) -> PolicyEvaluation {
        self.evaluate(envelope, true)
    }

    fn evaluate(&self, envelope: &ActionEnvelope, bypass_escalation: bool) -> PolicyEvaluation {
        if envelope.spawn_depth > self.config.max_spawn_depth {
            return deny("SPAWN_DEPTH_EXCEEDED");
        }

        let Some(tool_policy) = self.config.tools.iter().find(|tp| tp.name == envelope.proposed_action.tool)
        else {
            return deny("TOOL_NOT_ALLOWED");
        };

        if needs_evidence(tool_policy) && envelope.evidence.is_empty() {
            return deny("MISSING_EVIDENCE");
        }

        if let Some(reason_code) = blocked_by_constraints(tool_policy, envelope) {
            return deny(reason_code);
        }

        let claim_calls = envelope.budget_claim.tool_calls.max(1);
        let claim_writes = if tool_policy.write {
            envelope.budget_claim.write_actions.max(1)
        } else {
            0
        };

        if !self.has_budget(&envelope.run_id, claim_calls, claim_writes) {
            return deny("BUDGET_EXCEEDED");
        }

        if should_escalate(tool_policy, envelope) && !bypass_escalation {
            return PolicyEvaluation {
                decision: DecisionType::Escalate,
                reason_code: "HIGH_RISK_ESCALATION".to_string(),
                is_write: tool_policy.write,
                token_ttl_sec: self.config.token_ttl_sec,
                approval_ttl_sec: self.config.approval_ttl_sec,
                constraints: serde_json::to_value(&tool_policy.constraints)
                    .unwrap_or_else(|_| serde_json::json!({})),
            };
        }

        self.consume_budget(&envelope.run_id, claim_calls, claim_writes);

        PolicyEvaluation {
            decision: DecisionType::Allow,
            reason_code: if bypass_escalation {
                "APPROVED_AFTER_ESCALATION".to_string()
            } else {
                "ALLOW_POLICY".to_string()
            },
            is_write: tool_policy.write,
            token_ttl_sec: self.config.token_ttl_sec,
            approval_ttl_sec: self.config.approval_ttl_sec,
            constraints: serde_json::to_value(&tool_policy.constraints)
                .unwrap_or_else(|_| serde_json::json!({})),
        }
    }

    pub fn approval_ttl_sec(&self) -> u64 {
        self.config.approval_ttl_sec
    }

    fn has_budget(&self, run_id: &str, claim_calls: u32, claim_writes: u32) -> bool {
        let usage = self.usage_by_run.lock().expect("usage lock poisoned");
        let current = usage.get(run_id).cloned().unwrap_or_default();

        if current.tool_calls.saturating_add(claim_calls) > self.config.max_tool_calls_per_run {
            return false;
        }

        if current.write_actions.saturating_add(claim_writes) > self.config.max_write_actions_per_run {
            return false;
        }

        true
    }

    fn consume_budget(&self, run_id: &str, claim_calls: u32, claim_writes: u32) {
        let mut usage = self.usage_by_run.lock().expect("usage lock poisoned");
        let entry = usage.entry(run_id.to_string()).or_default();
        entry.tool_calls = entry.tool_calls.saturating_add(claim_calls);
        entry.write_actions = entry.write_actions.saturating_add(claim_writes);
    }
}

fn needs_evidence(tool_policy: &ToolPolicy) -> bool {
    tool_policy.requires_evidence || !matches!(tool_policy.risk, RiskLevel::Low)
}

fn should_escalate(tool_policy: &ToolPolicy, envelope: &ActionEnvelope) -> bool {
    if matches!(tool_policy.risk, RiskLevel::High) {
        return true;
    }

    match (&tool_policy.escalate_arg, &tool_policy.escalate_equals) {
        (Some(arg), Some(expected)) => envelope
            .proposed_action
            .args
            .get(arg)
            .and_then(|value| value.as_str())
            .map(|v| v == expected)
            .unwrap_or(false),
        _ => false,
    }
}

fn blocked_by_constraints(tool_policy: &ToolPolicy, envelope: &ActionEnvelope) -> Option<String> {
    if tool_policy.name != "shell.exec" {
        return None;
    }

    let blocked_pattern = tool_policy.constraints.get("blocked_pattern")?;
    let command = envelope
        .proposed_action
        .args
        .get("command")
        .and_then(|value| value.as_str())?;

    let normalized_blocked = normalize_shell_text(blocked_pattern);
    let normalized_command = normalize_shell_text(command);
    if normalized_blocked.is_empty() {
        return None;
    }

    if normalized_command.contains(&normalized_blocked) {
        return Some(
            tool_policy
                .constraints
                .get("deny_reason")
                .cloned()
                .unwrap_or_else(|| "DANGEROUS_COMMAND_BLOCKED".to_string()),
        );
    }

    None
}

fn normalize_shell_text(input: &str) -> String {
    input
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn deny(reason: impl Into<String>) -> PolicyEvaluation {
    PolicyEvaluation {
        decision: DecisionType::Deny,
        reason_code: reason.into(),
        is_write: false,
        token_ttl_sec: 0,
        approval_ttl_sec: 0,
        constraints: serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::now_rfc3339;
    use crate::proto::{
        ActionEnvelope, AgentPassport, BudgetClaim, EvidencePointer, Intent, ProposedAction,
    };

    use super::{PolicyConfig, PolicyEngine};

    fn config() -> PolicyConfig {
        toml::from_str(
            r#"
            max_tool_calls_per_run = 2
            max_write_actions_per_run = 1
            max_spawn_depth = 2
            approval_ttl_sec = 300
            token_ttl_sec = 120

            [[tools]]
            name = "repo.read"
            risk = "low"
            write = false
            requires_evidence = false

            [[tools]]
            name = "k8s.apply"
            risk = "medium"
            write = true
            requires_evidence = true
            escalate_arg = "cluster"
            escalate_equals = "prod"

            [[tools]]
            name = "shell.exec"
            risk = "high"
            write = true
            requires_evidence = true
            constraints = { blocked_pattern = "rm -rf", deny_reason = "DANGEROUS_COMMAND_BLOCKED" }
            "#,
        )
        .expect("valid policy config")
    }

    fn envelope(
        tool: &str,
        args: serde_json::Value,
        spawn_depth: u8,
        with_evidence: bool,
    ) -> ActionEnvelope {
        ActionEnvelope {
            action_id: "act-1".to_string(),
            run_id: "run-1".to_string(),
            agent_passport: AgentPassport {
                agent_id: "agent-1".to_string(),
                model_name: "m".to_string(),
                model_hash: "sha256:model".to_string(),
                policy_version: "p1".to_string(),
                pubkey: "unused".to_string(),
                runtime_attestation: "none".to_string(),
            },
            intent: Intent {
                intent_type: "deploy_fix".to_string(),
                risk: "medium".to_string(),
                justification: None,
            },
            proposed_action: ProposedAction {
                tool: tool.to_string(),
                args,
            },
            evidence: if with_evidence {
                vec![EvidencePointer {
                    evidence_type: "ticket".to_string(),
                    reference: "JIRA-9".to_string(),
                }]
            } else {
                vec![]
            },
            budget_claim: BudgetClaim {
                tool_calls: 1,
                write_actions: 1,
            },
            spawn_depth,
            created_at: now_rfc3339(),
            sig: String::new(),
        }
    }

    #[test]
    fn denies_on_spawn_depth() {
        let engine = PolicyEngine::from_config(config());
        let env = envelope("repo.read", serde_json::json!({"path":"README.md"}), 3, false);
        let eval = engine.evaluate_submit(&env);
        assert_eq!(eval.reason_code, "SPAWN_DEPTH_EXCEEDED");
    }

    #[test]
    fn escalates_high_risk_devops_action() {
        let engine = PolicyEngine::from_config(config());
        let env = envelope("k8s.apply", serde_json::json!({"cluster":"prod"}), 1, true);
        let eval = engine.evaluate_submit(&env);
        assert!(matches!(eval.decision, crate::proto::DecisionType::Escalate));
    }

    #[test]
    fn consumes_budget_and_blocks_overuse() {
        let engine = PolicyEngine::from_config(config());

        let first = envelope("repo.read", serde_json::json!({"path":"README.md"}), 1, false);
        let second = envelope("repo.read", serde_json::json!({"path":"README.md"}), 1, false);
        let third = envelope("repo.read", serde_json::json!({"path":"README.md"}), 1, false);

        assert!(matches!(
            engine.evaluate_submit(&first).decision,
            crate::proto::DecisionType::Allow
        ));
        assert!(matches!(
            engine.evaluate_submit(&second).decision,
            crate::proto::DecisionType::Allow
        ));
        assert!(matches!(
            engine.evaluate_submit(&third).decision,
            crate::proto::DecisionType::Deny
        ));
    }

    #[test]
    fn denies_dangerous_shell_command() {
        let engine = PolicyEngine::from_config(config());
        let env = envelope(
            "shell.exec",
            serde_json::json!({"command":"  RM   -RF   /tmp/demo  "}),
            1,
            true,
        );

        let eval = engine.evaluate_submit(&env);
        assert!(matches!(eval.decision, crate::proto::DecisionType::Deny));
        assert_eq!(eval.reason_code, "DANGEROUS_COMMAND_BLOCKED");
    }

    #[test]
    fn escalates_safe_shell_command() {
        let engine = PolicyEngine::from_config(config());
        let env = envelope(
            "shell.exec",
            serde_json::json!({"command":"ls   -la /tmp"}),
            1,
            true,
        );

        let eval = engine.evaluate_submit(&env);
        assert!(matches!(eval.decision, crate::proto::DecisionType::Escalate));
        assert_eq!(eval.reason_code, "HIGH_RISK_ESCALATION");
    }
}
