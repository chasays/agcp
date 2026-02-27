use std::sync::Mutex;

use crate::crypto::now_rfc3339;
use crate::proto::{ActionEnvelope, DegradeRequest, GovernorMode, GovernorState, KillRequest, KillRule, KillScope};

pub struct Governor {
    state: Mutex<GovernorState>,
}

impl Governor {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GovernorState {
                mode: GovernorMode::Normal,
                kills: vec![],
                updated_at: now_rfc3339(),
                updated_by: "system".to_string(),
            }),
        }
    }

    pub fn apply_kill(&self, req: KillRequest) -> GovernorState {
        let mut state = self.state.lock().expect("governor lock poisoned");
        state.kills.push(KillRule {
            scope: req.scope.clone(),
            value: req.value,
        });

        if matches!(req.scope, KillScope::Global) {
            state.mode = GovernorMode::Killed;
        }

        state.updated_at = now_rfc3339();
        state.updated_by = req.actor;
        state.clone()
    }

    pub fn set_mode(&self, req: DegradeRequest) -> GovernorState {
        let mut state = self.state.lock().expect("governor lock poisoned");
        state.mode = req.mode;
        state.updated_at = now_rfc3339();
        state.updated_by = req.actor;
        state.clone()
    }

    pub fn snapshot(&self) -> GovernorState {
        self.state.lock().expect("governor lock poisoned").clone()
    }

    pub fn evaluate(&self, envelope: &ActionEnvelope, is_write: bool) -> Option<String> {
        let state = self.state.lock().expect("governor lock poisoned");

        if matches!(state.mode, GovernorMode::Killed)
            || state
                .kills
                .iter()
                .any(|k| matches!(k.scope, KillScope::Global))
        {
            return Some("GOVERNOR_GLOBAL_KILL".to_string());
        }

        if state.kills.iter().any(|k| {
            matches!(k.scope, KillScope::Run)
                && k.value.as_deref() == Some(envelope.run_id.as_str())
        }) {
            return Some("GOVERNOR_RUN_KILL".to_string());
        }

        if state.kills.iter().any(|k| {
            matches!(k.scope, KillScope::Agent)
                && k.value.as_deref() == Some(envelope.agent_passport.agent_id.as_str())
        }) {
            return Some("GOVERNOR_AGENT_KILL".to_string());
        }

        let class = tool_class(&envelope.proposed_action.tool);
        if state.kills.iter().any(|k| {
            matches!(k.scope, KillScope::ToolClass)
                && k.value.as_deref() == Some(class.as_str())
        }) {
            return Some("GOVERNOR_TOOL_CLASS_KILL".to_string());
        }

        if matches!(state.mode, GovernorMode::ReadOnly) && is_write {
            return Some("GOVERNOR_READ_ONLY".to_string());
        }

        None
    }
}

pub fn tool_class(tool: &str) -> String {
    tool.split('.').next().unwrap_or(tool).to_string()
}

#[cfg(test)]
mod tests {
    use crate::crypto::now_rfc3339;
    use crate::proto::{
        ActionEnvelope, AgentPassport, BudgetClaim, Intent, ProposedAction,
    };

    use super::*;

    fn sample_envelope() -> ActionEnvelope {
        ActionEnvelope {
            action_id: "a1".to_string(),
            run_id: "run-77".to_string(),
            agent_passport: AgentPassport {
                agent_id: "agent-9".to_string(),
                model_name: "m".to_string(),
                model_hash: "sha256:m".to_string(),
                policy_version: "p".to_string(),
                pubkey: "pk".to_string(),
                runtime_attestation: "none".to_string(),
            },
            intent: Intent {
                intent_type: "deploy".to_string(),
                risk: "medium".to_string(),
                justification: None,
            },
            proposed_action: ProposedAction {
                tool: "k8s.apply".to_string(),
                args: serde_json::json!({"cluster": "prod"}),
            },
            evidence: vec![],
            budget_claim: BudgetClaim {
                tool_calls: 1,
                write_actions: 1,
            },
            spawn_depth: 0,
            created_at: now_rfc3339(),
            sig: "sig".to_string(),
        }
    }

    #[test]
    fn kill_priority_beats_read_only() {
        let governor = Governor::new();
        let env = sample_envelope();

        governor.set_mode(DegradeRequest {
            mode: GovernorMode::ReadOnly,
            actor: "ops".to_string(),
        });

        governor.apply_kill(KillRequest {
            scope: KillScope::Run,
            value: Some("run-77".to_string()),
            actor: "ops".to_string(),
        });

        let reason = governor.evaluate(&env, true).expect("must block");
        assert_eq!(reason, "GOVERNOR_RUN_KILL");
    }
}
