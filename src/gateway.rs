use thiserror::Error;

use crate::crypto::{hash_json, CryptoError};
use crate::proto::{ActionEnvelope, CapabilityToken, ToolExecutionResult};
use crate::token::{TokenError, TokenService};

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("missing capability token")]
    MissingToken,
    #[error("token rejected: {0}")]
    Token(#[from] TokenError),
    #[error("unsupported tool")]
    UnsupportedTool,
    #[error("hash error: {0}")]
    Hash(#[from] CryptoError),
}

impl GatewayError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            GatewayError::MissingToken => "NO_CAPABILITY",
            GatewayError::Token(err) => err.reason_code(),
            GatewayError::UnsupportedTool => "TOOL_UNSUPPORTED",
            GatewayError::Hash(_) => "TOOL_OUTPUT_HASH_ERROR",
        }
    }
}

#[derive(Clone)]
pub struct ToolGateway {
    token_service: TokenService,
}

impl ToolGateway {
    pub fn new(token_service: TokenService) -> Self {
        Self { token_service }
    }

    pub fn execute(
        &self,
        envelope: &ActionEnvelope,
        token: Option<&CapabilityToken>,
    ) -> Result<ToolExecutionResult, GatewayError> {
        let token = token.ok_or(GatewayError::MissingToken)?;
        self.token_service.validate_for_action(token, envelope)?;

        let output = match envelope.proposed_action.tool.as_str() {
            "repo.read" => serde_json::json!({
                "status": "ok",
                "data": "mock repository content",
            }),
            "k8s.apply" => serde_json::json!({
                "status": "applied",
                "cluster": envelope.proposed_action.args.get("cluster").cloned().unwrap_or(serde_json::json!("unknown")),
                "changes": 1,
            }),
            "k8s.diff" => serde_json::json!({
                "status": "ok",
                "diff_lines": 12,
            }),
            _ => return Err(GatewayError::UnsupportedTool),
        };

        let output_hash = hash_json(&output)?;
        Ok(ToolExecutionResult {
            tool: envelope.proposed_action.tool.clone(),
            output,
            output_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use crate::crypto::now_rfc3339;
    use crate::proto::{
        ActionEnvelope, AgentPassport, BudgetClaim, Intent, ProposedAction,
    };

    use super::*;

    fn envelope() -> ActionEnvelope {
        ActionEnvelope {
            action_id: "a".to_string(),
            run_id: "r".to_string(),
            agent_passport: AgentPassport {
                agent_id: "agent".to_string(),
                model_name: "m".to_string(),
                model_hash: "sha".to_string(),
                policy_version: "p".to_string(),
                pubkey: "unused".to_string(),
                runtime_attestation: "none".to_string(),
            },
            intent: Intent {
                intent_type: "read".to_string(),
                risk: "low".to_string(),
                justification: None,
            },
            proposed_action: ProposedAction {
                tool: "repo.read".to_string(),
                args: serde_json::json!({}),
            },
            evidence: vec![],
            budget_claim: BudgetClaim {
                tool_calls: 1,
                write_actions: 0,
            },
            spawn_depth: 0,
            created_at: now_rfc3339(),
            sig: String::new(),
        }
    }

    #[test]
    fn missing_token_is_denied() {
        let service = TokenService::new("issuer".to_string(), SigningKey::generate(&mut OsRng));
        let gateway = ToolGateway::new(service);
        let env = envelope();

        let result = gateway.execute(&env, None);
        assert!(matches!(result, Err(GatewayError::MissingToken)));
    }
}
