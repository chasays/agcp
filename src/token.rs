use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{
    now_rfc3339, sign_capability_token, verify_capability_token, verifying_key_to_b64, CryptoError,
};
use crate::proto::{ActionEnvelope, CapabilityBudget, CapabilityToken};

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("token expired")]
    Expired,
    #[error("subject mismatch")]
    SubjectMismatch,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("budget exhausted")]
    BudgetExhausted,
    #[error("invalid issued_at timestamp")]
    InvalidIssuedAt,
}

impl TokenError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            TokenError::Expired => "TOKEN_EXPIRED",
            TokenError::SubjectMismatch => "TOKEN_SUBJECT_MISMATCH",
            TokenError::ScopeMismatch => "TOKEN_SCOPE_MISMATCH",
            TokenError::BudgetExhausted => "TOKEN_BUDGET_EXHAUSTED",
            TokenError::InvalidIssuedAt => "TOKEN_ISSUED_AT_INVALID",
            TokenError::Crypto(_) => "TOKEN_SIGNATURE_INVALID",
        }
    }
}

#[derive(Clone)]
pub struct TokenService {
    issuer: String,
    signing_key: SigningKey,
    issuer_pubkey_b64: String,
}

impl TokenService {
    pub fn new(issuer: String, signing_key: SigningKey) -> Self {
        let issuer_pubkey_b64 = verifying_key_to_b64(&signing_key.verifying_key());
        Self {
            issuer,
            signing_key,
            issuer_pubkey_b64,
        }
    }

    pub fn issuer_pubkey_b64(&self) -> &str {
        &self.issuer_pubkey_b64
    }

    pub fn issue_for_action(
        &self,
        envelope: &ActionEnvelope,
        ttl_sec: u64,
        constraints: serde_json::Value,
    ) -> Result<CapabilityToken, TokenError> {
        let mut token = CapabilityToken {
            cap_id: format!("cap-{}", Uuid::new_v4()),
            issuer: self.issuer.clone(),
            subject_agent: envelope.agent_passport.agent_id.clone(),
            scope: scope_for_action(envelope),
            constraints,
            ttl_sec,
            budget: CapabilityBudget { calls: 1 },
            issued_at: now_rfc3339(),
            sig: String::new(),
        };

        sign_capability_token(&mut token, &self.signing_key)?;
        Ok(token)
    }

    pub fn validate_for_action(
        &self,
        token: &CapabilityToken,
        envelope: &ActionEnvelope,
    ) -> Result<(), TokenError> {
        verify_capability_token(token, &self.issuer_pubkey_b64)?;

        if token.subject_agent != envelope.agent_passport.agent_id {
            return Err(TokenError::SubjectMismatch);
        }

        if token.budget.calls == 0 {
            return Err(TokenError::BudgetExhausted);
        }

        let issued_at = DateTime::parse_from_rfc3339(&token.issued_at)
            .map_err(|_| TokenError::InvalidIssuedAt)?
            .with_timezone(&Utc);
        let expires_at = issued_at + Duration::seconds(token.ttl_sec as i64);
        if Utc::now() > expires_at {
            return Err(TokenError::Expired);
        }

        let accepted = expected_scopes(envelope)
            .iter()
            .any(|scope| token.scope.iter().any(|s| s == scope));
        if !accepted {
            return Err(TokenError::ScopeMismatch);
        }

        Ok(())
    }
}

fn scope_for_action(envelope: &ActionEnvelope) -> Vec<String> {
    let mut scopes = vec![envelope.proposed_action.tool.clone()];
    if let Some(cluster) = envelope
        .proposed_action
        .args
        .get("cluster")
        .and_then(|v| v.as_str())
    {
        scopes.push(format!("{}:{}", envelope.proposed_action.tool, cluster));
    }
    scopes
}

fn expected_scopes(envelope: &ActionEnvelope) -> Vec<String> {
    scope_for_action(envelope)
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use crate::crypto::now_rfc3339;
    use crate::proto::{
        ActionEnvelope, AgentPassport, BudgetClaim, Intent, ProposedAction,
    };

    use super::*;

    fn sample_envelope() -> ActionEnvelope {
        ActionEnvelope {
            action_id: "a1".to_string(),
            run_id: "r1".to_string(),
            agent_passport: AgentPassport {
                agent_id: "agent-1".to_string(),
                model_name: "m".to_string(),
                model_hash: "sha".to_string(),
                policy_version: "p1".to_string(),
                pubkey: "unused".to_string(),
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
            sig: String::new(),
        }
    }

    #[test]
    fn token_expiry_is_enforced() {
        let key = SigningKey::generate(&mut OsRng);
        let service = TokenService::new("policy".to_string(), key);

        let env = sample_envelope();
        let token = service
            .issue_for_action(&env, 1, serde_json::json!({}))
            .expect("token issue");

        std::thread::sleep(StdDuration::from_secs(2));

        let result = service.validate_for_action(&token, &env);
        assert!(matches!(result, Err(TokenError::Expired)));
    }
}
