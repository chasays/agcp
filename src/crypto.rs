use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::proto::{ActionEnvelope, AuditRecord, CapabilityToken};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("serialize error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
    #[error("base64 decode failed")]
    Base64,
    #[error("invalid public key")]
    PublicKey,
    #[error("invalid signature")]
    Signature,
    #[error("signature mismatch")]
    VerifyFailed,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let json_value = serde_json::to_value(value)?;
    canonical_json_value(&json_value)
}

pub fn canonical_json_value(value: &Value) -> Result<Vec<u8>, CryptoError> {
    serde_jcs::to_vec(value).map_err(|e| CryptoError::Canonicalization(e.to_string()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn hash_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    Ok(sha256_hex(&canonical_json(value)?))
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn strip_field<T: Serialize>(value: &T, field: &str) -> Result<Value, CryptoError> {
    let mut json_value = serde_json::to_value(value)?;
    if let Value::Object(ref mut map) = json_value {
        map.remove(field);
    }
    Ok(json_value)
}

fn decode_pubkey(pubkey_b64: &str) -> Result<VerifyingKey, CryptoError> {
    let raw = B64.decode(pubkey_b64).map_err(|_| CryptoError::Base64)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| CryptoError::PublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CryptoError::PublicKey)
}

fn decode_signature(sig_b64: &str) -> Result<Signature, CryptoError> {
    let raw = B64.decode(sig_b64).map_err(|_| CryptoError::Base64)?;
    let arr: [u8; 64] = raw.try_into().map_err(|_| CryptoError::Signature)?;
    Ok(Signature::from_bytes(&arr))
}

pub fn verifying_key_to_b64(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn signing_key_from_b64(secret_b64: &str) -> Result<SigningKey, CryptoError> {
    let raw = B64.decode(secret_b64).map_err(|_| CryptoError::Base64)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| CryptoError::PublicKey)?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn signing_key_to_b64(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn sign_value<T: Serialize>(value: &T, key: &SigningKey) -> Result<String, CryptoError> {
    let bytes = canonical_json(value)?;
    let sig = key.sign(&bytes);
    Ok(B64.encode(sig.to_bytes()))
}

pub fn verify_value<T: Serialize>(
    value: &T,
    sig_b64: &str,
    pubkey_b64: &str,
) -> Result<(), CryptoError> {
    let bytes = canonical_json(value)?;
    let pk = decode_pubkey(pubkey_b64)?;
    let sig = decode_signature(sig_b64)?;
    pk.verify(&bytes, &sig)
        .map_err(|_| CryptoError::VerifyFailed)
}

pub fn sign_action_envelope(
    envelope: &mut ActionEnvelope,
    signing_key: &SigningKey,
) -> Result<(), CryptoError> {
    let payload = strip_field(envelope, "sig")?;
    envelope.sig = sign_value(&payload, signing_key)?;
    Ok(())
}

pub fn verify_action_envelope(envelope: &ActionEnvelope) -> Result<(), CryptoError> {
    let payload = strip_field(envelope, "sig")?;
    verify_value(&payload, &envelope.sig, &envelope.agent_passport.pubkey)
}

pub fn sign_capability_token(
    token: &mut CapabilityToken,
    signing_key: &SigningKey,
) -> Result<(), CryptoError> {
    let payload = strip_field(token, "sig")?;
    token.sig = sign_value(&payload, signing_key)?;
    Ok(())
}

pub fn verify_capability_token(token: &CapabilityToken, issuer_pubkey: &str) -> Result<(), CryptoError> {
    let payload = strip_field(token, "sig")?;
    verify_value(&payload, &token.sig, issuer_pubkey)
}

pub fn compute_audit_record_hash(record: &AuditRecord) -> Result<String, CryptoError> {
    let payload = strip_field(record, "record_hash")?;
    hash_json(&payload)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;

    use super::*;
    use crate::proto::{
        ActionEnvelope, AgentPassport, BudgetClaim, EvidencePointer, Intent, ProposedAction,
    };

    #[test]
    fn canonicalization_is_stable() {
        let v1 = json!({"b": 2, "a": 1});
        let v2 = json!({"a": 1, "b": 2});
        let c1 = canonical_json_value(&v1).expect("canonical v1");
        let c2 = canonical_json_value(&v2).expect("canonical v2");
        assert_eq!(c1, c2);
    }

    #[test]
    fn action_signature_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut envelope = ActionEnvelope {
            action_id: "a1".to_string(),
            run_id: "r1".to_string(),
            agent_passport: AgentPassport {
                agent_id: "agent-1".to_string(),
                model_name: "model-x".to_string(),
                model_hash: "sha256:model".to_string(),
                policy_version: "p-1".to_string(),
                pubkey: verifying_key_to_b64(&signing.verifying_key()),
                runtime_attestation: "none".to_string(),
            },
            intent: Intent {
                intent_type: "deploy_fix".to_string(),
                risk: "medium".to_string(),
                justification: None,
            },
            proposed_action: ProposedAction {
                tool: "repo.read".to_string(),
                args: json!({"path": "README.md"}),
            },
            evidence: vec![EvidencePointer {
                evidence_type: "ticket".to_string(),
                reference: "JIRA-1".to_string(),
            }],
            budget_claim: BudgetClaim {
                tool_calls: 1,
                write_actions: 0,
            },
            spawn_depth: 0,
            created_at: now_rfc3339(),
            sig: String::new(),
        };

        sign_action_envelope(&mut envelope, &signing).expect("sign envelope");
        verify_action_envelope(&envelope).expect("verify envelope");

        envelope.proposed_action.tool = "k8s.apply".to_string();
        let result = verify_action_envelope(&envelope);
        assert!(result.is_err());
    }
}
