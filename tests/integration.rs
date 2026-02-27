use std::sync::Arc;

use agcp_mvp::api::{build_router, AppState};
use agcp_mvp::crypto::{now_rfc3339, sign_action_envelope, verifying_key_to_b64};
use agcp_mvp::gateway::ToolGateway;
use agcp_mvp::governor::Governor;
use agcp_mvp::ledger::AuditLedger;
use agcp_mvp::policy::{PolicyConfig, PolicyEngine};
use agcp_mvp::proto::{
    ActionEnvelope, AgentPassport, BudgetClaim, DegradeRequest, EvidencePointer, GovernorMode, Intent,
    ProposedAction,
};
use agcp_mvp::token::TokenService;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tempfile::TempDir;
use tower::ServiceExt;

fn test_policy() -> PolicyConfig {
    toml::from_str(
        r#"
        max_tool_calls_per_run = 20
        max_write_actions_per_run = 5
        max_spawn_depth = 2
        approval_ttl_sec = 300
        token_ttl_sec = 300

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
        "#,
    )
    .expect("test policy parse")
}

fn build_test_app(tmp: &TempDir) -> axum::Router {
    let policy = PolicyEngine::from_config(test_policy());
    let governor = Governor::new();
    let token_service = TokenService::new("policy-engine".to_string(), SigningKey::generate(&mut OsRng));
    let gateway = ToolGateway::new(token_service.clone());
    let ledger = AuditLedger::new(tmp.path().join("audit.wal")).expect("create ledger");
    let state = Arc::new(AppState::new(policy, governor, token_service, gateway, ledger));
    build_router(state)
}

fn make_action(
    signing_key: &SigningKey,
    action_id: &str,
    run_id: &str,
    tool: &str,
    args: serde_json::Value,
    with_evidence: bool,
) -> ActionEnvelope {
    let mut action = ActionEnvelope {
        action_id: action_id.to_string(),
        run_id: run_id.to_string(),
        agent_passport: AgentPassport {
            agent_id: "agent-devops-1".to_string(),
            model_name: "model-x".to_string(),
            model_hash: "sha256:model-x".to_string(),
            policy_version: "p-12".to_string(),
            pubkey: verifying_key_to_b64(&signing_key.verifying_key()),
            runtime_attestation: "placeholder".to_string(),
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
                reference: "JIRA-123".to_string(),
            }]
        } else {
            vec![]
        },
        budget_claim: BudgetClaim {
            tool_calls: 1,
            write_actions: 1,
        },
        spawn_depth: 0,
        created_at: now_rfc3339(),
        sig: String::new(),
    };

    sign_action_envelope(&mut action, signing_key).expect("sign action");
    action
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    payload: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("request build");

    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    (status, value)
}

#[tokio::test]
async fn low_risk_action_executes_and_is_auditable() {
    let tmp = TempDir::new().expect("tempdir");
    let app = build_test_app(&tmp);
    let agent_key = SigningKey::generate(&mut OsRng);

    let action = make_action(
        &agent_key,
        "act-low-1",
        "run-low",
        "repo.read",
        serde_json::json!({"path":"README.md"}),
        false,
    );

    let (status, body) = send_json(
        &app,
        "POST",
        "/v1/actions/submit",
        serde_json::to_value(action).expect("action json"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ALLOW_EXECUTED");

    let (audit_status, audit_body) = send_json(
        &app,
        "GET",
        "/v1/audit/act-low-1",
        serde_json::json!({}),
    )
    .await;

    assert_eq!(audit_status, StatusCode::OK);
    assert_eq!(audit_body["chain_valid"], true);
}

#[tokio::test]
async fn high_risk_action_escalates_then_approves() {
    let tmp = TempDir::new().expect("tempdir");
    let app = build_test_app(&tmp);
    let agent_key = SigningKey::generate(&mut OsRng);

    let action = make_action(
        &agent_key,
        "act-esc-1",
        "run-esc",
        "k8s.apply",
        serde_json::json!({"cluster":"prod"}),
        true,
    );

    let (submit_status, submit_body) = send_json(
        &app,
        "POST",
        "/v1/actions/submit",
        serde_json::to_value(action).expect("action json"),
    )
    .await;

    assert_eq!(submit_status, StatusCode::ACCEPTED);
    assert_eq!(submit_body["status"], "ESCALATE_PENDING");

    let approval_id = submit_body["decision"]["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();

    let (approve_status, approve_body) = send_json(
        &app,
        "POST",
        "/v1/actions/act-esc-1/approve",
        serde_json::json!({
            "approval_id": approval_id,
            "approver": "ops-oncall",
            "note": "looks safe"
        }),
    )
    .await;

    assert_eq!(approve_status, StatusCode::OK);
    assert_eq!(approve_body["status"], "APPROVED_EXECUTED");
}

#[tokio::test]
async fn missing_evidence_is_denied() {
    let tmp = TempDir::new().expect("tempdir");
    let app = build_test_app(&tmp);
    let agent_key = SigningKey::generate(&mut OsRng);

    let action = make_action(
        &agent_key,
        "act-deny-1",
        "run-deny",
        "k8s.apply",
        serde_json::json!({"cluster":"prod"}),
        false,
    );

    let (status, body) = send_json(
        &app,
        "POST",
        "/v1/actions/submit",
        serde_json::to_value(action).expect("action json"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["status"], "DENY");
    assert_eq!(body["decision"]["reason_code"], "MISSING_EVIDENCE");
}

#[tokio::test]
async fn read_only_blocks_write_actions() {
    let tmp = TempDir::new().expect("tempdir");
    let app = build_test_app(&tmp);
    let agent_key = SigningKey::generate(&mut OsRng);

    let (degrade_status, _) = send_json(
        &app,
        "POST",
        "/v1/governor/degrade",
        serde_json::to_value(DegradeRequest {
            mode: GovernorMode::ReadOnly,
            actor: "governor".to_string(),
        })
        .expect("degrade json"),
    )
    .await;
    assert_eq!(degrade_status, StatusCode::OK);

    let action = make_action(
        &agent_key,
        "act-ro-1",
        "run-ro",
        "k8s.apply",
        serde_json::json!({"cluster":"staging"}),
        true,
    );

    let (status, body) = send_json(
        &app,
        "POST",
        "/v1/actions/submit",
        serde_json::to_value(action).expect("action json"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["decision"]["reason_code"], "GOVERNOR_READ_ONLY");
}
