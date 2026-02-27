use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::crypto::{now_rfc3339, verify_action_envelope};
use crate::gateway::{GatewayError, ToolGateway};
use crate::governor::Governor;
use crate::ledger::{AuditLedger, LedgerError};
use crate::policy::PolicyEngine;
use crate::proto::{
    ActionEnvelope, ActionStatus, ApproveActionRequest, AuditQueryResponse, DecisionType, DegradeRequest,
    GovernorState, HealthResponse, KillRequest, PendingApproval, PolicyDecision, SubmitActionResponse,
};
use crate::token::{TokenError, TokenService};

pub struct AppState {
    pub policy: PolicyEngine,
    pub governor: Governor,
    pub token_service: TokenService,
    pub gateway: ToolGateway,
    pub ledger: AuditLedger,
    pub pending: Mutex<HashMap<String, PendingApproval>>,
}

impl AppState {
    pub fn new(
        policy: PolicyEngine,
        governor: Governor,
        token_service: TokenService,
        gateway: ToolGateway,
        ledger: AuditLedger,
    ) -> Self {
        Self {
            policy,
            governor,
            token_service,
            gateway,
            ledger,
            pending: Mutex::new(HashMap::new()),
        }
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/actions/submit", post(submit_action))
        .route("/v1/actions/{action_id}/approve", post(approve_action))
        .route("/v1/governor/kill", post(kill))
        .route("/v1/governor/degrade", post(degrade))
        .route("/v1/audit/{action_id}", get(audit))
        .route("/v1/health", get(health))
        .with_state(state)
}

async fn submit_action(
    State(state): State<Arc<AppState>>,
    Json(action): Json<ActionEnvelope>,
) -> (StatusCode, Json<SubmitActionResponse>) {
    if let Err(err) = verify_action_envelope(&action) {
        return deny_response(
            &state,
            &action.action_id,
            format!("INVALID_ACTION_SIGNATURE:{err}"),
            StatusCode::UNAUTHORIZED,
        );
    }

    let is_write = state.policy.is_write_tool(&action.proposed_action.tool);
    if let Some(reason) = state.governor.evaluate(&action, is_write) {
        return deny_response(&state, &action.action_id, reason, StatusCode::FORBIDDEN);
    }

    let evaluation = state.policy.evaluate_submit(&action);
    match evaluation.decision {
        DecisionType::Deny => {
            deny_response(&state, &action.action_id, evaluation.reason_code, StatusCode::FORBIDDEN)
        }
        DecisionType::Escalate => {
            let approval_id = format!("apr-{}", Uuid::new_v4());
            let now = Utc::now();
            let pending = PendingApproval {
                approval_id: approval_id.clone(),
                action: action.clone(),
                created_at: now.to_rfc3339(),
                expires_at: (now + Duration::seconds(evaluation.approval_ttl_sec as i64)).to_rfc3339(),
            };

            state
                .pending
                .lock()
                .expect("pending lock poisoned")
                .insert(action.action_id.clone(), pending);

            let decision = PolicyDecision {
                decision: DecisionType::Escalate,
                reason_code: evaluation.reason_code,
                issued_token: None,
                approval_id: Some(approval_id),
            };

            let _ = state
                .ledger
                .append_event(&action.action_id, "ACTION_ESCALATED", &decision, "policy-engine");

            (
                StatusCode::ACCEPTED,
                Json(SubmitActionResponse {
                    status: ActionStatus::EscalatePending,
                    decision,
                    execution: None,
                }),
            )
        }
        DecisionType::Allow => {
            let reason_code = evaluation.reason_code;
            let token_ttl_sec = evaluation.token_ttl_sec;
            let constraints = evaluation.constraints;
            match execute_action(
                &state,
                &action,
                &reason_code,
                ActionStatus::AllowExecuted,
                token_ttl_sec,
                constraints,
            ) {
                Ok(response) => (StatusCode::OK, Json(response)),
                Err(reason) => deny_response(&state, &action.action_id, reason, StatusCode::FORBIDDEN),
            }
        }
    }
}

async fn approve_action(
    Path(action_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ApproveActionRequest>,
) -> (StatusCode, Json<SubmitActionResponse>) {
    let pending = {
        let map = state.pending.lock().expect("pending lock poisoned");
        map.get(&action_id).cloned()
    };

    let Some(pending) = pending else {
        return deny_response(
            &state,
            &action_id,
            "APPROVAL_NOT_FOUND".to_string(),
            StatusCode::NOT_FOUND,
        );
    };

    if pending.approval_id != req.approval_id {
        return deny_response(
            &state,
            &action_id,
            "APPROVAL_ID_MISMATCH".to_string(),
            StatusCode::BAD_REQUEST,
        );
    }

    let expires_at = chrono::DateTime::parse_from_rfc3339(&pending.expires_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now() - Duration::seconds(1));
    if Utc::now() > expires_at {
        state
            .pending
            .lock()
            .expect("pending lock poisoned")
            .remove(&action_id);
        return deny_response(
            &state,
            &action_id,
            "APPROVAL_EXPIRED".to_string(),
            StatusCode::GONE,
        );
    }

    let action = pending.action;
    let is_write = state.policy.is_write_tool(&action.proposed_action.tool);
    if let Some(reason) = state.governor.evaluate(&action, is_write) {
        return deny_response(&state, &action_id, reason, StatusCode::FORBIDDEN);
    }

    let evaluation = state.policy.evaluate_approval(&action);
    if !matches!(evaluation.decision, DecisionType::Allow) {
        return deny_response(&state, &action_id, evaluation.reason_code, StatusCode::FORBIDDEN);
    }

    let reason_code = evaluation.reason_code;
    let token_ttl_sec = evaluation.token_ttl_sec;
    let constraints = evaluation.constraints;
    match execute_action(
        &state,
        &action,
        &reason_code,
        ActionStatus::ApprovedExecuted,
        token_ttl_sec,
        constraints,
    ) {
        Ok(mut response) => {
            response.decision.approval_id = Some(req.approval_id);
            let _ = state.ledger.append_event(
                &action_id,
                "ACTION_APPROVED",
                &serde_json::json!({
                    "approver": req.approver,
                    "note": req.note,
                    "approved_at": now_rfc3339(),
                }),
                "human-approver",
            );
            state
                .pending
                .lock()
                .expect("pending lock poisoned")
                .remove(&action_id);
            (StatusCode::OK, Json(response))
        }
        Err(reason) => deny_response(&state, &action_id, reason, StatusCode::FORBIDDEN),
    }
}

async fn kill(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KillRequest>,
) -> (StatusCode, Json<GovernorState>) {
    let snapshot = state.governor.apply_kill(req.clone());
    let _ = state
        .ledger
        .append_event("governor", "GOVERNOR_KILL", &req, "governor");
    (StatusCode::OK, Json(snapshot))
}

async fn degrade(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DegradeRequest>,
) -> (StatusCode, Json<GovernorState>) {
    let snapshot = state.governor.set_mode(req.clone());
    let _ = state
        .ledger
        .append_event("governor", "GOVERNOR_DEGRADE", &req, "governor");
    (StatusCode::OK, Json(snapshot))
}

async fn audit(
    Path(action_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<AuditQueryResponse>) {
    let records = state.ledger.records_for_action(&action_id);
    let (chain_valid, broken_seq) = match state.ledger.verify_chain() {
        Ok(()) => (true, None),
        Err(LedgerError::ChainBroken(seq)) => (false, Some(seq)),
        Err(_) => (false, None),
    };

    (
        StatusCode::OK,
        Json(AuditQueryResponse {
            action_id,
            records,
            chain_valid,
            broken_seq,
        }),
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

fn execute_action(
    state: &Arc<AppState>,
    action: &ActionEnvelope,
    reason_code: &str,
    status: ActionStatus,
    token_ttl_sec: u64,
    constraints: serde_json::Value,
) -> Result<SubmitActionResponse, String> {
    let token = state
        .token_service
        .issue_for_action(action, token_ttl_sec, constraints)
        .map_err(token_error_code)?;

    let execution = state
        .gateway
        .execute(action, Some(&token))
        .map_err(gateway_error_code)?;

    let decision = PolicyDecision {
        decision: DecisionType::Allow,
        reason_code: reason_code.to_string(),
        issued_token: Some(token),
        approval_id: None,
    };

    let response = SubmitActionResponse {
        status,
        decision: decision.clone(),
        execution: Some(execution.clone()),
    };

    let _ = state
        .ledger
        .append_event(&action.action_id, "ACTION_EXECUTED", &response, "tool-gateway");

    Ok(response)
}

fn token_error_code(err: TokenError) -> String {
    err.reason_code().to_string()
}

fn gateway_error_code(err: GatewayError) -> String {
    err.reason_code().to_string()
}

fn deny_response(
    state: &Arc<AppState>,
    action_id: &str,
    reason_code: String,
    status_code: StatusCode,
) -> (StatusCode, Json<SubmitActionResponse>) {
    let decision = PolicyDecision {
        decision: DecisionType::Deny,
        reason_code,
        issued_token: None,
        approval_id: None,
    };

    let response = SubmitActionResponse {
        status: ActionStatus::Deny,
        decision: decision.clone(),
        execution: None,
    };

    let _ = state
        .ledger
        .append_event(action_id, "ACTION_DENIED", &response, "policy-engine");

    (status_code, Json(response))
}
