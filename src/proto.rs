use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPassport {
    pub agent_id: String,
    pub model_name: String,
    pub model_hash: String,
    pub policy_version: String,
    pub pubkey: String,
    pub runtime_attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    #[serde(rename = "type")]
    pub intent_type: String,
    pub risk: String,
    #[serde(default)]
    pub justification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    #[serde(rename = "type")]
    pub evidence_type: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetClaim {
    #[serde(default)]
    pub tool_calls: u32,
    #[serde(default)]
    pub write_actions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEnvelope {
    pub action_id: String,
    pub run_id: String,
    pub agent_passport: AgentPassport,
    pub intent: Intent,
    pub proposed_action: ProposedAction,
    #[serde(default)]
    pub evidence: Vec<EvidencePointer>,
    #[serde(default)]
    pub budget_claim: BudgetClaim,
    pub spawn_depth: u8,
    pub created_at: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityBudget {
    pub calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub cap_id: String,
    pub issuer: String,
    pub subject_agent: String,
    pub scope: Vec<String>,
    pub constraints: serde_json::Value,
    pub ttl_sec: u64,
    pub budget: CapabilityBudget,
    pub issued_at: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionType {
    Allow,
    Deny,
    Escalate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: DecisionType,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token: Option<CapabilityToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: String,
    pub event_type: String,
    pub action_id: String,
    pub payload_hash: String,
    pub prev_hash: String,
    pub record_hash: String,
    pub signer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernorMode {
    Normal,
    ReadOnly,
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillScope {
    Global,
    Run,
    Agent,
    ToolClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillRule {
    pub scope: KillScope,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorState {
    pub mode: GovernorMode,
    #[serde(default)]
    pub kills: Vec<KillRule>,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitActionResponse {
    pub status: ActionStatus,
    pub decision: PolicyDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ToolExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionStatus {
    AllowExecuted,
    Deny,
    EscalatePending,
    ApprovedExecuted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionResult {
    pub tool: String,
    pub output: serde_json::Value,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveActionRequest {
    pub approval_id: String,
    pub approver: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillRequest {
    pub scope: KillScope,
    #[serde(default)]
    pub value: Option<String>,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradeRequest {
    pub mode: GovernorMode,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    pub action_id: String,
    pub records: Vec<AuditRecord>,
    pub chain_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_seq: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub action: ActionEnvelope,
    pub created_at: String,
    pub expires_at: String,
}
