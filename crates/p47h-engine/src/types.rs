use serde::{Deserialize, Serialize};

/// Authorization decision result
///
/// Returned by policy evaluation methods to indicate whether
/// an action is allowed and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDecision {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Human-readable reasons for the decision
    pub reasons: Vec<String>,
    /// Evaluation time in microseconds (deterministic, no floating point)
    pub evaluation_time_us: u64,
}

/// Authorization decision with metadata (simplified - no cryptographic proofs in open-core)
///
/// Note: Cryptographic Merkle proofs are a commercial feature available in p47h-pro.
/// This open-core version only provides basic authorization decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDecisionWithProof {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Human-readable reasons for the decision
    pub reasons: Vec<String>,
    /// Evaluation time in microseconds (deterministic, no floating point)
    pub evaluation_time_us: u64,
}

/// Policy validation diagnostic result
///
/// Returned by `validate_policy_detailed` to provide structured error information
/// including line and column numbers for precise error reporting in code editors.
///
/// This enables IDE integrations (like VS Code) to highlight exact error locations
/// in policy TOML files, improving developer experience.
#[derive(Serialize)]
pub struct PolicyDiagnostic {
    /// Whether the policy passed validation
    pub valid: bool,
    /// Human-readable error message if validation failed, None if valid
    pub message: Option<String>,
    /// Line number where error occurred (1-indexed), None if not applicable
    pub line: Option<u32>,
    /// Column number where error occurred (1-indexed), None if not applicable
    pub column: Option<u32>,
}
