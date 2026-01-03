use crate::types::PolicyDiagnostic;
use core_policy::Policy;
use wasm_bindgen::prelude::*;

/// Validates a policy TOML string
///
/// Checks if the provided string is a valid P47H policy.
/// Returns Ok(()) if valid, or an error message if invalid.
#[wasm_bindgen]
pub fn validate_policy(policy_toml: &str) -> Result<(), JsValue> {
    let _: Policy = toml::from_str(policy_toml)
        .map_err(|e| JsValue::from_str(&format!("Invalid policy TOML: {}", e)))?;
    Ok(())
}

/// Validates a policy TOML string with precise error reporting
#[wasm_bindgen]
pub fn validate_policy_detailed(policy_toml: &str) -> Result<JsValue, JsValue> {
    // 1. Syntax Validation (TOML)
    let policy: Policy = match toml::from_str(policy_toml) {
        Ok(p) => p,
        Err(e) => {
            // Extract line/col from toml error string if possible
            // toml error format: "TOML parse error at line 1, column 10"
            let msg = e.to_string();
            let (line, col) = parse_toml_error_position(&msg);

            let diagnostic = PolicyDiagnostic {
                valid: false,
                message: Some(msg),
                line,
                column: col,
            };
            return Ok(serde_wasm_bindgen::to_value(&diagnostic)?);
        }
    };

    // 2. Semantic Validation (Logic)
    if policy.rules().is_empty() {
        let diagnostic = PolicyDiagnostic {
            valid: false,
            message: Some("Policy is empty: must contain at least one rule".to_string()),
            line: Some(0), // Header issue
            column: None,
        };
        return Ok(serde_wasm_bindgen::to_value(&diagnostic)?);
    }

    // 3. Resource Validation
    for (i, rule) in policy.rules().iter().enumerate() {
        if rule.peer_id.is_empty() {
            let diagnostic = PolicyDiagnostic {
                valid: false,
                message: Some(format!("Rule #{} has empty peer_id", i + 1)),
                line: None, // Hard to map back to TOML line without a span-aware parser
                column: None,
            };
            return Ok(serde_wasm_bindgen::to_value(&diagnostic)?);
        }
    }

    // Success
    let diagnostic = PolicyDiagnostic {
        valid: true,
        message: None,
        line: None,
        column: None,
    };
    Ok(serde_wasm_bindgen::to_value(&diagnostic)?)
}

// Helper to extract line info from toml error string (simple regex heuristic)
fn parse_toml_error_position(msg: &str) -> (Option<u32>, Option<u32>) {
    // Example: "TOML parse error at line 1, column 10"
    // Regex: line (\d+), column (\d+)

    if let Some(line_idx) = msg.find("line ") {
        if let Some(col_idx) = msg.find("column ") {
            let line_str = &msg[line_idx + 5..];
            let line_end = line_str.find(',').unwrap_or(line_str.len());
            let line = line_str[..line_end].trim().parse::<u32>().ok();

            let col_str = &msg[col_idx + 7..];
            let col_end = col_str
                .find(|c: char| !c.is_numeric())
                .unwrap_or(col_str.len());
            let col = col_str[..col_end].trim().parse::<u32>().ok();

            return (line, col);
        }
    }
    (None, None)
}
