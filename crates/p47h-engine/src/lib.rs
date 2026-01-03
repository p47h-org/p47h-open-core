// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! # p47h-engine
//!
//! Core engine for P47H with cryptographic identity management
//! and local policy evaluation.
//!
//! This crate provides a complete AuthN/AuthZ solution for web applications.
//! It is designed to be used as a library (rlib) by WASM wrappers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod types;
mod utils;
mod validation;

mod vault;
mod wrappers;

#[allow(unused_imports)]
use wasm_bindgen::prelude::*;

// Re-export main types
pub use client::P47hClient;
pub use types::{AuthDecision, AuthDecisionWithProof, PolicyDiagnostic};
pub use utils::parse_resource;
pub use validation::{validate_policy, validate_policy_detailed};
pub use vault::VaultCrypto;
pub use wrappers::{WasmIdentity, WasmPolicy};

// Set panic hook for better error messages in browser console
#[cfg(feature = "console_error_panic_hook")]
pub use console_error_panic_hook::set_once as set_panic_hook;

/// Initialize the engine (sets panic hook for debugging).
/// This should be called by the WASM wrapper, not directly.
pub fn init_engine() {
    #[cfg(feature = "console_error_panic_hook")]
    set_panic_hook();
}
