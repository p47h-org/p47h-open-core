// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! # p47h-open-core
//!
//! Cryptographic primitives and policy engine for secure identity management.
//!
//! This crate provides a unified API for the P47H ecosystem's core functionality:
//!
//! - **Identity Management**: Ed25519 key generation and DID resolution
//! - **Policy Engine**: Pure RBAC/ABAC authorization without external dependencies
//! - **WASM Engine**: The core logic for browser-based vault operations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use p47h_open_core::identity::Identity;
//! use p47h_open_core::policy::Policy;
//!
//! // Generate a new cryptographic identity
//! let identity = Identity::generate();
//! println!("DID: {}", identity.did());
//! ```
//!
//! ## Architecture
//!
//! This facade crate re-exports the following modules:
//!
//! - [`identity`] - Ed25519 identity management (from `core-identity`)
//! - [`policy`] - Authorization policy engine (from `core-policy`)
//! - [`engine`] - WASM-ready vault engine (from `p47h-engine`)
//!
//! ## Feature Flags
//!
//! - `wasm` - Enable WebAssembly-specific optimizations (coming soon)
//!
//! ## Security
//!
//! All cryptographic operations use audited, production-ready libraries:
//!
//! - Ed25519 signatures via `ed25519-dalek`
//! - Argon2id key derivation via `argon2`
//! - XChaCha20-Poly1305 encryption via `chacha20poly1305`
//! - Memory zeroization via `zeroize`

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/p47h-open-core/1.0.1")]

/// Identity management module.
///
/// Re-exports `core_identity` for Ed25519 identity generation and DID operations.
pub mod identity {
    pub use core_identity::*;
}

/// Policy engine module.
///
/// Re-exports `core_policy` for RBAC/ABAC authorization.
pub mod policy {
    pub use core_policy::*;
}

/// Core engine module.
///
/// Re-exports `p47h_engine` for WASM-ready vault operations.
pub mod engine {
    pub use p47h_engine::*;
}

// Convenience re-exports at root level
pub use core_identity::Identity;
pub use core_policy::{Action, Policy, Resource};
