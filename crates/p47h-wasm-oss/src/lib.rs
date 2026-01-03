// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 P47H Team <https://p47h.com>

//! # p47h-wasm-oss
//!
//! Open Source WASM bindings for p47h governance engine.
//! This is the public cdylib wrapper around p47h-engine.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

// Re-export all public APIs from the engine
pub use p47h_engine::*;

/// Initialize the WASM module (sets panic hook for debugging)
#[wasm_bindgen(start)]
pub fn init() {
    p47h_engine::init_engine();
}
