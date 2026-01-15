# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.10.1] - 2026-01-15

### Added

#### Testing & Verification

- **Kani Proofs**: Added formal verification proofs in `core-identity` for Ed25519 constant assertions
- **Fuzz Testing**: New fuzz target `fuzz_context_expr` in `core-policy` for expression parsing
- **Mutation Testing**: Comprehensive mutation testing with cargo-mutants (see `mutants.out`)
- **Pure Rust Functions**: Marked core functions as fuzzable without WASM dependencies

### Changed

- **p47h-engine**: Added `js-sys` dependency for WASM compatibility
- **core-policy**: Improved context expression parsing robustness
- Version bump for coordinated release with vault-js/vault-react v0.10.2

### Testing Infrastructure

| Test Type | Coverage |
| ----------- | ---------- |
| Unit Tests | All crates |
| Fuzz Tests | core-policy (wildcard_match, context_expr) |
| Mutation Tests | core-identity, p47h-engine |
| Kani Proofs | core-identity (Ed25519 constants) |

## [0.10.0] - 2026-01-03

### Added

- **core-identity**: Ed25519 identity generation and management
- **core-policy**: Authorization policy engine with wildcard matching
- **p47h-engine**: XChaCha20-Poly1305 vault encryption, Argon2id key derivation
- **p47h-wasm-oss**: WASM bindings for browser environments
- **cli**: Command-line interface for vault operations
- **app-utils**: Shared utilities for P47H applications

### Security

- All cryptographic operations use audited libraries (RustCrypto)
- Memory-safe implementation with explicit zeroization
