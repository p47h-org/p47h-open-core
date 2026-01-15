# p47h-open-core

The cryptographic primitive layer for the P47H ecosystem.

[![Build Status](https://img.shields.io/github/actions/workflow/status/p47h-org/p47h-open-core/ci.yml?branch=main)](https://github.com/p47h-org/p47h-open-core/actions)
[![Crates.io](https://img.shields.io/crates/v/p47h-open-core)](https://crates.io/crates/p47h-open-core)

---

## Scope

This crate provides the low-level Rust implementation of the vault encryption logic, compiled to WebAssembly. It handles key derivation, memory isolation, and stateless authorization primitives.

**Included:**

- Ed25519 cryptographic identity generation
- Argon2id key derivation
- XChaCha20-Poly1305 authenticated encryption
- Memory zeroization on drop
- Abstract policy evaluation engine

> **Architecture Note:** This repository represents the **v2 architecture** (Rust/WASM) of the P47H core. It supersedes previous prototypes to ensure strict memory safety guarantees.

---

## Usage Warning

This is a **low-level core library**.

If you are a web developer looking to implement secure storage in your application, use the high-level SDK:

**[@p47h/vault](https://www.npmjs.com/package/@p47h/vault)**

Direct usage of this crate is recommended only for:

- Building custom wrappers or integrations
- Auditing the cryptographic implementation
- Extending the core functionality

---

## Architecture

```text
Layer 1: Core (no_std compatible)

* core-identity (Ed25519, DID generation)
* core-policy (Stateless authorization logic)

Layer 2: Application Logic

* app-if-ipc (Interfaces, Dependency Inversion)
* app-utils (YAML parsing, timestamps)

Layer 3: Engine & Adapters

* p47h-engine (Core engine - pure rlib, reusable)
* p47h-wasm-oss (Open Source WASM bindings - cdylib)
* cli (Command-line tools)

```

### Cryptographic Primitives

| Algorithm | Purpose | Library |
| ----------- | --------- | --------- |
| Ed25519 | Identity signing | `ed25519-dalek` |
| Argon2id | Key derivation | `argon2` |
| XChaCha20-Poly1305 | Authenticated encryption | `chacha20poly1305` |
| BLAKE3 | Hashing | `blake3` |
| Zeroize | Memory clearing | `zeroize` |

---

## Build Instructions

### Prerequisites

- Rust 1.85+
- wasm-pack (for WebAssembly builds)

### Native Build

```bash
git clone [https://github.com/p47h-org/p47h-open-core](https://github.com/p47h-org/p47h-open-core)
cd p47h-open-core
cargo build --release --workspace

```

### WebAssembly Build

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web (Open Source WASM wrapper)
cd crates/p47h-wasm-oss
wasm-pack build --target web --release

```

The output will be in `pkg/` directory.

### Run Tests

```bash
# All tests
cargo test --workspace

# With coverage
cargo tarpaulin --workspace --out Html

```

### Linting

```bash
cargo clippy --workspace --all-features -- -D warnings

```

---

## Security & Verification

### Test Suite

The core maintains unit tests for cryptographic primitives, policy evaluation, and identity management. Tests cover standard vectors and edge cases.

```bash
# Run all tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture

```

### Fuzzing

Continuous fuzzing infrastructure is initialized using `cargo-fuzz` (libFuzzer) to detect panics, memory issues, and edge cases in parsing logic.

**Available fuzz targets (core-policy):**

| Target | Purpose |
| --- | --- |
| `fuzz_path_pattern` | Path pattern matching edge cases |
| `fuzz_policy_from_toml` | TOML policy parsing robustness |
| `fuzz_wildcard_match` | Wildcard matching correctness |

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a fuzz target (requires nightly)
cd crates/core-policy
cargo +nightly fuzz run fuzz_policy_from_toml

```

### Reporting Vulnerabilities

If you discover a security vulnerability, report it via email to:

**<security@p47h.com>**

Do not open public issues for security vulnerabilities. We acknowledge reports within 48 hours.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Make changes and add tests
4. Run tests and lints (`cargo test && cargo clippy`)
5. Commit with signed-off-by (`git commit -s`)
6. Open a Pull Request

All contributors must sign the Contributor License Agreement (CLA) before their PR can be merged.

See [CONTRIBUTING.md](https://www.google.com/search?q=./CONTRIBUTING.md) for details.

---

## License

Apache License 2.0. See [LICENSE](https://www.google.com/search?q=./LICENSE) for full terms.

---

## Links

- Documentation: <https://docs.p47h.com>
- Website: <https://p47h.com>
- Support: <support@p47h.com>
