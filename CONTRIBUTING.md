# Contributing to P47H Open Core

Thank you for your interest in contributing to P47H Open Core!

## License

This project is licensed under **Apache License 2.0**.

You are free to:

- Use the code commercially
- Modify and distribute
- Use for private purposes
- Sublicense

See [`LICENSE`](./LICENSE) for full details.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Use issue templates when available
- Include reproduction steps for bugs
- For security vulnerabilities, email <security@p47h.com> privately

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make your changes**
4. **Write or update tests**
5. **Ensure tests pass**: `cargo test --workspace`
6. **Run lints**: `cargo clippy --workspace --all-features -- -D warnings`
7. **Commit with descriptive messages**
8. **Push and create a Pull Request**

### Code Style

- Follow Rust idioms and conventions
- Use `rustfmt` for formatting: `cargo fmt`
- Add doc comments for public APIs
- Write tests for new functionality
- Prefer `no_std` compatibility where possible

### Testing

```bash
# Run all tests
cargo test --workspace

# Run with all features
cargo test --workspace --all-features

# Check formatting
cargo fmt -- --check

# Lints
cargo clippy --workspace --all-features -- -D warnings
```

## Development Setup

```bash
# Clone the repository
git clone https://github.com/p47h-org/p47h-open-core.git
cd p47h-open-core

# Build
cargo build --release --workspace

# Build WASM
cd crates/p47h-wasm-core
wasm-pack build --target web --release
```

## Architecture

This is a monorepo structured in layers:

```text
Layer 1: Core (no_std compatible)
├── core-identity    # Ed25519 cryptography
└── core-policy      # RBAC/ABAC policy engine

Layer 2: Application
├── app-if-ipc       # Clean interfaces (DIP)
└── app-utils        # Utilities

Layer 3: Adapters
├── p47h-wasm-core   # WASM bindings
└── cli              # Command-line tools
```

## Questions?

- Open a [Discussion](https://github.com/p47h-org/p47h-open-core/discussions)
- Email: <support@p47h.com>

---

By contributing, you agree that your contributions will be licensed under Apache License 2.0.
