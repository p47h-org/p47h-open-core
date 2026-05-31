# core-policy

Pure RBAC/ABAC policy engine with zero crypto or network dependencies.

Evaluates access-control decisions using wildcard path matching, context expressions (`role == "admin" || role == "auditor"`), and composable policy rules. Designed for edge enforcement where latency matters.

## `no_std` support

This crate is `#![no_std]` compatible **with `alloc`** (uses `Vec`, `String`, `BTreeMap`). Verified on `thumbv7em-none-eabi`.

The optional `toml` feature enables `Policy::from_toml()` / `Policy::to_toml()` and requires `std`:

```toml
# no_std (with alloc):
core-policy = "0.11"

# With TOML serialization (requires std):
core-policy = { version = "0.11", features = ["toml"] }
```

## Links

- [Repository](https://github.com/p47h-org/p47h-open-core)
- [Security policy](https://github.com/p47h-org/p47h-open-core/blob/main/.github/SECURITY.md)
- [API docs](https://docs.rs/core-policy)

## License

Apache-2.0
