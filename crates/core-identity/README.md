# core-identity

Ed25519 identity management for decentralized systems.

Provides key generation, DID derivation, signing, and verification. Includes a pluggable `TrustAnchorSigner` / `TrustAnchorVerifier` trait abstraction for swappable signing backends (single-key Ed25519 shipped; FROST threshold placeholder for future use).

## `no_std` support

This crate is `#![no_std]` compatible with `alloc`. Verified on `thumbv7em-none-eabi`.

The default `std` feature enables `secrecy`-protected key storage. Disable default features for embedded targets:

```toml
core-identity = { version = "0.11", default-features = false }
```

## Links

- [Repository](https://github.com/p47h-org/p47h-open-core)
- [Security policy](https://github.com/p47h-org/p47h-open-core/blob/main/.github/SECURITY.md)
- [API docs](https://docs.rs/core-identity)

## License

Apache-2.0
