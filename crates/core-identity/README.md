# core-identity

Identity management and DID resolution for P47H.

Ed25519 key generation, signing, verification, and pluggable `TrustAnchorSigner` abstraction.

## Features

- **`std`** (default) — enables `secrecy` for protected key storage
- Without `std`: genuine `#![no_std]` with `alloc`, builds for `thumbv7em-none-eabi`

## License

Apache-2.0
