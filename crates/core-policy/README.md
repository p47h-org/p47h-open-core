# core-policy

Pure RBAC/ABAC policy engine core with zero crypto/network dependencies.

Wildcard path matching, context expressions, and policy authorization.

## Features

- **`toml`** — enables `Policy::from_toml()` / `Policy::to_toml()` (requires std)
- Without `toml`: genuine `#![no_std]`, builds for `thumbv7em-none-eabi`

## License

Apache-2.0
