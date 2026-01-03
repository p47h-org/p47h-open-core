# Fuzz Testing - core-policy

Este directorio contiene los fuzz targets para `core-policy` usando `cargo-fuzz` y LibFuzzer.

## Requisitos

- **Rust nightly** (`rustup install nightly`)
- **cargo-fuzz** (`cargo install cargo-fuzz`)
- **Linux/macOS o WSL2** (LibFuzzer no funciona en Windows nativo)

## Targets Disponibles

| Target | Descripción | Función Probada |
| -------- | -------- | -------- |
| `fuzz_path_pattern` | Fuzzing de creación de patrones | `PathPattern::new()` |
| `fuzz_policy_from_toml` | Fuzzing de deserialización TOML | `Policy::from_toml()` |
| `fuzz_wildcard_match` | Fuzzing de matching de wildcards | `PathPattern::matches()` |

## Ejecución Local

### Linux/macOS

```bash
cd crates/core-policy/fuzz

# Listar targets
cargo +nightly fuzz list

# Ejecutar un target (5 minutos)
cargo +nightly fuzz run fuzz_path_pattern -- -max_total_time=300

# Ejecutar indefinidamente (Ctrl+C para detener)
cargo +nightly fuzz run fuzz_path_pattern
```

### Windows (WSL2)

```bash
# Abrir WSL2
wsl

# Navegar al directorio
cd /mnt/c/dev/p47h-open-core/crates/core-policy/fuzz

# Instalar toolchain
rustup install nightly
cargo install cargo-fuzz

# Ejecutar
cargo +nightly fuzz run fuzz_path_pattern -- -max_total_time=300
```

## CI/CD

El fuzzing se ejecuta automáticamente en GitHub Actions:

- **Trigger:** Push a `main` o `workflow_dispatch`
- **Duración:** 5 minutos por target
- **Artefactos:** Crashes guardados en `fuzz-artifacts`

## Si Encuentras un Crash

1. El crash se guarda en `artifacts/<target>/<hash>`
2. Reproducir: `cargo +nightly fuzz run <target> artifacts/<target>/<hash>`
3. Crear issue con:
   - Archivo del crash
   - Stack trace
   - Versión de Rust
   - Comando ejecutado

## Estructura

```text
fuzz/
├── Cargo.toml              # Configuración del crate de fuzz
├── README.md               # Este archivo
├── fuzz_targets/
│   ├── fuzz_path_pattern.rs
│   ├── fuzz_policy_from_toml.rs
│   └── fuzz_wildcard_match.rs
├── corpus/                 # Inputs de prueba (generado)
│   ├── fuzz_path_pattern/
│   ├── fuzz_policy_from_toml/
│   └── fuzz_wildcard_match/
└── artifacts/              # Crashes encontrados (generado)
    ├── fuzz_path_pattern/
    ├── fuzz_policy_from_toml/
    └── fuzz_wildcard_match/
```

## Referencia

- [cargo-fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
