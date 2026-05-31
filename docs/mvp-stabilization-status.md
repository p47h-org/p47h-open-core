# MVP Stabilization Status

Last updated: 2026-05-31

## Fase 1 — Desenredar git y versiones del open-core

| Paso | Estado | Detalle |
|------|--------|---------|
| 1.1 Diagnostico real | ✅ | Grafo verificado, versiones mapeadas |
| 1.2 Fechas CHANGELOG | ✅ | 0.10.2 = 2026-05-29 (fecha real del merge a origin/main) |
| 1.3 Decision FROST | ✅ | NO se mergea como driver de version |
| 1.4 Consolidar fix no_std | ✅ | Merged a main via PR#3 (304c1eb) |
| 1.5 CHECKPOINT | ✅ | Aprobado por humano |

## Fase 2 — Bump a 0.11.0 y verificacion pre-publicacion

| Paso | Estado | Detalle |
|------|--------|---------|
| 2.1 Bump workspace a 0.11.0 | ✅ | Todas las versiones en 0.11.0 |
| 2.2 CHANGELOG 0.11.0 | ✅ | Seccion fijada con fecha 2026-05-31 |
| 2.3 Higiene crates.io | ✅ | READMEs, categories, keywords, documentation |
| 2.3a frost.rs eliminado | ✅ | Archivo commiteado por error, eliminado |
| 2.4 Dry-runs | 🟡 | core-identity ✅, core-policy ✅, p47h-engine/wasm-oss: packaging OK pero verificacion falla (esperado: deps no publicadas aun) |
| 2.5 CHECKPOINT CRITICO | 🟡 | Esperando OK humano |

### Verificaciones (todas sobre 0.11.0)

| Verificacion | Resultado |
|---|---|
| `cargo test --workspace --features toml` | ✅ 0 failed |
| `cargo check -p core-policy --target thumbv7em-none-eabi` | ✅ v0.11.0 |
| `cargo check -p core-identity --target thumbv7em-none-eabi --no-default-features` | ✅ v0.11.0 |
| `cargo build -p p47h-engine --target wasm32-unknown-unknown` | ✅ v0.11.0 |
| `cargo publish -p core-identity --dry-run` | ✅ packaged + verified |
| `cargo publish -p core-policy --dry-run` | ✅ packaged + verified |
| `cargo publish -p p47h-engine --dry-run` | ⚠️ packaging OK, verify fails (needs core-identity 0.11.0 on crates.io first) |
| `cargo publish -p p47h-wasm-oss --dry-run` | ⚠️ packaging OK, verify fails (needs p47h-engine 0.11.0 on crates.io first) |

## Comandos que requieren ejecucion humana

```bash
# 1. Commit y merge del release branch
git add -A && git commit -s -m "chore: release v0.11.0 ..."
# merge to main via PR o directo

# 2. Tag
git tag -s v0.11.0 -m "v0.11.0: genuine no_std for core-policy, honest metadata"

# 3. Push
git push origin main
git push origin v0.11.0

# 4. Publicar en ORDEN DE DEPENDENCIAS (esperar ~30s entre cada uno)
cargo publish -p core-identity
cargo publish -p core-policy
cargo publish -p p47h-engine
cargo publish -p p47h-wasm-oss   # si se publica

# 5. GitHub Release
gh release create v0.11.0 --title "v0.11.0" --notes-from-tag
```
