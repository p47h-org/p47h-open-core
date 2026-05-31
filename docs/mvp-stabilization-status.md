# MVP Stabilization Status

Last updated: 2026-05-31

## Fase 1 — Desenredar git y versiones del open-core

| Paso | Estado | Detalle |
|------|--------|---------|
| 1.1 Diagnostico real | ✅ | Grafo verificado, versiones mapeadas |
| 1.2 Fechas CHANGELOG | ✅ | 0.10.2 = 2026-05-29 (fecha real del merge a origin/main) |
| 1.3 Decision FROST | ✅ | NO se mergea como driver de version. Rama viva sin version propia |
| 1.4 Consolidar fix no_std | ✅ | Rebase sobre main 0.10.2, 4 verificaciones en verde |
| 1.5 CHECKPOINT | 🟡 | Esperando OK humano |

### Verificaciones Fase 1

| Verificacion | Resultado |
|---|---|
| `cargo test --workspace --features toml` | ✅ Todos pasan, 0 failed |
| `cargo check -p core-policy --target thumbv7em-none-eabi` | ✅ Compila sin flags extra |
| `cargo check -p core-identity --target thumbv7em-none-eabi --no-default-features` | ✅ Compila |
| `cargo build -p p47h-engine --target wasm32-unknown-unknown` | ✅ Compila |

## Fase 2 — Bump a 0.11.0 y verificacion pre-publicacion

| Paso | Estado | Detalle |
|------|--------|---------|
| 2.1 Bump workspace a 0.11.0 | ⛔ | Pendiente OK Fase 1 |
| 2.2 CHANGELOG 0.11.0 | 🟡 | Seccion [Unreleased] preparada, se fija en bump |
| 2.3 Higiene crates.io | ⛔ | Pendiente |
| 2.4 CHECKPOINT critico | ⛔ | Pendiente |

## Fase 3 — Pro consume 0.11.0 desde crates.io

| Paso | Estado | Detalle |
|------|--------|---------|
| 3.1 Actualizar Cargo.toml de Pro | ⛔ | Requiere publicacion real en crates.io |
| 3.2 Verificar compilacion Pro | ⛔ | Pendiente |
| 3.3 CHECKPOINT | ⛔ | Pendiente |

## Fase 4 — Contratos tipados (ts-rs)

| Paso | Estado | Detalle |
|------|--------|---------|
| 4.1 Barrido handlers untyped | ⛔ | Pendiente |
| 4.2 Convertir a structs tipados | ⛔ | Pendiente |
| 4.3 Implementar ts-export | ⛔ | Pendiente |
| 4.4 Migrar frontend | ⛔ | Pendiente |
| 4.5 CHECKPOINT | ⛔ | Pendiente |

## Fase 5 — Features MUST del frontend

| Feature | Estado | Detalle |
|---------|--------|---------|
| a) Gestion de roles (CRUD) | ⛔ | Pendiente |
| b) Emision de tokens p47h-agent | ⛔ | Pendiente |
| c) Rotacion de clave admin | ⛔ | Pendiente |
| d) Revocacion de DIDs | ⛔ | Pendiente |

## Fase 6 — Paquete de despliegue MVP

| Paso | Estado | Detalle |
|------|--------|---------|
| 6.1 docker-compose.yml | ⛔ | Pendiente |
| 6.2 Dockerfile multi-stage | ⛔ | Pendiente |
| 6.3 Build reproducible | ⛔ | Pendiente |
| 6.4 Firma cosign | ⛔ | Pendiente |
| 6.5 Binario p47h-agent | ⛔ | Pendiente |
| 6.6 CHECKPOINT | ⛔ | Pendiente |

## Fase 7 — Docs despliegue

| Paso | Estado | Detalle |
|------|--------|---------|
| 7.1 quickstart.md | ⛔ | Pendiente |
| 7.2 bootstrap.md | ⛔ | Pendiente |
| 7.3 runbook.md | ⛔ | Pendiente |
| 7.4 CHECKPOINT | ⛔ | Pendiente |

## Comandos que requieren ejecucion humana

```bash
# Fase 2 — tras checkpoint aprobado
git push origin main && git push origin v0.11.0
cargo publish -p core-identity
cargo publish -p core-policy
cargo publish -p p47h-engine
gh release create v0.11.0 ...

# Fase 6 — firma de imagenes
cosign sign --key cosign.key <image-digest>
```
