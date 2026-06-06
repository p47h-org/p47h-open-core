# Threat model — what the local layer protects, and what it does not

> Honesty contract: this document states what `p47h-open-core` (the local Rust/WASM layer
> behind **P47H Vault**) defends against **today**, in the present tense, and what it does
> **not**. The **distributed** guarantees (a Trust Anchor, signed policy distribution,
> mesh convergence, mergeable cross-node audit) belong to the **P47H Pro** layer and are
> **roadmap** — they are NOT provided by the local layer and must never be attributed to
> Vault. A reader auditing this repo should find no gap between this page and the code.

## The local layer (Vault / open-core) — what it IS

A single-device, single-identity, **stateless** cryptographic core:

- Ed25519 identity (a DID) generated and used inside WASM linear memory.
- Argon2id key derivation; XChaCha20-Poly1305 authenticated encryption for data at rest.
- A stateless policy **evaluation** engine (`core-policy`): given a policy and a request,
  it deterministically returns allow/deny. It evaluates; it does not distribute, sign, or
  converge policy, and there is no authority in this layer.

## Protected TODAY (in scope, present tense)

| Threat | How the local layer addresses it |
| --- | --- |
| Secrets readable in `localStorage`/cookies by injected scripts | Secrets are encrypted (XChaCha20-Poly1305) before they reach storage; the persisted blob is ciphertext, not plaintext. |
| Private key exposed to the JS heap | Keys live in WASM linear memory and are **zeroized on lock**; they are never returned to JavaScript in plaintext. |
| Offline brute-force of a stolen encrypted blob | Argon2id (OWASP params) makes password guessing expensive. |
| Silent tampering of the encrypted blob | Authenticated encryption (Poly1305 tag) makes tampering detectable on decrypt. |
| Weak/DIY browser crypto | One audited Rust core compiled to WASM, deterministic across platforms — not hand-rolled WebCrypto. |
| Local signing | The identity can produce Ed25519 signatures with a key that never leaves WASM. |

## NOT protected / explicitly out of scope for the local layer

- **A compromised page/origin while the vault is UNLOCKED.** XSS or malicious code running
  in your origin with an unlocked vault can ask the vault to decrypt or sign. The vault
  **reduces** blast radius versus plaintext `localStorage` (keys are not in the JS heap,
  data is encrypted at rest, locking wipes memory) but it is **not** a defense against
  arbitrary code execution in your own page. Keep the vault locked when idle; ship a strict
  CSP.
- **Host malware with live memory access** while unlocked.
- **Weak passwords.** Argon2id slows guessing; it cannot rescue a trivial password.
- **Phishing / social engineering.**
- **Any multi-party or cross-device trust.** The local layer has **no authority**, no peer
  trust, no role/claim issuance, no revocation propagation. A local policy decision proves
  *"this key evaluated this request against this policy"* — **not** *"an authority
  sanctioned this policy"*. Self-attestation is not authorization by a third party.

## What the DISTRIBUTED layer (Pro) adds — ROADMAP, not in Vault

These are **not** in `p47h-open-core` / Vault and are not promised in the present tense:

- A **Trust Anchor** that signs policy and role/claim assignments (authority, not
  self-assertion).
- **Signed policy distribution** and deterministic, partition-tolerant **convergence**
  across nodes.
- A cryptographic, append-only, **mergeable audit** chain across a mesh.
- **Offline / edge authorization** whose decisions remain auditable and explainable.

> The line that must never blur: a local signature proves a **key** acted; an authority's
> sanction requires the Pro Trust Anchor layer, which is roadmap. Do not let local
> self-attestation be presented as distributed proof.
