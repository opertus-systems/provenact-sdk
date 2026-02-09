# provenact-sdk

[![Compatibility](https://img.shields.io/badge/compatibility-provenact_pinned-blue)](./COMPATIBILITY.md)
[![Status](https://img.shields.io/badge/stability-0.x--alpha-orange)](./COMPATIBILITY.md)

Rust-first SDK for Provenact verify/execute/receipt flows.

Ecosystem map: `provenact-cli/docs/ecosystem.md` in the substrate repository.

This repository is intentionally thin in `0.x` and wraps `provenact-cli` to avoid
API drift while the substrate stabilizes.

## Scope

In scope:
- `verify_bundle(...)`
- `execute_verified(...)`
- `parse_receipt(...)`

Out of scope:
- agent loops
- planning/scheduling
- long-lived memory
- autonomous tool selection

## Install

```bash
cargo add provenact-sdk
```

## Prerequisite

`provenact-cli` must be available on `PATH` (or configure `CliRunner::new(...)` with
an explicit binary path).

If `keys_digest` is omitted, the SDK computes it from the provided keys file and
passes it to `provenact-cli`.

## Example

```rust
use std::path::PathBuf;
use provenact_sdk::{ExecuteRequest, ProvenactSdk, VerifyRequest};

let sdk = ProvenactSdk::default();

sdk.verify_bundle(VerifyRequest {
    bundle: PathBuf::from("./bundle"),
    keys: PathBuf::from("./public-keys.json"),
    keys_digest: None,
    require_cosign: false,
    oci_ref: None,
    allow_experimental: false,
})?;

let out = sdk.execute_verified(ExecuteRequest {
    bundle: PathBuf::from("./bundle"),
    keys: PathBuf::from("./public-keys.json"),
    keys_digest: None,
    policy: PathBuf::from("./policy.json"),
    input: PathBuf::from("./input.json"),
    receipt: PathBuf::from("./receipt.json"),
    require_cosign: false,
    oci_ref: None,
    allow_experimental: false,
})?;

let receipt = sdk.parse_receipt(out.receipt_path)?;
println!("{}", receipt.raw["schema_version"]);
// Ok::<(), provenact_sdk::SdkError>(())
```

## Versioning

- `0.x`: fast iteration, minimal stability guarantees outside documented API.
- `1.0`: after substrate API and conformance invariants are frozen.
- Pin details: `COMPATIBILITY.md` maps SDK versions to tested substrate commits.

## TypeScript SDK

A TypeScript mirror package lives at `/typescript` with the same stable surface:
- `verifyBundle(...)`
- `executeVerified(...)`
- `parseReceipt(...)`
- `experimental.validateManifestV1(...)`
- `experimental.validateReceiptV1(...)`

Run locally:

```bash
cd typescript
npm ci
npm run check
npm test
```

## CI

- `.github/workflows/ci.yml` runs format, clippy, tests, and example checks.
- `.github/workflows/conformance-smoke.yml` runs SDK smoke against substrate
  vectors by checking out a `provenact-cli` repo and building `provenact-cli`.

## Local Conformance Smoke

Run smoke tests against a local substrate checkout:

```bash
PROVENACT_VECTOR_ROOT=../provenact-cli \
PROVENACT_CLI_BIN=../provenact-cli/target/debug/provenact-cli \
cargo test --test conformance_smoke -- --nocapture
```

If `PROVENACT_CLI_BIN` is not set, the test attempts to build `provenact-cli` from
`PROVENACT_VECTOR_ROOT` (or from sibling `../provenact-cli`).
