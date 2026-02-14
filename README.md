# provenact-sdk

[![Compatibility](https://img.shields.io/badge/compatibility-provenact_pinned-blue)](./COMPATIBILITY.md)
[![Status](https://img.shields.io/badge/stability-0.x--alpha-orange)](./COMPATIBILITY.md)

Rust-first SDK for Provenact verify/execute/receipt flows.

Ecosystem map: `provenact/docs/ecosystem.md` in the substrate repository.

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

By default, `CliRunner` requires an absolute `provenact-cli` path
(`CliRunner::new("/abs/path/to/provenact-cli")`).
Set `PROVENACT_ALLOW_PATH_CLI=1` to opt into `PATH` lookup.

## Example

```rust
use std::path::PathBuf;
use provenact_sdk::{ExecuteRequest, ProvenactSdk, VerifyRequest};

let sdk = ProvenactSdk::default();

sdk.verify_bundle(VerifyRequest {
    bundle: PathBuf::from("./bundle"),
    keys: PathBuf::from("./public-keys.json"),
    keys_digest: Some("sha256:<public-keys-json-digest>".to_string()),
    require_cosign: false,
    oci_ref: None,
    cosign_key: None,
    cosign_cert_identity: None,
    cosign_cert_oidc_issuer: None,
    allow_experimental: false,
})?;

let out = sdk.execute_verified(ExecuteRequest {
    bundle: PathBuf::from("./bundle"),
    keys: PathBuf::from("./public-keys.json"),
    keys_digest: Some("sha256:<public-keys-json-digest>".to_string()),
    policy: PathBuf::from("./policy.json"),
    input: PathBuf::from("./input.json"),
    receipt: PathBuf::from("./receipt.json"),
    require_cosign: false,
    oci_ref: None,
    cosign_key: None,
    cosign_cert_identity: None,
    cosign_cert_oidc_issuer: None,
    allow_experimental: false,
})?;

let receipt = sdk.parse_receipt(out.receipt_path)?;
println!("{}", receipt.raw["schema_version"]);
// Ok::<(), provenact_sdk::SdkError>(())
```

When `require_cosign` is `true`, set all of: `oci_ref`, `cosign_key`,
`cosign_cert_identity`, and `cosign_cert_oidc_issuer`.
`keys_digest` must use `sha256:<64 lowercase hex>`.
`parse_receipt` only accepts regular files up to 1 MiB.

## Versioning

- `0.x`: fast iteration, minimal stability guarantees outside documented API.
- `1.0`: after substrate API and conformance invariants are frozen.
- Pin details: `COMPATIBILITY.md` maps SDK versions to tested `provenact` commits.

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
  vectors by checking out an `provenact` repo and building `provenact-cli`.

## Local Conformance Smoke

Run smoke tests against a local substrate checkout:

```bash
PROVENACT_VECTOR_ROOT=../provenact-cli \
PROVENACT_CLI_BIN=../provenact-cli/target/debug/provenact-cli \
cargo test --test conformance_smoke -- --nocapture
```

If `PROVENACT_CLI_BIN` is not set, the test attempts to build `provenact-cli` from
`PROVENACT_VECTOR_ROOT` (or from sibling `../provenact-cli`).
