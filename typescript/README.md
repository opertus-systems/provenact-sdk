# @provenact/sdk (TypeScript)

[![Compatibility](https://img.shields.io/badge/compatibility-provenact_pinned-blue)](../COMPATIBILITY.md)
[![Status](https://img.shields.io/badge/stability-0.x--alpha-orange)](../COMPATIBILITY.md)

TypeScript mirror of the Rust `provenact-sdk` alpha surface.

## Stable API (`0.x`)

- `verifyBundle(req)`
- `executeVerified(req)`
- `parseReceipt(path)`

## Experimental API

- `experimental.validateManifestV1(runner, manifestPath)`
- `experimental.validateReceiptV1(runner, receiptPath)`

## Development

```bash
npm ci
npm run check
npm test
```

## Smoke Test Against Local Substrate

```bash
PROVENACT_VECTOR_ROOT=../../provenact-cli \
PROVENACT_CLI_BIN=../../provenact-cli/target/debug/provenact-cli \
npm test
```

Compatibility pinning is tracked in [`../COMPATIBILITY.md`](../COMPATIBILITY.md).
