# @inactu/sdk (TypeScript)

[![Compatibility](https://img.shields.io/badge/compatibility-inactu_pinned-blue)](../COMPATIBILITY.md)
[![Status](https://img.shields.io/badge/stability-0.x--alpha-orange)](../COMPATIBILITY.md)

TypeScript mirror of the Rust `inactu-sdk` alpha surface.

## Stable API (`0.x`)

- `verifyBundle(req)`
- `executeVerified(req)`
- `parseReceipt(path)`

`req.keysDigest` is required for both `verifyBundle` and `executeVerified`.

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
INACTU_VECTOR_ROOT=../../inactu \
INACTU_CLI_BIN=../../inactu/target/debug/inactu-cli \
npm test
```

Compatibility pinning is tracked in [`../COMPATIBILITY.md`](../COMPATIBILITY.md).
