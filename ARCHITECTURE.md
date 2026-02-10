# Architecture

## Boundary

`provenact-sdk` is a client library for execution workflows.
It does not perform orchestration decisions.

## Design (0.1 alpha)

- Public API exposes three stable operations:
  - verify bundle
  - execute verified bundle
  - parse receipt JSON
- Implementation delegates to `provenact-cli` for behavioral parity with substrate
  conformance tests.
- Experimental operations live in the `experimental` module.

## Future Direction

- Keep API minimal while substrate evolves.
- Add a native library backend once parity and invariants are stable.
- Maintain fixture-driven behavior parity between Rust and TypeScript SDKs.
