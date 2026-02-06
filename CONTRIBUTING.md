# Contributing

## Scope Guardrails

`inactu-sdk` is an SDK layer over Inactu substrate behavior.

Allowed:
- stable SDK ergonomics for verify/execute/receipt flows
- conformance parity with pinned substrate behavior
- improved diagnostics and developer UX

Not allowed:
- introducing orchestration or agent-loop behavior
- changing substrate trust semantics in the SDK layer

## Development Standards

- Keep API additions explicit and documented.
- Update `COMPATIBILITY.md` when substrate pinning changes.
- Add tests for any behavior change.
- Run local checks before PR:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

## Security Reporting

See `SECURITY.md` for responsible disclosure guidance.
