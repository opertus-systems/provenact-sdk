# Security

## Principles

- No ambient authority: all file paths are caller supplied.
- No policy bypass: verification and execution are delegated to `inactu-cli`.
- No key handling in SDK internals beyond passing configured paths to CLI.

## Current Risk Envelope (0.1 alpha)

- The SDK shells out to `inactu-cli`; callers must trust the installed binary.
- For untrusted environments, callers should pass pinned `keys_digest`.

## Reporting

Report vulnerabilities privately to project maintainers before public disclosure.
