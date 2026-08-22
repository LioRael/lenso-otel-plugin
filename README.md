# Lenso OpenTelemetry Module

A removable OpenTelemetry Module for Lenso applications. It consumes the
published Kernel and Native Execution Adapter Interfaces; observability
semantics do not live in the portable core.

The source was extracted from `LioRael/lenso` at monorepo commit
`67d21499548d07e92c2f6529d7c8345e58c067d9` under ADR 0064. Imported subtrees
retain their relevant Git history.

## Validation

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
bun test fixtures/otel/trace-context-conformance.test.ts
```
