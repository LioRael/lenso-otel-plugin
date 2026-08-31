# Plan 001: Bound individual OTel signal size and attribute cardinality

> Drift check: `git diff --stat 7ebdaa1..HEAD -- crates/lenso-otel-plugin/src/signal.rs crates/lenso-otel-plugin/src/export.rs crates/lenso-otel-plugin/src/config.rs crates/lenso-otel-plugin/tests`.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: perf
- **Planned at**: commit `7ebdaa1`, 2026-08-30

## Why this matters

Queue capacity counts signals, not bytes. One signal can contain an unbounded body or
attribute map and consume memory/export/backend resources despite a small queue.

## Current state

- `signal.rs:21-63` owns unbounded strings and maps.
- `export.rs:172-209` caps item count only.
- `export.rs:384-402` checks nonempty names, finite values, and nonempty keys only.

## Scope

In scope: explicit constants or validated config limits, signal validation, errors,
and tests. Out of scope: sampling policy and backend-specific cardinality aggregation.

## Steps

1. Define conservative documented limits for encoded signal bytes, name/body/unit
   lengths, attribute count, and key/value lengths using byte-based checks.
2. Reject violations as `InvalidSignal` before enqueue without cloning the full signal.
3. Add boundary tests for every field and one aggregate encoded-size case.

## Verification

- `cargo test -p lenso-otel-plugin` -> all pass.
- `cargo check -p lenso-otel-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if existing Runtime Diagnostic conversion can exceed a proposed limit during
normal operation; derive the limit from that bounded producer instead of exempting it.
