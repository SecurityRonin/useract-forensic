# Security Policy

## Supported versions

The latest published `0.x` release receives security fixes. Pre-`1.0`, only the
most recent minor line is supported.

## Reporting a vulnerability

Please report security issues privately to
[albert@securityronin.com](mailto:albert@securityronin.com) rather than opening a
public issue. Include a description, affected version, and a reproducing input if
possible. You will receive an acknowledgement within a few business days.

## Security posture

`useract-forensic` correlates **attacker-controllable, already-decoded** forensic
evidence (shell-history entries, device-connection records, and the v0.2 sources to
come). It is built to fail safe:

- **`#![forbid(unsafe_code)]`** — no FFI, no raw pointers, no `unsafe` anywhere.
- **Panic-free production code** — the workspace denies `clippy::unwrap_used` and
  `clippy::expect_used`; missing or malformed fields degrade gracefully, never
  crash.
- **No network, no telemetry** — all processing is local.
- **Findings are observations, never verdicts** — the type system and the
  hedged-note convention keep the crate from asserting legal conclusions.

### Fuzzing

This crate parses no raw byte format of its own — it consumes the typed output of
reader crates that are themselves fuzzed at their parse boundary (e.g.
`shellhist-core`, `peripheral-core`). The fuzzing surface therefore lives in those
upstream crates; `useract-forensic`'s own logic is total over the typed inputs and
is covered to 100% by the test suite.
