# 6. `forbid(unsafe)` and panic-free-by-lint (Paranoid Gatekeeper)

Date: 2026-07-24
Status: Accepted

## Context

Although `useract-forensic` parses no byte format, it correlates events that upstream
readers decoded from **attacker-controllable evidence** — a crafted `.bash_history`,
a spoofed device-instance id, a hostile LNK volume id. A panic or out-of-bounds access
triggered by such a value would crash the whole correlation pass and take the
investigation's output with it. The fleet Paranoid Gatekeeper standard
(`~/src/ronin-issen/CLAUDE.md`) requires these crates to never panic and never trust a
value. Unlike the mmap-based readers (`ewf`, `memory-forensic`) that must downgrade to
`unsafe_code = "deny"` for one bounded `unsafe`, this crate has no FFI, no raw pointers,
and no memory-mapping need at all.

## Decision

Adopt the strongest posture, with no exception carved out:

- `#![forbid(unsafe_code)]` at the crate root (`src/lib.rs:39`) and
  `unsafe_code = "forbid"` in `[workspace.lints.rust]` (`Cargo.toml:46`). `forbid`
  (not `deny`) is correct here because nothing in the crate needs `unsafe`, so there
  is no per-site allow to preserve — the strongest, badge-able guarantee.
- Panic-free by lint: `[workspace.lints.clippy]` denies `unwrap_used` and
  `expect_used` in production code (`Cargo.toml:53-54`), with `correctness` and
  `suspicious` at `deny` and the fleet's canonical pedantic allow-list. The
  `Cargo.toml` comment records the intent: "Paranoid Gatekeeper: this crate consumes
  attacker-controllable, already-decoded user-activity events and correlates them.
  Never panic, never trust a value."

Correlation degrades gracefully — a value that cannot be interpreted is skipped, not
unwrapped. Defensive guard arms unreachable under a current invariant are kept and
annotated rather than deleted for coverage (commit `718f9af`, "annotate defensive
guards").

## Consequences

The crate earns the `unsafe forbidden` badge honestly (README row 2) — memory-safety
is proven by the compiler, not asserted. `unwrap`/`expect` in production is a hard
compile error, forcing every fallible step to handle absence explicitly, which suits a
model full of `Option` fields. Tests may still `unwrap` (the standard test carve-out).
The posture is verifiable and needs no per-site audit surface, since there is no
`unsafe` at all.
