# Contributing to useract-forensic

Thanks for your interest. `useract-forensic` is the user-activity correlation
layer of the SecurityRonin forensic fleet — it consumes published reader crates and
emits cross-source `forensicnomicon::report::Finding`s.

## Test-Driven Development is mandatory

All changes follow strict Red-Green-Refactor:

1. **RED** — write failing tests that define the new behavior; run them, confirm
   they fail.
2. **GREEN** — write the minimal implementation to pass; run them, confirm green.
3. **REFACTOR** — clean up while keeping tests green.

The RED commit (failing tests only) and the GREEN commit (implementation) are
**separate commits**. The RED commit is the verifiable proof that the tests came
first.

## Quality gates

All of the following must pass locally and in CI before a PR can merge:

```bash
cargo fmt --all -- --check                              # formatting
cargo clippy --workspace --all-targets -- -D warnings   # lints, warnings denied
cargo deny check                                        # license / advisory / source policy
cargo test --workspace                                  # unit + integration
cargo llvm-cov --lib --show-missing-lines               # 100% line coverage
```

- **Formatting** — `cargo fmt`; do not hand-format.
- **Lints** — `cargo clippy` with warnings denied; production code keeps
  `unwrap_used` / `expect_used` as hard denies.
- **Dependencies** — `cargo deny` must pass (no copyleft, no flagged advisories).
- **Coverage** — 100% library line coverage; a genuinely-unreachable defensive arm
  is annotated `// cov:unreachable: <invariant>`, never deleted to win a coverage
  point.

## Adding a new source (v0.2 and beyond)

A new per-user source is added by implementing `ActivitySource` over the relevant
published reader crate's output type and mapping it into `UserActivity`. It must
not break the existing model: add a new `SourceKind` / `Action` / `Subject` variant
(the shared enums are `#[non_exhaustive]`) and a new `USERACT-*` code rather than
changing an existing one. Validate the adapter against real artifacts, not only
synthetic fixtures.

## Robustness expectations

This crate correlates attacker-controllable, already-decoded evidence. Code must be
panic-free, must never assume a source populated a given field, and must surface
findings only as hedged observations ("consistent with …"), never as verdicts.

## Commits and signing

Commits are signed (gitsign). End commit messages with:

```
Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.
