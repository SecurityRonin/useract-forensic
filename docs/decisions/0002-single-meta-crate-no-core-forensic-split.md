# 2. Single meta crate — no `core/` + `forensic/` split

Date: 2026-07-24
Status: Accepted

## Context

The fleet crate-structure standard (`~/src/ronin-issen/CLAUDE.md`, "Crate-structure
standard") mandates a two-crate `<x>-core` (reader) + `<x>-forensic` (analyzer) split
for every *format* repo, because a robust reader abstracts away exactly the raw layout
a forensic auditor must see. That standard is written for repos that read a byte
format. `useract-forensic` reads no byte format: it consumes already-decoded events
from other crates and correlates them (ADR 0001). There is no reader to separate from
an analyzer — the "reader" work happens in the upstream fleet crates.

## Decision

Ship `useract-forensic` as a **single meta crate**, not a `core/` + `forensic/`
workspace. `Cargo.toml` declares one `[package]` (`useract-forensic`, `Cargo.toml:2`)
with a nested `[workspace]` used only to host the shared `[workspace.lints]` table
(`Cargo.toml:40-67`); the whole implementation is one `src/lib.rs`. The crate name
keeps the `-forensic` suffix because it is the analyzer/correlator — the thing that
emits findings — even though there is no companion `-core` reader. This matches the
fleet layer map, which lists `useract-forensic` as a single ORCHESTRATION-layer repo,
not a `core`+`forensic` pair.

## Consequences

The two-crate split's benefit (a low-MSRV reader reusable apart from the analyzer)
does not apply, because there is no reader to reuse — so a single crate is the honest
shape, not a shortcut. The whole surface is one publishable library; a consumer that
wants only the `UserActivity` model still pulls the correlation code, which is
acceptable given how small it is. If a future need arises to publish the normalized
`UserActivity`/`ActivitySource` types independently of the audit logic, that would be
the trigger to revisit the split — nothing today warrants it.
