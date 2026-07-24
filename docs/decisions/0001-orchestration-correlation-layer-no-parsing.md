# 1. Orchestration correlation layer — consume fleet reader crates, parse nothing

Date: 2026-07-24
Status: Accepted

## Context

Digital-forensic "user activity" is scattered across unrelated artifacts: shell
command history, external-device connection logs, SRUM per-user usage, registry
UserAssist/TypedURLs/ShellBags, Shell Link (`.lnk`) targets and Jump Lists, and
Apple Biome menu-item records. Each already has a dedicated reader crate in the
SecurityRonin fleet. The signals that matter for an investigation, though, are the
ones no single artifact can show alone — a file opened from a USB stick that was
plugged in, a command run while a stick was mounted, history wiped right after a
payload ran. Re-decoding any of those formats here would fork format knowledge that
already lives, tested and fuzzed, in the reader crates.

The fleet layer map (`~/src/ronin-issen/CLAUDE.md`) places `useract-forensic` in the
**ORCHESTRATION** layer: "user-activity correlation: merges shell-history +
peripheral-device + Biome App.MenuItem events into one per-user timeline."

## Decision

Build `useract-forensic` as a thin **meta / orchestration** crate that parses no raw
format itself. It depends *up* on already-decoded fleet reader types and correlates
their output. The crate docs state this directly (`src/lib.rs:1`: "A thin **meta /
orchestration** crate: it does not parse any raw format itself"), and every
dependency in `Cargo.toml:27-35` is a fleet reader crate or `forensicnomicon` — plus
`chrono` for epoch math:

- `shellhist-core`, `peripheral-core`, `srum-parser`/`srum-core`, `winreg-artifacts`,
  `lnk-core`, and `segb-core` (imported as `segb` via `package = "segb-core"`,
  `Cargo.toml:35`) supply the decoded events;
- `forensicnomicon` supplies the shared reporting vocabulary.

Consuming fleet crates rather than a third party also satisfies the fleet
**dependency-preference** rule ("Always prefer our own crates").

## Consequences

Format knowledge stays single-sourced: a fix in `lnk-core` or `srum-core` flows here
on a version bump, with no parser to keep in sync. The crate carries no untrusted-byte
parsing surface of its own — it correlates values that upstream readers already
decoded and range-checked. The dependency graph is wide (seven fleet crates), so a
breaking change in any reader's public types (e.g. the `forensicnomicon` 0.5 → 0.11 →
1.0 sweep, commits `e003d85`, `81899a9`) is a coordinated bump here. Adding a new
artifact family means adding (or waiting for) its reader crate first, then a source
adapter (see ADR 0003).
