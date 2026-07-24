# 7. Low CI-verified MSRV floor, separate from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain") draws a
hard line between the **dev toolchain** (what the fleet builds/fmt/clippy with — pinned
fleet-wide to the current stable) and the **declared MSRV** (`rust-version`, a
downstream-facing compatibility promise). For a *published library*, raising the
declared MSRV narrows its crates.io audience, so the floor is kept low and CI-verified
and raised only when a real newer-Rust need forces it. `useract-forensic` is a
published library (ADR 0002), consumed by issen and available on crates.io — so it must
keep the two apart, not conflate its dev pin with its promise.

## Decision

Declare a low MSRV distinct from the dev pin and verify it in CI:

- `rust-version = "1.81"` in `Cargo.toml:5` — the downstream promise.
- `rust-toolchain.toml` pins the **dev** toolchain to `1.96.0` (committed in
  `c388695`, "pin toolchain to 1.96.0 (fleet toolchain policy)") — what contributors
  and the main CI jobs build with.
- A dedicated `msrv` CI job builds on exactly 1.81
  (`.github/workflows/ci.yml:59-64`, `name: MSRV (1.81)`,
  `uses: dtolnay/rust-toolchain@1.81`), so the promise is a verified guarantee, not an
  aspiration.

## Consequences

Downstream consumers on a 1.81 toolchain can build the crate; the fleet still develops
on the newest stable. The floor is a real, tested contract — a change that needs a
newer feature turns the `msrv` job red rather than silently breaking a downstream
build. Raising 1.81 later is a deliberate, near-breaking decision requiring an explicit
reason, per policy.

The *exact* choice of 1.81 (rather than the fleet's more common 1.75/1.80 floor) is
most likely driven by the minimum a transitive fleet-reader dependency requires;
**rationale reconstructed from structure; original intent not recovered in available
history** for why 1.81 specifically rather than 1.80. The load-bearing decision — a low,
CI-verified floor kept below the dev pin — is fully grounded.
