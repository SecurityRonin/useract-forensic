# useract-forensic — Purpose & Scope

*Library-tier intent doc (per the fleet PRD & ADR Standard: a library gets a concise
Purpose & Scope, not a full product PRD). Every current-state claim is grounded in a
same-session read of `src/lib.rs`, `Cargo.toml`, `README.md`, and the git history
(2026-07-24). Load-bearing decisions live as ADRs under
[`docs/decisions/`](decisions/).*

## What it is

`useract-forensic` is the fleet's **user-activity correlation layer** — a thin
meta / orchestration crate that merges many decoded forensic artifacts into one
normalized per-user timeline and emits the cross-source findings no single artifact
can produce alone. It parses no raw byte format itself; it consumes already-decoded
types from the fleet reader crates and correlates them
([ADR 0001](decisions/0001-orchestration-correlation-layer-no-parsing.md)).

It sits in the **ORCHESTRATION** layer of the fleet architecture, below issen and
above the reader crates: issen (and any future GUI) links it to fold its findings into
one aggregated `forensicnomicon::report::Report`.

## Who links it

- **issen** — the fleet orchestrator, as the `useract`-family correlation input.
- Any Rust tool that has already decoded one or more of the supported artifacts (via
  the fleet reader crates) and wants a single merged `UserActivity` timeline plus
  graded cross-source findings, off one API.

It is a library — `cargo add useract-forensic` and call `build_timeline` / `audit`.
It ships no binary an examiner runs; the runnable surface is issen's CLI.

## What it does

- **Normalizes** every source into one `UserActivity` event (*who / what / when / to
  which subject / from where*) behind the `ActivitySource` trait — the single
  extension seam ([ADR 0003](decisions/0003-normalized-useractivity-and-activitysource-seam.md)).
- **Merges and sorts** all sources into one epoch-ordered timeline
  (`build_timeline`).
- **Audits** the merged timeline for cross-source signals and emits them as
  observations through the shared `forensicnomicon::report` model
  ([ADR 0004](decisions/0004-findings-via-forensicnomicon-report.md)).

### Sources (current)

| Source | Reader crate | Contributes |
|---|---|---|
| Shell command history (bash/zsh/fish/PowerShell) | `shellhist-core` | `Executed` / `HistoryTampered` |
| External-device connections (`setupapi.dev.log`) | `peripheral-core` | `Connected` (+ volume serial) |
| Per-user app exec + network bytes **by SID** | `srum-parser` / `srum-core` | `Executed` (actor-attributed) |
| UserAssist / TypedURLs / ShellBags | `winreg-artifacts` | `Executed` / `Typed` / `Accessed` |
| Recent-file LNK targets + Jump Lists | `lnk-core` | `Accessed` (File + volume serial) |
| Apple Biome `App.MenuItem` (macOS Tahoe 26+) | `segb-core` | `MenuSelected` |

SRUM is the first source that attributes activity to a specific **SID**, resolving the
SRUM integer foreign keys through the `SruDbIdMapTable`.

### Findings (published anomaly-code contract)

| Code | Severity | Category | Observes |
|---|---|---|---|
| `USERACT-FILE-ON-EXTERNAL-DEVICE` | Medium | Threat | File/folder on a volume whose serial matches a connected external device (LNK ⋈ peripheral volume-serial join) |
| `USERACT-NETWORK-EXFIL-VOLUME` | Medium | Threat | SRUM per-interval `bytes_sent` above a conservative 256 MiB lead threshold |
| `USERACT-EXEC-DURING-REMOVABLE-MEDIA` | Low | Threat | Shell command within one hour of a removable mass-storage connection |
| `USERACT-HISTORY-TAMPERED` | Medium | Concealment | A history-clearing activity present in the timeline |

Every finding is an **observation** ("consistent with …"); the examiner draws the
conclusions. MITRE techniques are narrated as consistency, never a verdict
([ADR 0005](decisions/0005-cross-source-joins-structural-and-graded.md)).

## Scope

- One normalized `UserActivity` model + `ActivitySource` trait seam.
- Merged epoch-ordered timeline construction.
- Cross-source joins — structural volume-serial equality, temporal windows, and a
  conservative graded exfiltration lead — as `forensicnomicon` findings.
- Correlation of the artifact families listed above, via their fleet reader crates.

## Non-goals

- **No format parsing.** Decoding `.bash_history`, `setupapi.dev.log`, SRUM ESE pages,
  registry hives, LNK/Jump Lists, or Biome SEGB containers is the reader crates' job;
  this crate only consumes their decoded output
  ([ADR 0001](decisions/0001-orchestration-correlation-layer-no-parsing.md)).
- **No `core/` + `forensic/` split.** There is no reader to separate from the analyzer
  ([ADR 0002](decisions/0002-single-meta-crate-no-core-forensic-split.md)).
- **No verdicts.** Findings state what is *consistent with* an interpretation; legal
  conclusions belong to the examiner or tribunal.
- **No binary / CLI / GUI.** The runnable surface is issen.
- **No I/O or acquisition.** Callers supply already-decoded events.

## Security & robustness posture

`#![forbid(unsafe_code)]` (no FFI, no raw pointers) and panic-free by lint —
`clippy::unwrap_used`/`expect_used` denied in production; correlation degrades
gracefully on a hostile value, never crashes
([ADR 0006](decisions/0006-forbid-unsafe-panic-free-by-lint.md)). The crate holds a low
CI-verified MSRV floor (1.81) distinct from the fleet dev toolchain pin
([ADR 0007](decisions/0007-low-msrv-floor-below-dev-pin.md)).

## Validation approach

100% library line coverage and `clippy -D warnings` clean. The integration test
(`tests/real_data.rs`) validates against a real `.bash_history` file written by a
genuine `bash` subshell and decoded with the published `shellhist_core::parse_auto`,
plus real `peripheral_core`, `lnk_core`, `srum_core`, and `winreg_artifacts` types —
asserting the timeline merges all sources in epoch order, the volume-serial join fires
`USERACT-FILE-ON-EXTERNAL-DEVICE`, and SRUM activity is actor-attributed. Because this
crate correlates rather than decodes, its correctness rests on the reader crates'
own validation for the decode step and on this test for the correlation logic.
