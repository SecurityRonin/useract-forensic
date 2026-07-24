# 4. Emit findings through the `forensicnomicon::report` model as observations

Date: 2026-07-24
Status: Accepted

## Context

Every analyzer in the fleet must feed one uniform reporting vocabulary so
ORCHESTRATION (issen) and a future GUI render findings uniformly instead of N bespoke
`XxxAnalysis` types (`~/src/ronin-issen/CLAUDE.md`, "The Reporting Model —
`forensicnomicon::report`"). A correlation layer that invented its own finding type
would break that aggregation. Separately, the fleet epistemology is binding: a finding
is an *observation* ("consistent with …"), never a legal conclusion — the examiner or
tribunal concludes.

## Decision

Emit findings as `forensicnomicon::report::Finding` (`src/lib.rs:41`, `audit` /
`audit_with` at `src/lib.rs:928`/`934`), stamped with a `Source { analyzer:
"useract-forensic", scope, version }` built by the `source()` helper
(`src/lib.rs:852`). Codes follow the published scheme-prefixed SCREAMING-KEBAB contract
— `USERACT-FILE-ON-EXTERNAL-DEVICE`, `USERACT-NETWORK-EXFIL-VOLUME`,
`USERACT-EXEC-DURING-REMOVABLE-MEDIA`, `USERACT-HISTORY-TAMPERED`. MITRE techniques are
attached with `ExternalRef::mitre_attack(...)` (e.g. `src/lib.rs:1049-1050`,
`1083-1084`) and every `note` is worded as consistency ("consistent with bulk data
exfiltration", `src/lib.rs:1077`), never a verdict. The crate docs make the discipline
explicit: "Every finding is an **observation** (\"consistent with …\"); the examiner
draws the conclusions" (`src/lib.rs:11`).

## Consequences

issen aggregates `useract-forensic` findings into one `Report` alongside every other
analyzer with no adapter. Anomaly codes are a stable published contract — a shipped
code is never repurposed; a new signal gets a new code. Severity is graded per finding
(mostly `Medium`/`Low`), and hedged wording plus MITRE-as-consistency keeps the output
within the observation layer, defensible in an expert-report context. The crate takes a
hard dependency on `forensicnomicon` and its release cadence.
