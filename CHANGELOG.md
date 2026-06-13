# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [useract-forensic 0.1.0] — 2026-06-13

### Added — the user-activity correlation layer

- `UserActivity { timestamp, actor, action, subject, source, detail }` — the
  uniform event every source normalizes into.
- `Action` (`Executed`, `Accessed`, `Connected`, `Searched`, `Typed`,
  `HistoryTampered`), `Subject` (`Command`, `File`, `Folder`,
  `Device { id, volume_serial }`, `Query`), and the `#[non_exhaustive]`
  `SourceKind` (`ShellHistory`, `PeripheralDevice`).
- `ActivitySource` trait — the v0.2 extension seam; new reader wrappers slot into
  `build_timeline` with no API change.
- Source adapters over the published reader crates:
  - `from_shell_history` / `ShellHistorySource` (consumes
    `shellhist_core::HistoryEntry`): command → `Executed`, a history-clearing
    command → `HistoryTampered`; actor carried when known.
  - `from_device_connections` / `DeviceSource` (consumes
    `peripheral_core::DeviceConnection`): connection → `Connected`, carrying the
    device id and **volume serial**; timestamp resolved
    `first_install` → `last_arrival` → `last_install`.
- `build_timeline` — merges any number of sources, sorted by epoch with
  `None`-timestamp events ordered stably at the end.
- `audit` / `audit_with` — cross-source findings, every one a hedged observation:
  - `USERACT-EXEC-DURING-REMOVABLE-MEDIA` (Low / Threat) — a command executed
    within an hour of a removable mass-storage device connection; the
    mass-storage classification is derived structurally from the device instance
    id's enumerator via `peripheral_core::Bus`. MITRE T1052 / T1091.
  - `USERACT-HISTORY-TAMPERED` (Medium / Concealment) — a history-clearing
    activity present in the timeline. MITRE T1070.003.
- `device_file_volume_joins` — the generic volume-serial join seam, implemented
  over `UserActivity` and tested by construction so a v0.2 LNK / shellbag source
  activates it with zero code change.
- `source(scope)` — stamps the analyzer provenance on emitted findings.

### Security

- `#![forbid(unsafe_code)]`; the workspace denies `clippy::unwrap_used` and
  `clippy::expect_used` in production code. Correlation is panic-free.

### Testing

- 100% library line coverage; `clippy -D warnings` clean; `cargo fmt` clean.
- Real-data integration test (`tests/real_data.rs`) over a genuine `bash`-authored
  `.bash_history` file (decoded with the published `shellhist_core::parse_auto`)
  plus a real `peripheral_core::DeviceConnection`: asserts the timeline merges
  across both sources in epoch order and that both v0.1 findings fire.
