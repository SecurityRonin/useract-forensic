# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [useract-forensic 0.3.0] — 2026-06-13

### Added

- **Jump List ActivitySource** (`JumpListSource` / `from_jumplists`). Parsed
  `lnk-core` Jump Lists (`*.automaticDestinations-ms` /
  `*.customDestinations-ms`) become `Accessed` file events. The `DestList`
  last-access time is the authoritative timestamp (falling back to the embedded
  link's write time for custom destinations), and the embedded link's `VolumeID`
  drive serial is carried as the device-join key. New `SourceKind::JumpList`.

### Changed

- ShellBag activity now carries **real folder names** (via `winreg-artifacts`
  0.1.1, which decodes BagMRU slots through the `shellitem` primitive) instead of
  opaque size previews.
- Bumped the `lnk-core` dependency to 0.3 (Jump List types + `shellitem`-decoded
  `LinkTargetIDList`).

## [useract-forensic 0.2.0] — 2026-06-13

### Added — three new actor-rich sources

- **SRUM** (`from_srum` / `SrumSource`, over `srum-parser` / `srum-core`): each
  `NetworkUsageRecord` and `AppUsageRecord` → an `Executed` `UserActivity`. The
  integer `user_id` / `app_id` foreign keys are resolved through the
  `SruDbIdMapTable` (`IdMapEntry`) to a user SID and application path — SRUM is the
  first source that **attributes** activity to a specific user (`actor`). Network
  rows carry per-interval `bytes_sent` / `bytes_recv` in `detail`; app-usage rows
  carry foreground/background CPU cycles. Unresolved ids fall back to stable
  `user-id:<n>` / `app-id:<n>` tokens, never dropped.
- **Registry** (`from_registry` / `from_userassist` / `from_typed_urls` /
  `from_shellbags` / `RegistrySource`, over `winreg-artifacts`): UserAssist →
  `Executed` (program + run count + ROT13 last-run), TypedURLs → `Typed`
  (address-bar URL as a `Query`), ShellBags → `Accessed` (folder). ISO-8601
  artifact timestamps parsed to epoch; every event attributed to the hive owner.
- **LNK** (`from_lnk` / `LnkSource`, over `lnk-core`): each `ShellLink` → an
  `Accessed` `Subject::File` whose path is `link_info.local_base_path` (or the
  network target's UNC name) and whose `volume_serial` is the `VolumeID`
  `DriveSerialNumber`; the target's `write_time` becomes the timestamp.

### Added — model extensions (additive)

- `SourceKind` gains `Srum`, `Registry`, `LnkFile` (`#[non_exhaustive]`).
- `Subject::File` and `Subject::Folder` are now struct variants carrying an optional
  `volume_serial`, with `Subject::file(..)` / `Subject::folder(..)` constructors.
  The volume-serial join reads this structured field, keeping the `vol:` detail-token
  fallback.

### Added — findings (every one a hedged observation)

- `USERACT-FILE-ON-EXTERNAL-DEVICE` (Medium / Threat) — the **volume-serial join is
  now live**: an LNK file/folder on a volume whose serial matches a `Connected`
  external device. MITRE T1052 / T1091.
- `USERACT-NETWORK-EXFIL-VOLUME` (Medium / Threat) — a SRUM network row whose
  per-interval `bytes_sent` crosses the conservative `NETWORK_EXFIL_BYTES_THRESHOLD`
  (256 MiB); a graded **lead**, not a verdict. MITRE T1048 / T1052.

### Changed

- `forensicnomicon` bumped `0.4` → `0.5`. `chrono` added (ISO timestamp parsing).
- The real-data integration test now also constructs a genuine `ShellLink` +
  `DeviceConnection` sharing a serial, a SID-attributed SRUM row, and a UserAssist
  entry, asserting all sources merge in epoch order, the join fires, and SRUM is
  actor-attributed.

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
