# 3. Normalized `UserActivity` event and the `ActivitySource` extension seam

Date: 2026-07-24
Status: Accepted

## Context

Each upstream reader emits its own record type: a `shellhist_core::HistoryEntry`, a
`peripheral_core::DeviceConnection`, a SRUM usage record, a `winreg_artifacts` entry,
a `lnk_core::ShellLink`/`JumpList`, a Biome `App.MenuItem`. To correlate across them —
sort one timeline, join a file to the device it lived on, window a command against a
device connection — they must share one shape. Cross-source joins are impossible while
every source speaks a different vocabulary.

## Decision

Collapse every source into one normalized event, `UserActivity` (`src/lib.rs:164`),
carrying *who* (`actor: Option<String>`), *what* (`action: Action`), *to which*
(`subject: Subject`), *when* (`timestamp: Option<i64>` Unix epoch), *from where*
(`source: SourceKind`), plus a human `detail`. `Action` and `Subject`
(`src/lib.rs:48`, `src/lib.rs:72`) are closed enums shaped by what the sources
actually produce — `Subject::File`/`Folder`/`Device` each carry an
`Option<u32> volume_serial` precisely so the volume-serial join (ADR 0005) has a key.

Every source implements one trait, `ActivitySource { fn activities(&self) ->
Vec<UserActivity> }` (`src/lib.rs:186`). `build_timeline(&[&dyn ActivitySource])`
(`src/lib.rs:825`) flat-maps all sources and stable-sorts by
`(timestamp.is_none(), timestamp)` so timestamped events order ascending and
untimestamped events keep source order at the end. Adding a source — SRUM (commit
`38b298a`), registry (`764e0c3`), LNK (`27a5191`), Jump Lists (`1dc85cf`), Biome
menu items (`f4a3df6`) — is one `impl ActivitySource` with no change to
`build_timeline` or `audit`.

## Consequences

New artifact families slot in behind one trait; the timeline and audit code never
change to accept them. `Option` timestamp/actor fields are honest: plain
`.bash_history` and PowerShell PSReadLine carry no timestamp, and most pre-SRUM
sources attribute no user — the model records that absence rather than fabricating a
value. The closed `Action`/`Subject` enums mean a genuinely new *kind* of activity or
subject requires a model edit (a deliberate, reviewable change) — as happened when
`Action::MenuSelected` and `SourceKind::BiomeMenuItem` were added for Biome
(`src/lib.rs:60`, `src/lib.rs:150`).
