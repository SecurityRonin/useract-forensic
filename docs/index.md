# useract-forensic

**The user-activity correlation layer for the SecurityRonin forensic fleet.**

`useract-forensic` does not parse any raw format itself. It is the thin
**orchestration** crate that consumes the fleet's already-built reader crates,
normalizes their output into one uniform `UserActivity` event, builds a per-user
timeline, and emits cross-source findings that no single artifact could produce
alone — so "who did what, when, to which file / program / folder / device" reads
off a single sorted list.

## Merge two sources, get cross-source findings

```rust
use useract_forensic::{build_timeline, audit, ShellHistorySource, DeviceSource};

let entries = shellhist_core::parse_auto(history_bytes, Some(".bash_history"));
let devices = peripheral_core::setupapi::parse(setupapi_bytes);

let shell = ShellHistorySource::new(&entries);
let usb   = DeviceSource::new(&devices);

let timeline = build_timeline(&[&shell, &usb]);
for finding in audit(&timeline) {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
}
```

## The normalized event

```rust
pub struct UserActivity {
    pub timestamp: Option<i64>,
    pub actor:     Option<String>,
    pub action:    Action,   // Executed | Accessed | Connected | Searched | Typed | HistoryTampered
    pub subject:   Subject,  // Command | File | Folder | Device{id, volume_serial} | Query
    pub source:    SourceKind,
    pub detail:    String,
}
```

A new source is one `impl ActivitySource` away — it slots into `build_timeline`
with no API change. See the [roadmap](roadmap.md) for the v0.2 sources.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `USERACT-EXEC-DURING-REMOVABLE-MEDIA` | Low | Threat | A shell command executed within an hour of a removable mass-storage device being connected — consistent with activity involving external media (MITRE T1052 / T1091) |
| `USERACT-HISTORY-TAMPERED` | Medium | Concealment | A history-clearing activity present in the timeline — consistent with anti-forensic history tampering (MITRE T1070.003) |

## Trust, but verify

`#![forbid(unsafe_code)]`, panic-free (the workspace denies `unwrap`/`expect` in
production), 100% library line coverage, and validated end-to-end against a
genuine `bash`-authored history file plus a real `peripheral_core::DeviceConnection`.

---

[Privacy Policy](https://securityronin.github.io/useract-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/useract-forensic/terms/) · © 2026 Security Ronin Ltd
