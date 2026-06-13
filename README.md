# useract-forensic

[![useract-forensic](https://img.shields.io/crates/v/useract-forensic.svg?label=useract-forensic)](https://crates.io/crates/useract-forensic)
[![Docs.rs](https://img.shields.io/docsrs/useract-forensic)](https://docs.rs/useract-forensic)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/useract-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/useract-forensic/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security advisories](https://img.shields.io/badge/advisories-clean-success.svg)](deny.toml)

**One per-user timeline from many artifacts — `useract-forensic` merges shell history, device connections, and (soon) LNK / shellbags / SRUM / registry MRU into a single `UserActivity` stream and surfaces the cross-source signals no one artifact can show: a command run while a USB stick was mounted, history wiped right after a payload ran.**

It is the **correlation layer**, not another parser. It consumes the forensic fleet's already-built reader crates and normalizes their output into one uniform event — so "who did what, when, to which file / program / folder / device" reads off a single sorted list, with graded findings attached.

## 30 seconds: merge two sources, get cross-source findings

```rust
use useract_forensic::{build_timeline, audit, ShellHistorySource, DeviceSource};

// Decode each source with its own published reader crate …
let entries = shellhist_core::parse_auto(history_bytes, Some(".bash_history"));
let devices = peripheral_core::setupapi::parse(setupapi_bytes);

// … then correlate them here.
let shell = ShellHistorySource::new(&entries);
let usb   = DeviceSource::new(&devices);

let timeline = build_timeline(&[&shell, &usb]);   // merged, sorted by epoch
for finding in audit(&timeline) {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // [Some(Low)]    USERACT-EXEC-DURING-REMOVABLE-MEDIA — the command "tar … /media/usb" ran within …
    // [Some(Medium)] USERACT-HISTORY-TAMPERED            — user activity "unset HISTFILE" disables …
}
```

## What it normalizes into

Every source collapses into one event type:

```rust
pub struct UserActivity {
    pub timestamp: Option<i64>,   // Unix epoch, when the source records it
    pub actor:     Option<String>,// user / SID, when the source attributes it
    pub action:    Action,        // Executed | Accessed | Connected | Searched | Typed | HistoryTampered
    pub subject:   Subject,       // Command | File | Folder | Device{id, volume_serial} | Query
    pub source:    SourceKind,    // which reader produced it
    pub detail:    String,
}
```

A new source is one `impl ActivitySource { fn activities(&self) -> Vec<UserActivity> }` away — it slots straight into `build_timeline` with no API change.

## v0.1 sources, and the v0.2 roadmap

| Source | Crate | Action | Status |
|---|---|---|---|
| Shell command history (bash/zsh/fish/PowerShell) | [`shellhist-core`](https://crates.io/crates/shellhist-core) | `Executed` / `HistoryTampered` | ✅ v0.1 |
| External device connections (`setupapi.dev.log`) | [`peripheral-core`](https://crates.io/crates/peripheral-core) | `Connected` (+ volume serial) | ✅ v0.1 |
| Recent-file LNK (and the volume serial that completes the device join) | `lnk-core` | `Accessed` (File) | v0.2 |
| Shellbags (folder access) | `shellbag-core` | `Accessed` (Folder) | v0.2 |
| Per-user app exec + network bytes **by SID** | `srum-core` | `Executed` / `Connected` (actor!) | v0.2 |
| UserAssist / RecentDocs / MRU / MountPoints2 | `winreg-artifacts` | `Executed` / `Accessed` | v0.2 |

The v0.2 sources need those reader crates published first. SRUM is the strongest — the first source that attributes activity to a specific **SID**. See [`docs/roadmap.md`](docs/roadmap.md).

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `USERACT-EXEC-DURING-REMOVABLE-MEDIA` | Low | Threat | A shell command executed within an hour of a removable mass-storage device being connected (temporal cross-source join) — consistent with activity involving external media (MITRE T1052 / T1091) |
| `USERACT-HISTORY-TAMPERED` | Medium | Concealment | A history-clearing activity present in the timeline — consistent with anti-forensic history tampering (MITRE T1070.003) |

A **volume-serial join** seam (`device_file_volume_joins`) is implemented generically over `UserActivity` today and tested by construction; it activates with zero code change the moment a v0.2 LNK / shellbag source contributes a file subject carrying a volume serial.

## Trust, but verify

`useract-forensic` consumes attacker-controllable, already-decoded evidence and correlates it:

- **`#![forbid(unsafe_code)]`** — no FFI, no C bindings, no raw pointers.
- **Panic-free** — the workspace denies `clippy::unwrap_used` and `clippy::expect_used` in production code; correlation degrades gracefully, never crashes.
- **100% line coverage** on the library, `clippy -D warnings` clean.
- **Validated on real artifacts** — the integration test feeds a `.bash_history` file written by a genuine `bash` subshell (decoded with the published `shellhist_core::parse_auto`) plus a real `peripheral_core::DeviceConnection`, and asserts the timeline merges and both findings fire (`tests/real_data.rs`).

```bash
cargo add useract-forensic
cargo test
```

---

[Privacy Policy](https://securityronin.github.io/useract-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/useract-forensic/terms/) · © 2026 Security Ronin Ltd
