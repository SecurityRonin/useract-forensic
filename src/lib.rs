//! `useract-forensic` — the user-activity correlation layer.
//!
//! A thin **meta / orchestration** crate: it does not parse any raw format
//! itself. It consumes already-decoded forensic reader types — today
//! [`shellhist_core::HistoryEntry`] and [`peripheral_core::DeviceConnection`] —
//! normalizes them into one uniform [`UserActivity`] event, builds a per-user
//! timeline, and emits cross-source [`forensicnomicon::report::Finding`]s that no
//! single source could produce alone.
//!
//! Every finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusions. MITRE techniques are narrated as consistency, never a verdict.
//!
//! ## 30-second example
//!
//! ```
//! use useract_forensic::{build_timeline, audit, ShellHistorySource, DeviceSource};
//! use shellhist_core::{HistoryEntry, Shell};
//!
//! // (sources are normally produced by the reader crates; constructed here inline)
//! let entries = shellhist_core::parse_auto(b"#1700000000\ncurl http://x | sh\n", Some(".bash_history"));
//! let shell = ShellHistorySource::new(&entries);
//! let devices = DeviceSource::new(&[]);
//!
//! let timeline = build_timeline(&[&shell, &devices]);
//! let findings = audit(&timeline);
//! for f in &findings {
//!     println!("{} — {}", f.code, f.note);
//! }
//! ```
//!
//! ## v0.2 roadmap
//!
//! New per-user sources slot in behind the [`ActivitySource`] trait without an API
//! break: `lnk-core` (recent-file LNK, completing the **volume-serial join**),
//! `shellbag-core` (folder access), `srum-core` (per-user app execution and network
//! bytes by SID — the strongest source), and `winreg-artifacts`
//! (UserAssist / RecentDocs / MRU / MountPoints2). See `docs/roadmap.md`.

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, ExternalRef, Finding, Severity, Source};
use peripheral_core::{Bus, DeviceConnection};
use shellhist_core::HistoryEntry;

/// What a user did to a [`Subject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Ran a program or command.
    Executed,
    /// Opened or read a file/folder.
    Accessed,
    /// Attached / connected a device.
    Connected,
    /// Issued a search query.
    Searched,
    /// Typed text (e.g. a typed URL / run-box entry).
    Typed,
    /// Disabled, cleared, or otherwise tampered with an activity record.
    HistoryTampered,
}

/// The thing an [`Action`] was performed on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Subject {
    /// A shell command or program invocation.
    Command(String),
    /// A file path.
    File(String),
    /// A folder path.
    Folder(String),
    /// An external device, with its volume serial kept distinct so a future LNK /
    /// shellbag [`Subject::File`] carrying the same NTFS/FAT volume serial can be
    /// joined to it (see [`device_file_volume_joins`]).
    Device {
        /// Device instance id (the stable primary key).
        id: String,
        /// NTFS/FAT volume serial of the device's volume, when known.
        volume_serial: Option<u32>,
    },
    /// A search / lookup query.
    Query(String),
}

/// Which reader the activity was normalized from.
///
/// Extensible: v0.2 adds `LnkFile`, `Shellbag`, `Srum`, `Registry` as new readers
/// are published. Marked `#[non_exhaustive]` so adding a variant is non-breaking;
/// consumers must use a `_` arm when matching.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// `shellhist-core` — shell command history.
    ShellHistory,
    /// `peripheral-core` — external-device connections.
    PeripheralDevice,
}

/// One normalized user-activity event: *who* did *what*, *when*, to *which* subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserActivity {
    /// Unix epoch seconds, when the source records it. `None` when the source
    /// carries no usable timestamp (e.g. plain bash / PowerShell PSReadLine).
    pub timestamp: Option<i64>,
    /// The acting user / SID, when the source attributes it. Most v0.1 sources do
    /// not attribute a user; SRUM (v0.2) is the first by-SID source.
    pub actor: Option<String>,
    /// What was done.
    pub action: Action,
    /// What it was done to.
    pub subject: Subject,
    /// Which reader produced this event.
    pub source: SourceKind,
    /// A human-readable detail string for the event.
    pub detail: String,
}

/// A producer of [`UserActivity`] events.
///
/// Implementing this trait is the v0.2 extension seam: a new reader wrapper
/// (`lnk-core`, `shellbag-core`, `srum-core`, `winreg-artifacts`) implements
/// `activities` and slots into [`build_timeline`] with no API change.
pub trait ActivitySource {
    /// The activities this source contributes to the timeline.
    fn activities(&self) -> Vec<UserActivity>;
}

/// Does this shell command disable or clear command history?
///
/// Recognizes the common anti-forensic primitives across bash/zsh/PowerShell. The
/// match is on structure (the verb + the well-known history target), not on a
/// hardcoded full command line, so any member of the class is caught.
fn is_history_tamper(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    let c = c.trim();
    // bash/zsh: unset the history file, point it at the bit bucket, or clear it.
    c.contains("unset histfile")
        || c.contains("histfile=/dev/null")
        || c.contains("histsize=0")
        || c.contains("histfilesize=0")
        || (c.contains("history") && (c.contains(" -c") || c.ends_with("-c")))
        || c.contains("history -c")
        // PowerShell PSReadLine history file removal.
        || (c.contains("clear-history"))
        || (c.contains("remove-item") && c.contains("consolehost_history"))
        // Truncate/remove the history file directly.
        || (c.contains("rm ") && c.contains(".bash_history"))
        || (c.contains("rm ") && c.contains(".zsh_history"))
        || (c.starts_with("> ") && c.contains("history"))
}

/// A [`ShellHistorySource`] wraps a borrowed slice of decoded history entries.
///
/// Each command becomes an [`Action::Executed`] [`UserActivity`]; a command that
/// disables or clears history becomes an [`Action::HistoryTampered`] event instead
/// (the clearing itself is the activity worth surfacing).
pub struct ShellHistorySource<'a> {
    entries: &'a [HistoryEntry],
    actor: Option<String>,
}

impl<'a> ShellHistorySource<'a> {
    /// Wrap decoded history entries with no attributed actor.
    #[must_use]
    pub fn new(entries: &'a [HistoryEntry]) -> Self {
        Self {
            entries,
            actor: None,
        }
    }

    /// Wrap decoded history entries, attributing them to a known user/account.
    #[must_use]
    pub fn for_actor(entries: &'a [HistoryEntry], actor: impl Into<String>) -> Self {
        Self {
            entries,
            actor: Some(actor.into()),
        }
    }
}

impl ActivitySource for ShellHistorySource<'_> {
    fn activities(&self) -> Vec<UserActivity> {
        from_shell_history(self.entries, self.actor.as_deref())
    }
}

/// Normalize a decoded shell-history stream into [`UserActivity`] events.
///
/// Each command → [`Action::Executed`]; a history-clearing command →
/// [`Action::HistoryTampered`]. The `actor` (when known) is carried onto every
/// event.
#[must_use]
pub fn from_shell_history(entries: &[HistoryEntry], actor: Option<&str>) -> Vec<UserActivity> {
    entries
        .iter()
        .map(|e| {
            let action = if is_history_tamper(&e.command) {
                Action::HistoryTampered
            } else {
                Action::Executed
            };
            UserActivity {
                timestamp: e.timestamp,
                actor: actor.map(ToString::to_string),
                action,
                subject: Subject::Command(e.command.clone()),
                source: SourceKind::ShellHistory,
                detail: e.command.clone(),
            }
        })
        .collect()
}

/// A [`DeviceSource`] wraps a borrowed slice of decoded device connections.
///
/// Each connection becomes an [`Action::Connected`] [`UserActivity`] whose
/// [`Subject::Device`] carries the device instance id and the **volume serial**, so
/// the v0.2 LNK/shellbag join can light up.
pub struct DeviceSource<'a> {
    connections: &'a [DeviceConnection],
}

impl<'a> DeviceSource<'a> {
    /// Wrap decoded device connections.
    #[must_use]
    pub fn new(connections: &'a [DeviceConnection]) -> Self {
        Self { connections }
    }
}

impl ActivitySource for DeviceSource<'_> {
    fn activities(&self) -> Vec<UserActivity> {
        from_device_connections(self.connections)
    }
}

/// Normalize a decoded device-connection stream into [`UserActivity`] events.
///
/// Each connection → [`Action::Connected`], carrying the device id and the volume
/// serial. The timestamp is the device's first-install/first-seen stamp when the
/// source recorded one.
#[must_use]
pub fn from_device_connections(connections: &[DeviceConnection]) -> Vec<UserActivity> {
    connections
        .iter()
        .map(|c| {
            let timestamp = c
                .first_install
                .or(c.last_arrival)
                .or(c.last_install)
                .map(|s| s.value);
            UserActivity {
                timestamp,
                actor: None,
                action: Action::Connected,
                subject: Subject::Device {
                    id: c.device_instance_id.clone(),
                    volume_serial: c.volume_serial,
                },
                source: SourceKind::PeripheralDevice,
                detail: c.device_instance_id.clone(),
            }
        })
        .collect()
}

/// Merge any number of [`ActivitySource`]s into one timeline, sorted by timestamp.
///
/// Events with a timestamp come first in ascending epoch order; `None`-timestamp
/// events are kept (their order is forensically meaningful too) and ordered stably
/// at the end, preserving source/insertion order among themselves.
#[must_use]
pub fn build_timeline(sources: &[&dyn ActivitySource]) -> Vec<UserActivity> {
    let mut events: Vec<UserActivity> = sources.iter().flat_map(|s| s.activities()).collect();
    // Stable sort keeps None-timestamp events in source order; the key puts
    // timestamped events first (ascending), untimestamped last.
    events.sort_by_key(|e| (e.timestamp.is_none(), e.timestamp.unwrap_or(i64::MAX)));
    events
}

/// The default temporal window (seconds) for the exec-during-removable-media join.
///
/// One hour: wide enough to catch a command run while a stick is mounted, tight
/// enough to keep the temporal coincidence meaningful and the false-positive rate
/// low.
pub const REMOVABLE_MEDIA_WINDOW_SECS: i64 = 3600;

/// The [`Source`] stamp for findings this analyzer emits.
#[must_use]
pub fn source(scope: impl Into<String>) -> Source {
    Source {
        analyzer: "useract-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Generic volume-serial join: pair every [`Subject::Device`] activity with every
/// [`Subject::File`] / [`Subject::Folder`] activity that names the **same volume
/// serial**.
///
/// This is the v0.2 seam: today no v0.1 source emits a `File`/`Folder` subject that
/// carries a volume serial, so the join returns nothing — but it is implemented
/// generically over [`UserActivity`], so the moment an `lnk-core` / `shellbag-core`
/// source contributes file activities tagged with a volume serial, the join lights
/// up with no change here. Returns `(device_index, file_index)` pairs into `events`.
///
/// A file/folder subject advertises its volume serial via the `vol:<serial>` token
/// convention in its [`UserActivity::detail`] (the seam the v0.2 readers will use);
/// v0.1 file sources do not exist yet, so this is exercised by a synthetic event in
/// tests to prove the join is correct by construction.
#[must_use]
pub fn device_file_volume_joins(events: &[UserActivity]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    for (di, dev) in events.iter().enumerate() {
        let Subject::Device {
            volume_serial: Some(dev_serial),
            ..
        } = &dev.subject
        else {
            continue;
        };
        for (fi, file) in events.iter().enumerate() {
            let is_file = matches!(file.subject, Subject::File(_) | Subject::Folder(_));
            if is_file && file_volume_serial(file) == Some(*dev_serial) {
                pairs.push((di, fi));
            }
        }
    }
    pairs
}

/// Extract the `vol:<serial>` volume-serial hint a file/folder activity advertises,
/// if any. The convention the v0.2 LNK/shellbag sources will populate.
fn file_volume_serial(activity: &UserActivity) -> Option<u32> {
    for tok in activity.detail.split_whitespace() {
        if let Some(rest) = tok.strip_prefix("vol:") {
            if let Ok(serial) = rest.parse::<u32>() {
                return Some(serial);
            }
        }
    }
    None
}

/// Audit a merged timeline for cross-source user-activity findings.
///
/// Emits hedged, low-false-positive observations achievable from the v0.1 sources:
///
/// - `USERACT-EXEC-DURING-REMOVABLE-MEDIA` — a shell command executed within
///   [`REMOVABLE_MEDIA_WINDOW_SECS`] of a removable mass-storage device connection
///   (temporal cross-source join). Consistent with activity involving external
///   media (MITRE T1052 / T1091).
/// - `USERACT-HISTORY-TAMPERED` — a history-clearing activity present in the
///   timeline (re-surfaced at the user-activity layer; MITRE T1070.003).
///
/// Every finding is an observation, never a verdict.
#[must_use]
pub fn audit(events: &[UserActivity]) -> Vec<Finding> {
    audit_with(events, &source("host"))
}

/// [`audit`] with a caller-supplied [`Source`] stamp (scope/version).
#[must_use]
pub fn audit_with(events: &[UserActivity], src: &Source) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Removable mass-storage connection windows: (epoch, device id).
    //
    // Eligibility is derived structurally from the device instance id's leading
    // enumerator token (`USBSTOR`, `USB`, `SD`, `SCSI`, …) via the published
    // `peripheral_core::Bus` classifier — not a hardcoded device list — so any
    // mass-storage member of the class qualifies and HID/Bluetooth/MTP devices do
    // not.
    let media_windows: Vec<(i64, &str)> = events
        .iter()
        .filter_map(|e| match (&e.action, &e.subject, e.timestamp) {
            (Action::Connected, Subject::Device { id, .. }, Some(ts)) if is_mass_storage_id(id) => {
                Some((ts, id.as_str()))
            }
            _ => None,
        })
        .collect();

    for event in events {
        // USERACT-HISTORY-TAMPERED — re-surface the clearing signal here.
        if event.action == Action::HistoryTampered {
            findings.push(history_tampered_finding(event, src));
            continue;
        }

        // USERACT-EXEC-DURING-REMOVABLE-MEDIA — temporal cross-source join.
        if let (Action::Executed, Some(ts), Subject::Command(cmd)) =
            (event.action, event.timestamp, &event.subject)
        {
            if let Some((win_ts, dev_id)) = media_windows
                .iter()
                .find(|(dev_ts, _)| (ts - dev_ts).abs() <= REMOVABLE_MEDIA_WINDOW_SECS)
            {
                findings.push(exec_during_media_finding(cmd, ts, *win_ts, dev_id, src));
            }
        }
    }

    findings
}

/// Is this device instance id a removable mass-storage transport?
///
/// Classifies the leading enumerator token (the part before the first `\`) with the
/// published [`peripheral_core::Bus`] classifier. A bare id with no separator is
/// treated as its own enumerator. Structural, not a device allow-list.
fn is_mass_storage_id(instance_id: &str) -> bool {
    let enumerator = instance_id.split('\\').next().unwrap_or(instance_id);
    Bus::from_enumerator(enumerator).is_mass_storage()
}

fn history_tampered_finding(event: &UserActivity, src: &Source) -> Finding {
    let cmd = match &event.subject {
        Subject::Command(c) => c.as_str(),
        _ => event.detail.as_str(),
    };
    Finding::observation(
        Severity::Medium,
        Category::Concealment,
        "USERACT-HISTORY-TAMPERED",
    )
    .source(src.clone())
    .note(format!(
        "user activity {cmd:?} disables or clears the activity record; consistent with \
             anti-forensic history tampering (MITRE T1070.003)"
    ))
    .evidence("command", cmd.to_string())
    .external_ref(ExternalRef::mitre_attack("T1070.003"))
    .build()
}

fn exec_during_media_finding(
    cmd: &str,
    cmd_ts: i64,
    dev_ts: i64,
    dev_id: &str,
    src: &Source,
) -> Finding {
    Finding::observation(
        Severity::Low,
        Category::Threat,
        "USERACT-EXEC-DURING-REMOVABLE-MEDIA",
    )
    .source(src.clone())
    .note(format!(
        "the command {cmd:?} ran within {REMOVABLE_MEDIA_WINDOW_SECS}s of removable mass-storage \
         device {dev_id:?} being connected; consistent with activity involving external media \
         (MITRE T1052 / T1091)"
    ))
    .evidence("command", cmd.to_string())
    .evidence("device", dev_id.to_string())
    .evidence("command_epoch", cmd_ts.to_string())
    .evidence("device_epoch", dev_ts.to_string())
    .external_ref(ExternalRef::mitre_attack("T1052"))
    .external_ref(ExternalRef::mitre_attack("T1091"))
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::{Bus, Provenance, Stamp};
    use shellhist_core::{HistoryEntry, Shell};

    fn entry(cmd: &str, ts: Option<i64>) -> HistoryEntry {
        HistoryEntry {
            shell: Shell::Bash,
            command: cmd.to_string(),
            timestamp: ts,
            elapsed: None,
            paths: Vec::new(),
        }
    }

    fn device(
        instance_id: &str,
        bus: Bus,
        first_install: Option<i64>,
        vol: Option<u32>,
    ) -> DeviceConnection {
        DeviceConnection {
            bus,
            device_class_guid: None,
            vid: None,
            pid: None,
            device_serial: None,
            serial_is_os_generated: false,
            friendly_name: None,
            device_instance_id: instance_id.to_string(),
            first_install: first_install.map(Stamp::authoritative),
            last_install: None,
            last_arrival: None,
            last_removal: None,
            parent_id_prefix: None,
            volume_guid: None,
            drive_letter: None,
            volume_serial: vol,
            disk_signature: None,
            dma_capable: bus.is_dma_capable(),
            mitre: Vec::new(),
            source: Provenance {
                file: "setupapi.dev.log".to_string(),
                line: 1,
            },
        }
    }

    // ── from_shell_history ────────────────────────────────────────────────────

    #[test]
    fn shell_command_becomes_executed_activity() {
        let entries = [entry("ls -la /tmp", Some(1_700_000_000))];
        let acts = from_shell_history(&entries, None);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].action, Action::Executed);
        assert_eq!(acts[0].source, SourceKind::ShellHistory);
        assert_eq!(acts[0].timestamp, Some(1_700_000_000));
        assert_eq!(acts[0].subject, Subject::Command("ls -la /tmp".to_string()));
        assert_eq!(acts[0].actor, None);
    }

    #[test]
    fn shell_actor_is_carried_when_known() {
        let entries = [entry("whoami", None)];
        let acts = from_shell_history(&entries, Some("alice"));
        assert_eq!(acts[0].actor.as_deref(), Some("alice"));
    }

    #[test]
    fn history_clearing_command_becomes_tampered() {
        for cmd in [
            "unset HISTFILE",
            "history -c",
            "export HISTFILE=/dev/null",
            "Clear-History",
            "rm ~/.bash_history",
        ] {
            let entries = [entry(cmd, Some(1))];
            let acts = from_shell_history(&entries, None);
            assert_eq!(acts[0].action, Action::HistoryTampered);
        }
    }

    #[test]
    fn benign_command_is_not_tampered() {
        let entries = [entry("git log --oneline", Some(1))];
        let acts = from_shell_history(&entries, None);
        assert_eq!(acts[0].action, Action::Executed);
    }

    // ── from_device_connections ───────────────────────────────────────────────

    #[test]
    fn device_becomes_connected_with_volume_serial() {
        let conns = [device(
            "USBSTOR\\Disk&Ven_SanDisk\\1234567890AB",
            Bus::Usb,
            Some(1_700_000_500),
            Some(0xDEAD_BEEF),
        )];
        let acts = from_device_connections(&conns);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].action, Action::Connected);
        assert_eq!(acts[0].source, SourceKind::PeripheralDevice);
        assert_eq!(acts[0].timestamp, Some(1_700_000_500));
        assert_eq!(
            acts[0].subject,
            Subject::Device {
                id: "USBSTOR\\Disk&Ven_SanDisk\\1234567890AB".to_string(),
                volume_serial: Some(0xDEAD_BEEF),
            }
        );
    }

    #[test]
    fn device_timestamp_falls_back_through_stamps() {
        let mut conn = device("USB\\VID_0781", Bus::Usb, None, None);
        conn.last_arrival = Some(Stamp::inferred(42));
        let acts = from_device_connections(&[conn]);
        assert_eq!(acts[0].timestamp, Some(42));
    }

    #[test]
    fn device_without_any_stamp_has_no_timestamp() {
        let conn = device("USB\\VID_0781", Bus::Usb, None, None);
        let acts = from_device_connections(&[conn]);
        assert_eq!(acts[0].timestamp, None);
    }

    // ── build_timeline ────────────────────────────────────────────────────────

    #[test]
    fn timeline_merges_and_sorts_by_timestamp() {
        let entries = [entry("late", Some(300)), entry("early", Some(100))];
        let conns = [device("USBSTOR\\x", Bus::Usb, Some(200), None)];
        let shell = ShellHistorySource::new(&entries);
        let devices = DeviceSource::new(&conns);
        let tl = build_timeline(&[&shell, &devices]);
        let ts: Vec<Option<i64>> = tl.iter().map(|e| e.timestamp).collect();
        assert_eq!(ts, vec![Some(100), Some(200), Some(300)]);
    }

    #[test]
    fn timeline_orders_untimestamped_events_last_and_stably() {
        let entries = [
            entry("no_ts_a", None),
            entry("ts", Some(50)),
            entry("no_ts_b", None),
        ];
        let shell = ShellHistorySource::new(&entries);
        let tl = build_timeline(&[&shell]);
        assert_eq!(tl[0].timestamp, Some(50));
        assert_eq!(tl[1].detail, "no_ts_a");
        assert_eq!(tl[2].detail, "no_ts_b");
    }

    // ── audit: USERACT-HISTORY-TAMPERED ───────────────────────────────────────

    #[test]
    fn audit_surfaces_history_tampered() {
        let entries = [entry("unset HISTFILE", Some(10))];
        let acts = from_shell_history(&entries, None);
        let findings = audit(&acts);
        let f = findings
            .iter()
            .find(|f| f.code == "USERACT-HISTORY-TAMPERED")
            .expect("history-tampered finding must fire");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Concealment);
    }

    // ── audit: USERACT-EXEC-DURING-REMOVABLE-MEDIA ────────────────────────────

    #[test]
    fn audit_fires_exec_during_removable_media_within_window() {
        let entries = [entry("tar czf /media/usb/out.tgz .", Some(1_000))];
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1_500), None)];
        let shell = ShellHistorySource::new(&entries);
        let devices = DeviceSource::new(&conns);
        let tl = build_timeline(&[&shell, &devices]);
        let findings = audit(&tl);
        assert!(findings
            .iter()
            .any(|f| f.code == "USERACT-EXEC-DURING-REMOVABLE-MEDIA"));
    }

    #[test]
    fn audit_does_not_fire_outside_window() {
        let entries = [entry("ls", Some(1_000))];
        let conns = [device(
            "USBSTOR\\Disk",
            Bus::Usb,
            Some(1_000 + REMOVABLE_MEDIA_WINDOW_SECS + 1),
            None,
        )];
        let shell = ShellHistorySource::new(&entries);
        let devices = DeviceSource::new(&conns);
        let tl = build_timeline(&[&shell, &devices]);
        let findings = audit(&tl);
        assert!(findings
            .iter()
            .all(|f| f.code != "USERACT-EXEC-DURING-REMOVABLE-MEDIA"));
    }

    #[test]
    fn audit_does_not_fire_for_non_mass_storage_device() {
        // A Bluetooth HID device is NOT mass storage → no exec-during-media finding.
        let entries = [entry("ls", Some(1_000))];
        let conns = [device("BTHENUM\\Dev", Bus::Bluetooth, Some(1_000), None)];
        let shell = ShellHistorySource::new(&entries);
        let devices = DeviceSource::new(&conns);
        let tl = build_timeline(&[&shell, &devices]);
        let findings = audit(&tl);
        assert!(findings
            .iter()
            .all(|f| f.code != "USERACT-EXEC-DURING-REMOVABLE-MEDIA"));
    }

    #[test]
    fn audit_with_custom_source_stamps_scope() {
        let entries = [entry("history -c", Some(1))];
        let acts = from_shell_history(&entries, None);
        let findings = audit_with(&acts, &source("CASE-001/host-7"));
        let f = &findings[0];
        assert_eq!(f.source.scope, "CASE-001/host-7");
        assert_eq!(f.source.analyzer, "useract-forensic");
    }

    // ── findings are observations, never verdicts ─────────────────────────────

    #[test]
    fn findings_are_hedged_observations_never_verdicts() {
        let entries = [
            entry("unset HISTFILE", Some(1_000)),
            entry("cp x /media/usb", Some(1_010)),
        ];
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1_005), None)];
        let shell = ShellHistorySource::new(&entries);
        let devices = DeviceSource::new(&conns);
        let tl = build_timeline(&[&shell, &devices]);
        let findings = audit(&tl);
        assert!(!findings.is_empty());
        for f in &findings {
            let note = f.note.to_ascii_lowercase();
            assert!(!note.contains("proves"));
            assert!(!note.contains("confirms"));
            assert!(!note.contains("definitely"));
            assert!(note.contains("consistent with"));
        }
    }

    // ── volume-serial join seam (v0.2 activation, proven by construction) ──────

    #[test]
    fn volume_serial_join_is_empty_for_v01_sources() {
        // v0.1 emits no File/Folder subjects carrying a volume serial → no joins.
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1), Some(0x1234))];
        let acts = from_device_connections(&conns);
        assert!(device_file_volume_joins(&acts).is_empty());
    }

    #[test]
    fn volume_serial_join_lights_up_for_a_v02_style_file_event() {
        // A synthetic v0.2-shape File activity advertising the same volume serial as
        // a connected device joins to it — proving the seam is correct by construction.
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1), Some(0x1234))];
        let mut acts = from_device_connections(&conns);
        acts.push(UserActivity {
            timestamp: Some(2),
            actor: None,
            action: Action::Accessed,
            subject: Subject::File("\\\\?\\E:\\secret.docx".to_string()),
            source: SourceKind::PeripheralDevice, // placeholder until LnkFile exists
            detail: "opened E:\\secret.docx vol:4660".to_string(), // 0x1234 == 4660
        });
        let joins = device_file_volume_joins(&acts);
        assert_eq!(joins, vec![(0, 1)]);
    }

    #[test]
    fn volume_serial_join_ignores_mismatched_serials() {
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1), Some(0x1234))];
        let mut acts = from_device_connections(&conns);
        acts.push(UserActivity {
            timestamp: Some(2),
            actor: None,
            action: Action::Accessed,
            subject: Subject::File("x".to_string()),
            source: SourceKind::PeripheralDevice,
            detail: "vol:9999".to_string(),
        });
        assert!(device_file_volume_joins(&acts).is_empty());
    }

    #[test]
    fn volume_serial_join_skips_files_without_a_volume_token() {
        // A folder activity that advertises no `vol:` token never joins (the
        // file_volume_serial None path).
        let conns = [device("USBSTOR\\Disk", Bus::Usb, Some(1), Some(0x1234))];
        let mut acts = from_device_connections(&conns);
        acts.push(UserActivity {
            timestamp: Some(2),
            actor: None,
            action: Action::Accessed,
            subject: Subject::Folder("E:\\photos".to_string()),
            source: SourceKind::PeripheralDevice,
            detail: "opened folder with no serial hint".to_string(),
        });
        // And a file whose `vol:` token is non-numeric (parse Err path) also never joins.
        acts.push(UserActivity {
            timestamp: Some(3),
            actor: None,
            action: Action::Accessed,
            subject: Subject::File("E:\\x".to_string()),
            source: SourceKind::PeripheralDevice,
            detail: "vol:notanumber".to_string(),
        });
        assert!(device_file_volume_joins(&acts).is_empty());
    }

    #[test]
    fn history_tampered_finding_falls_back_to_detail_for_non_command_subject() {
        // Defensive: a HistoryTampered activity whose subject is not a Command still
        // produces a finding, using detail for the command text.
        let act = UserActivity {
            timestamp: Some(1),
            actor: None,
            action: Action::HistoryTampered,
            subject: Subject::File("ConsoleHost_history.txt".to_string()),
            source: SourceKind::ShellHistory,
            detail: "Remove-Item ConsoleHost_history.txt".to_string(),
        };
        let findings = audit(&[act]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "USERACT-HISTORY-TAMPERED");
        assert!(findings[0]
            .note
            .contains("Remove-Item ConsoleHost_history.txt"));
    }

    #[test]
    fn is_mass_storage_id_classifies_bare_and_separated_ids() {
        assert!(is_mass_storage_id("USBSTOR\\Disk&Ven"));
        assert!(is_mass_storage_id("USBSTOR"));
        assert!(!is_mass_storage_id("BTHENUM\\Dev"));
        assert!(!is_mass_storage_id(""));
    }

    #[test]
    fn activitysource_trait_dispatches() {
        let entries = [entry("ls", Some(1))];
        let s = ShellHistorySource::for_actor(&entries, "bob");
        let acts: Vec<UserActivity> = s.activities();
        assert_eq!(acts[0].actor.as_deref(), Some("bob"));
    }

    // ── SRUM adapter (v0.2) ───────────────────────────────────────────────────

    use srum_core::{AppUsageRecord, IdMapEntry, NetworkUsageRecord};

    fn utc(epoch: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(epoch, 0).expect("valid epoch")
    }

    #[test]
    fn srum_network_row_is_executed_and_actor_attributed() {
        // user_id and app_id are integers resolved through the id-map.
        let id_map = [
            IdMapEntry {
                id: 7,
                name: "S-1-5-21-1-2-3-1001".to_string(),
            },
            IdMapEntry {
                id: 42,
                name: "\\Device\\HarddiskVolume3\\Windows\\explorer.exe".to_string(),
            },
        ];
        let net = [NetworkUsageRecord {
            app_id: 42,
            user_id: 7,
            timestamp: utc(1_700_000_000),
            bytes_sent: 4096,
            bytes_recv: 1024,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&net, &[], &id_map);
        assert_eq!(acts.len(), 1);
        let a = &acts[0];
        assert_eq!(a.action, Action::Executed);
        assert_eq!(a.source, SourceKind::Srum);
        assert_eq!(a.timestamp, Some(1_700_000_000));
        // First source that ATTRIBUTES to a specific user SID.
        assert_eq!(a.actor.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        // App resolves through the id-map.
        assert_eq!(
            a.subject,
            Subject::Command("\\Device\\HarddiskVolume3\\Windows\\explorer.exe".to_string())
        );
        // Network volume surfaced in the detail.
        assert!(a.detail.contains("4096"));
        assert!(a.detail.contains("1024"));
    }

    #[test]
    fn srum_unresolved_user_id_falls_back_to_numeric_token() {
        // No id-map entry for the user → actor is a stable synthetic token, never lost.
        let net = [NetworkUsageRecord {
            app_id: 1,
            user_id: 99,
            timestamp: utc(10),
            bytes_sent: 1,
            bytes_recv: 2,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&net, &[], &[]);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].actor.as_deref(), Some("user-id:99"));
        // App also falls back when unresolved.
        assert_eq!(acts[0].subject, Subject::Command("app-id:1".to_string()));
    }

    #[test]
    fn srum_app_usage_row_is_executed_and_actor_attributed() {
        let id_map = [
            IdMapEntry {
                id: 5,
                name: "S-1-5-21-9-9-9-500".to_string(),
            },
            IdMapEntry {
                id: 8,
                name: "C:\\Tools\\rclone.exe".to_string(),
            },
        ];
        let app = [AppUsageRecord {
            app_id: 8,
            user_id: 5,
            timestamp: utc(1_700_000_500),
            foreground_cycles: 900_000,
            background_cycles: 100,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&[], &app, &id_map);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].action, Action::Executed);
        assert_eq!(acts[0].source, SourceKind::Srum);
        assert_eq!(acts[0].actor.as_deref(), Some("S-1-5-21-9-9-9-500"));
        assert_eq!(
            acts[0].subject,
            Subject::Command("C:\\Tools\\rclone.exe".to_string())
        );
    }

    #[test]
    fn srum_source_adapter_dispatches() {
        let net = [NetworkUsageRecord {
            app_id: 1,
            user_id: 1,
            timestamp: utc(1),
            bytes_sent: 1,
            bytes_recv: 1,
            auto_inc_id: 0,
        }];
        let s = SrumSource::new(&net, &[], &[]);
        let acts = s.activities();
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].source, SourceKind::Srum);
    }

    // ── audit: USERACT-NETWORK-EXFIL-VOLUME (v0.2) ────────────────────────────

    #[test]
    fn audit_fires_network_exfil_volume_above_threshold() {
        let id_map = [
            IdMapEntry {
                id: 7,
                name: "S-1-5-21-1-2-3-1001".to_string(),
            },
            IdMapEntry {
                id: 42,
                name: "rclone.exe".to_string(),
            },
        ];
        let net = [NetworkUsageRecord {
            app_id: 42,
            user_id: 7,
            timestamp: utc(1_700_000_000),
            bytes_sent: NETWORK_EXFIL_BYTES_THRESHOLD + 1,
            bytes_recv: 0,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&net, &[], &id_map);
        let findings = audit(&acts);
        let f = findings
            .iter()
            .find(|f| f.code == "USERACT-NETWORK-EXFIL-VOLUME")
            .expect("network-exfil-volume must fire above threshold");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Threat);
    }

    #[test]
    fn audit_does_not_fire_network_exfil_below_threshold() {
        let net = [NetworkUsageRecord {
            app_id: 1,
            user_id: 1,
            timestamp: utc(1),
            bytes_sent: NETWORK_EXFIL_BYTES_THRESHOLD - 1,
            bytes_recv: 0,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&net, &[], &[]);
        let findings = audit(&acts);
        assert!(findings
            .iter()
            .all(|f| f.code != "USERACT-NETWORK-EXFIL-VOLUME"));
    }
}
