# 5. Cross-source joins — structural volume-serial equality, temporal windows, conservative graded leads

Date: 2026-07-24
Status: Accepted

## Context

The crate's whole value is the signal no single artifact shows: a file that lived on
the exact USB volume a device log recorded, a command run while that stick was mounted,
a bulk upload attributable to a process. These require *joining* events from different
sources, and each join must be built on structure — never on a hardcoded device list or
a fixture-specific constant — so it generalizes to inputs never seen (fleet "No Special
Cases" discipline). Thresholds must be honest: a correlation is a *lead* for the
examiner, not a verdict.

## Decision

Three join strategies, each grounded in the event structure:

- **Volume-serial equality join.** `device_file_volume_joins` (`src/lib.rs:873`) pairs
  every `Subject::Device` carrying a `volume_serial` with every `Subject::File`/`Folder`
  naming the same serial, firing `USERACT-FILE-ON-EXTERNAL-DEVICE`. The serial is read
  from the structured field first, with a `vol:<serial>` token in `detail` honored as a
  fallback (`file_volume_serial`, `src/lib.rs:895`). The join key is the NTFS/FAT volume
  serial the LNK `VolumeID` and the device log independently record — real shared
  identity, not a heuristic.
- **Temporal window join.** A shell command within `REMOVABLE_MEDIA_WINDOW_SECS`
  (3600 s, `src/lib.rs:838`) of a removable mass-storage connection fires
  `USERACT-EXEC-DURING-REMOVABLE-MEDIA`. Device eligibility is derived *structurally*
  from the instance-id enumerator token via the published `peripheral_core::Bus`
  classifier (`is_mass_storage_id`, `src/lib.rs:944-952` comment) — not a hardcoded
  device list — so any mass-storage member qualifies and HID/Bluetooth/MTP do not.
- **Conservative graded lead.** A SRUM network row whose per-interval `bytes_sent`
  crosses `NETWORK_EXFIL_BYTES_THRESHOLD` (256 MiB, `src/lib.rs:848`) fires
  `USERACT-NETWORK-EXFIL-VOLUME`. The constant's doc comment states it is a deliberately
  conservative *lead*, not a verdict — a backup client can also cross it, so the examiner
  adjudicates.

History-tampering (`is_history_tamper`, `src/lib.rs:196`) likewise matches on structure
(the verb + the well-known history target) rather than a full hardcoded command line, so
any member of the anti-forensic class is caught.

## Consequences

Every join generalizes by construction: a device model, volume, or command the author
never saw is handled by the same rule. Thresholds are named `pub const`s with rationale
in their doc comments, so an examiner can see and, if a downstream tool wishes, retune
them. The 256 MiB lead and the 1-hour window trade recall for a low false-positive rate
— a deliberate choice to keep findings actionable — and are documented as leads, keeping
the output honest. The volume-serial fallback via a `detail` token is a small seam that
lets an out-of-band source annotate a serial without a model change.
