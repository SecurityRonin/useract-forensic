# Roadmap

`useract-forensic` is the user-activity correlation layer. Its power grows with
every per-user source it can merge. v0.1 ships with two; the value compounds as the
reader crates below are published and slotted in behind the `ActivitySource` trait
— each one is purely additive, with no breaking change to the `UserActivity` model
or the `audit` surface.

## v0.1 — shipping now

| Source | Reader crate | Produces |
|---|---|---|
| Shell command history (bash / zsh / fish / PowerShell PSReadLine) | [`shellhist-core`](https://crates.io/crates/shellhist-core) | `Executed` commands; `HistoryTampered` for clearing commands |
| External device connections (`setupapi.dev.log`) | [`peripheral-core`](https://crates.io/crates/peripheral-core) | `Connected` devices, carrying the device id and **volume serial** |

Cross-source findings already achievable from these two:

- `USERACT-EXEC-DURING-REMOVABLE-MEDIA` — a command run inside the window a
  removable mass-storage device was connected (temporal join).
- `USERACT-HISTORY-TAMPERED` — a history-clearing activity re-surfaced at the
  user-activity layer.

## v0.2 — additive sources (need their reader crates published first)

| Source | Reader crate | Produces | Why it matters |
|---|---|---|---|
| Recent-file LNK | `lnk-core` | `Accessed` (File) **with a volume serial** | Completes the **volume-serial join**: a file opened from a USB stick links back to the exact `Device` that was connected. The `device_file_volume_joins` seam already implements this generically and is tested by construction — it activates with zero code change. |
| Shellbags | `shellbag-core` | `Accessed` (Folder) | Folder-browsing history, including folders on removable and network volumes. |
| SRUM (System Resource Usage Monitor) | `srum-core` | `Executed` / `Connected` **attributed to a SID** | The strongest source — the first to attribute activity to a specific user (`actor`), plus per-app network byte counts that sharpen the exfiltration lens. |
| Registry MRU artifacts | `winreg-artifacts` | `Executed` (UserAssist), `Accessed` (RecentDocs / RunMRU / typed paths), device first/last-seen (MountPoints2) | Per-user program-execution and recent-document evidence straight from `NTUSER.DAT`. |

## Cross-source findings unlocked by v0.2

Once the v0.2 sources are merged, the same `audit` surface gains observations such
as:

- a file `Accessed` from the same **volume serial** as a `Connected` device
  (the join already implemented),
- a program in UserAssist `Executed` with no corresponding on-disk binary,
- SRUM network bytes by SID correlated with a removable-media connection window.

Each is additive — a new `USERACT-*` code, never a change to an existing one.
