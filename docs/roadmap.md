# Roadmap

`useract-forensic` is the user-activity correlation layer. Its power grows with
every per-user source it can merge. Each source slots in behind the
`ActivitySource` trait — purely additive, with no breaking change to the `audit`
surface.

## Shipping now

| Source | Reader crate | Produces |
|---|---|---|
| Shell command history (bash / zsh / fish / PowerShell PSReadLine) | [`shellhist-core`](https://crates.io/crates/shellhist-core) | `Executed` commands; `HistoryTampered` for clearing commands |
| External device connections (`setupapi.dev.log`) | [`peripheral-core`](https://crates.io/crates/peripheral-core) | `Connected` devices, carrying the device id and **volume serial** |
| SRUM (System Resource Usage Monitor) | [`srum-parser`](https://crates.io/crates/srum-parser) / [`srum-core`](https://crates.io/crates/srum-core) | `Executed` **attributed to a SID** — network and app-usage rows; the integer `user_id` / `app_id` foreign keys resolved through the `SruDbIdMapTable` to a user SID and application path, with per-interval network byte counts |
| UserAssist / TypedURLs / ShellBags | [`winreg-artifacts`](https://crates.io/crates/winreg-artifacts) | `Executed` (UserAssist program + run count + last-run), `Typed` (TypedURLs address-bar entries), `Accessed` (ShellBags folders) |
| Recent-file LNK | [`lnk-core`](https://crates.io/crates/lnk-core) | `Accessed` (File) **with a volume serial** — the link's `VolumeID` `DriveSerialNumber`, completing the device join |

Cross-source findings achievable from these sources:

- `USERACT-FILE-ON-EXTERNAL-DEVICE` — a file accessed (LNK) on a volume whose
  serial matches a `Connected` device (the volume-serial join).
- `USERACT-NETWORK-EXFIL-VOLUME` — a SRUM network row whose per-interval
  `bytes_sent` crosses a conservative threshold (a graded lead).
- `USERACT-EXEC-DURING-REMOVABLE-MEDIA` — a command run inside the window a
  removable mass-storage device was connected (temporal join).
- `USERACT-HISTORY-TAMPERED` — a history-clearing activity re-surfaced at the
  user-activity layer.

## v0.3 — additive sources

| Source | Reader crate(s) | Produces | Why it matters |
|---|---|---|---|
| ShellBags with decoded ShellItem paths | `winreg-artifacts` + a ShellItem decoder | `Accessed` (Folder) **with reconstructed paths and volume serials** | Full folder-browsing history, including folders on removable and network volumes — extends the volume-serial join to folder access. |
| JumpLists (AutomaticDestinations / CustomDestinations) | `lnk` v0.2 | `Accessed` (File) per destination | Per-application recent-file lists, each embedding a Shell Link with its own target and volume serial. |

Each is additive — a new `USERACT-*` code, never a change to an existing one.
