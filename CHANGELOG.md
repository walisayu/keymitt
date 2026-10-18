# Changelog

## 0.1.0 — 2026-10-18

First version.

- MCP server (`keymitt mcp`) with tools `list_secrets`, `run_with_secrets`, `http_request`,
  `read_file_redacted` and `request_secret`.
- Secrets stored in the macOS Keychain, Windows Credential Manager or Linux Secret Service.
- Per-use approval: Touch ID / login password (macOS), Windows Hello, polkit (Linux), with optional
  weak fallbacks (message box, zenity/kdialog, `keymitt approve`).
- Per-secret policy: allowed channels, programs and hosts.
- `keymitt add` and `keymitt update` read the value from a no-echo prompt, standard input
  (`--from-stdin`) or the system clipboard (`--from-clipboard`, cleared afterwards unless
  `--keep-clipboard` is given). The clipboard is never exposed to agents.
- Redaction of all registered secret values and their common encodings; pattern-based masking for files.
- Audit log (JSON Lines, rotated at 10 MB).
- Encrypted, cross-platform backups with `keymitt backup` / `keymitt restore` (age, passphrase).
- One-line installers (`install.sh`, `install.ps1`) and a release workflow with checksums and
  build-provenance attestations.

### Security hardening (from an internal review before the first release)

- Output cut at a size limit can no longer return a fragment of a secret.
- Approval prompts show the stdin, environment, temp files and resolved program, escape invisible
  characters, and refuse requests too long to show in full.
- Programs are only looked up in absolute `PATH` directories; `--command` stores full paths.
  On macOS and Linux a program runs under the name it was called by, so multi-call programs such as
  busybox work, and the prompt adds `(as NAME)` when that name differs from the real file's.
- `read_file_redacted` is confined to the workspace and configured roots and refuses credential
  stores, key files, FIFOs and devices.
- Environment values must be exactly one placeholder; many more code-loading variables are refused;
  per-secret `env` name allowlists.
- `http_request` refuses `Host` and other transport headers; inputs are size-limited.
- Errors returned to agents are redacted; process groups are killed after a run (Unix);
  `request_secret` quotes safely; restore needs strong approval; the Linux polkit prompt is
  preceded by a notification with the details.
