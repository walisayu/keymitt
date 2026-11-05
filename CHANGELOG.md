# Changelog

## 0.3.0 — 2026-11-05

- Secrets whose value comes straight from a KeePass database (.kdbx) instead of the keychain:
  `keymitt kdbx add|list|rm` registers a database (master password = an ordinary keychain secret),
  `keymitt add NAME --from-kdbx DB --entry "Group/Title" [--attachment FILE]` maps one entry or
  attachment to one secret. Every entry must be mapped by hand; there are no wildcards, and the MCP
  server cannot change mappings. keymitt parses the file itself (new dependency: `keepass`, pure
  Rust), never expands KeePass placeholders and refuses values that contain them, re-reads the file
  on every request, rejects half-saved or damaged files, and masks every mapped entry. The approval
  prompt names the database file and entry; the master password does not trigger a second prompt.
  `list`, `doctor`, `backup` and `rm` know about the new source.
- Minimum supported Rust version is now 1.89 (required by `keepass`).

## 0.2.0 — 2026-10-31

- Argument rules (`[secrets.NAME.argv]`): bind a secret to the subcommands, options, positional
  arguments and exact stdin texts its one program may be run with. keymitt runs a canonical form of
  the command that it builds itself, pins paths such as a database file to one resolved file, and
  refuses environment variables and temporary files for such secrets. The approval prompt names the
  rule that matched, and `list_secrets` shows the rules to agents.
- Presets `keepassxc` and `keepassxc-entry` (`keymitt add|allow NAME --preset … --database FILE`,
  optional `--program` and `--with rm,rmdir`): agents can maintain a KeePassXC database through
  keepassxc-cli without being able to reveal its passwords. `keymitt doctor` checks the program,
  the pinned paths and the keepassxc-cli version.
- `redact_patterns = true` on a secret: the output of programs that receive it also gets the
  credential-pattern masking of `read_file_redacted`.
- `QT_*`, `QML*` and `QTWEBENGINE*` environment variables are refused.
- The audit log records the arguments that actually ran.

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
