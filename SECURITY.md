# Security model

keymitt lets AI agents use credentials without the credential values entering the agent's
context. This document states precisely what that does and does not protect against.

## Assets

1. **Secret values** stored in the OS keychain.
2. **The decision to use a secret** — which program or host receives it, and when.

## What keymitt protects against

| Threat | Mitigation |
|--------|------------|
| A secret ends up in the agent's context, transcript or logs | Agents only see `{{secret:NAME}}`. Everything returned — output, response headers and bodies, file contents, error messages — is redacted: the values of *all* registered secrets plus their base64 (at every alignment), URL-encoded (several styles, either hex case), hex and JSON-escaped forms. When output is cut at a size limit, any bytes that could be the start of a secret cut off by that limit are dropped before redacting, so a fragment of a value is never returned. |
| A secret is visible to other processes | Values are never placed in command-line arguments. Temp files are owner-only (`0600` in a `0700` directory), overwritten and deleted after the run. |
| A secret is used without you knowing | Every use requires approval through an out-of-band prompt. The prompt names the secrets and the resolved program (or the destination origin) first, then shows everything that decides where the value goes: arguments, the stdin text, environment variables, temp-file contents and the working directory, or the HTTP method, URL, headers and the start of the body. Invisible characters (newlines, terminal escapes, bidi overrides, zero-width characters) are shown escaped. A request too long to show in full is refused rather than truncated. Strong methods authenticate you (Touch ID / login password, Windows Hello, polkit). |
| A secret is handed to an impostor program | Programs are found only in *absolute* `PATH` directories — never relative or empty entries, which would resolve against a directory the agent may control. `keymitt add --command curl` stores the full path it resolved (for example `/usr/bin/curl`), so the policy names one program. |
| A secret is sent somewhere it shouldn't be | Per-secret allowlists of programs (`commands`) and destinations (`hosts`). `http_request` refuses placeholders and credentials in the URL, header injection (CR/LF), transport headers such as `Host`, non-HTTP(S) schemes and redirects; it starts `curl` with `--disable` so `~/.curlrc` cannot inject options. |
| An allowed program is hijacked through its environment | An environment variable may only carry a secret, and its value must be exactly one placeholder. Variables and variable families that load code, configuration or certificates are refused (`PATH`, `HOME`, `LD_*`, `DYLD_*`, `BASH_FUNC_*`, `GIT_*`, `NODE_*`, `PYTHON*`, `CARGO_*`, proxies, CA bundles, `SSLKEYLOGFILE`, pagers and editors, and more). A secret's policy can further restrict which variable names it may use. |
| A secret outlives the command | On macOS and Linux each run gets its own process group, which is killed when the run ends or times out. |
| `read_file_redacted` becomes a way around your client's file rules | It reads only below the MCP server's working directory (not when that is your home directory or a filesystem root) and any `[files] read_roots` you configure. Credential stores (`~/.ssh`, `~/.aws`, `~/.cloudflared`, `~/.netrc`, keychains and more) and key material (`id_*`, `*.pem`, `*.key`, …) are refused even there. Symlinks are resolved before checking, and FIFOs and devices are refused before opening. |
| Mass export of all secrets | Backups are CLI-only, need an interactive terminal, and always need strong approval. Restoring — which can change the policy — needs strong approval too. |

## What keymitt does **not** protect against

Be clear-eyed about these; they are inherent to running as the same OS user as the agent.

- **A malicious agent with an unrestricted shell.** An agent that can run arbitrary commands as you
  can bypass keymitt entirely: read the Linux Secret Service or Windows Credential Manager directly
  (both are readable by any process running as you), edit `policy.toml`, or write the decision file
  used by the weak terminal-approval method. On macOS, Keychain access by another program triggers
  a system prompt, which raises the bar but is not a guarantee.
  *Mitigation:* keep your AI client's own permission prompts on for shell commands, and treat the
  keymitt approval prompt as the place where you decide.
- **What an approved program does with the secret.** If you approve `curl` with a token, the
  arguments and stdin decide where it goes — both are in the prompt, so read it. Prefer
  `http_request`, which is host-restricted, for API calls. Do not allowlist shells or interpreters
  (`sh`, `bash`, `python`, `node`) for a secret: they can do anything with it.
- **Programs that read configuration from the working directory** (e.g. `git` reads
  `.git/config`). The approval prompt shows the directory; be careful with untrusted repositories.
- **Weak approval methods** (message box, zenity/kdialog, `keymitt approve`) confirm intent but
  don't authenticate you. Set `allow_weak = false` or `method = "native"` to forbid them.
- **The polkit dialog itself is generic.** On Linux the request details appear in a desktop
  notification just before it (best effort, via `notify-send`).
- **Masking in `read_file_redacted` is a convenience, not a boundary.** It removes known values and
  credential-looking patterns from files you allowed it to read; a credential in an unusual format
  inside an allowed directory can still be shown. Keep credential files out of the read roots.
- **Redaction is best-effort for transformed values.** Exact values and the common encodings above
  are caught; a value that a program hashes, encrypts, reverses, wraps across lines or splits apart
  is not.
- **Windows process trees.** On Windows only the direct child is stopped at the end of a run.
- **A compromised OS account or keychain** is out of scope.

## Design notes

- The MCP server loads the policy at start-up and never writes it. Agents have no tool to change
  the policy or approval settings.
- Approvals are never cached by default (`ttl_secs = 0`). With a TTL, only *byte-identical*
  requests to the same resolved program are remembered.
- Cancelling an authenticating prompt denies the request; keymitt never retries with a weaker method.
- Each decision records `elapsed_ms` in the audit log, so an implausibly fast approval stands out.
- Inputs are bounded: arguments, stdin, each temp file and request bodies are limited to 1 MiB.
- Only the CLI reads the clipboard (`keymitt add|update --from-clipboard`); the MCP server has no
  clipboard access. The CLI clears the clipboard after storing, but only while it still holds that
  value, and cannot reach copies kept by clipboard history or clipboard managers.
- Secret values are loaded from the keychain per request and dropped afterwards. Rendered
  templates and backup plaintext use zeroizing buffers; the redaction automaton's internal copies
  of the patterns are freed but not zeroized.
- The `testing` Cargo feature (in-memory vault, scripted approvals) must never be enabled in builds
  that are installed or distributed.

## Releases and the installers

- Release archives are built by GitHub Actions from a version tag, with actions pinned to commit
  SHAs, read-only tokens for build jobs and no build cache. Each release carries `SHA256SUMS.txt`
  and signed build-provenance attestations: `gh attestation verify <archive> --repo <owner>/keymitt`.
- The one-line installers verify the SHA-256 checksum before installing, refuse plain HTTP unless
  explicitly allowed, check every archive entry for path traversal before extracting only the
  binary, and refuse symlinks. The shell installer runs entirely inside a function called on its
  last line, so a truncated download executes nothing.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's private vulnerability reporting
(security advisories), not in public issues.
