# keymitt

**Let AI agents use your secrets without ever seeing them.**

[繁體中文](README.zh-TW.md)

keymitt is an [MCP](https://modelcontextprotocol.io) server and CLI that keeps your API tokens,
passwords and keys in your operating system's keychain and lets AI coding agents *use* them —
while the values never enter the agent's context, its transcript, or its logs.

```text
agent: run_with_secrets { command: ["curl", "--config", "-"],
                          stdin: "header = \"Authorization: Bearer {{secret:github}}\"" }
          │
          ▼
keymitt ── policy check ── you approve (Touch ID / Windows Hello / polkit) ── value from keychain
          │
          ▼
curl gets the real token on stdin  ──►  output comes back as  "token": "[REDACTED:github]"
```

Like an oven mitt for keys: the agent can pick things up, but never touches them.

> **Status: early (0.1).** The design is deliberate, but the code has not been audited.
> Read [SECURITY.md](SECURITY.md) for exactly what keymitt does and does not protect against.

## Why

Agents keep hitting the same wall: the task needs a credential. Today you either paste it into the
chat (now it lives in a transcript forever), put it in a file the agent can `cat`, or do the step
yourself. keymitt gives a fourth option:

- **Values stay in the OS keychain** — macOS Keychain, Windows Credential Manager, or the Linux
  Secret Service (GNOME Keyring, KWallet).
- **Agents refer to secrets by name**, as `{{secret:NAME}}` placeholders. keymitt substitutes the
  value at the last moment, into stdin, an environment variable, an owner-only temp file, or an
  HTTP header — **never into command-line arguments**, which other processes can read.
- **Every use is approved by you, on your device**, with an authenticating prompt the agent
  cannot click: Touch ID or your login password on macOS, Windows Hello on Windows, polkit on Linux.
- **A per-secret policy** says which programs may receive a secret and which hosts it may be sent to.
- **Everything the agent gets back is redacted** — the values of *all* your secrets, including
  their base64, hex, URL-encoded and JSON-escaped forms.
- **An audit log** records every use (never the values).
- **Encrypted, portable backups** (age + passphrase) that restore on any platform.

## Platform support

|                  | macOS                     | Windows                     | Linux                                      |
|------------------|---------------------------|-----------------------------|--------------------------------------------|
| Secret storage   | Keychain                  | Credential Manager          | Secret Service (D-Bus)                     |
| Strong approval  | Touch ID / login password | Windows Hello (PIN, bio)    | polkit (`keymitt setup polkit`)            |
| Weak fallback\*  | CLI                       | Yes/No message box, CLI     | zenity / kdialog question, CLI             |

\* Weak methods confirm intent but do not authenticate you. They are only used when no strong method
is available *and* `allow_weak = true` (the default). Backups always require strong approval.

Requirements: `curl` on `PATH` (built into macOS, Windows 10+ and most Linux distributions) for
`http_request`. Windows Credential Manager limits a secret to 2560 bytes.

## Install

One line — it downloads the release for your platform, verifies its SHA-256 checksum and installs
the `keymitt` binary (to `~/.local/bin` by default).

macOS and Linux:

```sh
curl -fsSL https://keymitt.walisayu.com/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://keymitt.walisayu.com/install.ps1 | iex
```

Or build from source with Rust 1.85 or newer:

```sh
git clone <this repository> keymitt
cd keymitt
cargo install --path .
```

Check the installation (this writes and deletes a probe entry in your keychain). Add `--approval`
to also see a test approval prompt:

```sh
keymitt doctor --approval
```

## Quick start

**1. Store a secret** — you type the value; it is never echoed or written to disk.

```sh
keymitt add github --description "GitHub fine-grained token" --host api.github.com
keymitt add pg-staging --description "staging DB password" --command psql
```

Copied the token from a web page? Add `--from-clipboard` to read it from the clipboard instead (see
[Storing a copied secret](#storing-a-copied-secret)). `--host` allows `http_request` to send the
secret to that host. `--command` allows a program to
receive it via stdin, an environment variable or a temp file; a bare name such as `psql` is
resolved right away and stored as its full path, so the policy names exactly one program. All
flags are repeatable; see `keymitt allow --help` to change them later.

**2. Register the MCP server** with your AI client. For Claude Code, this prints the exact
`claude mcp add …` command for your installation:

```sh
keymitt setup claude
```

Any MCP client that can launch a stdio server works: the command is `keymitt mcp`.

**3. Ask the agent to do the task.** It will find the secret with `list_secrets` and use it:

```json
{ "tool": "http_request",
  "arguments": { "url": "https://api.github.com/user",
                 "headers": { "Authorization": "Bearer {{secret:github}}" } } }
```

```json
{ "tool": "run_with_secrets",
  "arguments": { "command": ["psql", "-h", "staging-db", "-U", "app", "-c", "select count(*) from users"],
                 "env": { "PGPASSWORD": "{{secret:pg-staging}}" } } }
```

A Touch ID / Windows Hello / polkit prompt appears describing exactly what will run. Approve it, and
the agent receives the output with every secret value replaced by `[REDACTED:NAME]`.

## Storing a copied secret

Most tokens are copied from a web page. Rather than pasting them into a prompt, let keymitt read
the clipboard directly:

```sh
keymitt add github --description "GitHub fine-grained token" --host api.github.com --from-clipboard
keymitt update github --from-clipboard
```

```text
Read 93 characters from the clipboard.
Stored github in the macOS Keychain.
Cleared the clipboard.
```

- Surrounding whitespace, such as a trailing newline, is removed. keymitt shows how many characters
  it read, never the value.
- Once the secret is stored, keymitt clears the clipboard, but only if it still holds that value:
  anything you copied in the meantime is left alone. Add `--keep-clipboard` to leave it as it is.
- An empty clipboard is an error, never an empty secret.
- Clipboard history keeps its own copy: Windows clipboard history (Win+V) and clipboard managers
  such as Maccy or Klipper. Delete the entry there too, or pause the history while you copy.
- On Linux this needs a desktop session (X11 or Wayland). On a server, pipe the value in with
  `--from-stdin` instead.
- Only the `keymitt` command line reads the clipboard. The MCP server has no access to it, because
  the clipboard often holds a secret you have just copied.

## Examples

Everyday tasks, each set up once: copy the token from the provider's page and store it with
`--from-clipboard`.

| Ask your agent | One-time setup | What the agent uses |
| --- | --- | --- |
| "List the open bugs in my-org/my-app, oldest first" | `keymitt add github --host api.github.com --from-clipboard` | `http_request` to `api.github.com` |
| "Build the docs and deploy them to Cloudflare Pages" | `keymitt add cloudflare --command wrangler --env CLOUDFLARE_API_TOKEN --from-clipboard` | `run_with_secrets` running `wrangler pages deploy` |
| "How many users signed up on staging this week?" | `keymitt add pg-staging --command psql --env PGPASSWORD --from-clipboard` | `run_with_secrets` running `psql -c …` |
| "Post the release notes to #releases on Slack" | The agent asks via `request_secret`; you run `keymitt add slack-bot --host slack.com --from-clipboard` | `http_request` to `slack.com` |

After adding a secret, restart the keymitt server in your AI client (in Claude Code: `/mcp` →
keymitt → Reconnect). Every use still needs your approval, and the prompt shows the full command
or request. The [examples page](https://keymitt.walisayu.com/guide/examples) walks through each
one with the exact request and prompt.

## Tools exposed to agents

| Tool                 | What it does |
|----------------------|--------------|
| `list_secrets`       | Names, descriptions and allowed uses of your secrets. Never values. |
| `run_with_secrets`   | Runs a program (no shell) with secrets in `stdin`, `env` values, or temp `files` referenced as `{{file:ID}}`. |
| `http_request`       | keymitt sends the request itself (via `curl`), only to allowed hosts, without following redirects. |
| `read_file_redacted` | Reads a config file with all known secret values *and* credential-looking values (passwords, tokens, private keys, URL passwords) masked. Only below the server's working directory and configured roots; credential stores and key files are refused. |
| `request_secret`     | Returns the exact `keymitt add …` command for *you* to run. Agents are told never to ask for values in chat. |

There is deliberately no tool that returns a secret value, exports secrets, or changes the policy.

## The policy file

`~/.config/keymitt/policy.toml` (`%APPDATA%\keymitt\policy.toml` on Windows; override with
`KEYMITT_HOME`). It contains no secret values, so you can keep it in your dotfiles.

```toml
version = 1

[approval]
method = "auto"        # auto | native (strong only) | cli
ttl_secs = 0           # remember an approval for an *identical* request; 0 = ask every time
timeout_secs = 120     # deny if nobody answers
allow_weak = true      # allow weak methods when no strong one is available

[secrets.github]
description = "GitHub fine-grained token"
channels = ["http"]                   # stdin | env | file | http
hosts = ["api.github.com"]            # also "*.example.com", "http://127.0.0.1:8080", "*"

[secrets.pg-staging]
description = "staging DB password"
channels = ["env", "stdin"]
commands = ["/opt/homebrew/bin/psql"]   # full paths (`keymitt add --command psql` resolves them), or "*"
env = ["PGPASSWORD"]                    # optional: the only variable names it may be put in

[files]
read_roots = ["~/projects/infra"]       # extra directories read_file_redacted may read
```

Bare host names only match HTTPS on port 443. Use an explicit origin such as
`http://127.0.0.1:3000` for local plain-HTTP services. The MCP server reads the policy at start-up;
restart it after changes.

## Approvals

Each request shows a prompt with the secrets involved, the full command line (or method and URL)
and the working directory. If you cancel an authenticating prompt, the request is denied — keymitt
never falls back to a weaker method after you said no. Fallbacks only happen when a strong method
is *unavailable* (no Touch ID/password UI over SSH, Windows Hello not set up, polkit action not
installed).

On a headless machine, set `method = "cli"` and approve from another terminal:

```sh
keymitt pending
keymitt approve 3f9c2a1b
```

## Backup and restore

Back up — this needs strong approval and a passphrase of at least 12 characters:

```sh
keymitt backup keymitt-2026-10.age
```

Restore on any OS — existing values are kept unless you add `--overwrite`:

```sh
keymitt restore keymitt-2026-10.age
```

The backup is an ASCII-armored [age](https://age-encryption.org) file encrypted with your
passphrase (scrypt). It contains the policy and every secret value, so store it like you would a
password-manager export. Backup and restore are CLI-only and never exposed to agents.

## Hardening your AI client

keymitt only protects secrets that flow *through* it. Agents with a shell can still read credential
files directly. Deny that in your client, so they reach for `read_file_redacted` instead. For Claude
Code, add rules like these to `~/.claude/settings.json` (adapt the paths to your setup):

```json
{
  "permissions": {
    "deny": [
      "Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)",
      "Read(~/.pgpass)", "Read(~/.netrc)", "Read(~/.ssh/**)", "Read(~/.aws/credentials)"
    ]
  }
}
```

Shell commands such as `cat .env` can't be blocked reliably by patterns; the client's own
permission prompts remain your line of defence there.

## Security model in one paragraph

keymitt prevents *accidental* exposure — a secret printed into a transcript, committed to a log, or
pasted into chat — and makes every *use* of a secret visible and approved by a human. It is not a
sandbox against a deliberately malicious agent that runs arbitrary commands as your user: such an
agent could, for example, read the Linux Secret Service directly. See [SECURITY.md](SECURITY.md)
for the full threat model.

## Development

Unit tests and end-to-end MCP tests, then lints:

```sh
cargo test --features testing
cargo clippy --all-targets --features testing
```

The `testing` feature compiles in an in-memory vault and scripted approvals for tests. **Never**
install or distribute a build with it enabled.

## Contributing

This repository is published as a snapshot with each release, so its history is a single commit.
Issues and pull requests are welcome: accepted changes are applied upstream and appear in the next
snapshot.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in keymitt shall be dual licensed as above, without any additional terms or conditions.
