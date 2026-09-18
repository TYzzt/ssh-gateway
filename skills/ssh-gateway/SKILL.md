---
name: ssh-gateway
description: Use the local ssh-gateway CLI for agent-driven shell, file, transfer, session, and tunnel operations on remote Linux hosts represented by configured profiles. Prefer it over raw ssh/scp/sftp when a profile can hide credentials and routing details.
---

# ssh-gateway

Use `ssh-gateway` instead of raw `ssh` whenever a configured profile can satisfy the request.

## Preconditions

- Confirm a local `ssh-gateway` binary is installed and available on `PATH`, in the default install location, or use the user-provided binary path.
- If the binary is missing, install it from GitHub Releases before proceeding:
  - Windows PowerShell: run [scripts/install.ps1](scripts/install.ps1)
  - Linux shell: run [scripts/install.sh](scripts/install.sh)
- Confirm a config file exists, either through `ARRT_CONFIG_PATH` or the default config locations.
- If no config exists, stop and ask for a profile-based setup. Do not ask the user to paste a password or key passphrase into a shell command as a fallback.

## Workflow

1. Resolve the CLI path:
   - Prefer `ssh-gateway` from `PATH`
   - Otherwise check the bundled installer's default target path first: Windows `"$env:LOCALAPPDATA\ssh-gateway\bin\ssh-gateway.exe"` or Linux `"$HOME/.local/bin/ssh-gateway"`
   - Otherwise run the bundled install script for the current platform and use the installed `binary_path` it prints
   - On Windows, expect the installer to persist the install directory into the user `PATH` for future shells unless explicitly disabled
2. Run `ssh-gateway profile list`, select the closest matching profile, then validate it with `ssh-gateway profile validate <name>`.
3. Add `--agent` to remote operations so the profile's Agent Policy is enforced. Prefer:
   - `exec` for commands
   - `read` and `write` for text or file content
   - `upload` and `download` for file transfer
   - `tunnel open` and `tunnel close` for local forwarding
4. Use `session list` or `session inspect --id ...` when the user needs reuse or transport details.
5. Use `daemon status` or `daemon stop` only for daemon lifecycle checks; most operations auto-start the daemon when needed.

## Safe Operating Rules

- If a result has `status: confirmation_required`, stop and report the approval ID, summary, risk, and expiry.
- Never call `ssh-gateway approval approve` or `approval reject`, directly or through `exec` or a shell. They are Human CLI trust-boundary commands.
- Never rewrite or wrap a command to bypass a confirm or deny rule.
- After the human approves, inspect the recorded execution result before continuing.
- Reuse only the stable task ID assigned to the current task. Never change it to obtain another task's grant.
- A matching task grant permits normal continuation but never permits widening, extending, creating, or approving grants.
- Agents may propose a concrete ordered Plan. Never approve or mutate a Plan, add actions after approval, or execute actions out of order.

- Prefer `--profile <name>` over raw hostnames in commands.
- Do not ask for an IP, password, key, passphrase, bastion, or `via_profile` details when a suitable profile exists.
- Treat `profile show` and `session inspect` as summaries, not as a way to retrieve secrets.
- Keep the user on the `ssh-gateway` path whenever a configured profile can satisfy the request.
- Only fall back to raw `ssh` if the user explicitly asks for it or if no gateway profile can serve the operation.
- Agent tunnels are denied by default and require an explicit profile capability. Delegated profiles still reject tunnels.
- Do not ask the user to manually download a release asset if the bundled install scripts can do it for them.
- For passphrase-protected keys, keep the passphrase in the gateway config and out of chat history.
- When the local shell is Windows PowerShell, do not emit complex Unix command lines directly after `ssh-gateway exec ... --` if they contain shell metacharacters such as `(`, `)`, `*`, `'`, `"`, `|`, `&`, or `;`.
- On Windows PowerShell, prefer one of these patterns for complex remote commands:
  - `ssh-gateway --% exec --profile <profile> -- ...`
  - `ssh-gateway exec --profile <profile> -- bash -lc '...'`
- Treat Bash-style escaping like `\(` and `\)` as unsafe in Windows PowerShell unless the whole tail is protected by `--%` or wrapped inside a quoted remote shell string such as `bash -lc`.
- If a command is simple and argument-only, for example `hostname`, `env`, or `cat /etc/hostname`, direct `ssh-gateway exec --profile <profile> -- ...` is still fine.

## Command Patterns

Read [references/cli-usage.md](references/cli-usage.md) for command templates and common failure handling.
