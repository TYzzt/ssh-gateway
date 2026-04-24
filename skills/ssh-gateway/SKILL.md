---
name: ssh-gateway
description: Use the local ssh-gateway CLI to run commands, read files, write files, transfer files, inspect sessions, or open tunnels on remote Linux hosts behind bastions. Trigger when the user wants agent-driven remote access through configured profiles and credentials should stay inside ssh-gateway instead of raw ssh commands, pasted passwords, private keys, or key passphrases.
---

# ssh-gateway

Use `ssh-gateway` instead of raw `ssh` whenever a configured profile can satisfy the request.

## Preconditions

- Confirm a local `ssh-gateway` binary is installed and available on `PATH`, or use the user-provided binary path.
- If the binary is missing, install it from GitHub Releases before proceeding:
  - Windows PowerShell: run [scripts/install.ps1](scripts/install.ps1)
  - Linux shell: run [scripts/install.sh](scripts/install.sh)
- Confirm a config file exists, either through `ARRT_CONFIG_PATH` or the default config locations.
- If no config exists, stop and ask for a profile-based setup. Do not ask the user to paste a password or key passphrase into a shell command as a fallback.

## Workflow

1. Resolve the CLI path:
   - Prefer `ssh-gateway` from `PATH`
   - Otherwise run the bundled install script for the current platform and use the installed binary path it prints
2. Validate the profile first with `ssh-gateway profile validate [name]`.
3. Prefer profile-driven operations:
   - `exec` for commands
   - `read` and `write` for text or file content
   - `upload` and `download` for file transfer
   - `tunnel open` and `tunnel close` for local forwarding
4. Use `session list` or `session inspect --id ...` when the user needs reuse or transport details.
5. Use `daemon status` or `daemon stop` only for daemon lifecycle checks; most operations auto-start the daemon when needed.

## Safe Operating Rules

- Prefer `--profile <name>` over raw hostnames in commands.
- Treat `profile show` and `session inspect` as summaries, not as a way to retrieve secrets.
- Keep the user on the `ssh-gateway` path whenever a configured profile can satisfy the request.
- Only fall back to raw `ssh` if the user explicitly asks for it or if no gateway profile can serve the operation.
- For delegated profiles, expect `tunnel open` to fail by design.
- Do not ask the user to manually download a release asset if the bundled install scripts can do it for them.
- For passphrase-protected keys, keep the passphrase in the gateway config and out of chat history.

## Command Patterns

Read [references/cli-usage.md](references/cli-usage.md) for command templates and common failure handling.
