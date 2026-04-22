# ssh-gateway

<p align="center">
  <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <img src="docs/readme/hero.svg" alt="SSH Gateway for Agents" width="100%">
</p>

<p align="center">
  <a href="https://github.com/TYzzt/ssh-gateway/releases">
    <img src="https://img.shields.io/github/v/release/TYzzt/ssh-gateway?display_name=tag&sort=semver" alt="Latest release">
  </a>
  <a href="https://github.com/TYzzt/ssh-gateway/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/TYzzt/ssh-gateway/release.yml?label=release" alt="Release workflow">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-0f766e.svg" alt="Apache 2.0 license">
  </a>
  <img src="https://img.shields.io/badge/platforms-Windows%20x64%20%7C%20Linux%20x64-0f172a.svg" alt="Supported platforms">
</p>

`ssh-gateway` is an agent-facing SSH gateway for remote Linux automation behind bastions. It keeps reusable embedded SSH sessions inside a local daemon, moves authentication material into gateway-managed profiles, and lets agents operate by `profile` name instead of raw passwords or keys.

It is intentionally **not** a general-purpose SSH client replacement. The project is optimized for agent workflows, profile-driven safety, and repeatable remote operations.

## Why ssh-gateway

- Agents that repeatedly spawn one-shot `ssh` or `scp` often hit connection churn, login throttling, or refused sessions.
- Bastion chains, delegated hops, and mixed per-hop auth are awkward to express safely in prompts.
- Passwords and private keys should stay in gateway-owned config, not in agent-visible command lines or chat history.

## Features

- **Secret isolation at the gateway API boundary**: the daemon reads passwords and key paths from config; callers send only `profile` plus operation arguments.
- **Redacted profile and session output**: `profile show`, `session inspect`, and error payloads never echo raw passwords.
- **Profile-first agent workflow**: agents use named profiles instead of embedding secrets in `ssh` commands.
- **Embedded SSH transport with session reuse**: direct and bastion profiles use in-process SSH instead of spawning local `ssh.exe` or `scp`.
- **No local OpenSSH dependency for direct or bastion mode**: Windows and Linux direct transports run through the embedded client stack.
- **Per-hop auth for bastions and targets**: every hop can use its own password or key configuration.
- **Delegated `via_profile` mode**: reuse an upstream host's remote SSH capability when the final target is only reachable from that host.
- **Managed remote agent lifecycle**: version checks, bootstrap, and reuse happen on connect.
- **JSON-only CLI**: predictable automation surface for `daemon`, `profile`, `exec`, `read`, `write`, `upload`, `download`, `tunnel`, and `session`.

## Security Model

<p align="center">
  <img src="docs/readme/security.svg" alt="Security boundary for profile-driven secrets and redacted outputs" width="100%">
</p>

### What is isolated

- Passwords and private-key paths live in `profiles.yaml`, `profiles.yml`, or legacy `profiles.toml`, and are consumed by the local gateway daemon.
- CLI and RPC requests carry `profile` names and operation arguments, not raw password or private-key values.
- `profile show`, `session inspect`, and error results redact secret material before returning JSON to the caller.

### What this is not

- This is **not** a claim of strong isolation against other local processes running under the same OS user.
- This is **not** a replacement for OS file permissions, secret managers, host hardening, or bastion policy.
- Delegated `via_profile` sessions still rely on the upstream host's own SSH capability to reach the final target.

### Operator guidance

- Keep live configs outside the repository.
- Restrict config file permissions to the expected local user or service account.
- Do not commit real profiles, passwords, or private keys.

## Quick Start

<p align="center">
  <img src="docs/readme/architecture.svg" alt="Agent to daemon to embedded SSH to bastion and target flow" width="100%">
</p>

1. Download a release asset from [GitHub Releases](https://github.com/TYzzt/ssh-gateway/releases) and place `ssh-gateway` on your `PATH`.
2. Prepare a profile file. YAML is preferred; start from [examples/profiles.yaml](examples/profiles.yaml).
3. Validate the profile before the first run.
4. Start the daemon implicitly or explicitly and run remote operations by `profile`.

PowerShell:

```powershell
$env:ARRT_CONFIG_PATH = (Resolve-Path .\examples\profiles.yaml)
ssh-gateway profile validate
ssh-gateway daemon start
ssh-gateway exec --profile direct-with-bastion -- hostname
ssh-gateway session list
ssh-gateway daemon stop
```

Bash:

```bash
export ARRT_CONFIG_PATH="$PWD/examples/profiles.yaml"
ssh-gateway profile validate
ssh-gateway daemon start
ssh-gateway exec --profile direct-with-bastion -- hostname
ssh-gateway session list
ssh-gateway daemon stop
```

The config loader uses `ARRT_CONFIG_PATH` first. If it is unset, the default search order is:

- Windows: `%APPDATA%\opensource\ssh-gateway\profiles.yaml`, then `profiles.yml`, then legacy `profiles.toml`
- Linux: `$XDG_CONFIG_HOME/opensource/ssh-gateway/profiles.yaml`, then `profiles.yml`, then legacy `profiles.toml`

## Config Examples

The repository keeps public-safe examples in [examples/profiles.yaml](examples/profiles.yaml).

### Direct SSH with a bastion

```yaml
profiles:
  - name: direct-with-bastion
    target:
      host: target.internal
      user: root
      port: 22
      auth:
        type: password
        password: target-password
    bastions:
      - host: bastion.example.com
        user: root
        port: 22
        auth:
          type: key
          key_path: ~/.ssh/id_ed25519
```

### Delegated `via_profile`

```yaml
profiles:
  - name: upstream-bastion
    target:
      host: bastion.example.com
      user: root
      port: 22
      auth:
        type: key
        key_path: ~/.ssh/id_ed25519

  - name: delegated-target
    via_profile: upstream-bastion
    target:
      host: target.internal
      user: root
      port: 22
```

Delegated mode is useful when the upstream host already knows how to `ssh target.internal ...` and the local machine should not carry an additional target credential. In this mode:

- the delegated profile must not define `auth`
- the delegated profile must not define `bastions`
- `exec`, `read`, `write`, `upload`, and `download` are supported
- `tunnel open` is rejected for delegated sessions

### Legacy TOML

Legacy TOML remains supported for compatibility:

```toml
[[profiles]]
name = "legacy"

[profiles.target]
host = "target.internal"
user = "root"

[profiles.auth]
key_path = "~/.ssh/id_ed25519"
```

## Commands

All commands print JSON.

| Area | Commands |
| --- | --- |
| `daemon` | `daemon start`, `daemon status`, `daemon stop` |
| `profile` | `profile list`, `profile show <name>`, `profile validate [name]` |
| remote ops | `exec`, `read`, `write`, `upload`, `download` |
| `tunnel` | `tunnel open --profile <name> --local <port> --remote <host:port>`, `tunnel close --id <tunnel-id>` |
| `session` | `session list`, `session inspect --id <session-id>`, `session close --id <session-id>` |

Common examples:

```text
ssh-gateway exec --profile delegated-target -- hostname
ssh-gateway read --profile delegated-target --path /etc/hostname
ssh-gateway write --profile delegated-target --path /tmp/demo.txt --input hello
ssh-gateway upload --profile delegated-target --src ./local.txt --dst /tmp/local.txt
ssh-gateway download --profile delegated-target --src /tmp/local.txt --dst ./local-copy.txt
ssh-gateway tunnel open --profile direct-with-bastion --local 8080 --remote 127.0.0.1:11434
```

`daemon stop` returns `{"status":"stopping"}` when it successfully signals a running daemon and `{"status":"not_running"}` when nothing is listening.

## Install from Releases

Release assets are published automatically for every pushed `v*` tag.

- Windows x64: `ssh-gateway-<version>-x86_64-pc-windows-msvc.zip`
- Linux x64: `ssh-gateway-<version>-x86_64-unknown-linux-gnu.tar.gz`
- Checksums: `SHA256SUMS`

Typical install flow:

1. Download the archive for your platform from [Releases](https://github.com/TYzzt/ssh-gateway/releases).
2. Extract `ssh-gateway` or `ssh-gateway.exe`.
3. Put the binary on your `PATH`.
4. Create a config file from [examples/profiles.yaml](examples/profiles.yaml).

## Install as a Skill

The repository includes a Codex-style skill at [skills/ssh-gateway](skills/ssh-gateway). The skill teaches the agent to prefer profile-driven `ssh-gateway` commands over raw `ssh`.

Windows PowerShell:

```powershell
py -3 "$env:USERPROFILE\.codex\skills\.system\skill-installer\scripts\install-skill-from-github.py" `
  --repo TYzzt/ssh-gateway `
  --path skills/ssh-gateway
```

Linux or macOS shell:

```bash
python ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo TYzzt/ssh-gateway \
  --path skills/ssh-gateway
```

Notes:

- Restart Codex after installing the skill.
- The skill expects a local `ssh-gateway` binary and a valid config file to already exist.
- The skill is intentionally thin: it does not replace the CLI, it standardizes how the agent should call it.

## Release Workflow Overview

The repository ships a tag-driven GitHub Actions workflow at [.github/workflows/release.yml](.github/workflows/release.yml).

- Trigger: push a tag that matches `v*`
- Build matrix: Windows x64 and Linux x64
- Steps: checkout, install Rust stable, `cargo test --locked`, `cargo build --release --locked`, package artifacts, create GitHub Release, upload binaries plus `SHA256SUMS`
- Release notes: generated automatically by GitHub

Example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## License

Released under [Apache License 2.0](LICENSE).
