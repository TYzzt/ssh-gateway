# Architecture (v0.2.0)

The binary exposes CLI/IPC and MCP adapters. MCP authenticates Bearer or OAuth JWT callers and creates a `Principal`; CLI/IPC callers receive a local principal. `GatewayService` uses the principal for audit and a deterministic session namespace. An OAuth audience selects the MCP resource configuration; the JWT subject identifies the caller.

```text
CLI / MCP -> Principal -> GatewayService -> Policy / Approval
                                  |               |
                           AuditSink        ApprovalStore
                                  |
                           ProfileStore -> CredentialStore -> SessionManager
                                                               |
                                                       TargetPolicy -> SSH
                                                                    HostKeyVerifier
```

The default providers are file backed profiles, file based password/key resolution, SQLite approvals, and JSON audit events on stderr. The provider interfaces are in `src/storage.rs` and `src/audit.rs`. SSH transport has no MCP dependency. The current binary remains `sshmcp`.

The legacy YAML `Profile` is a configuration input and may contain credentials. MCP profile listings and summaries are projected to public metadata. `ResolvedProfile` carries credentials only in the execution path. Self-hosted YAML password and key authentication remain supported.

Cloud mode is a runtime safety setting, not a hosted control plane. No account database, Portal, KMS, or hosted deployment is included.
