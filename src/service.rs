use crate::approval::{request_hash, ApprovalService};
use crate::config::{config_path_display, AppConfig};
use crate::errors::ArrtError;
use crate::policy::{PolicyEffect, PolicyEngine};
use crate::protocol::{CallerType, CommandResult, ErrorPayload, Request};
use crate::redaction::SecretRedactor;
use crate::session::{absolute_local_path, SessionManager};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct PublicProfileInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<&'static str>,
}

pub struct GatewayService {
    sessions: Mutex<SessionManager>,
    maintenance_started: AtomicBool,
}

impl GatewayService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(SessionManager::new()),
            maintenance_started: AtomicBool::new(false),
        })
    }

    pub fn start_maintenance(self: &Arc<Self>) {
        if self.maintenance_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let service = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                if let Ok(config) = AppConfig::load().await {
                    service
                        .sessions
                        .lock()
                        .await
                        .reap_idle_sessions(&config)
                        .await;
                }
            }
        });
    }

    pub async fn list_hosts(
        &self,
        request_id: &str,
        caller: CallerType,
    ) -> Result<Vec<PublicProfileInfo>, ArrtError> {
        let started = Instant::now();
        let config = AppConfig::load().await?;
        let redactor = SecretRedactor::from_config(&config);
        let hosts = config
            .profiles
            .iter()
            .map(|profile| {
                let caps = &profile.agent_policy.capabilities;
                let mut capabilities = Vec::new();
                for (enabled, name) in [
                    (
                        caps.exec && !profile.agent_policy.allowed_commands.is_empty(),
                        "exec",
                    ),
                    (caps.read, "read"),
                    (caps.write, "write"),
                    (caps.upload, "upload"),
                    (caps.download, "download"),
                    (caps.tunnel, "tunnel"),
                ] {
                    if enabled {
                        capabilities.push(name);
                    }
                }
                PublicProfileInfo {
                    name: profile.name.clone(),
                    description: profile
                        .description
                        .as_ref()
                        .map(|value| redactor.redact(value)),
                    capabilities,
                }
            })
            .collect();
        audit(
            &config,
            request_id,
            caller,
            &Request::ProfileList,
            started,
            &CommandResult::success(),
            &redactor,
        );
        Ok(hosts)
    }

    pub async fn execute(
        &self,
        request_id: &str,
        caller: CallerType,
        request: Request,
    ) -> CommandResult {
        let started = Instant::now();
        if let Err(err) = prevalidate(&request) {
            return error_result(err, &request);
        }
        if let Err(err) = PolicyEngine::authorize_caller(caller, &request) {
            return error_result(err, &request);
        }
        if matches!(request, Request::Ping) {
            return CommandResult::success().with_data(json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "config_path": config_path_display().unwrap_or_else(|_| "unavailable".to_string()),
            }));
        }
        if matches!(request, Request::Shutdown) {
            self.shutdown().await;
            return CommandResult::success().with_data(json!({"status":"stopping"}));
        }
        let config = AppConfig::load().await;
        let mut result = match config {
            Ok(config) => {
                let redactor = SecretRedactor::from_config(&config);
                let result = if matches!(
                    request,
                    Request::ApprovalList
                        | Request::ApprovalShow { .. }
                        | Request::ApprovalApprove { .. }
                        | Request::ApprovalReject { .. }
                        | Request::ApprovalCleanup
                ) {
                    self.execute_approval(&config, caller, request.clone())
                        .await
                } else {
                    match PolicyEngine::authorize(&config, caller, &request) {
                        Ok(decision) if decision.effect == PolicyEffect::Allow => {
                            self.execute_authorized(&config, caller, request.clone())
                                .await
                        }
                    Ok(decision) if decision.effect == PolicyEffect::Confirm => {
                        ApprovalService::from_config(&config).and_then(|service| service.create(
                            &request, caller, decision.rule_id.as_deref(), decision.reason.as_deref(), decision.risk, &redactor
                        )).map(|approval| {
                            let mut audit_metadata=approval.clone();
                            if let Some(object)=audit_metadata.as_object_mut(){object.insert("rule".into(),json!(decision.rule_id));}
                            audit_approval("approval_created", &audit_metadata, caller);
                            CommandResult::success().with_data(json!({"status":"confirmation_required","approval":approval}))
                        })
                        }
                        Ok(decision) => Err(ArrtError::PolicyDenied(
                            decision
                                .reason
                                .unwrap_or_else(|| "policy rule denied operation".into()),
                        )),
                        Err(err) => Err(err),
                    }
                };
                let mut result = result.unwrap_or_else(|err| error_result(err, &request));
                redact_result(&redactor, &mut result);
                audit(
                    &config, request_id, caller, &request, started, &result, &redactor,
                );
                result
            }
            Err(err) => error_result(err, &request),
        };
        if result.duration_ms.is_none() && matches!(request, Request::Exec { .. }) {
            result.duration_ms = Some(started.elapsed().as_millis());
        }
        result
    }

    async fn execute_approval(
        &self,
        config: &AppConfig,
        caller: CallerType,
        request: Request,
    ) -> Result<CommandResult, ArrtError> {
        if caller != CallerType::HumanCli {
            return Err(ArrtError::PolicyDenied(
                "approval administration requires Human CLI".into(),
            ));
        }
        let approvals = ApprovalService::from_config(config)?;
        match request {
            Request::ApprovalList => {
                Ok(CommandResult::success().with_data(json!({"approvals":approvals.list()?})))
            }
            Request::ApprovalShow { approval_id } => Ok(CommandResult::success()
                .with_data(json!({"approval":approvals.show(&approval_id)?}))),
            Request::ApprovalReject { approval_id } => {
                let data = approvals.reject(&approval_id)?;
                audit_approval("approval_rejected", &approvals.show(&approval_id)?, caller);
                Ok(CommandResult::success().with_data(data))
            }
            Request::ApprovalCleanup => {
                Ok(CommandResult::success().with_data(approvals.cleanup()?))
            }
            Request::ApprovalApprove { approval_id } => {
                let claim = approvals.claim(&approval_id)?;
                let current_hash = request_hash(&claim.request);
                if current_hash.as_ref().is_err_and(|_| true)
                    || current_hash.is_ok_and(|hash| hash != claim.request_hash)
                {
                    let failed = error_result(
                        ArrtError::Approval("request changed after approval creation".into()),
                        &claim.request,
                    );
                    approvals.finish(&claim.id, &failed)?;
                    return Ok(failed);
                }
                let decision = match PolicyEngine::authorize(config, claim.caller, &claim.request) {
                    Ok(decision) => decision,
                    Err(err) => {
                        let failed = error_result(err, &claim.request);
                        approvals.finish(&claim.id, &failed)?;
                        return Ok(failed);
                    }
                };
                if decision.effect == PolicyEffect::Deny {
                    let failed = error_result(
                        ArrtError::PolicyDenied(
                            decision
                                .reason
                                .unwrap_or_else(|| "policy now denies operation".into()),
                        ),
                        &claim.request,
                    );
                    approvals.finish(&claim.id, &failed)?;
                    return Ok(failed);
                }
                audit_approval("approval_approved", &approvals.show(&claim.id)?, caller);
                let mut result = self
                    .execute_authorized(config, claim.caller, claim.request.clone())
                    .await
                    .unwrap_or_else(|e| error_result(e, &claim.request));
                let redactor = SecretRedactor::from_config(config);
                redact_result(&redactor, &mut result);
                approvals.finish(&claim.id, &result)?;
                audit_approval(
                    if result.ok {
                        "approval_executed"
                    } else {
                        "approval_failed"
                    },
                    &approvals.show(&claim.id)?,
                    caller,
                );
                Ok(CommandResult::success().with_data(json!({"status":if result.ok{"executed"}else{"failed"},"approval_id":claim.id,"result":result})))
            }
            _ => Err(ArrtError::InvalidArgument("not an approval request".into())),
        }
    }

    pub async fn shutdown(&self) {
        if let Ok(config) = AppConfig::load().await {
            self.sessions.lock().await.close_all(&config).await;
        }
    }

    async fn execute_authorized(
        &self,
        config: &AppConfig,
        caller: CallerType,
        request: Request,
    ) -> Result<CommandResult, ArrtError> {
        match request {
            Request::Ping => Ok(CommandResult::success().with_data(json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            }))),
            Request::Shutdown => {
                self.sessions.lock().await.close_all(config).await;
                Ok(CommandResult::success().with_data(json!({"status":"stopping"})))
            }
            Request::ProfileList => Ok(CommandResult::success().with_data(json!({
                "profiles": config.profiles.iter().map(|profile| &profile.name).collect::<Vec<_>>()
            }))),
            Request::ProfileShow { name } => {
                Ok(CommandResult::success().with_data(config.profile_summary(&name)?))
            }
            Request::ProfileValidate { name } => {
                config.validate()?;
                if let Some(name) = name {
                    let profile = config.profile(&name)?;
                    Ok(CommandResult::success()
                        .with_data(json!({"valid": true, "profile": profile.name})))
                } else {
                    Ok(CommandResult::success()
                        .with_data(json!({"valid": true, "profiles": config.profiles.len()})))
                }
            }
            Request::Exec {
                profile,
                command,
                cwd,
                timeout_seconds,
                env,
            } => {
                let prepared = {
                    let mut sessions = self.sessions.lock().await;
                    sessions.reap_idle_sessions(config).await;
                    sessions
                        .prepare_exec(config, &profile, command, cwd, timeout_seconds, env)
                        .await?
                };
                let session_id = prepared.session_id().to_string();
                let result = SessionManager::execute_prepared_exec(&prepared).await;
                self.sessions.lock().await.finish_exec(&session_id);
                result
            }
            Request::Read { profile, path } => {
                let roots = allowed_remote_paths(config, caller, &profile, false)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config).await;
                sessions.read(config, &profile, path, &roots).await
            }
            Request::Write {
                profile,
                path,
                mode,
                content_b64,
            } => {
                let roots = allowed_remote_paths(config, caller, &profile, true)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config).await;
                sessions
                    .write(config, &profile, path, mode, content_b64, &roots)
                    .await
            }
            Request::Upload { profile, src, dst } => {
                absolute_local_path(src.clone(), "upload src")?;
                let roots = allowed_remote_paths(config, caller, &profile, true)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config).await;
                sessions.upload(config, &profile, src, dst, &roots).await
            }
            Request::Download { profile, src, dst } => {
                absolute_local_path(dst.clone(), "download dst")?;
                let roots = allowed_remote_paths(config, caller, &profile, false)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config).await;
                sessions.download(config, &profile, src, dst, &roots).await
            }
            Request::TunnelOpen {
                profile,
                local_port,
                remote_host,
                remote_port,
            } => {
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config).await;
                sessions
                    .tunnel_open(config, &profile, local_port, remote_host, remote_port)
                    .await
            }
            Request::TunnelClose { tunnel_id, profile } => {
                let mut sessions = self.sessions.lock().await;
                if let Some(expected_profile) = profile {
                    if sessions.tunnel_profile(&tunnel_id) != Some(expected_profile.as_str()) {
                        return Err(ArrtError::PolicyDenied(
                            "tunnel does not belong to the supplied profile".to_string(),
                        ));
                    }
                }
                sessions.tunnel_close(config, &tunnel_id).await
            }
            Request::SessionList => Ok(CommandResult::success().with_data(json!({
                "sessions": self.sessions.lock().await.sessions_json()
            }))),
            Request::SessionInspect { session_id } => {
                Ok(CommandResult::success().with_data(json!({
                    "session": self.sessions.lock().await.session_json(&session_id)?
                })))
            }
            Request::SessionClose { session_id } => {
                self.sessions
                    .lock()
                    .await
                    .close_session(config, &session_id)
                    .await?;
                Ok(CommandResult::success().with_data(json!({"closed": session_id})))
            }
            Request::ApprovalList
            | Request::ApprovalShow { .. }
            | Request::ApprovalApprove { .. }
            | Request::ApprovalReject { .. }
            | Request::ApprovalCleanup => Err(ArrtError::InvalidArgument(
                "approval request reached operation executor".into(),
            )),
        }
    }
}

fn allowed_remote_paths(
    config: &AppConfig,
    caller: CallerType,
    profile: &str,
    write: bool,
) -> Result<Vec<String>, ArrtError> {
    if !caller.enforces_agent_policy() {
        return Ok(Vec::new());
    }
    let policy = config.profile(profile)?.agent_policy;
    Ok(if write {
        policy.allowed_write_paths
    } else {
        policy.allowed_read_paths
    })
}

fn prevalidate(request: &Request) -> Result<(), ArrtError> {
    match request {
        Request::Upload { src, .. } => absolute_local_path(src.clone(), "upload src").map(|_| ()),
        Request::Download { dst, .. } => {
            absolute_local_path(dst.clone(), "download dst").map(|_| ())
        }
        _ => Ok(()),
    }
}

fn error_result(err: ArrtError, request: &Request) -> CommandResult {
    let data = match request {
        Request::Upload { src, dst, .. } => Some(json!({"local_src": src, "remote_dst": dst})),
        Request::Download { src, dst, .. } => Some(json!({"remote_src": src, "local_dst": dst})),
        _ => None,
    };
    CommandResult {
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        duration_ms: None,
        session_id: None,
        error: Some(ErrorPayload {
            code: err.code().to_string(),
            message: err.to_string(),
        }),
        data,
    }
}

fn redact_result(redactor: &SecretRedactor, result: &mut CommandResult) {
    result.stdout = redactor.redact(&result.stdout);
    result.stderr = redactor.redact(&result.stderr);
    if let Some(error) = &mut result.error {
        error.message = redactor.redact(&error.message);
    }
    if let Some(data) = &mut result.data {
        redactor.redact_value(data);
    }
}

fn audit(
    config: &AppConfig,
    request_id: &str,
    caller: CallerType,
    request: &Request,
    started: Instant,
    result: &CommandResult,
    redactor: &SecretRedactor,
) {
    let profile = request_profile(request);
    let command = match request {
        Request::Exec {
            profile, command, ..
        } if config
            .profile(profile)
            .is_ok_and(|p| p.agent_policy.audit_command) =>
        {
            Some(redactor.redact(command))
        }
        _ => None,
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    eprintln!(
        "{}",
        json!({
            "event": "ssh_gateway_audit",
            "timestamp_ms": timestamp_ms,
            "request_id": request_id,
            "caller": format!("{caller:?}").to_ascii_lowercase(),
            "tool": request_name(request),
            "profile": profile,
            "command": command,
            "duration_ms": started.elapsed().as_millis(),
            "result": if result.ok { "ok" } else { "error" },
            "error_code": result.error.as_ref().map(|error| &error.code),
        })
    );
}

fn request_profile(request: &Request) -> Option<&str> {
    match request {
        Request::Exec { profile, .. }
        | Request::Read { profile, .. }
        | Request::Write { profile, .. }
        | Request::Upload { profile, .. }
        | Request::Download { profile, .. }
        | Request::TunnelOpen { profile, .. } => Some(profile),
        _ => None,
    }
}

fn request_name(request: &Request) -> &'static str {
    match request {
        Request::Ping => "ping",
        Request::Shutdown => "shutdown",
        Request::ProfileList => "profile_list",
        Request::ProfileShow { .. } => "profile_show",
        Request::ProfileValidate { .. } => "profile_validate",
        Request::Exec { .. } => "exec",
        Request::Read { .. } => "read",
        Request::Write { .. } => "write",
        Request::Upload { .. } => "upload",
        Request::Download { .. } => "download",
        Request::TunnelOpen { .. } => "tunnel_open",
        Request::TunnelClose { .. } => "tunnel_close",
        Request::SessionList => "session_list",
        Request::SessionInspect { .. } => "session_inspect",
        Request::SessionClose { .. } => "session_close",
        Request::ApprovalList => "approval_list",
        Request::ApprovalShow { .. } => "approval_show",
        Request::ApprovalApprove { .. } => "approval_approve",
        Request::ApprovalReject { .. } => "approval_reject",
        Request::ApprovalCleanup => "approval_cleanup",
    }
}

fn audit_approval(event: &str, metadata: &serde_json::Value, caller: CallerType) {
    eprintln!(
        "{}",
        json!({"event":event,"caller":format!("{caller:?}").to_ascii_lowercase(),"metadata":metadata,"timestamp_ms":SystemTime::now().duration_since(UNIX_EPOCH).map_or(0,|d|d.as_millis())})
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_prevalidation_preserves_daemon_boundary() {
        let upload = Request::Upload {
            profile: "unused".to_string(),
            src: "relative/input.txt".to_string(),
            dst: "/tmp/input.txt".to_string(),
        };
        let download = Request::Download {
            profile: "unused".to_string(),
            src: "/tmp/output.txt".to_string(),
            dst: "relative/output.txt".to_string(),
        };
        assert_eq!(
            prevalidate(&upload).unwrap_err().code(),
            "relative_local_path"
        );
        assert_eq!(
            prevalidate(&download).unwrap_err().code(),
            "relative_local_path"
        );
        assert_eq!(
            error_result(ArrtError::Io("failed".into()), &upload)
                .data
                .unwrap()["local_src"],
            "relative/input.txt"
        );
    }

    #[tokio::test]
    async fn shutdown_respects_caller_policy_before_lifecycle_shortcut() {
        let service = GatewayService::new();
        let human = service
            .execute("human", CallerType::HumanCli, Request::Shutdown)
            .await;
        let agent = service
            .execute("agent", CallerType::AgentCli, Request::Shutdown)
            .await;
        let mcp = service
            .execute("mcp", CallerType::Mcp, Request::Shutdown)
            .await;

        assert!(human.ok);
        assert_eq!(human.data.unwrap()["status"], "stopping");
        assert_eq!(agent.error.unwrap().code, "policy_denied");
        assert_eq!(mcp.error.unwrap().code, "policy_denied");
    }
}
