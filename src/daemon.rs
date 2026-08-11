use crate::config::{config_path_display, AppConfig};
use crate::errors::ArrtError;
use crate::ipc;
use crate::protocol::{CommandResult, ErrorPayload, Request, RpcRequest, RpcResponse};
use crate::session::{absolute_local_path, SessionManager};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

pub struct DaemonState {
    sessions: Mutex<SessionManager>,
    pub(crate) shutdown: Notify,
}

impl DaemonState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(SessionManager::new()),
            shutdown: Notify::new(),
        })
    }

    pub async fn serve(self: Arc<Self>) -> Result<(), ArrtError> {
        ipc::serve(self).await
    }

    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub async fn handle(self: Arc<Self>, request: RpcRequest) -> RpcResponse {
        let rpc_request = request.request.clone();
        let result = match self.handle_inner(rpc_request.clone()).await {
            Ok(result) => result,
            Err(err) => error_result_with_request(err, &rpc_request),
        };
        RpcResponse {
            request_id: request.request_id,
            result,
        }
    }

    async fn handle_inner(&self, request: Request) -> Result<CommandResult, ArrtError> {
        match request {
            Request::Ping => Ok(CommandResult::success().with_data(json!({
                "status": "ok",
                "config_path": config_path_display()?,
            }))),
            Request::Shutdown => {
                if let Ok(config) = AppConfig::load().await {
                    self.sessions.lock().await.close_all(&config).await;
                }
                Ok(CommandResult::success().with_data(json!({"status":"stopping"})))
            }
            Request::ProfileList => {
                let config = AppConfig::load().await?;
                Ok(CommandResult::success().with_data(json!({
                    "profiles": config.profiles.iter().map(|p| &p.name).collect::<Vec<_>>()
                })))
            }
            Request::ProfileShow { name } => {
                let config = AppConfig::load().await?;
                Ok(CommandResult::success().with_data(config.profile_summary(&name)?))
            }
            Request::ProfileValidate { name } => {
                let config = AppConfig::load().await?;
                config.validate()?;
                if let Some(name) = name {
                    let profile = config.profile(&name)?;
                    Ok(CommandResult::success()
                        .with_data(json!({"valid": true, "profile": profile.name })))
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
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions
                    .exec(&config, &profile, command, cwd, timeout_seconds, env)
                    .await
            }
            Request::Read { profile, path } => {
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions.read(&config, &profile, path).await
            }
            Request::Write {
                profile,
                path,
                mode,
                content_b64,
            } => {
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions
                    .write(&config, &profile, path, mode, content_b64)
                    .await
            }
            Request::Upload { profile, src, dst } => {
                absolute_local_path(src.clone(), "upload src")?;
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions.upload(&config, &profile, src, dst).await
            }
            Request::Download { profile, src, dst } => {
                absolute_local_path(dst.clone(), "download dst")?;
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions.download(&config, &profile, src, dst).await
            }
            Request::TunnelOpen {
                profile,
                local_port,
                remote_host,
                remote_port,
            } => {
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(&config).await;
                sessions
                    .tunnel_open(&config, &profile, local_port, remote_host, remote_port)
                    .await
            }
            Request::TunnelClose { tunnel_id } => {
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.tunnel_close(&config, &tunnel_id).await
            }
            Request::SessionList => {
                let sessions = self.sessions.lock().await;
                Ok(CommandResult::success().with_data(json!({
                    "sessions": sessions.sessions_json()
                })))
            }
            Request::SessionInspect { session_id } => {
                let sessions = self.sessions.lock().await;
                Ok(CommandResult::success().with_data(json!({
                    "session": sessions.session_json(&session_id)?
                })))
            }
            Request::SessionClose { session_id } => {
                let config = AppConfig::load().await?;
                let mut sessions = self.sessions.lock().await;
                sessions.close_session(&config, &session_id).await?;
                Ok(CommandResult::success().with_data(json!({"closed": session_id})))
            }
        }
    }
}

fn error_result_with_request(err: ArrtError, request: &Request) -> CommandResult {
    let data = match request {
        Request::Upload { src, dst, .. } => Some(json!({
            "local_src": src,
            "remote_dst": dst,
        })),
        Request::Download { src, dst, .. } => Some(json!({
            "remote_src": src,
            "local_dst": dst,
        })),
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn send_direct_rpc(request: Request) -> CommandResult {
        DaemonState::new()
            .handle(RpcRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                request,
            })
            .await
            .result
    }

    #[tokio::test]
    async fn direct_rpc_rejects_relative_upload_source_before_config_load() {
        let result = send_direct_rpc(Request::Upload {
            profile: "unused".to_string(),
            src: "relative/input.txt".to_string(),
            dst: "/tmp/input.txt".to_string(),
        })
        .await;

        assert_eq!(result.error.unwrap().code, "relative_local_path");
        assert_eq!(result.data.unwrap()["local_src"], "relative/input.txt");
    }

    #[tokio::test]
    async fn direct_rpc_rejects_relative_download_destination_before_config_load() {
        let result = send_direct_rpc(Request::Download {
            profile: "unused".to_string(),
            src: "/tmp/output.txt".to_string(),
            dst: "relative/output.txt".to_string(),
        })
        .await;

        assert_eq!(result.error.unwrap().code, "relative_local_path");
        assert_eq!(result.data.unwrap()["local_dst"], "relative/output.txt");
    }

    #[test]
    fn transfer_errors_include_local_and_remote_paths() {
        #[cfg(windows)]
        let local_src = r"C:\Users\caller\input.txt";
        #[cfg(not(windows))]
        let local_src = "/home/caller/input.txt";
        let request = Request::Upload {
            profile: "unused".to_string(),
            src: local_src.to_string(),
            dst: "/tmp/input.txt".to_string(),
        };

        let result = error_result_with_request(ArrtError::Io("read failed".to_string()), &request);

        let data = result.data.unwrap();
        assert_eq!(data["local_src"], local_src);
        assert_eq!(data["remote_dst"], "/tmp/input.txt");
    }
}
