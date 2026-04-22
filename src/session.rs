use crate::agent::{expected_version, render_agent_script};
use crate::config::{
    normalize_local_path, AppConfig, DelegatedEndpoint, ResolvedProfile, ResolvedTransport,
};
use crate::errors::ArrtError;
use crate::protocol::{CommandResult, EnvVar, ErrorPayload, WriteMode};
use crate::ssh::{self, CommandOutput, EmbeddedSession};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub profile_name: String,
    pub transport: Arc<EmbeddedSession>,
    pub delegated_target: Option<DelegatedEndpoint>,
    pub upstream_profile: Option<String>,
    pub owns_transport: bool,
    pub agent_path: Option<String>,
    pub agent_version: Option<String>,
    pub last_used: Instant,
}

#[derive(Debug)]
pub struct TunnelInfo {
    pub session_id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub shutdown: Option<oneshot::Sender<()>>,
    pub task: JoinHandle<()>,
}

#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<String, SessionInfo>,
    profile_index: HashMap<String, String>,
    tunnels: HashMap<String, TunnelInfo>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sessions_json(&self) -> serde_json::Value {
        json!(
            self.sessions
                .values()
                .map(|session| self.session_summary(session))
                .collect::<Vec<_>>()
        )
    }

    pub fn session_json(&self, id: &str) -> Result<serde_json::Value, ArrtError> {
        let session = self
            .sessions
            .get(id)
            .ok_or_else(|| ArrtError::SessionNotFound(id.to_string()))?;
        Ok(self.session_summary(session))
    }

    pub async fn close_session(
        &mut self,
        config: &AppConfig,
        session_id: &str,
    ) -> Result<(), ArrtError> {
        let session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
        self.profile_index.remove(&session.profile_name);

        let tunnel_ids = self
            .tunnels
            .iter()
            .filter_map(|(tunnel_id, tunnel)| {
                if tunnel.session_id == session_id {
                    Some(tunnel_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for tunnel_id in tunnel_ids {
            let _ = self.tunnel_close(config, &tunnel_id).await;
        }

        if session.owns_transport {
            session.transport.disconnect().await;
        }
        Ok(())
    }

    pub async fn close_all(&mut self, config: &AppConfig) {
        let ids = self.sessions.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let _ = self.close_session(config, &id).await;
        }
    }

    pub async fn reap_idle_sessions(&mut self, config: &AppConfig) {
        let mut expired = Vec::new();
        for (session_id, session) in &self.sessions {
            if let Ok(profile) = config.resolved_profile(&session.profile_name) {
                if session.last_used.elapsed() > Duration::from_secs(profile.timeouts.idle_session_seconds) {
                    expired.push(session_id.clone());
                }
            }
        }
        for session_id in expired {
            let _ = self.close_session(config, &session_id).await;
        }
    }

    fn ensure_session<'a>(
        &'a mut self,
        config: &'a AppConfig,
        profile: &'a ResolvedProfile,
    ) -> Pin<Box<dyn Future<Output = Result<String, ArrtError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(session_id) = self.profile_index.get(&profile.name).cloned() {
                if let Some(existing) = self.sessions.get_mut(&session_id) {
                    if existing.transport.is_alive().await {
                        existing.last_used = Instant::now();
                        return Ok(session_id);
                    }
                }
                self.sessions.remove(&session_id);
                self.profile_index.remove(&profile.name);
            }

            let session_id = uuid::Uuid::new_v4().to_string();
            let (transport, delegated_target, upstream_profile, owns_transport) = match &profile.transport {
                ResolvedTransport::Direct { .. } => (
                    Arc::new(EmbeddedSession::connect(profile).await?),
                    None,
                    None,
                    true,
                ),
                ResolvedTransport::Delegated { via_profile, target } => {
                    let upstream = config.resolved_profile(via_profile)?;
                    let upstream_session_id = self.ensure_session(config, &upstream).await?;
                    let upstream_transport = self
                        .sessions
                        .get(&upstream_session_id)
                        .ok_or_else(|| ArrtError::SessionNotFound(upstream_session_id.clone()))?
                        .transport
                        .clone();
                    (
                        upstream_transport,
                        Some(target.clone()),
                        Some(via_profile.clone()),
                        false,
                    )
                }
            };
            let session = SessionInfo {
                session_id: session_id.clone(),
                profile_name: profile.name.clone(),
                transport,
                delegated_target,
                upstream_profile,
                owns_transport,
                agent_path: None,
                agent_version: None,
                last_used: Instant::now(),
            };
            self.profile_index
                .insert(profile.name.clone(), session_id.clone());
            self.sessions.insert(session_id.clone(), session);
            Ok(session_id)
        })
    }

    async fn ensure_agent(&mut self, profile: &ResolvedProfile, session_id: &str) -> Result<(), ArrtError> {
        let remote_path = profile.agent.remote_path.clone();
        let expected = expected_version(&profile.agent.version);
        let (transport, delegated_target) = {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
            (session.transport.clone(), session.delegated_target.clone())
        };

        let current_version = self
            .query_agent_version(transport.as_ref(), delegated_target.as_ref(), &remote_path)
            .await;
        let version = match current_version {
            Ok(version) if version == expected => version,
            _ => {
                self.install_agent(
                    transport.as_ref(),
                    delegated_target.as_ref(),
                    &remote_path,
                    &expected,
                )
                    .await?;
                let verified = self
                    .query_agent_version(transport.as_ref(), delegated_target.as_ref(), &remote_path)
                    .await?;
                if verified != expected {
                    return Err(ArrtError::Agent(format!(
                        "agent version mismatch after install: expected {}, got {}",
                        expected, verified
                    )));
                }
                verified
            }
        };

        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
        session.agent_path = Some(remote_path);
        session.agent_version = Some(version);
        session.last_used = Instant::now();
        Ok(())
    }

    async fn query_agent_version(
        &self,
        transport: &EmbeddedSession,
        delegated_target: Option<&DelegatedEndpoint>,
        remote_path: &str,
    ) -> Result<String, ArrtError> {
        let output = run_remote_argv(
            transport,
            delegated_target,
            &[remote_path.to_string(), "version".to_string()],
            None,
        )
            .await?;
        if output.exit_code != 0 {
            return Err(ArrtError::Agent(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if version.is_empty() {
            return Err(ArrtError::Agent("remote agent returned empty version".to_string()));
        }
        Ok(version)
    }

    async fn install_agent(
        &self,
        transport: &EmbeddedSession,
        delegated_target: Option<&DelegatedEndpoint>,
        remote_path: &str,
        version: &str,
    ) -> Result<(), ArrtError> {
        let script = render_agent_script(version);
        let parent = remote_parent(remote_path);
        let target_stage = format!("{}.{}", remote_path, uuid::Uuid::new_v4());
        let command = format!(
            "mkdir -p {} && cat > {} && chmod 700 {} && mv {} {}",
            ssh::shell_quote(&parent),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(remote_path)
        );
        let output = run_remote_command(transport, delegated_target, &command, Some(script.as_bytes())).await?;
        if output.exit_code == 0 {
            return Ok(());
        }
        Err(ArrtError::Agent(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    async fn invoke_agent(
        &mut self,
        session_id: &str,
        args: Vec<String>,
        input: Option<&[u8]>,
    ) -> Result<CommandResult, ArrtError> {
        let (transport, delegated_target, agent_path) = {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
            (
                session.transport.clone(),
                session.delegated_target.clone(),
                session.agent_path.clone().ok_or_else(|| {
                    ArrtError::Agent(format!("agent is not ready for session {}", session_id))
                })?,
            )
        };

        let mut remote_args = Vec::with_capacity(1 + args.len());
        remote_args.push(agent_path);
        remote_args.extend(args);
        let output = run_remote_argv(transport.as_ref(), delegated_target.as_ref(), &remote_args, input).await?;
        let result = parse_agent_output(output)?;
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_used = Instant::now();
        }
        Ok(result)
    }

    pub async fn exec(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        command: String,
        cwd: Option<String>,
        timeout_seconds: Option<u64>,
        env: Vec<EnvVar>,
    ) -> Result<CommandResult, ArrtError> {
        let profile = config.resolved_profile(profile_name)?;
        let session_id = self.ensure_session(config, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let started = Instant::now();
        let mut args = vec![
            "exec".to_string(),
            cwd.map(|value| BASE64.encode(value))
                .unwrap_or_else(|| "-".to_string()),
            timeout_seconds
                .unwrap_or(profile.timeouts.exec_seconds)
                .to_string(),
            BASE64.encode(command),
        ];
        args.extend(
            env.into_iter()
                .map(|item| BASE64.encode(format!("{}={}", item.key, item.value))),
        );
        let mut result = self.invoke_agent(&session_id, args, None).await?;
        result.duration_ms = Some(started.elapsed().as_millis());
        result.session_id = Some(session_id);
        Ok(result)
    }

    pub async fn read(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        path: String,
    ) -> Result<CommandResult, ArrtError> {
        let profile = config.resolved_profile(profile_name)?;
        let session_id = self.ensure_session(config, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let mut result = self
            .invoke_agent(
                &session_id,
                vec!["read".to_string(), BASE64.encode(path)],
                None,
            )
            .await?;
        let content_b64 = result
            .data
            .as_ref()
            .and_then(|value| value.get("stdout_b64"))
            .cloned()
            .unwrap_or_else(|| json!(BASE64.encode(result.stdout.as_bytes())));
        result.data = Some(json!({
            "content_b64": content_b64,
        }));
        result.session_id = Some(session_id);
        Ok(result)
    }

    pub async fn write(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        path: String,
        mode: WriteMode,
        content_b64: String,
    ) -> Result<CommandResult, ArrtError> {
        let profile = config.resolved_profile(profile_name)?;
        let session_id = self.ensure_session(config, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let content = BASE64
            .decode(content_b64.as_bytes())
            .map_err(|err| ArrtError::InvalidArgument(format!("invalid content_b64: {err}")))?;
        let mut result = self
            .invoke_agent(
                &session_id,
                vec![
                    "write".to_string(),
                    write_mode_name(mode).to_string(),
                    BASE64.encode(path),
                ],
                Some(&content),
            )
            .await?;
        result.session_id = Some(session_id);
        Ok(result)
    }

    pub async fn upload(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        src: String,
        dst: String,
    ) -> Result<CommandResult, ArrtError> {
        let src = normalize_local_path(&src)?;
        let content = fs::read(&src).await?;
        let result = self
            .write(
                config,
                profile_name,
                dst,
                WriteMode::Truncate,
                BASE64.encode(content),
            )
            .await?;
        Ok(result)
    }

    pub async fn download(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        src: String,
        dst: String,
    ) -> Result<CommandResult, ArrtError> {
        let mut result = self.read(config, profile_name, src).await?;
        let content_b64 = result
            .data
            .as_ref()
            .and_then(|value| value.get("content_b64"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| ArrtError::Agent("missing content_b64 in read result".to_string()))?;
        let content = BASE64
            .decode(content_b64.as_bytes())
            .map_err(|err| ArrtError::Agent(format!("invalid content_b64 in read result: {err}")))?;
        let dst = normalize_local_path(&dst)?;
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        fs::write(&dst, content).await?;
        result.data = Some(json!({
            "saved_to": dst.display().to_string(),
        }));
        Ok(result)
    }

    pub async fn tunnel_open(
        &mut self,
        config: &AppConfig,
        profile_name: &str,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    ) -> Result<CommandResult, ArrtError> {
        let profile = config.resolved_profile(profile_name)?;
        let session_id = self.ensure_session(config, &profile).await?;
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.clone()))?;
        if session.delegated_target.is_some() {
            return Err(ArrtError::InvalidArgument(
                "tunnel open is not supported for via_profile delegated sessions".to_string(),
            ));
        }
        let transport = session.transport.clone();

        let listener = TcpListener::bind(("127.0.0.1", local_port)).await?;
        let actual_local_port = listener.local_addr()?.port();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let remote_host_for_task = remote_host.clone();
        let transport_for_task = transport.clone();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((socket, originator)) = accepted else {
                            break;
                        };
                        let tunnel_transport = transport_for_task.clone();
                        let tunnel_host = remote_host_for_task.clone();
                        tokio::spawn(async move {
                            let _ = tunnel_transport
                                .proxy_tcp_stream(socket, &tunnel_host, remote_port, originator)
                                .await;
                        });
                    }
                }
            }
        });

        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.last_used = Instant::now();
        }

        let tunnel_id = uuid::Uuid::new_v4().to_string();
        self.tunnels.insert(
            tunnel_id.clone(),
            TunnelInfo {
                session_id: session_id.clone(),
                local_port: actual_local_port,
                remote_host: remote_host.clone(),
                remote_port,
                shutdown: Some(shutdown_tx),
                task,
            },
        );

        let mut result = CommandResult::success();
        result.session_id = Some(session_id);
        result.data = Some(json!({
            "tunnel_id": tunnel_id,
            "local_port": actual_local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
        }));
        Ok(result)
    }

    pub async fn tunnel_close(
        &mut self,
        _config: &AppConfig,
        tunnel_id: &str,
    ) -> Result<CommandResult, ArrtError> {
        let mut tunnel = self
            .tunnels
            .remove(tunnel_id)
            .ok_or_else(|| ArrtError::InvalidArgument(format!("unknown tunnel id: {}", tunnel_id)))?;

        if let Some(session) = self.sessions.get_mut(&tunnel.session_id) {
            session.last_used = Instant::now();
        }

        if let Some(shutdown) = tunnel.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tunnel.task.await;

        let mut result = CommandResult::success();
        result.data = Some(json!({
            "closed": tunnel_id,
            "local_port": tunnel.local_port,
            "remote_host": tunnel.remote_host,
            "remote_port": tunnel.remote_port,
        }));
        Ok(result)
    }

    fn session_summary(&self, session: &SessionInfo) -> serde_json::Value {
        json!({
            "session_id": session.session_id,
            "profile": session.profile_name,
            "transport": session.transport.transport_name(),
            "upstream_profile": session.upstream_profile,
            "delegated_target": session.delegated_target.as_ref().map(|target| {
                json!({
                    "host": target.host,
                    "user": target.user,
                    "port": target.port,
                })
            }),
            "reused": true,
            "agent_path": session.agent_path,
            "agent_version": session.agent_version,
            "agent_ready": session.agent_path.is_some() && session.agent_version.is_some(),
        })
    }
}

async fn run_remote_argv(
    transport: &EmbeddedSession,
    delegated_target: Option<&DelegatedEndpoint>,
    argv: &[String],
    input: Option<&[u8]>,
) -> Result<CommandOutput, ArrtError> {
    match delegated_target {
        Some(target) => {
            let command = ssh::shell_join(&delegate_ssh_tokens(target, argv));
            transport.run_command(&command, input).await
        }
        None => transport.run_argv(argv, input).await,
    }
}

async fn run_remote_command(
    transport: &EmbeddedSession,
    delegated_target: Option<&DelegatedEndpoint>,
    command: &str,
    input: Option<&[u8]>,
) -> Result<CommandOutput, ArrtError> {
    match delegated_target {
        Some(target) => {
            let remote = format!("sh -lc {}", ssh::shell_quote(command));
            let wrapped = format!(
                "{} {}",
                delegate_ssh_prefix(target),
                ssh::shell_quote(&remote)
            );
            transport.run_command(&wrapped, input).await
        }
        None => transport.run_command(command, input).await,
    }
}

fn delegate_ssh_tokens(target: &DelegatedEndpoint, remote_args: &[String]) -> Vec<String> {
    let mut tokens = delegate_ssh_base_tokens(target);
    tokens.extend(remote_args.iter().cloned());
    tokens
}

fn delegate_ssh_prefix(target: &DelegatedEndpoint) -> String {
    ssh::shell_join(&delegate_ssh_base_tokens(target))
}

fn delegate_ssh_base_tokens(target: &DelegatedEndpoint) -> Vec<String> {
    let mut tokens = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
    ];
    if !target.user.trim().is_empty() {
        tokens.push("-l".to_string());
        tokens.push(target.user.clone());
    }
    if target.port != 22 {
        tokens.push("-p".to_string());
        tokens.push(target.port.to_string());
    }
    tokens.push(target.host.clone());
    tokens
}

fn write_mode_name(mode: WriteMode) -> &'static str {
    match mode {
        WriteMode::Create => "create",
        WriteMode::Truncate => "truncate",
        WriteMode::Append => "append",
    }
}

fn remote_parent(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(index) => path[..index].to_string(),
        None => ".".to_string(),
    }
}

fn parse_agent_output(output: CommandOutput) -> Result<CommandResult, ArrtError> {
    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let mut parts = stdout_text.splitn(3, '\n');
    let exit_code = parts
        .next()
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or_else(|| {
            ArrtError::Agent(format!(
                "invalid agent response: stdout={}, stderr={}",
                stdout_text.trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        })?;
    let stdout_b64 = parts.next().unwrap_or("").trim();
    let stderr_b64 = parts.next().unwrap_or("").trim();
    let stdout_bytes = decode_base64_field(stdout_b64)?;
    let stderr_bytes = decode_base64_field(stderr_b64)?;
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let mut result = CommandResult::success();
    result.ok = exit_code == 0;
    result.exit_code = Some(exit_code);
    result.stdout = stdout;
    result.stderr = stderr.clone();
    result.data = Some(json!({
        "stdout_b64": BASE64.encode(&stdout_bytes),
        "stderr_b64": BASE64.encode(&stderr_bytes),
    }));
    if !result.ok {
        result.error = Some(ErrorPayload {
            code: "remote_command_failed".to_string(),
            message: if stderr.is_empty() {
                format!("remote command exited with {}", exit_code)
            } else {
                stderr
            },
        });
    }
    Ok(result)
}

fn decode_base64_field(raw: &str) -> Result<Vec<u8>, ArrtError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    BASE64
        .decode(raw.as_bytes())
        .map_err(|err| ArrtError::Agent(format!("invalid base64 from remote agent: {err}")))
}
