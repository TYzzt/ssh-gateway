use crate::config::{ResolvedAuthConfig, ResolvedEndpoint, ResolvedProfile};
use crate::errors::ArrtError;
use russh::client::{self, Handle};
use russh::keys::{load_secret_key, ssh_key::PublicKey, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TRANSPORT_NAME: &str = "embedded_ssh";
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(10);

type ClientHandle = Handle<GatewayClient>;

#[derive(Clone)]
pub struct EmbeddedSession {
    handles: Vec<Arc<ClientHandle>>,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
struct GatewayClient;

impl client::Handler for GatewayClient {
    type Error = ArrtError;

    async fn check_server_key(&mut self, _server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl EmbeddedSession {
    pub async fn connect(profile: &ResolvedProfile) -> Result<Self, ArrtError> {
        let config = Arc::new(client::Config {
            nodelay: true,
            ..Default::default()
        });

        let chain = profile
            .direct_chain()
            .ok_or_else(|| ArrtError::Ssh("embedded ssh transport requires a direct profile chain".to_string()))?;
        let mut handles: Vec<Arc<ClientHandle>> = Vec::with_capacity(chain.len());
        for endpoint in chain {
            let handle = if let Some(parent) = handles.last() {
                connect_via_channel(config.clone(), parent.clone(), endpoint).await?
            } else {
                connect_direct(config.clone(), endpoint).await?
            };
            handles.push(Arc::new(handle));
        }

        Ok(Self { handles })
    }

    pub fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    pub async fn is_alive(&self) -> bool {
        let Some(handle) = self.handles.last() else {
            return false;
        };
        if handle.is_closed() {
            return false;
        }
        timeout(HEALTHCHECK_TIMEOUT, handle.send_ping())
            .await
            .is_ok_and(|result| result.is_ok())
    }

    pub async fn disconnect(&self) {
        for handle in self.handles.iter().rev() {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "ssh-gateway session closed", "en")
                .await;
        }
    }

    pub async fn run_command(&self, command: &str, input: Option<&[u8]>) -> Result<CommandOutput, ArrtError> {
        let mut channel = self.target_handle()?.channel_open_session().await?;
        channel.exec(true, command.as_bytes().to_vec()).await?;

        if let Some(input) = input {
            let mut writer = BufWriter::new(channel.make_writer());
            writer.write_all(input).await?;
            writer.flush().await?;
            drop(writer);
            channel.eof().await?;
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(&data);
                    } else {
                        stdout.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status as i32),
                ChannelMsg::Close => break,
                ChannelMsg::Eof
                | ChannelMsg::Success
                | ChannelMsg::Failure
                | ChannelMsg::WindowAdjusted { .. } => {}
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } => {
                    if stderr.is_empty() {
                        let message = if error_message.is_empty() {
                            format!("remote command terminated by signal {:?}", signal_name)
                        } else {
                            error_message
                        };
                        stderr.extend_from_slice(message.as_bytes());
                    }
                }
                _ => {}
            }
        }

        let _ = channel.close().await;

        Ok(CommandOutput {
            exit_code: exit_code.unwrap_or(0),
            stdout,
            stderr,
        })
    }

    pub async fn run_argv(
        &self,
        argv: &[String],
        input: Option<&[u8]>,
    ) -> Result<CommandOutput, ArrtError> {
        self.run_command(&shell_join(argv), input).await
    }

    pub async fn proxy_tcp_stream(
        &self,
        mut local_stream: TcpStream,
        remote_host: &str,
        remote_port: u16,
        originator: std::net::SocketAddr,
    ) -> Result<(), ArrtError> {
        let channel = self
            .target_handle()?
            .channel_open_direct_tcpip(
                remote_host.to_string(),
                remote_port.into(),
                originator.ip().to_string(),
                originator.port().into(),
            )
            .await?;
        let mut remote_stream = channel.into_stream();
        let _ = tokio::io::copy_bidirectional(&mut local_stream, &mut remote_stream).await?;
        let _ = remote_stream.shutdown().await;
        Ok(())
    }

    fn target_handle(&self) -> Result<&Arc<ClientHandle>, ArrtError> {
        self.handles
            .last()
            .ok_or_else(|| ArrtError::Ssh("session has no active handles".to_string()))
    }
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn connect_direct(
    config: Arc<client::Config>,
    endpoint: &ResolvedEndpoint,
) -> Result<ClientHandle, ArrtError> {
    let mut handle =
        client::connect(config, (endpoint.host.as_str(), endpoint.port), GatewayClient).await?;
    authenticate(&mut handle, endpoint).await?;
    Ok(handle)
}

async fn connect_via_channel(
    config: Arc<client::Config>,
    upstream: Arc<ClientHandle>,
    endpoint: &ResolvedEndpoint,
) -> Result<ClientHandle, ArrtError> {
    let channel = upstream
        .channel_open_direct_tcpip(endpoint.host.clone(), endpoint.port.into(), "127.0.0.1", 0)
        .await?;
    let mut handle = client::connect_stream(config, channel.into_stream(), GatewayClient).await?;
    authenticate(&mut handle, endpoint).await?;
    Ok(handle)
}

async fn authenticate(handle: &mut ClientHandle, endpoint: &ResolvedEndpoint) -> Result<(), ArrtError> {
    let success = match &endpoint.auth {
        ResolvedAuthConfig::Password { password } => handle
            .authenticate_password(endpoint.user.clone(), password.clone())
            .await?
            .success(),
        ResolvedAuthConfig::Key { key_path } => {
            let key_pair = load_secret_key(Path::new(key_path), None)?;
            handle
                .authenticate_publickey(
                    endpoint.user.clone(),
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?
                .success()
        }
    };

    if success {
        Ok(())
    } else {
        Err(ArrtError::Ssh(format!(
            "authentication failed for {}@{}:{}",
            endpoint.user, endpoint.host, endpoint.port
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_join_quotes_arguments() {
        let command = shell_join(&[
            "/tmp/ssh-gatewayd".to_string(),
            "exec".to_string(),
            "hello world".to_string(),
            "quote'check".to_string(),
        ]);
        assert!(command.contains("'/tmp/ssh-gatewayd'"));
        assert!(command.contains("'hello world'"));
        assert!(command.contains("'quote'\\''check'"));
    }
}
