use crate::config::{config_path_display, AppConfig};
use crate::daemon::DaemonState;
use crate::errors::ArrtError;
use crate::ipc;
use crate::protocol::{CommandResult, EnvVar, ErrorPayload, Request, RpcRequest, WriteMode};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use tokio::fs;

#[derive(Parser, Debug)]
#[command(name = "ssh-gateway")]
#[command(about = "Agent Remote Runtime CLI")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopLevelCommand,
}

#[derive(Subcommand, Debug)]
pub enum TopLevelCommand {
    Daemon(DaemonCommand),
    Profile(ProfileCommand),
    Exec(ExecCommand),
    Read(ReadCommand),
    Write(WriteCommand),
    Upload(UploadCommand),
    Download(DownloadCommand),
    Tunnel(TunnelCommand),
    Session(SessionCommand),
}

#[derive(Args, Debug)]
pub struct DaemonCommand {
    #[command(subcommand)]
    pub command: DaemonSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum DaemonSubcommand {
    Start,
    Stop,
    Status,
    #[command(hide = true)]
    Serve,
}

#[derive(Args, Debug)]
pub struct ProfileCommand {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ProfileSubcommand {
    List,
    Show { name: String },
    Validate { name: Option<String> },
}

#[derive(Args, Debug)]
pub struct ExecCommand {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub cwd: Option<String>,
    #[arg(long)]
    pub timeout: Option<u64>,
    #[arg(long = "env")]
    pub env: Vec<String>,
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ReadCommand {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub path: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum CliWriteMode {
    Create,
    Truncate,
    Append,
}

#[derive(Args, Debug)]
pub struct WriteCommand {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub path: String,
    #[arg(long, value_enum, default_value = "truncate")]
    pub mode: CliWriteMode,
    #[arg(long)]
    pub file: Option<String>,
    #[arg(long)]
    pub input: Option<String>,
}

#[derive(Args, Debug)]
pub struct UploadCommand {
    #[arg(long)]
    pub profile: String,
    /// Local source file. Relative paths use the CLI caller's current directory.
    #[arg(long)]
    pub src: String,
    /// Remote destination file. Parent directories are created and existing files are overwritten.
    #[arg(long)]
    pub dst: String,
}

#[derive(Args, Debug)]
pub struct DownloadCommand {
    #[arg(long)]
    pub profile: String,
    /// Remote source file.
    #[arg(long)]
    pub src: String,
    /// Local destination file. Relative paths use the CLI caller's current directory. Parent directories are created and existing files are atomically overwritten.
    #[arg(long)]
    pub dst: String,
}

#[derive(Args, Debug)]
pub struct TunnelCommand {
    #[command(subcommand)]
    pub command: TunnelSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TunnelSubcommand {
    Open {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        local: u16,
        #[arg(long)]
        remote: String,
    },
    Close {
        #[arg(long = "id")]
        tunnel_id: String,
    },
}

#[derive(Args, Debug)]
pub struct SessionCommand {
    #[command(subcommand)]
    pub command: SessionSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum SessionSubcommand {
    List,
    Inspect {
        #[arg(long = "id")]
        session_id: String,
    },
    Close {
        #[arg(long = "id")]
        session_id: String,
    },
}

pub async fn dispatch(cli: Cli) -> CommandResult {
    match dispatch_inner(cli).await {
        Ok(result) => result,
        Err(err) => error_result(err),
    }
}

async fn dispatch_inner(cli: Cli) -> Result<CommandResult, ArrtError> {
    match cli.command {
        TopLevelCommand::Daemon(daemon) => dispatch_daemon(daemon).await,
        TopLevelCommand::Profile(command) => {
            let request = match command.command {
                ProfileSubcommand::List => Request::ProfileList,
                ProfileSubcommand::Show { name } => Request::ProfileShow { name },
                ProfileSubcommand::Validate { name } => Request::ProfileValidate { name },
            };
            send_request(request, true).await
        }
        TopLevelCommand::Exec(command) => {
            let env = command
                .env
                .into_iter()
                .map(parse_env)
                .collect::<Result<Vec<_>, _>>()?;
            let profile = command.profile;
            let timeout_seconds = match command.timeout {
                Some(seconds) => Some(seconds),
                None => Some(
                    AppConfig::load()
                        .await?
                        .resolved_profile(&profile)?
                        .timeouts
                        .exec_seconds,
                ),
            };
            let request = Request::Exec {
                profile,
                command: command.command.join(" "),
                cwd: command.cwd,
                timeout_seconds,
                env,
            };
            send_request(request, true).await
        }
        TopLevelCommand::Read(command) => {
            send_request(
                Request::Read {
                    profile: command.profile,
                    path: command.path,
                },
                true,
            )
            .await
        }
        TopLevelCommand::Write(command) => {
            let content = resolve_write_content(command.file, command.input).await?;
            let mode = match command.mode {
                CliWriteMode::Create => WriteMode::Create,
                CliWriteMode::Truncate => WriteMode::Truncate,
                CliWriteMode::Append => WriteMode::Append,
            };
            send_request(
                Request::Write {
                    profile: command.profile,
                    path: command.path,
                    mode,
                    content_b64: BASE64.encode(content),
                },
                true,
            )
            .await
        }
        TopLevelCommand::Upload(command) => {
            let request = upload_request(command)?;
            send_request(request, true).await
        }
        TopLevelCommand::Download(command) => {
            let request = download_request(command)?;
            send_request(request, true).await
        }
        TopLevelCommand::Tunnel(command) => match command.command {
            TunnelSubcommand::Open {
                profile,
                local,
                remote,
            } => {
                let (remote_host, remote_port) = parse_remote_endpoint(&remote)?;
                send_request(
                    Request::TunnelOpen {
                        profile,
                        local_port: local,
                        remote_host,
                        remote_port,
                    },
                    true,
                )
                .await
            }
            TunnelSubcommand::Close { tunnel_id } => {
                send_request(Request::TunnelClose { tunnel_id }, true).await
            }
        },
        TopLevelCommand::Session(command) => match command.command {
            SessionSubcommand::List => send_request(Request::SessionList, true).await,
            SessionSubcommand::Inspect { session_id } => {
                send_request(Request::SessionInspect { session_id }, true).await
            }
            SessionSubcommand::Close { session_id } => {
                send_request(Request::SessionClose { session_id }, true).await
            }
        },
    }
}

async fn dispatch_daemon(command: DaemonCommand) -> Result<CommandResult, ArrtError> {
    match command.command {
        DaemonSubcommand::Serve => {
            let state = DaemonState::new();
            state.serve().await?;
            Ok(CommandResult::success().with_data(json!({"status":"stopped"})))
        }
        DaemonSubcommand::Start => {
            if ipc::send(&rpc(Request::Ping)).await.is_ok() {
                return Ok(CommandResult::success().with_data(json!({"status":"already_running"})));
            }
            spawn_daemon().await?;
            wait_for_daemon_ready().await?;
            Ok(CommandResult::success().with_data(json!({
                "status":"running",
                "config_path": config_path_display()?,
            })))
        }
        DaemonSubcommand::Status => {
            let response = ipc::send(&rpc(Request::Ping)).await?;
            Ok(response.result)
        }
        DaemonSubcommand::Stop => stop_daemon().await,
    }
}

async fn send_request(request: Request, auto_start: bool) -> Result<CommandResult, ArrtError> {
    let req = rpc(request);
    match ipc::send(&req).await {
        Ok(response) => Ok(response.result),
        Err(_err) if auto_start => {
            spawn_daemon().await?;
            wait_for_daemon_ready().await?;
            let response = ipc::send(&req).await?;
            Ok(response.result)
        }
        Err(err) => Err(err),
    }
}

async fn stop_daemon() -> Result<CommandResult, ArrtError> {
    let request = rpc(Request::Shutdown);
    match ipc::send(&request).await {
        Ok(response) => Ok(response.result),
        Err(ArrtError::DaemonUnavailable(_)) => {
            Ok(CommandResult::success().with_data(json!({"status":"not_running"})))
        }
        Err(err) => {
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if ipc::send(&rpc(Request::Ping)).await.is_err() {
                    return Ok(CommandResult::success().with_data(json!({"status":"stopped"})));
                }
            }
            Err(err)
        }
    }
}

fn rpc(request: Request) -> RpcRequest {
    RpcRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        request,
    }
}

fn upload_request(command: UploadCommand) -> Result<Request, ArrtError> {
    let client_cwd = std::env::current_dir()?;
    upload_request_from(command, &client_cwd)
}

fn upload_request_from(command: UploadCommand, client_cwd: &Path) -> Result<Request, ArrtError> {
    Ok(Request::Upload {
        profile: command.profile,
        src: resolve_client_local_path(command.src, client_cwd)?,
        dst: command.dst,
    })
}

fn download_request(command: DownloadCommand) -> Result<Request, ArrtError> {
    let client_cwd = std::env::current_dir()?;
    download_request_from(command, &client_cwd)
}

fn download_request_from(
    command: DownloadCommand,
    client_cwd: &Path,
) -> Result<Request, ArrtError> {
    Ok(Request::Download {
        profile: command.profile,
        src: command.src,
        dst: resolve_client_local_path(command.dst, client_cwd)?,
    })
}

fn resolve_client_local_path(path: String, client_cwd: &Path) -> Result<String, ArrtError> {
    if Path::new(&path).is_absolute() {
        return Ok(path);
    }
    normalize_absolute_path(&client_cwd.join(path))
        .into_os_string()
        .into_string()
        .map_err(|_| ArrtError::InvalidArgument("local path is not valid UTF-8".to_string()))
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn parse_env(raw: String) -> Result<EnvVar, ArrtError> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(ArrtError::InvalidArgument(format!(
            "invalid env assignment: {}",
            raw
        )));
    };
    Ok(EnvVar {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_remote_endpoint(raw: &str) -> Result<(String, u16), ArrtError> {
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(ArrtError::InvalidArgument(format!(
            "remote endpoint must look like host:port, got {}",
            raw
        )));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| ArrtError::InvalidArgument(format!("invalid port in {}", raw)))?;
    Ok((host.to_string(), port))
}

async fn resolve_write_content(
    file: Option<String>,
    input: Option<String>,
) -> Result<Vec<u8>, ArrtError> {
    match (file, input) {
        (Some(path), None) => fs::read(path).await.map_err(ArrtError::from),
        (None, Some(input)) if input == "-" => {
            let mut stdin = tokio::io::stdin();
            let mut data = Vec::new();
            use tokio::io::AsyncReadExt;
            stdin.read_to_end(&mut data).await?;
            Ok(data)
        }
        (None, Some(input)) => Ok(input.into_bytes()),
        (None, None) => Err(ArrtError::InvalidArgument(
            "write requires either --file or --input".to_string(),
        )),
        (Some(_), Some(_)) => Err(ArrtError::InvalidArgument(
            "write accepts only one of --file or --input".to_string(),
        )),
    }
}

async fn wait_for_daemon_ready() -> Result<(), ArrtError> {
    for _ in 0..20 {
        if ipc::send(&rpc(Request::Ping)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    Err(ArrtError::DaemonUnavailable(
        "daemon did not become ready".to_string(),
    ))
}

async fn spawn_daemon() -> Result<(), ArrtError> {
    let exe =
        std::env::current_exe().map_err(|err| ArrtError::DaemonUnavailable(err.to_string()))?;
    let mut command = tokio::process::Command::new(exe);
    command
        .arg("daemon")
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command
            .as_std_mut()
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    command
        .spawn()
        .map_err(|err| ArrtError::DaemonUnavailable(err.to_string()))?;
    Ok(())
}

fn error_result(err: ArrtError) -> CommandResult {
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
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn upload(src: &str, dst: &str) -> UploadCommand {
        UploadCommand {
            profile: "test".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
        }
    }

    fn download(src: &str, dst: &str) -> DownloadCommand {
        DownloadCommand {
            profile: "test".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
        }
    }

    #[test]
    fn version_flag_is_available() {
        let error = Cli::try_parse_from(["ssh-gateway", "--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));

        let short = Cli::try_parse_from(["ssh-gateway", "-V"]).unwrap_err();
        assert_eq!(short.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn transfer_help_explains_local_and_remote_paths() {
        let upload = Cli::try_parse_from(["ssh-gateway", "upload", "--help"])
            .unwrap_err()
            .to_string();
        assert!(upload.contains("Local source file"));
        assert!(upload.contains("Remote destination file"));
        assert!(upload.contains("overwritten"));

        let download = Cli::try_parse_from(["ssh-gateway", "download", "--help"])
            .unwrap_err()
            .to_string();
        assert!(download.contains("Remote source file"));
        assert!(download.contains("Local destination file"));
        assert!(download.contains("atomically overwritten"));
    }

    #[test]
    fn transfer_requests_resolve_local_paths_against_client_cwd() {
        #[cfg(windows)]
        let (client_cwd, daemon_cwd) = (
            PathBuf::from(r"C:\Users\caller\work"),
            PathBuf::from(r"D:\daemon\work"),
        );
        #[cfg(not(windows))]
        let (client_cwd, daemon_cwd) = (
            PathBuf::from("/home/caller/work"),
            PathBuf::from("/srv/daemon/work"),
        );

        let upload =
            upload_request_from(upload("input/local.txt", "/tmp/local.txt"), &client_cwd).unwrap();
        let download =
            download_request_from(download("/tmp/remote.txt", "output/local.txt"), &client_cwd)
                .unwrap();

        match upload {
            Request::Upload { src, .. } => {
                let src = PathBuf::from(src);
                assert_eq!(src, client_cwd.join("input/local.txt"));
                assert!(src.is_absolute());
                assert!(!src.starts_with(&daemon_cwd));
            }
            _ => panic!("expected upload request"),
        }
        match download {
            Request::Download { dst, .. } => {
                let dst = PathBuf::from(dst);
                assert_eq!(dst, client_cwd.join("output/local.txt"));
                assert!(dst.is_absolute());
                assert!(!dst.starts_with(&daemon_cwd));
            }
            _ => panic!("expected download request"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn local_path_resolution_preserves_windows_absolute_paths() {
        let client_cwd = Path::new(r"C:\Users\caller\work");

        assert_eq!(
            resolve_client_local_path(r"D:\archive\file.txt".to_string(), client_cwd).unwrap(),
            r"D:\archive\file.txt"
        );
        assert_eq!(
            resolve_client_local_path(r"\\server\share\file.txt".to_string(), client_cwd).unwrap(),
            r"\\server\share\file.txt"
        );
        assert_eq!(
            resolve_client_local_path(r"paper\file.txt".to_string(), client_cwd).unwrap(),
            r"C:\Users\caller\work\paper\file.txt"
        );
        assert_eq!(
            resolve_client_local_path(r".\paper drafts\old\..\file.txt".to_string(), client_cwd,)
                .unwrap(),
            r"C:\Users\caller\work\paper drafts\file.txt"
        );
    }
}
