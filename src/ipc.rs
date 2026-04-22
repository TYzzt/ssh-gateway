use crate::daemon::DaemonState;
use crate::errors::ArrtError;
use crate::protocol::{Request, RpcRequest, RpcResponse};
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};

#[cfg(unix)]
use crate::config::ensure_runtime_dirs;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(windows)]
const WINDOWS_DAEMON_ADDR: &str = "127.0.0.1:46173";

#[cfg(unix)]
pub fn endpoint_path() -> Result<PathBuf, ArrtError> {
    Ok(ensure_runtime_dirs()?.join("ssh-gateway.sock"))
}

#[cfg(windows)]
#[allow(dead_code)]
pub fn endpoint_path() -> Result<PathBuf, ArrtError> {
    Ok(PathBuf::from(WINDOWS_DAEMON_ADDR))
}

async fn write_frame<T: Serialize, W: AsyncWrite + Unpin>(writer: &mut W, value: &T) -> Result<(), ArrtError> {
    let payload =
        serde_json::to_vec(value).map_err(|err| ArrtError::Ipc(format!("serialize request: {err}")))?;
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned, R: AsyncRead + Unpin>(reader: &mut R) -> Result<T, ArrtError> {
    let mut len = [0_u8; 4];
    reader.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|err| ArrtError::Ipc(format!("decode frame: {err}")))
}

#[cfg(unix)]
pub async fn send(request: &RpcRequest) -> Result<RpcResponse, ArrtError> {
    let path = endpoint_path()?;
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|err| ArrtError::DaemonUnavailable(err.to_string()))?;
    write_frame(&mut stream, request).await?;
    read_frame(&mut stream).await
}

#[cfg(windows)]
pub async fn send(request: &RpcRequest) -> Result<RpcResponse, ArrtError> {
    let mut stream = TcpStream::connect(WINDOWS_DAEMON_ADDR)
        .await
        .map_err(|err| ArrtError::DaemonUnavailable(err.to_string()))?;
    write_frame(&mut stream, request).await?;
    read_frame(&mut stream).await
}

#[cfg(unix)]
pub async fn serve(state: Arc<DaemonState>) -> Result<(), ArrtError> {
    let path = endpoint_path()?;
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)?;
    loop {
        tokio::select! {
            _ = state.shutdown.notified() => break,
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(ArrtError::from)?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let request = read_frame::<RpcRequest, _>(&mut stream).await;
                    if let Ok(request) = request {
                        let should_shutdown = matches!(&request.request, Request::Shutdown);
                        let response = Arc::clone(&state).handle(request).await;
                        let _ = write_frame(&mut stream, &response).await;
                        if should_shutdown {
                            state.request_shutdown();
                        }
                    }
                });
            }
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(windows)]
pub async fn serve(state: Arc<DaemonState>) -> Result<(), ArrtError> {
    let listener = TcpListener::bind(WINDOWS_DAEMON_ADDR)
        .await
        .map_err(|err| ArrtError::Ipc(err.to_string()))?;
    loop {
        tokio::select! {
            _ = state.shutdown.notified() => break,
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(|err| ArrtError::Ipc(err.to_string()))?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let request = read_frame::<RpcRequest, _>(&mut stream).await;
                    if let Ok(request) = request {
                        let should_shutdown = matches!(&request.request, Request::Shutdown);
                        let response = Arc::clone(&state).handle(request).await;
                        let _ = write_frame(&mut stream, &response).await;
                        if should_shutdown {
                            state.request_shutdown();
                        }
                    }
                });
            }
        }
    }
    Ok(())
}
