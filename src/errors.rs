use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArrtError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("daemon unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("ssh error: {0}")]
    Ssh(String),
    #[error("agent error: {0}")]
    Agent(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("io error: {0}")]
    Io(String),
}

impl ArrtError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::ProfileNotFound(_) => "profile_not_found",
            Self::DaemonUnavailable(_) => "daemon_unavailable",
            Self::Ipc(_) => "ipc_error",
            Self::Ssh(_) => "ssh_error",
            Self::Agent(_) => "agent_error",
            Self::SessionNotFound(_) => "session_not_found",
            Self::InvalidArgument(_) => "invalid_argument",
            Self::Io(_) => "io_error",
        }
    }
}

impl From<std::io::Error> for ArrtError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<russh::Error> for ArrtError {
    fn from(value: russh::Error) -> Self {
        Self::Ssh(value.to_string())
    }
}

impl From<russh::keys::Error> for ArrtError {
    fn from(value: russh::keys::Error) -> Self {
        Self::Ssh(value.to_string())
    }
}
