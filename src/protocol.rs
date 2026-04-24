use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl CommandResult {
    pub fn success() -> Self {
        Self {
            ok: true,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: None,
            session_id: None,
            error: None,
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            json!({
                "ok": false,
                "stdout": "",
                "stderr": "",
                "error": {
                    "code": "serialization_error",
                    "message": "failed to serialize result",
                }
            })
            .to_string()
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WriteMode {
    Create,
    Truncate,
    Append,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Shutdown,
    ProfileList,
    ProfileShow {
        name: String,
    },
    ProfileValidate {
        name: Option<String>,
    },
    Exec {
        profile: String,
        command: String,
        cwd: Option<String>,
        timeout_seconds: Option<u64>,
        env: Vec<EnvVar>,
    },
    Read {
        profile: String,
        path: String,
    },
    Write {
        profile: String,
        path: String,
        mode: WriteMode,
        content_b64: String,
    },
    Upload {
        profile: String,
        src: String,
        dst: String,
    },
    Download {
        profile: String,
        src: String,
        dst: String,
    },
    TunnelOpen {
        profile: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    },
    TunnelClose {
        tunnel_id: String,
    },
    SessionList,
    SessionInspect {
        session_id: String,
    },
    SessionClose {
        session_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RpcRequest {
    pub request_id: String,
    pub request: Request,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RpcResponse {
    pub request_id: String,
    pub result: CommandResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_serializes() {
        let json = CommandResult::success()
            .with_data(json!({"hello":"world"}))
            .to_json();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"hello\":\"world\""));
    }
}
