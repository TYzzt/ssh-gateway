use crate::config::AppConfig;
use crate::errors::ArrtError;
use crate::protocol::{CallerType, Request, WriteMode};
use crate::service::GatewayService;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MCP_PROTOCOL_CURRENT: &str = "2026-07-28";
const MCP_PROTOCOL_COMPAT: &str = "2025-11-25";
const MAX_READ_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct McpState {
    service: Arc<GatewayService>,
    token: Arc<str>,
    allowed_origins: Arc<Vec<String>>,
    local_file_root: Option<Arc<PathBuf>>,
}

#[derive(Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

pub async fn serve(listen_override: Option<String>) -> Result<(), ArrtError> {
    serve_with_service(GatewayService::new(), listen_override).await
}

pub async fn serve_with_service(
    service: Arc<GatewayService>,
    listen_override: Option<String>,
) -> Result<(), ArrtError> {
    service.start_maintenance();
    let config = AppConfig::load().await?;
    if !config.mcp.auth.kind.eq_ignore_ascii_case("bearer") {
        return Err(ArrtError::Config(format!(
            "unsupported mcp.auth.type: {}",
            config.mcp.auth.kind
        )));
    }
    let token = std::env::var(&config.mcp.auth.token_env).map_err(|_| {
        ArrtError::Config(format!(
            "MCP bearer token environment variable {} is not set",
            config.mcp.auth.token_env
        ))
    })?;
    if token.is_empty() {
        return Err(ArrtError::Config(
            "MCP bearer token must not be empty".to_string(),
        ));
    }
    let listen = listen_override.unwrap_or(config.mcp.listen.clone());
    let address: SocketAddr = listen
        .parse()
        .map_err(|err| ArrtError::Config(format!("invalid MCP listen address {listen}: {err}")))?;
    let local_file_root = config
        .mcp
        .local_file_root
        .as_deref()
        .map(|root| {
            let root = PathBuf::from(root);
            if !root.is_absolute() {
                return Err(ArrtError::Config(
                    "mcp.local_file_root must be absolute".to_string(),
                ));
            }
            std::fs::canonicalize(&root).map(Arc::new).map_err(|err| {
                ArrtError::Config(format!(
                    "cannot resolve mcp.local_file_root {}: {err}",
                    root.display()
                ))
            })
        })
        .transpose()?;
    let state = McpState {
        service,
        token: token.into(),
        allowed_origins: Arc::new(config.mcp.allowed_origins),
        local_file_root,
    };
    let app = app(state.clone());
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("ssh-gateway MCP listening on http://{address}/mcp");
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|err| ArrtError::Io(err.to_string()));
    state.service.shutdown().await;
    result
}

fn app(state: McpState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/mcp", post(mcp_post).get(mcp_get))
        .with_state(state)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn health() -> Json<Value> {
    Json(json!({"status":"ok", "version": env!("CARGO_PKG_VERSION")}))
}

async fn mcp_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "SSE subscriptions are not enabled",
    )
        .into_response()
}

async fn mcp_post(
    State(state): State<McpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if !authorized(&headers, &state.token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }
    if !origin_allowed(&headers, &state.allowed_origins) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"origin_not_allowed"})),
        )
            .into_response();
    }

    let id = payload.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = payload.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "Invalid Request");
    };
    if !routing_headers_match(&headers, method, &payload) {
        return rpc_error(id, -32600, "MCP routing headers do not match request body");
    }
    if id.is_null() {
        return StatusCode::ACCEPTED.into_response();
    }

    let result = match method {
        "initialize" => initialize_result(&payload),
        "ping" => json!({}),
        "tools/list" => json!({
            "resultType": "complete",
            "tools": tool_definitions(),
            "ttlMs": 300000,
            "cacheScope": "private"
        }),
        "tools/call" => {
            let call = match serde_json::from_value::<ToolCall>(
                payload.get("params").cloned().unwrap_or_default(),
            ) {
                Ok(call) => call,
                Err(err) => return rpc_error(id, -32602, &format!("Invalid tool call: {err}")),
            };
            return tool_response(id, call, state).await;
        }
        _ => return rpc_error(id, -32601, "Method not found"),
    };
    rpc_result(id, result)
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let size = left.len().max(right.len());
    for index in 0..size {
        difference |= left.get(index).copied().unwrap_or(0) as usize
            ^ right.get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}

fn origin_allowed(headers: &HeaderMap, configured: &[String]) -> bool {
    let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) else {
        return true;
    };
    configured.iter().any(|allowed| allowed == origin)
        || origin.starts_with("http://127.0.0.1:")
        || origin.starts_with("http://localhost:")
        || origin == "http://localhost"
}

fn routing_headers_match(headers: &HeaderMap, method: &str, payload: &Value) -> bool {
    let current_protocol = payload
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str)
        == Some(MCP_PROTOCOL_CURRENT);
    if current_protocol && !headers.contains_key("mcp-method") {
        return false;
    }
    if let Some(header_method) = headers
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
    {
        if header_method != method {
            return false;
        }
    }
    if method == "tools/call" {
        if current_protocol && !headers.contains_key("mcp-name") {
            return false;
        }
        if let Some(header_name) = headers
            .get("mcp-name")
            .and_then(|value| value.to_str().ok())
        {
            if payload.pointer("/params/name").and_then(Value::as_str) != Some(header_name) {
                return false;
            }
        }
        let profile = payload
            .pointer("/params/arguments/profile")
            .and_then(Value::as_str);
        if current_protocol && profile.is_some() && !headers.contains_key("mcp-param-profile") {
            return false;
        }
        if let Some(header_profile) = headers
            .get("mcp-param-profile")
            .and_then(|value| value.to_str().ok())
        {
            if payload
                .pointer("/params/arguments/profile")
                .and_then(Value::as_str)
                != Some(header_profile)
            {
                return false;
            }
        }
    }
    true
}

fn initialize_result(payload: &Value) -> Value {
    let requested = payload
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str);
    let version = if requested == Some(MCP_PROTOCOL_CURRENT) {
        MCP_PROTOCOL_CURRENT
    } else {
        MCP_PROTOCOL_COMPAT
    };
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name":"ssh-gateway", "version":env!("CARGO_PKG_VERSION")},
        "instructions":"Use named profiles. All operations are restricted by each profile's agent_policy."
    })
}

async fn tool_response(id: Value, call: ToolCall, state: McpState) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let outcome = call_tool(
        &state.service,
        state.local_file_root.as_deref().map(PathBuf::as_path),
        &request_id,
        &call.name,
        call.arguments,
    )
    .await;
    match outcome {
        Ok(value) => rpc_result(id, tool_result(value, false)),
        Err(message) => rpc_result(id, tool_result(json!({"error": message}), true)),
    }
}

async fn call_tool(
    service: &GatewayService,
    local_file_root: Option<&Path>,
    request_id: &str,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    if name == "list_hosts" {
        return service
            .list_hosts(request_id, CallerType::Mcp)
            .await
            .map(|hosts| json!({"hosts": hosts}))
            .map_err(|err| err.to_string());
    }
    guard_local_transfer(name, &args, local_file_root)?;
    let request = request_from_tool(name, &args)?;
    let result = service.execute(request_id, CallerType::Mcp, request).await;
    if result
        .data
        .as_ref()
        .and_then(|v| v.get("status"))
        .and_then(Value::as_str)
        == Some("confirmation_required")
    {
        return Ok(result.data.unwrap_or_default());
    }
    if !result.ok {
        return Err(result
            .error
            .map_or_else(|| "operation failed".to_string(), |error| error.message));
    }
    if name == "read_file" {
        return paginate_read(result.data.unwrap_or_default(), &args);
    }
    if name == "exec" {
        return Ok(json!({
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "session_id": result.session_id,
        }));
    }
    Ok(result.data.unwrap_or_else(|| json!({"ok": true})))
}

fn guard_local_transfer(name: &str, args: &Value, root: Option<&Path>) -> Result<(), String> {
    let (key, existing) = match name {
        "upload_file" => ("src", true),
        "download_file" => ("dst", false),
        _ => return Ok(()),
    };
    let root = root.ok_or_else(|| {
        format!("{name} requires mcp.local_file_root to be configured on the gateway")
    })?;
    let raw = args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string argument: {key}"))?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!("{key} must be an absolute path"));
    }
    let checked = if existing {
        std::fs::canonicalize(&path).map_err(|err| format!("cannot resolve {key}: {err}"))?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| format!("{key} has no parent directory"))?;
        let parent = std::fs::canonicalize(parent)
            .map_err(|err| format!("destination parent must already exist: {err}"))?;
        parent.join(
            path.file_name()
                .ok_or_else(|| format!("{key} has no file name"))?,
        )
    };
    if checked.starts_with(root) {
        Ok(())
    } else {
        Err(format!("{key} is outside mcp.local_file_root"))
    }
}

fn request_from_tool(name: &str, args: &Value) -> Result<Request, String> {
    let string = |key: &str| {
        args.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("missing string argument: {key}"))
    };
    match name {
        "exec" => {
            let timeout_seconds = args
                .get("timeout_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(30);
            if timeout_seconds > 3600 {
                return Err("timeout_seconds must be at most 3600".to_string());
            }
            Ok(Request::Exec {
                profile: string("profile")?,
                command: string("command")?,
                cwd: args.get("cwd").and_then(Value::as_str).map(str::to_string),
                timeout_seconds: Some(timeout_seconds),
                env: Vec::new(),
            })
        }
        "read_file" => Ok(Request::Read {
            profile: string("profile")?,
            path: string("path")?,
        }),
        "write_file" => Ok(Request::Write {
            profile: string("profile")?,
            path: string("path")?,
            mode: match args
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("overwrite")
            {
                "overwrite" => WriteMode::Truncate,
                "append" => WriteMode::Append,
                mode => return Err(format!("unsupported write mode: {mode}")),
            },
            content_b64: BASE64.encode(string("content")?.as_bytes()),
        }),
        "upload_file" => Ok(Request::Upload {
            profile: string("profile")?,
            src: string("src")?,
            dst: string("dst")?,
        }),
        "download_file" => Ok(Request::Download {
            profile: string("profile")?,
            src: string("src")?,
            dst: string("dst")?,
        }),
        "list_sessions" => Ok(Request::SessionList),
        "close_session" => Ok(Request::SessionClose {
            session_id: string("session_id")?,
        }),
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn paginate_read(data: Value, args: &Value) -> Result<Value, String> {
    let encoded = data
        .get("content_b64")
        .and_then(Value::as_str)
        .ok_or("read response has no content")?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|err| format!("invalid remote content: {err}"))?;
    let offset = usize::try_from(args.get("offset").and_then(Value::as_u64).unwrap_or(0))
        .map_err(|_| "offset is too large".to_string())?;
    let limit =
        (args.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize).min(MAX_READ_BYTES);
    let start = offset.min(bytes.len());
    let end = start.saturating_add(limit).min(bytes.len());
    Ok(json!({
        "content": String::from_utf8_lossy(&bytes[start..end]),
        "offset": start,
        "next_offset": end,
        "size_bytes": bytes.len(),
        "eof": end == bytes.len(),
    }))
}

fn tool_result(value: Value, is_error: bool) -> Value {
    json!({
        "resultType": "complete",
        "content": [{"type":"text", "text": serde_json::to_string(&value).unwrap_or_default()}],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn rpc_result(id: Value, result: Value) -> Response {
    (
        StatusCode::OK,
        Json(json!({"jsonrpc":"2.0", "id":id, "result":result})),
    )
        .into_response()
}

fn rpc_error(id: Value, code: i32, message: &str) -> Response {
    (
        StatusCode::OK,
        Json(json!({"jsonrpc":"2.0", "id":id, "error":{"code":code, "message":message}})),
    )
        .into_response()
}

fn tool_definitions() -> Vec<Value> {
    let profile =
        json!({"type":"string", "description":"Configured profile name", "x-mcp-header":"Profile"});
    vec![
        tool(
            "list_hosts",
            "List configured hosts without credentials",
            json!({"type":"object", "additionalProperties":false}),
        ),
        tool(
            "exec",
            "Execute a command using a reusable SSH session",
            json!({"type":"object","properties":{"profile":profile,"command":{"type":"string"},"cwd":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":0,"maximum":3600}},"required":["profile","command"],"additionalProperties":false}),
        ),
        tool(
            "read_file",
            "Read a bounded page of a remote file",
            json!({"type":"object","properties":{"profile":profile,"path":{"type":"string"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":262144}},"required":["profile","path"],"additionalProperties":false}),
        ),
        tool(
            "write_file",
            "Overwrite or append UTF-8 content to a remote file",
            json!({"type":"object","properties":{"profile":profile,"path":{"type":"string"},"content":{"type":"string"},"mode":{"type":"string","enum":["overwrite","append"]}},"required":["profile","path","content"],"additionalProperties":false}),
        ),
        tool(
            "upload_file",
            "Upload a file local to the gateway host",
            json!({"type":"object","properties":{"profile":profile,"src":{"type":"string"},"dst":{"type":"string"}},"required":["profile","src","dst"],"additionalProperties":false}),
        ),
        tool(
            "download_file",
            "Download a remote file onto the gateway host",
            json!({"type":"object","properties":{"profile":profile,"src":{"type":"string"},"dst":{"type":"string"}},"required":["profile","src","dst"],"additionalProperties":false}),
        ),
        tool(
            "list_sessions",
            "List reusable gateway SSH sessions",
            json!({"type":"object","additionalProperties":false}),
        ),
        tool(
            "close_session",
            "Close a reusable SSH session",
            json!({"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"],"additionalProperties":false}),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({"name":name, "description":description, "inputSchema":input_schema})
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    #[test]
    fn bearer_auth_is_exact_and_constant_time() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer correct".parse().unwrap());
        assert!(authorized(&headers, "correct"));
        assert!(!authorized(&headers, "wrong"));
    }

    #[test]
    fn read_pagination_is_bounded() {
        let data = json!({"content_b64": BASE64.encode(b"abcdef")});
        let page = paginate_read(data, &json!({"offset":2,"limit":2})).unwrap();
        assert_eq!(page["content"], "cd");
        assert_eq!(page["next_offset"], 4);
        assert_eq!(page["eof"], false);
    }

    #[test]
    fn current_protocol_requires_routing_headers() {
        let payload = json!({
            "method":"tools/call",
            "params": {
                "name":"exec",
                "arguments":{"profile":"test"},
                "_meta":{"io.modelcontextprotocol/protocolVersion":MCP_PROTOCOL_CURRENT}
            }
        });
        let mut headers = HeaderMap::new();
        assert!(!routing_headers_match(&headers, "tools/call", &payload));
        headers.insert("mcp-method", "tools/call".parse().unwrap());
        headers.insert("mcp-name", "exec".parse().unwrap());
        headers.insert("mcp-param-profile", "test".parse().unwrap());
        assert!(routing_headers_match(&headers, "tools/call", &payload));
    }

    #[test]
    fn approval_mutation_tools_are_not_exposed() {
        let names = tool_definitions()
            .into_iter()
            .filter_map(|value| value["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(!names
            .iter()
            .any(|name| name.contains("approve") || name.contains("reject")));
    }

    #[tokio::test]
    async fn mcp_http_rejects_missing_bearer_token() {
        let state = McpState {
            service: GatewayService::new(),
            token: "secret".into(),
            allowed_origins: Arc::new(Vec::new()),
            local_file_root: None,
        };
        let response = app(state)
            .oneshot(
                HttpRequest::post("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
