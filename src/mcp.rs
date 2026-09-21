use crate::config::{AppConfig, Profile};
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
    task_id: Option<Arc<str>>,
    profile_management_enabled: bool,
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
    let task_id = config
        .mcp
        .task_id_env
        .as_deref()
        .map(|name| {
            std::env::var(name)
                .map_err(|_| ArrtError::Config(format!("MCP task_id_env {name} is not set")))
                .and_then(|value| {
                    if value.trim().is_empty() {
                        Err(ArrtError::Config(format!(
                            "MCP task_id_env {name} must not be empty"
                        )))
                    } else {
                        Ok(Arc::<str>::from(value))
                    }
                })
        })
        .transpose()?;
    let state = McpState {
        service,
        token: token.into(),
        allowed_origins: Arc::new(config.mcp.allowed_origins),
        local_file_root,
        task_id,
        profile_management_enabled: config.mcp.profile_management.enabled,
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
            "tools": tool_definitions(state.profile_management_enabled),
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
        state.task_id.as_deref(),
        &request_id,
        &call.name,
        call.arguments,
        state.profile_management_enabled,
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
    task_id: Option<&str>,
    request_id: &str,
    name: &str,
    args: Value,
    profile_management_enabled: bool,
) -> Result<Value, String> {
    if name == "list_hosts" {
        return service
            .list_hosts(request_id, CallerType::Mcp)
            .await
            .map(|hosts| json!({"hosts": hosts}))
            .map_err(|err| err.to_string());
    }
    if args.get("task_id").is_some() {
        return Err(
            "task_id is injected by the gateway and is not accepted as a tool argument".to_string(),
        );
    }
    if matches!(name, "create_profile" | "delete_profile") && !profile_management_enabled {
        return Err("profile management is disabled".to_string());
    }
    guard_local_transfer(name, &args, local_file_root)?;
    let request = request_from_tool(name, &args, task_id)?;
    let result = service
        .execute(
            request_id,
            CallerType::Mcp,
            task_id.map(str::to_string),
            request,
        )
        .await;
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
        return Err(result.error.map_or_else(
            || "operation failed".to_string(),
            |error| format!("{}: {}", error.code, error.message),
        ));
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

fn request_from_tool(name: &str, args: &Value, task_id: Option<&str>) -> Result<Request, String> {
    if args.get("task_id").is_some() {
        return Err(
            "task_id is injected by the gateway and is not accepted as a tool argument".to_string(),
        );
    }
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
        "get_profile_policy" => {
            reject_keys(args, "arguments", &["profile"])?;
            Ok(Request::ProfilePolicy {
                profile: match args.get("profile") {
                    Some(value) => Some(
                        value
                            .as_str()
                            .ok_or_else(|| "profile must be a string".to_string())?
                            .to_string(),
                    ),
                    None => None,
                },
            })
        }
        "create_profile" => {
            reject_keys(args, "arguments", &["profile"])?;
            let value = args
                .get("profile")
                .ok_or_else(|| "missing object argument: profile".to_string())?;
            if value.get("agent_policy").is_none() {
                return Err("profile.agent_policy is required".to_string());
            }
            Ok(Request::ProfileCreate {
                profile: Box::new(parse_profile(value)?),
            })
        }
        "delete_profile" => {
            reject_keys(args, "arguments", &["profile"])?;
            Ok(Request::ProfileDelete {
                profile: string("profile")?,
                expected_profile_hash: String::new(),
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
        "propose_plan" => {
            let actions = args
                .get("actions")
                .and_then(Value::as_array)
                .ok_or_else(|| "missing actions array".to_string())?
                .iter()
                .cloned()
                .map(|value| {
                    serde_json::from_value::<Request>(value)
                        .map_err(|e| format!("invalid plan action: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Request::PlanPropose {
                profile: string("profile")?,
                task_id: task_id
                    .ok_or_else(|| "propose_plan requires gateway-injected task_id".to_string())?
                    .to_string(),
                actions,
            })
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn parse_profile(value: &Value) -> Result<Profile, String> {
    reject_unknown_profile_fields(value)?;
    serde_json::from_value(value.clone()).map_err(|err| format!("invalid profile: {err}"))
}

fn reject_unknown_profile_fields(value: &Value) -> Result<(), String> {
    reject_keys(
        value,
        "profile",
        &[
            "name",
            "description",
            "via_profile",
            "target",
            "bastions",
            "auth",
            "remote",
            "agent",
            "bootstrap",
            "timeouts",
            "keepalive",
            "agent_policy",
        ],
    )?;
    validate_endpoint(value.get("target"), "profile.target")?;
    if let Some(items) = value.get("bastions").and_then(Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            validate_endpoint(Some(item), &format!("profile.bastions[{index}]"))?;
        }
    }
    validate_auth(value.get("auth"), "profile.auth")?;
    reject_optional_keys(value.get("remote"), "profile.remote", &["shell"])?;
    reject_optional_keys(
        value.get("agent"),
        "profile.agent",
        &["manage", "remote_path", "version"],
    )?;
    reject_optional_keys(
        value.get("bootstrap"),
        "profile.bootstrap",
        &["enabled", "remote_temp_dir"],
    )?;
    reject_optional_keys(
        value.get("timeouts"),
        "profile.timeouts",
        &["exec_seconds", "idle_session_seconds"],
    )?;
    reject_optional_keys(
        value.get("keepalive"),
        "profile.keepalive",
        &["interval_seconds", "count_max"],
    )?;
    if let Some(policy) = value.get("agent_policy") {
        reject_keys(
            policy,
            "profile.agent_policy",
            &[
                "capabilities",
                "allowed_read_paths",
                "allowed_write_paths",
                "allowed_commands",
                "deny_commands",
                "audit_command",
                "rules",
            ],
        )?;
        reject_optional_keys(
            policy.get("capabilities"),
            "profile.agent_policy.capabilities",
            &["exec", "read", "write", "upload", "download", "tunnel"],
        )?;
        if let Some(rules) = policy.get("rules").and_then(Value::as_array) {
            for (index, rule) in rules.iter().enumerate() {
                let path = format!("profile.agent_policy.rules[{index}]");
                reject_keys(rule, &path, &["id", "match", "effect", "risk", "reason"])?;
                reject_optional_keys(
                    rule.get("match"),
                    &format!("{path}.match"),
                    &["operation", "commands", "paths"],
                )?;
            }
        }
    }
    Ok(())
}

fn validate_endpoint(value: Option<&Value>, path: &str) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    reject_keys(value, path, &["host", "user", "port", "auth"])?;
    validate_auth(value.get("auth"), &format!("{path}.auth"))
}

fn validate_auth(value: Option<&Value>, path: &str) -> Result<(), String> {
    reject_optional_keys(value, path, &["type", "key_path", "passphrase", "password"])
}

fn reject_optional_keys(value: Option<&Value>, path: &str, allowed: &[&str]) -> Result<(), String> {
    match value {
        Some(value) => reject_keys(value, path, allowed),
        None => Ok(()),
    }
}

fn reject_keys(value: &Value, path: &str, allowed: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let unknown = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!("unknown fields in {path}: {}", unknown.join(", ")))
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

fn tool_definitions(profile_management_enabled: bool) -> Vec<Value> {
    let profile =
        json!({"type":"string", "description":"Configured profile name", "x-mcp-header":"Profile"});
    let mut tools = vec![
        tool(
            "list_hosts",
            "List configured hosts without credentials",
            json!({"type":"object", "additionalProperties":false}),
        ),
        read_only_tool(
            "get_profile_policy",
            "Get the complete Agent Policy for one or all configured profiles",
            json!({"type":"object","properties":{"profile":profile},"additionalProperties":false}),
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
        tool(
            "propose_plan",
            "Store an ordered, non-executing plan for later human approval",
            json!({"type":"object","properties":{"profile":profile,"actions":{"type":"array","items":{"type":"object","description":"Canonical Request object with a kind field"},"minItems":1}},"required":["profile","actions"],"additionalProperties":false}),
        ),
    ];
    if profile_management_enabled {
        tools.push(mutating_tool(
            "create_profile",
            "Create a profile and Agent Policy after user confirmation",
            json!({"type":"object","properties":{"profile":profile_schema()},"required":["profile"],"additionalProperties":false}),
            false,
        ));
        tools.push(mutating_tool(
            "delete_profile",
            "Delete a profile after user confirmation",
            json!({"type":"object","properties":{"profile":profile},"required":["profile"],"additionalProperties":false}),
            true,
        ));
    }
    tools
}

fn profile_schema() -> Value {
    let auth = json!({"type":"object","properties":{"type":{"type":"string","enum":["key","password"]},"key_path":{"type":"string"},"passphrase":{"type":"string"},"password":{"type":"string"}},"additionalProperties":false});
    let endpoint = json!({"type":"object","properties":{"host":{"type":"string"},"user":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"auth":auth},"required":["host","user"],"additionalProperties":false});
    let capabilities = json!({"type":"object","properties":{"exec":{"type":"boolean"},"read":{"type":"boolean"},"write":{"type":"boolean"},"upload":{"type":"boolean"},"download":{"type":"boolean"},"tunnel":{"type":"boolean"}},"additionalProperties":false});
    let rule = json!({"type":"object","properties":{"id":{"type":"string"},"match":{"type":"object","properties":{"operation":{"type":"string","enum":["exec","read","write","upload","download"]},"commands":{"type":"array","items":{"type":"string"}},"paths":{"type":"array","items":{"type":"string"}}},"required":["operation"],"additionalProperties":false},"effect":{"type":"string","enum":["allow","confirm","deny"]},"risk":{"type":"string","enum":["low","medium","high","critical"]},"reason":{"type":"string"}},"required":["id","match","effect"],"additionalProperties":false});
    json!({
        "type":"object",
        "properties":{
            "name":{"type":"string"},"description":{"type":"string"},"via_profile":{"type":"string"},
            "target":endpoint,"bastions":{"type":"array","items":endpoint},"auth":auth,
            "remote":{"type":"object","properties":{"shell":{"type":"string"}},"additionalProperties":false},
            "agent":{"type":"object","properties":{"manage":{"type":"boolean"},"remote_path":{"type":"string"},"version":{"type":"string"}},"additionalProperties":false},
            "bootstrap":{"type":"object","properties":{"enabled":{"type":"boolean"},"remote_temp_dir":{"type":"string"}},"additionalProperties":false},
            "timeouts":{"type":"object","properties":{"exec_seconds":{"type":"integer","minimum":0},"idle_session_seconds":{"type":"integer","minimum":0}},"additionalProperties":false},
            "keepalive":{"type":"object","properties":{"interval_seconds":{"type":"integer","minimum":0},"count_max":{"type":"integer","minimum":0}},"additionalProperties":false},
            "agent_policy":{"type":"object","properties":{"capabilities":capabilities,"allowed_read_paths":{"type":"array","items":{"type":"string"}},"allowed_write_paths":{"type":"array","items":{"type":"string"}},"allowed_commands":{"type":"array","items":{"type":"string"}},"deny_commands":{"type":"array","items":{"type":"string"}},"audit_command":{"type":"boolean"},"rules":{"type":"array","items":rule}},"additionalProperties":false}
        },
        "required":["name","target","agent_policy"],"additionalProperties":false
    })
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({"name":name, "description":description, "inputSchema":input_schema})
}

fn read_only_tool(name: &str, description: &str, input_schema: Value) -> Value {
    let mut definition = tool(name, description, input_schema);
    definition["annotations"] = json!({
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false
    });
    definition
}

fn mutating_tool(name: &str, description: &str, input_schema: Value, destructive: bool) -> Value {
    let mut definition = tool(name, description, input_schema);
    definition["annotations"] = json!({
        "readOnlyHint": false,
        "destructiveHint": destructive,
        "idempotentHint": false,
        "openWorldHint": false
    });
    definition
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
        let names = tool_definitions(true)
            .into_iter()
            .filter_map(|value| value["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(!names
            .iter()
            .any(|name| name.contains("approve") || name.contains("reject")));
        assert!(!names.iter().any(|name| name.starts_with("grant_")));
        assert!(names.iter().any(|name| name == "propose_plan"));
    }

    #[test]
    fn profile_management_tools_follow_enablement() {
        let disabled = tool_definitions(false);
        assert!(disabled
            .iter()
            .any(|tool| tool["name"] == "get_profile_policy"));
        assert!(!disabled.iter().any(|tool| tool["name"] == "create_profile"));
        assert!(!disabled.iter().any(|tool| tool["name"] == "delete_profile"));
        let enabled = tool_definitions(true);
        assert!(enabled.iter().any(|tool| tool["name"] == "create_profile"));
        assert!(enabled.iter().any(|tool| tool["name"] == "delete_profile"));
        let create = enabled
            .iter()
            .find(|tool| tool["name"] == "create_profile")
            .unwrap();
        let delete = enabled
            .iter()
            .find(|tool| tool["name"] == "delete_profile")
            .unwrap();
        assert_eq!(create["annotations"]["readOnlyHint"], false);
        assert_eq!(create["annotations"]["destructiveHint"], false);
        assert_eq!(delete["annotations"]["readOnlyHint"], false);
        assert_eq!(delete["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn profile_policy_tool_is_declared_read_only() {
        let tools = tool_definitions(false);
        let definition = tools
            .iter()
            .find(|tool| tool["name"] == "get_profile_policy")
            .unwrap();
        assert_eq!(definition["annotations"]["readOnlyHint"], true);
        assert_eq!(definition["annotations"]["destructiveHint"], false);
        assert_eq!(definition["annotations"]["idempotentHint"], true);
        assert_eq!(definition["annotations"]["openWorldHint"], false);
    }

    #[test]
    fn create_profile_requires_policy_and_rejects_unknown_fields() {
        let base = json!({
            "name":"nas",
            "target":{"host":"nas.local","user":"ops"},
            "agent_policy":{"capabilities":{"exec":true},"rules":[]}
        });
        assert!(matches!(
            request_from_tool("create_profile", &json!({"profile":base}), None),
            Ok(Request::ProfileCreate { .. })
        ));
        assert!(request_from_tool(
            "create_profile",
            &json!({"profile":{
                "name":"nas","target":{"host":"nas.local","user":"ops"}
            }}),
            None
        )
        .is_err());
        assert!(request_from_tool(
            "create_profile",
            &json!({"profile":{
                "name":"nas","target":{"host":"nas.local","user":"ops","typo":true},
                "agent_policy":{}
            }}),
            None
        )
        .unwrap_err()
        .contains("unknown fields"));
    }

    #[test]
    fn mcp_tools_do_not_accept_agent_supplied_task_id() {
        let tools = tool_definitions(true);
        for tool in &tools {
            let properties = &tool["inputSchema"]["properties"];
            assert!(properties.get("task_id").is_none());
        }
        assert!(request_from_tool(
            "exec",
            &json!({"profile":"test","command":"whoami","task_id":"agent-picked"}),
            None,
        )
        .is_err());
        assert!(request_from_tool(
            "propose_plan",
            &json!({"profile":"test","actions":[{"kind":"exec","profile":"test","command":"whoami","cwd":null,"timeout_seconds":1,"env":[]}]}),
            None,
        )
        .is_err());
        let plan = request_from_tool(
            "propose_plan",
            &json!({"profile":"test","actions":[{"kind":"exec","profile":"test","command":"whoami","cwd":null,"timeout_seconds":1,"env":[]}]}),
            Some("gateway-task"),
        )
        .unwrap();
        match plan {
            Request::PlanPropose { task_id, .. } => assert_eq!(task_id, "gateway-task"),
            _ => panic!("expected plan proposal"),
        }
    }

    #[tokio::test]
    async fn mcp_http_rejects_missing_bearer_token() {
        let state = McpState {
            service: GatewayService::new(),
            token: "secret".into(),
            allowed_origins: Arc::new(Vec::new()),
            local_file_root: None,
            task_id: None,
            profile_management_enabled: false,
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
