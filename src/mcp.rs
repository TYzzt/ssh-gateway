use crate::config::{AppConfig, McpTenantConfig, Profile};
use crate::errors::ArrtError;
use crate::principal::Principal;
use crate::protocol::{CallerType, Request, WriteMode};
use crate::service::GatewayService;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Map;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const MCP_PROTOCOL_CURRENT: &str = "2026-07-28";
const MCP_PROTOCOL_COMPAT: &str = "2025-11-25";
const MAX_READ_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct McpState {
    service: Arc<GatewayService>,
    auth: Arc<McpAuthState>,
    allowed_origins: Arc<Vec<String>>,
    local_file_root: Option<Arc<PathBuf>>,
    task_id: Option<Arc<str>>,
    profile_management_enabled: bool,
}

enum McpAuthState {
    Bearer { token: Arc<str> },
    OAuth(OAuthState),
}

struct OAuthState {
    resource: Arc<str>,
    issuer: Arc<str>,
    jwks_url: Arc<str>,
    required_scopes: Arc<Vec<String>>,
    audience_claim: Arc<str>,
    tenants: Arc<Vec<TenantRuntime>>,
    client: Client,
    jwks: RwLock<Option<JwksCache>>,
}

#[derive(Clone)]
struct TenantRuntime {
    resource: Arc<str>,
    tenant_id: Arc<str>,
    config_path: Arc<PathBuf>,
    local_file_root: Option<Arc<PathBuf>>,
    task_id: Option<Arc<str>>,
    profile_management: Option<bool>,
}

struct JwksCache {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

#[derive(Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct JwtClaims {
    iss: String,
    sub: Option<String>,
    aud: Option<Audience>,
    #[serde(rename = "exp")]
    _exp: usize,
    scope: Option<String>,
    scp: Option<ScopeClaim>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScopeClaim {
    Text(String),
    Many(Vec<String>),
}

struct AuthContext {
    tenant: Option<TenantRuntime>,
    principal: Principal,
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
    let auth = Arc::new(build_auth_state(&config).await?);
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
        auth,
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
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
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

async fn oauth_protected_resource(State(state): State<McpState>) -> Response {
    let McpAuthState::OAuth(oauth) = state.auth.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(json!({
        "resource": oauth.resource.as_ref(),
        "authorization_servers": [oauth.issuer.as_ref()],
        "scopes_supported": oauth.required_scopes.as_ref(),
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://github.com/TYzzt/ssh-gateway"
    }))
    .into_response()
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
    if !origin_allowed(&headers, &state.allowed_origins) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"origin_not_allowed"})),
        )
            .into_response();
    }
    let auth = match authenticate(&headers, &state).await {
        Ok(auth) => auth,
        Err(challenge) => return unauthorized_response(challenge),
    };

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
            "tools": tool_definitions(profile_management_enabled(&state, &auth).await, security_schemes(&state)),
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
            return tool_response(id, call, state, auth).await;
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

async fn build_auth_state(config: &AppConfig) -> Result<McpAuthState, ArrtError> {
    if config.mcp.auth.kind.eq_ignore_ascii_case("bearer") {
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
        return Ok(McpAuthState::Bearer {
            token: token.into(),
        });
    }
    if !config.mcp.auth.kind.eq_ignore_ascii_case("oauth_jwt") {
        return Err(ArrtError::Config(format!(
            "unsupported mcp.auth.type: {}",
            config.mcp.auth.kind
        )));
    }
    build_oauth_state(config).await.map(McpAuthState::OAuth)
}

async fn build_oauth_state(config: &AppConfig) -> Result<OAuthState, ArrtError> {
    let auth = &config.mcp.auth;
    let resource = required_auth_value(auth.resource.as_deref(), "mcp.auth.resource")?;
    let issuer = required_auth_value(auth.issuer.as_deref(), "mcp.auth.issuer")?;
    let jwks_url = match auth.jwks_url.as_deref() {
        Some(value) if !value.trim().is_empty() => value.to_string(),
        _ => discover_jwks_url(issuer).await?,
    };
    let tenants = if config.mcp.tenants.is_empty() {
        vec![TenantRuntime {
            resource: Arc::from(resource),
            tenant_id: Arc::from(resource),
            config_path: Arc::new(config.source_path().to_path_buf()),
            local_file_root: canonical_local_file_root(config.mcp.local_file_root.as_deref())?,
            task_id: task_id_from_env(config.mcp.task_id_env.as_deref())?,
            profile_management: Some(config.mcp.profile_management.enabled),
        }]
    } else {
        config
            .mcp
            .tenants
            .iter()
            .map(|tenant| tenant_runtime(config.source_path(), tenant))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(OAuthState {
        resource: Arc::from(resource),
        issuer: Arc::from(issuer),
        jwks_url: Arc::from(jwks_url),
        required_scopes: Arc::new(auth.scopes.clone()),
        audience_claim: Arc::from(auth.audience_claim.as_str()),
        tenants: Arc::new(tenants),
        client: Client::new(),
        jwks: RwLock::new(None),
    })
}

fn required_auth_value<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, ArrtError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ArrtError::Config(format!("{name} is required for oauth_jwt")))
}

fn tenant_runtime(root_path: &Path, tenant: &McpTenantConfig) -> Result<TenantRuntime, ArrtError> {
    let base = root_path.parent().unwrap_or_else(|| Path::new("."));
    let path = PathBuf::from(&tenant.config_path);
    let config_path = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    Ok(TenantRuntime {
        resource: Arc::from(tenant.resource.as_str()),
        tenant_id: Arc::from(tenant.tenant_id.as_deref().unwrap_or(&tenant.resource)),
        config_path: Arc::new(config_path),
        local_file_root: canonical_local_file_root(tenant.local_file_root.as_deref())?,
        task_id: task_id_from_env(tenant.task_id_env.as_deref())?,
        profile_management: tenant
            .profile_management
            .as_ref()
            .map(|value| value.enabled),
    })
}

fn canonical_local_file_root(root: Option<&str>) -> Result<Option<Arc<PathBuf>>, ArrtError> {
    root.map(|root| {
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
    .transpose()
}

fn task_id_from_env(name: Option<&str>) -> Result<Option<Arc<str>>, ArrtError> {
    name.map(|name| {
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
    .transpose()
}

async fn discover_jwks_url(issuer: &str) -> Result<String, ArrtError> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let metadata: Value = Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|err| ArrtError::Config(format!("fetch OIDC metadata {url}: {err}")))?
        .error_for_status()
        .map_err(|err| ArrtError::Config(format!("fetch OIDC metadata {url}: {err}")))?
        .json()
        .await
        .map_err(|err| ArrtError::Config(format!("parse OIDC metadata {url}: {err}")))?;
    metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| ArrtError::Config(format!("OIDC metadata {url} has no jwks_uri")))
}

async fn authenticate(headers: &HeaderMap, state: &McpState) -> Result<AuthContext, AuthChallenge> {
    match state.auth.as_ref() {
        McpAuthState::Bearer { token } => {
            if authorized(headers, token) {
                Ok(AuthContext {
                    tenant: None,
                    principal: Principal::local(CallerType::Mcp),
                })
            } else {
                Err(AuthChallenge::bearer())
            }
        }
        McpAuthState::OAuth(oauth) => authenticate_oauth(headers, oauth).await,
    }
}

async fn authenticate_oauth(
    headers: &HeaderMap,
    oauth: &OAuthState,
) -> Result<AuthContext, AuthChallenge> {
    let token = bearer_token(headers).ok_or_else(|| oauth_challenge(oauth, None))?;
    let header = decode_header(token).map_err(|_| oauth_challenge(oauth, Some("invalid_token")))?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| oauth_challenge(oauth, Some("invalid_token")))?;
    let key = jwk_for_kid(oauth, kid)
        .await
        .map_err(|_| oauth_challenge(oauth, Some("invalid_token")))?;
    let decoding_key = DecodingKey::from_rsa_components(
        key.n.as_deref().unwrap_or_default(),
        key.e.as_deref().unwrap_or_default(),
    )
    .map_err(|_| oauth_challenge(oauth, Some("invalid_token")))?;
    let algorithm = header.alg;
    if !matches!(
        algorithm,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
    ) {
        return Err(oauth_challenge(oauth, Some("invalid_token")));
    }
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[oauth.issuer.as_ref()]);
    validation.validate_aud = false;
    let claims = decode::<JwtClaims>(token, &decoding_key, &validation)
        .map_err(|_| oauth_challenge(oauth, Some("invalid_token")))?
        .claims;
    if claims.iss != oauth.issuer.as_ref() {
        return Err(oauth_challenge(oauth, Some("invalid_token")));
    }
    let subject = claims
        .sub
        .as_deref()
        .filter(|subject| !subject.trim().is_empty())
        .ok_or_else(|| oauth_challenge(oauth, Some("invalid_token")))?
        .to_string();
    let audiences = claim_audiences(&claims, oauth.audience_claim.as_ref());
    let scopes = claim_scopes(&claims);
    if !oauth
        .required_scopes
        .iter()
        .all(|scope| scopes.iter().any(|item| item == scope))
    {
        return Err(oauth_challenge(oauth, Some("insufficient_scope")));
    }
    let tenant = oauth
        .tenants
        .iter()
        .find(|tenant| {
            audiences
                .iter()
                .any(|audience| audience == tenant.resource.as_ref())
        })
        .cloned()
        .ok_or_else(|| oauth_challenge(oauth, Some("invalid_token")))?;
    Ok(AuthContext {
        principal: Principal {
            caller_type: CallerType::Mcp,
            subject: Some(subject),
            tenant_id: Some(tenant.tenant_id.to_string()),
            resource: Some(tenant.resource.to_string()),
            client_id: claims
                .extra
                .get("client_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            scopes,
        },
        tenant: Some(tenant),
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

async fn jwk_for_kid(oauth: &OAuthState, kid: &str) -> Result<Jwk, ArrtError> {
    if let Some(key) = cached_jwk(oauth, kid).await {
        return Ok(key);
    }
    refresh_jwks(oauth).await?;
    cached_jwk(oauth, kid)
        .await
        .ok_or_else(|| ArrtError::Config(format!("JWKS key not found: {kid}")))
}

async fn cached_jwk(oauth: &OAuthState, kid: &str) -> Option<Jwk> {
    let guard = oauth.jwks.read().await;
    let cache = guard.as_ref()?;
    if cache.fetched_at.elapsed() > Duration::from_secs(300) {
        return None;
    }
    cache
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(kid) && key.kty.as_deref() == Some("RSA"))
        .cloned()
}

async fn refresh_jwks(oauth: &OAuthState) -> Result<(), ArrtError> {
    let jwks: Jwks = oauth
        .client
        .get(oauth.jwks_url.as_ref())
        .send()
        .await
        .map_err(|err| ArrtError::Config(format!("fetch JWKS: {err}")))?
        .error_for_status()
        .map_err(|err| ArrtError::Config(format!("fetch JWKS: {err}")))?
        .json()
        .await
        .map_err(|err| ArrtError::Config(format!("parse JWKS: {err}")))?;
    *oauth.jwks.write().await = Some(JwksCache {
        keys: jwks.keys,
        fetched_at: Instant::now(),
    });
    Ok(())
}

fn claim_audiences(claims: &JwtClaims, audience_claim: &str) -> Vec<String> {
    if audience_claim == "aud" {
        return match &claims.aud {
            Some(Audience::One(value)) => vec![value.clone()],
            Some(Audience::Many(values)) => values.clone(),
            None => Vec::new(),
        };
    }
    match claims.extra.get(audience_claim) {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn claim_scopes(claims: &JwtClaims) -> Vec<String> {
    if let Some(scope) = &claims.scope {
        return scope.split_whitespace().map(str::to_string).collect();
    }
    match &claims.scp {
        Some(ScopeClaim::Text(value)) => value.split_whitespace().map(str::to_string).collect(),
        Some(ScopeClaim::Many(values)) => values.clone(),
        None => Vec::new(),
    }
}

#[derive(Debug)]
struct AuthChallenge {
    header: String,
}

impl AuthChallenge {
    fn bearer() -> Self {
        Self {
            header: "Bearer".to_string(),
        }
    }
}

fn oauth_challenge(oauth: &OAuthState, error: Option<&str>) -> AuthChallenge {
    let mut header = format!(
        "Bearer resource_metadata=\"{}\"",
        oauth_resource_metadata_url(oauth.resource.as_ref())
    );
    if let Some(error) = error {
        header.push_str(&format!(", error=\"{error}\""));
    }
    if !oauth.required_scopes.is_empty() {
        header.push_str(&format!(", scope=\"{}\"", oauth.required_scopes.join(" ")));
    }
    AuthChallenge { header }
}

fn oauth_resource_metadata_url(resource: &str) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        resource.trim_end_matches('/')
    )
}

fn unauthorized_response(challenge: AuthChallenge) -> Response {
    let header = challenge.header.clone();
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error":"unauthorized","_meta":{"mcp/www_authenticate":challenge.header}})),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&header) {
        response.headers_mut().insert("www-authenticate", value);
    }
    response
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

async fn tool_response(id: Value, call: ToolCall, state: McpState, auth: AuthContext) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let outcome = call_tool(
        &state.service,
        &state,
        &auth,
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
    state: &McpState,
    auth: &AuthContext,
    request_id: &str,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    if name == "list_hosts" {
        let config = load_tenant_config(auth).await?;
        return service
            .list_hosts_for_principal(request_id, &auth.principal, config.as_ref())
            .await
            .map(|hosts| json!({"hosts": hosts}))
            .map_err(|err| err.to_string());
    }
    if args.get("task_id").is_some() {
        return Err(
            "task_id is injected by the gateway and is not accepted as a tool argument".to_string(),
        );
    }
    let profile_management_enabled = profile_management_enabled(state, auth).await;
    if matches!(name, "create_profile" | "delete_profile") && !profile_management_enabled {
        return Err("profile management is disabled".to_string());
    }
    let local_file_root = local_file_root(state, auth);
    guard_local_transfer(name, &args, local_file_root)?;
    let task_id = task_id(state, auth);
    let request = request_from_tool(name, &args, task_id)?;
    let result = match load_tenant_config(auth).await? {
        Some(config) => {
            service
                .execute_for_principal_config(
                    request_id,
                    auth.principal.clone(),
                    task_id.map(str::to_string),
                    request,
                    config,
                    session_namespace(auth),
                )
                .await
        }
        None => {
            service
                .execute_principal(
                    request_id,
                    auth.principal.clone(),
                    task_id.map(str::to_string),
                    request,
                )
                .await
        }
    };
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

async fn load_tenant_config(auth: &AuthContext) -> Result<Option<AppConfig>, String> {
    let Some(tenant) = &auth.tenant else {
        return Ok(None);
    };
    AppConfig::load_from_path(tenant.config_path.as_ref().clone())
        .await
        .map(Some)
        .map_err(|err| err.to_string())
}

fn local_file_root<'a>(state: &'a McpState, auth: &'a AuthContext) -> Option<&'a Path> {
    auth.tenant
        .as_ref()
        .and_then(|tenant| tenant.local_file_root.as_deref())
        .or(state.local_file_root.as_deref())
        .map(PathBuf::as_path)
}

fn task_id<'a>(state: &'a McpState, auth: &'a AuthContext) -> Option<&'a str> {
    auth.tenant
        .as_ref()
        .and_then(|tenant| tenant.task_id.as_deref())
        .or(state.task_id.as_deref())
}

fn session_namespace(auth: &AuthContext) -> &str {
    auth.tenant
        .as_ref()
        .map(|tenant| tenant.resource.as_ref())
        .unwrap_or("default")
}

async fn profile_management_enabled(state: &McpState, auth: &AuthContext) -> bool {
    if let Some(enabled) = auth
        .tenant
        .as_ref()
        .and_then(|tenant| tenant.profile_management)
    {
        return enabled;
    }
    match load_tenant_config(auth).await {
        Ok(Some(config)) => config.mcp.profile_management.enabled,
        _ => state.profile_management_enabled,
    }
}

fn security_schemes(state: &McpState) -> Option<Value> {
    let McpAuthState::OAuth(oauth) = state.auth.as_ref() else {
        return None;
    };
    Some(json!([{
        "type": "oauth2",
        "scopes": oauth.required_scopes.as_ref()
    }]))
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
    reject_keys(
        value,
        path,
        &["host", "user", "port", "auth", "host_key_sha256"],
    )?;
    validate_auth(value.get("auth"), &format!("{path}.auth"))
}

fn validate_auth(value: Option<&Value>, path: &str) -> Result<(), String> {
    reject_optional_keys(
        value,
        path,
        &[
            "type",
            "key_path",
            "passphrase",
            "password",
            "credential_id",
        ],
    )
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

fn tool_definitions(
    profile_management_enabled: bool,
    security_schemes: Option<Value>,
) -> Vec<Value> {
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
    if let Some(security_schemes) = security_schemes {
        for tool in &mut tools {
            tool["securitySchemes"] = security_schemes.clone();
            tool["_meta"]["securitySchemes"] = security_schemes.clone();
        }
    }
    tools
}

fn profile_schema() -> Value {
    let auth = json!({"type":"object","properties":{"type":{"type":"string","enum":["key","password","external"]},"key_path":{"type":"string"},"passphrase":{"type":"string"},"password":{"type":"string"},"credential_id":{"type":"string"}},"additionalProperties":false});
    let endpoint = json!({"type":"object","properties":{"host":{"type":"string"},"user":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"host_key_sha256":{"type":"string"},"auth":auth},"required":["host","user"],"additionalProperties":false});
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey};
    use serde::Serialize;
    use tower::ServiceExt;

    #[tokio::test]
    async fn oauth_jwt_authenticates_subject_and_isolates_principals() {
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            exp: usize,
            scope: &'a str,
            client_id: &'a str,
        }
        let key = RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let public = key.to_public_key();
        let der = key.to_pkcs1_der().unwrap();
        let oauth = OAuthState {
            resource: "https://resource.example/mcp".into(),
            issuer: "https://issuer.example".into(),
            jwks_url: "https://issuer.example/jwks".into(),
            required_scopes: Arc::new(vec!["ssh-gateway".into()]),
            audience_claim: "aud".into(),
            tenants: Arc::new(vec![TenantRuntime {
                resource: "https://resource.example/mcp".into(),
                tenant_id: "tenant-1".into(),
                config_path: Arc::new(PathBuf::from("/tmp/unused-config")),
                local_file_root: None,
                task_id: None,
                profile_management: None,
            }]),
            client: Client::new(),
            jwks: RwLock::new(Some(JwksCache {
                keys: vec![Jwk {
                    kid: Some("test-key".into()),
                    kty: Some("RSA".into()),
                    n: Some(URL_SAFE_NO_PAD.encode(public.n_bytes())),
                    e: Some(URL_SAFE_NO_PAD.encode(public.e_bytes())),
                }],
                fetched_at: Instant::now(),
            })),
        };
        let signing_key = EncodingKey::from_rsa_der(der.as_bytes());
        let sign = |sub: &str, aud: &str, scope: &str| {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("test-key".into());
            encode(
                &header,
                &Claims {
                    iss: "https://issuer.example",
                    sub,
                    aud,
                    exp: 4_102_444_800,
                    scope,
                    client_id: "codex",
                },
                &signing_key,
            )
            .unwrap()
        };
        let authenticate_token = |token: String| {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
            headers
        };
        let alice = authenticate_oauth(
            &authenticate_token(sign("alice", "https://resource.example/mcp", "ssh-gateway")),
            &oauth,
        )
        .await
        .unwrap();
        let bob = authenticate_oauth(
            &authenticate_token(sign("bob", "https://resource.example/mcp", "ssh-gateway")),
            &oauth,
        )
        .await
        .unwrap();
        assert_eq!(alice.principal.subject.as_deref(), Some("alice"));
        assert_eq!(alice.principal.tenant_id.as_deref(), Some("tenant-1"));
        assert_eq!(alice.principal.client_id.as_deref(), Some("codex"));
        assert_ne!(
            alice.principal.execution_namespace(),
            bob.principal.execution_namespace()
        );
        assert!(authenticate_oauth(
            &authenticate_token(sign("alice", "https://other.example/mcp", "ssh-gateway")),
            &oauth
        )
        .await
        .is_err());
        assert!(authenticate_oauth(
            &authenticate_token(sign("alice", "https://resource.example/mcp", "wrong")),
            &oauth
        )
        .await
        .is_err());
    }

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
        let names = tool_definitions(true, None)
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
        let disabled = tool_definitions(false, None);
        assert!(disabled
            .iter()
            .any(|tool| tool["name"] == "get_profile_policy"));
        assert!(!disabled.iter().any(|tool| tool["name"] == "create_profile"));
        assert!(!disabled.iter().any(|tool| tool["name"] == "delete_profile"));
        let enabled = tool_definitions(true, None);
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
        let tools = tool_definitions(false, None);
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
    fn oauth_security_schemes_are_added_to_tools() {
        let tools = tool_definitions(
            true,
            Some(json!([{"type":"oauth2","scopes":["ssh-gateway"]}])),
        );
        assert!(tools
            .iter()
            .all(|tool| tool["securitySchemes"][0]["type"] == "oauth2"));
    }

    #[test]
    fn oauth_claim_helpers_accept_audiences_and_scopes() {
        let claims = JwtClaims {
            iss: "https://idp.example.com".into(),
            sub: Some("user".into()),
            aud: Some(Audience::Many(vec![
                "https://a.example.com/mcp".into(),
                "https://b.example.com/mcp".into(),
            ])),
            _exp: 4_102_444_800,
            scope: Some("ssh-gateway other".into()),
            scp: None,
            extra: Map::new(),
        };
        assert_eq!(
            claim_audiences(&claims, "aud"),
            vec![
                "https://a.example.com/mcp".to_string(),
                "https://b.example.com/mcp".to_string()
            ]
        );
        assert_eq!(
            claim_scopes(&claims),
            vec!["ssh-gateway".to_string(), "other".to_string()]
        );
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
        let tools = tool_definitions(true, None);
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
            auth: Arc::new(McpAuthState::Bearer {
                token: "secret".into(),
            }),
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

    #[tokio::test]
    async fn mcp_http_preserves_bearer_and_both_protocol_versions() {
        let state = McpState {
            service: GatewayService::new(),
            auth: Arc::new(McpAuthState::Bearer {
                token: "test-token".into(),
            }),
            allowed_origins: Arc::new(Vec::new()),
            local_file_root: None,
            task_id: None,
            profile_management_enabled: false,
        };
        for version in [MCP_PROTOCOL_CURRENT, MCP_PROTOCOL_COMPAT] {
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":version}}).to_string();
            let response = app(state.clone())
                .oneshot(
                    HttpRequest::post("/mcp")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer test-token")
                        .header("mcp-method", "initialize")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let payload: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(payload["result"]["protocolVersion"], version);
        }
        let current_ping = json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":MCP_PROTOCOL_CURRENT}}}).to_string();
        let response = app(state.clone())
            .oneshot(
                HttpRequest::post("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(current_ping.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["code"],
            -32600
        );
        let response = app(state)
            .oneshot(
                HttpRequest::post("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .header("mcp-method", "ping")
                    .body(Body::from(current_ping))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["result"],
            json!({})
        );
    }
}
