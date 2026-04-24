use crate::errors::ArrtError;
use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const APP_QUALIFIER: &str = "opensource";
const APP_ORG: &str = "opensource";
const APP_NAME: &str = "ssh-gateway";

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(skip)]
    source_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub via_profile: Option<String>,
    pub target: HostEndpoint,
    #[serde(default)]
    pub bastions: Vec<HostEndpoint>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub remote: RemoteConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub keepalive: KeepaliveConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostEndpoint {
    pub host: String,
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuthConfig {
    #[serde(rename = "type", default)]
    pub kind: Option<AuthKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Key,
    Password,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemoteConfig {
    #[serde(default = "default_shell")]
    pub shell: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    #[serde(default = "default_agent_enabled")]
    pub manage: bool,
    #[serde(default = "default_agent_remote_path")]
    pub remote_path: String,
    #[serde(default = "default_agent_version")]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BootstrapConfig {
    #[serde(default = "default_bootstrap_enabled")]
    pub enabled: bool,
    #[serde(default = "default_remote_temp_dir")]
    pub remote_temp_dir: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeoutConfig {
    #[serde(default = "default_exec_timeout")]
    pub exec_seconds: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_session_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeepaliveConfig {
    #[serde(default = "default_keepalive_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_keepalive_count")]
    pub count_max: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedProfile {
    pub name: String,
    pub transport: ResolvedTransport,
    pub agent: AgentConfig,
    pub timeouts: TimeoutConfig,
}

#[derive(Debug, Clone)]
pub enum ResolvedTransport {
    Direct {
        target: ResolvedEndpoint,
        bastions: Vec<ResolvedEndpoint>,
    },
    Delegated {
        via_profile: String,
        target: DelegatedEndpoint,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub auth: ResolvedAuthConfig,
}

#[derive(Debug, Clone)]
pub struct DelegatedEndpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub enum ResolvedAuthConfig {
    Key {
        key_path: PathBuf,
        passphrase: Option<String>,
    },
    Password {
        password: String,
    },
}

fn default_port() -> u16 {
    22
}

fn default_shell() -> String {
    "bash -lc".to_string()
}

fn default_agent_enabled() -> bool {
    true
}

fn default_agent_remote_path() -> String {
    "/tmp/ssh-gatewayd".to_string()
}

fn default_agent_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_bootstrap_enabled() -> bool {
    true
}

fn default_remote_temp_dir() -> String {
    "/tmp".to_string()
}

fn default_exec_timeout() -> u64 {
    600
}

fn default_idle_timeout() -> u64 {
    900
}

fn default_keepalive_interval() -> u64 {
    30
}

fn default_keepalive_count() -> u64 {
    3
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            shell: default_shell(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manage: default_agent_enabled(),
            remote_path: default_agent_remote_path(),
            version: default_agent_version(),
        }
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_enabled(),
            remote_temp_dir: default_remote_temp_dir(),
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            exec_seconds: default_exec_timeout(),
            idle_session_seconds: default_idle_timeout(),
        }
    }
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_keepalive_interval(),
            count_max: default_keepalive_count(),
        }
    }
}

impl AppConfig {
    pub async fn load() -> Result<Self, ArrtError> {
        let path = config_path()?;
        let raw = tokio::fs::read_to_string(&path).await.map_err(|err| {
            ArrtError::Config(format!("failed to read {}: {}", path.display(), err))
        })?;
        let mut config = parse_config(&raw, &path)?;
        config.source_path = path;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ArrtError> {
        let mut names = HashSet::new();
        if self.profiles.is_empty() {
            return Err(ArrtError::Config("no profiles configured".to_string()));
        }
        for profile in &self.profiles {
            if !names.insert(profile.name.clone()) {
                return Err(ArrtError::Config(format!(
                    "duplicate profile name: {}",
                    profile.name
                )));
            }
        }
        for profile in &self.profiles {
            let mut stack = Vec::new();
            let _ = self.resolve_profile(&profile.name, &mut stack)?;
        }
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<Profile, ArrtError> {
        self.profiles
            .iter()
            .find(|profile| profile.name == name)
            .cloned()
            .ok_or_else(|| ArrtError::ProfileNotFound(name.to_string()))
    }

    pub fn resolved_profile(&self, name: &str) -> Result<ResolvedProfile, ArrtError> {
        let mut stack = Vec::new();
        self.resolve_profile(name, &mut stack)
    }

    pub fn profile_summary(&self, name: &str) -> Result<Value, ArrtError> {
        let mut stack = Vec::new();
        self.profile_summary_with_stack(name, &mut stack)
    }

    fn resolve_profile(
        &self,
        name: &str,
        stack: &mut Vec<String>,
    ) -> Result<ResolvedProfile, ArrtError> {
        if stack.iter().any(|item| item == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(ArrtError::Config(format!(
                "profile dependency cycle: {}",
                cycle.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        let profile = self.profile(name)?;
        let result = profile.resolve(self, self.config_base_dir(), stack);
        let _ = stack.pop();
        result
    }

    fn profile_summary_with_stack(
        &self,
        name: &str,
        stack: &mut Vec<String>,
    ) -> Result<Value, ArrtError> {
        if stack.iter().any(|item| item == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(ArrtError::Config(format!(
                "profile dependency cycle: {}",
                cycle.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        let profile = self.profile(name)?;
        let result = profile.sanitized_json(self, self.config_base_dir(), stack);
        let _ = stack.pop();
        result
    }

    fn config_base_dir(&self) -> &Path {
        self.source_path.parent().unwrap_or_else(|| Path::new("."))
    }
}

impl Profile {
    fn resolve(
        &self,
        config: &AppConfig,
        base_dir: &Path,
        stack: &mut Vec<String>,
    ) -> Result<ResolvedProfile, ArrtError> {
        self.validate_common()?;

        let transport = if let Some(via_profile) = &self.via_profile {
            if !self.bastions.is_empty() {
                return Err(ArrtError::Config(format!(
                    "profile {} via_profile cannot be combined with bastions",
                    self.name
                )));
            }
            if self.auth.is_some() || self.target.auth.is_some() {
                return Err(ArrtError::Config(format!(
                    "profile {} via_profile uses the upstream profile's SSH capability and must not set auth",
                    self.name
                )));
            }

            let _ = config.resolve_profile(via_profile, stack)?;
            ResolvedTransport::Delegated {
                via_profile: via_profile.clone(),
                target: self
                    .target
                    .as_delegated(&format!("profile {} target", self.name))?,
            }
        } else {
            self.target.validate(
                self.auth.as_ref(),
                base_dir,
                &format!("profile {} target", self.name),
            )?;
            for (index, bastion) in self.bastions.iter().enumerate() {
                bastion.validate(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} bastion {}", self.name, index + 1),
                )?;
            }
            ResolvedTransport::Direct {
                target: self.target.resolve(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} target", self.name),
                )?,
                bastions: self
                    .bastions
                    .iter()
                    .enumerate()
                    .map(|(index, bastion)| {
                        bastion.resolve(
                            self.auth.as_ref(),
                            base_dir,
                            &format!("profile {} bastion {}", self.name, index + 1),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }
        };

        Ok(ResolvedProfile {
            name: self.name.clone(),
            transport,
            agent: self.agent.clone(),
            timeouts: self.timeouts.clone(),
        })
    }

    fn sanitized_json(
        &self,
        config: &AppConfig,
        base_dir: &Path,
        stack: &mut Vec<String>,
    ) -> Result<Value, ArrtError> {
        let target = if self.via_profile.is_some() {
            self.target.sanitized_without_auth()?
        } else {
            self.target.sanitized_json(
                self.auth.as_ref(),
                base_dir,
                &format!("profile {} target", self.name),
            )?
        };

        let via_profile = if let Some(via_profile) = &self.via_profile {
            let _ = config.resolve_profile(via_profile, stack)?;
            json!(via_profile)
        } else {
            Value::Null
        };

        Ok(json!({
            "name": self.name,
            "via_profile": via_profile,
            "target": target,
            "bastions": self.bastions.iter().enumerate().map(|(index, bastion)| {
                bastion.sanitized_json(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} bastion {}", self.name, index + 1),
                )
            }).collect::<Result<Vec<_>, _>>()?,
            "remote": self.remote,
            "agent": self.agent,
            "bootstrap": self.bootstrap,
            "timeouts": self.timeouts,
            "keepalive": self.keepalive,
        }))
    }

    fn validate_common(&self) -> Result<(), ArrtError> {
        if self.name.trim().is_empty() {
            return Err(ArrtError::Config("profile name is empty".to_string()));
        }
        if self.target.host.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} target host is empty",
                self.name
            )));
        }
        if self.target.user.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} target user is empty",
                self.name
            )));
        }
        if self.agent.manage && self.agent.remote_path.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} agent.remote_path is empty",
                self.name
            )));
        }
        Ok(())
    }
}

impl HostEndpoint {
    fn validate(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
    ) -> Result<(), ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} host is empty")));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} user is empty")));
        }
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .ok_or_else(|| ArrtError::Config(format!("{label} auth is missing")))?;
        let _ = auth.resolve(base_dir, label)?;
        Ok(())
    }

    fn resolve(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
    ) -> Result<ResolvedEndpoint, ArrtError> {
        self.validate(fallback_auth, base_dir, label)?;
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .expect("validated auth exists");
        Ok(ResolvedEndpoint {
            host: self.host.clone(),
            user: self.user.clone(),
            port: self.port,
            auth: auth.resolve(base_dir, label)?,
        })
    }

    fn as_delegated(&self, label: &str) -> Result<DelegatedEndpoint, ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} host is empty")));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} user is empty")));
        }
        Ok(DelegatedEndpoint {
            host: self.host.clone(),
            user: self.user.clone(),
            port: self.port,
        })
    }

    fn sanitized_json(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
    ) -> Result<Value, ArrtError> {
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .ok_or_else(|| ArrtError::Config(format!("{label} auth is missing")))?;
        Ok(json!({
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "auth": auth.summary(base_dir, label)?,
        }))
    }

    fn sanitized_without_auth(&self) -> Result<Value, ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config("target host is empty".to_string()));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config("target user is empty".to_string()));
        }
        Ok(json!({
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "auth": Value::Null,
        }))
    }
}

impl AuthConfig {
    fn resolve(&self, base_dir: &Path, label: &str) -> Result<ResolvedAuthConfig, ArrtError> {
        match self.infer_kind(label)? {
            AuthKind::Key => {
                let key_path = self
                    .key_path
                    .as_deref()
                    .ok_or_else(|| ArrtError::Config(format!("{label} auth.key_path is empty")))?;
                if self.password.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=key cannot also set password"
                    )));
                }
                Ok(ResolvedAuthConfig::Key {
                    key_path: resolve_config_path(base_dir, key_path)?,
                    passphrase: self.passphrase.clone(),
                })
            }
            AuthKind::Password => {
                let password = self
                    .password
                    .clone()
                    .ok_or_else(|| ArrtError::Config(format!("{label} auth.password is empty")))?;
                if self.key_path.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=password cannot also set key_path"
                    )));
                }
                if self.passphrase.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=password cannot also set passphrase"
                    )));
                }
                Ok(ResolvedAuthConfig::Password { password })
            }
        }
    }

    fn infer_kind(&self, label: &str) -> Result<AuthKind, ArrtError> {
        match self.kind {
            Some(kind) => Ok(kind),
            None => match (
                self.key_path.is_some() || self.passphrase.is_some(),
                self.password.is_some(),
            ) {
                (true, false) => Ok(AuthKind::Key),
                (false, true) => Ok(AuthKind::Password),
                (false, false) => Err(ArrtError::Config(format!(
                    "{label} auth is missing type and credentials"
                ))),
                (true, true) => Err(ArrtError::Config(format!(
                    "{label} auth must not set both key credentials and password"
                ))),
            },
        }
    }

    fn summary(&self, base_dir: &Path, label: &str) -> Result<Value, ArrtError> {
        Ok(match self.resolve(base_dir, label)? {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => json!({
                "type": AuthKind::Key.as_str(),
                "has_password": false,
                "has_passphrase": passphrase.is_some(),
                "key_path": key_path.display().to_string(),
            }),
            ResolvedAuthConfig::Password { .. } => json!({
                "type": AuthKind::Password.as_str(),
                "has_password": true,
                "has_passphrase": false,
            }),
        })
    }
}

impl AuthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Password => "password",
        }
    }
}

impl ResolvedProfile {
    pub fn direct_chain(&self) -> Option<Vec<&ResolvedEndpoint>> {
        match &self.transport {
            ResolvedTransport::Direct { target, bastions } => {
                let mut chain = Vec::with_capacity(bastions.len() + 1);
                chain.extend(bastions.iter());
                chain.push(target);
                Some(chain)
            }
            ResolvedTransport::Delegated { .. } => None,
        }
    }
}

pub fn project_dirs() -> Result<ProjectDirs, ArrtError> {
    ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
        .ok_or_else(|| ArrtError::Config("failed to resolve application directories".to_string()))
}

#[cfg_attr(windows, allow(dead_code))]
pub fn ensure_runtime_dirs() -> Result<PathBuf, ArrtError> {
    let dirs = project_dirs()?;
    let runtime_dir = dirs.data_local_dir().to_path_buf();
    std::fs::create_dir_all(runtime_dir.join("control"))?;
    std::fs::create_dir_all(runtime_dir.join("logs"))?;
    Ok(runtime_dir)
}

pub fn config_path() -> Result<PathBuf, ArrtError> {
    if let Ok(override_path) = std::env::var("SSH_GATEWAY_CONFIG_PATH") {
        let path = PathBuf::from(override_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(path);
    }
    if let Ok(override_path) = std::env::var("ARRT_CONFIG_PATH") {
        let path = PathBuf::from(override_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(path);
    }
    let dirs = project_dirs()?;
    let config_dir = dirs.config_dir();
    std::fs::create_dir_all(config_dir)?;
    let yaml_path = config_dir.join("profiles.yaml");
    let yml_path = config_dir.join("profiles.yml");
    let toml_path = config_dir.join("profiles.toml");
    if yaml_path.exists() {
        return Ok(yaml_path);
    }
    if yml_path.exists() {
        return Ok(yml_path);
    }
    if toml_path.exists() {
        return Ok(toml_path);
    }
    if let Some(parent) = yaml_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(yaml_path)
}

pub fn config_path_display() -> Result<String, ArrtError> {
    Ok(config_path()?.display().to_string())
}

pub fn normalize_local_path(path: &str) -> Result<PathBuf, ArrtError> {
    let input = Path::new(path);
    if input.is_absolute() {
        return Ok(input.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(input))
}

fn resolve_config_path(base_dir: &Path, raw: &str) -> Result<PathBuf, ArrtError> {
    let expanded = expand_home(raw)?;
    if expanded.is_absolute() {
        return Ok(expanded);
    }
    Ok(base_dir.join(expanded))
}

fn expand_home(raw: &str) -> Result<PathBuf, ArrtError> {
    if raw == "~" {
        return home_dir();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return Ok(home_dir()?.join(rest));
    }
    Ok(PathBuf::from(raw))
}

fn home_dir() -> Result<PathBuf, ArrtError> {
    BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| ArrtError::Config("failed to resolve home directory".to_string()))
}

fn parse_config(raw: &str, path: &Path) -> Result<AppConfig, ArrtError> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("yaml") | Some("yml") => serde_yaml::from_str(raw)
            .map_err(|err| ArrtError::Config(format!("invalid yaml: {err}"))),
        Some("toml") => {
            toml::from_str(raw).map_err(|err| ArrtError::Config(format!("invalid toml: {err}")))
        }
        _ => serde_yaml::from_str(raw)
            .or_else(|_| toml::from_str(raw))
            .map_err(|err| ArrtError::Config(format!("invalid config: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set_base_dir(config: &mut AppConfig) {
        config.source_path = PathBuf::from("C:/config/profiles.yaml");
    }

    #[test]
    fn parses_legacy_profile_auth() {
        let raw = r#"
            [[profiles]]
            name = "gpu11"

            [profiles.target]
            host = "gpu11"
            user = "root"

            [profiles.auth]
            key_path = "~/.ssh/id_ed25519"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key { .. } => {}
            _ => panic!("expected key auth"),
        }
        assert_eq!(target.port, 22);
        assert_eq!(resolved.agent.remote_path, "/tmp/ssh-gatewayd");
    }

    #[test]
    fn resolves_per_hop_auth() {
        let raw = r#"
            [[profiles]]
            name = "gpu11"

            [profiles.target]
            host = "gpu11"
            user = "ubuntu"

            [profiles.target.auth]
            type = "password"
            password = "secret"

            [[profiles.bastions]]
            host = "vger"
            user = "root"

            [profiles.bastions.auth]
            type = "key"
            key_path = "./id_ed25519"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Direct { target, bastions } = resolved.transport else {
            panic!("expected direct transport");
        };
        match &target.auth {
            ResolvedAuthConfig::Password { password } => assert_eq!(password, "secret"),
            _ => panic!("expected password auth"),
        }
        match &bastions[0].auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_ed25519")
                );
                assert!(passphrase.is_none());
            }
            _ => panic!("expected key auth"),
        }
    }

    #[test]
    fn resolves_via_profile_transport() {
        let raw = r#"
            [[profiles]]
            name = "vger"

            [profiles.target]
            host = "111.186.43.31"
            user = "root"

            [profiles.target.auth]
            type = "key"
            key_path = "./id_ed25519"

            [[profiles]]
            name = "gpu11"
            via_profile = "vger"

            [profiles.target]
            host = "gpu11"
            user = "root"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Delegated {
            via_profile,
            target,
        } = resolved.transport
        else {
            panic!("expected delegated transport");
        };
        assert_eq!(via_profile, "vger");
        assert_eq!(target.host, "gpu11");
        assert_eq!(target.user, "root");
    }

    #[test]
    fn detects_via_profile_cycle() {
        let raw = r#"
            [[profiles]]
            name = "a"
            via_profile = "b"

            [profiles.target]
            host = "a"
            user = "root"

            [[profiles]]
            name = "b"
            via_profile = "a"

            [profiles.target]
            host = "b"
            user = "root"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("profile dependency cycle"));
    }

    #[test]
    fn profile_summary_redacts_password() {
        let raw = r#"
            [[profiles]]
            name = "vger"

            [profiles.target]
            host = "vger"
            user = "root"

            [profiles.target.auth]
            type = "password"
            password = "super-secret"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let summary = config.profile_summary("vger").unwrap();
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(encoded.contains("\"type\":\"password\""));
        assert!(encoded.contains("\"has_password\":true"));
        assert!(encoded.contains("\"has_passphrase\":false"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn resolves_key_passphrase_and_redacts_it() {
        let raw = r#"
            [[profiles]]
            name = "dcim"

            [profiles.target]
            host = "dcim"
            user = "root"

            [profiles.target.auth]
            type = "key"
            key_path = "./id_rsa_2048"
            passphrase = "secret-passphrase"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();

        let resolved = config.resolved_profile("dcim").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_rsa_2048")
                );
                assert_eq!(passphrase.as_deref(), Some("secret-passphrase"));
            }
            _ => panic!("expected key auth"),
        }

        let summary = config.profile_summary("dcim").unwrap();
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(encoded.contains("\"type\":\"key\""));
        assert!(encoded.contains("\"has_passphrase\":true"));
        assert!(!encoded.contains("secret-passphrase"));
    }

    #[test]
    fn infers_key_auth_when_passphrase_is_present() {
        let raw = r#"
            [[profiles]]
            name = "dcim"

            [profiles.target]
            host = "dcim"
            user = "root"

            [profiles.target.auth]
            key_path = "./id_rsa_2048"
            passphrase = "secret-passphrase"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();

        let resolved = config.resolved_profile("dcim").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_rsa_2048")
                );
                assert_eq!(passphrase.as_deref(), Some("secret-passphrase"));
            }
            _ => panic!("expected key auth"),
        }
    }

    #[test]
    fn rejects_password_auth_with_passphrase() {
        let raw = r#"
            [[profiles]]
            name = "bad"

            [profiles.target]
            host = "bad"
            user = "root"

            [profiles.target.auth]
            type = "password"
            password = "secret"
            passphrase = "nope"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("target auth.type=password cannot also set passphrase"));
    }

    #[test]
    fn rejects_mixed_password_and_key_passphrase_without_type() {
        let raw = r#"
            [[profiles]]
            name = "bad"

            [profiles.target]
            host = "bad"
            user = "root"

            [profiles.target.auth]
            password = "secret"
            passphrase = "nope"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("target auth must not set both key credentials and password"));
    }

    #[test]
    fn loads_yaml_preferred_over_toml() {
        let yaml = r#"
profiles:
  - name: vger
    target:
      host: 111.186.43.31
      user: root
      auth:
        type: key
        key_path: ./id_ed25519
"#;
        let mut config = parse_config(yaml, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        assert_eq!(config.profiles[0].name, "vger");
    }
}
