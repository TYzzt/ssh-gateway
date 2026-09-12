use crate::config::{AgentPolicyConfig, AppConfig};
use crate::errors::ArrtError;
use crate::protocol::{CallerType, Request};

pub struct PolicyEngine;

#[derive(Clone, Copy)]
enum Capability {
    Exec,
    Read,
    Write,
    Upload,
    Download,
    Tunnel,
}

impl PolicyEngine {
    pub fn authorize_caller(caller: CallerType, request: &Request) -> Result<(), ArrtError> {
        if caller.enforces_agent_policy() && matches!(request, Request::Shutdown) {
            return Err(ArrtError::PolicyDenied(
                "agents cannot stop the gateway daemon".to_string(),
            ));
        }
        Ok(())
    }

    pub fn authorize(
        config: &AppConfig,
        caller: CallerType,
        request: &Request,
    ) -> Result<(), ArrtError> {
        Self::authorize_caller(caller, request)?;
        if !caller.enforces_agent_policy() {
            return Ok(());
        }

        match request {
            Request::Exec {
                profile,
                command,
                cwd,
                ..
            } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Exec)?;
                require_allowed_command(policy, command)?;
                if let Some(cwd) = cwd {
                    require_path(policy, cwd, false)?;
                }
            }
            Request::Read { profile, path } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Read)?;
                require_path(policy, path, false)?;
            }
            Request::Write { profile, path, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Write)?;
                require_path(policy, path, true)?;
            }
            Request::Upload { profile, dst, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Upload)?;
                require_path(policy, dst, true)?;
            }
            Request::Download { profile, src, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Download)?;
                require_path(policy, src, false)?;
            }
            Request::TunnelOpen { profile, .. } => {
                require_capability(&config.profile(profile)?.agent_policy, Capability::Tunnel)?;
            }
            Request::TunnelClose { profile, .. } => {
                let profile = profile.as_deref().ok_or_else(|| {
                    ArrtError::PolicyDenied(
                        "agent tunnel close requires --profile for policy verification".to_string(),
                    )
                })?;
                require_capability(&config.profile(profile)?.agent_policy, Capability::Tunnel)?;
            }
            Request::SessionClose { .. } | Request::SessionInspect { .. } => {}
            Request::SessionList
            | Request::Ping
            | Request::ProfileList
            | Request::ProfileShow { .. }
            | Request::ProfileValidate { .. } => {}
            Request::Shutdown => {}
        }
        Ok(())
    }
}

fn require_capability(policy: &AgentPolicyConfig, capability: Capability) -> Result<(), ArrtError> {
    let (allowed, name) = match capability {
        Capability::Exec => (policy.capabilities.exec, "exec"),
        Capability::Read => (policy.capabilities.read, "read"),
        Capability::Write => (policy.capabilities.write, "write"),
        Capability::Upload => (policy.capabilities.upload, "upload"),
        Capability::Download => (policy.capabilities.download, "download"),
        Capability::Tunnel => (policy.capabilities.tunnel, "tunnel"),
    };
    if allowed {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(format!(
            "capability {name} is disabled"
        )))
    }
}

fn require_allowed_command(policy: &AgentPolicyConfig, command: &str) -> Result<(), ArrtError> {
    if policy
        .allowed_commands
        .iter()
        .any(|allowed| allowed == command)
    {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(
            "command is not present in agent_policy.allowed_commands".to_string(),
        ))
    }
}

fn require_path(policy: &AgentPolicyConfig, path: &str, write: bool) -> Result<(), ArrtError> {
    let allowed = if write {
        &policy.allowed_write_paths
    } else {
        &policy.allowed_read_paths
    };
    if allowed.is_empty() {
        return Ok(());
    }
    let normalized = normalize_remote_path(path)?;
    if allowed.iter().any(|root| {
        normalize_remote_path(root).is_ok_and(|root| {
            root == "/" || normalized == root || normalized.starts_with(&(root + "/"))
        })
    }) {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(format!(
            "{} path is outside allowed roots: {path}",
            if write { "write" } else { "read" }
        )))
    }
}

fn normalize_remote_path(path: &str) -> Result<String, ArrtError> {
    if !path.starts_with('/') {
        return Err(ArrtError::PolicyDenied(format!(
            "policy-restricted remote path must be absolute: {path}"
        )));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_allowlist_rejects_shell_quote_and_escape_bypasses() {
        let policy = AgentPolicyConfig {
            allowed_commands: vec!["docker ps".to_string()],
            ..AgentPolicyConfig::default()
        };
        assert!(require_allowed_command(&policy, "docker ps").is_ok());
        assert!(require_allowed_command(&policy, "reboot").is_err());
        assert!(require_allowed_command(&policy, "re\"boot\"").is_err());
        assert!(require_allowed_command(&policy, "reboo\\t").is_err());
        assert!(require_allowed_command(&policy, "docker  ps").is_err());
    }

    #[test]
    fn allowed_paths_resist_parent_traversal() {
        let policy = AgentPolicyConfig {
            allowed_read_paths: vec!["/var/log".to_string()],
            ..AgentPolicyConfig::default()
        };
        assert!(require_path(&policy, "/var/log/nginx/access.log", false).is_ok());
        assert!(require_path(&policy, "/var/log/../../etc/shadow", false).is_err());
        assert!(require_path(&policy, "/var/logger", false).is_err());
    }

    #[test]
    fn agent_context_enforces_capability_while_human_cli_stays_compatible() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
  - name: readonly
    target:
      host: example
      user: root
      auth:
        type: password
        password: secret
    agent_policy:
      capabilities:
        exec: false
"#,
        )
        .unwrap();
        let request = Request::Exec {
            profile: "readonly".to_string(),
            command: "id".to_string(),
            cwd: None,
            timeout_seconds: Some(30),
            env: Vec::new(),
        };
        assert!(PolicyEngine::authorize(&config, CallerType::AgentCli, &request).is_err());
        assert!(PolicyEngine::authorize(&config, CallerType::Mcp, &request).is_err());
        assert!(PolicyEngine::authorize(&config, CallerType::HumanCli, &request).is_ok());
    }
}
