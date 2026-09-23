use crate::config::{AppConfig, AuthConfig, Profile, ResolvedAuthConfig, ResolvedTransport};
use crate::storage::CredentialStore;
#[cfg(test)]
use crate::storage::FileCredentialStore;
use serde_json::Value;

#[derive(Default)]
pub struct SecretRedactor {
    secrets: Vec<String>,
}

impl SecretRedactor {
    #[cfg(test)]
    pub fn from_config(config: &AppConfig) -> Self {
        Self::from_config_with_credentials(config, &FileCredentialStore)
    }

    pub fn from_config_with_credentials(
        config: &AppConfig,
        credentials: &dyn CredentialStore,
    ) -> Self {
        let mut secrets = Vec::new();
        for profile in &config.profiles {
            if let Ok(resolved) =
                config.resolved_profile_with_credentials(&profile.name, credentials)
            {
                if let ResolvedTransport::Direct { target, bastions } = resolved.transport {
                    collect_auth(&target.auth, &mut secrets);
                    for bastion in bastions {
                        collect_auth(&bastion.auth, &mut secrets);
                    }
                }
            }
        }
        if let Ok(token) = std::env::var(&config.mcp.auth.token_env) {
            push_secret(&mut secrets, token);
        }
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Self { secrets }
    }

    #[cfg(test)]
    pub fn from_config_and_profile(config: &AppConfig, profile: &Profile) -> Self {
        Self::from_config_and_profile_with_credentials(config, profile, &FileCredentialStore)
    }

    pub fn from_config_and_profile_with_credentials(
        config: &AppConfig,
        profile: &Profile,
        credentials: &dyn CredentialStore,
    ) -> Self {
        let mut redactor = Self::from_config_with_credentials(config, credentials);
        collect_raw_auth(profile.auth.as_ref(), &mut redactor.secrets);
        collect_raw_auth(profile.target.auth.as_ref(), &mut redactor.secrets);
        for endpoint in &profile.bastions {
            collect_raw_auth(endpoint.auth.as_ref(), &mut redactor.secrets);
        }
        redactor
            .secrets
            .sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        redactor.secrets.dedup();
        redactor
    }

    pub fn redact(&self, input: &str) -> String {
        let text = self.secrets.iter().fold(input.to_string(), |text, secret| {
            text.replace(secret, "[REDACTED]")
        });
        redact_private_key_blocks(text)
    }

    pub fn redact_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.redact(text),
            Value::Array(items) => items.iter_mut().for_each(|item| self.redact_value(item)),
            Value::Object(map) => map.values_mut().for_each(|item| self.redact_value(item)),
            _ => {}
        }
    }
}

fn collect_raw_auth(auth: Option<&AuthConfig>, secrets: &mut Vec<String>) {
    let Some(auth) = auth else {
        return;
    };
    for value in [&auth.password, &auth.passphrase, &auth.key_path]
        .into_iter()
        .flatten()
    {
        push_secret(secrets, value.clone());
    }
}

fn redact_private_key_blocks(mut text: String) -> String {
    let mut search_from = 0;
    while let Some(start) = text[search_from..]
        .find("-----BEGIN ")
        .map(|offset| search_from + offset)
    {
        let header_end = text[start..]
            .find('\n')
            .map_or(text.len(), |offset| start + offset + 1);
        if !text[start..header_end].contains("PRIVATE KEY") {
            search_from = header_end;
            continue;
        }
        let Some(end_start) = text[header_end..]
            .find("-----END ")
            .map(|offset| header_end + offset)
        else {
            text.replace_range(start.., "[REDACTED PRIVATE KEY]");
            break;
        };
        let end = text[end_start..]
            .find('\n')
            .map_or(text.len(), |offset| end_start + offset + 1);
        text.replace_range(start..end, "[REDACTED PRIVATE KEY]");
        search_from = start + "[REDACTED PRIVATE KEY]".len();
    }
    text
}

fn collect_auth(auth: &ResolvedAuthConfig, secrets: &mut Vec<String>) {
    match auth {
        ResolvedAuthConfig::Key {
            key_path,
            passphrase,
        } => {
            push_secret(secrets, key_path.display().to_string());
            if let Some(passphrase) = passphrase {
                push_secret(secrets, passphrase.clone());
            }
        }
        ResolvedAuthConfig::Password { password } => push_secret(secrets, password.clone()),
    }
}

fn push_secret(secrets: &mut Vec<String>, value: String) {
    if !value.is_empty() {
        secrets.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_all_occurrences_longest_first() {
        let redactor = SecretRedactor {
            secrets: vec!["hunter2".into()],
        };
        assert_eq!(
            redactor.redact("bad hunter2 hunter2"),
            "bad [REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn redacts_private_key_blocks_from_command_output() {
        let redactor = SecretRedactor::default();
        let output = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let redacted = redactor.redact(output);
        assert!(redacted.contains("[REDACTED PRIVATE KEY]"));
        assert!(!redacted.contains("abc123"));
        assert!(redacted.contains("before") && redacted.contains("after"));
    }

    #[test]
    fn includes_credentials_from_a_proposed_profile() {
        let config: AppConfig = serde_yaml::from_str(
            "profiles:\n- name: current\n  target: {host: current, user: root, auth: {type: password, password: existing}}\n",
        )
        .unwrap();
        let profile: Profile = serde_yaml::from_str(
            "name: new\ntarget: {host: new, user: ops, auth: {type: key, key_path: /keys/private, passphrase: proposed-secret}}\n",
        )
        .unwrap();
        let redactor = SecretRedactor::from_config_and_profile(&config, &profile);
        assert_eq!(
            redactor.redact("proposed-secret /keys/private existing"),
            "[REDACTED] [REDACTED] [REDACTED]"
        );
    }
}
