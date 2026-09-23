use crate::protocol::CallerType;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Authenticated caller identity. Credential material is deliberately absent.
#[derive(Clone, Serialize)]
pub struct Principal {
    pub caller_type: CallerType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

impl Principal {
    pub fn local(caller_type: CallerType) -> Self {
        let subject = match caller_type {
            CallerType::HumanCli => "local-human",
            CallerType::AgentCli => "local-agent",
            CallerType::Mcp => "local-bearer",
        };
        Self {
            caller_type,
            subject: Some(subject.into()),
            tenant_id: None,
            resource: None,
            client_id: None,
            scopes: Vec::new(),
        }
    }

    pub fn execution_namespace(&self) -> String {
        let mut hasher = Sha256::new();
        for value in [
            format!("{:?}", self.caller_type),
            self.tenant_id.clone().unwrap_or_default(),
            self.resource.clone().unwrap_or_default(),
            self.subject.clone().unwrap_or_default(),
            self.client_id.clone().unwrap_or_default(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        format!("principal:{:x}", hasher.finalize())
    }
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("caller_type", &self.caller_type)
            .field("subject", &self.subject)
            .field("tenant_id", &self.tenant_id)
            .field("resource", &self.resource)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_principal_and_tenant_specific() {
        let mut principal = Principal::local(CallerType::Mcp);
        let original = principal.execution_namespace();
        principal.subject = Some("another-user".into());
        assert_ne!(original, principal.execution_namespace());
        principal.tenant_id = Some("tenant-1".into());
        assert_ne!(original, principal.execution_namespace());
    }
}
