use crate::approval::{ApprovalClaim, ApprovalService};
use crate::config::{AppConfig, AuthConfig, ResolvedAuthConfig, RiskLevelConfig};
use crate::errors::ArrtError;
use crate::protocol::{CallerType, CommandResult, Request};
use crate::redaction::SecretRedactor;
use serde_json::Value;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

pub trait ProfileStore: Send + Sync {
    fn load(&self) -> Pin<Box<dyn Future<Output = Result<AppConfig, ArrtError>> + Send + '_>>;
}

pub struct FileProfileStore;

pub trait CredentialStore: Send + Sync {
    fn resolve(
        &self,
        auth: &AuthConfig,
        base_dir: &Path,
        label: &str,
    ) -> Result<ResolvedAuthConfig, ArrtError>;
}

pub struct FileCredentialStore;

impl CredentialStore for FileCredentialStore {
    fn resolve(
        &self,
        auth: &AuthConfig,
        base_dir: &Path,
        label: &str,
    ) -> Result<ResolvedAuthConfig, ArrtError> {
        auth.resolve(base_dir, label)
    }
}

impl ProfileStore for FileProfileStore {
    fn load(&self) -> Pin<Box<dyn Future<Output = Result<AppConfig, ArrtError>> + Send + '_>> {
        Box::pin(AppConfig::load())
    }
}

pub trait ApprovalStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        request: &Request,
        caller: CallerType,
        rule_id: Option<&str>,
        reason: Option<&str>,
        risk: Option<RiskLevelConfig>,
        redactor: &SecretRedactor,
        task_id: Option<&str>,
    ) -> Result<Value, ArrtError>;
    fn list(&self) -> Result<Value, ArrtError>;
    fn show(&self, id: &str) -> Result<Value, ArrtError>;
    fn claim(&self, id: &str) -> Result<ApprovalClaim, ArrtError>;
    fn reject(&self, id: &str) -> Result<Value, ArrtError>;
    fn finish(&self, id: &str, result: &CommandResult) -> Result<(), ArrtError>;
    fn cleanup(&self) -> Result<Value, ArrtError>;
}

pub trait ApprovalStoreFactory: Send + Sync {
    fn open(&self, config: &AppConfig) -> Result<Box<dyn ApprovalStore>, ArrtError>;
}

pub struct SqliteApprovalStoreFactory;

impl ApprovalStoreFactory for SqliteApprovalStoreFactory {
    fn open(&self, config: &AppConfig) -> Result<Box<dyn ApprovalStore>, ArrtError> {
        Ok(Box::new(ApprovalService::from_config(config)?))
    }
}

impl ApprovalStore for ApprovalService {
    fn create(
        &self,
        request: &Request,
        caller: CallerType,
        rule_id: Option<&str>,
        reason: Option<&str>,
        risk: Option<RiskLevelConfig>,
        redactor: &SecretRedactor,
        task_id: Option<&str>,
    ) -> Result<Value, ArrtError> {
        ApprovalService::create(
            self, request, caller, rule_id, reason, risk, redactor, task_id,
        )
    }
    fn list(&self) -> Result<Value, ArrtError> {
        ApprovalService::list(self)
    }
    fn show(&self, id: &str) -> Result<Value, ArrtError> {
        ApprovalService::show(self, id)
    }
    fn claim(&self, id: &str) -> Result<ApprovalClaim, ArrtError> {
        ApprovalService::claim(self, id)
    }
    fn reject(&self, id: &str) -> Result<Value, ArrtError> {
        ApprovalService::reject(self, id)
    }
    fn finish(&self, id: &str, result: &CommandResult) -> Result<(), ArrtError> {
        ApprovalService::finish(self, id, result)
    }
    fn cleanup(&self) -> Result<Value, ArrtError> {
        ApprovalService::cleanup(self)
    }
}
