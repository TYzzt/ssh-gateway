use crate::principal::Principal;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub struct AuditEvent<'a> {
    pub event: &'static str,
    pub timestamp_ms: u128,
    pub request_id: &'a str,
    pub principal: &'a Principal,
    pub operation: &'a str,
    pub profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub duration_ms: u128,
    pub success: bool,
    pub error_code: Option<&'a str>,
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent<'_>);
    fn emit_authorization(&self, event: &AuthorizationAuditEvent<'_>);
}

#[derive(Serialize)]
pub struct AuthorizationAuditEvent<'a> {
    pub event: &'a str,
    pub timestamp_ms: u128,
    pub principal: &'a Principal,
    pub metadata: &'a Value,
}

pub struct StderrAuditSink;

impl AuditSink for StderrAuditSink {
    fn emit(&self, event: &AuditEvent<'_>) {
        if let Ok(line) = serde_json::to_string(event) {
            eprintln!("{line}");
        }
    }

    fn emit_authorization(&self, event: &AuthorizationAuditEvent<'_>) {
        if let Ok(line) = serde_json::to_string(event) {
            eprintln!("{line}");
        }
    }
}
