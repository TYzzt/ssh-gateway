use crate::config::{project_dirs, AppConfig, RiskLevelConfig};
use crate::errors::ArrtError;
use crate::protocol::{CallerType, CommandResult, Request};
use crate::redaction::SecretRedactor;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ApprovalClaim {
    pub id: String,
    pub request: Request,
    pub caller: CallerType,
    pub request_hash: String,
}

pub struct ApprovalService {
    path: PathBuf,
    ttl_seconds: u64,
}

impl ApprovalService {
    pub fn from_config(config: &AppConfig) -> Result<Self, ArrtError> {
        if !config.approval.enabled {
            return Err(ArrtError::Approval("approval service is disabled".into()));
        }
        if config.approval.storage.kind != "sqlite" {
            return Err(ArrtError::Approval(format!(
                "unsupported approval storage type: {}",
                config.approval.storage.kind
            )));
        }
        let path = match &config.approval.storage.path {
            Some(path) => expand_home(path)?,
            None => project_dirs()?.data_local_dir().join("approvals.db"),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let service = Self {
            path,
            ttl_seconds: config.approval.ttl_seconds,
        };
        service.connection()?;
        Ok(service)
    }

    fn connection(&self) -> Result<Connection, ArrtError> {
        let conn = Connection::open(&self.path).map_err(db_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db_error)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS approvals (
              id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              profile TEXT NOT NULL, operation TEXT NOT NULL, request_payload TEXT NOT NULL,
              request_hash TEXT NOT NULL, rule_id TEXT, reason TEXT, risk TEXT,
              caller TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL,
              result_payload TEXT
            );
            CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals(status, expires_at);",
        )
        .map_err(db_error)?;
        Ok(conn)
    }

    pub fn create(
        &self,
        request: &Request,
        caller: CallerType,
        rule_id: Option<&str>,
        reason: Option<&str>,
        risk: Option<RiskLevelConfig>,
        redactor: &SecretRedactor,
    ) -> Result<Value, ArrtError> {
        let payload =
            serde_json::to_string(request).map_err(|e| ArrtError::Approval(e.to_string()))?;
        let request_hash = request_hash(request)?;
        let now = now_seconds();
        let expires = now.saturating_add(self.ttl_seconds);
        let id = format!("apr_{}", uuid::Uuid::new_v4().simple());
        let profile = request_profile(request)
            .ok_or_else(|| ArrtError::Approval("operation has no profile".into()))?;
        let operation = request_name(request);
        let summary = redactor.redact(&safe_summary(request));
        let risk = risk.map(risk_name);
        self.connection()?.execute("INSERT INTO approvals (id,created_at,expires_at,profile,operation,request_payload,request_hash,rule_id,reason,risk,caller,status,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![id, now, expires, profile, operation, payload, request_hash, rule_id, reason, risk, caller_name(caller), "pending", summary]).map_err(db_error)?;
        Ok(
            json!({"id":id,"profile":profile,"operation":operation,"summary":summary,"risk":risk,"expires_at":expires}),
        )
    }

    pub fn list(&self) -> Result<Value, ArrtError> {
        self.expire()?;
        let conn = self.connection()?;
        let mut stmt = conn.prepare("SELECT id,profile,operation,risk,status,created_at,expires_at,summary FROM approvals ORDER BY created_at DESC").map_err(db_error)?;
        let rows = stmt.query_map([], |r| Ok(json!({"id":r.get::<_,String>(0)?,"profile":r.get::<_,String>(1)?,"operation":r.get::<_,String>(2)?,"risk":r.get::<_,Option<String>>(3)?,"status":r.get::<_,String>(4)?,"created_at":r.get::<_,u64>(5)?,"expires_at":r.get::<_,u64>(6)?,"summary":r.get::<_,String>(7)?}))).map_err(db_error)?;
        Ok(Value::Array(
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?,
        ))
    }

    pub fn show(&self, id: &str) -> Result<Value, ArrtError> {
        self.expire()?;
        self.connection()?.query_row("SELECT id,profile,operation,risk,status,created_at,expires_at,summary,rule_id,reason,caller FROM approvals WHERE id=?", [id], |r| Ok(json!({"id":r.get::<_,String>(0)?,"profile":r.get::<_,String>(1)?,"operation":r.get::<_,String>(2)?,"risk":r.get::<_,Option<String>>(3)?,"status":r.get::<_,String>(4)?,"created_at":r.get::<_,u64>(5)?,"expires_at":r.get::<_,u64>(6)?,"summary":r.get::<_,String>(7)?,"rule_id":r.get::<_,Option<String>>(8)?,"reason":r.get::<_,Option<String>>(9)?,"caller":r.get::<_,String>(10)?}))).optional().map_err(db_error)?.ok_or_else(|| ArrtError::Approval(format!("approval not found: {id}")))
    }

    pub fn claim(&self, id: &str) -> Result<ApprovalClaim, ArrtError> {
        self.expire()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(db_error)?;
        let row = tx.query_row("SELECT request_payload,request_hash,caller FROM approvals WHERE id=? AND status='pending' AND expires_at>?", params![id, now_seconds()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional().map_err(db_error)?;
        let Some((payload, stored_hash, caller)) = row else {
            return Err(ArrtError::Approval("already_processed or expired".into()));
        };
        let request: Request =
            serde_json::from_str(&payload).map_err(|e| ArrtError::Approval(e.to_string()))?;
        if request_hash(&request)? != stored_hash {
            return Err(ArrtError::Approval("request hash mismatch".into()));
        }
        let changed = tx
            .execute(
                "UPDATE approvals SET status='executing' WHERE id=? AND status='pending'",
                [id],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(ArrtError::Approval("already_processed".into()));
        }
        tx.commit().map_err(db_error)?;
        Ok(ApprovalClaim {
            id: id.into(),
            request,
            caller: parse_caller(&caller)?,
            request_hash: stored_hash,
        })
    }

    pub fn reject(&self, id: &str) -> Result<Value, ArrtError> {
        self.expire()?;
        let changed = self.connection()?.execute("UPDATE approvals SET status='rejected' WHERE id=? AND status='pending' AND expires_at>?", params![id,now_seconds()]).map_err(db_error)?;
        if changed != 1 {
            return Err(ArrtError::Approval("already_processed or expired".into()));
        }
        Ok(json!({"status":"rejected","approval_id":id}))
    }

    pub fn finish(&self, id: &str, result: &CommandResult) -> Result<(), ArrtError> {
        let status = if result.ok { "executed" } else { "failed" };
        let payload =
            serde_json::to_string(result).map_err(|e| ArrtError::Approval(e.to_string()))?;
        self.connection()?
            .execute(
                "UPDATE approvals SET status=?,result_payload=? WHERE id=? AND status='executing'",
                params![status, payload, id],
            )
            .map_err(db_error)?;
        Ok(())
    }

    pub fn cleanup(&self) -> Result<Value, ArrtError> {
        self.expire()?;
        let removed = self
            .connection()?
            .execute(
                "DELETE FROM approvals WHERE status IN ('expired','rejected','executed','failed')",
                [],
            )
            .map_err(db_error)?;
        Ok(json!({"removed":removed}))
    }

    fn expire(&self) -> Result<(), ArrtError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().map_err(db_error)?;
        let now = now_seconds();
        let expired = {
            let mut stmt = tx.prepare("SELECT id,profile,operation,rule_id,risk,caller FROM approvals WHERE status='pending' AND expires_at<=?").map_err(db_error)?;
            let rows=stmt.query_map([now], |r| Ok(json!({"approval_id":r.get::<_,String>(0)?,"profile":r.get::<_,String>(1)?,"operation":r.get::<_,String>(2)?,"rule":r.get::<_,Option<String>>(3)?,"risk":r.get::<_,Option<String>>(4)?,"caller":r.get::<_,String>(5)?}))).map_err(db_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
        };
        tx.execute(
            "UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at<=?",
            [now],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        for metadata in expired {
            eprintln!(
                "{}",
                json!({"event":"approval_expired","timestamp_ms":now.saturating_mul(1000),"metadata":metadata})
            );
        }
        Ok(())
    }
}

pub fn request_hash(request: &Request) -> Result<String, ArrtError> {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(request).map_err(|e| ArrtError::Approval(e.to_string()))?);
    if let Request::Upload { src, .. } = request {
        hasher.update(std::fs::read(src).map_err(ArrtError::from)?);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn safe_summary(request: &Request) -> String {
    match request {
        Request::Exec { command, .. } => redact_inline_secrets(command),
        Request::Read { path, .. } => format!("read {path}"),
        Request::Write { path, .. } => format!("write {path}"),
        Request::Upload { dst, .. } => format!("upload to {dst}"),
        Request::Download { src, .. } => format!("download {src}"),
        _ => request_name(request).to_string(),
    }
}

fn redact_inline_secrets(command: &str) -> String {
    command
        .split_whitespace()
        .map(|part| {
            let upper = part.to_ascii_uppercase();
            if upper.starts_with("TOKEN=")
                || upper.starts_with("PASSWORD=")
                || upper.starts_with("SECRET=")
            {
                part.split_once('=')
                    .map_or("[REDACTED]".into(), |(k, _)| format!("{k}=[REDACTED]"))
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn expand_home(path: &str) -> Result<PathBuf, ArrtError> {
    if path == "~" || path.starts_with("~/") || path.starts_with("~\\") {
        let base = directories::BaseDirs::new()
            .ok_or_else(|| ArrtError::Approval("home directory unavailable".into()))?;
        return Ok(base
            .home_dir()
            .join(path.trim_start_matches('~').trim_start_matches(['/', '\\'])));
    }
    Ok(PathBuf::from(path))
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn db_error(e: rusqlite::Error) -> ArrtError {
    ArrtError::Approval(format!("approval database: {e}"))
}
fn risk_name(r: RiskLevelConfig) -> &'static str {
    match r {
        RiskLevelConfig::Low => "low",
        RiskLevelConfig::Medium => "medium",
        RiskLevelConfig::High => "high",
        RiskLevelConfig::Critical => "critical",
    }
}
fn caller_name(c: CallerType) -> &'static str {
    match c {
        CallerType::HumanCli => "human_cli",
        CallerType::AgentCli => "agent_cli",
        CallerType::Mcp => "mcp",
    }
}
fn parse_caller(s: &str) -> Result<CallerType, ArrtError> {
    match s {
        "human_cli" => Ok(CallerType::HumanCli),
        "agent_cli" => Ok(CallerType::AgentCli),
        "mcp" => Ok(CallerType::Mcp),
        _ => Err(ArrtError::Approval("invalid stored caller".into())),
    }
}
fn request_profile(r: &Request) -> Option<&str> {
    match r {
        Request::Exec { profile, .. }
        | Request::Read { profile, .. }
        | Request::Write { profile, .. }
        | Request::Upload { profile, .. }
        | Request::Download { profile, .. }
        | Request::TunnelOpen { profile, .. } => Some(profile),
        _ => None,
    }
}
fn request_name(r: &Request) -> &'static str {
    match r {
        Request::Exec { .. } => "exec",
        Request::Read { .. } => "read",
        Request::Write { .. } => "write",
        Request::Upload { .. } => "upload",
        Request::Download { .. } => "download",
        Request::TunnelOpen { .. } => "tunnel",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApprovalConfig, ApprovalStorageConfig};
    use crate::protocol::EnvVar;
    use std::sync::{Arc, Barrier};

    fn service(ttl: u64) -> (ApprovalService, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("ssh-gateway-approval-{}.db", uuid::Uuid::new_v4()));
        let config: AppConfig = serde_yaml::from_str("profiles: []").unwrap();
        let mut config = config;
        config.approval = ApprovalConfig {
            enabled: true,
            ttl_seconds: ttl,
            storage: ApprovalStorageConfig {
                kind: "sqlite".into(),
                path: Some(path.display().to_string()),
            },
        };
        (ApprovalService::from_config(&config).unwrap(), path)
    }
    fn request() -> Request {
        Request::Exec {
            profile: "test".into(),
            command: "systemctl restart nginx".into(),
            cwd: None,
            timeout_seconds: Some(30),
            env: Vec::<EnvVar>::new(),
        }
    }

    #[test]
    fn redacts_summary_assignment_secrets() {
        assert_eq!(
            redact_inline_secrets("env TOKEN=abc run"),
            "env TOKEN=[REDACTED] run"
        );
    }

    #[test]
    fn persists_lists_shows_and_rejects_without_payload_disclosure() {
        let (svc, path) = service(300);
        let created = svc
            .create(
                &request(),
                CallerType::Mcp,
                Some("restart"),
                None,
                Some(RiskLevelConfig::Medium),
                &SecretRedactor::default(),
            )
            .unwrap();
        let id = created["id"].as_str().unwrap();
        let reopened = ApprovalService {
            path: path.clone(),
            ttl_seconds: 300,
        };
        assert_eq!(reopened.list().unwrap().as_array().unwrap().len(), 1);
        let shown = reopened.show(id).unwrap();
        assert!(shown.get("request_payload").is_none());
        assert_eq!(reopened.reject(id).unwrap()["status"], "rejected");
        assert!(reopened.claim(id).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn claim_is_single_use_under_concurrency() {
        let (svc, path) = service(300);
        let id = svc
            .create(
                &request(),
                CallerType::Mcp,
                None,
                None,
                None,
                &SecretRedactor::default(),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let svc = Arc::new(svc);
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let svc = svc.clone();
                let barrier = barrier.clone();
                let id = id.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    svc.claim(&id).is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|claimed| *claimed)
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn expiry_and_payload_tampering_fail_closed() {
        let (svc, path) = service(300);
        let id = svc
            .create(
                &request(),
                CallerType::Mcp,
                None,
                None,
                None,
                &SecretRedactor::default(),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        svc.connection()
            .unwrap()
            .execute("UPDATE approvals SET expires_at=0 WHERE id=?", [&id])
            .unwrap();
        assert!(svc.claim(&id).is_err());
        let id2 = svc
            .create(
                &request(),
                CallerType::Mcp,
                None,
                None,
                None,
                &SecretRedactor::default(),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        svc.connection()
            .unwrap()
            .execute(
                "UPDATE approvals SET request_payload='{}' WHERE id=?",
                [&id2],
            )
            .unwrap();
        assert!(svc.claim(&id2).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upload_content_change_invalidates_hash() {
        let (svc, path) = service(300);
        let src = path.with_extension("upload");
        std::fs::write(&src, b"one").unwrap();
        let req = Request::Upload {
            profile: "test".into(),
            src: src.display().to_string(),
            dst: "/tmp/x".into(),
        };
        let id = svc
            .create(
                &req,
                CallerType::Mcp,
                None,
                None,
                None,
                &SecretRedactor::default(),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        std::fs::write(&src, b"two").unwrap();
        assert!(svc.claim(&id).is_err());
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(path);
    }
}
