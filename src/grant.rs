use crate::approval::{request_hash, DB_SCHEMA_LOCK};
use crate::config::{project_dirs, AppConfig, GrantConfig, GrantRiskConfig};
use crate::errors::ArrtError;
use crate::protocol::Request;
use crate::redaction::SecretRedactor;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
const PLAN_CLAIM_LEASE_SECONDS: u64 = 300;
const PLAN_CLAIM_MAX_LEASE_SECONDS: u64 = 3660;

pub struct GrantService {
    path: PathBuf,
    config: GrantConfig,
    namespace: Option<String>,
}
#[derive(Debug)]
pub struct PlanAuthorization {
    pub plan_id: String,
    pub action_index: u64,
}

impl GrantService {
    pub fn from_config(config: &AppConfig) -> Result<Self, ArrtError> {
        if !config.approval.enabled {
            return Err(ArrtError::Approval("approval service is disabled".into()));
        }
        let path = match &config.approval.storage.path {
            Some(p) => expand_home(p)?,
            None => project_dirs()?.data_local_dir().join("approvals.db"),
        };
        let service = Self {
            path,
            config: config.approval.grants.clone(),
            namespace: config.authorization_namespace.clone(),
        };
        let _guard = DB_SCHEMA_LOCK
            .lock()
            .map_err(|_| ArrtError::Approval("database migration lock poisoned".into()))?;
        service.migrate()?;
        Ok(service)
    }
    fn connection(&self) -> Result<Connection, ArrtError> {
        let conn = Connection::open(&self.path).map_err(db_error)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db_error)?;
        Ok(conn)
    }
    fn migrate(&self) -> Result<(), ArrtError> {
        let conn = self.connection()?;
        conn.execute_batch("PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS approvals(
            id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
            profile TEXT NOT NULL,operation TEXT NOT NULL,request_payload TEXT NOT NULL,
            request_hash TEXT NOT NULL,rule_id TEXT,reason TEXT,risk TEXT,caller TEXT NOT NULL,
            status TEXT NOT NULL,summary TEXT NOT NULL,result_payload TEXT);
          CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
          INSERT INTO schema_version(version) SELECT 3 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
          CREATE TABLE IF NOT EXISTS approval_grants(
            id TEXT PRIMARY KEY, profile TEXT NOT NULL, rule_id TEXT NOT NULL, task_id TEXT, plan_id TEXT,
            scope_json TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            max_uses INTEGER, used_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
            created_from_approval_id TEXT NOT NULL, created_by TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS grants_match_idx ON approval_grants(profile,rule_id,task_id,status,expires_at);
          CREATE UNIQUE INDEX IF NOT EXISTS grants_source_idx ON approval_grants(created_from_approval_id);
          CREATE TABLE IF NOT EXISTS execution_plans(
            id TEXT PRIMARY KEY, profile TEXT NOT NULL, task_id TEXT NOT NULL, actions_json TEXT NOT NULL,
            plan_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            status TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0, claimed_index INTEGER, claim_expires_at INTEGER);
          CREATE INDEX IF NOT EXISTS plans_match_idx ON execution_plans(profile,task_id,status,expires_at);
          UPDATE schema_version SET version=3 WHERE version<3;").map_err(db_error)?;
        if !has_column(&conn, "approvals", "task_id")? {
            conn.execute("ALTER TABLE approvals ADD COLUMN task_id TEXT", [])
                .map_err(db_error)?;
        }
        if !has_column(&conn, "execution_plans", "claim_expires_at")? {
            conn.execute(
                "ALTER TABLE execution_plans ADD COLUMN claim_expires_at INTEGER",
                [],
            )
            .map_err(db_error)?;
        }
        for table in ["approvals", "approval_grants", "execution_plans"] {
            if !has_column(&conn, table, "authorization_namespace")? {
                conn.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN authorization_namespace TEXT"),
                    [],
                )
                .map_err(db_error)?;
            }
        }
        conn.execute("UPDATE execution_plans SET claim_expires_at=? WHERE status='executing' AND claimed_index IS NOT NULL AND claim_expires_at IS NULL",[now_seconds()]).map_err(db_error)?;
        Ok(())
    }

    #[cfg(test)]
    pub fn create_from_approval(
        &self,
        approval_id: &str,
        ttl: u64,
        task_id: Option<&str>,
        max_uses: Option<u64>,
    ) -> Result<Value, ArrtError> {
        self.create_from_status(approval_id, ttl, task_id, max_uses, "pending", None)
    }

    pub fn validate_pending_grant(
        &self,
        approval_id: &str,
        ttl: u64,
        task_id: Option<&str>,
        max_uses: Option<u64>,
    ) -> Result<(), ArrtError> {
        self.validate_grant_source(approval_id, ttl, task_id, max_uses, "pending", None)
            .map(|_| ())
    }

    pub fn create_from_claimed_approval(
        &self,
        approval_id: &str,
        ttl: u64,
        task_id: Option<&str>,
        max_uses: Option<u64>,
        rule_id: &str,
    ) -> Result<Value, ArrtError> {
        self.create_from_status(
            approval_id,
            ttl,
            task_id,
            max_uses,
            "executing",
            Some(rule_id),
        )
    }

    fn create_from_status(
        &self,
        approval_id: &str,
        ttl: u64,
        task_id: Option<&str>,
        max_uses: Option<u64>,
        required_status: &str,
        expected_rule: Option<&str>,
    ) -> Result<Value, ArrtError> {
        let (profile, rule_id, max_uses) = self.validate_grant_source(
            approval_id,
            ttl,
            task_id,
            max_uses,
            required_status,
            expected_rule,
        )?;
        let conn = self.connection()?;
        let now = now_seconds();
        let id = format!("grt_{}", uuid::Uuid::new_v4().simple());
        let expires = now + ttl;
        let scope = json!({"type":if task_id.is_some(){"task_rule"}else{"time_rule"},"profile":profile,"rule_id":rule_id});
        let namespace: Option<String> = conn
            .query_row(
                "SELECT authorization_namespace FROM approvals WHERE id=?",
                [approval_id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        conn.execute("INSERT INTO approval_grants(id,profile,rule_id,task_id,scope_json,created_at,expires_at,max_uses,status,created_from_approval_id,created_by,authorization_namespace) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",params![id,profile,rule_id,task_id,scope.to_string(),now,expires,max_uses,"active",approval_id,"human_cli",namespace]).map_err(db_error)?;
        Ok(
            json!({"id":id,"profile":profile,"rule_id":rule_id,"task_id":task_id,"scope":scope,"created_at":now,"expires_at":expires,"max_uses":max_uses,"used_count":0,"status":"active","created_from_approval_id":approval_id,"created_by":"human_cli"}),
        )
    }

    fn validate_grant_source(
        &self,
        approval_id: &str,
        ttl: u64,
        task_id: Option<&str>,
        max_uses: Option<u64>,
        required_status: &str,
        expected_rule: Option<&str>,
    ) -> Result<(String, String, u64), ArrtError> {
        if ttl == 0 || ttl > self.config.max_ttl_seconds {
            return Err(ArrtError::Approval(format!(
                "grant TTL must be between 1 and {} seconds",
                self.config.max_ttl_seconds
            )));
        }
        let conn = self.connection()?;
        let row = conn
            .query_row(
                "SELECT profile,rule_id,risk,status FROM approvals WHERE id=?",
                [approval_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| ArrtError::Approval("approval not found".into()))?;
        if row.3 != required_status {
            return Err(ArrtError::Approval(format!(
                "grant requires an approval in {required_status} state"
            )));
        }
        let rule_id = row
            .1
            .ok_or_else(|| ArrtError::Approval("approval has no matched rule".into()))?;
        if expected_rule.is_some_and(|expected| expected != rule_id) {
            return Err(ArrtError::Approval(
                "approval rule no longer matches the policy decision".into(),
            ));
        }
        let permissions = self.risk_permissions(row.2.as_deref());
        if task_id.is_some() && !permissions.task {
            return Err(ArrtError::Approval(
                "risk policy does not permit task grants".into(),
            ));
        }
        if task_id.is_none() && !permissions.time {
            return Err(ArrtError::Approval(
                "risk policy does not permit time grants".into(),
            ));
        }
        let max_uses = max_uses.unwrap_or(self.config.default_max_uses);
        if max_uses == 0 {
            return Err(ArrtError::Approval(
                "max uses must be greater than zero".into(),
            ));
        }
        Ok((row.0, rule_id, max_uses))
    }

    pub fn consume(
        &self,
        profile: &str,
        rule_id: &str,
        task_id: Option<&str>,
    ) -> Result<Option<String>, ArrtError> {
        self.expire_grants()?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let ids = {
            let mut stmt=tx.prepare("SELECT id FROM approval_grants WHERE profile=? AND rule_id=? AND authorization_namespace IS ? AND status='active' AND expires_at>? AND (task_id IS NULL OR task_id=?) AND (max_uses IS NULL OR used_count<max_uses) ORDER BY CASE WHEN task_id IS NULL THEN 1 ELSE 0 END,created_at DESC").map_err(db_error)?;
            let rows = stmt
                .query_map(
                    params![
                        profile,
                        rule_id,
                        self.namespace.as_deref(),
                        now_seconds(),
                        task_id
                    ],
                    |r| r.get::<_, String>(0),
                )
                .map_err(db_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
        };
        for id in ids {
            let changed=tx.execute("UPDATE approval_grants SET used_count=used_count+1,status=CASE WHEN max_uses IS NOT NULL AND used_count+1>=max_uses THEN 'exhausted' ELSE status END WHERE id=? AND status='active' AND expires_at>? AND (max_uses IS NULL OR used_count<max_uses)",params![id,now_seconds()]).map_err(db_error)?;
            if changed == 1 {
                tx.commit().map_err(db_error)?;
                return Ok(Some(id));
            }
        }
        tx.commit().map_err(db_error)?;
        Ok(None)
    }

    pub fn list(&self) -> Result<Value, ArrtError> {
        self.expire_grants()?;
        query_many(&self.connection()?,"SELECT id,profile,rule_id,task_id,created_at,expires_at,max_uses,used_count,status,created_from_approval_id,created_by FROM approval_grants ORDER BY created_at DESC",[])
    }
    pub fn show(&self, id: &str) -> Result<Value, ArrtError> {
        self.expire_grants()?;
        query_one(&self.connection()?, id)
    }
    pub fn revoke(&self, id: &str) -> Result<Value, ArrtError> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE approval_grants SET status='revoked' WHERE id=? AND status='active'",
                [id],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(ArrtError::Approval("grant is not active".into()));
        }
        Ok(json!({"status":"revoked","grant_id":id}))
    }
    pub fn cleanup_grants(&self) -> Result<Value, ArrtError> {
        self.expire_grants()?;
        let n = self
            .connection()?
            .execute(
                "DELETE FROM approval_grants WHERE status IN('revoked','expired','exhausted')",
                [],
            )
            .map_err(db_error)?;
        Ok(json!({"removed":n}))
    }

    pub fn propose_plan(
        &self,
        profile: &str,
        task_id: &str,
        actions: &[Request],
        ttl: u64,
        redactor: &SecretRedactor,
    ) -> Result<Value, ArrtError> {
        if task_id.trim().is_empty() || actions.is_empty() {
            return Err(ArrtError::Approval(
                "plan requires task_id and at least one action".into(),
            ));
        }
        if actions.iter().any(|a| request_profile(a) != Some(profile)) {
            return Err(ArrtError::Approval(
                "all plan actions must use the plan profile".into(),
            ));
        }
        let payload = serde_json::to_string(actions).map_err(json_error)?;
        let hash = plan_hash(actions)?;
        let now = now_seconds();
        let expires = now + ttl.min(self.config.max_ttl_seconds);
        let id = format!("pln_{}", uuid::Uuid::new_v4().simple());
        self.connection()?.execute("INSERT INTO execution_plans(id,profile,task_id,actions_json,plan_hash,created_at,expires_at,status,authorization_namespace) VALUES(?,?,?,?,?,?,?,'pending',?)",params![id,profile,task_id,payload,hash,now,expires,self.namespace.as_deref()]).map_err(db_error)?;
        Ok(
            json!({"id":id,"profile":profile,"task_id":task_id,"action_count":actions.len(),"actions":plan_summaries(actions,redactor)?,"hash":hash,"status":"pending","created_at":now,"expires_at":expires}),
        )
    }
    pub fn list_plans(&self) -> Result<Value, ArrtError> {
        self.expire_plans()?;
        let conn = self.connection()?;
        let mut stmt=conn.prepare("SELECT id,profile,task_id,status,created_at,expires_at,next_index,json_array_length(actions_json),plan_hash FROM execution_plans ORDER BY created_at DESC").map_err(db_error)?;
        let rows=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"profile":r.get::<_,String>(1)?,"task_id":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"created_at":r.get::<_,u64>(4)?,"expires_at":r.get::<_,u64>(5)?,"next_index":r.get::<_,u64>(6)?,"action_count":r.get::<_,u64>(7)?,"hash":r.get::<_,String>(8)?}))).map_err(db_error)?;
        Ok(Value::Array(
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?,
        ))
    }
    pub fn show_plan(&self, id: &str, redactor: &SecretRedactor) -> Result<Value, ArrtError> {
        self.expire_plans()?;
        let row=self.connection()?.query_row("SELECT profile,task_id,actions_json,plan_hash,status,created_at,expires_at,next_index FROM execution_plans WHERE id=?",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,u64>(5)?,r.get::<_,u64>(6)?,r.get::<_,u64>(7)?))).optional().map_err(db_error)?.ok_or_else(||ArrtError::Approval("plan not found".into()))?;
        let actions: Vec<Request> = serde_json::from_str(&row.2).map_err(json_error)?;
        Ok(
            json!({"id":id,"profile":row.0,"task_id":row.1,"actions":plan_summaries(&actions,redactor)?,"hash":row.3,"status":row.4,"created_at":row.5,"expires_at":row.6,"next_index":row.7}),
        )
    }
    pub fn approve_plan(&self, id: &str) -> Result<Value, ArrtError> {
        self.expire_plans()?;
        let n=self.connection()?.execute("UPDATE execution_plans SET status='approved' WHERE id=? AND status='pending' AND expires_at>?",params![id,now_seconds()]).map_err(db_error)?;
        if n != 1 {
            return Err(ArrtError::Approval("plan is not pending".into()));
        }
        Ok(json!({"status":"approved","plan_id":id}))
    }
    pub fn reject_plan(&self, id: &str) -> Result<Value, ArrtError> {
        let n = self
            .connection()?
            .execute(
                "UPDATE execution_plans SET status='rejected' WHERE id=? AND status='pending'",
                [id],
            )
            .map_err(db_error)?;
        if n != 1 {
            return Err(ArrtError::Approval("plan is not pending".into()));
        }
        Ok(json!({"status":"rejected","plan_id":id}))
    }

    pub fn claim_plan_action(
        &self,
        profile: &str,
        task_id: Option<&str>,
        request: &Request,
    ) -> Result<Option<PlanAuthorization>, ArrtError> {
        let Some(task_id) = task_id else {
            return Ok(None);
        };
        self.expire_plans()?;
        let mut conn = self.connection()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let row=tx.query_row("SELECT id,actions_json,next_index,claimed_index,plan_hash FROM execution_plans WHERE profile=? AND task_id=? AND authorization_namespace IS ? AND status IN('approved','executing') AND expires_at>? ORDER BY created_at DESC LIMIT 1",params![profile,task_id,self.namespace.as_deref(),now_seconds()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u64>(2)?,r.get::<_,Option<u64>>(3)?,r.get::<_,String>(4)?))).optional().map_err(db_error)?;
        let Some((id, payload, index, claimed, stored_hash)) = row else {
            return Ok(None);
        };
        if claimed.is_some() {
            return Err(ArrtError::Approval(
                "plan action is already executing".into(),
            ));
        }
        let actions: Vec<Request> = serde_json::from_str(&payload).map_err(json_error)?;
        if plan_hash(&actions)? != stored_hash {
            return Err(ArrtError::Approval(
                "approved plan content hash mismatch".into(),
            ));
        }
        let expected = actions
            .get(index as usize)
            .ok_or_else(|| ArrtError::Approval("plan has no next action".into()))?;
        if request_hash(expected)? != request_hash(request)? {
            return Err(ArrtError::PolicyDenied(
                "request does not match the next approved plan action".into(),
            ));
        }
        let claim_expires_at = now_seconds().saturating_add(plan_claim_lease_seconds(request));
        let n=tx.execute("UPDATE execution_plans SET status='executing',claimed_index=?,claim_expires_at=? WHERE id=? AND claimed_index IS NULL AND next_index=?",params![index,claim_expires_at,id,index]).map_err(db_error)?;
        if n != 1 {
            return Err(ArrtError::Approval("plan action already claimed".into()));
        }
        tx.commit().map_err(db_error)?;
        Ok(Some(PlanAuthorization {
            plan_id: id,
            action_index: index,
        }))
    }
    pub fn finish_plan_action(
        &self,
        auth: &PlanAuthorization,
        success: bool,
    ) -> Result<Value, ArrtError> {
        let conn = self.connection()?;
        if success {
            let count: usize = conn
                .query_row(
                    "SELECT json_array_length(actions_json) FROM execution_plans WHERE id=?",
                    [&auth.plan_id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            let status = if auth.action_index as usize + 1 >= count {
                "completed"
            } else {
                "approved"
            };
            let changed=conn.execute("UPDATE execution_plans SET next_index=next_index+1,claimed_index=NULL,claim_expires_at=NULL,status=? WHERE id=? AND status='executing' AND claimed_index=?",params![status,auth.plan_id,auth.action_index]).map_err(db_error)?;
            if changed != 1 {
                return Err(ArrtError::Approval(
                    "plan action lease is no longer active".into(),
                ));
            }
            Ok(json!({"plan_id":auth.plan_id,"action_index":auth.action_index,"status":status}))
        } else {
            let changed=conn.execute("UPDATE execution_plans SET status='failed',claimed_index=NULL,claim_expires_at=NULL WHERE id=? AND status='executing' AND claimed_index=?",params![auth.plan_id,auth.action_index]).map_err(db_error)?;
            if changed != 1 {
                return Err(ArrtError::Approval(
                    "plan action lease is no longer active".into(),
                ));
            }
            Ok(json!({"plan_id":auth.plan_id,"action_index":auth.action_index,"status":"failed"}))
        }
    }

    fn risk_permissions(&self, risk: Option<&str>) -> &GrantRiskConfig {
        match risk {
            Some("high") => &self.config.high,
            Some("critical") => &self.config.critical,
            Some("medium") => &self.config.medium,
            _ => &self.config.low,
        }
    }
    fn expire_grants(&self) -> Result<(), ArrtError> {
        let conn = self.connection()?;
        let now = now_seconds();
        let ids = {
            let mut stmt = conn
                .prepare("SELECT id FROM approval_grants WHERE status='active' AND expires_at<=?")
                .map_err(db_error)?;
            let rows = stmt
                .query_map([now], |r| r.get::<_, String>(0))
                .map_err(db_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
        };
        conn.execute(
            "UPDATE approval_grants SET status='expired' WHERE status='active' AND expires_at<=?",
            [now],
        )
        .map_err(db_error)?;
        for id in ids {
            audit_event("grant_expired", &id);
        }
        Ok(())
    }
    fn expire_plans(&self) -> Result<(), ArrtError> {
        let conn = self.connection()?;
        let now = now_seconds();
        conn.execute("UPDATE execution_plans SET status='failed',claimed_index=NULL,claim_expires_at=NULL WHERE status='executing' AND claim_expires_at IS NOT NULL AND claim_expires_at<=?",[now]).map_err(db_error)?;
        let ids = {
            let mut stmt=conn.prepare("SELECT id FROM execution_plans WHERE status IN('pending','approved') AND expires_at<=?").map_err(db_error)?;
            let rows = stmt
                .query_map([now], |r| r.get::<_, String>(0))
                .map_err(db_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
        };
        conn.execute("UPDATE execution_plans SET status='expired' WHERE status IN('pending','approved') AND expires_at<=?",[now]).map_err(db_error)?;
        for id in ids {
            audit_event("plan_expired", &id);
        }
        Ok(())
    }
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, ArrtError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(db_error)?;
    let names = rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(names.into_iter().any(|name| name == column))
}
fn query_many<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<Value, ArrtError> {
    let mut stmt = conn.prepare(sql).map_err(db_error)?;
    let rows = stmt.query_map(params, grant_row).map_err(db_error)?;
    Ok(Value::Array(
        rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?,
    ))
}
fn query_one(conn: &Connection, id: &str) -> Result<Value, ArrtError> {
    conn.query_row("SELECT id,profile,rule_id,task_id,created_at,expires_at,max_uses,used_count,status,created_from_approval_id,created_by FROM approval_grants WHERE id=?",[id],grant_row).optional().map_err(db_error)?.ok_or_else(||ArrtError::Approval("grant not found".into()))
}
fn grant_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(
        json!({"id":r.get::<_,String>(0)?,"profile":r.get::<_,String>(1)?,"rule_id":r.get::<_,String>(2)?,"task_id":r.get::<_,Option<String>>(3)?,"created_at":r.get::<_,u64>(4)?,"expires_at":r.get::<_,u64>(5)?,"max_uses":r.get::<_,Option<u64>>(6)?,"used_count":r.get::<_,u64>(7)?,"status":r.get::<_,String>(8)?,"created_from_approval_id":r.get::<_,String>(9)?,"created_by":r.get::<_,String>(10)?}),
    )
}
fn plan_summaries(actions: &[Request], redactor: &SecretRedactor) -> Result<Vec<Value>, ArrtError> {
    actions.iter().enumerate().map(|(i,a)|Ok(json!({"index":i,"operation":request_name(a),"summary":redactor.redact(&redact_assignments(&summary(a))),"request_hash":request_hash(a)?}))).collect()
}
fn redact_assignments(value: &str) -> String {
    value
        .split_whitespace()
        .map(|part| {
            let upper = part.to_ascii_uppercase();
            if ["TOKEN=", "PASSWORD=", "SECRET="]
                .iter()
                .any(|key| upper.starts_with(key))
            {
                part.split_once('=')
                    .map_or("[REDACTED]".into(), |(key, _)| format!("{key}=[REDACTED]"))
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn summary(r: &Request) -> String {
    match r {
        Request::Exec { command, .. } => command.clone(),
        Request::Read { path, .. } => format!("read {path}"),
        Request::Write { path, .. } => format!("write {path}"),
        Request::Upload { dst, .. } => format!("upload to {dst}"),
        Request::Download { src, .. } => format!("download {src}"),
        _ => request_name(r).into(),
    }
}
fn request_profile(r: &Request) -> Option<&str> {
    match r {
        Request::Exec { profile, .. }
        | Request::Read { profile, .. }
        | Request::Write { profile, .. }
        | Request::Upload { profile, .. }
        | Request::Download { profile, .. } => Some(profile),
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
        _ => "unsupported",
    }
}
fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn plan_hash(actions: &[Request]) -> Result<String, ArrtError> {
    let hashes = actions
        .iter()
        .map(request_hash)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(hash_bytes(
        serde_json::to_string(&hashes)
            .map_err(json_error)?
            .as_bytes(),
    ))
}
fn plan_claim_lease_seconds(request: &Request) -> u64 {
    match request {
        Request::Exec {
            timeout_seconds, ..
        } => timeout_seconds
            .unwrap_or(PLAN_CLAIM_LEASE_SECONDS)
            .saturating_add(60)
            .clamp(PLAN_CLAIM_LEASE_SECONDS, PLAN_CLAIM_MAX_LEASE_SECONDS),
        _ => PLAN_CLAIM_LEASE_SECONDS,
    }
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn audit_event(event: &str, id: &str) {
    eprintln!(
        "{}",
        json!({"event":event,"id":id,"timestamp_ms":now_seconds().saturating_mul(1000)})
    );
}
fn db_error(e: rusqlite::Error) -> ArrtError {
    ArrtError::Approval(format!("authorization database: {e}"))
}
fn json_error(e: serde_json::Error) -> ArrtError {
    ArrtError::Approval(e.to_string())
}
fn expand_home(path: &str) -> Result<PathBuf, ArrtError> {
    if path == "~" || path.starts_with("~/") || path.starts_with("~\\") {
        let base = directories::BaseDirs::new()
            .ok_or_else(|| ArrtError::Approval("home directory unavailable".into()))?;
        Ok(base
            .home_dir()
            .join(path.trim_start_matches('~').trim_start_matches(['/', '\\'])))
    } else {
        Ok(PathBuf::from(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalService;
    use crate::config::{ApprovalStorageConfig, RiskLevelConfig};
    use crate::protocol::{CallerType, EnvVar};
    use std::sync::{Arc, Barrier};

    fn setup() -> (AppConfig, PathBuf) {
        let path = std::env::temp_dir().join(format!("sshmcp-grant-{}.db", uuid::Uuid::new_v4()));
        let mut config: AppConfig = serde_yaml::from_str("profiles: []").unwrap();
        config.approval.storage = ApprovalStorageConfig {
            kind: "sqlite".into(),
            path: Some(path.display().to_string()),
        };
        (config, path)
    }
    fn exec(profile: &str, command: &str) -> Request {
        Request::Exec {
            profile: profile.into(),
            command: command.into(),
            cwd: None,
            timeout_seconds: Some(30),
            env: Vec::<EnvVar>::new(),
        }
    }
    fn pending(config: &AppConfig, rule: &str, risk: RiskLevelConfig) -> String {
        ApprovalService::from_config(config)
            .unwrap()
            .create(
                &exec("a", "restart"),
                CallerType::Mcp,
                Some(rule),
                None,
                Some(risk),
                &SecretRedactor::default(),
                Some("task-a"),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .into()
    }

    #[test]
    fn grants_and_plans_are_isolated_by_authorization_namespace() {
        let (mut first, path) = setup();
        first.authorization_namespace = Some("tenant-a:user-a".into());
        let mut second = first.clone();
        second.authorization_namespace = Some("tenant-b:user-b".into());
        let approval = pending(&first, "rule-a", RiskLevelConfig::Medium);
        let first_grants = GrantService::from_config(&first).unwrap();
        first_grants
            .create_from_approval(&approval, 300, Some("task-a"), Some(2))
            .unwrap();
        let second_grants = GrantService::from_config(&second).unwrap();
        assert!(second_grants
            .consume("a", "rule-a", Some("task-a"))
            .unwrap()
            .is_none());
        assert!(first_grants
            .consume("a", "rule-a", Some("task-a"))
            .unwrap()
            .is_some());

        let plan = first_grants
            .propose_plan(
                "a",
                "task-a",
                &[exec("a", "restart")],
                300,
                &SecretRedactor::default(),
            )
            .unwrap();
        first_grants
            .approve_plan(plan["id"].as_str().unwrap())
            .unwrap();
        assert!(second_grants
            .claim_plan_action("a", Some("task-a"), &exec("a", "restart"))
            .unwrap()
            .is_none());
        assert!(first_grants
            .claim_plan_action("a", Some("task-a"), &exec("a", "restart"))
            .unwrap()
            .is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn grant_is_rule_profile_and_task_bound_and_persistent() {
        let (config, path) = setup();
        let approval = pending(&config, "rule-a", RiskLevelConfig::Medium);
        let service = GrantService::from_config(&config).unwrap();
        let grant = service
            .create_from_approval(&approval, 300, Some("task-a"), Some(2))
            .unwrap();
        assert!(service
            .consume("b", "rule-a", Some("task-a"))
            .unwrap()
            .is_none());
        assert!(service
            .consume("a", "rule-b", Some("task-a"))
            .unwrap()
            .is_none());
        assert!(service
            .consume("a", "rule-a", Some("task-b"))
            .unwrap()
            .is_none());
        assert!(GrantService::from_config(&config)
            .unwrap()
            .consume("a", "rule-a", Some("task-a"))
            .unwrap()
            .is_some());
        assert_eq!(grant["status"], "active");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn grant_max_use_is_atomic_and_exhausts() {
        let (config, path) = setup();
        let approval = pending(&config, "rule-a", RiskLevelConfig::Medium);
        let service = Arc::new(GrantService::from_config(&config).unwrap());
        let id = service
            .create_from_approval(&approval, 300, None, Some(1))
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let service = service.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    service.consume("a", "rule-a", None).unwrap().is_some()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|v| *v)
                .count(),
            1
        );
        assert_eq!(service.show(&id).unwrap()["status"], "exhausted");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn revoked_and_risk_restricted_grants_fail() {
        let (config, path) = setup();
        let approval = pending(&config, "rule-a", RiskLevelConfig::Medium);
        let service = GrantService::from_config(&config).unwrap();
        let id = service
            .create_from_approval(&approval, 300, None, Some(2))
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.revoke(&id).unwrap();
        assert!(service.consume("a", "rule-a", None).unwrap().is_none());
        let critical = pending(&config, "rule-b", RiskLevelConfig::Critical);
        assert!(service
            .create_from_approval(&critical, 300, None, None)
            .is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn expired_grant_and_plan_summary_secrets_are_safe() {
        let (config, path) = setup();
        let approval = pending(&config, "rule-a", RiskLevelConfig::Medium);
        let service = GrantService::from_config(&config).unwrap();
        let id = service
            .create_from_approval(&approval, 300, None, Some(2))
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service
            .connection()
            .unwrap()
            .execute("UPDATE approval_grants SET expires_at=0 WHERE id=?", [&id])
            .unwrap();
        assert!(service.consume("a", "rule-a", None).unwrap().is_none());
        assert_eq!(service.show(&id).unwrap()["status"], "expired");
        let plan = service
            .propose_plan(
                "a",
                "task",
                &[exec("a", "env TOKEN=secret run")],
                300,
                &SecretRedactor::default(),
            )
            .unwrap();
        let text = plan.to_string();
        assert!(!text.contains("TOKEN=secret"));
        assert!(text.contains("REDACTED"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plan_is_ordered_single_use_and_completed() {
        let (config, path) = setup();
        let service = GrantService::from_config(&config).unwrap();
        let actions = vec![exec("a", "one"), exec("a", "two")];
        let id = service
            .propose_plan("a", "task-a", &actions, 300, &SecretRedactor::default())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.approve_plan(&id).unwrap();
        assert!(service
            .claim_plan_action("a", Some("task-a"), &actions[1])
            .is_err());
        let first = service
            .claim_plan_action("a", Some("task-a"), &actions[0])
            .unwrap()
            .unwrap();
        assert!(service
            .claim_plan_action("a", Some("task-a"), &actions[0])
            .is_err());
        service.finish_plan_action(&first, true).unwrap();
        let second = service
            .claim_plan_action("a", Some("task-a"), &actions[1])
            .unwrap()
            .unwrap();
        service.finish_plan_action(&second, true).unwrap();
        assert_eq!(
            service.show_plan(&id, &SecretRedactor::default()).unwrap()["status"],
            "completed"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn modified_rejected_and_expired_plans_cannot_run() {
        let (config, path) = setup();
        let service = GrantService::from_config(&config).unwrap();
        let actions = vec![exec("a", "one")];
        let rejected = service
            .propose_plan("a", "reject", &actions, 300, &SecretRedactor::default())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.reject_plan(&rejected).unwrap();
        assert!(service
            .claim_plan_action("a", Some("reject"), &actions[0])
            .unwrap()
            .is_none());
        let modified = service
            .propose_plan("a", "modified", &actions, 300, &SecretRedactor::default())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.approve_plan(&modified).unwrap();
        service
            .connection()
            .unwrap()
            .execute(
                "UPDATE execution_plans SET actions_json=? WHERE id=?",
                params![
                    serde_json::to_string(&vec![exec("a", "evil")]).unwrap(),
                    modified
                ],
            )
            .unwrap();
        assert!(service
            .claim_plan_action("a", Some("modified"), &exec("a", "evil"))
            .is_err());
        let expired = service
            .propose_plan("a", "expired", &actions, 300, &SecretRedactor::default())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.approve_plan(&expired).unwrap();
        service
            .connection()
            .unwrap()
            .execute(
                "UPDATE execution_plans SET expires_at=0 WHERE id=?",
                [expired],
            )
            .unwrap();
        assert!(service
            .claim_plan_action("a", Some("expired"), &actions[0])
            .unwrap()
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_claim_fails_plan_after_restart_without_replay() {
        let (config, path) = setup();
        let service = GrantService::from_config(&config).unwrap();
        let action = exec("a", "once");
        let id = service
            .propose_plan(
                "a",
                "crash",
                std::slice::from_ref(&action),
                300,
                &SecretRedactor::default(),
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        service.approve_plan(&id).unwrap();
        let claimed = service
            .claim_plan_action("a", Some("crash"), &action)
            .unwrap()
            .unwrap();
        service
            .connection()
            .unwrap()
            .execute(
                "UPDATE execution_plans SET claim_expires_at=0 WHERE id=?",
                [&id],
            )
            .unwrap();
        drop(service);
        let reopened = GrantService::from_config(&config).unwrap();
        assert_eq!(
            reopened.show_plan(&id, &SecretRedactor::default()).unwrap()["status"],
            "failed"
        );
        assert!(reopened
            .claim_plan_action("a", Some("crash"), &action)
            .unwrap()
            .is_none());
        assert!(reopened.finish_plan_action(&claimed, true).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn migrates_existing_database_without_data_loss() {
        let (config, path) = setup();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE approvals(id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,profile TEXT NOT NULL,operation TEXT NOT NULL,request_payload TEXT NOT NULL,request_hash TEXT NOT NULL,rule_id TEXT,reason TEXT,risk TEXT,caller TEXT NOT NULL,status TEXT NOT NULL,summary TEXT NOT NULL,result_payload TEXT);INSERT INTO approvals VALUES('old',1,9999999999,'a','exec','{}','hash','rule',NULL,'medium','mcp','pending','safe',NULL);").unwrap();
        drop(conn);
        let service = GrantService::from_config(&config).unwrap();
        assert!(has_column(&service.connection().unwrap(), "approvals", "task_id").unwrap());
        assert_eq!(
            service
                .connection()
                .unwrap()
                .query_row("SELECT count(*) FROM approvals WHERE id='old'", [], |r| r
                    .get::<_, u64>(
                    0
                ))
                .unwrap(),
            1
        );
        let _ = std::fs::remove_file(path);
    }
}
