use crate::model::*;
use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

#[derive(Debug)]
pub struct Rejection {
    pub status: u16,
    pub message: String,
}
impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Rejection {}
pub fn reject<T>(status: u16, message: impl Into<String>) -> Result<T> {
    Err(Rejection {
        status,
        message: message.into(),
    }
    .into())
}

#[derive(Clone)]
pub struct Store(Arc<Mutex<Connection>>);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SystemAdmin,
    TenantAdmin,
    Viewer,
}
impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Self::SystemAdmin => "system_admin",
            Self::TenantAdmin => "tenant_admin",
            Self::Viewer => "viewer",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub role: Role,
}
impl Actor {
    pub fn may_write(&self) -> bool {
        self.role != Role::Viewer
    }
    pub fn permits_tenant(&self, tenant: &str) -> bool {
        self.role == Role::SystemAdmin || self.tenant_id == tenant
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub last_seen_ms: Option<i64>,
    pub apply_error: Option<String>,
    pub enrolled: bool,
    pub stats: EngineStats,
}

#[derive(Clone, Debug)]
pub struct Admission {
    pub rule_id: String,
    pub meter_epoch: String,
    pub upload: bool,
    pub bytes: usize,
    pub datagram: bool,
}

pub fn secret() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
pub fn password_hash(password: &str) -> Result<String> {
    ensure!(
        (12..=1024).contains(&password.len()),
        "password must contain 12..1024 bytes"
    );
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| anyhow::anyhow!("password hash failed: {e}"))
}

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    ensure!(path.is_dir(), "state path is not a directory");
    Ok(())
}

/// Creates a new private file; never overwrites an existing secret.
pub fn write_secret(path: &Path, value: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            private_directory(parent)?;
        }
        if path.exists() {
            ensure!(
                !fs::symlink_metadata(path)?.file_type().is_symlink(),
                "database cannot be a symbolic link"
            );
        } else {
            write_secret(path, b"")?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                "database permissions must be 0600"
            );
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 1, "database schema newer than this binary");
        if version == 0 {
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.execute_batch("PRAGMA user_version=1")?;
            tx.commit()?;
        }
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    pub fn set_kind(&self, kind: &str) -> Result<()> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        conn.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES('kind',?1)",
            [kind],
        )?;
        let old: String =
            conn.query_row("SELECT value FROM metadata WHERE key='kind'", [], |r| {
                r.get(0)
            })?;
        ensure!(old == kind, "database belongs to {old}, not {kind}");
        Ok(())
    }

    pub fn metadata(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.0.lock().unwrap().execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value])?;
        Ok(())
    }

    pub fn needs_bootstrap(&self) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?
            == 0)
    }

    pub fn bootstrap(&self, password: &str) -> Result<Actor> {
        let hash = password_hash(password)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let count: u64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        ensure!(count == 0, "controller already initialized");
        tx.execute(
            "INSERT INTO tenants(id,name) VALUES('default','Default')",
            [],
        )?;
        tx.execute("INSERT INTO users(id,tenant_id,username,password_hash,role) VALUES('admin','default','admin',?1,'system_admin')", [hash])?;
        audit(&tx, "bootstrap", "initialize", "default", "{}")?;
        tx.commit()?;
        Ok(Actor {
            id: "admin".into(),
            tenant_id: "default".into(),
            username: "admin".into(),
            role: Role::SystemAdmin,
        })
    }

    pub fn login(&self, username: &str, password: &str) -> Result<(String, Actor)> {
        let record = {
            let conn = self.0.lock().unwrap();
            conn.query_row("SELECT id,tenant_id,username,role,password_hash FROM users WHERE username=?1 AND disabled=0", [username], |r| {
                Ok((actor_row(r)?, r.get::<_,String>(4)?))
            }).optional()?
        };
        // A dummy hash keeps unknown usernames on the same expensive verification path.
        let dummy = "$argon2id$v=19$m=19456,t=2,p=1$cmVsYXktZHVtbXktc2FsdA$cqS/K9c47e2jdQad9yP11mC/2ZWE1pgbdIoV/OOdSNA";
        let hash = record.as_ref().map(|(_, h)| h.as_str()).unwrap_or(dummy);
        let parsed =
            PasswordHash::new(hash).map_err(|_| anyhow::anyhow!("stored password hash invalid"))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
            || record.is_none()
        {
            return reject(401, "invalid username or password");
        }
        let (actor, _) = record.unwrap();
        let token = secret();
        let conn = self.0.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE expires_at_ms<=?1", [now_ms()])?;
        conn.execute(
            "INSERT INTO sessions(hash,user_id,expires_at_ms) VALUES(?1,?2,?3)",
            params![token_hash(&token), actor.id, now_ms() + 8 * 60 * 60 * 1000],
        )?;
        Ok((token, actor))
    }

    pub fn authenticate(&self, token: &str) -> Result<Actor> {
        self.0.lock().unwrap().query_row("SELECT u.id,u.tenant_id,u.username,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.hash=?1 AND s.expires_at_ms>?2 AND u.disabled=0", params![token_hash(token),now_ms()], actor_row).optional()?.map(Ok).unwrap_or_else(|| reject(401,"session expired or invalid"))
    }
    pub fn logout(&self, token: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM sessions WHERE hash=?1", [token_hash(token)])?;
        Ok(())
    }
    pub fn users(&self, actor: &Actor) -> Result<Vec<Actor>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare("SELECT id,tenant_id,username,role FROM users WHERE (?1='system_admin' OR tenant_id=?2) ORDER BY username")?;
        Ok(
            q.query_map(params![actor.role.as_str(), actor.tenant_id], actor_row)?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
    pub fn create_tenant(&self, actor: &Actor, name: &str) -> Result<String> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "system administrator required");
        }
        if name.trim().is_empty() || name.len() > 120 {
            return reject(400, "invalid tenant name");
        }
        let id = Uuid::new_v4().to_string();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO tenants(id,name) VALUES(?1,?2)",
            params![id, name],
        )?;
        audit(&tx, &actor.id, "tenant.create", &id, "{}")?;
        tx.commit()?;
        Ok(id)
    }
    pub fn create_user(
        &self,
        actor: &Actor,
        tenant: &str,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<Actor> {
        if !actor.may_write()
            || !actor.permits_tenant(tenant)
            || (role == Role::SystemAdmin && actor.role != Role::SystemAdmin)
        {
            return reject(403, "insufficient user scope");
        }
        if !identifier(username) {
            return reject(400, "invalid username");
        }
        let hash = password_hash(password).map_err(|e| Rejection {
            status: 400,
            message: e.to_string(),
        })?;
        let user = Actor {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant.into(),
            username: username.into(),
            role,
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
            [tenant],
            |r| r.get::<_, bool>(0),
        )? {
            return reject(404, "tenant not found");
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1)",
            [username],
            |r| r.get::<_, bool>(0),
        )? {
            return reject(409, "username already exists");
        }
        tx.execute(
            "INSERT INTO users(id,tenant_id,username,password_hash,role) VALUES(?1,?2,?3,?4,?5)",
            params![user.id, tenant, username, hash, user.role.as_str()],
        )?;
        audit(&tx, &actor.id, "user.create", &user.id, "{}")?;
        tx.commit()?;
        Ok(user)
    }
    pub fn revoke_sessions(&self, actor: &Actor, user_id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let user = tx
            .query_row(
                "SELECT id,tenant_id,username,role FROM users WHERE id=?1",
                [user_id],
                actor_row,
            )
            .optional()?;
        let Some(user) = user else {
            return reject(404, "user not found");
        };
        if actor.id != user_id
            && (!actor.may_write()
                || !actor.permits_tenant(&user.tenant_id)
                || (user.role == Role::SystemAdmin && actor.role != Role::SystemAdmin))
        {
            return reject(403, "insufficient user scope");
        }
        tx.execute("DELETE FROM sessions WHERE user_id=?1", [user_id])?;
        audit(&tx, &actor.id, "session.revoke", user_id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_node(&self, actor: &Actor, tenant: &str, name: &str) -> Result<(Node, String)> {
        if !actor.may_write() || !actor.permits_tenant(tenant) {
            return reject(403, "insufficient node scope");
        }
        if name.trim().is_empty() || name.len() > 120 {
            return reject(400, "invalid node name");
        }
        let id = Uuid::new_v4().to_string();
        let token = secret();
        let config = NodeConfig {
            api_version: API_VERSION,
            node_id: id.clone(),
            revision: 0,
            rules: vec![],
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
            [tenant],
            |r| r.get::<_, bool>(0),
        )? {
            return reject(404, "tenant not found");
        }
        tx.execute(
            "INSERT INTO nodes(id,tenant_id,name,enrollment_hash) VALUES(?1,?2,?3,?4)",
            params![id, tenant, name, token_hash(&token)],
        )?;
        tx.execute("INSERT INTO config_history(node_id,revision,config_json,actor_id,created_at_ms) VALUES(?1,0,?2,?3,?4)",params![id,serde_json::to_string(&config)?,actor.id,now_ms()])?;
        audit(&tx, &actor.id, "node.create", &id, "{}")?;
        tx.commit()?;
        Ok((
            Node {
                id,
                tenant_id: tenant.into(),
                name: name.into(),
                desired_revision: 0,
                applied_revision: 0,
                last_seen_ms: None,
                apply_error: None,
                enrolled: false,
                stats: EngineStats::default(),
            },
            token,
        ))
    }
    pub fn enroll(&self, node: &str, token: &str, credential: &str) -> Result<()> {
        if [token, credential]
            .iter()
            .any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()))
            || token == credential
        {
            return reject(400, "invalid or reused enrollment credential");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let changed=tx.execute("UPDATE nodes SET token_hash=?1,enrollment_hash=NULL WHERE id=?2 AND enrollment_hash=?3",params![token_hash(credential),node,token_hash(token)])?;
        if changed != 1 {
            let same_credential = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND token_hash=?2 AND enrollment_hash IS NULL)",
                params![node, token_hash(credential)], |r| r.get::<_,bool>(0)
            )?;
            if !same_credential {
                return reject(401, "enrollment token invalid or already consumed");
            }
        } else {
            audit(&tx, node, "node.enroll", node, "{}")?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn authenticate_node(&self, token: &str) -> Result<String> {
        self.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT id FROM nodes WHERE token_hash=?1",
                [token_hash(token)],
                |r| r.get(0),
            )
            .optional()?
            .map(Ok)
            .unwrap_or_else(|| reject(401, "node credential invalid"))
    }
    pub fn nodes(&self, actor: &Actor) -> Result<Vec<Node>> {
        let conn = self.0.lock().unwrap();
        let mut q=conn.prepare("SELECT id,tenant_id,name,desired_revision,applied_revision,last_seen_ms,apply_error,token_hash IS NOT NULL,stats_json FROM nodes WHERE (?1='system_admin' OR tenant_id=?2) ORDER BY name,id")?;
        let rows = q.query_map(params![actor.role.as_str(), actor.tenant_id], |r| {
            Ok(Node {
                id: r.get(0)?,
                tenant_id: r.get(1)?,
                name: r.get(2)?,
                desired_revision: r.get(3)?,
                applied_revision: r.get(4)?,
                last_seen_ms: r.get(5)?,
                apply_error: r.get(6)?,
                enrolled: r.get(7)?,
                stats: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    pub fn config(&self, actor: &Actor, node: &str, revision: Option<u64>) -> Result<NodeConfig> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let json = if let Some(revision) = revision {
            conn.query_row(
                "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
                params![node, revision],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        } else {
            conn.query_row("SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1",[node],|r|r.get(0)).optional()?
        };
        match json {
            Some(s) => Ok(serde_json::from_str(&s)?),
            None => reject(404, "configuration revision not found"),
        }
    }
    pub fn set_config(
        &self,
        actor: &Actor,
        node: &str,
        expected: u64,
        rules: Vec<Rule>,
    ) -> Result<NodeConfig> {
        if expected >= MAX_COUNTER {
            return reject(400, "revision out of range");
        }
        let config = NodeConfig {
            api_version: API_VERSION,
            node_id: node.into(),
            revision: expected + 1,
            rules,
        };
        config.validate().map_err(|e| Rejection {
            status: 400,
            message: e.to_string(),
        })?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = require_node(&tx, actor, node, true)?;
        for rule in &config.rules {
            if rule.tenant_id != tenant {
                return reject(403, "rule tenant does not match node");
            }
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND tenant_id=?2)",
                params![rule.owner_id, tenant],
                |r| r.get::<_, bool>(0),
            )? {
                return reject(403, "rule owner must belong to node tenant");
            }
            let bound: Option<(String, String)> = tx
                .query_row(
                    "SELECT node_id,owner_id FROM rule_bindings WHERE rule_id=?1",
                    [&rule.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if bound.is_some_and(|(n, o)| n != node || o != rule.owner_id) {
                return reject(
                    409,
                    "rule identity already belongs to another node or owner",
                );
            }
            tx.execute("INSERT OR IGNORE INTO rule_bindings(rule_id,node_id,tenant_id,owner_id) VALUES(?1,?2,?3,?4)",params![rule.id,node,tenant,rule.owner_id])?;
            tx.execute(
                "INSERT OR IGNORE INTO rule_epochs(rule_id,meter_epoch) VALUES(?1,?2)",
                params![rule.id, rule.meter_epoch],
            )?;
        }
        if tx.execute(
            "UPDATE nodes SET desired_revision=?1 WHERE id=?2 AND desired_revision=?3",
            params![config.revision, node, expected],
        )? != 1
        {
            return reject(409, "configuration changed; reload before saving");
        }
        tx.execute("INSERT INTO config_history(node_id,revision,config_json,actor_id,created_at_ms) VALUES(?1,?2,?3,?4,?5)",params![node,config.revision,serde_json::to_string(&config)?,actor.id,now_ms()])?;
        audit(
            &tx,
            &actor.id,
            "config.publish",
            node,
            &serde_json::json!({"revision":config.revision,"rules":config.rules.len()}).to_string(),
        )?;
        tx.commit()?;
        Ok(config)
    }
    pub fn history(&self, actor: &Actor, node: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let mut q=conn.prepare("SELECT revision,actor_id,created_at_ms FROM config_history WHERE node_id=?1 ORDER BY revision DESC LIMIT 100")?;
        Ok(q.query_map([node],|r|Ok(serde_json::json!({"revision":r.get::<_,u64>(0)?,"actor_id":r.get::<_,String>(1)?,"created_at_ms":r.get::<_,i64>(2)?})))?.collect::<rusqlite::Result<_>>()?)
    }

    pub fn sync(&self, node: &str, request: SyncRequest) -> Result<SyncResponse> {
        if request.usage.len() > 1024
            || request.apply_error.as_ref().is_some_and(|e| e.len() > 2048)
        {
            return reject(400, "sync payload exceeds limits");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let desired: u64 = tx.query_row(
            "SELECT desired_revision FROM nodes WHERE id=?1",
            [node],
            |r| r.get(0),
        )?;
        if request.applied_revision > desired {
            return reject(
                409,
                "agent revision exceeds controller; reconcile restored state",
            );
        }
        let mut acknowledgements = vec![];
        for usage in request.usage {
            if usage.sequence == 0
                || usage.sequence > MAX_COUNTER
                || usage
                    .upload_bytes
                    .checked_add(usage.download_bytes)
                    .is_none_or(|n| n > MAX_COUNTER)
            {
                return reject(400, "invalid usage counters");
            }
            let known=tx.query_row("SELECT EXISTS(SELECT 1 FROM rule_epochs e JOIN rule_bindings b ON b.rule_id=e.rule_id WHERE b.node_id=?1 AND e.rule_id=?2 AND e.meter_epoch=?3)",params![node,usage.rule_id,usage.meter_epoch],|r|r.get::<_,bool>(0))?;
            if !known {
                return reject(403, "usage does not belong to this node and period");
            }
            let old=tx.query_row("SELECT sequence,upload_bytes,download_bytes FROM usage WHERE node_id=?1 AND rule_id=?2 AND meter_epoch=?3",params![node,usage.rule_id,usage.meter_epoch],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?))).optional()?;
            if let Some((seq, up, down)) = old
                && (usage.sequence < seq
                    || usage.upload_bytes < up
                    || usage.download_bytes < down
                    || (usage.sequence == seq
                        && (usage.upload_bytes != up || usage.download_bytes != down)))
            {
                return reject(
                    409,
                    "usage history conflicts with controller; restore or reconcile agent ledger",
                );
            }
            tx.execute("INSERT INTO usage(node_id,rule_id,meter_epoch,sequence,upload_bytes,download_bytes,reported_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(node_id,rule_id,meter_epoch) DO UPDATE SET sequence=excluded.sequence,upload_bytes=excluded.upload_bytes,download_bytes=excluded.download_bytes,reported_at_ms=excluded.reported_at_ms",params![node,usage.rule_id,usage.meter_epoch,usage.sequence,usage.upload_bytes,usage.download_bytes,now_ms()])?;
            acknowledgements.push(UsageAck {
                rule_id: usage.rule_id,
                meter_epoch: usage.meter_epoch,
                sequence: usage.sequence,
            });
        }
        tx.execute("UPDATE nodes SET applied_revision=?1,last_seen_ms=?2,apply_error=?3,stats_json=?4 WHERE id=?5",params![request.applied_revision,now_ms(),request.apply_error,serde_json::to_string(&request.stats)?,node])?;
        let config = if request.need_config || desired != request.applied_revision {
            Some(serde_json::from_str(&tx.query_row(
                "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
                params![node, desired],
                |r| r.get::<_, String>(0),
            )?)?)
        } else {
            None
        };
        tx.commit()?;
        Ok(SyncResponse {
            config,
            acknowledgements,
            server_time_ms: now_ms(),
        })
    }

    pub fn reported_usage(&self, actor: &Actor) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        let mut q=conn.prepare("SELECT u.node_id,u.rule_id,u.meter_epoch,u.sequence,u.upload_bytes,u.download_bytes,u.reported_at_ms,b.owner_id,b.tenant_id FROM usage u JOIN rule_bindings b ON b.rule_id=u.rule_id WHERE (?1='system_admin' OR b.tenant_id=?2) ORDER BY u.reported_at_ms DESC LIMIT 2000")?;
        Ok(q.query_map(params![actor.role.as_str(),actor.tenant_id],|r|Ok(serde_json::json!({"node_id":r.get::<_,String>(0)?,"rule_id":r.get::<_,String>(1)?,"meter_epoch":r.get::<_,String>(2)?,"sequence":r.get::<_,u64>(3)?,"upload_bytes":r.get::<_,u64>(4)?,"download_bytes":r.get::<_,u64>(5)?,"reported_at_ms":r.get::<_,i64>(6)?,"owner_id":r.get::<_,String>(7)?,"tenant_id":r.get::<_,String>(8)?})))?.collect::<rusqlite::Result<_>>()?)
    }
    pub fn audit_log(&self, actor: &Actor) -> Result<Vec<serde_json::Value>> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "system administrator required for global audit");
        }
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare(
            "SELECT id,at_ms,actor_id,action,resource,detail FROM audit ORDER BY id DESC LIMIT 200",
        )?;
        Ok(q.query_map([],|r|Ok(serde_json::json!({"id":r.get::<_,u64>(0)?,"at_ms":r.get::<_,i64>(1)?,"actor_id":r.get::<_,String>(2)?,"action":r.get::<_,String>(3)?,"resource":r.get::<_,String>(4)?,"detail":r.get::<_,String>(5)?})))?.collect::<rusqlite::Result<_>>()?)
    }

    pub fn agent_config(&self) -> Result<Option<NodeConfig>> {
        self.metadata("agent_config")?
            .map(|s| serde_json::from_str(&s).context("invalid stored agent config"))
            .transpose()
    }
    /// Called only after every listener has been staged successfully.
    pub fn save_agent_config(&self, config: &NodeConfig) -> Result<()> {
        config.validate()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='agent_config'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: NodeConfig = serde_json::from_str(&old)?;
            ensure!(
                old.node_id == config.node_id,
                "agent identity cannot change"
            );
            ensure!(config.revision >= old.revision, "stale config rejected");
            if config.revision == old.revision {
                ensure!(
                    serde_json::to_value(&old)? == serde_json::to_value(config)?,
                    "same revision with different content"
                );
            }
        }
        tx.execute("UPDATE agent_meters SET enabled=0", [])?;
        for rule in &config.rules {
            tx.execute("INSERT INTO agent_meters(rule_id,meter_epoch,enabled,quota_bytes,expires_at_ms) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(rule_id,meter_epoch) DO UPDATE SET enabled=excluded.enabled,quota_bytes=excluded.quota_bytes,expires_at_ms=excluded.expires_at_ms",params![rule.id,rule.meter_epoch,rule.enabled,rule.quota_bytes,rule.expires_at_ms])?;
        }
        tx.execute("INSERT INTO metadata(key,value) VALUES('agent_config',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[serde_json::to_string(config)?])?;
        tx.commit()?;
        Ok(())
    }
    pub fn admit_batch(&self, requests: &[Admission]) -> Result<Vec<Option<usize>>> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut result = Vec::with_capacity(requests.len());
        let now = now_ms();
        let mut read_meter = tx.prepare_cached(
            "SELECT enabled,quota_bytes,expires_at_ms,upload_bytes,download_bytes,sequence
             FROM agent_meters WHERE rule_id=?1 AND meter_epoch=?2",
        )?;
        let mut write_meter = tx.prepare_cached(
            "UPDATE agent_meters SET upload_bytes=upload_bytes+?1,
             download_bytes=download_bytes+?2,sequence=sequence+1
             WHERE rule_id=?3 AND meter_epoch=?4",
        )?;
        for r in requests {
            let state = read_meter
                .query_row(params![r.rule_id, r.meter_epoch], |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, Option<u64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                })
                .optional()?;
            let Some((enabled, quota, expires, up, down, seq)) = state else {
                result.push(None);
                continue;
            };
            let remaining = quota
                .unwrap_or(MAX_COUNTER)
                .saturating_sub(up + down)
                .min(MAX_COUNTER - (up + down));
            if !enabled
                || remaining == 0
                || expires.is_some_and(|t| t <= now)
                || seq >= MAX_COUNTER
                || (r.datagram && r.bytes as u64 > remaining)
            {
                result.push(None);
                continue;
            }
            let allowed = (r.bytes as u64).min(remaining) as usize;
            if allowed > 0 {
                write_meter.execute(params![
                    if r.upload { allowed as u64 } else { 0 },
                    if r.upload { 0 } else { allowed as u64 },
                    r.rule_id,
                    r.meter_epoch
                ])?;
            }
            result.push(Some(allowed));
        }
        drop(read_meter);
        drop(write_meter);
        tx.commit()?;
        Ok(result)
    }
    pub fn agent_usage(&self, unsynced_only: bool) -> Result<Vec<Usage>> {
        let conn = self.0.lock().unwrap();
        let mut q=conn.prepare("SELECT rule_id,meter_epoch,sequence,upload_bytes,download_bytes FROM agent_meters WHERE sequence>0 AND (?1=0 OR sequence>ack_sequence) ORDER BY rule_id,meter_epoch LIMIT 1024")?;
        Ok(q.query_map([unsynced_only], |r| {
            Ok(Usage {
                rule_id: r.get(0)?,
                meter_epoch: r.get(1)?,
                sequence: r.get(2)?,
                upload_bytes: r.get(3)?,
                download_bytes: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
    }
    pub fn acknowledge(&self, acks: &[UsageAck]) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        for ack in acks {
            let sequence: u64 = tx.query_row(
                "SELECT sequence FROM agent_meters WHERE rule_id=?1 AND meter_epoch=?2",
                params![ack.rule_id, ack.meter_epoch],
                |r| r.get(0),
            )?;
            ensure!(
                ack.sequence <= sequence,
                "controller acknowledgement is ahead of local ledger"
            );
            tx.execute("UPDATE agent_meters SET ack_sequence=MAX(ack_sequence,?1) WHERE rule_id=?2 AND meter_epoch=?3",params![ack.sequence,ack.rule_id,ack.meter_epoch])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn backup(&self, destination: &Path) -> Result<()> {
        write_secret(destination, b"")?;
        let mut dest = Connection::open(destination)?;
        let src = self.0.lock().unwrap();
        let backup = rusqlite::backup::Backup::new(&src, &mut dest)?;
        backup.run_to_completion(256, Duration::from_millis(10), None)?;
        drop(backup);
        drop(dest);
        fs::File::open(destination)?.sync_all()?;
        Ok(())
    }
}

fn actor_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Actor> {
    let role: String = r.get(3)?;
    Ok(Actor {
        id: r.get(0)?,
        tenant_id: r.get(1)?,
        username: r.get(2)?,
        role: match role.as_str() {
            "system_admin" => Role::SystemAdmin,
            "tenant_admin" => Role::TenantAdmin,
            _ => Role::Viewer,
        },
    })
}
fn require_node(conn: &Connection, actor: &Actor, node: &str, write: bool) -> Result<String> {
    let tenant: Option<String> = conn
        .query_row("SELECT tenant_id FROM nodes WHERE id=?1", [node], |r| {
            r.get(0)
        })
        .optional()?;
    let Some(tenant) = tenant else {
        return reject(404, "node not found");
    };
    if !actor.permits_tenant(&tenant) {
        return reject(404, "node not found");
    }
    if write && !actor.may_write() {
        return reject(403, "read-only role cannot publish configuration");
    }
    Ok(tenant)
}
fn audit(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    resource: &str,
    detail: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO audit(at_ms,actor_id,action,resource,detail) VALUES(?1,?2,?3,?4,?5)",
        params![now_ms(), actor, action, resource, detail],
    )?;
    Ok(())
}
