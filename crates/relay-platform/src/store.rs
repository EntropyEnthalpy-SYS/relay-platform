use crate::model::*;
use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

mod accounts;
mod alert_config;
mod budgets;
mod credentials;
mod health;
mod leases;
mod node_profiles;
mod recovery;
mod reservations;
mod sync;
mod topology;
mod user_rates;
pub use accounts::{
    API_TOKEN_PREFIX, ApiToken, SECOND_FACTOR_INVALID, SECOND_FACTOR_REQUIRED, Scope,
    SecondFactorSetup, SecondFactorStatus, UserSummary,
};
pub use alert_config::AlertNode;
pub use reservations::MeterFlush;
pub use user_rates::{MAX_USER_RATE, MIN_USER_RATE, UserRateView};

fn acknowledge_usage(tx: &Transaction<'_>, acks: &[UsageAck]) -> Result<()> {
    ensure!(acks.len() <= 1024, "too many usage acknowledgements");
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
    Ok(())
}

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
pub struct Store(
    Arc<Mutex<crate::journal::LoggedConnection>>,
    Arc<PathBuf>,
    Arc<BudgetSignals>,
    Arc<Mutex<leases::LeaseClocks>>,
    Arc<crate::telemetry::Telemetry>,
    Arc<crate::alerts::Alerts>,
    Arc<Mutex<user_rates::UserRates>>,
);
#[derive(Default)]
struct BudgetSignals {
    refill: tokio::sync::Notify,
    updated: tokio::sync::Notify,
    /// Wakes agent watches after any node's desired configuration changes.
    config: tokio::sync::Notify,
}

#[derive(Clone, Copy, Debug)]
pub enum AdmissionDecision {
    Admitted(usize),
    Rejected,
    AwaitingBudget,
}

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
    #[serde(default)]
    pub credential_phase: crate::credential::CredentialPhase,
    #[serde(default)]
    pub profile: crate::node::NodeProfile,
    #[serde(default)]
    pub lifecycle: crate::node::NodeLifecycle,
    #[serde(default)]
    pub lease: crate::lease::LeaseStatus,
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
fn password_matches(hash: &str, password: &str) -> Result<bool> {
    let parsed =
        PasswordHash::new(hash).map_err(|_| anyhow::anyhow!("stored password hash invalid"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
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
        let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 5, "database schema newer than this binary");
        if version == 0 {
            let tables: u64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0))?;
            ensure!(tables == 0, "refusing to initialize an unrelated database");
        } else {
            let expected: u64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('metadata','nodes','agent_meters','config_history')", [], |r| r.get(0))?;
            ensure!(expected == 4, "not a Relay database");
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        if version == 0 {
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.execute_batch("PRAGMA user_version=1")?;
            tx.commit()?;
        }
        if version < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "ALTER TABLE nodes ADD COLUMN ledger_id TEXT;
                INSERT OR REPLACE INTO metadata(key,value)
                  SELECT 'recovery_required','true' FROM metadata WHERE key='agent_credential';
                PRAGMA user_version=2;",
            )?;
            tx.commit()?;
        }
        if version < 3 {
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("store/budget_schema.sql"))?;
            tx.execute_batch("INSERT OR IGNORE INTO metadata(key,value) SELECT 'budget_allocation_paused','true' FROM metadata WHERE key='backup_created_at_ms'; PRAGMA user_version=3;")?;
            tx.commit()?;
        }
        if version < 4 {
            conn.execute_batch("BEGIN; CREATE TABLE recovery_state(id INTEGER PRIMARY KEY CHECK(id=1),journal_id TEXT NOT NULL,sequence INTEGER NOT NULL CHECK(sequence>=0),digest TEXT NOT NULL); CREATE TABLE cancelled_budget_requests(node_id TEXT NOT NULL REFERENCES nodes(id),run_id TEXT NOT NULL,request_id TEXT NOT NULL,budget_id TEXT NOT NULL REFERENCES budgets(id),PRIMARY KEY(node_id,run_id,request_id)); PRAGMA user_version=4; COMMIT;")?;
        }
        // 0.20.0: the security state introduced in 0.19.0 (MFA, scoped API
        // tokens) is not understood by 0.18.0/0.19.0. Bumping the persisted
        // application schema makes every older binary refuse the database
        // before it opens a listener or serves a password-only login. The
        // table layout is unchanged, so the recovery-log format and its
        // schema fingerprint stay valid and no journal rewrite is needed.
        if version < 5 {
            conn.execute_batch("PRAGMA user_version=5")?;
        }
        Ok(Self(
            Arc::new(Mutex::new(crate::journal::LoggedConnection::new(conn)?)),
            Arc::new(fs::canonicalize(path)?),
            Arc::new(BudgetSignals::default()),
            Arc::new(Mutex::new(leases::LeaseClocks::default())),
            Arc::default(),
            Arc::default(),
            Arc::default(),
        ))
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
    pub fn enable_recovery_log(&self, path: &Path) -> Result<()> {
        self.0.lock().unwrap().enable(path)
    }
    pub fn recovery_log_status(&self) -> Result<crate::journal::JournalStatus> {
        self.0.lock().unwrap().status()
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
        self.login_with_second_factor(username, password, None)
    }
    pub fn login_with_second_factor(
        &self,
        username: &str,
        password: &str,
        second_factor: Option<&str>,
    ) -> Result<(String, Actor)> {
        let record = {
            let conn = self.0.lock().unwrap();
            conn.query_row("SELECT id,tenant_id,username,role,password_hash FROM users WHERE username=?1 AND disabled=0", [username], |r| {
                Ok((actor_row(r)?, r.get::<_,String>(4)?))
            }).optional()?
        };
        // A dummy hash keeps unknown usernames on the same expensive verification path.
        let dummy = "$argon2id$v=19$m=19456,t=2,p=1$cmVsYXktZHVtbXktc2FsdA$cqS/K9c47e2jdQad9yP11mC/2ZWE1pgbdIoV/OOdSNA";
        let hash = record.as_ref().map(|(_, h)| h.as_str()).unwrap_or(dummy);
        if !password_matches(hash, password)? || record.is_none() {
            return reject(401, "invalid username or password");
        }
        let (actor, _) = record.unwrap();
        let token = secret();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        accounts::check_second_factor(&tx, &actor.id, second_factor)?;
        tx.execute("DELETE FROM sessions WHERE expires_at_ms<=?1", [now_ms()])?;
        tx.execute(
            "INSERT INTO sessions(hash,user_id,expires_at_ms) VALUES(?1,?2,?3)",
            params![token_hash(&token), actor.id, now_ms() + 8 * 60 * 60 * 1000],
        )?;
        tx.commit()?;
        Ok((token, actor))
    }

    pub fn logout(&self, token: &str) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .execute("DELETE FROM sessions WHERE hash=?1", [token_hash(token)])?;
        Ok(())
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
        if actor.id != user_id {
            accounts::require_user_manager(&tx, actor, user_id)?;
        }
        accounts::end_credentials(&tx, user_id)?;
        audit(&tx, &actor.id, "session.revoke", user_id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_node(&self, actor: &Actor, tenant: &str, name: &str) -> Result<(Node, String)> {
        self.create_node_with_lease(actor, tenant, name, None)
    }
    pub fn create_node_with_lease(
        &self,
        actor: &Actor,
        tenant: &str,
        name: &str,
        policy: Option<crate::lease::LeasePolicy>,
    ) -> Result<(Node, String)> {
        self.create_node_with_settings(actor, tenant, name, policy, Default::default())
    }
    pub fn create_node_with_settings(
        &self,
        actor: &Actor,
        tenant: &str,
        name: &str,
        policy: Option<crate::lease::LeasePolicy>,
        settings: crate::node::NodeSettings,
    ) -> Result<(Node, String)> {
        if !actor.may_write() || !actor.permits_tenant(tenant) {
            return reject(403, "insufficient node scope");
        }
        crate::node::validate_name(name)?;
        node_profiles::validate_policy(&settings, policy.as_ref())?;
        let now = self.3.lock().unwrap().policy_now_ms();
        let profile = crate::node::NodeProfile {
            revision: 1,
            updated_at_ms: Some(now),
            settings,
        };
        let id = Uuid::new_v4().to_string();
        let token = secret();
        let config = NodeConfig {
            api_version: API_VERSION,
            node_id: id.clone(),
            revision: 0,
            rules: vec![],
            rate_bytes_per_sec: None,
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
        leases::initialize(&tx, &id, policy.clone())?;
        node_profiles::write(&tx, &id, &profile)?;
        audit(&tx, &actor.id, "node.create", &id, "{}")?;
        tx.commit()?;
        leases::created(&mut self.3.lock().unwrap(), &id);
        Ok((
            Node {
                credential_phase: crate::credential::CredentialPhase::NotEnrolled,
                lifecycle: profile.settings.lifecycle(now),
                profile,
                lease: crate::lease::LeaseStatus {
                    policy,
                    ..Default::default()
                },
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
        self.enroll_revision(node, token, credential).map(|_| ())
    }
    pub fn enroll_revision(&self, node: &str, token: &str, credential: &str) -> Result<u64> {
        self.enroll_with_capability(node, token, credential, true)
    }
    pub fn enroll_with_capability(
        &self,
        node: &str,
        token: &str,
        credential: &str,
        identity_revision_supported: bool,
    ) -> Result<u64> {
        if [token, credential]
            .iter()
            .any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()))
            || token == credential
        {
            return reject(400, "invalid or reused enrollment credential");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let eligible: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND enrollment_hash=?2)",
            params![node, token_hash(token)],
            |row| row.get(0),
        )?;
        if eligible {
            credentials::enrollment_ready(
                &tx,
                node,
                self.3.lock().unwrap().policy_now_ms(),
                identity_revision_supported,
            )?;
            credentials::require_fresh(&tx, &token_hash(credential))?;
        }
        let changed=tx.execute("UPDATE nodes SET token_hash=?1,enrollment_hash=NULL WHERE id=?2 AND enrollment_hash=?3",params![token_hash(credential),node,token_hash(token)])?;
        if changed != 1 {
            let same_credential = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1 AND token_hash=?2 AND enrollment_hash IS NULL)",
                params![node, token_hash(credential)], |r| r.get::<_,bool>(0)
            )?;
            if !same_credential {
                return reject(401, "enrollment token invalid or already consumed");
            }
        }
        let revision = if changed == 1 {
            let revision =
                credentials::finish_enrollment(&tx, node, self.3.lock().unwrap().policy_now_ms())?;
            audit(&tx, node, "node.enroll", node, "{}")?;
            revision
        } else {
            credentials::read(&tx, node)?.revision
        };
        tx.commit()?;
        Ok(revision)
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
                credential_phase: crate::credential::CredentialPhase::NotEnrolled,
                profile: Default::default(),
                lifecycle: Default::default(),
                lease: crate::lease::LeaseStatus::default(),
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
        let mut nodes: Vec<Node> = rows.collect::<rusqlite::Result<_>>()?;
        let mut clocks = self.3.lock().unwrap();
        let now = clocks.policy_now_ms();
        for node in &mut nodes {
            node.credential_phase = credentials::read(&conn, &node.id)?.phase;
            node.lease = leases::status(&conn, &mut clocks, &node.id)?;
            node.profile = node_profiles::read(&conn, &node.id)?;
            node.lifecycle = node.profile.settings.lifecycle(now);
        }
        Ok(nodes)
    }
    /// Recent per-node samples and incidents for the nodes the actor can see.
    pub fn telemetry(&self, actor: &Actor) -> Result<serde_json::Value> {
        use crate::telemetry::OFFLINE_AFTER_MS;
        let rows: Vec<(String, String, Option<i64>, bool)> = {
            let conn = self.0.lock().unwrap();
            let mut q = conn.prepare("SELECT id,name,last_seen_ms,token_hash IS NOT NULL FROM nodes WHERE (?1='system_admin' OR tenant_id=?2) ORDER BY name,id")?;
            q.query_map(params![actor.role.as_str(), actor.tenant_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let visible: Vec<String> = rows.iter().map(|r| r.0.clone()).collect();
        let (mut samples, mut events) = self.4.snapshot(&visible);
        let now = now_ms();
        // Silence produces no report, so offline incidents are derived on read.
        for (id, name, last_seen, enrolled) in &rows {
            if let Some(last) = last_seen.filter(|last| *enrolled && now - last > OFFLINE_AFTER_MS)
            {
                events.push(crate::telemetry::Event {
                    id: 0,
                    at_ms: last + OFFLINE_AFTER_MS,
                    node_id: id.clone(),
                    severity: crate::telemetry::Severity::Critical,
                    kind: "node_offline",
                    subject: String::new(),
                    message: format!("节点 {name} 已 {} 秒无回报", (now - last) / 1000),
                });
            }
        }
        events.sort_by_key(|e| e.at_ms);
        let nodes: Vec<_> = rows
            .into_iter()
            .map(|(id, name, last_seen_ms, enrolled)| {
                let samples = samples.remove(&id).unwrap_or_default();
                serde_json::json!({"id": id, "name": name, "last_seen_ms": last_seen_ms, "enrolled": enrolled, "samples": samples})
            })
            .collect();
        Ok(serde_json::json!({
            "generated_at_ms": now,
            "window_ms": crate::telemetry::WINDOW_MS,
            "offline_after_ms": OFFLINE_AFTER_MS,
            "nodes": nodes,
            "events": events,
        }))
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
    pub fn history(&self, actor: &Actor, node: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let mut q=conn.prepare("SELECT revision,actor_id,created_at_ms FROM config_history WHERE node_id=?1 ORDER BY revision DESC LIMIT 100")?;
        Ok(q.query_map([node],|r|Ok(serde_json::json!({"revision":r.get::<_,u64>(0)?,"actor_id":r.get::<_,String>(1)?,"created_at_ms":r.get::<_,i64>(2)?})))?.collect::<rusqlite::Result<_>>()?)
    }

    pub fn reported_usage(&self, actor: &Actor) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        let mut q=conn.prepare("SELECT u.node_id,u.rule_id,u.meter_epoch,u.sequence,u.upload_bytes,u.download_bytes,u.reported_at_ms,b.owner_id,b.tenant_id FROM usage u JOIN rule_bindings b ON b.rule_id=u.rule_id WHERE (?1='system_admin' OR b.tenant_id=?2) ORDER BY u.reported_at_ms DESC,u.node_id,u.rule_id,u.meter_epoch LIMIT 2000")?;
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
        tx.execute("DELETE FROM agent_rule_budgets", [])?;
        for rule in &config.rules {
            for id in &rule.budget_ids {
                tx.execute("INSERT INTO agent_rule_budgets(rule_id,meter_epoch,budget_id) VALUES(?1,?2,?3)",params![rule.id,rule.meter_epoch,id])?;
            }
            tx.execute("INSERT INTO agent_meters(rule_id,meter_epoch,enabled,quota_bytes,expires_at_ms,budgeted) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(rule_id,meter_epoch) DO UPDATE SET enabled=excluded.enabled,quota_bytes=excluded.quota_bytes,expires_at_ms=excluded.expires_at_ms,budgeted=excluded.budgeted",params![rule.id,rule.meter_epoch,rule.enabled,rule.quota_bytes,rule.expires_at_ms,!rule.budget_ids.is_empty()])?;
        }
        tx.execute("INSERT INTO metadata(key,value) VALUES('agent_config',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[serde_json::to_string(config)?])?;
        tx.commit()?;
        Ok(())
    }
    pub fn admit_batch(&self, requests: &[Admission]) -> Result<Vec<Option<usize>>> {
        Ok(self
            .admit_batch_detailed(requests)?
            .into_iter()
            .map(|d| match d {
                AdmissionDecision::Admitted(n) => Some(n),
                _ => None,
            })
            .collect())
    }
    /// Construct before reading the revision, as with [`Self::budget_updated`].
    pub fn config_published(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.2.config.notified()
    }
    pub fn node_desired_revision(&self, credential: &str) -> Result<u64> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let node = leases::authenticated(&tx, credential)?;
        Ok(tx.query_row(
            "SELECT desired_revision FROM nodes WHERE id=?1",
            [node],
            |r| r.get(0),
        )?)
    }
    pub async fn budget_refill_needed(&self) {
        self.2.refill.notified().await;
    }
    pub fn budget_updated(&self) -> impl std::future::Future<Output = ()> + '_ {
        // Construct before checking credit: notify_waiters remembers changes
        // since construction even if the future has not been polled yet.
        self.2.updated.notified()
    }
    pub fn admit_batch_detailed(&self, requests: &[Admission]) -> Result<Vec<AdmissionDecision>> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut result = Vec::with_capacity(requests.len());
        let mut refill = false;
        let now = now_ms();
        let mut read_meter = tx.prepare_cached(
            "SELECT enabled,quota_bytes,expires_at_ms,upload_bytes,download_bytes,sequence,budgeted
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
                        row.get::<_, bool>(6)?,
                    ))
                })
                .optional()?;
            let Some((enabled, quota, expires, up, down, seq, budgeted)) = state else {
                result.push(AdmissionDecision::Rejected);
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
                result.push(AdmissionDecision::Rejected);
                continue;
            }
            let allowed = (r.bytes as u64).min(remaining) as usize;
            let (budget_allowed, needs_refill) = if budgeted {
                budgets::admit(&tx, r, allowed)?
            } else {
                (Some(allowed), false)
            };
            refill |= needs_refill;
            let Some(allowed) = budget_allowed else {
                result.push(AdmissionDecision::AwaitingBudget);
                continue;
            };
            if allowed > 0 {
                write_meter.execute(params![
                    if r.upload { allowed as u64 } else { 0 },
                    if r.upload { 0 } else { allowed as u64 },
                    r.rule_id,
                    r.meter_epoch
                ])?;
            }
            result.push(AdmissionDecision::Admitted(allowed));
        }
        drop(read_meter);
        drop(write_meter);
        tx.commit()?;
        if refill {
            self.2.refill.notify_one();
        }
        Ok(result)
    }
    pub fn agent_usage(&self, unsynced_only: bool) -> Result<Vec<Usage>> {
        let conn = self.0.lock().unwrap();
        let mut q=conn.prepare("SELECT rule_id,meter_epoch,sequence,upload_bytes,download_bytes FROM agent_meters WHERE sequence>0 AND (?1=0 OR sequence>ack_sequence) ORDER BY rule_id,meter_epoch LIMIT CASE WHEN ?1 THEN 1024 ELSE -1 END")?;
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
        acknowledge_usage(&tx, acks)?;
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
        let managed_agent: bool = dest.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='agent_credential')",
            [],
            |r| r.get(0),
        )?;
        if managed_agent {
            dest.execute("INSERT INTO metadata(key,value) VALUES('recovery_required','true') ON CONFLICT(key) DO UPDATE SET value=excluded.value", [])?;
            // A snapshot cannot certify consumption after it was taken. Only
            // the retained original durable state may resume an execution run.
            dest.execute("DELETE FROM metadata WHERE key='agent_budget_resume'", [])?;
        }
        let original_pause: Option<String> = dest
            .query_row(
                "SELECT value FROM metadata WHERE key='budget_allocation_paused'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        dest.execute("INSERT INTO metadata(key,value) VALUES('backup_original_budget_pause',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[serde_json::to_string(&original_pause)?])?;
        dest.execute("INSERT INTO metadata(key,value) VALUES('budget_allocation_paused','true') ON CONFLICT(key) DO UPDATE SET value=excluded.value", [])?;
        dest.execute("INSERT INTO metadata(key,value) VALUES('backup_created_at_ms',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [now_ms().to_string()])?;
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
