//! Operator two-factor login and scoped API tokens. Both live in `metadata`
//! rows so the schema, backups and recovery journal stay at schema v4.
use super::*;
use crate::totp;

pub const SECOND_FACTOR_REQUIRED: &str = "two-factor code required";
pub const SECOND_FACTOR_INVALID: &str = "invalid two-factor code";
pub const API_TOKEN_PREFIX: &str = "rpat_";
const RECOVERY_CODES: usize = 8;
const MAX_API_TOKENS: usize = 20;

#[derive(Serialize, Deserialize)]
struct SecondFactor {
    secret: String,
    enabled: bool,
    used_through_step: Option<u64>,
    recovery_hashes: Vec<String>,
}
enum Accepted {
    Code,
    Recovery,
}
impl SecondFactor {
    fn accept(&mut self, input: &str) -> Option<Accepted> {
        let input: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .to_ascii_lowercase();
        let secret = totp::decode_base32(&self.secret)?;
        let now = (now_ms() / 1000) as u64;
        if let Some(step) = totp::verify(&secret, &input, now, self.used_through_step) {
            self.used_through_step = Some(step);
            return Some(Accepted::Code);
        }
        let hash = token_hash(&input);
        let position = self.recovery_hashes.iter().position(|h| *h == hash)?;
        self.recovery_hashes.remove(position);
        Some(Accepted::Recovery)
    }
}
fn factor_key(user: &str) -> String {
    format!("user_mfa:{user}")
}
fn read_factor(conn: &Connection, user: &str) -> Result<Option<SecondFactor>> {
    let saved: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [factor_key(user)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(saved.map(|s| serde_json::from_str(&s)).transpose()?)
}
fn write_factor(tx: &Transaction<'_>, user: &str, factor: &SecondFactor) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![factor_key(user), serde_json::to_string(factor)?])?;
    Ok(())
}
fn recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut raw = [0u8; 7];
            OsRng.fill_bytes(&mut raw);
            let code = totp::base32(&raw)[..10].to_ascii_lowercase();
            format!("{}-{}", &code[..5], &code[5..])
        })
        .collect()
}
/// Checks the active second factor of a user whose password was verified.
pub(super) fn check_second_factor(
    tx: &Transaction<'_>,
    user: &str,
    input: Option<&str>,
) -> Result<()> {
    let Some(mut factor) = read_factor(tx, user)?.filter(|f| f.enabled) else {
        return Ok(());
    };
    let Some(input) = input.filter(|s| !s.trim().is_empty()) else {
        return reject(401, SECOND_FACTOR_REQUIRED);
    };
    match factor.accept(input) {
        None => return reject(401, SECOND_FACTOR_INVALID),
        Some(Accepted::Recovery) => audit(
            tx,
            user,
            "mfa.recovery_code_used",
            user,
            &serde_json::json!({"remaining":factor.recovery_hashes.len()}).to_string(),
        )?,
        Some(Accepted::Code) => {}
    }
    write_factor(tx, user, &factor)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "nodes:write")]
    NodesWrite,
    #[serde(rename = "budgets:write")]
    BudgetsWrite,
    #[serde(rename = "users:write")]
    UsersWrite,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}
fn token_key(hash: &str) -> String {
    format!("api_token:{hash}")
}
#[derive(Serialize)]
pub struct SecondFactorStatus {
    pub enabled: bool,
    pub pending: bool,
    pub recovery_codes_remaining: usize,
}
#[derive(Serialize)]
pub struct SecondFactorSetup {
    pub secret: String,
    pub otpauth_uri: String,
}
#[derive(Serialize)]
pub struct UserSummary {
    #[serde(flatten)]
    pub user: Actor,
    pub mfa_enabled: bool,
    /// Combined bytes/second across every node, if limited.
    pub rate_bytes_per_sec: Option<u64>,
}

impl Store {
    /// Re-checks the caller's password for sensitive account changes, outside the store lock.
    fn confirm_password(&self, actor: &Actor, password: &str) -> Result<()> {
        let hash: String = self.0.lock().unwrap().query_row(
            "SELECT password_hash FROM users WHERE id=?1 AND disabled=0",
            [&actor.id],
            |r| r.get(0),
        )?;
        if password.len() > 1024 || !password_matches(&hash, password)? {
            return reject(403, "password confirmation failed");
        }
        Ok(())
    }
    pub fn second_factor_status(&self, actor: &Actor) -> Result<SecondFactorStatus> {
        let factor = read_factor(&self.0.lock().unwrap(), &actor.id)?;
        Ok(SecondFactorStatus {
            enabled: factor.as_ref().is_some_and(|f| f.enabled),
            pending: factor.as_ref().is_some_and(|f| !f.enabled),
            recovery_codes_remaining: factor.map_or(0, |f| f.recovery_hashes.len()),
        })
    }
    /// Stores a new pending secret; login is unchanged until it is confirmed.
    pub fn begin_second_factor(&self, actor: &Actor, password: &str) -> Result<SecondFactorSetup> {
        self.confirm_password(actor, password)?;
        let mut raw = [0u8; 20];
        OsRng.fill_bytes(&mut raw);
        let secret = totp::base32(&raw);
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if read_factor(&tx, &actor.id)?.is_some_and(|f| f.enabled) {
            return reject(409, "two-factor login is already enabled");
        }
        let factor = SecondFactor {
            secret: secret.clone(),
            enabled: false,
            used_through_step: None,
            recovery_hashes: vec![],
        };
        write_factor(&tx, &actor.id, &factor)?;
        tx.commit()?;
        Ok(SecondFactorSetup {
            otpauth_uri: totp::provisioning_uri("Relay", &actor.username, &secret),
            secret,
        })
    }
    /// Activates the pending secret and returns single-use recovery codes once.
    pub fn enable_second_factor(&self, actor: &Actor, code: &str) -> Result<Vec<String>> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let Some(mut factor) = read_factor(&tx, &actor.id)?.filter(|f| !f.enabled) else {
            return reject(409, "start two-factor setup first");
        };
        let secret = totp::decode_base32(&factor.secret).context("stored second factor invalid")?;
        let Some(step) = totp::verify(&secret, code.trim(), (now_ms() / 1000) as u64, None) else {
            return reject(400, SECOND_FACTOR_INVALID);
        };
        let codes = recovery_codes();
        factor.enabled = true;
        factor.used_through_step = Some(step);
        factor.recovery_hashes = codes
            .iter()
            .map(|c| token_hash(&c.replace('-', "")))
            .collect();
        write_factor(&tx, &actor.id, &factor)?;
        audit(&tx, &actor.id, "mfa.enable", &actor.id, "{}")?;
        tx.commit()?;
        Ok(codes)
    }
    pub fn disable_second_factor(&self, actor: &Actor, password: &str, code: &str) -> Result<()> {
        self.confirm_password(actor, password)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let Some(mut factor) = read_factor(&tx, &actor.id)? else {
            return reject(409, "two-factor login is not enabled");
        };
        if factor.enabled && factor.accept(code).is_none() {
            return reject(403, SECOND_FACTOR_INVALID);
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [factor_key(&actor.id)])?;
        audit(&tx, &actor.id, "mfa.disable", &actor.id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    /// Lockout recovery by an administrator; also ends the user's sessions and tokens.
    pub fn reset_second_factor(&self, actor: &Actor, user_id: &str) -> Result<()> {
        if actor.id == user_id {
            return reject(
                400,
                "use the account page to change your own two-factor login",
            );
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_user_manager(&tx, actor, user_id)?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [factor_key(user_id)])?;
        end_credentials(&tx, user_id)?;
        audit(&tx, &actor.id, "mfa.reset", user_id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    pub fn users(&self, actor: &Actor) -> Result<Vec<UserSummary>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare("SELECT u.id,u.tenant_id,u.username,u.role,COALESCE(json_extract(m.value,'$.enabled'),0),CAST(r.value AS INTEGER) FROM users u LEFT JOIN metadata m ON m.key='user_mfa:'||u.id LEFT JOIN metadata r ON r.key='user_rate:'||u.id WHERE (?1='system_admin' OR u.tenant_id=?2) ORDER BY u.username")?;
        Ok(
            q.query_map(params![actor.role.as_str(), actor.tenant_id], |r| {
                Ok(UserSummary {
                    user: actor_row(r)?,
                    mfa_enabled: r.get(4)?,
                    rate_bytes_per_sec: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?,
        )
    }

    pub fn create_api_token(
        &self,
        actor: &Actor,
        name: &str,
        scopes: &[Scope],
        expires_in_days: u32,
    ) -> Result<(String, ApiToken)> {
        if name.trim().is_empty() || name.chars().count() > 80 {
            return reject(400, "token name must contain 1..80 characters");
        }
        if scopes.is_empty() {
            return reject(400, "choose at least one scope");
        }
        if !(1..=365).contains(&expires_in_days) {
            return reject(400, "token lifetime must be 1..365 days");
        }
        let mut scopes = scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        let token = format!("{API_TOKEN_PREFIX}{}", secret());
        let record = ApiToken {
            id: Uuid::new_v4().to_string(),
            user_id: actor.id.clone(),
            name: name.trim().into(),
            scopes,
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + i64::from(expires_in_days) * 86_400_000,
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM metadata WHERE key GLOB 'api_token:*' AND json_extract(value,'$.user_id')=?1 AND json_extract(value,'$.expires_at_ms')<=?2", params![actor.id, now_ms()])?;
        let count: usize = tx.query_row("SELECT COUNT(*) FROM metadata WHERE key GLOB 'api_token:*' AND json_extract(value,'$.user_id')=?1", [&actor.id], |r| r.get(0))?;
        if count >= MAX_API_TOKENS {
            return reject(409, "API token limit reached; revoke an unused token first");
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![
                token_key(&token_hash(&token)),
                serde_json::to_string(&record)?
            ],
        )?;
        audit(
            &tx,
            &actor.id,
            "api_token.create",
            &record.id,
            &serde_json::json!({"scopes":record.scopes,"expires_at_ms":record.expires_at_ms})
                .to_string(),
        )?;
        tx.commit()?;
        Ok((token, record))
    }
    pub fn api_tokens(&self, actor: &Actor) -> Result<Vec<ApiToken>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'api_token:*' AND json_extract(value,'$.user_id')=?1 ORDER BY json_extract(value,'$.created_at_ms')")?;
        let rows = q.query_map([&actor.id], |r| r.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }
    pub fn revoke_api_token(&self, actor: &Actor, id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let removed = tx.execute("DELETE FROM metadata WHERE key GLOB 'api_token:*' AND json_extract(value,'$.user_id')=?1 AND json_extract(value,'$.id')=?2", params![actor.id, id])?;
        if removed == 0 {
            return reject(404, "API token not found");
        }
        audit(&tx, &actor.id, "api_token.revoke", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    /// Resolves a Bearer value to its user. API tokens also return their scopes;
    /// interactive sessions return `None` and keep full role permissions.
    pub fn authenticate(&self, token: &str) -> Result<(Actor, Option<Vec<Scope>>)> {
        let conn = self.0.lock().unwrap();
        if token.starts_with(API_TOKEN_PREFIX) {
            let found = conn.query_row("SELECT u.id,u.tenant_id,u.username,u.role,m.value FROM metadata m JOIN users u ON u.id=json_extract(m.value,'$.user_id') WHERE m.key=?1 AND json_extract(m.value,'$.expires_at_ms')>?2 AND u.disabled=0", params![token_key(&token_hash(token)), now_ms()], |r| Ok((actor_row(r)?, r.get::<_, String>(4)?))).optional()?;
            let Some((actor, record)) = found else {
                return reject(401, "API token expired or invalid");
            };
            let record: ApiToken = serde_json::from_str(&record)?;
            return Ok((actor, Some(record.scopes)));
        }
        conn.query_row("SELECT u.id,u.tenant_id,u.username,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.hash=?1 AND s.expires_at_ms>?2 AND u.disabled=0", params![token_hash(token),now_ms()], actor_row).optional()?
            .map(|actor| Ok((actor, None)))
            .unwrap_or_else(|| reject(401, "session expired or invalid"))
    }
}

/// Ends every interactive session and API token of a user.
pub(super) fn end_credentials(tx: &Transaction<'_>, user_id: &str) -> Result<()> {
    tx.execute("DELETE FROM sessions WHERE user_id=?1", [user_id])?;
    tx.execute(
        "DELETE FROM metadata WHERE key GLOB 'api_token:*' AND json_extract(value,'$.user_id')=?1",
        [user_id],
    )?;
    Ok(())
}
/// Same scope rule as session revocation: tenant writers manage their tenant,
/// and only system administrators manage system administrators.
pub(super) fn require_user_manager(
    conn: &Connection,
    actor: &Actor,
    user_id: &str,
) -> Result<Actor> {
    let user = conn
        .query_row(
            "SELECT id,tenant_id,username,role FROM users WHERE id=?1",
            [user_id],
            actor_row,
        )
        .optional()?;
    let Some(user) = user else {
        return reject(404, "user not found");
    };
    if !actor.may_write()
        || !actor.permits_tenant(&user.tenant_id)
        || (user.role == Role::SystemAdmin && actor.role != Role::SystemAdmin)
    {
        return reject(403, "insufficient user scope");
    }
    Ok(user)
}
