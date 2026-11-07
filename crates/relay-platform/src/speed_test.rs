//! Built-in speed tests (测速): what the controller asks an agent to run,
//! what the agent reports, the wire format between two agents and the
//! measurement maths. Agents never fetch addresses or run programs the
//! panel chooses: a task is one of four fixed kinds with bounded numbers,
//! and the public service is always Cloudflare's speed endpoints.
//!
//! Server ↔ server: the receiving server listens on a port the controller
//! chose; the other server dials it with a random per-test token in its
//! first bytes. Upload is the dialer sending, download the listener
//! sending, and the receiving side measures. Bytes go into 100 ms buckets
//! relative to the receiver's start of that direction; the first 2 s are
//! warm-up and are left out of the result.
use crate::store::reject;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// The public speed service. Only tests construct agents with another one.
pub const CLOUDFLARE: &str = "https://speed.cloudflare.com";
/// Left out of every result: TCP slow start and connection setup.
pub const WARMUP_MS: u64 = 2_000;
pub const BUCKET_MS: u64 = 100;
pub const MIN_SECS: u32 = 5;
pub const MAX_SECS: u32 = 60;
pub const DEFAULT_SECS: u32 = 10;
/// A byte amount per direction; the time limit of `MAX_SECS` still applies.
pub const MIN_BYTES: u64 = 1_000_000;
pub const MAX_BYTES: u64 = 1_000_000_000;
pub const MAX_STREAMS: u8 = 8;
/// Most tasks an agent runs or reports at once.
pub const MAX_TASKS: usize = 8;
/// Most error lines kept per direction, and their length.
pub const MAX_ERRORS: usize = 4;
pub const MAX_ERROR_LEN: usize = 200;
/// First bytes of every test connection: magic, token, direction, stream.
pub const MAGIC: &[u8; 8] = b"RLYSPD01";
pub const TOKEN_BYTES: usize = 32;
pub const HEADER_LEN: usize = MAGIC.len() + TOKEN_BYTES + 2;
/// Most buckets one stream's reply may carry: the longest direction plus
/// a grace period, at 100 ms each.
pub const MAX_BUCKETS: usize = ((WARMUP_MS + MAX_SECS as u64 * 1000 + 10_000) / BUCKET_MS) as usize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    /// From the testing (dialing) server towards the other end; on a path,
    /// towards the last hop.
    Upload,
    /// Towards the testing server; on a path, towards the entry.
    Download,
}
impl Direction {
    pub fn byte(self) -> u8 {
        match self {
            Self::Upload => b'U',
            Self::Download => b'D',
        }
    }
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'U' => Some(Self::Upload),
            b'D' => Some(Self::Download),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Directions {
    Upload,
    Download,
    Both,
}
impl Directions {
    pub fn list(self) -> Vec<Direction> {
        match self {
            Self::Upload => vec![Direction::Upload],
            Self::Download => vec![Direction::Download],
            Self::Both => vec![Direction::Upload, Direction::Download],
        }
    }
}

/// Parameters of a test, the same for every segment and direction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub direction: Directions,
    /// Seconds measured per direction, after the warm-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u32>,
    /// Bytes sent per direction instead of a duration; still stops after
    /// `MAX_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub streams: u8,
}
impl Params {
    /// Checks the bounds (400). Agents check them again.
    pub fn validate(&self) -> Result<()> {
        if self.duration_secs.is_some() && self.bytes.is_some() {
            return reject(400, "choose a duration or a byte amount, not both");
        }
        if let Some(secs) = self.duration_secs
            && !(MIN_SECS..=MAX_SECS).contains(&secs)
        {
            return reject(
                400,
                format!("the duration must be {MIN_SECS} to {MAX_SECS} seconds per direction"),
            );
        }
        if let Some(bytes) = self.bytes
            && !(MIN_BYTES..=MAX_BYTES).contains(&bytes)
        {
            return reject(
                400,
                format!("the byte amount must be {MIN_BYTES} to {MAX_BYTES} bytes per direction"),
            );
        }
        if !(1..=MAX_STREAMS).contains(&self.streams) {
            return reject(400, format!("parallel streams must be 1 to {MAX_STREAMS}"));
        }
        Ok(())
    }
    /// The duration used when neither a duration nor bytes is given.
    pub fn normalized(mut self) -> Self {
        if self.duration_secs.is_none() && self.bytes.is_none() {
            self.duration_secs = Some(DEFAULT_SECS);
        }
        self
    }
    /// How long one direction may send, warm-up included.
    pub fn limit_ms(&self) -> u64 {
        WARMUP_MS + u64::from(self.duration_secs.unwrap_or(MAX_SECS)) * 1000
    }
    /// The longest a whole task may run before both ends give up.
    pub fn hard_limit(&self) -> Duration {
        let directions = self.direction.list().len() as u64;
        Duration::from_millis(directions * (self.limit_ms() + 20_000) + 15_000)
    }
    /// Bytes one stream sends in byte mode.
    pub fn stream_bytes(&self) -> Option<u64> {
        self.bytes
            .map(|bytes| bytes.div_ceil(u64::from(self.streams.max(1))))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRole {
    /// Accept test connections on `listen` that present `token`.
    Listen,
    /// Connect to `address` (a listening agent) and send or receive.
    Dial,
    /// Download from and upload to the public speed service.
    Cloudflare,
    /// Time one TCP connect to `address` (a rule's target); no data.
    Connect,
}

/// One task for one agent, in [`crate::model::SyncResponse::speed_test_tasks`].
/// Unknown fields are ignored so a newer controller may add optional ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub role: TaskRole,
    pub params: Params,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// 64 hex digits; listen and dial tasks only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
impl Task {
    /// What an agent checks before running a task.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            crate::model::identifier(&self.id) && self.id.len() <= 80,
            "invalid speed test id"
        );
        self.params.validate()?;
        match self.role {
            TaskRole::Listen => {
                anyhow::ensure!(
                    self.listen.is_some_and(|l| l.port() != 0),
                    "a listen task needs an address"
                );
                anyhow::ensure!(
                    self.token.as_deref().and_then(parse_token).is_some(),
                    "a listen task needs a token"
                );
            }
            TaskRole::Dial => {
                anyhow::ensure!(
                    self.address
                        .as_deref()
                        .is_some_and(|a| crate::model::validate_target(a).is_ok()),
                    "a dial task needs host:port"
                );
                anyhow::ensure!(
                    self.token.as_deref().and_then(parse_token).is_some(),
                    "a dial task needs a token"
                );
            }
            TaskRole::Cloudflare => {}
            TaskRole::Connect => anyhow::ensure!(
                self.address
                    .as_deref()
                    .is_some_and(|a| crate::model::validate_target(a).is_ok()),
                "a connect task needs host:port"
            ),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Finished,
    Failed,
}

/// Results of one direction, measured by the receiving side.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectionResult {
    pub direction: Direction,
    /// Bytes received in the measured window (after the warm-up).
    pub bytes: u64,
    pub measured_ms: u64,
    pub average_bps: u64,
    /// The most bits received in any 1 s of the measured window.
    pub peak_bps: u64,
    pub streams: u8,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub failed_streams: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// The public speed service refused further requests (HTTP 429) after
    /// part of this direction; the result covers what came before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub limited: bool,
}

/// One task's state in an agent's report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReport {
    pub id: String,
    pub state: TaskState,
    /// The direction running now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Direction>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub elapsed_ms: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes: u64,
    /// Bits in the last second.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub current_bps: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<DirectionResult>,
    /// TCP connect time of a connect task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_us: Option<u64>,
    /// Connections a listener closed: wrong token, wrong format or too many.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rejected: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
impl TaskReport {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            state: TaskState::Running,
            phase: None,
            elapsed_ms: 0,
            bytes: 0,
            current_bps: 0,
            results: vec![],
            connect_us: None,
            rejected: 0,
            error: None,
        }
    }
    pub fn failed(id: &str, error: impl std::fmt::Display) -> Self {
        Self {
            state: TaskState::Failed,
            error: Some(clip(&error.to_string())),
            ..Self::new(id)
        }
    }
}

/// What an agent reports in [`crate::model::EngineStats::speed_test`]; that
/// it reports at all tells the controller it runs speed tests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<TaskReport>,
}
impl Report {
    pub fn within_limits(&self) -> bool {
        self.tasks.len() <= MAX_TASKS
            && self.tasks.iter().all(|t| {
                t.id.len() <= 80
                    && t.error
                        .as_ref()
                        .is_none_or(|e| e.len() <= 4 * MAX_ERROR_LEN)
                    && t.results.len() <= 2
                    && t.results.iter().all(|r| {
                        r.errors.len() <= MAX_ERRORS
                            && r.errors.iter().all(|e| e.len() <= 4 * MAX_ERROR_LEN)
                    })
            })
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

/// At most `MAX_ERROR_LEN` characters.
pub fn clip(text: &str) -> String {
    text.chars().take(MAX_ERROR_LEN).collect()
}

pub fn parse_token(hex: &str) -> Option<[u8; TOKEN_BYTES]> {
    if hex.len() != TOKEN_BYTES * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut token = [0u8; TOKEN_BYTES];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(token)
}

/// The first bytes a dialer sends on each stream.
pub fn header(token: &[u8; TOKEN_BYTES], direction: Direction, stream: u8) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()..MAGIC.len() + TOKEN_BYTES].copy_from_slice(token);
    header[HEADER_LEN - 2] = direction.byte();
    header[HEADER_LEN - 1] = stream;
    header
}

/// The direction and stream of a header carrying `token`; `None` for any
/// other bytes. The token is compared in constant time.
pub fn check_header(token: &[u8; TOKEN_BYTES], header: &[u8]) -> Option<(Direction, u8)> {
    if header.len() != HEADER_LEN {
        return None;
    }
    let magic = header[..MAGIC.len()].ct_eq(MAGIC);
    let presented = header[MAGIC.len()..MAGIC.len() + TOKEN_BYTES].ct_eq(token);
    if !bool::from(magic & presented) {
        return None;
    }
    let stream = header[HEADER_LEN - 1];
    if stream >= MAX_STREAMS {
        return None;
    }
    Some((Direction::from_byte(header[HEADER_LEN - 2])?, stream))
}

/// Received bytes per 100 ms since the start of a direction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Buckets(pub Vec<u64>);
impl Buckets {
    pub fn add(&mut self, elapsed: Duration, bytes: u64) {
        let index = (elapsed.as_millis() / u128::from(BUCKET_MS)) as usize;
        if index >= MAX_BUCKETS {
            return;
        }
        if self.0.len() <= index {
            self.0.resize(index + 1, 0);
        }
        self.0[index] = self.0[index].saturating_add(bytes);
    }
    pub fn merge(&mut self, other: &[u64]) {
        if self.0.len() < other.len() {
            self.0.resize(other.len().min(MAX_BUCKETS), 0);
        }
        for (mine, theirs) in self.0.iter_mut().zip(other) {
            *mine = mine.saturating_add(*theirs);
        }
    }
    pub fn total(&self) -> u64 {
        self.0.iter().fold(0u64, |sum, b| sum.saturating_add(*b))
    }
    /// Bits in the last full second before `elapsed`.
    pub fn recent_bps(&self, elapsed: Duration) -> u64 {
        let end = ((elapsed.as_millis() / u128::from(BUCKET_MS)) as usize).min(self.0.len());
        let start = end.saturating_sub((1000 / BUCKET_MS) as usize);
        self.0[start..end]
            .iter()
            .fold(0u64, |sum, b| sum.saturating_add(*b))
            .saturating_mul(8)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub bytes: u64,
    pub measured_ms: u64,
    pub average_bps: u64,
    pub peak_bps: u64,
}

/// The result of one direction from its buckets. The window runs from the
/// end of the warm-up to the last bucket with data, at most `limit_ms`
/// after the start. A transfer that ended within a second of the warm-up
/// (a small byte amount) is measured whole instead. The peak is the most
/// bits in any 10 consecutive buckets of the window; a window shorter than
/// a second has the average as its peak.
pub fn summarize(buckets: &[u64], limit_ms: u64) -> Summary {
    let per_second = (1000 / BUCKET_MS) as usize;
    let limit = (limit_ms / BUCKET_MS) as usize;
    let end = buckets
        .iter()
        .rposition(|b| *b > 0)
        .map_or(0, |last| last + 1)
        .min(limit)
        .min(buckets.len());
    let warmup = (WARMUP_MS / BUCKET_MS) as usize;
    let start = if end >= warmup + per_second {
        warmup
    } else {
        0
    };
    if end <= start {
        return Summary::default();
    }
    let window = &buckets[start..end];
    let bytes = window.iter().fold(0u64, |sum, b| sum.saturating_add(*b));
    let measured_ms = (end - start) as u64 * BUCKET_MS;
    let average_bps = (u128::from(bytes) * 8 * 1000 / u128::from(measured_ms)) as u64;
    let peak_bps = if window.len() < per_second {
        average_bps
    } else {
        window
            .windows(per_second)
            .map(|w| w.iter().fold(0u64, |sum, b| sum.saturating_add(*b)))
            .max()
            .unwrap_or(0)
            .saturating_mul(8)
    };
    Summary {
        bytes,
        measured_ms,
        average_bps,
        peak_bps,
    }
}

/// The reply a listener sends after an upload stream: its buckets.
pub fn encode_buckets(buckets: &[u64]) -> Vec<u8> {
    let buckets = &buckets[..buckets.len().min(MAX_BUCKETS)];
    let mut out = Vec::with_capacity(4 + buckets.len() * 8);
    out.extend_from_slice(&(buckets.len() as u32).to_be_bytes());
    for bucket in buckets {
        out.extend_from_slice(&bucket.to_be_bytes());
    }
    out
}

// ---- The panel's API ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Started by an administrator between two servers or to Cloudflare.
    Server,
    /// Every segment of a rule's path.
    Path,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Cloudflare,
    Server,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Running,
    Finished,
    Failed,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    Running,
    Finished,
    Failed,
    Cancelled,
}
impl StepState {
    pub fn ended(self) -> bool {
        matches!(self, Self::Finished | Self::Failed | Self::Cancelled)
    }
}

fn four() -> u8 {
    4
}

/// `POST /api/v1/speed-tests`: a server test (system administrators).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTestInput {
    pub mode: Mode,
    /// The testing server: it dials, or downloads from Cloudflare.
    pub node_id: String,
    /// The receiving server of a server ↔ server test.
    #[serde(default)]
    pub peer_node_id: Option<String>,
    /// The receiving server's test port; omitted picks a free one from its
    /// forwarding port range.
    #[serde(default)]
    pub port: Option<u16>,
    pub direction: Directions,
    #[serde(default)]
    pub duration_secs: Option<u32>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default = "four")]
    pub streams: u8,
}

/// `POST /api/v1/speed-tests/path`: every segment of a rule's path.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathTestInput {
    pub node_id: String,
    pub rule_id: String,
    pub direction: Directions,
    #[serde(default)]
    pub duration_secs: Option<u32>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default = "four")]
    pub streams: u8,
}

/// One measured segment: a server to Cloudflare, or a dialing server to a
/// receiving one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub from_node_id: String,
    pub from_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_name: Option<String>,
    /// On a path: the rule on the dialing server whose target this follows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Where the receiving server listens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
    /// What the dialing server connects to, or the public service.
    pub address: String,
    pub state: StepState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<DirectionResult>,
    /// Connections the listener closed (wrong token or format).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rejected_connections: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<i64>,
}
impl Segment {
    /// The slower direction's average, for naming the slowest segment.
    pub fn slowest_bps(&self) -> Option<u64> {
        self.results
            .iter()
            .filter(|r| r.measured_ms > 0)
            .map(|r| r.average_bps)
            .min()
    }
}

/// The last hop's TCP connect to the rule's target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProbe {
    pub node_id: String,
    pub node_name: String,
    pub rule_id: String,
    pub address: String,
    pub state: StepState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Rule,
    Server,
}
/// A configured limit along a path, shown next to the results: the test
/// does not pass through the rule, so none of them applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLimit {
    pub kind: LimitKind,
    pub node_id: String,
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    pub rate_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<crate::model::RateLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    pub node_id: String,
    pub rule_id: String,
    pub name: String,
}

/// A test as kept in metadata `speed_test:<id>`. Its tokens are kept apart
/// in `speed_test_token:<id>` and go only to the agents, never into views
/// or the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub kind: Kind,
    pub mode: Mode,
    pub tenant_id: String,
    pub started_by: String,
    pub started_by_name: String,
    pub params: Params,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<PathRule>,
    /// Every server taking part; each runs one test at a time.
    pub node_ids: Vec<String>,
    pub segments: Vec<Segment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetProbe>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<PathLimit>,
    pub state: JobState,
    /// The step running now: a segment, then the target probe.
    pub step: usize,
    pub step_started_ms: i64,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The running segment's live numbers, from the agents' latest reports.
#[derive(Clone, Debug, Serialize)]
pub struct Progress {
    pub segment: usize,
    pub direction: Option<Direction>,
    pub elapsed_ms: u64,
    pub bytes: u64,
    pub current_bps: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobView {
    #[serde(flatten)]
    pub job: Job,
    pub progress: Option<Progress>,
    /// On a path, the segment with the lowest average once measured.
    pub slowest_segment: Option<usize>,
    /// Always false: test traffic bypasses rules, so no limit, meter,
    /// quota or budget applies to it.
    pub metered: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlanHop {
    pub node_id: String,
    pub node_name: String,
    pub rule_id: String,
    pub rule_name: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct PlanSegment {
    pub from_node_id: String,
    pub from_name: String,
    pub to_node_id: String,
    pub to_name: String,
    pub rule_id: String,
    /// The target address of the rule on the dialing server; the test
    /// dials its host on a test port.
    pub target_address: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct PlanTarget {
    pub node_id: String,
    pub node_name: String,
    pub rule_id: String,
    pub address: String,
}
/// `GET /api/v1/speed-tests/path`: what a path test of a rule measures, the
/// limits along it, and why it cannot start now if it cannot.
#[derive(Clone, Debug, Serialize)]
pub struct PathPlan {
    pub node_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub hops: Vec<PlanHop>,
    pub segments: Vec<PlanSegment>,
    pub target: Option<PlanTarget>,
    pub limits: Vec<PathLimit>,
    pub reason: Option<String>,
    pub metered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(duration: Option<u32>, bytes: Option<u64>, streams: u8) -> Params {
        Params {
            direction: Directions::Both,
            duration_secs: duration,
            bytes,
            streams,
        }
    }

    #[test]
    fn parameters_are_bounded() {
        assert!(params(Some(5), None, 1).validate().is_ok());
        assert!(params(Some(60), None, 8).validate().is_ok());
        assert!(params(None, Some(MIN_BYTES), 1).validate().is_ok());
        assert!(params(None, Some(MAX_BYTES), 8).validate().is_ok());
        for bad in [
            params(Some(4), None, 1),
            params(Some(61), None, 1),
            params(Some(10), None, 0),
            params(Some(10), None, 9),
            params(None, Some(MIN_BYTES - 1), 1),
            params(None, Some(MAX_BYTES + 1), 1),
            params(Some(10), Some(MIN_BYTES), 1),
        ] {
            let error = bad.validate().unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<crate::store::Rejection>()
                    .unwrap()
                    .status,
                400,
                "{bad:?}"
            );
        }
        let normalized = params(None, None, 2).normalized();
        assert_eq!(normalized.duration_secs, Some(DEFAULT_SECS));
        assert_eq!(normalized.limit_ms(), WARMUP_MS + 10_000);
        // A byte amount is still cut at the longest duration.
        assert_eq!(
            params(None, Some(MIN_BYTES), 3).limit_ms(),
            WARMUP_MS + 60_000
        );
        assert_eq!(params(None, Some(10), 3).stream_bytes(), Some(4));
        assert!(params(Some(60), None, 8).hard_limit() < Duration::from_secs(200));
    }

    #[test]
    fn tasks_are_checked_before_they_run() {
        let token = "ab".repeat(32);
        let task = |role, listen: Option<&str>, address: Option<&str>, token: Option<&str>| Task {
            id: "job-0".into(),
            role,
            params: params(Some(5), None, 2),
            listen: listen.map(|l| l.parse().unwrap()),
            address: address.map(str::to_owned),
            token: token.map(str::to_owned),
        };
        assert!(
            task(TaskRole::Listen, Some("0.0.0.0:29999"), None, Some(&token))
                .validate()
                .is_ok()
        );
        assert!(
            task(TaskRole::Listen, Some("0.0.0.0:29999"), None, None)
                .validate()
                .is_err()
        );
        assert!(
            task(TaskRole::Listen, Some("0.0.0.0:0"), None, Some(&token))
                .validate()
                .is_err()
        );
        assert!(
            task(
                TaskRole::Dial,
                None,
                Some("gw.example.net:40001"),
                Some(&token)
            )
            .validate()
            .is_ok()
        );
        assert!(
            task(TaskRole::Dial, None, Some("http://x/"), Some(&token))
                .validate()
                .is_err()
        );
        assert!(
            task(
                TaskRole::Dial,
                None,
                Some("gw.example.net:40001"),
                Some("00")
            )
            .validate()
            .is_err()
        );
        assert!(
            task(TaskRole::Cloudflare, None, None, None)
                .validate()
                .is_ok()
        );
        assert!(
            task(TaskRole::Connect, None, Some("192.0.2.1:443"), None)
                .validate()
                .is_ok()
        );
        assert!(
            task(TaskRole::Connect, None, None, None)
                .validate()
                .is_err()
        );
        let mut long = task(TaskRole::Cloudflare, None, None, None);
        long.params.streams = 9;
        assert!(long.validate().is_err());
    }

    #[test]
    fn only_the_right_token_opens_a_stream() {
        let token = parse_token(&"5a".repeat(32)).unwrap();
        assert_eq!(token, [0x5a; 32]);
        assert!(parse_token("5a").is_none());
        assert!(parse_token(&"zz".repeat(32)).is_none());
        let good = header(&token, Direction::Download, 3);
        assert_eq!(check_header(&token, &good), Some((Direction::Download, 3)));
        assert_eq!(
            check_header(&token, &header(&token, Direction::Upload, 0)),
            Some((Direction::Upload, 0))
        );
        let mut wrong = token;
        wrong[31] ^= 1;
        assert_eq!(
            check_header(&token, &header(&wrong, Direction::Upload, 0)),
            None
        );
        let mut magic = good;
        magic[0] = b'X';
        assert_eq!(check_header(&token, &magic), None);
        let mut direction = good;
        direction[HEADER_LEN - 2] = b'Q';
        assert_eq!(check_header(&token, &direction), None);
        let mut stream = good;
        stream[HEADER_LEN - 1] = MAX_STREAMS;
        assert_eq!(check_header(&token, &stream), None);
        assert_eq!(check_header(&token, &good[..HEADER_LEN - 1]), None);
        assert_eq!(
            check_header(&token, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n12345"),
            None
        );
    }

    #[test]
    fn warm_up_is_left_out_of_the_average() {
        // 12 s at 100 ms: 1 MB per bucket during the warm-up, 125 kB after
        // (10 Mbit/s), so a result that counted the warm-up would be wrong.
        let mut buckets = vec![1_000_000u64; 20];
        buckets.extend(std::iter::repeat_n(125_000u64, 100));
        let summary = summarize(&buckets, WARMUP_MS + 10_000);
        assert_eq!(summary.bytes, 12_500_000);
        assert_eq!(summary.measured_ms, 10_000);
        assert_eq!(summary.average_bps, 10_000_000);
        assert_eq!(summary.peak_bps, 10_000_000);
    }

    #[test]
    fn the_peak_is_the_busiest_second() {
        // 4 s measured: 1 Mbit/s, except 1.5 s at 8 Mbit/s in the middle.
        let mut buckets = vec![0u64; 20];
        buckets.extend(std::iter::repeat_n(12_500u64, 10));
        buckets.extend(std::iter::repeat_n(100_000u64, 15));
        buckets.extend(std::iter::repeat_n(12_500u64, 15));
        let summary = summarize(&buckets, WARMUP_MS + 60_000);
        assert_eq!(summary.measured_ms, 4_000);
        assert_eq!(summary.bytes, 25 * 12_500 + 15 * 100_000);
        assert_eq!(summary.average_bps, (25 * 12_500 + 15 * 100_000) * 8 / 4);
        assert_eq!(summary.peak_bps, 8_000_000);
        assert!(summary.peak_bps > summary.average_bps);
    }

    #[test]
    fn the_window_ends_at_the_last_data_or_the_limit() {
        // Data stops after 5 s although 10 s were allowed: measured 3 s.
        let mut buckets = vec![50_000u64; 50];
        buckets.extend(std::iter::repeat_n(0u64, 70));
        let summary = summarize(&buckets, WARMUP_MS + 10_000);
        assert_eq!(summary.measured_ms, 3_000);
        assert_eq!(summary.average_bps, 4_000_000);
        // Bytes after the limit (a late tail) are not counted.
        let buckets = vec![50_000u64; 200];
        let summary = summarize(&buckets, WARMUP_MS + 5_000);
        assert_eq!(summary.measured_ms, 5_000);
        assert_eq!(summary.bytes, 50 * 50_000);
        // A stall inside the window counts as time without bytes.
        let mut buckets = vec![50_000u64; 30];
        buckets.extend(std::iter::repeat_n(0u64, 10));
        buckets.extend(std::iter::repeat_n(50_000u64, 10));
        let summary = summarize(&buckets, WARMUP_MS + 10_000);
        assert_eq!(summary.measured_ms, 3_000);
        assert_eq!(summary.bytes, 20 * 50_000);
        assert_eq!(summary.peak_bps, 4_000_000);
    }

    #[test]
    fn short_transfers_are_measured_whole() {
        // A byte amount done in 1.5 s: there is no window after the warm-up.
        let buckets = vec![100_000u64; 15];
        let summary = summarize(&buckets, WARMUP_MS + 60_000);
        assert_eq!(summary.measured_ms, 1_500);
        assert_eq!(summary.bytes, 1_500_000);
        assert_eq!(summary.average_bps, 8_000_000);
        // Under a second: the peak is the average.
        let summary = summarize(&[100_000u64; 5], WARMUP_MS + 60_000);
        assert_eq!((summary.measured_ms, summary.peak_bps), (500, 8_000_000));
        assert_eq!(summarize(&[], WARMUP_MS + 5_000), Summary::default());
        assert_eq!(summarize(&[0; 80], WARMUP_MS + 5_000), Summary::default());
    }

    #[test]
    fn buckets_add_merge_and_encode() {
        let mut a = Buckets::default();
        a.add(Duration::from_millis(50), 10);
        a.add(Duration::from_millis(99), 5);
        a.add(Duration::from_millis(250), 7);
        a.add(Duration::from_secs(3600), 1_000);
        assert_eq!(a.0, vec![15, 0, 7]);
        let mut b = Buckets(vec![1, 1, 1, 1]);
        b.merge(&a.0);
        assert_eq!(b.0, vec![16, 1, 8, 1]);
        assert_eq!(b.total(), 26);
        assert_eq!(b.recent_bps(Duration::from_millis(400)), 26 * 8);
        let encoded = encode_buckets(&b.0);
        assert_eq!(encoded.len(), 4 + 4 * 8);
        assert_eq!(&encoded[..4], &4u32.to_be_bytes());
        assert_eq!(&encoded[4..12], &16u64.to_be_bytes());
    }

    #[test]
    fn reports_are_bounded() {
        let mut report = Report {
            tasks: vec![TaskReport::new("a"); MAX_TASKS],
        };
        assert!(report.within_limits());
        report.tasks.push(TaskReport::new("b"));
        assert!(!report.within_limits());
        let mut task = TaskReport::failed("a", "x".repeat(1000));
        assert_eq!(task.error.as_ref().unwrap().len(), MAX_ERROR_LEN);
        task.results = vec![DirectionResult::default(); 3];
        assert!(!Report { tasks: vec![task] }.within_limits());
    }
}
