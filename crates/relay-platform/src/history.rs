//! Seven days of per-node report figures and per-hop connection outcomes,
//! summed into five-minute buckets. They live in their own SQLite file beside
//! the controller database, outside its backups and recovery log: losing the
//! file loses charts, never configuration or usage.
use crate::model::ConnectionCounts;
use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::{collections::HashMap, fs, path::Path, sync::Mutex, time::Duration};
use tokio_util::sync::CancellationToken;

pub const BUCKET_MS: i64 = 5 * 60_000;
pub const RETAIN_MS: i64 = 7 * 24 * 60 * 60_000;

pub fn bucket(at_ms: i64) -> i64 {
    at_ms.div_euclid(BUCKET_MS) * BUCKET_MS
}

/// Sums over one node's reports in one bucket; averages divide by `reports`
/// or by the matching `*_count`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct NodeBucket {
    pub reports: u64,
    pub forwarded_bytes: u64,
    pub sessions_sum: u64,
    pub sessions_max: u64,
    pub latency_sum_us: u64,
    pub latency_count: u64,
    pub healthy_sum: u64,
    pub probed_sum: u64,
    pub cpu_sum: f64,
    pub cpu_count: u64,
}
impl NodeBucket {
    pub fn add(&mut self, other: &Self) {
        self.reports += other.reports;
        self.forwarded_bytes += other.forwarded_bytes;
        self.sessions_sum += other.sessions_sum;
        self.sessions_max = self.sessions_max.max(other.sessions_max);
        self.latency_sum_us += other.latency_sum_us;
        self.latency_count += other.latency_count;
        self.healthy_sum += other.healthy_sum;
        self.probed_sum += other.probed_sum;
        self.cpu_sum += other.cpu_sum;
        self.cpu_count += other.cpu_count;
    }
}

/// One hop of one rule on one node: the inbound side (`target_index` is
/// `None`) or a configured target.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct HopKey {
    pub node_id: String,
    pub rule_id: String,
    pub target_index: Option<usize>,
    pub target_address: String,
}

/// Buckets keyed by their start time.
#[derive(Default)]
pub struct Buckets {
    pub nodes: HashMap<(String, i64), NodeBucket>,
    pub hops: HashMap<(HopKey, i64), ConnectionCounts>,
}
impl Buckets {
    pub fn merge(&mut self, other: Buckets) {
        for (key, value) in other.nodes {
            self.nodes.entry(key).or_default().add(&value);
        }
        for (key, value) in other.hops {
            self.hops.entry(key).or_default().add(&value);
        }
    }
}

pub struct History(Mutex<Connection>);

impl History {
    pub fn open(path: &Path) -> Result<Self> {
        if path.exists() {
            ensure!(
                !fs::symlink_metadata(path)?.file_type().is_symlink(),
                "history database cannot be a symbolic link"
            );
        } else {
            crate::store::write_secret(path, b"")?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                "history database permissions must be 0600"
            );
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 1, "history database newer than this binary");
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS node_buckets(node_id TEXT NOT NULL, at_ms INTEGER NOT NULL,
              reports INTEGER NOT NULL, forwarded_bytes INTEGER NOT NULL,
              sessions_sum INTEGER NOT NULL, sessions_max INTEGER NOT NULL,
              latency_sum_us INTEGER NOT NULL, latency_count INTEGER NOT NULL,
              healthy_sum INTEGER NOT NULL, probed_sum INTEGER NOT NULL,
              cpu_sum REAL NOT NULL, cpu_count INTEGER NOT NULL,
              PRIMARY KEY(node_id, at_ms)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS hop_buckets(node_id TEXT NOT NULL, rule_id TEXT NOT NULL,
              target_index INTEGER NOT NULL, target_address TEXT NOT NULL, at_ms INTEGER NOT NULL,
              attempts INTEGER NOT NULL, connected INTEGER NOT NULL, timeout INTEGER NOT NULL,
              refused INTEGER NOT NULL, dns INTEGER NOT NULL, closed INTEGER NOT NULL,
              other INTEGER NOT NULL, connect_us INTEGER NOT NULL,
              PRIMARY KEY(node_id, rule_id, target_index, target_address, at_ms)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS node_buckets_at ON node_buckets(at_ms);
            CREATE INDEX IF NOT EXISTS hop_buckets_at ON hop_buckets(at_ms);
            PRAGMA user_version=1;",
        )?;
        Ok(Self(Mutex::new(conn)))
    }

    /// Adds `buckets` to what is stored and drops buckets older than seven days.
    pub fn write(&self, buckets: &Buckets, now_ms: i64) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut node = tx.prepare_cached(
                "INSERT INTO node_buckets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                ON CONFLICT DO UPDATE SET reports=reports+excluded.reports,
                  forwarded_bytes=forwarded_bytes+excluded.forwarded_bytes,
                  sessions_sum=sessions_sum+excluded.sessions_sum,
                  sessions_max=max(sessions_max,excluded.sessions_max),
                  latency_sum_us=latency_sum_us+excluded.latency_sum_us,
                  latency_count=latency_count+excluded.latency_count,
                  healthy_sum=healthy_sum+excluded.healthy_sum,
                  probed_sum=probed_sum+excluded.probed_sum,
                  cpu_sum=cpu_sum+excluded.cpu_sum, cpu_count=cpu_count+excluded.cpu_count",
            )?;
            for ((id, at), b) in &buckets.nodes {
                node.execute(params![
                    id,
                    at,
                    b.reports,
                    b.forwarded_bytes,
                    b.sessions_sum,
                    b.sessions_max,
                    b.latency_sum_us,
                    b.latency_count,
                    b.healthy_sum,
                    b.probed_sum,
                    b.cpu_sum,
                    b.cpu_count
                ])?;
            }
            let mut hop = tx.prepare_cached(
                "INSERT INTO hop_buckets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                ON CONFLICT DO UPDATE SET attempts=attempts+excluded.attempts,
                  connected=connected+excluded.connected, timeout=timeout+excluded.timeout,
                  refused=refused+excluded.refused, dns=dns+excluded.dns,
                  closed=closed+excluded.closed, other=other+excluded.other,
                  connect_us=connect_us+excluded.connect_us",
            )?;
            for ((key, at), c) in &buckets.hops {
                hop.execute(params![
                    key.node_id,
                    key.rule_id,
                    key.target_index.map_or(-1, |i| i as i64),
                    key.target_address,
                    at,
                    c.attempts,
                    c.connected,
                    c.timeout,
                    c.refused,
                    c.dns,
                    c.closed,
                    c.other,
                    c.connect_us
                ])?;
            }
            let cutoff = now_ms - RETAIN_MS;
            tx.execute("DELETE FROM node_buckets WHERE at_ms<?1", [cutoff])?;
            tx.execute("DELETE FROM hop_buckets WHERE at_ms<?1", [cutoff])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stored buckets of `nodes` starting at or after `since_ms`.
    pub fn read(&self, nodes: &[String], since_ms: i64) -> Result<Buckets> {
        let conn = self.0.lock().unwrap();
        let mut buckets = Buckets::default();
        let mut q = conn.prepare_cached("SELECT * FROM node_buckets WHERE at_ms>=?1")?;
        let mut rows = q.query([since_ms])?;
        while let Some(r) = rows.next()? {
            let id: String = r.get(0)?;
            if !nodes.contains(&id) {
                continue;
            }
            let bucket = NodeBucket {
                reports: r.get(2)?,
                forwarded_bytes: r.get(3)?,
                sessions_sum: r.get(4)?,
                sessions_max: r.get(5)?,
                latency_sum_us: r.get(6)?,
                latency_count: r.get(7)?,
                healthy_sum: r.get(8)?,
                probed_sum: r.get(9)?,
                cpu_sum: r.get(10)?,
                cpu_count: r.get(11)?,
            };
            buckets.nodes.insert((id, r.get(1)?), bucket);
        }
        let mut q = conn.prepare_cached("SELECT * FROM hop_buckets WHERE at_ms>=?1")?;
        let mut rows = q.query([since_ms])?;
        while let Some(r) = rows.next()? {
            let node_id: String = r.get(0)?;
            if !nodes.contains(&node_id) {
                continue;
            }
            let index: i64 = r.get(2)?;
            let key = HopKey {
                node_id,
                rule_id: r.get(1)?,
                target_index: usize::try_from(index).ok(),
                target_address: r.get(3)?,
            };
            let counts = ConnectionCounts {
                attempts: r.get(5)?,
                connected: r.get(6)?,
                timeout: r.get(7)?,
                refused: r.get(8)?,
                dns: r.get(9)?,
                closed: r.get(10)?,
                other: r.get(11)?,
                connect_us: r.get(12)?,
            };
            buckets.hops.insert((key, r.get(4)?), counts);
        }
        Ok(buckets)
    }
}

/// Writes the controller's pending buckets every `tick`, and once more on stop.
pub async fn run(store: crate::store::Store, tick: Duration, stop: CancellationToken) {
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        let stopping = tokio::select! {
            biased;
            _ = stop.cancelled() => true,
            _ = interval.tick() => false,
        };
        let db = store.clone();
        match tokio::task::spawn_blocking(move || db.flush_history()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "history write failed; these buckets are lost")
            }
            Err(_) => return,
        }
        if stopping {
            return;
        }
    }
}
