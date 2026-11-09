//! The controller's block records, kept in their own SQLite file beside the
//! controller database (`blocks.sqlite`), outside its backups and recovery
//! log, like [`crate::history`]: losing the file loses diagnostic records,
//! never configuration or usage. A controller restart keeps them, and keeps
//! where each node's records end ([`Cursor`]), so an agent sends only what
//! changed since.
//!
//! One row per record of one agent run (`stream`) and its id; a record sent
//! again with the same or an older `seq` changes nothing, and a grown one
//! replaces its row, so counts are never added twice. Each change takes the
//! next value of a counter, which orders the records and pages them. A node
//! keeps at most [`Retention::per_node`] rows, the oldest change first to go,
//! and rows go [`Retention::days`] after their latest change, checked when
//! the file opens and then at most once a minute while records arrive; so
//! neither the rows nor the source addresses in them grow without bound.
//! Each row keeps the tenant of its rule when it arrived, for who may read it.
use crate::connections::{BlockBatch, BlockView, Cursor, Retention};
use crate::model::identifier;
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

const DAY_MS: i64 = 24 * 60 * 60_000;
/// Age pruning while records arrive runs at most this often.
const PRUNE_EVERY_MS: i64 = 60_000;
pub const MAX_PAGE: usize = 1000;
/// A page of one rule's records, and of all the node's, each from its index.
const READ_RULE: &str =
    "SELECT change,rule_id,protocol,source,reason,detail,first_ms,last_ms,count FROM block_records
     WHERE node_id=?1 AND rule_id=?2 AND change<?4 AND (?3 IS NULL OR tenant_id=?3)
     ORDER BY change DESC LIMIT ?5";
const READ_NODE: &str =
    "SELECT change,rule_id,protocol,source,reason,detail,first_ms,last_ms,count FROM block_records
     WHERE node_id=?1 AND change<?4 AND (?3 IS NULL OR tenant_id=?3)
     ORDER BY change DESC LIMIT ?5";

pub struct Records {
    conn: Mutex<Connection>,
    retention: Retention,
    pruned_ms: AtomicI64,
    /// Whether the latest write failed, so that failures are logged once.
    failing: AtomicBool,
}

/// Which records a reader asks for and may see.
pub struct Query<'a> {
    pub node: &'a str,
    pub rule: Option<&'a str>,
    /// `None` for system administrators; otherwise only this tenant's.
    pub tenant: Option<&'a str>,
    /// Only records whose latest change came before this page cursor.
    pub before: Option<i64>,
    pub limit: usize,
}

impl Records {
    pub fn open(path: &Path, retention: Retention, now_ms: i64) -> Result<Self> {
        ensure!(
            Retention::DAYS.contains(&retention.days)
                && Retention::PER_NODE.contains(&retention.per_node),
            "block record retention must be 1..=365 days and 100..=100000 records per server"
        );
        if path.exists() {
            ensure!(
                !fs::symlink_metadata(path)?.file_type().is_symlink(),
                "block record database cannot be a symbolic link"
            );
        } else {
            crate::store::write_secret(path, b"")?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                "block record database permissions must be 0600"
            );
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 1, "block record database newer than this binary");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        if version == 0 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TABLE block_records(node_id TEXT NOT NULL, stream TEXT NOT NULL,
                  record_id INTEGER NOT NULL, seq INTEGER NOT NULL, change INTEGER NOT NULL,
                  received_ms INTEGER NOT NULL, tenant_id TEXT, rule_id TEXT NOT NULL,
                  protocol TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
                  detail TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,
                  count INTEGER NOT NULL, PRIMARY KEY(node_id, stream, record_id)) WITHOUT ROWID;
                CREATE INDEX block_records_change ON block_records(node_id, change);
                CREATE INDEX block_records_rule ON block_records(node_id, rule_id, change);
                CREATE INDEX block_records_received ON block_records(received_ms);
                CREATE TABLE block_cursors(node_id TEXT PRIMARY KEY, stream TEXT NOT NULL,
                  seq INTEGER NOT NULL) WITHOUT ROWID;
                CREATE TABLE block_counter(id INTEGER PRIMARY KEY CHECK(id=1), change INTEGER NOT NULL);
                INSERT INTO block_counter VALUES(1, 0);
                PRAGMA user_version=1;",
            )?;
            tx.commit()?;
        }
        // Version 1 files made before this index existed get it too.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS block_records_rule ON block_records(node_id, rule_id, change)",
        )?;
        let records = Self {
            conn: Mutex::new(conn),
            retention,
            pruned_ms: AtomicI64::new(i64::MIN),
            failing: AtomicBool::new(false),
        };
        // Records past their days go before anyone reads them.
        records.prune(now_ms)?;
        Ok(records)
    }

    pub fn retention(&self) -> Retention {
        self.retention
    }

    /// Notes whether the latest write failed; true when that changed.
    pub fn failing(&self, failed: bool) -> bool {
        self.failing.swap(failed, Ordering::Relaxed) != failed
    }

    /// Where `node`'s kept records end.
    pub fn cursor(&self, node: &str) -> Result<Cursor> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT stream,seq FROM block_cursors WHERE node_id=?1",
                [node],
                |r| {
                    Ok(Cursor {
                        stream: r.get(0)?,
                        seq: r.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    /// Keeps the records of `batch` newer than what is kept, with the tenant
    /// of their rule from `tenants`, and moves `node`'s cursor past them.
    pub fn add(
        &self,
        node: &str,
        batch: Option<BlockBatch>,
        tenants: &HashMap<String, String>,
        now_ms: i64,
    ) -> Result<()> {
        let Some(batch) = batch.filter(|b| identifier(&b.stream) && !b.entries.is_empty()) else {
            return Ok(());
        };
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction()?;
            let cursor: Option<(String, u64)> = tx
                .query_row(
                    "SELECT stream,seq FROM block_cursors WHERE node_id=?1",
                    [node],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let mut last = cursor
                .filter(|(stream, _)| *stream == batch.stream)
                .map_or(0, |(_, seq)| seq);
            let mut kept = 0;
            {
                let mut upsert = tx.prepare_cached(
                    "INSERT INTO block_records VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                     ON CONFLICT(node_id,stream,record_id) DO UPDATE SET seq=excluded.seq,
                       change=excluded.change, received_ms=excluded.received_ms,
                       tenant_id=COALESCE(block_records.tenant_id,excluded.tenant_id),
                       protocol=excluded.protocol, detail=excluded.detail,
                       first_ms=excluded.first_ms, last_ms=excluded.last_ms, count=excluded.count
                     WHERE excluded.seq>block_records.seq",
                )?;
                let mut next = tx.prepare_cached(
                    "UPDATE block_counter SET change=change+1 WHERE id=1 RETURNING change",
                )?;
                for block in batch.entries.iter().take(crate::connections::BATCH) {
                    if block.seq <= last {
                        continue;
                    }
                    last = block.seq;
                    let change: i64 = next.query_row([], |r| r.get(0))?;
                    kept += upsert.execute(params![
                        node,
                        batch.stream,
                        block.id,
                        block.seq,
                        change,
                        now_ms,
                        tenants.get(&block.rule_id),
                        block.rule_id,
                        block.protocol,
                        block.source.to_string(),
                        block.reason,
                        block.detail,
                        block.first_ms,
                        block.last_ms,
                        block.count,
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO block_cursors VALUES(?1,?2,?3) ON CONFLICT(node_id) DO UPDATE SET stream=excluded.stream, seq=excluded.seq",
                params![node, batch.stream, last],
            )?;
            if kept > 0 {
                tx.execute(
                    "DELETE FROM block_records WHERE node_id=?1 AND change<(SELECT change FROM block_records WHERE node_id=?1 ORDER BY change DESC LIMIT 1 OFFSET ?2)",
                    params![node, self.retention.per_node - 1],
                )?;
            }
            tx.commit()?;
        }
        if now_ms.saturating_sub(self.pruned_ms.load(Ordering::Relaxed)) >= PRUNE_EVERY_MS {
            self.prune(now_ms)?;
        }
        Ok(())
    }

    /// Drops records whose latest change is older than the kept days.
    fn prune(&self, now_ms: i64) -> Result<()> {
        self.pruned_ms.store(now_ms, Ordering::Relaxed);
        self.conn.lock().unwrap().execute(
            "DELETE FROM block_records WHERE received_ms<?1",
            [now_ms - i64::from(self.retention.days) * DAY_MS],
        )?;
        Ok(())
    }

    /// One page of `query`'s records, latest change first, and the cursor of
    /// the next page when there may be one.
    pub fn read(&self, query: &Query<'_>) -> Result<(Vec<BlockView>, Option<i64>)> {
        let limit = query.limit.clamp(1, MAX_PAGE);
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare_cached(if query.rule.is_some() {
            READ_RULE
        } else {
            READ_NODE
        })?;
        let mut rows = statement
            .query_map(
                params![
                    query.node,
                    query.rule,
                    query.tenant,
                    query.before.unwrap_or(i64::MAX),
                    limit as i64 + 1
                ],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, u64>(8)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next = more.then(|| rows.last().map(|row| row.0)).flatten();
        let mut blocks = Vec::with_capacity(rows.len());
        for (_, rule_id, protocol, source, reason, detail, first_ms, last_ms, count) in rows {
            blocks.push(BlockView {
                rule_id,
                protocol,
                source: source.parse()?,
                reason,
                detail,
                first_ms,
                last_ms,
                count,
            });
        }
        Ok((blocks, next))
    }

    /// Drops a deleted node's records and cursor.
    pub fn forget(&self, node: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM block_records WHERE node_id=?1", [node])?;
        tx.execute("DELETE FROM block_cursors WHERE node_id=?1", [node])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::Block;

    const NOW: i64 = 1_800_000_000_000;

    fn batch(stream: &str, entries: &[(u64, u64, u64)]) -> Option<BlockBatch> {
        Some(BlockBatch {
            stream: stream.into(),
            entries: entries
                .iter()
                .map(|&(id, seq, count)| Block {
                    id,
                    seq,
                    rule_id: if id % 2 == 0 { "even" } else { "odd" }.into(),
                    protocol: "tcp".into(),
                    source: std::net::IpAddr::from([203, 0, 113, id as u8]),
                    reason: "source_denied".into(),
                    detail: String::new(),
                    first_ms: 0,
                    last_ms: seq as i64,
                    count,
                })
                .collect(),
        })
    }
    fn tenants() -> HashMap<String, String> {
        HashMap::from([
            ("odd".to_owned(), "t-odd".to_owned()),
            ("even".to_owned(), "t-even".to_owned()),
        ])
    }
    fn all<'a>(node: &'a str) -> Query<'a> {
        Query {
            node,
            rule: None,
            tenant: None,
            before: None,
            limit: MAX_PAGE,
        }
    }
    fn seen(records: &Records, query: &Query<'_>) -> Vec<(u8, u64)> {
        records
            .read(query)
            .unwrap()
            .0
            .iter()
            .map(|b| match b.source {
                std::net::IpAddr::V4(ip) => (ip.octets()[3], b.count),
                _ => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn records_are_kept_once_through_resends_updates_and_both_restarts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blocks.sqlite");
        let records = Records::open(&path, Retention::default(), NOW).unwrap();
        assert_eq!(records.cursor("n").unwrap(), Cursor::default());
        records
            .add("n", batch("a", &[(1, 1, 1), (2, 2, 1)]), &tenants(), NOW)
            .unwrap();
        // A lost reply: the same records again, plus a newer one.
        records
            .add(
                "n",
                batch("a", &[(1, 1, 1), (2, 2, 1), (3, 3, 1)]),
                &tenants(),
                NOW,
            )
            .unwrap();
        assert_eq!(records.cursor("n").unwrap().seq, 3);
        // Record 1 grew: it replaces its row and moves to the front, also
        // when sent twice; an older copy arriving late changes nothing.
        records
            .add("n", batch("a", &[(1, 4, 5)]), &tenants(), NOW)
            .unwrap();
        records
            .add("n", batch("a", &[(1, 4, 5)]), &tenants(), NOW)
            .unwrap();
        assert_eq!(seen(&records, &all("n")), [(1, 5), (3, 1), (2, 1)]);
        drop(records);
        // The controller restarted: records and cursor are still there.
        let records = Records::open(&path, Retention::default(), NOW).unwrap();
        assert_eq!(
            records.cursor("n").unwrap(),
            Cursor {
                stream: "a".into(),
                seq: 4
            }
        );
        assert_eq!(seen(&records, &all("n")), [(1, 5), (3, 1), (2, 1)]);
        // The agent restarted: its new stream starts at 1 again and is kept
        // next to the earlier run's records, which keep their counts.
        records
            .add("n", batch("b", &[(1, 1, 2)]), &tenants(), NOW)
            .unwrap();
        assert_eq!(records.cursor("n").unwrap().stream, "b");
        assert_eq!(seen(&records, &all("n")), [(1, 2), (1, 5), (3, 1), (2, 1)]);
        // Other nodes, invalid streams and empty batches are apart.
        records
            .add("m", batch("../x", &[(9, 9, 9)]), &tenants(), NOW)
            .unwrap();
        records.add("m", batch("c", &[]), &tenants(), NOW).unwrap();
        assert!(seen(&records, &all("m")).is_empty());
        assert_eq!(records.cursor("m").unwrap(), Cursor::default());
        records.forget("n").unwrap();
        assert!(seen(&records, &all("n")).is_empty());
        assert_eq!(records.cursor("n").unwrap(), Cursor::default());
    }

    #[test]
    fn pages_tenants_and_retention_bound_what_is_read_and_kept() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("blocks.sqlite");
        let retention = Retention {
            days: 2,
            per_node: 100,
        };
        let records = Records::open(&path, retention, NOW).unwrap();
        let many: Vec<(u64, u64, u64)> = (1..=150).map(|i| (i, i, 1)).collect();
        for chunk in many.chunks(50) {
            records
                .add("n", batch("s", chunk), &tenants(), NOW)
                .unwrap();
        }
        records
            .add("other", batch("s", &[(1, 1, 7)]), &tenants(), NOW)
            .unwrap();
        // At most 100 per node, the oldest changes gone; other nodes apart.
        let kept = seen(&records, &all("n"));
        assert_eq!(kept.len(), 100);
        assert_eq!(kept[0].0, 150);
        assert_eq!(kept[99].0, 51);
        assert_eq!(seen(&records, &all("other")), [(1, 7)]);
        // Pages: newest first, each page after the last one's cursor, until
        // there is no next page; nothing twice, nothing left out.
        let mut before = None;
        let mut paged = vec![];
        loop {
            let (page, next) = records
                .read(&Query {
                    limit: 30,
                    before,
                    ..all("n")
                })
                .unwrap();
            assert!(page.len() <= 30);
            paged.extend(page);
            match next {
                Some(cursor) => before = Some(cursor),
                None => break,
            }
        }
        assert_eq!(paged.len(), 100);
        // A tenant reads only records of its rules; a rule filter narrows.
        let odd = seen(
            &records,
            &Query {
                tenant: Some("t-odd"),
                ..all("n")
            },
        );
        assert_eq!(odd.len(), 50);
        assert!(odd.iter().all(|(id, _)| id % 2 == 1));
        let none = seen(
            &records,
            &Query {
                tenant: Some("t-none"),
                ..all("n")
            },
        );
        assert!(none.is_empty());
        let even = seen(
            &records,
            &Query {
                rule: Some("even"),
                tenant: Some("t-odd"),
                ..all("n")
            },
        );
        assert!(even.is_empty(), "a rule of another tenant shows nothing");
        // A record without a known rule tenant is for system administrators.
        records
            .add("n", batch("s", &[(201, 201, 1)]), &HashMap::new(), NOW)
            .unwrap();
        assert_eq!(seen(&records, &all("n"))[0], (201, 1));
        let visible = Query {
            tenant: Some("t-odd"),
            ..all("n")
        };
        assert!(!seen(&records, &visible).contains(&(201, 1)));
        // A rule's older page: `before` and `rule_id` together.
        let (first, next) = records
            .read(&Query {
                rule: Some("odd"),
                limit: 10,
                ..all("n")
            })
            .unwrap();
        let (second, _) = records
            .read(&Query {
                rule: Some("odd"),
                limit: 10,
                before: next,
                ..all("n")
            })
            .unwrap();
        let ids = |page: &[BlockView]| -> Vec<u8> {
            page.iter()
                .map(|b| match b.source {
                    std::net::IpAddr::V4(ip) => ip.octets()[3],
                    _ => unreachable!(),
                })
                .collect()
        };
        // 201 is the newest "odd" record, then the odd ones of 51..=150.
        assert_eq!(ids(&first)[..3], [201, 149, 147]);
        assert_eq!(ids(&second)[0], 131, "the page after the first ten");
        assert!(second.iter().all(|b| b.rule_id == "odd"));
        // Both kinds of page come from an index, not a scan of the table.
        for sql in [READ_RULE, READ_NODE] {
            let conn = records.conn.lock().unwrap();
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(params!["n", "odd", None::<String>, i64::MAX, 10], |r| {
                    r.get(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                plan.iter()
                    .any(|step| step.contains("INDEX block_records_")),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|step| step.contains("TEMP B-TREE")),
                "{plan:?}"
            );
        }
        // Days: records that last changed before them go when the file
        // opens and then at most once a minute while records arrive.
        records
            .add("n", batch("s", &[(202, 202, 1)]), &tenants(), NOW + 30_000)
            .unwrap();
        assert_eq!(seen(&records, &all("n")).len(), 100);
        let pruned = NOW + 2 * DAY_MS + 1;
        records
            .add("n", batch("s", &[(203, 203, 1)]), &tenants(), pruned)
            .unwrap();
        let fresh = seen(&records, &all("n"));
        assert_eq!(fresh.iter().map(|r| r.0).collect::<Vec<_>>(), [203, 202]);
        assert!(seen(&records, &all("other")).is_empty());
        // 202 is past its days 40 s later, but goes only a minute after the
        // last clean-up.
        records
            .add(
                "n",
                batch("s", &[(204, 204, 1)]),
                &tenants(),
                pruned + 40_000,
            )
            .unwrap();
        let ids_now = |records: &Records| -> Vec<u8> {
            seen(records, &all("n")).iter().map(|r| r.0).collect()
        };
        assert_eq!(ids_now(&records), [204, 203, 202]);
        records
            .add(
                "n",
                batch("s", &[(205, 205, 1)]),
                &tenants(),
                pruned + 60_000,
            )
            .unwrap();
        assert_eq!(ids_now(&records), [205, 204, 203]);
        drop(records);
        records_open_prunes(&path, retention);
        // Settings are bounded; a newer file is refused.
        for bad in [
            Retention {
                days: 0,
                per_node: 100,
            },
            Retention {
                days: 2,
                per_node: 99,
            },
        ] {
            assert!(Records::open(&path, bad, NOW).is_err());
        }
        Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version=2")
            .unwrap();
        assert!(Records::open(&path, retention, NOW).is_err());
    }

    #[test]
    fn a_version_1_file_from_before_the_rule_index_gets_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.sqlite");
        crate::store::write_secret(&path, b"").unwrap();
        // As the first release of this file made it.
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE block_records(node_id TEXT NOT NULL, stream TEXT NOT NULL,
                  record_id INTEGER NOT NULL, seq INTEGER NOT NULL, change INTEGER NOT NULL,
                  received_ms INTEGER NOT NULL, tenant_id TEXT, rule_id TEXT NOT NULL,
                  protocol TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
                  detail TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,
                  count INTEGER NOT NULL, PRIMARY KEY(node_id, stream, record_id)) WITHOUT ROWID;
                CREATE INDEX block_records_change ON block_records(node_id, change);
                CREATE INDEX block_records_received ON block_records(received_ms);
                CREATE TABLE block_cursors(node_id TEXT PRIMARY KEY, stream TEXT NOT NULL,
                  seq INTEGER NOT NULL) WITHOUT ROWID;
                CREATE TABLE block_counter(id INTEGER PRIMARY KEY CHECK(id=1), change INTEGER NOT NULL);
                INSERT INTO block_counter VALUES(1, 0);
                PRAGMA user_version=1;",
            )
            .unwrap();
        let records = Records::open(&path, Retention::default(), NOW).unwrap();
        records
            .add("n", batch("s", &[(1, 1, 1), (2, 2, 1)]), &tenants(), NOW)
            .unwrap();
        let query = Query {
            rule: Some("odd"),
            before: Some(10),
            ..all("n")
        };
        assert_eq!(seen(&records, &query), [(1, 1)]);
        let conn = records.conn.lock().unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let plan: Vec<String> = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {READ_RULE}"))
            .unwrap()
            .query_map(params!["n", "odd", None::<String>, 10i64, 10i64], |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains("block_records_rule")),
            "{plan:?}"
        );
    }

    fn records_open_prunes(path: &Path, retention: Retention) {
        // Opened long after: nothing is left even before any record arrives.
        let later = Records::open(path, retention, NOW + 10 * DAY_MS).unwrap();
        assert!(seen(&later, &all("n")).is_empty());
        // The file and SQLite's write-ahead log and shared memory beside it
        // are the owner's only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let file = format!("{}{suffix}", path.display());
                assert_eq!(
                    fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{file}"
                );
            }
        }
    }
}
