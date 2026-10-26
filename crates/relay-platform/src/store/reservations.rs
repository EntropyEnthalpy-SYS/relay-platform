//! Durable pre-reservation for rule meters. The forwarding path spends bytes
//! from an in-memory allowance that is first recorded here, so no packet waits
//! for a disk commit. A process that stops without releasing its allowance has
//! every outstanding reserved byte counted as consumed on the next start:
//! usage may be over-counted by the unused allowance, never under-counted.
//! Quotas cover both directions, so one reservation serves both; bytes are
//! attributed to a direction when flushed, and a crash remainder is recorded
//! as download. A restored backup settles only after reconciliation, and only
//! the part of its reservation the controller checkpoint does not already cover.
use super::*;

#[derive(Serialize, Deserialize, Default)]
struct Outstanding {
    rule_id: String,
    meter_epoch: String,
    bytes: u64,
    /// Rule total if every reserved byte were spent; flushes keep it fixed.
    ceiling: u64,
}
fn key(rule: &str, epoch: &str) -> String {
    format!(
        "meter_reservation:{}",
        token_hash(&format!("{rule}\n{epoch}"))
    )
}
fn read(tx: &Transaction<'_>, rule: &str, epoch: &str) -> Result<Outstanding> {
    let saved: Option<String> = tx
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(rule, epoch)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match saved {
        Some(saved) => serde_json::from_str(&saved)?,
        None => Outstanding {
            rule_id: rule.into(),
            meter_epoch: epoch.into(),
            ..Default::default()
        },
    })
}
fn write(tx: &Transaction<'_>, value: &Outstanding) -> Result<()> {
    let key = key(&value.rule_id, &value.meter_epoch);
    if value.bytes == 0 {
        tx.execute("DELETE FROM metadata WHERE key=?1", [key])?;
    } else {
        tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, serde_json::to_string(value)?])?;
    }
    Ok(())
}

/// Bytes forwarded from an allowance since the previous flush.
#[derive(Clone, Debug, Default)]
pub struct MeterFlush {
    pub rule_id: String,
    pub meter_epoch: String,
    pub upload: u64,
    pub download: u64,
}
fn apply_flush(tx: &Transaction<'_>, flush: &MeterFlush) -> Result<()> {
    if flush.upload == 0 && flush.download == 0 {
        return Ok(());
    }
    tx.execute(
        "UPDATE agent_meters SET upload_bytes=upload_bytes+?1,download_bytes=download_bytes+?2,sequence=sequence+1 WHERE rule_id=?3 AND meter_epoch=?4",
        params![flush.upload, flush.download, flush.rule_id, flush.meter_epoch],
    )?;
    let mut outstanding = read(tx, &flush.rule_id, &flush.meter_epoch)?;
    outstanding.bytes = outstanding
        .bytes
        .saturating_sub(flush.upload + flush.download);
    write(tx, &outstanding)
}

impl Store {
    /// Counts reservations left by a previous process as consumed usage.
    /// Fails while a restored state awaits reconciliation, because the
    /// controller checkpoint may already include part of the reservation.
    pub fn settle_meter_reservations(&self) -> Result<u64> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let pending: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='recovery_required'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            pending.as_deref() != Some("true"),
            "meter reservations wait for ledger reconciliation"
        );
        let rows: Vec<String> = tx
            .prepare("SELECT value FROM metadata WHERE key GLOB 'meter_reservation:*'")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut settled = 0;
        for row in rows {
            let outstanding: Outstanding = serde_json::from_str(&row)?;
            let used: Option<u64> = tx
                .query_row(
                    "SELECT upload_bytes+download_bytes FROM agent_meters WHERE rule_id=?1 AND meter_epoch=?2",
                    params![outstanding.rule_id, outstanding.meter_epoch],
                    |r| r.get(0),
                )
                .optional()?;
            let missing = outstanding.ceiling.saturating_sub(used.unwrap_or(u64::MAX));
            apply_flush(
                &tx,
                &MeterFlush {
                    rule_id: outstanding.rule_id,
                    meter_epoch: outstanding.meter_epoch,
                    upload: 0,
                    download: missing,
                },
            )?;
            settled += missing;
        }
        tx.execute(
            "DELETE FROM metadata WHERE key GLOB 'meter_reservation:*'",
            [],
        )?;
        tx.commit()?;
        Ok(settled)
    }
    /// Records pending usage, then reserves up to `wanted` more bytes.
    /// Returns 0 when the rule cannot admit at least `minimum`.
    pub fn reserve_meter(
        &self,
        flushes: &[MeterFlush],
        rule: &str,
        epoch: &str,
        wanted: u64,
        minimum: u64,
    ) -> Result<u64> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        for flush in flushes {
            apply_flush(&tx, flush)?;
        }
        let state = tx
            .query_row(
                "SELECT enabled,quota_bytes,expires_at_ms,upload_bytes,download_bytes,sequence,budgeted FROM agent_meters WHERE rule_id=?1 AND meter_epoch=?2",
                params![rule, epoch],
                |r| {
                    Ok((
                        r.get::<_, bool>(0)?,
                        r.get::<_, Option<u64>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, u64>(3)? + r.get::<_, u64>(4)?,
                        r.get::<_, u64>(5)?,
                        r.get::<_, bool>(6)?,
                    ))
                },
            )
            .optional()?;
        let mut granted = 0;
        if let Some((enabled, quota, expires, used, sequence, budgeted)) = state {
            let mut outstanding = read(&tx, rule, epoch)?;
            let used = used + outstanding.bytes;
            let remaining = quota
                .unwrap_or(MAX_COUNTER)
                .min(MAX_COUNTER)
                .saturating_sub(used);
            if enabled
                && !budgeted
                && expires.is_none_or(|t| t > now_ms())
                && sequence < MAX_COUNTER
                && remaining >= minimum.max(1)
            {
                granted = wanted.min(remaining);
                outstanding.bytes += granted;
                outstanding.ceiling = used + granted;
                write(&tx, &outstanding)?;
            }
        }
        tx.commit()?;
        Ok(granted)
    }
    /// Records pending usage. `release` also drops every unused reservation.
    pub fn flush_meters(&self, flushes: &[MeterFlush], release: bool) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        for flush in flushes {
            apply_flush(&tx, flush)?;
        }
        if release {
            tx.execute(
                "DELETE FROM metadata WHERE key GLOB 'meter_reservation:*'",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
