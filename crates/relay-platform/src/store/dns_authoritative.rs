//! Authoritative DNS pool persistence. Zones, members and records live in
//! metadata like provider-managed DNS, so the schema and recovery log stay
//! unchanged. Only system administrators manage the pool.
use super::*;
use crate::dns::HealthGate;
use crate::dns_authoritative::{
    self as pool, Kind, MAX_LISTEN, MAX_MEMBERS, MAX_RECORDS, MAX_VALUES, MAX_ZONES, Member,
    MemberInput, MemberView, PoolView, Record, RecordInput, RecordView, ServeStats, Snapshot,
    Value, Zone, ZoneInput, ZoneView,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

const FEATURE: &str = "dns-authoritative";

fn key(kind: &str, id: &str) -> String {
    format!("dns_auth_{kind}:{id}")
}
fn read<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<T>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(kind, id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write<T: Serialize>(tx: &Transaction<'_>, kind: &str, id: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(kind, id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn remove(tx: &Transaction<'_>, kind: &str, id: &str) -> Result<()> {
    tx.execute("DELETE FROM metadata WHERE key=?1", [key(kind, id)])?;
    Ok(())
}
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, kind: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("dns_auth_{kind}:*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored authoritative DNS data"))
        .collect()
}
/// Zones in the pool; the feature cannot be switched off while any exist.
pub(super) fn zone_count(conn: &Connection) -> Result<usize> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM metadata WHERE key GLOB 'dns_auth_zone:*'",
        [],
        |r| r.get(0),
    )?)
}

fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(
            403,
            "the authoritative DNS pool requires a system administrator",
        );
    }
    Ok(())
}
fn invalid<T>(error: anyhow::Error) -> Result<T> {
    reject(400, format!("{error:#}"))
}
fn zone(conn: &Connection, id: &str) -> Result<Zone> {
    match read(conn, "zone", id)? {
        Some(zone) => Ok(zone),
        None => reject(404, "authoritative DNS zone not found"),
    }
}
/// Any change to a zone, its members or its records raises the SOA serial.
fn touch(tx: &Transaction<'_>, zone: &mut Zone) -> Result<()> {
    let now = now_ms();
    zone.serial = zone.serial.saturating_add(1).max((now / 1000) as u32);
    zone.updated_at_ms = now;
    write(tx, "zone", &zone.id.clone(), zone)
}

fn zone_fields(conn: &Connection, input: &ZoneInput, current: Option<&str>) -> Result<Zone> {
    let name = pool::zone_name(&input.name).or_else(invalid)?;
    let hostmaster = input
        .hostmaster
        .as_deref()
        .map(|h| h.trim().to_ascii_lowercase())
        .unwrap_or_else(|| format!("hostmaster@{name}"));
    pool::hostmaster_name(&hostmaster).or_else(invalid)?;
    let (ttl, negative_ttl) = (input.ttl.unwrap_or(60), input.negative_ttl.unwrap_or(60));
    if !(30..=86_400).contains(&ttl) || !(30..=86_400).contains(&negative_ttl) {
        return reject(400, "TTLs must be 30..86400 seconds");
    }
    let min_keep = input.min_keep.unwrap_or(1);
    if min_keep as usize > MAX_VALUES {
        return reject(400, format!("min_keep must be 0..{MAX_VALUES}"));
    }
    let zones = all::<Zone>(conn, "zone")?;
    if current.is_none() && zones.len() >= MAX_ZONES {
        return reject(409, format!("the pool holds at most {MAX_ZONES} zones"));
    }
    for other in zones.iter().filter(|z| Some(z.id.as_str()) != current) {
        let nested = |a: &str, b: &str| a == b || a.ends_with(&format!(".{b}"));
        if nested(&name, &other.name) || nested(&other.name, &name) {
            return reject(409, format!("{name} overlaps the pool zone {}", other.name));
        }
    }
    if let Some(id) = current {
        for record in all::<Record>(conn, "record")?
            .iter()
            .filter(|r| r.zone_id == id)
        {
            pool::record_name(&record.name, &name).or_else(invalid)?;
        }
    }
    Ok(Zone {
        id: current.map_or_else(|| Uuid::new_v4().to_string(), str::to_string),
        name,
        hostmaster,
        ttl,
        negative_ttl,
        min_keep,
        serial: 0,
        updated_at_ms: 0,
    })
}

fn member_fields(
    conn: &Connection,
    zone: &Zone,
    input: MemberInput,
    current: Option<&Member>,
) -> Result<Member> {
    let usable = |ip: &IpAddr| {
        !ip.is_unspecified() && !ip.is_multicast() && *ip != IpAddr::from([255, 255, 255, 255])
    };
    let listen: Vec<IpAddr> = input
        .listen
        .iter()
        .map(|ip| crate::model::canonical_ip(*ip))
        .collect();
    let mut distinct = listen.clone();
    distinct.sort();
    distinct.dedup();
    if listen.is_empty()
        || listen.len() > MAX_LISTEN
        || !listen.iter().all(usable)
        || distinct.len() != listen.len()
    {
        return reject(
            400,
            format!(
                "listen needs 1..{MAX_LISTEN} distinct addresses of this node; wildcards such as 0.0.0.0 are not allowed"
            ),
        );
    }
    let advertise = crate::model::canonical_ip(input.advertise.unwrap_or(listen[0]));
    if !usable(&advertise) {
        return reject(400, "the advertised address must be a unicast address");
    }
    let port = input.port.unwrap_or(53);
    if port == 0 {
        return reject(400, "port must be 1..65535");
    }
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1)",
        [&input.node_id],
        |r| r.get(0),
    )?;
    if !exists {
        return reject(404, "node not found");
    }
    let others: Vec<Member> = all::<Member>(conn, "member")?
        .into_iter()
        .filter(|m| m.zone_id == zone.id && Some(&m.id) != current.map(|c| &c.id))
        .collect();
    if current.is_none() && others.len() >= MAX_MEMBERS {
        return reject(
            409,
            format!("a zone has at most {MAX_MEMBERS} name servers"),
        );
    }
    if others.iter().any(|m| m.node_id == input.node_id) {
        return reject(409, "this node already answers for the zone");
    }
    let label = match input.label.as_deref().filter(|l| !l.trim().is_empty()) {
        Some(label) => pool::nameserver_label(label).or_else(invalid)?,
        None => (1..)
            .map(|n| format!("ns{n}"))
            .find(|label| !others.iter().any(|m| &m.label == label))
            .expect("a free label"),
    };
    if others.iter().any(|m| m.label == label) {
        return reject(
            409,
            format!("{label} is already a name server of this zone"),
        );
    }
    if all::<Record>(conn, "record")?
        .iter()
        .any(|r| r.zone_id == zone.id && r.name == label && r.kind != Kind::Txt)
    {
        return reject(
            409,
            format!("the record {label} would clash with the name server's address"),
        );
    }
    Ok(Member {
        id: current.map_or_else(|| Uuid::new_v4().to_string(), |c| c.id.clone()),
        zone_id: zone.id.clone(),
        node_id: input.node_id,
        label,
        listen,
        advertise,
        port,
        updated_at_ms: now_ms(),
    })
}

fn record_fields(
    conn: &Connection,
    zone: &Zone,
    input: RecordInput,
    current: Option<&str>,
) -> Result<Record> {
    let name = pool::record_name(&input.name, &zone.name).or_else(invalid)?;
    if input.ttl.is_some_and(|ttl| !(30..=86_400).contains(&ttl)) {
        return reject(400, "TTL must be 30..86400 seconds");
    }
    if input.values.is_empty() || input.values.len() > MAX_VALUES {
        return reject(400, format!("a record needs 1..{MAX_VALUES} values"));
    }
    let mut values: Vec<Value> = Vec::with_capacity(input.values.len());
    for value in input.values {
        let content = match input.kind {
            Kind::Cname => value
                .content
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            Kind::Txt => value.content,
            _ => value.content.trim().to_string(),
        };
        pool::validate_value(input.kind, &content).or_else(invalid)?;
        crate::dns::validate_health(value.health.as_ref()).or_else(invalid)?;
        if values.iter().any(|v| v.content == content) {
            return reject(400, format!("{content} is listed twice"));
        }
        values.push(Value {
            content,
            health: value.health,
        });
    }
    let others: Vec<Record> = all::<Record>(conn, "record")?
        .into_iter()
        .filter(|r| r.zone_id == zone.id && Some(r.id.as_str()) != current)
        .collect();
    if current.is_none() && others.len() >= MAX_RECORDS {
        return reject(409, format!("a zone has at most {MAX_RECORDS} records"));
    }
    if input.kind == Kind::Cname && (values.len() != 1 || name == "@") {
        return reject(
            400,
            "a CNAME has exactly one value and cannot be the zone itself",
        );
    }
    for other in others.iter().filter(|r| r.name == name) {
        if other.kind == input.kind {
            return reject(
                409,
                "this name already has a record of that type; add the value to it instead",
            );
        }
        if other.kind == Kind::Cname || input.kind == Kind::Cname {
            return reject(409, "a CNAME cannot share its name with other records");
        }
    }
    if input.kind != Kind::Txt
        && all::<Member>(conn, "member")?
            .iter()
            .any(|m| m.zone_id == zone.id && m.label == name)
    {
        return reject(
            409,
            format!("{name} is a name server; its address comes from the member"),
        );
    }
    Ok(Record {
        id: current.map_or_else(|| Uuid::new_v4().to_string(), str::to_string),
        zone_id: zone.id.clone(),
        name,
        kind: input.kind,
        ttl: input.ttl,
        values,
        updated_at_ms: now_ms(),
    })
}

/// Caches health per gate while one snapshot or view is built.
fn health<'a>(
    conn: &'a Connection,
    telemetry: &'a crate::telemetry::Telemetry,
) -> impl FnMut(&HealthGate) -> bool + 'a {
    let mut seen: HashMap<HealthGate, bool> = HashMap::new();
    move |gate| {
        *seen
            .entry(gate.clone())
            .or_insert_with(|| super::dns::health_ok(conn, telemetry, gate).unwrap_or(false))
    }
}

/// What `node` serves: every zone it is a member of, rendered with the newest
/// health reports. Empty while the feature is off.
pub(super) fn snapshot(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    node: &str,
) -> Result<Snapshot> {
    if !features::enabled(conn, FEATURE)? {
        return Ok(Snapshot::new(vec![], vec![]));
    }
    let members = all::<Member>(conn, "member")?;
    if !members.iter().any(|m| m.node_id == node) {
        return Ok(Snapshot::new(vec![], vec![]));
    }
    let records = all::<Record>(conn, "record")?;
    let mut healthy = health(conn, telemetry);
    let (mut listen, mut zones) = (vec![], vec![]);
    for member in members.iter().filter(|m| m.node_id == node) {
        let Some(zone) = read::<Zone>(conn, "zone", &member.zone_id)? else {
            continue;
        };
        listen.extend(
            member
                .listen
                .iter()
                .map(|ip| SocketAddr::new(*ip, member.port)),
        );
        let zone_members: Vec<Member> = members
            .iter()
            .filter(|m| m.zone_id == zone.id)
            .cloned()
            .collect();
        let zone_records: Vec<Record> = records
            .iter()
            .filter(|r| r.zone_id == zone.id)
            .cloned()
            .collect();
        zones.push(pool::render(
            &zone,
            &zone_members,
            &zone_records,
            &mut healthy,
        )?);
    }
    zones.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Snapshot::new(listen, zones))
}

impl Store {
    /// Every zone with its members' serving state and the answers given now.
    pub fn authoritative_dns(&self, actor: &Actor) -> Result<PoolView> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let telemetry = &self.4;
        let mut members = all::<Member>(&conn, "member")?;
        members.sort_by(|a, b| a.label.cmp(&b.label));
        let mut records = all::<Record>(&conn, "record")?;
        records.sort_by(|a, b| {
            (a.name != "@", &a.name, a.kind).cmp(&(b.name != "@", &b.name, b.kind))
        });
        let mut expected: HashMap<String, String> = HashMap::new();
        let mut zones = vec![];
        for zone in all::<Zone>(&conn, "zone")? {
            let mut healthy = health(&conn, telemetry);
            let records = records
                .iter()
                .filter(|r| r.zone_id == zone.id)
                .map(|record| {
                    let (served, healthy) =
                        pool::served(&record.values, zone.min_keep as usize, &mut healthy);
                    RecordView {
                        record: record.clone(),
                        served,
                        healthy,
                    }
                })
                .collect();
            let mut views = vec![];
            for member in members.iter().filter(|m| m.zone_id == zone.id) {
                let (name, last_seen, stats): (String, Option<i64>, String) = conn.query_row(
                    "SELECT name,last_seen_ms,COALESCE(stats_json,'{}') FROM nodes WHERE id=?1",
                    [&member.node_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let (last_seen, stats) = telemetry.current(&member.node_id, last_seen, stats);
                let report: Option<ServeStats> = serde_json::from_str::<EngineStats>(&stats)
                    .ok()
                    .and_then(|stats| stats.authoritative_dns);
                let digest = match expected.get(&member.node_id) {
                    Some(digest) => digest.clone(),
                    None => {
                        let digest = snapshot(&conn, telemetry, &member.node_id)?.digest;
                        expected.insert(member.node_id.clone(), digest.clone());
                        digest
                    }
                };
                let state = match &report {
                    _ if last_seen.is_none_or(|seen| now_ms().saturating_sub(seen) > 90_000) => {
                        "offline"
                    }
                    None => "waiting",
                    Some(report) if !report.errors.is_empty() => "error",
                    Some(report) if report.digest != digest => "updating",
                    Some(_) => "serving",
                };
                views.push(MemberView {
                    nameserver: pool::absolute(&member.label, &zone.name),
                    member: member.clone(),
                    node_name: name,
                    state,
                    report,
                });
            }
            zones.push(ZoneView {
                zone,
                members: views,
                records,
            });
        }
        Ok(PoolView {
            enabled: features::enabled(&conn, FEATURE)?,
            zones,
        })
    }

    pub fn create_authoritative_zone(&self, actor: &Actor, input: ZoneInput) -> Result<Zone> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let mut zone = zone_fields(&tx, &input, None)?;
        touch(&tx, &mut zone)?;
        audit(
            &tx,
            &actor.id,
            "dns.authoritative.zone.create",
            &zone.id,
            &serde_json::json!({"name": zone.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(zone)
    }
    pub fn update_authoritative_zone(
        &self,
        actor: &Actor,
        id: &str,
        input: ZoneInput,
    ) -> Result<Zone> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let old = zone(&tx, id)?;
        let mut zone = zone_fields(&tx, &input, Some(id))?;
        zone.serial = old.serial;
        touch(&tx, &mut zone)?;
        audit(
            &tx,
            &actor.id,
            "dns.authoritative.zone.update",
            id,
            &serde_json::json!({"name": zone.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(zone)
    }
    /// Removes the zone with its members and records.
    pub fn delete_authoritative_zone(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let zone = zone(&tx, id)?;
        for member in all::<Member>(&tx, "member")?
            .iter()
            .filter(|m| m.zone_id == id)
        {
            remove(&tx, "member", &member.id)?;
        }
        for record in all::<Record>(&tx, "record")?
            .iter()
            .filter(|r| r.zone_id == id)
        {
            remove(&tx, "record", &record.id)?;
        }
        remove(&tx, "zone", id)?;
        audit(
            &tx,
            &actor.id,
            "dns.authoritative.zone.delete",
            id,
            &serde_json::json!({"name": zone.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_authoritative_member(
        &self,
        actor: &Actor,
        zone_id: &str,
        input: MemberInput,
    ) -> Result<Member> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let mut zone = zone(&tx, zone_id)?;
        let member = member_fields(&tx, &zone, input, None)?;
        write(&tx, "member", &member.id, &member)?;
        touch(&tx, &mut zone)?;
        audit(&tx, &actor.id, "dns.authoritative.member.create", &member.id, &serde_json::json!({"zone_id": zone.id, "node_id": member.node_id, "label": member.label}).to_string())?;
        tx.commit()?;
        Ok(member)
    }
    pub fn update_authoritative_member(
        &self,
        actor: &Actor,
        id: &str,
        input: MemberInput,
    ) -> Result<Member> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let Some(current) = read::<Member>(&tx, "member", id)? else {
            return reject(404, "name server not found");
        };
        let mut zone = zone(&tx, &current.zone_id)?;
        let member = member_fields(&tx, &zone, input, Some(&current))?;
        write(&tx, "member", id, &member)?;
        touch(&tx, &mut zone)?;
        audit(&tx, &actor.id, "dns.authoritative.member.update", id, "{}")?;
        tx.commit()?;
        Ok(member)
    }
    pub fn delete_authoritative_member(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let Some(member) = read::<Member>(&tx, "member", id)? else {
            return reject(404, "name server not found");
        };
        remove(&tx, "member", id)?;
        if let Some(mut zone) = read::<Zone>(&tx, "zone", &member.zone_id)? {
            touch(&tx, &mut zone)?;
        }
        audit(&tx, &actor.id, "dns.authoritative.member.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_authoritative_record(
        &self,
        actor: &Actor,
        zone_id: &str,
        input: RecordInput,
    ) -> Result<Record> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let mut zone = zone(&tx, zone_id)?;
        let record = record_fields(&tx, &zone, input, None)?;
        write(&tx, "record", &record.id, &record)?;
        touch(&tx, &mut zone)?;
        audit(
            &tx,
            &actor.id,
            "dns.authoritative.record.create",
            &record.id,
            &serde_json::json!({"zone_id": zone.id, "name": record.name, "type": record.kind})
                .to_string(),
        )?;
        tx.commit()?;
        Ok(record)
    }
    pub fn update_authoritative_record(
        &self,
        actor: &Actor,
        id: &str,
        input: RecordInput,
    ) -> Result<Record> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "The authoritative DNS pool")?;
        let Some(current) = read::<Record>(&tx, "record", id)? else {
            return reject(404, "authoritative DNS record not found");
        };
        let mut zone = zone(&tx, &current.zone_id)?;
        let record = record_fields(&tx, &zone, input, Some(id))?;
        write(&tx, "record", id, &record)?;
        touch(&tx, &mut zone)?;
        audit(&tx, &actor.id, "dns.authoritative.record.update", id, "{}")?;
        tx.commit()?;
        Ok(record)
    }
    pub fn delete_authoritative_record(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let Some(record) = read::<Record>(&tx, "record", id)? else {
            return reject(404, "authoritative DNS record not found");
        };
        remove(&tx, "record", id)?;
        if let Some(mut zone) = read::<Zone>(&tx, "zone", &record.zone_id)? {
            touch(&tx, &mut zone)?;
        }
        audit(&tx, &actor.id, "dns.authoritative.record.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
}
