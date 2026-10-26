//! Controller recovery log. A confirmed write has three durable boundaries:
//! prepared changeset, SQLite commit, and committed log + atomic head manifest.
//! The head must be kept with the latest log; an old pair cannot prove freshness.
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{
    Connection, OptionalExtension, Params, Transaction, params,
    session::{ConflictAction, Session},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"RLYJNL01";
/// On-disk recovery-log format. It is independent of the SQLite application
/// schema: 0.20.0 raises `user_version` to 5 without changing any table, so
/// existing logs keep their format and schema fingerprint.
const FORMAT: u32 = 4;
/// Oldest application schema this binary serves.
const SCHEMA: u32 = 5;
const HEADER_LEN: u64 = 92;
const MAX_CHANGESET: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalHead {
    pub journal_id: String,
    pub schema: u32,
    pub schema_sha256: String,
    pub sequence: u64,
    pub sha256: String,
    pub committed_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalStatus {
    pub enabled: bool,
    pub healthy: bool,
    pub head: Option<JournalHead>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreReport {
    pub journal_id: String,
    pub backup_sequence: u64,
    pub restored_sequence: u64,
    pub replayed_transactions: u64,
    pub budget_allocation_paused: bool,
    pub ignored_uncommitted_tail: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn head_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.head.json",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}
fn parent_sync(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn private_file(path: &Path, write: bool, create: bool) -> Result<File> {
    private_parent(path)?;
    if !create {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "recovery input must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "recovery files require private permissions (0600)"
            );
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(write).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn private_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "recovery directory must be a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o022 == 0,
            "recovery directory must not be writable by group or others"
        );
    }
    Ok(())
}
fn publish_head(path: &Path, head: &JournalHead) -> Result<()> {
    let temporary = path.with_file_name(format!(".recovery-head-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = private_file(&temporary, true, true)?;
        file.write_all(&serde_json::to_vec(head)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        parent_sync(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
fn read_head(path: &Path) -> Result<JournalHead> {
    let file = private_file(path, false, false)?;
    ensure!(
        file.metadata()?.len() <= 4096,
        "recovery head exceeds size limit"
    );
    Ok(serde_json::from_reader(file)?)
}
fn schema_hash(conn: &Connection) -> Result<String> {
    let mut query=conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
    let rows = query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hash(&serde_json::to_vec(&rows)?))
}
fn initial_head(id: &str, schema_hash: &str) -> Result<(Vec<u8>, JournalHead)> {
    let id = Uuid::parse_str(id)?;
    let mut header = Vec::from(MAGIC.as_slice());
    header.extend(FORMAT.to_be_bytes());
    header.extend(id.as_bytes());
    header.extend(schema_hash.as_bytes());
    let head = JournalHead {
        journal_id: id.to_string(),
        schema: FORMAT,
        schema_sha256: schema_hash.into(),
        sequence: 0,
        sha256: hash(&header),
        committed_bytes: HEADER_LEN,
    };
    Ok((header, head))
}
fn checkpoint(conn: &Connection) -> Result<Option<(String, u64, String)>> {
    Ok(conn
        .query_row(
            "SELECT journal_id,sequence,digest FROM recovery_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?)
}
fn set_checkpoint(conn: &Connection, id: &str, seq: u64, digest: &str) -> Result<()> {
    conn.execute("INSERT INTO recovery_state(id,journal_id,sequence,digest) VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest",params![id,seq,digest])?;
    Ok(())
}
struct Frame {
    sequence: u64,
    payload: Vec<u8>,
    digest: [u8; 32],
}
fn prepare_frame(head: &JournalHead, payload: Vec<u8>) -> Result<(Frame, Vec<u8>)> {
    ensure!(
        !payload.is_empty() && payload.len() as u64 <= MAX_CHANGESET,
        "recovery changeset exceeds limit"
    );
    let sequence = head
        .sequence
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .context("recovery sequence exhausted")?;
    let mut bytes = vec![b'P'];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend((payload.len() as u64).to_be_bytes());
    bytes.extend(head.sha256.as_bytes());
    bytes.extend(&payload);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend(digest);
    Ok((
        Frame {
            sequence,
            payload,
            digest,
        },
        bytes,
    ))
}
fn commit_bytes(frame: &Frame) -> Vec<u8> {
    let mut bytes = vec![b'C'];
    bytes.extend(frame.sequence.to_be_bytes());
    bytes.extend(frame.digest);
    bytes
}
fn fixed<const N: usize>(file: &mut File) -> Result<Option<[u8; N]>> {
    let mut bytes = [0u8; N];
    match file.read_exact(&mut bytes) {
        Ok(()) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}
struct Scan {
    head: JournalHead,
    pending: Option<Frame>,
    tail: bool,
    checkpoint_seen: bool,
}
fn scan(
    file: &mut File,
    database: Option<&(String, u64, String)>,
    mut committed: impl FnMut(&Frame, &JournalHead) -> Result<()>,
) -> Result<Scan> {
    file.rewind()?;
    let header = fixed::<92>(file)?.context("incomplete recovery log header")?;
    ensure!(
        &header[..8] == MAGIC && u32::from_be_bytes(header[8..12].try_into()?) == FORMAT,
        "unsupported recovery log format or schema"
    );
    let id = Uuid::from_slice(&header[12..28])?.to_string();
    let schema = std::str::from_utf8(&header[28..])?;
    ensure!(
        schema.len() == 64 && schema.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid schema fingerprint"
    );
    let (_, mut head) = initial_head(&id, schema)?;
    let mut seen = database.is_some_and(|(i, s, h)| i == &id && *s == 0 && h == &head.sha256);
    let mut pending = None;
    let mut tail = false;
    loop {
        let mut tag = [0u8; 1];
        if file.read(&mut tag)? == 0 {
            break;
        }
        match tag[0] {
            b'P' => {
                ensure!(
                    pending.is_none(),
                    "overlapping prepared recovery transactions"
                );
                let Some(prefix) = fixed::<80>(file)? else {
                    tail = true;
                    break;
                };
                let sequence = u64::from_be_bytes(prefix[..8].try_into()?);
                let length = u64::from_be_bytes(prefix[8..16].try_into()?);
                ensure!(
                    sequence == head.sequence + 1 && length > 0 && length <= MAX_CHANGESET,
                    "invalid recovery sequence or record length"
                );
                ensure!(
                    &prefix[16..] == head.sha256.as_bytes(),
                    "recovery hash chain is broken"
                );
                let mut payload = vec![0u8; length as usize];
                match file.read_exact(&mut payload) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        tail = true;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
                let Some(digest) = fixed::<32>(file)? else {
                    tail = true;
                    break;
                };
                let (frame, _) = prepare_frame(&head, payload)?;
                ensure!(frame.digest == digest, "recovery record checksum mismatch");
                pending = Some(frame);
            }
            b'C' => {
                let Some(bytes) = fixed::<40>(file)? else {
                    tail = true;
                    break;
                };
                let frame = pending
                    .take()
                    .context("recovery commit lacks its prepared transaction")?;
                ensure!(
                    u64::from_be_bytes(bytes[..8].try_into()?) == frame.sequence
                        && bytes[8..] == frame.digest,
                    "recovery commit identity mismatch"
                );
                head.sequence = frame.sequence;
                head.sha256 = hex(&frame.digest);
                head.committed_bytes = file.stream_position()?;
                seen |= database
                    .is_some_and(|(i, s, h)| i == &id && *s == head.sequence && h == &head.sha256);
                committed(&frame, &head)?;
            }
            _ => bail!("unrecognized recovery record"),
        }
    }
    Ok(Scan {
        head,
        pending,
        tail,
        checkpoint_seen: seen,
    })
}

struct Journal {
    file: File,
    path: PathBuf,
    head: JournalHead,
    poisoned: bool,
    schema_version: u64,
}
impl Journal {
    fn open(conn: &Connection, path: &Path) -> Result<Self> {
        private_parent(path)?;
        let schema = schema_hash(conn)?;
        let schema_version = conn.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
        ensure!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))? == SCHEMA,
            "recovery journal schema mismatch"
        );
        let current = checkpoint(conn)?;
        let current = if let Some(current) = current {
            current
        } else {
            ensure!(
                !path.exists() && !head_path(path).exists(),
                "existing journal cannot be attached to an unrelated database"
            );
            ensure!(
                !conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='backup_created_at_ms')",
                    [],
                    |r| r.get::<_, bool>(0)
                )?,
                "restore a backup with its latest recovery log before starting the controller"
            );
            let id = Uuid::new_v4().to_string();
            let (_, head) = initial_head(&id, &schema)?;
            set_checkpoint(conn, &id, 0, &head.sha256)?;
            (id, 0, head.sha256)
        };
        if !path.exists() {
            ensure!(
                current.1 == 0 && !head_path(path).exists(),
                "recovery log is missing; refusing to start a new history"
            );
            let (header, head) = initial_head(&current.0, &schema)?;
            let mut file = private_file(path, true, true)?;
            file.try_lock()?;
            file.write_all(&header)?;
            file.sync_all()?;
            parent_sync(path)?;
            publish_head(&head_path(path), &head)?;
            return Ok(Self {
                file,
                path: path.into(),
                head,
                poisoned: false,
                schema_version,
            });
        }
        let mut file = private_file(path, true, false)?;
        file.try_lock().context("recovery log is already in use")?;
        let mut scanned = scan(&mut file, Some(&current), |_, _| Ok(()))?;
        ensure!(
            scanned.head.journal_id == current.0 && scanned.head.schema_sha256 == schema,
            "recovery log belongs to a different controller"
        );
        let declared = match read_head(&head_path(path)) {
            Ok(head) => head,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    && current.1 == 0
                    && scanned.head.sequence == 0
                    && scanned.checkpoint_seen =>
            {
                scanned.head.clone()
            }
            Err(error) => return Err(error),
        };
        ensure!(
            declared.journal_id == current.0 && declared.sequence <= scanned.head.sequence,
            "recovery head is ahead of or unrelated to the log"
        );
        // A crash between SQLite commit and log commit is resolved from the live
        // database's sequence + payload digest. Never infer this from an old backup.
        if let Some(frame) = scanned
            .pending
            .take()
            .filter(|p| p.sequence == current.1 && hex(&p.digest) == current.2)
        {
            file.set_len(scanned.head.committed_bytes + 1 + 80 + frame.payload.len() as u64 + 32)?;
            file.seek(SeekFrom::End(0))?;
            file.write_all(&commit_bytes(&frame))?;
            file.sync_all()?;
            scanned.head.sequence = frame.sequence;
            scanned.head.sha256 = hex(&frame.digest);
            scanned.head.committed_bytes = file.stream_position()?;
        } else {
            ensure!(
                scanned.checkpoint_seen && current.1 == scanned.head.sequence,
                "database and recovery log differ; restore with the latest log instead of starting stale state"
            );
            file.set_len(scanned.head.committed_bytes)?;
            file.sync_all()?;
        }
        // A manifest that names a present sequence must agree with that prefix.
        let mut head_seen =
            declared.sequence == 0 && declared == initial_head(&current.0, &schema)?.1;
        scan(&mut file, None, |_, h| {
            if h.sequence == declared.sequence {
                ensure!(*h == declared, "recovery head checksum mismatch");
                head_seen = true;
            }
            Ok(())
        })?;
        ensure!(head_seen, "recovery head does not match a committed prefix");
        publish_head(&head_path(path), &scanned.head)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            path: path.into(),
            head: scanned.head,
            poisoned: false,
            schema_version,
        })
    }
}

pub(crate) struct LoggedConnection {
    conn: Connection,
    journal: Option<Mutex<Journal>>,
    required: bool,
}
impl Deref for LoggedConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}
impl LoggedConnection {
    pub fn new(conn: Connection) -> Result<Self> {
        let required = checkpoint(&conn)?.is_some();
        Ok(Self {
            conn,
            journal: None,
            required,
        })
    }
    pub fn enable(&mut self, path: &Path) -> Result<()> {
        ensure!(self.journal.is_none(), "recovery logging already enabled");
        let kind: Option<String> = self
            .conn
            .query_row("SELECT value FROM metadata WHERE key='kind'", [], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(
            kind.as_deref().is_none_or(|k| k == "controller"),
            "recovery logging is currently for controller databases"
        );
        self.required = true;
        self.journal = Some(Mutex::new(Journal::open(&self.conn, path)?));
        Ok(())
    }
    pub fn status(&self) -> Result<JournalStatus> {
        if let Some(journal) = &self.journal {
            let j = journal.lock().unwrap();
            Ok(JournalStatus {
                enabled: true,
                healthy: !j.poisoned,
                head: Some(j.head.clone()),
            })
        } else {
            Ok(JournalStatus {
                enabled: false,
                healthy: !self.required,
                head: None,
            })
        }
    }
    fn begin(&self) -> Result<LoggedTransaction<'_>> {
        if let Some(j) = &self.journal {
            let j = j.lock().unwrap();
            ensure!(
                !j.poisoned,
                "recovery logging failed; restart to reconcile durable state"
            );
            ensure!(
                self.conn
                    .query_row("PRAGMA schema_version", [], |r| r.get::<_, u64>(0))?
                    == j.schema_version,
                "schema changed outside recovery logging; restart requires a matching schema baseline"
            );
        } else {
            ensure!(
                !self.required,
                "this database requires its recovery log for writes"
            );
        }
        let tx = self.conn.unchecked_transaction()?;
        let session = if self.journal.is_some() {
            let mut s = Session::new(&self.conn)?;
            s.table_filter(Some(|name: &str| name != "recovery_state"));
            s.attach(None::<&str>)?;
            Some(s)
        } else {
            None
        };
        Ok(LoggedTransaction {
            tx,
            session,
            journal: self.journal.as_ref(),
        })
    }
    pub fn transaction(&mut self) -> Result<LoggedTransaction<'_>> {
        self.begin()
    }
    pub fn execute<P: Params>(&self, sql: &str, params: P) -> Result<usize> {
        let tx = self.begin()?;
        let changed = tx.execute(sql, params)?;
        tx.commit()?;
        Ok(changed)
    }
}
pub(crate) struct LoggedTransaction<'a> {
    tx: Transaction<'a>,
    session: Option<Session<'a>>,
    journal: Option<&'a Mutex<Journal>>,
}
impl<'a> Deref for LoggedTransaction<'a> {
    type Target = Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}
impl LoggedTransaction<'_> {
    pub fn commit(mut self) -> Result<()> {
        let Some(session) = self.session.as_mut().filter(|s| !s.is_empty()) else {
            self.tx.commit()?;
            return Ok(());
        };
        let mut payload = Vec::new();
        session.changeset_strm(&mut payload)?;
        // A changed-and-reverted row can yield an empty changeset.
        if payload.is_empty() {
            self.tx.commit()?;
            return Ok(());
        }
        let mut journal = self.journal.unwrap().lock().unwrap();
        ensure!(!journal.poisoned, "recovery journal is unavailable");
        let (frame, prepared) = prepare_frame(&journal.head, payload)?;
        set_checkpoint(
            &self.tx,
            &journal.head.journal_id,
            frame.sequence,
            &hex(&frame.digest),
        )?;
        let result = (|| {
            journal.file.write_all(&prepared)?;
            journal.file.sync_all()?;
            #[cfg(test)]
            crash_point("prepared");
            self.tx.commit()?;
            #[cfg(test)]
            crash_point("sqlite");
            journal.file.write_all(&commit_bytes(&frame))?;
            journal.file.sync_all()?;
            #[cfg(test)]
            crash_point("log_commit");
            let mut head = journal.head.clone();
            head.sequence = frame.sequence;
            head.sha256 = hex(&frame.digest);
            head.committed_bytes = journal.file.stream_position()?;
            publish_head(&head_path(&journal.path), &head)?;
            #[cfg(test)]
            crash_point("head");
            journal.head = head;
            Ok::<_, anyhow::Error>(())
        })();
        if result.is_err() {
            journal.poisoned = true;
        }
        result.context("controller recovery write could not be confirmed")
    }
}

/// Restore only to a newly created directory. Inputs remain untouched. The log
/// is held exclusively throughout validation and replay, fencing local writers.
pub fn restore_controller(backup: &Path, log: &Path, output: &Path) -> Result<RestoreReport> {
    let _backup = private_file(backup, false, false)?;
    let mut journal = private_file(log, false, false)?;
    journal
        .try_lock()
        .context("stop the controller before restoring from its recovery log")?;
    let expected = read_head(&head_path(log))?;
    let source = Connection::open_with_flags(backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let source_schema: u32 = source.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    ensure!(
        (4..=SCHEMA).contains(&source_schema),
        "backup schema is not supported by this recovery log version"
    );
    let start = checkpoint(&source)?
        .context("backup predates recovery logging; no continuous history can be proven")?;
    ensure!(
        expected.schema_sha256 == schema_hash(&source)?,
        "backup schema fingerprint differs from recovery log"
    );
    ensure!(
        source.query_row("SELECT value FROM metadata WHERE key='kind'", [], |r| {
            r.get::<_, String>(0)
        })? == "controller",
        "restore requires a controller backup"
    );
    let scanned = scan(&mut journal, Some(&start), |_, _| Ok(()))?;
    ensure!(
        scanned.head == expected && scanned.checkpoint_seen,
        "backup, recovery log and latest head manifest do not describe one continuous history"
    );
    fs::create_dir(output).context("restore destination must not exist")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| {
        let database = output.join("controller.sqlite");
        private_file(&database, true, true)?;
        let mut restored = Connection::open(&database)?;
        {
            let copy = rusqlite::backup::Backup::new(&source, &mut restored)?;
            copy.run_to_completion(256, std::time::Duration::from_millis(1), None)?;
        }
        restored.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
        // Undo only the export markers. They are not mutations of the live DB and
        // must not interfere with strict changeset conflict checks.
        let original: Option<String> = restored
            .query_row(
                "SELECT value FROM metadata WHERE key='backup_original_budget_pause'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            original.is_some(),
            "input is not a supported controller backup"
        );
        let pause: Option<String> = serde_json::from_str(original.as_ref().unwrap())?;
        if let Some(value) = pause {
            restored.execute("INSERT INTO metadata(key,value) VALUES('budget_allocation_paused',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[value])?;
        } else {
            restored.execute(
                "DELETE FROM metadata WHERE key='budget_allocation_paused'",
                [],
            )?;
        }
        restored.execute("DELETE FROM metadata WHERE key IN('backup_created_at_ms','backup_original_budget_pause')",[])?;
        // A 0.19.0 backup is schema 4 but has the same tables; finish the
        // compatibility bump after replay so this binary serves it and older
        // binaries reject the restored state.
        restored.execute_batch("PRAGMA user_version=5")?;
        let mut replayed = 0;
        scan(&mut journal, Some(&start), |frame, head| {
            if frame.sequence > start.1 {
                let tx = restored.unchecked_transaction()?;
                tx.apply_strm(
                    &mut frame.payload.as_slice(),
                    None::<fn(&str) -> bool>,
                    |_, _| ConflictAction::SQLITE_CHANGESET_ABORT,
                )
                .context(
                    "recovery changeset conflicts with backup; no rows were silently replaced",
                )?;
                set_checkpoint(&tx, &head.journal_id, head.sequence, &head.sha256)?;
                tx.commit()?;
                replayed += 1;
            }
            Ok(())
        })?;
        ensure!(
            checkpoint(&restored)?
                == Some((
                    expected.journal_id.clone(),
                    expected.sequence,
                    expected.sha256.clone()
                )),
            "restored checkpoint does not match recovery head"
        );
        let violations: u64 =
            restored.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        ensure!(
            violations == 0,
            "restored database has foreign key violations"
        );
        ensure!(
            restored.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))? == "ok",
            "restored database integrity check failed"
        );
        let paused:bool=restored.query_row("SELECT EXISTS(SELECT 1 FROM metadata WHERE key='budget_allocation_paused' AND value='true')",[],|r|r.get(0))?;
        drop(restored);
        File::open(&database)?.sync_all()?;
        let destination = output.join("recovery.log");
        let mut dest = private_file(&destination, true, true)?;
        journal.rewind()?;
        std::io::copy(
            &mut Read::by_ref(&mut journal).take(expected.committed_bytes),
            &mut dest,
        )?;
        dest.sync_all()?;
        publish_head(&head_path(&destination), &expected)?;
        parent_sync(&database)?;
        parent_sync(output)?;
        Ok(RestoreReport {
            journal_id: expected.journal_id,
            backup_sequence: start.1,
            restored_sequence: expected.sequence,
            replayed_transactions: replayed,
            budget_allocation_paused: paused,
            ignored_uncommitted_tail: scanned.tail || scanned.pending.is_some(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

#[cfg(test)]
fn crash_point(stage: &str) {
    if std::env::var("RELAY_TEST_JOURNAL_CRASH_STAGE")
        .ok()
        .as_deref()
        == Some(stage)
    {
        std::process::exit(73);
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Store;
    #[test]
    #[ignore = "subprocess helper exercised by abrupt_exit_at_each_durable_boundary"]
    fn crash_worker() {
        let directory =
            std::path::PathBuf::from(std::env::var("RELAY_TEST_JOURNAL_DIRECTORY").unwrap());
        let store = Store::open(&directory.join("controller.sqlite")).unwrap();
        store
            .enable_recovery_log(&directory.join("recovery.log"))
            .unwrap();
        store.set_metadata("crash-result", "written").unwrap();
        panic!("fault injection did not exit at its requested stage");
    }
    #[test]
    fn abrupt_exit_at_each_durable_boundary() {
        for stage in ["prepared", "sqlite", "log_commit", "head"] {
            let tmp = tempfile::tempdir().unwrap();
            let store = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
            store
                .enable_recovery_log(&tmp.path().join("recovery.log"))
                .unwrap();
            store.set_kind("controller").unwrap();
            let initial = store.recovery_log_status().unwrap().head.unwrap().sequence;
            drop(store);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "journal::tests::crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("RELAY_TEST_JOURNAL_DIRECTORY", tmp.path())
                .env("RELAY_TEST_JOURNAL_CRASH_STAGE", stage)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73), "{stage}");
            let store = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
            store
                .enable_recovery_log(&tmp.path().join("recovery.log"))
                .unwrap();
            let committed = stage != "prepared";
            assert_eq!(
                store.metadata("crash-result").unwrap().is_some(),
                committed,
                "{stage}"
            );
            assert_eq!(
                store.recovery_log_status().unwrap().head.unwrap().sequence,
                initial + u64::from(committed)
            );
            store.set_metadata("after-restart", "works").unwrap();
        }
    }
}
