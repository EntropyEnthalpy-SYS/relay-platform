//! Recent log lines, in memory only. Every process copies its own lines into
//! a bounded ring through [`Capture`]. Agents send the lines the controller
//! has not seen with their reports, once the controller has asked for them
//! with a [`Cursor`], and the controller keeps the latest lines of each node
//! and of itself for the panel. The system journal stays the full record.
use crate::model::{identifier, now_ms};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    sync::{Mutex, OnceLock},
};

/// Lines kept by each process and, on the controller, for each source.
pub const KEEP: usize = 2000;
/// At most this many lines, and this much text, go with one report.
pub const BATCH_LINES: usize = 200;
pub const BATCH_BYTES: usize = 64 * 1024;
const LINE_CHARS: usize = 1000;
/// The controller's own lines are kept under this source name.
pub const CONTROLLER: &str = "controller";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    pub seq: u64,
    pub at_ms: i64,
    pub level: Level,
    pub text: String,
}

/// Lines of one process run, oldest first; `stream` is new on every start.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub stream: String,
    pub lines: Vec<Line>,
}

/// The last line the controller holds from a source. An empty stream asks
/// for every line the agent still keeps.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Cursor {
    pub stream: String,
    pub seq: u64,
}

struct Ring {
    stream: String,
    next: u64,
    lines: VecDeque<Line>,
}

fn ring() -> &'static Mutex<Ring> {
    static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
    RING.get_or_init(|| {
        Mutex::new(Ring {
            stream: uuid::Uuid::new_v4().simple().to_string(),
            next: 1,
            lines: VecDeque::new(),
        })
    })
}

fn clip(text: &str) -> String {
    text.chars().take(LINE_CHARS).collect()
}

/// Adds a line to this process's ring.
pub fn record(level: Level, text: &str) {
    let line = Line {
        seq: 0,
        at_ms: now_ms(),
        level,
        text: clip(text),
    };
    let mut ring = ring().lock().unwrap();
    let seq = ring.next;
    ring.next += 1;
    ring.lines.push_back(Line { seq, ..line });
    if ring.lines.len() > KEEP {
        ring.lines.pop_front();
    }
}

/// This process's lines after `cursor`, or `None` when there are none or no
/// controller has asked for them yet.
pub fn after(cursor: Option<&Cursor>) -> Option<Batch> {
    let cursor = cursor?;
    let ring = ring().lock().unwrap();
    let from = if cursor.stream == ring.stream {
        cursor.seq
    } else {
        0
    };
    let mut bytes = 0;
    let lines: Vec<Line> = ring
        .lines
        .iter()
        .filter(|line| line.seq > from)
        .take(BATCH_LINES)
        .take_while(|line| {
            bytes += line.text.len();
            bytes <= BATCH_BYTES
        })
        .cloned()
        .collect();
    (!lines.is_empty()).then(|| Batch {
        stream: ring.stream.clone(),
        lines,
    })
}

/// A tracing layer that copies every event passing the subscriber's filter
/// into this process's ring.
pub struct Capture;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut text = Text::default();
        event.record(&mut text);
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => Level::Error,
            tracing::Level::WARN => Level::Warn,
            tracing::Level::INFO => Level::Info,
            tracing::Level::DEBUG => Level::Debug,
            tracing::Level::TRACE => Level::Trace,
        };
        record(level, &(text.message + &text.fields));
    }
}

#[derive(Default)]
struct Text {
    message: String,
    fields: String,
}

/// The event's message first, then its fields as `name=value`. A field
/// that is itself called `message` follows the format string as a field.
impl tracing::field::Visit for Text {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_debug(field, &format_args!("{value}"));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && self.message.is_empty() {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

/// A line as the controller keeps it. `id` orders lines across sources.
/// `restarted` marks the first line of a new process run and `missing`
/// counts lines of the same run that never arrived before this one.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Kept {
    pub id: u64,
    pub source: String,
    pub at_ms: i64,
    pub level: Level,
    pub text: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub restarted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<u64>,
}

#[derive(Default)]
struct Source {
    cursor: Cursor,
    lines: VecDeque<Kept>,
}

/// The controller's copy of every source's latest lines.
#[derive(Default)]
pub struct Sources {
    last_id: u64,
    sources: HashMap<String, Source>,
}

impl Sources {
    /// Keeps the lines of `batch` newer than what `source` holds and returns
    /// where the copy now ends.
    pub fn add(&mut self, source: &str, batch: Option<Batch>) -> Cursor {
        let kept = self.sources.entry(source.to_owned()).or_default();
        if let Some(batch) = batch.filter(|b| identifier(&b.stream)) {
            let fresh = batch.stream != kept.cursor.stream;
            let restarted = fresh && !kept.cursor.stream.is_empty();
            let mut last = if fresh { 0 } else { kept.cursor.seq };
            for line in batch.lines.into_iter().take(BATCH_LINES) {
                if line.seq <= last {
                    continue;
                }
                self.last_id += 1;
                kept.lines.push_back(Kept {
                    id: self.last_id,
                    source: source.to_owned(),
                    at_ms: line.at_ms,
                    level: line.level,
                    text: clip(&line.text),
                    restarted: restarted && last == 0,
                    missing: (last > 0 && line.seq > last + 1).then(|| line.seq - last - 1),
                });
                last = line.seq;
                if kept.lines.len() > KEEP {
                    kept.lines.pop_front();
                }
            }
            kept.cursor = Cursor {
                stream: batch.stream,
                seq: last,
            };
        }
        kept.cursor.clone()
    }

    /// Takes in the lines this process logged since the last call.
    pub fn add_own(&mut self) {
        loop {
            let cursor = self
                .sources
                .get(CONTROLLER)
                .map(|s| s.cursor.clone())
                .unwrap_or_default();
            let Some(batch) = after(Some(&cursor)) else {
                return;
            };
            self.add(CONTROLLER, Some(batch));
        }
    }

    /// Lines newer than `after` from `source`, or from every source, oldest
    /// first. With more than `limit`, the newest `limit` and `true`.
    pub fn read(&self, source: Option<&str>, after: u64, limit: usize) -> (Vec<Kept>, bool) {
        let mut lines: Vec<&Kept> = self
            .sources
            .iter()
            .filter(|(id, _)| source.is_none_or(|s| s == id.as_str()))
            .flat_map(|(_, s)| s.lines.iter().filter(|line| line.id > after))
            .collect();
        lines.sort_by_key(|line| line.id);
        let skip = lines.len().saturating_sub(limit);
        (
            lines[skip..].iter().map(|l| (*l).clone()).collect(),
            skip > 0,
        )
    }

    pub fn last_id(&self) -> u64 {
        self.last_id
    }

    pub fn forget(&mut self, source: &str) {
        self.sources.remove(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(stream: &str, seqs: &[u64]) -> Option<Batch> {
        Some(Batch {
            stream: stream.into(),
            lines: seqs
                .iter()
                .map(|&seq| Line {
                    seq,
                    at_ms: seq as i64,
                    level: Level::Info,
                    text: format!("line {seq}"),
                })
                .collect(),
        })
    }

    #[test]
    fn resent_lines_are_kept_once_and_restarts_and_gaps_are_marked() {
        let mut sources = Sources::default();
        assert_eq!(sources.add("n", None), Cursor::default());
        // After a controller restart the agent's first kept line is not seq 1;
        // that is not a gap.
        assert_eq!(sources.add("n", batch("a", &[5, 6])).seq, 6);
        // A lost reply makes the agent resend lines the controller kept.
        let cursor = sources.add("n", batch("a", &[5, 6, 7, 10]));
        assert_eq!(
            cursor,
            Cursor {
                stream: "a".into(),
                seq: 10
            }
        );
        // The agent restarted: its new run starts again at 1.
        sources.add("n", batch("b", &[1, 2]));
        sources.add("other", batch("c", &[1]));
        let (lines, truncated) = sources.read(Some("n"), 0, 100);
        assert!(!truncated);
        let seen: Vec<_> = lines
            .iter()
            .map(|l| (l.text.as_str(), l.restarted, l.missing))
            .collect();
        assert_eq!(
            seen,
            [
                ("line 5", false, None),
                ("line 6", false, None),
                ("line 7", false, None),
                ("line 10", false, Some(2)),
                ("line 1", true, None),
                ("line 2", false, None),
            ]
        );
        // Reading every source after a known id returns only newer lines, by
        // arrival, and keeps the newest when limited.
        let (lines, truncated) = sources.read(None, lines[3].id, 2);
        assert!(truncated);
        let texts: Vec<_> = lines
            .iter()
            .map(|l| (l.source.as_str(), l.text.as_str()))
            .collect();
        assert_eq!(texts, [("n", "line 2"), ("other", "line 1")]);
        assert_eq!(sources.last_id(), lines[1].id);
    }

    #[test]
    fn captured_events_keep_their_level_message_and_fields() {
        use tracing_subscriber::prelude::*;
        let marker = uuid::Uuid::new_v4().to_string();
        tracing::subscriber::with_default(tracing_subscriber::registry().with(Capture), || {
            tracing::warn!(error = %"refused", port = 9000, "{marker} target failed");
            let message = "cannot stage TCP listener";
            tracing::warn!(%message, "{marker} configuration rejected");
        });
        let ring = ring().lock().unwrap();
        let mine: Vec<_> = ring
            .lines
            .iter()
            .filter(|l| l.text.starts_with(&marker))
            .collect();
        assert_eq!(mine[0].level, Level::Warn);
        assert_eq!(
            mine[0].text,
            format!("{marker} target failed error=refused port=9000")
        );
        assert_eq!(
            mine[1].text,
            format!("{marker} configuration rejected message=cannot stage TCP listener")
        );
    }

    #[test]
    fn a_process_sends_lines_only_after_being_asked_and_in_bounded_batches() {
        assert_eq!(after(None), None);
        let marker = uuid::Uuid::new_v4().to_string();
        for i in 0..BATCH_LINES + 5 {
            record(Level::Warn, &format!("{marker} {i}"));
        }
        // An unknown stream asks for everything still kept.
        let first = after(Some(&Cursor::default())).unwrap();
        assert!(first.lines.len() <= BATCH_LINES);
        let mut cursor = Cursor::default();
        let mut mine = vec![];
        while let Some(batch) = after(Some(&cursor)) {
            cursor = Cursor {
                stream: batch.stream.clone(),
                seq: batch.lines.last().unwrap().seq,
            };
            mine.extend(
                batch
                    .lines
                    .into_iter()
                    .filter(|l| l.text.starts_with(&marker)),
            );
        }
        assert_eq!(mine.len(), BATCH_LINES + 5);
        assert!(mine.windows(2).all(|w| w[0].seq < w[1].seq));
        assert_eq!(mine[0].level, Level::Warn);
    }
}
