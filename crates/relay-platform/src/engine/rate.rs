//! Speed limits: token buckets with optional burst credit, the fair line
//! bulk sends wait in, and the combined, upload and download limits of one
//! rule, user share or node. The arithmetic takes the time as an argument,
//! so it is tested on a synthetic clock.
use super::{BUFFER_SIZE, MIN_STREAM_BUFFER};
use crate::model::{Burst, RateDirection, RateLimits};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep};

/// One limit as enforced: the sustained rate S and, with a burst, the
/// faster rate B its credit allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pace {
    pub sustained: u64,
    pub burst: Option<Burst>,
}
impl Pace {
    pub fn of(rate: Option<u64>, burst: Option<Burst>) -> Option<Self> {
        rate.map(|sustained| Self {
            sustained: sustained.max(1),
            burst: burst.filter(|b| b.bytes_per_sec > sustained && b.secs > 0),
        })
    }
    /// The combined, upload and download limits of `rate` and `limits`.
    pub fn lanes(rate: Option<u64>, limits: Option<&RateLimits>) -> [Option<Self>; 3] {
        RateLimits::lanes(limits, rate).map(|(_, rate, burst)| Self::of(rate, burst))
    }
    /// Burst credit capacity, (B − S) × W bytes.
    fn capacity(&self) -> f64 {
        self.burst
            .map_or(0.0, |burst| burst.capacity(self.sustained) as f64)
    }
}
/// What a bucket holds besides burst credit: one second of sending, and
/// never less than one full read, so a read always fits.
fn second(rate: u64) -> f64 {
    rate.max(BUFFER_SIZE as u64) as f64
}

/// Token state of one limit. `sustained` refills at S up to one second of
/// sending plus the burst credit capacity; whatever it holds above that
/// second is the burst credit. With a burst, `peak` refills at B up to one
/// second and keeps sending at or below B. So sending at a rate above S
/// spends credit at (rate − S), sending below S earns it back at
/// (S − rate) until it is full, and without credit the limit is S.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tokens {
    pace: Option<Pace>,
    sustained: f64,
    peak: f64,
    updated: Instant,
}
impl Tokens {
    /// Full: one second of sending and, with a burst, all of its credit.
    pub fn new(pace: Option<Pace>, now: Instant) -> Self {
        Self {
            sustained: Self::size(pace),
            peak: pace
                .and_then(|p| p.burst)
                .map_or(0.0, |burst| second(burst.bytes_per_sec)),
            pace,
            updated: now,
        }
    }
    fn size(pace: Option<Pace>) -> f64 {
        pace.map_or(BUFFER_SIZE as f64, |p| second(p.sustained) + p.capacity())
    }
    /// A changed limit keeps what it holds, up to its new size; a burst
    /// that was not there before starts with full credit.
    pub fn set(&mut self, pace: Option<Pace>, now: Instant) {
        if self.pace == pace {
            return;
        }
        let new_burst =
            pace.is_some_and(|p| p.burst.is_some()) && self.pace.is_none_or(|p| p.burst.is_none());
        if new_burst {
            *self = Self::new(pace, now);
            return;
        }
        self.pace = pace;
        self.sustained = self.sustained.min(Self::size(pace));
        if let Some(burst) = pace.and_then(|p| p.burst) {
            self.peak = self.peak.min(second(burst.bytes_per_sec));
        }
        self.updated = now;
    }
    fn refill(&mut self, now: Instant) {
        let Some(pace) = self.pace else {
            return;
        };
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.sustained =
            (self.sustained + elapsed * pace.sustained as f64).min(Self::size(Some(pace)));
        if let Some(burst) = pace.burst {
            self.peak =
                (self.peak + elapsed * burst.bytes_per_sec as f64).min(second(burst.bytes_per_sec));
        }
        self.updated = now;
    }
    /// Takes `bytes` when every bucket holds them; otherwise says how long
    /// until they would. Without a limit everything passes.
    pub fn take(&mut self, bytes: usize, now: Instant) -> Result<(), Duration> {
        let Some(pace) = self.pace else {
            return Ok(());
        };
        self.refill(now);
        let bytes = bytes as f64;
        let mut wait = 0f64;
        if self.sustained < bytes {
            wait = (bytes - self.sustained) / pace.sustained as f64;
        }
        if let Some(burst) = pace.burst
            && self.peak < bytes
        {
            wait = wait.max((bytes - self.peak) / burst.bytes_per_sec as f64);
        }
        if wait > 0.0 {
            return Err(Duration::from_secs_f64(wait));
        }
        self.sustained -= bytes;
        if pace.burst.is_some() {
            self.peak -= bytes;
        }
        Ok(())
    }
    /// Burst credit left now and its capacity, for a limit with a burst.
    pub fn credit(&mut self, now: Instant) -> Option<(u64, u64)> {
        let pace = self.pace.filter(|p| p.burst.is_some())?;
        self.refill(now);
        let capacity = pace.capacity();
        Some((
            (self.sustained - second(pace.sustained)).clamp(0.0, capacity) as u64,
            capacity as u64,
        ))
    }
}

struct Bucket {
    tokens: Tokens,
    line: Line,
}
/// Smaller sends (interactive traffic, a new connection's first reads) skip
/// the line while their user and session are at most `SKIP_LEAD` ahead of
/// the next bulk send, so bulk transfers cannot delay them and a flood of
/// small sends (UDP datagrams, say) cannot keep a bulk send waiting.
const SMALL_SEND: usize = MIN_STREAM_BUFFER;
/// How far ahead, in bytes of virtual time, small sends may take a user or
/// session past the next bulk send: one full read.
const SKIP_LEAD: u64 = BUFFER_SIZE as u64;
/// How often, in sends joining the line, it forgets users and sessions that
/// stopped sending.
const PRUNE_EVERY: u64 = 1024;

/// Where a user or session stands in the line, in bytes of the line's
/// virtual time: `finish` is where what it has sent ends and, while it
/// waits, `start` is where its next bulk send starts. `lined` says whether a
/// bulk send of it has passed the line before. `since` orders equal starts:
/// the ticket number at which it took its current place, so a tie goes to
/// the earlier arrival and does not change when someone joins.
#[derive(Default)]
struct Tags {
    start: Option<u64>,
    finish: u64,
    lined: bool,
    since: u64,
}
impl Tags {
    /// Where a send joining the line starts, when this user or session has
    /// nothing else waiting. One that sent before starts where it left off,
    /// or at the line's time if that has moved past it: it keeps its place
    /// but saves no credit while idle. A newcomer waits behind everyone
    /// already waiting (`last`), so a stream of new connections cannot keep
    /// a long transfer waiting.
    fn arrival(&self, clock: u64, last: Option<u64>) -> u64 {
        let start = clock.max(self.finish);
        if self.lined {
            start
        } else {
            start.max(last.unwrap_or(0))
        }
    }
}
#[derive(Default)]
struct UserLine {
    tags: Tags,
    /// The user's own virtual time: where its last admitted session started.
    clock: u64,
    sessions: HashMap<u64, SessionLine>,
    waiting: usize,
}
#[derive(Default)]
struct SessionLine {
    tags: Tags,
    /// Waiting tickets and their sizes, in arrival order.
    sends: VecDeque<(u64, u64)>,
}
/// The order bulk sends pass in: start-time fair queueing by bytes, first
/// between users and then between each user's sessions. The next send is
/// the one whose user, then whose session, starts earliest; a send that
/// passes moves its user and session on by its size, and so does a small
/// send that skips the line. So each gets the same bytes whatever size its
/// reads happen to be (a connection whose socket holds less data reads
/// less each time and passes more often), however many sessions a user
/// opens.
#[derive(Default)]
struct Line {
    /// Where the last admitted send's user started.
    clock: u64,
    users: HashMap<u64, UserLine>,
    /// The ticket that passes next, with its user and session, kept
    /// because every waiter checks it.
    head: Option<(u64, u64, u64)>,
    /// Each waiting ticket's wake-up. Whenever the head moves to a ticket,
    /// whatever moved it, that ticket is notified; the notice is kept until
    /// its sender waits, so it is never missed.
    wakes: HashMap<u64, Arc<Notify>>,
    next_ticket: u64,
    joined: u64,
}
impl Line {
    fn join(&mut self, user: u64, session: u64, bytes: u64) -> u64 {
        self.joined += 1;
        if self.joined.is_multiple_of(PRUNE_EVERY) {
            self.prune();
        }
        let id = self.next_ticket;
        self.next_ticket += 1;
        let clock = self.clock;
        let last = |starts: &mut dyn Iterator<Item = Option<u64>>| starts.flatten().max();
        let last_user = last(&mut self.users.values().map(|u| u.tags.start));
        let u = self.users.entry(user).or_default();
        if u.tags.start.is_none() {
            u.tags.start = Some(u.tags.arrival(clock, last_user));
            u.tags.since = id;
        }
        let last_session = last(&mut u.sessions.values().map(|s| s.tags.start));
        let own = u.clock;
        let s = u.sessions.entry(session).or_default();
        if s.tags.start.is_none() {
            s.tags.start = Some(s.tags.arrival(own, last_session));
            s.tags.since = id;
        }
        s.sends.push_back((id, bytes));
        u.waiting += 1;
        self.wakes.insert(id, Arc::new(Notify::new()));
        self.update_head();
        id
    }
    /// The wake-up of a waiting ticket.
    fn wake(&self, id: u64) -> Arc<Notify> {
        self.wakes[&id].clone()
    }
    /// Recomputes the head and wakes the ticket it moved to.
    fn update_head(&mut self) {
        let head = self.next();
        if head != self.head
            && let Some((ticket, _, _)) = head
        {
            self.wakes[&ticket].notify_one();
        }
        self.head = head;
    }
    /// Removes a ticket; `served` moves its user and session on by its size.
    fn leave(&mut self, user: u64, session: u64, id: u64, served: bool) {
        let Some(u) = self.users.get_mut(&user) else {
            return;
        };
        let Some(s) = u.sessions.get_mut(&session) else {
            return;
        };
        let Some(at) = s.sends.iter().position(|&(ticket, _)| ticket == id) else {
            return;
        };
        let (_, bytes) = s.sends.remove(at).unwrap();
        u.waiting -= 1;
        self.wakes.remove(&id);
        if served {
            // What still waits takes its new place now, behind equal starts.
            let since = self.next_ticket;
            self.next_ticket += 1;
            // Only the head passes, so these are the earliest starts.
            let user_start = u.tags.start.unwrap_or(self.clock);
            let session_start = s.tags.start.unwrap_or(u.clock);
            self.clock = user_start;
            // `finish` may already be past the start by skipped small sends.
            u.tags.finish = u.tags.finish.max(user_start) + bytes;
            u.tags.lined = true;
            u.clock = session_start;
            s.tags.finish = s.tags.finish.max(session_start) + bytes;
            s.tags.lined = true;
            s.tags.start = (!s.sends.is_empty()).then(|| u.clock.max(s.tags.finish));
            u.tags.start = (u.waiting > 0).then(|| self.clock.max(u.tags.finish));
            (s.tags.since, u.tags.since) = (since, since);
        } else {
            // An abandoned send changes nobody's place.
            if s.sends.is_empty() {
                s.tags.start = None;
            }
            if u.waiting == 0 {
                u.tags.start = None;
            }
        }
        self.update_head();
    }
    /// The next ticket to pass: of the user, then of that user's session,
    /// that starts earliest, ties going to the earlier arrival. A user's
    /// order does not depend on which of its sessions is next, so a join
    /// moves the head only to the ticket that joined.
    fn next(&self) -> Option<(u64, u64, u64)> {
        self.users
            .iter()
            .filter_map(|(&user, u)| {
                let (_, _, ticket, session) = u
                    .sessions
                    .iter()
                    .filter_map(|(&session, s)| {
                        Some((s.tags.start?, s.tags.since, s.sends.front()?.0, session))
                    })
                    .min()?;
                Some((u.tags.start?, u.tags.since, ticket, user, session))
            })
            .min()
            .map(|(_, _, ticket, user, session)| (ticket, user, session))
    }
    /// Whether a small send may skip the line: when nothing waits, or when
    /// its user, and its session among the head's user's sessions, would not
    /// be more than `SKIP_LEAD` ahead of the head.
    fn may_skip(&self, user: u64, session: u64) -> bool {
        let Some((_, head_user, head_session)) = self.head else {
            return true;
        };
        let head = &self.users[&head_user];
        let ahead = |tags: Option<&Tags>, clock: u64, head: &Tags| {
            tags.map_or(clock, |t| t.finish.max(clock)) > head.start.unwrap_or(clock) + SKIP_LEAD
        };
        if ahead(
            self.users.get(&user).map(|u| &u.tags),
            self.clock,
            &head.tags,
        ) {
            return false;
        }
        user != head_user
            || !ahead(
                head.sessions.get(&session).map(|s| &s.tags),
                head.clock,
                &head.sessions[&head_session].tags,
            )
    }
    /// Counts a small send that skipped the line against its user and session.
    fn charge(&mut self, user: u64, session: u64, bytes: u64) {
        let clock = self.clock;
        let u = self.users.entry(user).or_default();
        u.tags.finish = u.tags.finish.max(clock) + bytes;
        let own = u.clock;
        let s = u.sessions.entry(session).or_default();
        s.tags.finish = s.tags.finish.max(own) + bytes;
    }
    /// Forgets users and sessions that wait for nothing and are not ahead
    /// of the line's time. One that sends again later is a newcomer.
    fn prune(&mut self) {
        let clock = self.clock;
        self.users.retain(|_, u| {
            let own = u.clock;
            u.sessions
                .retain(|_, s| !s.sends.is_empty() || s.tags.finish > own);
            u.waiting > 0 || u.tags.finish > clock
        });
    }
}

/// Token bucket over the bytes one limit counts. Bulk sends wait in a
/// [`Line`] that shares the rate evenly by bytes between users however
/// many connections each opens, and between one user's connections,
/// instead of letting them race for each refill.
pub(super) struct Limiter {
    bucket: StdMutex<Bucket>,
}
/// Leaves the line when a send is admitted or abandoned (session
/// cancelled); the line wakes whoever is next.
struct Ticket<'a> {
    limiter: &'a Limiter,
    user: u64,
    session: u64,
    id: u64,
    wake: Arc<Notify>,
    served: bool,
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        let mut b = self.limiter.bucket.lock().unwrap();
        b.line.leave(self.user, self.session, self.id, self.served);
    }
}
impl Limiter {
    pub fn new(pace: Option<Pace>) -> Self {
        Self {
            bucket: StdMutex::new(Bucket {
                tokens: Tokens::new(pace, Instant::now()),
                line: Line::default(),
            }),
        }
    }
    pub fn set(&self, pace: Option<Pace>) {
        let mut b = self.bucket.lock().unwrap();
        b.tokens.set(pace, Instant::now());
        // Waiters re-check: a removed rate admits everyone at once.
        for wake in b.line.wakes.values() {
            wake.notify_one();
        }
    }
    pub fn credit(&self) -> Option<(u64, u64)> {
        self.bucket.lock().unwrap().tokens.credit(Instant::now())
    }
    /// Waits until `bytes` may pass. `session` is one connection or
    /// datagram session of `user`, unique within the engine.
    pub async fn throttle(&self, bytes: usize, user: u64, session: u64) {
        let mut ticket: Option<Ticket> = None;
        loop {
            let wait = {
                let mut b = self.bucket.lock().unwrap();
                if b.tokens.pace.is_none() {
                    return;
                }
                if ticket.is_none() && (bytes >= SMALL_SEND || !b.line.may_skip(user, session)) {
                    let id = b.line.join(user, session, bytes as u64);
                    ticket = Some(Ticket {
                        limiter: self,
                        user,
                        session,
                        id,
                        wake: b.line.wake(id),
                        served: false,
                    });
                }
                if ticket
                    .as_ref()
                    .is_some_and(|t| b.line.head.map(|(id, _, _)| id) != Some(t.id))
                {
                    None
                } else {
                    match b.tokens.take(bytes, Instant::now()) {
                        Ok(()) => {
                            match &mut ticket {
                                Some(ticket) => ticket.served = true,
                                None => b.line.charge(user, session, bytes as u64),
                            }
                            return;
                        }
                        Err(wait) => {
                            Some(wait.clamp(Duration::from_millis(1), Duration::from_secs(1)))
                        }
                    }
                }
            };
            match (wait, &ticket) {
                (Some(wait), _) => sleep(wait).await,
                // Woken when this ticket becomes the head, or the rate changes.
                (None, Some(ticket)) => ticket.wake.notified().await,
                (None, None) => unreachable!("only a ticket waits for its turn"),
            }
        }
    }
}

fn index(direction: RateDirection) -> usize {
    match direction {
        RateDirection::Combined => 0,
        RateDirection::Upload => 1,
        RateDirection::Download => 2,
    }
}
const DIRECTIONS: [RateDirection; 3] = [
    RateDirection::Combined,
    RateDirection::Upload,
    RateDirection::Download,
];
/// Which of the three limits a send in `upload` direction waits for after
/// the combined one.
pub(super) fn direction(upload: bool) -> RateDirection {
    if upload {
        RateDirection::Upload
    } else {
        RateDirection::Download
    }
}

/// The combined, upload and download limits of one rule or node. A send
/// waits for the combined limit, then for its direction's.
pub(super) struct Limits([Limiter; 3]);
impl Limits {
    pub fn new(paces: [Option<Pace>; 3]) -> Self {
        Self(paces.map(Limiter::new))
    }
    pub fn set(&self, paces: [Option<Pace>; 3]) {
        for (limiter, pace) in self.0.iter().zip(paces) {
            limiter.set(pace);
        }
    }
    pub async fn throttle(&self, bytes: usize, user: u64, session: u64, upload: bool) {
        self.0[0].throttle(bytes, user, session).await;
        self.0[index(direction(upload))]
            .throttle(bytes, user, session)
            .await;
    }
    /// Burst credit and capacity of each limit with a burst.
    pub fn bursts(&self) -> Vec<(RateDirection, u64, u64)> {
        DIRECTIONS
            .into_iter()
            .zip(&self.0)
            .filter_map(|(direction, limiter)| {
                limiter
                    .credit()
                    .map(|(credit, capacity)| (direction, credit, capacity))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    const MB: u64 = 1_000_000;
    fn burst(bytes_per_sec: u64, secs: u32) -> Option<Burst> {
        Some(Burst {
            bytes_per_sec,
            secs,
        })
    }
    /// Sends `rate` bytes/second for `secs` seconds in 10 ms steps, each
    /// waiting until the tokens allow it. Returns the bytes sent.
    fn send(tokens: &mut Tokens, now: &mut Instant, rate: u64, secs: f64) -> u64 {
        let step = Duration::from_millis(10);
        let chunk = (rate / 100) as usize;
        let end = *now + Duration::from_secs_f64(secs);
        let mut sent = 0;
        while *now < end {
            if chunk > 0 && tokens.take(chunk, *now).is_ok() {
                sent += chunk as u64;
            }
            *now += step;
        }
        sent
    }

    #[test]
    fn burst_credit_spends_refills_and_caps_by_the_model() {
        // S = 1 MB/s, B = 4 MB/s, W = 10 s: capacity (B − S) × W = 30 MB.
        let start = Instant::now();
        let mut now = start;
        let pace = Pace::of(Some(MB), burst(4 * MB, 10));
        let mut tokens = Tokens::new(pace, now);
        assert_eq!(tokens.credit(now), Some((30 * MB, 30 * MB)), "starts full");
        // At B the credit falls by (B − S) = 3 MB each second.
        assert_eq!(send(&mut tokens, &mut now, 4 * MB, 5.0), 20 * MB);
        assert_eq!(tokens.credit(now), Some((15 * MB, 30 * MB)));
        // Between S and B (2 MB/s) it falls by (rate − S) = 1 MB/s.
        assert_eq!(send(&mut tokens, &mut now, 2 * MB, 3.0), 6 * MB);
        assert_eq!(tokens.credit(now), Some((12 * MB, 30 * MB)));
        // Below S (0.25 MB/s) it is earned back at (S − rate) = 0.75 MB/s.
        assert_eq!(send(&mut tokens, &mut now, MB / 4, 4.0), MB);
        assert_eq!(tokens.credit(now), Some((15 * MB, 30 * MB)));
        // Idle for long enough, it stops at the capacity.
        now += Duration::from_secs(3600);
        assert_eq!(tokens.credit(now), Some((30 * MB, 30 * MB)));
    }

    #[test]
    fn a_full_burst_lasts_its_time_then_the_limit_is_the_sustained_rate() {
        let mut now = Instant::now();
        let mut tokens = Tokens::new(Pace::of(Some(MB), burst(4 * MB, 10)), now);
        // Asking for 8 MB/s gets B: one second of peak tokens, then 4 MB/s.
        let fast = send(&mut tokens, &mut now, 8 * MB, 3.0);
        assert!((15_800_000..=16 * MB).contains(&fast), "{fast}");
        let mut now = Instant::now();
        let mut tokens = Tokens::new(Pace::of(Some(MB), burst(4 * MB, 10)), now);
        // At B, the credit and the second at S last (30 + 1) / (4 − 1) s.
        let mut seconds = 0;
        while send(&mut tokens, &mut now, 4 * MB, 1.0) == 4 * MB {
            seconds += 1;
        }
        assert_eq!(seconds, 10, "a full burst runs at B for W seconds");
        assert_eq!(tokens.credit(now), Some((0, 30 * MB)));
        // Without credit only S passes, not B.
        let sustained = send(&mut tokens, &mut now, 4 * MB, 10.0);
        assert!(
            (9_900_000..=10 * MB + 40_000).contains(&sustained),
            "{sustained} bytes in 10 s at S = 1 MB/s"
        );
        // From empty, idle: first the second at S, then (B − S) × W / S = 30 s.
        (tokens.sustained, tokens.updated) = (0.0, now);
        now += Duration::from_secs(1);
        assert_eq!(tokens.credit(now), Some((0, 30 * MB)));
        now += Duration::from_secs(12);
        assert_eq!(tokens.credit(now), Some((12 * MB, 30 * MB)));
        now += Duration::from_secs(18);
        assert_eq!(tokens.credit(now), Some((30 * MB, 30 * MB)));
    }

    #[test]
    fn the_documented_example_bursts_five_minutes_and_refills_in_under_twelve() {
        // Burst 100 Mbps, sustained 30 Mbps, burst time 5 minutes.
        let (sustained, peak) = (30_000_000 / 8, 100_000_000 / 8);
        let mut now = Instant::now();
        let mut tokens = Tokens::new(Pace::of(Some(sustained), burst(peak, 300)), now);
        let capacity = (peak - sustained) * 300;
        assert_eq!(tokens.credit(now), Some((capacity, capacity)));
        let mut seconds = 0;
        while tokens.take(peak as usize, now).is_ok() {
            seconds += 1;
            now += Duration::from_secs(1);
        }
        assert_eq!(seconds, 300, "100 Mbps for 5 minutes");
        // Then 30 Mbps: asking for twice that for a minute gets one second
        // more than a minute at 30 Mbps (the bucket's one second).
        let mut sent = 0;
        for _ in 0..60 {
            now += Duration::from_secs(1);
            for _ in 0..2 {
                if tokens.take(sustained as usize, now).is_ok() {
                    sent += sustained;
                }
            }
        }
        assert_eq!(sent, 61 * sustained);
        // Idle, the full burst is back after one second plus 700 s ≈ 11.7 minutes.
        tokens.sustained = 0.0;
        now += Duration::from_secs(700);
        assert!(tokens.credit(now).unwrap().0 < capacity);
        now += Duration::from_secs(1);
        assert_eq!(tokens.credit(now), Some((capacity, capacity)));
    }

    #[test]
    fn changing_a_limit_keeps_or_starts_its_credit() {
        let mut now = Instant::now();
        let mut tokens = Tokens::new(Pace::of(Some(MB), None), now);
        assert_eq!(tokens.credit(now), None, "no burst, no credit");
        // A new burst starts full.
        tokens.set(Pace::of(Some(MB), burst(3 * MB, 5)), now);
        assert_eq!(tokens.credit(now), Some((10 * MB, 10 * MB)));
        send(&mut tokens, &mut now, 3 * MB, 2.0);
        assert_eq!(tokens.credit(now), Some((6 * MB, 10 * MB)));
        // A longer burst keeps what was spent.
        tokens.set(Pace::of(Some(MB), burst(3 * MB, 20)), now);
        assert_eq!(tokens.credit(now), Some((6 * MB, 40 * MB)));
        // A shorter one cuts the credit to its capacity.
        tokens.set(Pace::of(Some(MB), burst(3 * MB, 1)), now);
        assert_eq!(tokens.credit(now), Some((2 * MB, 2 * MB)));
        // Lifting the limit lets everything pass.
        tokens.set(None, now);
        assert_eq!(tokens.take(10 * MB as usize, now), Ok(()));
    }

    /// Senders in a [`Line`]: each serve passes the head, and its session
    /// rejoins at once with the same size, like a connection reading again.
    #[derive(Default)]
    struct Senders {
        line: Line,
        /// Ticket to (user, session, size).
        waiting: HashMap<u64, (u64, u64, u64)>,
        sent: HashMap<(u64, u64), u64>,
    }
    impl Senders {
        fn join(&mut self, user: u64, session: u64, size: u64) {
            let ticket = self.line.join(user, session, size);
            self.waiting.insert(ticket, (user, session, size));
        }
        /// Passes the head; `again` says whether its session reads again.
        fn pass(&mut self, again: bool) -> (u64, u64) {
            let (ticket, _, _) = self.line.head.expect("someone waits");
            let (user, session, size) = self.waiting.remove(&ticket).unwrap();
            self.line.leave(user, session, ticket, true);
            *self.sent.entry((user, session)).or_default() += size;
            if again {
                self.join(user, session, size);
            }
            (user, session)
        }
        fn sent(&self, user: u64, session: u64) -> u64 {
            self.sent.get(&(user, session)).copied().unwrap_or(0)
        }
    }

    #[test]
    fn the_line_shares_bytes_evenly_whatever_size_each_session_reads() {
        // One user's eight connections, as under one rule's cap; three of
        // them read less each time because their sockets hold less data.
        let sizes = [65536, 32768, 47168, 65536, 65536, 49152, 65536, 65536];
        let mut senders = Senders::default();
        for (session, size) in sizes.into_iter().enumerate() {
            senders.join(1, session as u64, size);
        }
        for _ in 0..4000 {
            senders.pass(true);
        }
        let shares: Vec<u64> = (0..8).map(|session| senders.sent(1, session)).collect();
        let (min, max) = (shares.iter().min().unwrap(), shares.iter().max().unwrap());
        // Taking turns would give the 32 KiB reader half of a 64 KiB one;
        // by bytes, shares differ by at most one send of each of two.
        assert!(max - min <= 2 * 65536, "{shares:?}");
        assert!(*min > 25_000_000, "{shares:?}");

        // Between users: Alice's one connection reads 32 KiB, Bob's four
        // read 64 KiB. Each user gets half, and Bob's four a quarter of his.
        let mut senders = Senders::default();
        senders.join(1, 0, 32768);
        for session in 1..=4 {
            senders.join(2, session, 65536);
        }
        for _ in 0..3000 {
            senders.pass(true);
        }
        let alice = senders.sent(1, 0);
        let bob: Vec<u64> = (1..=4).map(|session| senders.sent(2, session)).collect();
        let bob_total: u64 = bob.iter().sum();
        assert!(
            alice.abs_diff(bob_total) <= 32768 + 65536,
            "{alice} vs {bob:?}"
        );
        let (min, max) = (bob.iter().min().unwrap(), bob.iter().max().unwrap());
        assert!(max - min <= 2 * 65536, "{bob:?}");
    }

    #[test]
    fn the_line_keeps_no_credit_for_idle_users_and_forgets_finished_sessions() {
        let mut senders = Senders::default();
        senders.join(1, 0, 65536);
        for _ in 0..100 {
            senders.pass(true);
        }
        // Bob arrives after Alice sent alone. A newcomer waits behind what
        // already waits, then they alternate; Alice's head start is not held
        // against her either.
        senders.join(2, 0, 65536);
        assert_eq!(senders.pass(true), (1, 0));
        assert_eq!(senders.pass(true), (2, 0));
        for _ in 0..20 {
            senders.pass(true);
        }
        assert_eq!(senders.sent(2, 0), 11 * 65536);
        // Bob stops reading; Alice sends alone again. Back, Bob gets no
        // credit for the time he was idle: they alternate from there.
        let bob = senders
            .waiting
            .iter()
            .find(|(_, f)| f.0 == 2)
            .map(|(t, _)| *t);
        senders.waiting.remove(&bob.unwrap());
        senders.line.leave(2, 0, bob.unwrap(), false);
        for _ in 0..100 {
            assert_eq!(senders.pass(true), (1, 0));
        }
        let before = senders.sent(2, 0);
        senders.join(2, 0, 65536);
        for _ in 0..20 {
            senders.pass(true);
        }
        assert_eq!(senders.sent(2, 0) - before, 10 * 65536);

        // Thousands of short sessions, each sending once beside a long one:
        // the line forgets the finished ones instead of growing.
        let mut senders = Senders::default();
        senders.join(1, 0, 65536);
        senders.pass(true);
        for session in 1..=10_000 {
            senders.join(1, session, 16384);
            assert_eq!(senders.pass(true), (1, 0));
            assert_eq!(senders.pass(false), (1, session));
        }
        let sessions = senders.line.users[&1].sessions.len();
        assert!(
            sessions <= PRUNE_EVERY as usize + 2,
            "{sessions} sessions kept"
        );
    }

    #[test]
    fn new_connections_and_small_sends_cannot_starve_a_long_transfer() {
        // One user's long transfer beside new connections that keep coming
        // as earlier ones finish, `waiting` of them at a time, each sending
        // once; every other one first sends something small that skips the
        // line. Starting new connections at the user's current time would
        // keep the long transfer waiting for ever; it gets its turn per round.
        for waiting in [1, 3] {
            let mut senders = Senders::default();
            senders.join(1, 0, 65536);
            let mut next = 1;
            let mut arrive = |senders: &mut Senders| {
                if next % 2 == 0 {
                    assert!(senders.line.may_skip(1, next));
                    senders.line.charge(1, next, 512);
                }
                senders.join(1, next, 65536);
                next += 1;
            };
            for _ in 0..waiting {
                arrive(&mut senders);
            }
            let mut long = 0;
            for _ in 0..1000 {
                if senders.pass(false) == (1, 0) {
                    long += 1;
                    senders.join(1, 0, 65536);
                } else {
                    arrive(&mut senders);
                }
            }
            assert!(
                long * (waiting + 1) >= 900,
                "with {waiting} new connections waiting the long transfer passed {long} of 1000 times"
            );
        }

        // Another user floods small sends while a bulk send waits: they skip
        // the line until that user is one full read ahead, then queue behind.
        let mut line = Line::default();
        let bulk = line.join(1, 0, 65536);
        let mut skipped = 0;
        while line.may_skip(2, 0) {
            line.charge(2, 0, 1024);
            skipped += 1;
            assert!(skipped < 1000, "small sends skip without bound");
        }
        assert_eq!(skipped * 1024, SKIP_LEAD + 1024);
        line.join(2, 0, 1024);
        assert_eq!(line.head.map(|(ticket, _, _)| ticket), Some(bulk));
        // Interactive sends, here a new connection of the waiting user,
        // still skip a busy line.
        assert!(line.may_skip(1, 7));
        assert!(line.may_skip(3, 0));
    }

    #[test]
    fn whoever_becomes_the_head_is_woken_and_a_join_never_hands_it_to_another_waiter() {
        // A waiter that becomes the head and is not woken stalls the whole
        // limit, with tokens to spare. Three users each keep a long session
        // and open short ones that double their send size up to 64 KiB;
        // served sessions read again after a random delay, some sends are
        // abandoned and small sends skip the line, which makes equal starts
        // between users common. Every time the head moves, by a join, a
        // send passing or one abandoned, the new head must hold a wake-up
        // that its sender finds however late it starts to wait; and a join
        // moves the head only to the ticket that joined.
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut random = move |below: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % below
        };
        let mut line = Line::default();
        // Ticket to (user, session, size), and sessions about to read again.
        let mut waiting: HashMap<u64, (u64, u64, u64)> = HashMap::new();
        let mut later: Vec<(u64, u64, u64)> = (1..=3).map(|user| (user, user, 65536)).collect();
        let mut next_session = 100;
        let mut joins = 0;
        let mut woken = 0;
        for step in 0..200_000 {
            let previous = line.head;
            let join = match random(5) {
                0 => {
                    next_session += 1;
                    Some((random(3) + 1, next_session, 4096))
                }
                1 if !later.is_empty() => {
                    Some(later.swap_remove(random(later.len() as u64) as usize))
                }
                2 if !waiting.is_empty() && random(8) == 0 => {
                    let tickets: Vec<u64> = waiting.keys().copied().collect();
                    let ticket = tickets[random(tickets.len() as u64) as usize];
                    let (user, session, _) = waiting.remove(&ticket).unwrap();
                    line.leave(user, session, ticket, false);
                    None
                }
                3 => {
                    let (user, session) = (random(3) + 1, random(4) + 1);
                    if line.may_skip(user, session) {
                        line.charge(user, session, 1024);
                    }
                    None
                }
                _ => {
                    if let Some((ticket, user, session)) = line.head {
                        let (_, _, size) = waiting.remove(&ticket).unwrap();
                        line.leave(user, session, ticket, true);
                        if session <= 3 || size < 65536 {
                            later.push((user, session, if session <= 3 { size } else { size * 2 }));
                        }
                    }
                    None
                }
            };
            if let Some((user, session, size)) = join {
                let before = line.head;
                let ticket = line.join(user, session, size);
                waiting.insert(ticket, (user, session, size));
                joins += 1;
                let after = line.head.map(|(t, _, _)| t);
                assert!(
                    line.head == before || after == Some(ticket),
                    "step {step}: user {user} session {session} joined as {ticket} and moved the head from {before:?} to {after:?}"
                );
            }
            if line.head != previous
                && let Some((ticket, _, _)) = line.head
            {
                assert!(
                    line.wake(ticket).notified().now_or_never().is_some(),
                    "step {step}: the head moved from {previous:?} to {ticket} without waking it"
                );
                woken += 1;
            }
            match line.head {
                Some((ticket, user, session)) => {
                    assert_eq!(
                        waiting.get(&ticket).map(|w| (w.0, w.1)),
                        Some((user, session))
                    )
                }
                None => assert!(
                    waiting.is_empty(),
                    "step {step}: tickets wait without a head"
                ),
            }
        }
        assert!(
            joins > 80_000 && woken > 70_000,
            "{joins} joins, {woken} wake-ups"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_next_sender_passes_when_the_head_is_abandoned_or_admitted() {
        // The bucket is empty: Alice's send is the head and sleeps for
        // tokens, Bob and Carol wait for their turn. Alice's session is
        // cancelled; nothing else happens on this limiter, so Bob and then
        // Carol pass only if leaving the line woke them.
        let limiter = Arc::new(Limiter::new(Pace::of(Some(1 << 20), None)));
        limiter.bucket.lock().unwrap().tokens.sustained = 0.0;
        let send = |user: u64| {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.throttle(65536, user, user).await })
        };
        let alice = send(1);
        sleep(Duration::from_millis(20)).await;
        let (bob, carol) = (send(2), send(3));
        sleep(Duration::from_millis(20)).await;
        assert_eq!(
            limiter.bucket.lock().unwrap().line.head.map(|h| h.1),
            Some(1)
        );
        alice.abort();
        tokio::time::timeout(Duration::from_secs(5), async {
            bob.await.unwrap();
            carol.await.unwrap();
        })
        .await
        .expect("a sender waited after the head left");
        assert!(limiter.bucket.lock().unwrap().line.wakes.is_empty());
    }

    /// Two senders, one per direction, each sending `chunk` bytes as fast
    /// as the limits allow for 10 simulated seconds. Like `Limits::throttle`,
    /// a send takes the combined limit and then its direction's.
    fn both_directions(paces: [Option<Pace>; 3], chunk: usize) -> [u64; 2] {
        let start = Instant::now();
        let mut lanes = paces.map(|pace| Tokens::new(pace, start));
        let mut sent = [0u64; 2];
        // Per sender: whether the combined limit already let its send through.
        let mut passed = [false; 2];
        let mut now = start;
        let end = start + Duration::from_secs(10);
        while now < end {
            for (sender, upload) in [(0, true), (1, false)] {
                if !passed[sender] {
                    passed[sender] = lanes[0].take(chunk, now).is_ok();
                }
                if passed[sender] && lanes[index(direction(upload))].take(chunk, now).is_ok() {
                    sent[sender] += chunk as u64;
                    passed[sender] = false;
                }
            }
            now += Duration::from_millis(1);
        }
        sent
    }

    #[test]
    fn upload_and_download_limits_are_independent_and_combined_caps_the_sum() {
        let chunk = 16 * 1024;
        // A bucket starts with one second of sending; ten more pass in 10 s.
        let near = |sent: u64, rate: u64| {
            let expected = rate * 11;
            assert!(
                sent.abs_diff(expected) <= expected / 50 + chunk as u64,
                "{sent} bytes, expected {expected}"
            );
        };
        // An unlimited sender passes a chunk every millisecond.
        let unlimited = 10_000 * chunk as u64;
        let limit = |rate| Pace::of(Some(rate), None);
        // Upload 1 MB/s, download 3 MB/s, no combined limit.
        let [up, down] = both_directions([None, limit(MB), limit(3 * MB)], chunk);
        near(up, MB);
        near(down, 3 * MB);
        // Upload only: download is not slowed, and the reverse.
        let [up, down] = both_directions([None, limit(MB), None], chunk);
        near(up, MB);
        assert_eq!(down, unlimited);
        let [up, down] = both_directions([None, None, limit(MB)], chunk);
        assert_eq!(up, unlimited);
        near(down, MB);
        // A combined 2 MB/s still caps the sum, upload staying within 1 MB/s.
        let [up, down] = both_directions([limit(2 * MB), limit(MB), limit(3 * MB)], chunk);
        near(up + down, 2 * MB);
        assert!(up <= 11 * MB + chunk as u64, "upload {up}");
        // A download burst lets download run at B; upload keeps its limit.
        let [up, down] = both_directions(
            [None, limit(MB), Pace::of(Some(MB), burst(2 * MB, 100))],
            chunk,
        );
        near(up, MB);
        near(down, 2 * MB);
    }
}
