//! Speed limits: token buckets with optional burst credit, the fair line
//! bulk sends wait in, and the combined, upload and download limits of one
//! rule, user share or node. The arithmetic takes the time as an argument,
//! so it is tested on a synthetic clock.
use super::{BUFFER_SIZE, MIN_STREAM_BUFFER};
use crate::model::{Burst, RateDirection, RateLimits};
use std::{collections::VecDeque, sync::Mutex as StdMutex, time::Duration};
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
    /// Sends of at least `SMALL_SEND` bytes wait here: one queue per user in
    /// arrival order, and the users take turns.
    line: VecDeque<(u64, VecDeque<u64>)>,
    next_ticket: u64,
}
/// Smaller sends (interactive traffic, a new connection's first reads) skip
/// the line, so bulk transfers cannot delay them.
const SMALL_SEND: usize = MIN_STREAM_BUFFER;
/// Token bucket over the bytes one limit counts. Bulk sends take turns:
/// users in rotation, each user's sends in arrival order, and a session
/// reading again rejoins at the back. Users share the rate evenly however
/// many connections each opens, and so do one user's connections, instead
/// of racing for each refill.
pub(super) struct Limiter {
    bucket: StdMutex<Bucket>,
    turn: tokio::sync::Notify,
}
/// Leaves the line when a send is admitted or abandoned (session cancelled).
struct Ticket<'a> {
    limiter: &'a Limiter,
    user: u64,
    id: u64,
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        let mut b = self.limiter.bucket.lock().unwrap();
        let first = b.line.front().and_then(|(_, q)| q.front()) == Some(&self.id);
        let Some(at) = b.line.iter().position(|(user, _)| *user == self.user) else {
            return;
        };
        b.line[at].1.retain(|&t| t != self.id);
        // The user who just sent goes to the back of the rotation.
        let (user, queue) = b.line.remove(at).unwrap();
        if !queue.is_empty() {
            if first {
                b.line.push_back((user, queue));
            } else {
                b.line.insert(at, (user, queue));
            }
        }
        drop(b);
        if first {
            self.limiter.turn.notify_waiters();
        }
    }
}
impl Limiter {
    pub fn new(pace: Option<Pace>) -> Self {
        Self {
            bucket: StdMutex::new(Bucket {
                tokens: Tokens::new(pace, Instant::now()),
                line: VecDeque::new(),
                next_ticket: 0,
            }),
            turn: tokio::sync::Notify::new(),
        }
    }
    pub fn set(&self, pace: Option<Pace>) {
        self.bucket.lock().unwrap().tokens.set(pace, Instant::now());
        // Waiters re-check: a removed rate admits everyone at once.
        self.turn.notify_waiters();
    }
    pub fn credit(&self) -> Option<(u64, u64)> {
        self.bucket.lock().unwrap().tokens.credit(Instant::now())
    }
    pub async fn throttle(&self, bytes: usize, user: u64) {
        let mut ticket = None;
        loop {
            // Registered before checking, so a turn handed over in between is not missed.
            let turn = self.turn.notified();
            let wait = {
                let mut b = self.bucket.lock().unwrap();
                if b.tokens.pace.is_none() {
                    return;
                }
                if bytes >= SMALL_SEND && ticket.is_none() {
                    let id = b.next_ticket;
                    b.next_ticket += 1;
                    match b.line.iter_mut().find(|(u, _)| *u == user) {
                        Some((_, queue)) => queue.push_back(id),
                        None => b.line.push_back((user, VecDeque::from([id]))),
                    }
                    ticket = Some(Ticket {
                        limiter: self,
                        user,
                        id,
                    });
                }
                let head = b.line.front().and_then(|(_, q)| q.front());
                let my_turn = ticket.as_ref().is_none_or(|t| head == Some(&t.id));
                if !my_turn {
                    None
                } else {
                    match b.tokens.take(bytes, Instant::now()) {
                        Ok(()) => return,
                        Err(wait) => {
                            Some(wait.clamp(Duration::from_millis(1), Duration::from_secs(1)))
                        }
                    }
                }
            };
            match wait {
                Some(wait) => sleep(wait).await,
                None => turn.await,
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
    pub async fn throttle(&self, bytes: usize, user: u64, upload: bool) {
        self.0[0].throttle(bytes, user).await;
        self.0[index(direction(upload))].throttle(bytes, user).await;
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
