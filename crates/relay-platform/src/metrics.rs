//! Process-local diagnostic samples, never billing or quota authority.
use serde::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingStats {
    pub samples: u64,
    pub total_us: u64,
    pub max_us: u64,
}

#[derive(Default)]
pub(crate) struct Timing {
    samples: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
}
impl Timing {
    pub fn record(&self, elapsed: Duration) {
        let us = elapsed.as_micros().min(crate::model::MAX_COUNTER as u128) as u64;
        self.samples.fetch_add(1, Ordering::Relaxed);
        let mut current = self.total_us.load(Ordering::Relaxed);
        loop {
            match self.total_us.compare_exchange_weak(
                current,
                current.saturating_add(us),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        self.max_us.fetch_max(us, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> TimingStats {
        TimingStats {
            samples: self.samples.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeterStats {
    pub admission_batches: TimingStats,
    pub admission_requests: u64,
    pub failed_batches: u64,
    pub budget_wait: TimingStats,
    pub budget_waiting: u64,
    pub budget_timeouts: u64,
}
