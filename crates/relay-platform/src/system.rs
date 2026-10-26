//! Host and process resource samples that agents attach to their reports.
//! Linux only (`/proc`); other platforms report nothing rather than guesses.
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemStats {
    /// Whole-host CPU busy share since the previous sample, 0..=100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f32>,
    /// This process's CPU time since the previous sample, as a share of one core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_cpu_percent: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_available_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_1m: Option<f32>,
    pub cpus: u32,
}

impl SystemStats {
    /// Values a controller accepts; anything else is dropped, not clamped.
    pub fn plausible(&self) -> bool {
        let percent =
            |v: Option<f32>, max: f32| v.is_none_or(|v| v.is_finite() && (0.0..=max).contains(&v));
        let cores = self.cpus.clamp(1, 4096) as f32;
        (1..=4096).contains(&self.cpus)
            && percent(self.cpu_percent, 100.0)
            && percent(self.process_cpu_percent, 100.0 * cores)
            && percent(self.load_1m, 100_000.0)
            && self
                .memory_available_bytes
                .zip(self.memory_total_bytes)
                .is_none_or(|(available, total)| available <= total)
    }
}

/// Keeps the previous CPU counters so each sample covers the time since the last.
#[derive(Default)]
pub struct Sampler {
    last: Option<Reading>,
}

struct Reading {
    at: Instant,
    process: Option<u64>,
    host: Option<(u64, u64)>,
}

/// Linux reports process times in USER_HZ ticks, fixed at 100 by the kernel ABI.
const TICKS_PER_SECOND: f64 = 100.0;

impl Sampler {
    pub fn sample(&mut self) -> SystemStats {
        let now = Instant::now();
        let process = process_ticks();
        let host = host_ticks();
        let mut stats = SystemStats {
            cpus: std::thread::available_parallelism().map_or(1, |n| n.get() as u32),
            ..Default::default()
        };
        if let Some(last) = &self.last {
            let seconds = now.duration_since(last.at).as_secs_f64();
            if let (Some(before), Some(after)) = (last.process, process)
                && seconds > 0.0
            {
                let used = after.saturating_sub(before) as f64 / TICKS_PER_SECOND;
                stats.process_cpu_percent = Some((used / seconds * 100.0) as f32);
            }
            if let (Some((total0, idle0)), Some((total1, idle1))) = (last.host, host) {
                let total = total1.saturating_sub(total0);
                if total > 0 {
                    let busy = total.saturating_sub(idle1.saturating_sub(idle0));
                    stats.cpu_percent = Some((busy as f64 / total as f64 * 100.0) as f32);
                }
            }
        }
        self.last = Some(Reading {
            at: now,
            process,
            host,
        });
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        stats.memory_total_bytes = kib_field(&meminfo, "MemTotal:");
        stats.memory_available_bytes = kib_field(&meminfo, "MemAvailable:");
        stats.rss_bytes = kib_field(
            &std::fs::read_to_string("/proc/self/status").unwrap_or_default(),
            "VmRSS:",
        );
        stats.load_1m = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok());
        if !stats.plausible() {
            return SystemStats {
                cpus: stats.cpus.max(1),
                ..Default::default()
            };
        }
        stats
    }
}

fn kib_field(text: &str, name: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with(name))?;
    let kib: u64 = line[name.len()..].split_whitespace().next()?.parse().ok()?;
    kib.checked_mul(1024)
}

/// utime + stime of this process. The command name may contain spaces, so
/// fields are counted after its closing parenthesis.
fn process_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
}

/// (all ticks, idle + iowait ticks) from the aggregate `cpu` line.
fn host_ticks() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let values: Vec<u64> = stat
        .lines()
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    let idle = values.get(3)? + values.get(4).copied().unwrap_or(0);
    // Guest time is already included in user and nice.
    Some((values.iter().take(8).sum(), idle))
}
