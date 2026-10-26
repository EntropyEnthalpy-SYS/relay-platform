//! Operator announcements. Global announcements are visible to every tenant;
//! tenant announcements are scoped by the existing tenant boundary.
use crate::model::now_ms;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
#[derive(Clone, Debug)]
pub struct AnnouncementDraft {
    pub tenant_id: Option<String>,
    pub title: String,
    pub body: String,
    pub severity: Severity,
    pub starts_at_ms: i64,
    pub ends_at_ms: Option<i64>,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    pub id: String,
    /// `None` is global; `Some` is a tenant announcement.
    pub tenant_id: Option<String>,
    pub title: String,
    pub body: String,
    pub severity: Severity,
    pub starts_at_ms: i64,
    pub ends_at_ms: Option<i64>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
}
pub fn validate(title: &str, body: &str, starts_at_ms: i64, ends_at_ms: Option<i64>) -> Result<()> {
    ensure!(
        !title.trim().is_empty() && title.len() <= 200 && !title.chars().any(char::is_control),
        "announcement title must contain 1..200 bytes without control characters"
    );
    ensure!(
        body.len() <= 10_000 && !body.contains('\0'),
        "announcement body must be at most 10000 bytes"
    );
    ensure!(starts_at_ms >= 0, "announcement start must be nonnegative");
    ensure!(
        ends_at_ms.is_none_or(|end| end > starts_at_ms),
        "announcement end must be after its start"
    );
    Ok(())
}
pub fn active(announcement: &Announcement, tenant: &str, now: i64) -> bool {
    announcement.enabled
        && announcement.starts_at_ms <= now
        && announcement.ends_at_ms.is_none_or(|end| end > now)
        && announcement
            .tenant_id
            .as_deref()
            .is_none_or(|id| id == tenant)
}
pub fn now() -> i64 {
    now_ms()
}
