//! Tenant-scoped support tickets with a message thread. Internal notes are
//! visible only to administrators.
use crate::model::now_ms;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketPriority {
    Low,
    Normal,
    High,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Pending,
    Closed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub subject: String,
    pub priority: TicketPriority,
    pub status: TicketStatus,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TicketMessage {
    pub id: String,
    pub ticket_id: String,
    pub author_id: String,
    pub body: String,
    pub internal: bool,
    pub created_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct TicketView {
    pub ticket: Ticket,
    pub messages: Vec<TicketMessage>,
}
#[derive(Clone, Debug)]
pub struct NewTicket {
    pub subject: String,
    pub body: String,
    pub priority: TicketPriority,
}
pub fn validate_subject(subject: &str) -> Result<()> {
    ensure!(
        !subject.trim().is_empty()
            && subject.len() <= 200
            && !subject.chars().any(char::is_control),
        "ticket subject must contain 1..200 bytes without control characters"
    );
    Ok(())
}
pub fn validate_body(body: &str) -> Result<()> {
    ensure!(
        !body.trim().is_empty() && body.len() <= 10_000 && !body.contains('\0'),
        "ticket message must contain 1..10000 bytes"
    );
    Ok(())
}
pub fn now() -> i64 {
    now_ms()
}
