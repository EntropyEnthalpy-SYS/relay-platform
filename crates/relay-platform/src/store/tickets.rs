//! Ticket persistence in metadata. Visibility is owner, tenant administrator
//! or system administrator; internal notes never reach the owner.
use super::*;
use crate::ticket::{
    NewTicket, Ticket, TicketMessage, TicketStatus, TicketView, validate_body, validate_subject,
};

fn ticket_key(id: &str) -> String {
    format!("ticket:{id}")
}
fn message_key(id: &str) -> String {
    format!("ticket_message:{id}")
}
fn read_ticket(conn: &Connection, id: &str) -> Result<Option<Ticket>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [ticket_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_ticket(tx: &Transaction<'_>, value: &Ticket) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![ticket_key(&value.id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn all_tickets(conn: &Connection) -> Result<Vec<Ticket>> {
    let mut q =
        conn.prepare("SELECT value FROM metadata WHERE key GLOB 'ticket:*' ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored ticket"))
        .collect()
}
fn messages(conn: &Connection, ticket: &str) -> Result<Vec<TicketMessage>> {
    let mut q =
        conn.prepare("SELECT value FROM metadata WHERE key GLOB 'ticket_message:*' ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut values: Vec<TicketMessage> = rows
        .into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored ticket message"))
        .collect::<Result<_>>()?;
    values.retain(|message| message.ticket_id == ticket);
    values.sort_by_key(|message| message.created_at_ms);
    Ok(values)
}
fn write_message(tx: &Transaction<'_>, value: &TicketMessage) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![message_key(&value.id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn can_view(actor: &Actor, ticket: &Ticket) -> bool {
    actor.role == Role::SystemAdmin
        || (actor.role == Role::TenantAdmin && actor.tenant_id == ticket.tenant_id)
        || actor.id == ticket.user_id
}
fn can_manage(actor: &Actor, ticket: &Ticket) -> bool {
    actor.role == Role::SystemAdmin
        || (actor.role == Role::TenantAdmin && actor.tenant_id == ticket.tenant_id)
}
fn view(conn: &Connection, ticket: Ticket, actor: &Actor) -> Result<TicketView> {
    let mut messages = messages(conn, &ticket.id)?;
    if !can_manage(actor, &ticket) {
        messages.retain(|message| !message.internal);
    }
    Ok(TicketView { ticket, messages })
}

impl Store {
    pub fn tickets(&self, actor: &Actor) -> Result<Vec<Ticket>> {
        let conn = self.0.lock().unwrap();
        let mut tickets = all_tickets(&conn)?;
        tickets.retain(|ticket| can_view(actor, ticket));
        tickets.sort_by_key(|ticket| std::cmp::Reverse(ticket.updated_at_ms));
        Ok(tickets)
    }
    pub fn ticket(&self, actor: &Actor, id: &str) -> Result<TicketView> {
        let conn = self.0.lock().unwrap();
        let ticket = read_ticket(&conn, id)?.context("ticket not found")?;
        if !can_view(actor, &ticket) {
            return reject(403, "ticket belongs to another user");
        }
        view(&conn, ticket, actor)
    }
    pub fn create_ticket(&self, actor: &Actor, input: NewTicket) -> Result<TicketView> {
        validate_subject(&input.subject)?;
        validate_body(&input.body)?;
        let now = now_ms();
        let ticket = Ticket {
            id: Uuid::new_v4().to_string(),
            tenant_id: actor.tenant_id.clone(),
            user_id: actor.id.clone(),
            subject: input.subject,
            priority: input.priority,
            status: TicketStatus::Open,
            created_at_ms: now,
            updated_at_ms: now,
        };
        let message = TicketMessage {
            id: Uuid::new_v4().to_string(),
            ticket_id: ticket.id.clone(),
            author_id: actor.id.clone(),
            body: input.body,
            internal: false,
            created_at_ms: now,
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_ticket(&tx, &ticket)?;
        write_message(&tx, &message)?;
        audit(&tx, &actor.id, "ticket.create", &ticket.id, "{}")?;
        tx.commit()?;
        Ok(TicketView {
            ticket,
            messages: vec![message],
        })
    }
    pub fn reply_ticket(
        &self,
        actor: &Actor,
        id: &str,
        body: &str,
        internal: bool,
    ) -> Result<TicketView> {
        validate_body(body)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut ticket = read_ticket(&tx, id)?.context("ticket not found")?;
        if !can_view(actor, &ticket) {
            return reject(403, "ticket belongs to another user");
        }
        if internal && !can_manage(actor, &ticket) {
            return reject(403, "internal notes require an administrator");
        }
        if ticket.status == TicketStatus::Closed {
            return reject(409, "closed tickets cannot receive messages");
        }
        let message = TicketMessage {
            id: Uuid::new_v4().to_string(),
            ticket_id: ticket.id.clone(),
            author_id: actor.id.clone(),
            body: body.into(),
            internal,
            created_at_ms: now_ms(),
        };
        ticket.updated_at_ms = message.created_at_ms;
        if !internal && ticket.status == TicketStatus::Pending {
            ticket.status = TicketStatus::Open;
        }
        write_message(&tx, &message)?;
        write_ticket(&tx, &ticket)?;
        audit(&tx, &actor.id, "ticket.reply", &ticket.id, "{}")?;
        let view = view(&tx, ticket, actor)?;
        tx.commit()?;
        Ok(view)
    }
    pub fn set_ticket_status(
        &self,
        actor: &Actor,
        id: &str,
        status: TicketStatus,
    ) -> Result<TicketView> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut ticket = read_ticket(&tx, id)?.context("ticket not found")?;
        if !can_manage(actor, &ticket)
            && !(actor.id == ticket.user_id && status == TicketStatus::Closed)
        {
            return reject(
                403,
                "only the owner may close, or an administrator may change status",
            );
        }
        ticket.status = status;
        ticket.updated_at_ms = now_ms();
        write_ticket(&tx, &ticket)?;
        audit(&tx, &actor.id, "ticket.status", &ticket.id, "{}")?;
        let view = view(&tx, ticket, actor)?;
        tx.commit()?;
        Ok(view)
    }
}
