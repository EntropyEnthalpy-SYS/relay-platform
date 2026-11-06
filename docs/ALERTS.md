# Notification delivery and tenant scope

Email delivery uses SMTP with required STARTTLS or implicit TLS. Server certificates and names are verified. A private CA PEM may be added without disabling public roots or verification. Unencrypted delivery is restricted to a literal loopback IP and cannot carry credentials. SMTP passwords are omitted from public views and debug output. Saving an empty password preserves the old one only when host, port, username and security mode remain unchanged.

A channel may have `tenant_id: null` for all tenants or an existing tenant ID. Only system administrators using an interactive session can create, change, delete or test channels and alter the global maintenance window. Tenant administrators can read their own incidents and dedicated channels; viewers cannot read operational alerts. Global channels and other tenants' incidents and deliveries are excluded from tenant views. SMTP editing details are shown only to system administrators.

Routing filters incidents before grouping messages. Every asynchronous delivery attempt rechecks the complete channel configuration and each incident's ownership (its node, budget or DNS record). Deleting, disabling or changing a channel cancels queued attempts made from its old configuration. Changes cannot recall a message already accepted by an SMTP server or webhook. The controller keeps the most recent 200 resolved incidents and deliveries in memory; these are not a durable mail archive. Retries use 10 seconds, 60 seconds and 300 seconds; SMTP delivery has a 20-second overall deadline.

Example channel (replace the placeholders locally; never put a real credential in a committed example):

```json
{
  "tenant_id": "default",
  "name": "Tenant operations",
  "enabled": true,
  "min_severity": "warning",
  "target": {
    "kind": "smtp",
    "config": {
      "host": "smtp.example.test",
      "port": 587,
      "security": "starttls",
      "from": "Relay <relay@example.test>",
      "to": ["operator@example.test"],
      "username": "relay",
      "password": "ENTER_LOCALLY",
      "ca_pem": ""
    }
  }
}
```

`GET /api/v1/alerts` returns `can_manage`, settings, redacted channel views and scoped incidents. Existing webhook and chatbot payloads are unchanged. `POST /api/v1/alerts/channels/{id}/test` sends a real notification and should be used only with an intended recipient. Automated tests use loopback SMTP and HTTP fixtures; no real recipient was contacted during this development work.

Acceptance coverage includes recipient routing, header injection, STARTTLS downgrade refusal without credential disclosure, certificate trust failures, custom CA success, saved-secret redaction, tenant grouping, scoped reads and cancellation after channel changes or deletion. Actual SMTP-provider delivery requires an authorized provider and recipient.

## Threshold rules

Besides unavailable targets, rejected configurations and offline nodes, which are always on, the controller can raise seven kinds of incident. Each has a rule with `enabled`, a `threshold` where the problem has a level, and `checks`: how many checks in a row must find the problem before the incident opens. **Every rule is off by default**, so an upgrade sends no new kinds of notice.

| Rule | Problem | Threshold (default) | Checks (default) | Severity | Incident key |
| --- | --- | --- | --- | --- | --- |
| `node_cpu` | host CPU use at or above the threshold | 1–100 % (90) | 5 | warning | `cpu:<node>` |
| `node_memory` | host memory use, (total − available) / total, at or above the threshold | 1–100 % (90) | 5 | warning | `memory:<node>` |
| `node_expiring` | the node profile's `expires_at_ms` is at most N days away, or already passed | 1–365 days (7) | 1 | warning | `expiring:<node>` |
| `node_expired` | `expires_at_ms` has passed | — | 1 | critical | `expired:<node>` |
| `budget_near` | a shared budget's `committed_bytes` reach the threshold share of `limit_bytes` | 1–100 % (90) | 1 | warning | `budget_near:<budget>` |
| `budget_exhausted` | `committed_bytes` equal `limit_bytes`: nothing is left to allocate | — | 1 | critical | `budget_exhausted:<budget>` |
| `dns_sync_failed` | a managed DNS record's last provider sync left `last_error` | — | 1 | warning | `dns:<record>` |

`checks` is 1–100. CPU and memory come from each node's agent report (`EngineStats.system`) and are checked once per **new** report the alert worker sees; the worker runs every 2 seconds and agents report every 5 seconds by default, so the defaults mean about 25 seconds of high use. A report seen on several passes counts once; reports that arrive faster than the worker runs are not all counted. A node that stops reporting keeps its count and its open CPU or memory incident; its silence is the offline incident's job. The other rules are checked on every pass of the worker. Budget use is measured the way the **Shared budgets** page shows *committed*: consumed bytes plus reservations not yet returned. A budget with `limit_bytes` 0 is an operator's stop for new allocations and raises nothing. An approaching expiry stays open after the node expires, so an expiring node has both incidents and no misleading recovery notice.

One check without the problem resolves the incident (with a recovery text such as *CPU 使用率回落到 42%*), as does extending or removing a node's expiry, topping up a budget or a successful DNS sync. Switching a rule off resolves its open incidents with the text *此项告警已停用* and forgets the counts; switching it on again counts from zero. Deleting a node, budget or DNS record drops its incidents without a notice, as before for nodes. Like the built-in incidents, a problem that returns within 5 minutes is one incident with a repeat count, notices are grouped and held during maintenance, and a controller restart re-detects open problems instead of replaying old notices.

**Tenant routing**: CPU, memory and expiry incidents belong to the node's tenant and budget incidents to the budget's tenant, so tenant channels and tenant administrators receive and see their own. DNS records belong to no tenant (only system administrators manage DNS), so their incidents reach only channels for all tenants and never appear in tenant views. Channels with `min_severity: critical` receive expired nodes and exhausted budgets besides configuration rejections and offline nodes.

**API and storage**: `GET /api/v1/alerts` returns `settings.rules` with every rule, defaults filled in. `PUT /api/v1/alerts/settings` (system administrators in an interactive session, as before) accepts `{"maintenance_until_ms": …, "rules": {…}}`; a body without `rules` keeps the saved rules, so the maintenance buttons and older scripts do not reset them, and rules left out of `rules` take their defaults. Out-of-range values return 400, as does a `threshold` on a rule without a level. Rules are stored in the existing `alert_settings` metadata value; until rules are first saved the stored value is unchanged, so older controllers can still read it, but after a save they cannot (the settings struct rejects unknown fields). Example:

```json
{
  "maintenance_until_ms": null,
  "rules": {
    "node_cpu": {"enabled": true, "threshold": 85, "checks": 6},
    "budget_exhausted": {"enabled": true, "checks": 1}
  }
}
```

In the panel, the **Alert rules** card on the Alerts page lists every rule; **Edit rules** (system administrators) changes them. Incident texts are translated in the English panel; notices stay in Chinese like the built-in ones.

**Verification**: unit tests in `alerts.rs` cover consecutive counting (a report seen on several passes counts once, a low report starts over), recovery texts, switching a rule off and on, every threshold boundary, the owner keys and settings compatibility and validation. `tests/alerts.rs` drives CPU and memory through real sync reports and the running worker to webhook notices and recoveries, and checks the settings API (defaults, permissions, validation, rules kept by a maintenance-only save). `tests/tenant_alerts.rs` checks that a budget, an expired node of another tenant and a failing DNS record are routed to the right tenant and global channels after maintenance, are hidden from other tenants, and resolve with recovery notices.
