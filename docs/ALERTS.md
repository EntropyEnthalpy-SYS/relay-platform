# Notification delivery and tenant scope

Email delivery uses SMTP with required STARTTLS or implicit TLS. Server certificates and names are verified. A private CA PEM may be added without disabling public roots or verification. Unencrypted delivery is restricted to a literal loopback IP and cannot carry credentials. SMTP passwords are omitted from public views and debug output. Saving an empty password preserves the old one only when host, port, username and security mode remain unchanged.

A channel may have `tenant_id: null` for all tenants or an existing tenant ID. Only system administrators using an interactive session can create, change, delete or test channels and alter the global maintenance window. Tenant administrators can read their own incidents and dedicated channels; viewers cannot read operational alerts. Global channels and other tenants' incidents and deliveries are excluded from tenant views. SMTP editing details are shown only to system administrators.

Routing filters incidents before grouping messages. Every asynchronous delivery attempt rechecks the complete channel configuration and each incident's node ownership. Deleting, disabling or changing a channel cancels queued attempts made from its old configuration. Changes cannot recall a message already accepted by an SMTP server or webhook. The controller keeps the most recent 200 resolved incidents and deliveries in memory; these are not a durable mail archive. Retries use 10 seconds, 60 seconds and 300 seconds; SMTP delivery has a 20-second overall deadline.

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
