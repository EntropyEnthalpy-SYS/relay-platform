# Managed HTTP/2 CONNECT (0.113.0)

HTTP/2 CONNECT is now a managed TCP rule. Set `inbound_http2_connect` and an empty `targets` array. The controller, agent, templates, revision history and rule editor carry the same configuration. Upgrade the controller before the agents: older releases reject the new rule and telemetry fields.

A managed tunnel uses the ordinary engine path for persistent upload/download accounting, combined quotas, hierarchical budgets, rule/owner/node throttling, destination DNS/IP/port policy, source ACLs, outbound binding and expiry. HTTP/2 framing and TLS overhead are not counted as application payload. Requests share their rule owner's identity; individual Bearer tokens are not separate billed users. Give different owners separate rules.

## Configuration

| Field | Meaning |
|---|---|
| `username`, `password` | Optional paired Basic credentials. |
| `bearer_token_sha256` | Up to eight distinct 64-character SHA-256 hexadecimal digests. No raw Bearer tokens are stored. |
| `allow_private_destinations` | Defaults to false. Destination ACLs still apply when true. |
| `max_concurrent_streams` | 1–4096; default 128. Shared across every TCP connection and listen port of the rule, including pending destination connects. |
| `socket_buffer_bytes` | Optional 16 KiB–4 MiB request for each send/receive OS buffer, on ingress and destination TCP sockets. Omit for OS autotuning. Linux normally doubles the requested size for accounting. |

`max_connections` separately limits physical TCP connections. A multiplexed client cannot bypass the rule's stream limit. New tunnels over the limit receive 429. Authentication failures receive 407, unsupported methods 405, malformed authorities 400, and failed destination setup 502. ACL and private-address rejection also fail destination setup and never establish a tunnel.

`inbound_tls` selects a local certificate profile. TLS listeners require ALPN `h2`; `client_ca` enables mutual TLS. Without `inbound_tls`, the listener uses HTTP/2 prior knowledge (`h2c`). Use TLS on public networks. This version does not combine an HTTP/2 rule with an outer WebSocket listener, multipath transport or fixed-target health checks. Web traffic transported inside a CONNECT tunnel is opaque.

## Credential lifecycle

The UI can create a random 256-bit token and calculate its digest in the browser. The plaintext appears only in the current dialog. Save it before closing. Add the new digest alongside the old one for a rotation overlap, deploy the revision, migrate clients, then remove the old digest. A credential/configuration security change closes existing tunnels, so revoked credentials cannot retain an old connection. Disabling a rule, expiry and engine shutdown also release its tunnels and permits.

Basic and Bearer can coexist. Leaving both empty explicitly creates an unauthenticated proxy; restrict its source network. Mutual TLS may be required in addition to either scheme. This is per-rule credential management, not OAuth/OIDC or per-token user accounting.

## Low-memory settings

An initial constrained profile is `max_connections=64`, `max_concurrent_streams=64`, `socket_buffer_bytes=32768`. These are operating parameters to validate against a workload, not hardware guarantees. Automatic TCP buffer growth can consume substantial kernel memory when many clients read slowly. A cgroup limit must include that memory, not just process RSS. Smaller buffers trade per-connection throughput over high-latency paths for lower memory demand. The default remains OS autotuning.

The verification package records both the exploratory failure under automatic socket buffers and subsequent tests with explicit buffers. Do not turn the smallest successful short batch into a general minimum-memory claim.

## Clients and observations

A curl HTTPS proxy example is:

```sh
curl --proxy-http2 --proxytunnel \
  --proxy https://PROXY_HOST:PORT \
  --proxy-cacert proxy-ca.pem \
  --proxy-user USER:PASSWORD \
  https://DESTINATION/
```

Bearer clients send `Proxy-Authorization: Bearer TOKEN` using curl's `--proxy-header` option. Keep actual credentials in a private curl configuration or secret store. The server only implements CONNECT. Browsers can tunnel HTTPS sites; ordinary HTTP requests sent as forward-proxy GET requests are not implemented. A successful HTTPS browser check does not certify every browser, operating system or proxy client.

Telemetry adds `active_http2_streams`, a node-detail UI row, and the Prometheus gauge `relay_node_active_http2_streams`. TCP connection counters remain physical connections. Existing standalone `http2-connect` CLI commands retain their Basic-auth compatibility interface; managed rules provide the new credential and resource controls.

## Reproduce

- `cargo test --locked --test managed_http2 -- --test-threads=1` checks metering/quota, multi-connection limits, ACLs, shared rates, rotation, TLS/mTLS/ALPN, expiry/disable/idle cleanup and templates.
- `node scripts/test_web_http2.cjs web/app.js` checks editor serialization and invalid input.
- `scripts/check_linux_capacity.py` creates isolated systemd units, a real controller/agent pair, test certificates, curl loads and private fixture credentials. It needs root on a test host with systemd/cgroup v2, Python, curl with HTTP/2 support and OpenSSL. Read its arguments first. It does not upgrade an existing installation or alter the firewall.
- `scripts/check_browser_http2.cjs PRIVATE_LAB_JSON OUTPUT [--proxy]` exercises a fresh Chromium profile through CDP. The normal mode tests panel interactions; `--proxy` tests an HTTPS origin through the HTTP/2 proxy. Certificate pinning applies only to the generated test certificate.
- Create `WORKDIR/start-soak` after external probes to release the bounded soak gate. The lab stops its own service units at completion. Test credential files and browser profiles are private fixtures and must not be included in public packages.

Protocol references: [HTTP/2 CONNECT and resource considerations](https://www.rfc-editor.org/rfc/rfc9113.html), [Basic authentication](https://www.rfc-editor.org/rfc/rfc7617.html), [curl HTTPS proxy options](https://curl.se/docs/manpage.html).
