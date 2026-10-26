# Relay Platform 0.20.0 — Response to the 0.19 Source Review

Date: 27 October 2026. Baseline: supplied `relay-platform-0.19-51db7ea` source.
Review: `Review_0.19_vs_0.18_EN.md` and `Evidence_and_Reproductions.zip`.

## Decision

All four P1 findings and both P2 findings are corrected in 0.20.0. Each review
reproduction has a permanent regression test that asserts the desired behaviour,
and the full macOS suite is green (297 Rust tests, 29 Python deployment tests,
plus the shipped editor-serializer check). The state-compatibility fix was also
verified with the actual 0.18.0, 0.19.0 and 0.20.0 binaries against fresh local
state. No production state, remote server or signed installer rollback was used.

## Findings

### R1 (P1) — advertised listener bypassed the user limit

**Change.** `store/user_rates.rs` no longer filters `advertise.is_none()` when
building per-owner participants, and `Engine::apply` gives every rule the
owner's share. Advertised addresses are reachable directly, so topology metadata
alone cannot prove an already metered upstream.

**Regression.** `review_regressions::advertised_listener_enforces_the_owners_limit_for_direct_clients`
publishes an advertised rule with a 16 KiB/s limit, confirms the controller
grants a share, and confirms that a direct 1 MiB echo cannot complete in one
second while a small exchange still succeeds. Existing share tests were updated
to stop expecting the exemption.

**Boundary.** Multi-hop flows now execute a share at each hop. Link throughput
can therefore be lower than the sum of one node's shares. The platform still
lacks authenticated upstream metering, so charging only the entry is not safe.

### R2 (P1) — a failed revision removed the retained limit

**Change.** `UserRates::refresh` builds participants from the union of the
node's desired and last-applied revisions; a node stops participating in an old
rule only after it reports the new `applied_revision`. `agent::run` applies a
share list only when the synchronization has no pending activation error;
otherwise it renews the shares already in force with `Engine::renew_user_shares`.
The controller still answers with the same `SyncResponse.user_rates` shape.

**Regression.** `review_regressions::rejected_revision_renews_the_running_limit_instead_of_removing_it`
forces revision 2 to fail on an occupied port, verifies the controller still
returns the revision-1 owner's share, renews it and proves a 1 MiB exchange is
throttled. `control_agent::rejected_config_keeps_the_running_user_share_on_a_managed_agent`
repeats this through a real managed Agent and checks that the share is retired
only after the blocker is released and revision 2 activates.

### R3 (P1) — a name-only Shadowsocks edit forgot TCP replay state

**Change.** TCP salt state now lives in the engine, keyed by the cryptographic
identity (method and derived key). Rule revisions that keep that identity share
one cache; a key or method change starts a new replay domain. The cache is kept
only while a rule references it, and a rejected `apply` leaves the old map
untouched.

**Regression.** `review_regressions::shadowsocks_replay_state_survives_compatible_rule_revisions`
replays the same authenticated request before an edit, then after a rename and
after a rate change; each is refused. A fresh salt is accepted, old-key
ciphertext is refused after a key change, and the new key is accepted. UDP
association replay tests remain unchanged; this finding is TCP-specific.

### R4 (P1) — downgrade could bypass enabled 2FA

**Change.** The application schema is raised to `PRAGMA user_version=5` without
changing any table, and `relay build-info` reports
`controller_schema: 5` and `state_contract: {controller: 2, agent: 2}`. The
recovery-log format remains 4 and its schema fingerprint is unchanged, so
continuous logs survive the upgrade. 0.18.0 and 0.19.0 refuse schema 5 in
`Store::open`; the signed installer refuses a rollback across contract 2→1.
`relay restore` accepts schema-4 backups, replays the same log, then upgrades the
output to schema 5.

**Regression.** `recovery::application_schema_five_fences_downgrades_without_rewriting_tables`
checks the fence does not rewrite tables. `scripts/check_state_fence.py` runs real
binaries and reports: 0.20 password-only login after enabling MFA = 401; 0.19 and
0.18 refuse the state with `database schema newer than this binary`; 0.20 reopens
with a recovery code = 200 and the revoked API token still 401; a 0.19 schema-4 state migrates with recovery sequence 3→5→6 and
then rejects 0.19; a 0.19 backup plus log restores under 0.20 with login 200.

**Boundary.** The fence applies to state after a 0.20 controller has opened it.
A deployment still running 0.19 state with MFA enabled must upgrade before any
rollback discussion; 0.18 still ignores 0.19 MFA state if started before the
upgrade. Signed installer rollback itself was not executed (no root service
manager changes were made).

### R5 (P2) — saving a rule silently cancelled draining

**Change.** The target editor has an explicit maintenance-draining control and
`read()` emits `draining: true` when selected. A no-change save preserves the
field; choosing “normal use” removes it deliberately.

**Regression.** `scripts/test_web_editor.cjs` executes the shipped
`targetEditor` with form-control stubs and checks preservation of `draining`,
`via`, TLS, PROXY, WebSocket, priority, prewarm and session limits, plus explicit
ending of maintenance. This is serialization coverage, not a browser click test.

### R6 (P2) — macOS verification path

**Change.** The telemetry test requires a traffic sample on every platform but
gates CPU/RSS/memory assertions to Linux and asserts explicit nulls elsewhere.
The listener migration test keeps the portable specific↔wildcard transition and
routes 127.0.0.2 and the conflict rollback to Linux. The stalled-primary test no
longer depends on a partially full accept queue (macOS resets new SYNs); the
primary accepts TCP but never answers a TLS handshake, which is deterministic
and portable. Thresholds allow a loaded runner while still proving the 1 s hedge
wins before the 3 s connect deadline.

**Regression.** The three tests named above pass in the full parallel suite.

## Verification

macOS 27.0.1 arm64, Rust/Cargo 1.99.1, Python 3.14.4, Node 24.22.0:

```text
cargo fmt --all -- --check                                  pass
cargo clippy --locked --all-targets -- -D warnings          pass
cargo test --locked --all-targets                            297 passed, 0 failed, 1 ignored helper
python3 -m unittest discover -s scripts/tests               29 passed
node --check web/app.js                                      pass
node scripts/test_web_editor.cjs web/app.js                  pass
cargo build --locked --release                               pass (macOS strip warning due to missing libLLVM.dylib)
python3 scripts/check_state_fence.py ...                     pass (see state-fence evidence)
```

The Linux suite adds one conditional unit test (298 Rust + 29 Python). The
`docs/VALIDATION.md` introduction previously mixed a 289-test partial run with a
318 total; 0.20.0 now reports one complete population and keeps the historical
0.19 observations clearly marked.

## Remaining scope

0.20.0 is a correctness/security release, not completion of the 22-module
platform. Linux two-node acceptance, the 72-hour mixed-load run, browser
click-through beyond the previously accepted pages, long-term telemetry,
cross-panel sharing, commerce, subscriptions, DNS, NAT/WireGuard, kernel MPTCP
and the remaining protocol matrix stay open. The review's performance caveats
remain: no same-hardware comparison against the reference products is claimed.

## Artifacts

- `relay-platform-dev-0.20.0-source.zip` — source at the release commit.
- `relay-platform-dev-0.20.0-manifest.json` — archive, source fingerprint,
  binary hash, test counts and environment.
- `relay-platform-0.20.0-verification/` — verification log, state-fence JSON,
  evidence manifest and this response.
