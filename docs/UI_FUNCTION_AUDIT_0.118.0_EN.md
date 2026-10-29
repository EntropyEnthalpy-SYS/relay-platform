# UI and function alignment audit — 0.118.0

Date: 2026-10-29. Development source based on `a5e7541513b60bf53eca009e1fe57188ad6398a6`, with the changes described below. This report covers the local controller, local Agents, browser UI, and automated regression suite. It is not a new VPS deployment or a production certification.

## Result

The rule editor and topology workflow now expose where each service runs. A single rule belongs to one selected VPS. A forwarding path explicitly connects an entry, optional relays, and an exit. For a Shadowsocks path, the entry and relays forward encrypted traffic, and only the exit runs the Shadowsocks service.

```text
Client --SS encrypted TCP/UDP--> VPS1 entry --> VPS2 relay --> VPS3 SS exit --> destination
```

The browser-created three-Agent path passed TCP and UDP traffic checks with a separate sing-box client. An immediate TCP write-half-close limitation also reproduced using an upstream-only sing-box client/server pair; it remains documented below.

## Corrections delivered

| Area | Previous mismatch | Current behavior |
| --- | --- | --- |
| Rule placement | The dialog did not clearly identify the deployment VPS. | A **Run on node / VPS** selector appears in the dialog. New rules can select another node in the same tenant; editing retains the existing node. Saving loads and preserves that node's other rules. |
| Protocol selection | TCP/UDP and several proxy-service forms appeared together. | **Rule purpose** selects forwarding, SS, SOCKS5, HTTP CONNECT, HTTP/2 CONNECT, or managed protocols. **Transport protocol** separately controls TCP/UDP. Unrelated editors are hidden and disabled. |
| Unsupported settings | Hidden listener, WebSocket, and gateway values could survive a mode change or block submission. | The editor serializes supported combinations and clears incompatible gateway listener options. Optional numeric fields remain unset rather than becoming zero. |
| Multi-hop creation | A single-node proxy form did not represent a VPS1 → VPS2 → VPS3 path. | **Create forwarding path** provides ordered entry/relay/exit cards, VPS selection, listeners, advertised endpoints, per-hop source ACLs, and a preview before publication. Existing rules and revision checks are preserved. |
| Service placement | Operators could confuse forwarding a protocol with running its server. | The wizard can create SS only on the final VPS. Single-node dialogs state where the service runs. |
| Client export | Controller hostname fallback or exit-only addresses could be misleading. | Direct links use the rule's advertised/listen endpoint; wildcard endpoints require an explicit host. **Entry client link** combines the entry address with the SS exit credentials for an unambiguous supported chain. |
| Runtime status | An enabled desired rule or online Agent could imply successful service operation. | The UI distinguishes desired enablement, pending configuration, apply rejection, offline status, and configuration acknowledgment. Client traffic must be tested separately. Actual apply errors appear on the rules page. |
| Missing protocol engines | Saving a managed-protocol rule could be mistaken for automatic installation. | The form states that the engine and certificate/Reality materials must already exist on the selected VPS. Agent rejection is visible. |
| Templates | Native prompts failed in the embedded browser; direct links lacked a node list; rollout examples used revision zero; applying could leave the wrong page/node selected. | Panel dialogs replace native prompts. Template pages load their own nodes, rollout examples use current revisions, and applying opens the target VPS's rules. |
| Role permissions | Tenant administrators could create templates through the API but could not reach the template page. | Tenant administrators can manage their tenant templates. Global template deletion/rollback stays restricted to system administrators. Viewer write controls remain hidden. |
| Confirmations | Native `prompt()`/`confirm()` was unsupported in the in-app browser. | Accessible panel dialogs provide accept, cancel, and Escape handling. Sequential prompts preserve their contents and distinguish cancel from an empty value. |
| Documentation and labels | Feature status, subscriptions, onboarding, and some translations implied broader automation or acceptance. | Labels explain Agent enrollment versus installation, subscription filtering, engine prerequisites, CLI-only features, and implementation versus live acceptance. Chinese and English labels were updated together. |

## How to use the corrected workflow

### One rule on one VPS

1. Register the node under **Nodes** and install/enroll its Agent on that VPS. Registering the record does not SSH into or install software on the machine.
2. Open **Forwarding rules → Add rule**.
3. Select **Run on node / VPS**.
4. Choose **Rule purpose**. For an SS server, select **Shadowsocks · Exit proxy service**. For a simple relay, select port forwarding and enter the next destination.
5. Set the listener on that VPS. A `127.0.0.1` listener is local to that VPS; `0.0.0.0` is a bind address, not a client destination. Use an actual reachable IP or hostname for advertised/client endpoints.
6. Configure credentials, source restrictions, quotas, and limits as appropriate. Publish, wait for acknowledgment, then test real traffic from the intended client.

### VPS1 → VPS2 → VPS3 with Shadowsocks on VPS3

1. Enroll all three Agents. Use three distinct VPS nodes in the same tenant and select the intended owner.
2. Open **Forwarding rules → Create forwarding path**, or use the same action in **Multi-hop topology**.
3. Select **Create Shadowsocks on exit VPS**. The wizard uses native TCP + UDP forwarding between these nodes.
4. Assign VPS1 as entry, add VPS2 as a relay, and assign VPS3 as exit. Confirm the order in the path summary.
5. Enter a listener and reachable advertised endpoint for each hop. For example, listeners can be `0.0.0.0:19121`, `0.0.0.0:19122`, and `0.0.0.0:19123`; advertised endpoints must use each VPS's actual reachable address. NAT may require a different advertised port.
6. Restrict relay/exit source ACLs to the addresses of their preceding hops where appropriate. Account for NAT: use the source IP actually observed by the receiving VPS. Allow the corresponding TCP and UDP ports in the host and provider firewalls. The panel does not modify these firewalls.
7. Configure the SS method and key on the exit. Keep private/local destination access disabled unless the intended workload requires it.
8. Preview the changes. Check every VPS, preserved rule, revision, listener, and exit placement. Use **Back to edit** if needed, then publish.
9. Wait for every node to acknowledge. If any node rejects its configuration, inspect the error; publication is not a simultaneous all-node runtime switch.
10. In topology, use **Entry client link**. The client connects to VPS1 and uses VPS3's SS credentials. Test both TCP and UDP from outside the VPS network.

The wizard currently creates fixed-target forwarding paths and SS exit paths. It does not automatically construct every managed-protocol chain. Native, WS, and WSS inter-node wrappers are available for compatible fixed-target TCP paths; the SS wizard deliberately uses native forwarding.

## Browser coverage

All 20 navigation pages loaded in English and Chinese without a recorded page-load failure. This checks rendering and initial reads; it does not mean every button was used against a live external service.

| Page | Rendering / initial reads | Additional coverage or boundary |
| --- | --- | --- |
| Overview | EN + ZH passed | Control connectivity and pending/applied semantics reviewed; proxy exit path rendering corrected. |
| Nodes | EN + ZH passed | Onboarding explanation reviewed; three real local Agents used. No SSH installation or VPS mutation in this audit. |
| Forwarding rules | EN + ZH passed | Selected-VPS SS creation, protocol editor visibility, managed-engine failure, revision restore, and live status checked in browser. |
| Rule templates | EN + ZH passed | Sequential prompts, direct reload, target-node application, actual forwarded HTTP traffic, cancel, and current-revision bulk form checked. |
| Multi-hop topology | EN + ZH passed | Three-hop SS preview/publication, all-node acknowledgment, entry link, real TCP and UDP traffic checked. |
| Target health | EN + ZH passed | Initial data/read presentation; detailed engine behavior is covered by regression tests. |
| Traffic ledger | EN + ZH passed | Real fixture traffic available; no new billing reconciliation certification. |
| Shared budgets | EN + ZH passed | Existing backend concurrency/accounting regression tests rerun. |
| Alerts & notifications | EN + ZH passed | Initial configuration and forms checked by existing JS tests; no external message sent. |
| Client subscriptions | EN + ZH passed | Scope and supported-format wording reviewed; no arbitrary chain rewrite claimed. |
| DNS management | EN + ZH passed | Initial reads and shared dialogs reviewed; no live DNS provider write. |
| Announcements | EN + ZH passed | Initial reads; no public announcement published. |
| Support tickets | EN + ZH passed | Initial reads; no external support message sent. |
| Wallet & orders | EN + ZH passed | Rendering only in browser. Payment delivery and financial transactions are outside scope. |
| Users & permissions | EN + ZH passed | System administrator, tenant administrator, and viewer navigation/control visibility checked. |
| Account security | EN + ZH passed | Initial reads and regression tests; no user credential changed. |
| Audit log | EN + ZH passed | Local acceptance actions generated records. |
| Recovery protection | EN + ZH passed | Initial reads; fixture revision recovery exercised. No destructive restore of user state. |
| Feature status | EN + ZH passed | Implementation status, dependencies, and remaining live acceptance are distinguished. |
| Handbook | EN + ZH passed | Rule placement, multi-hop, client link, and onboarding guidance aligned. |

Responsive check: at a 390 × 844 viewport, the revised rule dialog had no horizontal overflow. Viewer navigation exposed 15 pages and no rule/path creation controls. Tenant administrator navigation exposed 17 pages, including templates, with no global-template delete control.

## Verification evidence

The accompanying verification package contains the full regression log, browser acceptance matrix, path traffic results, build information, and screenshots. The source includes new workflow and dialog contract tests, integrated into `scripts/verify.sh`.

Final results: **451 Rust tests passed, 0 failed, 6 ignored; 30 Python deployment tests passed; all JavaScript checks passed, including both interface languages and the new workflow/dialog tests.** Rust formatting and Clippy checks passed. The release binary reports `0.118.0` on macOS/aarch64. All six served JS/CSS assets matched the final source byte-for-byte, and the three-Agent traffic probe passed again after restarting with that compiled binary.

The standard regression command is `sh scripts/verify.sh` with the repository's Rust toolchain, Node.js, and Python available. The default Rust run has six ignored entries: one crash-test worker invoked by its parent test, and five optional protocol-engine/client acceptance tests requiring explicit engine paths. A passing default run must not be described as having executed those five optional tests.

The independent traffic probe used three local Agent processes and sing-box 1.14.4. It verified that only the exit had SS enabled, the entry link used exit credentials, unrelated existing rules survived, all nodes acknowledged, a 105,169-byte TCP payload returned intact, and UDP payloads of 1, 64, 1,200, and 4,096 bytes returned intact. A template-created forward also delivered the HTTP fixture through the selected relay node.

No private runtime state, enrollment tokens, admin passwords, operational SS keys, or client configurations are included in either delivery ZIP.

## Local trial delivery

The hands-on panel at `http://127.0.0.1:57766/#rules` now runs the compiled 0.118.0 release. Its two existing nodes and two rules were preserved: complete configuration hashes before and after the upgrade match. Both Agents acknowledged, and the existing HTTP, TCP, and UDP forwards passed. A private local state backup was made before restarting. Refresh any older panel tab to load the updated interface.

The temporary three-Agent acceptance environment and development UI proxy were stopped after verification. The hands-on panel remains running. This delivery provides local source and evidence archives; GitHub publication and Linux rollout are separate steps.

## Remaining acceptance limits

- **Immediate TCP write-half-close with the tested sing-box SS2022 combination:** zero reply bytes were observed, including when the client connected directly to an upstream sing-box SS server with no Relay component. Direct SOCKS-to-echo returned the full payload. Normal SS TCP request/reply and UDP passed. This isolates the observation from multi-hop routing but does not establish compatibility for every client or resolve the upstream behavior.
- **External engines:** VLESS/Reality, Hysteria2, TUIC, and other managed protocols still require a supported engine and appropriate local certificate/key material. This audit intentionally verified the missing-engine rejection and recovery, not every engine/client combination.
- **Deployment and network:** the local trial is updated separately from Linux VPS installations. This audit does not establish WAN throughput, long-duration stability, production DNS/SMTP delivery, or minimum-hardware performance. Those require the corresponding Linux acceptance procedures.
- **Subscriptions:** subscription scope remains owner/tag based. The topology entry-link action covers an unambiguous supported SS chain; subscription feeds do not automatically transform arbitrary multi-hop paths into entry endpoints.
- **Publication:** controller preview and revision checks prevent invalid/stale writes, while each Agent applies asynchronously. Check every hop and actual traffic before treating a path as available.
- **Payment:** excluded from this delivery scope.

Use this report as the 0.118.0 UI supplement to the existing deployment/tutorial documents. It does not create or imply a published GitHub tag or a Linux release bundle.
