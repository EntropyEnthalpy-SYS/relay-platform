# UI review and appearance controls — 0.126.0

This release refines the existing Relay workspace. The warm paper light theme, charcoal dark theme, terracotta default, navigation and forwarding workflows remain recognizable. Appearance choices are local browser preferences; they do not change node configurations.

## Choose your appearance

Open **Appearance** in the header (the sliders icon on narrow screens).

| Setting | Choices | Behavior |
|---|---|---|
| Theme | Light, Dark, System | System follows the operating system's color preference, including changes while the page is open. |
| Accent color | Terracotta, Ocean blue, Forest green, Iris violet | Styles navigation, primary actions and throughput charts. Healthy, warning and error states retain their own colors and text. |
| Overview display mode | Expanded, Compact | Expanded uses larger charts and full-width paths/events. Compact uses smaller summaries. Both use the same real telemetry. |

Changes save immediately in this browser. **Done** or Escape closes the dialog. Existing light/dark and overview preferences remain compatible; the old Monitoring and Workspace layouts are now labelled Expanded and Compact. The default is Light, Terracotta and Expanded. Blocked preference storage does not prevent switching during the current page session.

English and Chinese remain available from the header. Wide tables and diagrams scroll inside their own regions. Table regions can be focused with Tab and scrolled with the arrow keys. Appearance options have 48-pixel minimum touch height.

## Functional corrections

- A counter needs two increasing timestamps before it establishes throughput. Missing samples, duplicate timestamps and reset counters remain unknown; measured zero is still shown as zero. The overview peak follows the same rule.
- Offline or unenrolled nodes show unknown active sessions in the node and path views. Zero is reserved for a recent report showing no sessions.
- All 19 API-backed page renderers reject delayed results after navigation, sign-out or an account change. An expired response from an old session cannot sign out a newer session.
- Direct connections in the overview graph route around intervening VPS cards. Each edge identifies its source and destination; unprobed links remain visually distinct. This graph summarizes declared rules and probe results, not a packet trace.
- Input boundaries, small labels and table actions are more readable. Headers identify their column scope, and scrollable tables have accessible names and keyboard focus.

## Rule creation and service placement

1. Open **Node rules → Add rule**, **Templates**, or **Forwarding paths → Create forwarding path**.
2. Choose single-VPS forwarding, single-VPS SS, multi-hop forwarding, or multi-hop SS.
3. Select entry, optional relay VPSs, and exit. Save each VPS's reachable address once; the controller suggests ports within its configured range, avoiding managed conflicts. Suggestions are not operating-system port reservations.
4. Click a diagram card, or focus it and press Enter, to edit that hop. Changes require a new server preview.
5. Choose **Preview changes**, inspect the roles, addresses and revision changes, then **Publish these changes**.
6. Check every Agent's applied revision, then test real traffic through the entry. In an SS path, earlier hops forward encrypted traffic; only the exit has an SS service. Every participating VPS needs the Agent. Publication does not perform SSH installation or open firewall ports.

## Review coverage

The companion verification package contains the results and logs for this release. A page-loading pass is separate from exercising an operation or testing real traffic.

| Area | Review performed |
|---|---|
| Navigation and translation | All 20 pages in English and Chinese; title/content, visible errors, page overflow and table headers. |
| Permissions | Viewer navigation across its 15 available pages; infrastructure write controls absent; node creation rejected by the API. Three-role navigation/search boundaries are also covered by the existing automated suite. |
| Management forms | Open/cancel checks for node enrollment/filtering, revision history, node rate limits, shared budgets, notification channels, subscriptions, DNS providers, announcements, tickets, user creation and password change. These checks do not certify every external integration. |
| Guided paths | Isolated three-hop SS selection, missing-address setup, automatic allocation, Enter-key diagram editing, server preview and publication; saved configurations inspected for exit-only SS. |
| Appearance | Eight explicit theme/accent combinations, stored preference reload, desktop/mobile layout, scrollable mobile settings, Escape, keyboard table scrolling and sampled contrast calculations. These are focused checks, not a complete accessibility certification. |
| Browser races and telemetry | Byte-conserving chart bins, unknown versus zero, duplicate timestamps, counter resets, 57 delayed-response cases across 19 pages and three expired-session cases. |
| Regression | `scripts/verify.sh`: formatting, Clippy, Rust tests, bilingual UI scripts, release build and deployment tests. Explicit managed-engine and local forwarding acceptance results are recorded separately. |
| Local panel update | Rebuild the embedded assets, preserve controller state/credentials/node identities, confirm Agent revisions, and exercise existing HTTP/TCP/UDP forwarding. |

Local automated results: **465 default Rust tests passed**, with six default ignores; five of those optional managed-engine tests were then run explicitly and passed using the pinned sing-box and mihomo fixtures. The remaining ignore is a crash-worker subprocess helper exercised by its parent test. **30 deployment tests**, **22 JavaScript test-script executions**, and **29 automatic-path checks with three real local Agents** passed. The browser audit covered 40 administrator page/language combinations, 15 viewer pages, 12 management forms and eight mobile pages. All eight explicit light/dark accent combinations passed the sampled contrast checks (lowest normal-text ratio 4.57:1; control-border minimum 3.17:1).

The payment workflow is outside this delivery's acceptance scope. Default regression still includes existing commerce unit/integration tests; their success is not payment-provider certification.

## Remaining acceptance boundaries

This release does not establish new VPS/WAN throughput, endurance, minimum-hardware, physical-mobile or cross-browser results. The native UDP WAN loss observed during the 0.124.0 VPS run remains open. External DNS/provider changes, SMTP/notification delivery, certificate renewal, Linux MPTCP/multi-interface behavior and full disaster-recovery operations need their own environment-specific acceptance. Local engine/client interoperability does not replace that work.

The forwarding engine and rule schema are unchanged in this release. See [the non-payment target checklist](NONPAYMENT_TARGETS_EN.md), [current status](STATUS.md), and the prior VPS verification evidence before interpreting an implemented feature as fully accepted.
