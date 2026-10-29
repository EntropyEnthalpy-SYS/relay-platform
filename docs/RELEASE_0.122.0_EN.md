# Clear setup workflows — 0.122.0

The workspace now separates three views of the same configuration:

- **Node rules** manages listeners, proxy services and targets on one selected VPS.
- **Forwarding paths** shows complete entry-to-destination diagrams. Intermediate and exit rules are grouped under their entry rather than repeated as separate paths. Standalone rules remain visible, even without an advertised address. Shared exits can appear in several paths; missing references and cycles remain visible with diagnostics.
- **Templates** includes four built-in starting points: single-VPS forwarding, single-VPS Shadowsocks, multi-hop forwarding and multi-hop Shadowsocks. Saved custom rule templates appear separately below them.

Adding a rule begins with the intended connection. The guided forms identify the VPS, listener, reachable address, target or proxy credentials, then show a path preview. In multi-hop SS setups, only the final VPS receives an SS service; earlier hops forward encrypted traffic. VPSs still require an Agent. Managed protocols still require their supported engine.

Optional target tuning, health checks, multipath, port ranges and limits are grouped in expandable sections. Existing configured options remain editable. SS keys are hidden by default with an explicit reveal control.

New guided rules and saved-template applications require a server-validated preview before publication. The preview preserves the node's other rules and uses its expected revision, so concurrent configuration changes are rejected. A custom template's reachable address is entered for the destination VPS rather than silently copied from the original VPS. Existing-rule edits retain their existing update workflow.

Chinese and English labels, search metadata and handbook instructions have been updated together. The path page renders at most ten entry paths per page. Diagram bounds and credential exclusion remain unchanged.

This release changes the UI workflow; it does not make new VPS throughput or native-UDP WAN reliability claims. The 0.121.0 network acceptance qualification remains applicable. UI validation uses an isolated local controller and browser, followed by preservation and HTTP/TCP/UDP smoke checks on the existing local playground.

Verification completed on 2026-10-29:

- All ten UI regression scripts passed in Chinese and English (20 runs), including path grouping, existing editor settings, protocol serialization and translation contracts.
- Browser checks exercised all four built-in templates. Single-VPS forwarding and a reordered three-hop SS path were published to an isolated controller with no Agents; the stored configuration placed SS only on the exit. Single-VPS SS and fixed-target multi-hop previews were cancelled without changing configurations.
- A custom saved template was reused through preview and publish. The clone retained its target, received the new VPS address, and had a fresh rule identity and metering period.
- The local release build passed. Restarting the existing playground preserved both node identities, credentials and configurations; both Agents acknowledged their existing revisions. HTTP, TCP and UDP smoke tests passed. All seven served web assets matched the source.
- The updated local Templates screen showed all four built-ins with an empty custom-template collection. Browser checks recorded no console warnings or errors.
