# Forwarding diagrams — 0.120.0

The rule editor now draws the route while you edit it. The multi-node wizard shows the ordered VPSs, and the controller-validated preview redraws the proposed configurations before publication. Saved rules have a **View path diagram** action in **Multi-hop topology**.

## Create a path

1. Open **Forwarding rules** or **Multi-hop topology**, then **Create forwarding path**.
2. Choose the exit service: fixed-target forwarding or Shadowsocks on the final VPS.
3. Select the VPS for each hop. Supply its local listener and the address that the client or previous hop can reach. Add, remove or reorder hops as required.
4. Watch the diagram update. The first VPS is the entry, intermediate VPSs relay traffic, and the final VPS connects to the destination. Reordering also moves the SS service to the new final VPS.
5. For fixed-target forwarding, enter the final destinations. Multiple targets are candidates selected by the rule's policy, not additional sequential hops.
6. Select **Validate & preview path**. Review the diagram, per-node revision changes and configuration differences. This action does not publish, open a firewall port or send a network probe.
7. Publish when ready. Check each Agent's applied revision in Topology, then test through the entry with a real client.

For an individual rule, **Run on node / VPS** selects its execution location. **Check configuration and path** uses the same rule serialization as direct publication, including advanced settings. **Back to edit** retains the form. Referenced next-hop rules are expanded; manually entered targets remain external addresses because an address alone does not establish another managed VPS.

## Read the diagram

```text
SS client → Entry VPS → Relay VPS → Exit VPS → Requested website
            forwarding  forwarding  SS service
```

Every managed VPS needs an Agent. Native SS is included in the Agent and is enabled only on the exit rule produced by the wizard. The client connects to the entry address using the exit's SS credentials. A managed protocol gateway such as VLESS requires its supported engine and security configuration on the service VPS first.

The cards distinguish **Connect to** from **Local listener**. A wildcard listener such as `0.0.0.0:9000` is not a client connection address. Loopback addresses work only on the same machine. The diagram flags incomplete addresses, unavailable references, loops, duplicate wizard nodes, tenant/protocol mismatches, disabled rules and missing Agents. The controller remains the authority for full configuration validation.

Arrows show the declared forwarding direction; responses return through the connection. WS/TLS/WSS labels describe wrappers on the configured link. Ordinary multiple targets form branches. Multipath aggregation is labeled as parallel subflows; the diagram does not imply that independent bandwidth has been measured or combined. Port ranges are represented by their first port and carry a notice.

The three verification stages are deliberately separate:

- **Configuration check:** draft, server-validated preview, or saved desired configuration.
- **Agent application:** confirm applied and desired revisions after publication.
- **Real traffic:** test TCP, UDP and the observed exit using an actual client. An applied revision alone does not prove this stage.

Previously saved downstream rules and node enrollment information come from the topology snapshot loaded when the editor opens. Reopen the editor to refresh them after another operator changes the topology. Publish validation and revision checks still run on the server. The diagram does not display SS passwords, proxy passwords, UUIDs or Reality private keys.

## Lessons from Volatile Cloud

The [Volatile forwarding form](https://volatile.cloud/forward) was inspected interactively on 2026-10-29. These observations describe visible controls, not verified implementation or network performance:

- It separates the **entry protocol**, **ordered path segments**, and **optional custom exit protocol**. Its visible entry choices were WireGuard, RAW, SSH and SOCKS5.
- Entry selection can use a node or a published server group. Its path explanation describes WireGuard or Remora transport at added node boundaries.
- A **connection preview** updates while selecting the path. RAW forwarding presents fixed destination host/port fields and explains TCP + UDP on the public port.
- Custom exit choices included SOCKS5 and SS2022. This is an outbound exit-proxy setting; Relay's SS service card describes an inbound server terminating the client's SS connection. The two roles should not share an ambiguous “SS installed here” label.

Relay adopts the clear role separation, live preview and contextual explanation. This change does not add Volatile's WireGuard, SSH, Remora or server-group implementations. No Volatile service was created and its traffic performance was not tested.

## Verification scope

- JavaScript syntax, all existing UI contract tests, both language suites and new diagram tests passed locally.
- Diagram tests cover exit-only SS placement, changed hop order, unsaved targets, candidate branches, missing references, cycles, protocol/tenant mismatch, UoT's TCP requirement, bounded expansion and credential exclusion.
- An isolated controller accepted the three-hop SS and two-hop WS/candidate previews. Preview actions left revisions unchanged. Publishing a single-rule draft affected the selected node and preserved the existing exit rule.
- Browser checks covered next-hop selection, add/remove targets, returning from preview, saved topology diagrams, Chinese/English labels, desktop rendering and dark-mode rendering at 390 × 844. No horizontal page/dialog overflow was observed in the narrow viewport.
- This is a UI/configuration-workflow change. It is not a new VPS traffic, throughput or endurance acceptance run. The [0.119.0 measured forwarding limitations](RELEASE_0.119.0_EN.md) continue to apply.
