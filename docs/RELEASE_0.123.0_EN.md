# Automatic rule setup — 0.123.0

Creating a common forwarding rule now starts with VPS selection. Choose the entry, optional relays, and exit; the controller proposes addresses and ports, and the panel shows the complete path before publication. The four built-in templates share this flow, including single-VPS forwarding and Shadowsocks.

## How to use it

1. Enroll your VPSs and run their Agents. In **Nodes → Edit node**, save each VPS's reachable IP or hostname under **Connection defaults for new rules**. Enter only the host, without a port. You can also save a missing address directly in the rule setup form.
2. Open **Templates** or **Forwarding paths → Create forwarding path**. Choose port forwarding or Shadowsocks.
3. Select the **entry VPS** and **exit VPS**. Use **+ Add relay VPS (optional)** to insert relays between them. Reordering relays keeps the entry and exit fixed. Selecting a VPS already in the path swaps its position with the previous selection, including in a two-VPS setup.
4. The reachable endpoints and listeners fill automatically. For ordinary forwarding, enter the final destination as `host:port`. For SS, a key is generated automatically and only the exit receives the SS service.
5. Click **Preview changes**. Review the diagram, endpoints, and per-node additions. Then click **Publish these changes**. The exact reviewed batch is published; the final confirmation does not silently change ports.
6. Wait for all Agents to apply the new configuration. Test real traffic through the entry. For SS, use **Entry client link** on the published path card.

For example, choosing A as entry, C as exit, and B as a relay creates:

```text
Client → A:automatic-port → B:automatic-port → C:automatic-port (SS) → Destination
         forwards          forwards           terminates SS
```

The diagram and published rules use the same endpoint proposals. SS is built into the Agent; the controller does not SSH into VPSs or install a separate SS daemon.

## Addresses and ports

- Defaults are stored separately from forwarding configurations. Editing a node address or allocation range affects future proposals, not existing rules.
- The default local port range is **20000–29999**. The allocator avoids managed listeners, disabled rules, port ranges, gateway public/bridge ports and already-used advertised endpoints. Proposals within one path also avoid one another.
- A new node needs a reachable address once. An existing node can reuse an unambiguous configured address. Node names and the controller hostname are never treated as guessed VPS addresses.
- Optional NAT settings describe a continuous range already mapped by the provider. A single old NAT mapping is not extrapolated to a whole port range. The panel does not create NAT mappings or firewall rules.
- IPv6 literals are supported. The default bind follows the address family; loopback defaults remain loopback for local testing. An explicit listen IP can be set in node defaults.
- Manual listeners, reachable endpoints and source ACLs remain available under each VPS card's **Advanced** section. Other protocols and existing saved custom templates retain their advanced editors.

Port proposals are based on saved configurations, not a remote OS socket scan. Previewing does not reserve a port. Publication uses expected revisions and the existing graph validation, so concurrent drafts must be reallocated and reviewed after a conflict. Unmanaged processes, firewalls, DNS aliases or multiple Agents on one machine still require correct operator configuration and an Agent application check. Use disjoint ranges when machine identity or NAT ownership is shared.

## Compatibility

The controller adds the optional `profile.settings.forwarding` field and the authenticated `POST /api/v1/configurations/allocate-endpoints` endpoint. `/topology` now includes node profiles and lifecycle state. The Agent rule format and forwarding engine are unchanged by this feature. Back up controller state before upgrading. Source updates on GitHub do not deploy a binary to a VPS.

The workflow takes inspiration from the entry/path/exit ordering and automatic-port presentation observed in Volatile's forwarding form. It uses Relay's own configuration, validation and forwarding implementation; it does not claim Volatile's tunnel engine or network performance.

## Verification scope

The verification package contains regression logs, allocator tests, browser screenshots and an automated three-Agent local acceptance result. This release does not establish new Linux/WAN throughput, endurance or minimum-hardware results. Existing network qualifications remain applicable.

To repeat the extra local path probe with a built Relay binary and the optional compatibility client:

```sh
python3 scripts/check_auto_endpoint_path.py \
  --binary /absolute/path/to/relay \
  --ss-client /absolute/path/to/relay-ss-client
```

It starts an isolated controller, three Agents, a TCP/UDP echo destination and SS clients. It uses the shipped form's path builder, verifies that preview does not publish, compares the diagram with applied configurations, checks exit-only SS and retained rules, and transfers traffic over plain forwarding, SS native UDP and SS UDP-over-TCP. It closes its processes and removes temporary credentials afterward.

See the [panel tutorial](PANEL_TUTORIAL_EN.md) for enrollment, installation, firewall checks and a complete first forwarding example.
