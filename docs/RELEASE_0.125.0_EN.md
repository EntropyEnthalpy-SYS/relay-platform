# Monitoring overview — 0.125.x

Open **Overview** and choose **Monitoring**. This restores the spacious operations display: four metric cards with sparklines, a full-width forwarding graph, the event list underneath, and the node resource table. **Workspace** keeps the compact arrangement. The browser remembers this choice; a new browser defaults to Monitoring.

Updated in **0.125.1**: Monitoring uses the existing workspace theme, including its warm paper light palette, charcoal dark palette, terracotta accents, sans-serif typography, card surfaces and dotted diagram canvas. It changes spacing and arrangement only. Use the theme button independently for light or dark colors; both overview layouts share that choice. Layout and language controls remain keyboard accessible.

## What populates the display

| Display | Source and meaning |
|---|---|
| Throughput and sessions | Agent reports; throughput counts each forwarding hop separately |
| Probe round trip | Node-to-target probe observations; excludes the client segment |
| Online nodes | Recent Agent reports and node application state; does not prove end-to-end traffic |
| Forwarding graph | Enabled rules and their declared next-hop references; target-probe colors retain their existing meaning |
| Events | The controller's recorded node/configuration/target events |
| CPU and memory | Agent resource reports, when available on that host |

The two layouts use the same API responses. No generated traffic values, CPU measurements, latency samples or event entries are added to make the screen look populated. Missing values stay unknown.

Example or unenrolled nodes appear as disconnected nodes, with an explanation that live data requires an enrolled, running Agent. Enabled rules are needed to draw forwarding connections. A teaching workspace with no registered Agents is therefore expected to look different from a running VPS workspace.

Click or keyboard-activate a graph node to open that VPS's rules. The larger graph is for monitoring; **Forwarding paths** remains the place to create or edit a complete path using the [guided diagram editor](RELEASE_0.124.0_EN.md).

## Verification and scope

The verification package records the bilingual UI suite and browser checks for mode switching, reload persistence, independent themes, graph-to-rule navigation, mobile overflow and the unenrolled-node state. Existing local panel configurations and identities are retained when deploying the rebuilt controller.

This changes the controller UI only. The forwarding engine, rule schema, telemetry API and resource sampling implementation are unchanged. It does not close the native UDP WAN losses recorded during 0.124.0 acceptance, certify minimum hardware, or establish new VPS throughput/endurance results.
