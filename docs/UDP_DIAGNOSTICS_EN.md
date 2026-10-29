# Native UDP diagnosis (0.127.0)

UDP acceptance must distinguish packets that never reach a VPS interface from packets dropped inside the relay. The 0.126.0 public-path run had three native UDP timeouts. Follow-up direct echo probes, with no Relay process, reproduced losses toward the entry VPS. This is not evidence that those packets can be repaired by changing forwarding code.

The entry VPS uses a private interface behind public NAT. A capture filter requiring both public endpoint addresses wrongly excluded its packets. `scripts/check_udp_path.py` fixes that diagnostic error: it selects the peer and chosen test ports while permitting the local private address. It records header metadata and payload hashes, never payload content, and changes no firewall rules.

A failed sample is localized only when both endpoint captures contain a successful request/reply, report zero capture drops, cover the full test window and have not reached their packet cap. Missing capture evidence, partial fragments and uncertain samples remain unlocalized. Clocks must be synchronized; supply the receiver-minus-sender clock offset when analyzing. Address translation is supported; port translation and non-Ethernet/IPv6 capture are outside this tool's scope.

Use a controlled echo endpoint restricted to the test peer. Start a capture on each Linux host (root is required for AF_PACKET), selecting the actual interface and the other host's public address:

```sh
python3 scripts/check_udp_path.py capture --interface eth0 \
  --peer PEER_PUBLIC_IPV4 --ports TEST_PORT \
  --output packets.jsonl --stats capture-stats.json --ready capture-ready.json
```

Wait for both ready files. Send each datagram once from the client, with a separate evidence path:

```sh
python3 scripts/check_udp_path.py probe --peer ECHO_PUBLIC_IPV4 \
  --ports TEST_PORT --sizes 0,1,64,1200 --timeout 5 --output samples.json
```

Stop both captures with SIGTERM after the probe and retain their statistics. Analyze downloaded records offline:

```sh
python3 scripts/check_udp_path.py analyze --samples samples.json \
  --sender sender-packets.jsonl --receiver receiver-packets.jsonl \
  --sender-stats sender-stats.json --receiver-stats receiver-stats.json \
  --receiver-offset 0 --clock-uncertainty 0.5 --output analysis.json
```

Exit status 0 requires all samples delivered and validated capture evidence. A failed or unvalidated result exits 1. Successful later samples never replace prior failed samples. The capture cap, time bounds and probe bounds prevent an unattended run from growing indefinitely.

For a controlled Linux regression without changing host networking, the existing SS/MTU probe now supports a DNAT entry:

```sh
python3 scripts/check_ss_udp_mtu.py --binary /path/to/relay \
  --client /path/to/relay-ss-client --routed --nat-entry --output nat-result.json
```

It creates four temporary namespaces with a 1500/1280/1500 MTU route. The router translates a public test endpoint to a private wildcard listener; the path is entry forwarding -> SS exit -> controlled UDP echo. A separate two-hop plain UDP path starts with an empty datagram on a fresh DNAT listener. The native SS fragmentation and UoT cases also start with an empty datagram. The explicit no-fragment case is a negative control. Namespaces, routes and NAT rules are removed on completion. This checks Relay behavior under controlled NAT/MTU conditions; it does not certify an external provider's network.

Native UDP cannot recover packets lost before they reach the listener without changing transport semantics or retransmitting application datagrams. This release does neither. SS UDP-over-TCP remains an explicit alternative and must be reported separately from native UDP. Provider-side NAT, firewall or filtering changes need their own first-packet acceptance evidence.
