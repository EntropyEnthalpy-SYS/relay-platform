// Operator workflow contracts: deployment location, preservation, entry export,
// per-hop ACLs and acknowledgement semantics. No browser coverage is implied.
const assert = require('node:assert/strict');
const { loadWorkflows } = require('./web_i18n_helpers.cjs');
const { buildForwardingPath, shadowsocksPath, clientEndpoint, applicationState, shadowsocksClientProfile } = loadWorkflows();
const copy = value => JSON.parse(JSON.stringify(value));
const nodes = [1, 2, 3].map(i => ({ id: `node-${i}`, name: `VPS ${i}`, tenant_id: 'tenant' }));
const snapshot = { nodes, configs: nodes.map(n => ({ node_id: n.id, revision: 7, rules: [{ id: 'existing-' + n.id, name: 'Preserve this rule', listen: '127.0.0.1:9000', protocol: 'tcp', targets: [{ address: '127.0.0.1:9001' }] }] })) };
const key = Buffer.alloc(32, 7).toString('base64'); // Public, test-only fixture key.
const input = { name: 'Phone route', owner: { id: 'owner', tenant_id: 'tenant' }, protocol: 'both', mode: 'ss', transport: 'plain', shadowsocks: { method: '2022-blake3-aes-256-gcm', password: key, allow_private_destinations: true }, hops: nodes.map((n, i) => ({ node_id: n.id, listen: `0.0.0.0:${21001 + i}`, advertise: `vps${i + 1}.example:${31001 + i}`, allow_sources: [i ? `192.0.2.${i}/32` : '198.51.100.0/24'] })) };
let id = 0;
const build = value => buildForwardingPath(snapshot, value, () => `generated-${++id}`);
const before = JSON.stringify(snapshot), batch = copy(build(input));
assert.equal(JSON.stringify(snapshot), before, 'preview construction mutated the live snapshot');
assert.equal(batch.updates.length, 3);
const rules = batch.updates.map(c => c.rules.at(-1));
batch.updates.forEach((c, i) => { assert.equal(c.expected_revision, 7); assert.deepEqual(c.rules[0], snapshot.configs[i].rules[0]); });
assert.ok(!rules[0].inbound_shadowsocks && !rules[1].inbound_shadowsocks);
assert.equal(rules[2].inbound_shadowsocks.password, key, 'SS must run only on the exit');
assert.equal(rules[2].targets.length, 0, 'SS exit uses client destinations');
assert.equal(rules[0].targets[0].address, 'vps2.example:31002');
assert.equal(rules[1].targets[0].via.rule_id, rules[2].id);
assert.deepEqual(rules.map(r => r.allow_sources), input.hops.map(h => h.allow_sources));
const topology = { nodes, configs: batch.updates };
const root = { node_id: 'node-1', rule_id: rules[0].id };
let path = shadowsocksPath(topology, root);
assert.equal(path.endpoint.host, 'vps1.example'); assert.equal(path.endpoint.port, '31001');
assert.equal(path.exit.inbound_shadowsocks.password, key); assert.equal(path.hops.length, 3);
const fork = copy(topology); fork.configs[0].rules.at(-1).targets.push({ address: 'fallback.example:80' });
assert.equal(shadowsocksPath(fork, root), null, 'ambiguous paths must not silently export one exit');
const protectedEntry = copy(topology); protectedEntry.configs[0].rules.at(-1).inbound_tls = { identity: 'server' };
assert.equal(shadowsocksPath(protectedEntry, root), null, 'ordinary SS link cannot represent an extra entry TLS layer');
for (const [change, error] of [
  [{ hops: [input.hops[0], input.hops[0]] }, /path_duplicate/],
  [{ hops: [input.hops[0]] }, /path_hops/],
  [{ owner: { id: 'wrong', tenant_id: 'other' } }, /path_tenant/],
  [{ hops: input.hops.map(h => ({ ...h, advertise: '0.0.0.0:8080' })) }, /path_advertise/],
  [{ shadowsocks: null }, /path_ss/],
  [{ mode: 'forward', targets: [] }, /path_targets/],
  [{ transport: 'wss' }, /path_transport/],
]) assert.throws(() => build({ ...input, ...change }), error);
const native = copy(build({ ...input, mode: 'forward', transport: 'wss', protocol: 'tcp', ws_path: '/relay', server_identity: 'server', ca_identity: 'root', client_identity: 'client', targets: [{ address: 'target.example:443', weight: 1 }], hops: input.hops.map(h => ({ ...h, tls_name: 'relay.example' })) }));
assert.ok(!native.updates[0].rules.at(-1).inbound_tls, 'client-facing entry should accept ordinary TCP');
assert.equal(native.updates[1].rules.at(-1).inbound_tls.identity, 'server');
assert.equal(native.updates[2].rules.at(-1).targets[0].address, 'target.example:443');
assert.equal(clientEndpoint({ listen: '0.0.0.0:443' }).host, '', 'never substitute the controller hostname');
assert.equal(clientEndpoint({ listen: '[::]:443', advertise: '[2001:db8::8]:8443' }).host, '2001:db8::8');
assert.equal(clientEndpoint({ listen: '127.0.0.1:23456', protocol_gateway: { listen: '0.0.0.0:443' } }).port, '443', 'never export the gateway bridge');
const node = { enrolled: true, last_seen_ms: 9000, desired_revision: 2, applied_revision: 2 };
assert.equal(applicationState(node, 10000), 'applied');
assert.equal(applicationState({ ...node, applied_revision: 1 }, 10000), 'pending');
assert.equal(applicationState({ ...node, apply_error: 'port busy' }, 10000), 'rejected');
assert.equal(applicationState(node, 50000), 'offline');
assert.equal(applicationState({ ...node, enrolled: false }, 10000), 'not_enrolled');
console.log('Workflow contracts passed: three-hop SS placement, per-hop sources, preserved rules/revisions, truthful status, entry exports, ambiguous path rejection, tenant checks and native WSS compatibility');

const compatible = copy(shadowsocksClientProfile({ ...input.shadowsocks, udp_over_tcp: true }, path.endpoint, 'Phone route'));
assert.equal(compatible.outbounds[0].server, 'vps1.example');
assert.equal(compatible.outbounds[0].password, key);
assert.deepEqual(compatible.outbounds[0].udp_over_tcp, { enabled: true, version: 2 });
assert.equal(compatible.inbounds[0].listen, '127.0.0.1');
assert.equal(shadowsocksClientProfile(input.shadowsocks, path.endpoint, 'Native').outbounds[0].udp_over_tcp, undefined);
assert.throws(() => shadowsocksClientProfile(input.shadowsocks, { host: '', port: '90' }, 'Invalid'), /client_endpoint/);
console.log('SS client profiles preserve entry address, exit credentials and explicit UoT negotiation');

const { forwardingDiagram, forwardingPathDiagram } = loadWorkflows();
const declared = forwardingDiagram(topology, root);
assert.equal(declared.root.role, 'entry');
assert.equal(declared.root.children[0].next.role, 'relay');
assert.equal(declared.root.children[0].next.children[0].next.role, 'exit');
assert.equal(declared.root.children[0].next.children[0].next.service, 'ss');
assert.equal(declared.root.service, 'forward');
assert.equal(declared.root.children[0].next.service, 'forward');
assert.ok(!JSON.stringify(declared).includes(key), 'diagram leaked an SS key');
const editable = forwardingPathDiagram(snapshot, { ...input, uot: true });
assert.equal(editable.root.children[0].next.children[0].next.uot, true);
assert.deepEqual(copy(editable.root.children.map(c => c.address)), ['vps2.example:31002']);
const changedOrder = forwardingPathDiagram(snapshot, { ...input, hops: [...input.hops].reverse() });
assert.equal(changedOrder.root.name, 'VPS 3');
assert.equal(changedOrder.root.children[0].next.children[0].next.name, 'VPS 1');
const forked = forwardingDiagram(fork, root);
assert.equal(forked.root.children.length, 2, 'candidate targets must branch, not become sequential hops');
assert.equal(forked.root.children[1].next.kind, 'target', 'manual addresses must remain opaque');
assert.equal(forked.root.children[1].next.address, 'fallback.example:80');
const cyclic = copy(topology);
cyclic.configs[2].rules.at(-1).inbound_shadowsocks = null;
cyclic.configs[2].rules.at(-1).targets = [{ address: 'vps1.example:31001', via: root }];
assert.ok(forwardingDiagram(cyclic, root).issues.some(i => i.code === 'cycle'));
const missing = copy(topology); missing.configs.pop();
assert.ok(forwardingDiagram(missing, root).issues.some(i => i.code === 'missing'));
assert.equal(forwardingDiagram(missing, root).root.children[0].next.role, 'relay', 'an unresolved next hop must not turn a relay into an exit');
const protocolMismatch = copy(topology); protocolMismatch.configs[1].rules.at(-1).protocol = 'tcp';
assert.ok(forwardingDiagram(protocolMismatch, root).issues.some(i => i.code === 'protocol'));
const draft = { ...rules[0], targets: [{ address: 'new.example:8443', weight: 2 }] };
assert.equal(forwardingDiagram(topology, root, draft).root.children[0].next.address, 'new.example:8443', 'editor must preview unsaved targets');
assert.equal(JSON.stringify(snapshot), before, 'diagram construction changed saved state');
const incomplete = forwardingPathDiagram(snapshot, { ...input, hops: input.hops.map(h => ({ ...h, advertise: '' })) });
assert.ok(incomplete.issues.some(i => i.code === 'address'));
assert.ok(forwardingPathDiagram(snapshot, { ...input, hops: [input.hops[0], input.hops[0]] }).issues.some(i => i.code === 'duplicate'));
assert.ok(forwardingPathDiagram(snapshot, { ...input, uot: true, protocol: 'udp' }).issues.some(i => i.code === 'uot_tcp'));
assert.ok(forwardingPathDiagram(snapshot, { ...input, owner: { tenant_id: 'other' } }).issues.some(i => i.code === 'tenant'));
const externalProxy = forwardingDiagram({ nodes, configs: [{ node_id: nodes[0].id, rules: [{ id: 'gw', protocol: 'tcp', listen: '127.0.0.1:54321', protocol_gateway: { listen: '192.0.2.4:443', protocol: { type: 'vless', password: 'do-not-render' }, security: { private_key: 'private-value' } }, targets: [] }] }] }, { node_id: nodes[0].id, rule_id: 'gw' });
assert.equal(externalProxy.root.listen, '192.0.2.4:443', 'gateway bridge must not appear as the client listener');
assert.ok(externalProxy.issues.some(i => i.code === 'engine'));
assert.ok(!JSON.stringify(externalProxy).includes('private-value'));
assert.ok(!JSON.stringify(externalProxy).includes('do-not-render'));
const bounds = copy(topology);
bounds.configs[0].rules.at(-1).targets = Array.from({ length: 40 }, (_, i) => ({ address: `target${i}.example:443` }));
assert.equal(forwardingDiagram(bounds, root).root.children.length, 32);
assert.ok(forwardingDiagram(bounds, root).issues.some(i => i.code === 'truncated'));
console.log('Diagram contracts passed: exit-only SS, live order and targets, branches, unresolved references, cycles, protocol/tenant checks, UoT requirements, bounded rendering and credential exclusion');
