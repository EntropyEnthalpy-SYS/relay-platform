// Shared by the console and its contract tests. Rules remain the source of truth.
export function serviceKind(rule) {
  if (rule.protocol_gateway) return 'gateway';
  if (rule.inbound_shadowsocks) return 'ss';
  if (rule.inbound_socks5) return 'socks5';
  if (rule.inbound_http_connect) return 'http';
  if (rule.inbound_http2_connect) return 'h2';
  return 'forward';
}

export function splitEndpoint(address) {
  const value = String(address || '').trim(), at = value.lastIndexOf(':');
  if (at < 1) return null;
  const host = value.slice(0, at).replace(/^\[|\]$/g, ''), rawPort = value.slice(at + 1);
  const port = Number(rawPort);
  if (!host || /[\s/@?#]/.test(host) || !/^\d+$/.test(rawPort) || port < 1 || port > 65535) return null;
  return { host, port: String(port), wildcard: host === '0.0.0.0' || host === '::', loopback: host === '::1' || host === 'localhost' || /^127\./.test(host) };
}

export function clientEndpoint(rule) {
  const endpoint = splitEndpoint(rule.advertise || rule.protocol_gateway?.listen || rule.listen);
  return endpoint ? { ...endpoint, host: endpoint.wildcard ? '' : endpoint.host } : { host: '', port: '' };
}

// A standard ss:// URI cannot carry the optional UDP-over-TCP setting.
export function shadowsocksClientProfile(spec, endpoint, tag, protocol = 'both') {
  if (!endpoint?.host || endpoint.wildcard || !endpoint.port) throw new Error('client_endpoint');
  const outbound = { type: 'shadowsocks', tag: 'relay-path', server: endpoint.host, server_port: Number(endpoint.port), method: spec.method, password: spec.password };
  if (spec.udp_over_tcp) outbound.udp_over_tcp = { enabled: true, version: 2 };
  else {
    if (protocol !== 'tcp') outbound.udp_fragment = true;
    if (protocol !== 'both') outbound.network = protocol;
  }
  return { log: { level: 'warn' }, inbounds: [{ type: 'socks', tag: tag || 'Relay', listen: '127.0.0.1', listen_port: 1080 }], outbounds: [outbound], route: { final: 'relay-path' } };
}

export function applicationState(node, now = Date.now()) {
  if (!node?.enrolled) return 'not_enrolled';
  if (!node.last_seen_ms || now - node.last_seen_ms >= 30000) return 'offline';
  if (node.lifecycle === 'disabled') return 'paused';
  if (node.lifecycle === 'expired') return 'expired';
  if (node.apply_error) return 'rejected';
  if (node.applied_revision !== node.desired_revision) return 'pending';
  return 'applied';
}

// Show complete routes once, starting at their entry rules. Shared exits may
// appear in several routes; disconnected rules and malformed cycles stay visible.
export function forwardingPathRoots(snapshot) {
  const rules = new Map((snapshot.configs || []).flatMap(config => config.rules.map(rule =>
    [`${config.node_id}/${rule.id}`, { node_id: config.node_id, rule_id: rule.id, rule }])));
  const next = item => serviceKind(item.rule) === 'forward' ? (item.rule.targets || [])
    .filter(target => target.via).map(target => `${target.via.node_id}/${target.via.rule_id}`) : [];
  const referenced = new Set([...rules.values()].flatMap(next));
  const roots = [...rules].filter(([key]) => !referenced.has(key)).map(([, item]) => item);
  const covered = new Set();
  function visit(item) {
    const pending = [item];
    while (pending.length) {
      const current = pending.pop(), key = `${current.node_id}/${current.rule_id}`;
      if (covered.has(key)) continue;
      covered.add(key);
      for (const key of next(current)) if (rules.has(key)) pending.push(rules.get(key));
    }
  }
  roots.forEach(visit);
  for (const [key, item] of rules) if (!covered.has(key)) { roots.push(item); visit(item); }
  return roots.map(({ node_id, rule_id }) => ({ node_id, rule_id }));
}

// A bounded, credential-free view of declared routing, never a reachability test.
// A target with no `via` is opaque: matching an address does not prove another VPS.
export function forwardingDiagram(snapshot, root, draft = null) {
  const rules = new Map((snapshot.configs || []).flatMap(c => c.rules.map(r => [`${c.node_id}/${r.id}`, r])));
  if (draft) rules.set(`${root.node_id}/${root.rule_id}`, draft);
  const issues = [], nodes = new Map((snapshot.nodes || []).map(n => [n.id, n]));
  const issue = (code, name) => { if (!issues.some(i => i.code === code && i.name === name)) issues.push({ code, name }); };
  let count = 0;
  function walk(ref, ancestors = new Set(), depth = 0) {
    const key = `${ref.node_id}/${ref.rule_id}`, rule = rules.get(key), node = nodes.get(ref.node_id);
    const name = node?.name || ref.node_id;
    if (ancestors.has(key)) { issue('cycle', name); return { kind: 'unresolved', name, reason: 'cycle' }; }
    if (depth >= 16 || ++count > 64) { issue('truncated', name); return { kind: 'unresolved', name, reason: 'truncated' }; }
    if (!rule || !node) { issue('missing', name); return { kind: 'unresolved', name, reason: 'missing' }; }
    const service = serviceKind(rule), listen = rule.protocol_gateway?.listen || rule.listen || '';
    const endpoint = rule.advertise || listen, parsedListen = splitEndpoint(listen), parsedEndpoint = splitEndpoint(endpoint);
    if (!parsedListen) issue('listen', name);
    if (!parsedEndpoint || parsedEndpoint.wildcard) issue('address', name);
    if (parsedListen?.loopback || parsedEndpoint?.loopback) issue('loopback', name);
    if (rule.enabled === false) issue('disabled', name);
    if (!node.enrolled) issue('agent', name);
    if (service === 'gateway') issue('engine', name);
    if (rule.listen_end_port || rule.port_mapping === 'offset') issue('range', name);
    if (rule.inbound_shadowsocks?.udp_over_tcp && (rule.protocol === 'udp' || [...ancestors].some(k => rules.get(k)?.protocol === 'udp'))) issue('uot_tcp', name);
    const path = new Set([...ancestors, key]), targets = service === 'forward' ? rule.targets || [] : [];
    if (service === 'forward' && !targets.length) issue('targets', name);
    const children = targets.slice(0, 32).map(target => {
      const address = target.address || '', parsed = splitEndpoint(address);
      if (!parsed || parsed.wildcard) issue('target', name);
      const next = target.via && rules.get(`${target.via.node_id}/${target.via.rule_id}`);
      if (next) {
        const required = rule.protocol === 'both' ? ['tcp', 'udp'] : [rule.protocol];
        if (required.some(p => next.protocol !== 'both' && next.protocol !== p)) issue('protocol', name);
        if (next.tenant_id && rule.tenant_id && next.tenant_id !== rule.tenant_id) issue('tenant', name);
        if (address !== next.advertise && !next.inbound_multipath) issue('mismatch', name);
      }
      return {
        address, protocol: rule.protocol,
        transport: target.websocket ? (target.tls ? 'WSS' : 'WS') : target.tls ? 'TLS' : '',
        weight: target.weight ?? 1, priority: target.priority ?? 0, draining: !!target.draining,
        next: target.via ? walk(target.via, path, depth + 1) : { kind: 'target', address },
      };
    });
    if (targets.length > 32) issue('truncated', name);
    return { kind: 'node', name, node_id: ref.node_id, rule_id: ref.rule_id, ruleName: rule.name || '',
      service, listen, endpoint: parsedEndpoint && !parsedEndpoint.wildcard ? endpoint : '', protocol: rule.protocol, children,
      inboundTransport: rule.inbound_websocket ? (rule.inbound_tls ? 'WSS' : 'WS') : rule.inbound_tls ? 'TLS' : '',
      role: depth === 0 ? (children.some(c => c.next.kind !== 'target') ? 'entry' : 'single') : children.some(c => c.next.kind !== 'target') ? 'relay' : 'exit',
      aggregate: !!rule.outbound_multipath, uot: !!rule.inbound_shadowsocks?.udp_over_tcp,
    };
  }
  return { root: walk(root), issues };
}

// Incomplete wizard inputs stay drawable. These ephemeral rules are never published.
export function forwardingPathDiagram(snapshot, input) {
  const hops = input.hops || [];
  const configs = hops.map((hop, index) => ({ node_id: hop.node_id, rules: [{
    id: `diagram-${index}`, listen: hop.listen, advertise: hop.advertise,
    tenant_id: snapshot.nodes.find(n => n.id === hop.node_id)?.tenant_id,
    protocol: input.protocol, enabled: true,
    ...(index === hops.length - 1 && input.mode === 'ss' ? { inbound_shadowsocks: { udp_over_tcp: !!input.uot } } : {}),
    targets: index === hops.length - 1 ? (input.mode === 'ss' ? [] : input.targets || []) : [{
      address: hops[index + 1].advertise, via: { node_id: hops[index + 1].node_id, rule_id: `diagram-${index + 1}` },
      ...(input.transport !== 'plain' ? { websocket: {} } : {}), ...(input.transport === 'wss' ? { tls: {} } : {}),
    }],
  }] }));
  const model = forwardingDiagram({ ...snapshot, configs }, { node_id: hops[0]?.node_id || '', rule_id: 'diagram-0' });
  if (new Set(hops.map(h => h.node_id)).size !== hops.length) model.issues.push({ code: 'duplicate', name: '' });
  if (input.owner && hops.some(h => snapshot.nodes.find(n => n.id === h.node_id)?.tenant_id !== input.owner.tenant_id)) model.issues.push({ code: 'tenant', name: '' });
  return model;
}

// Returns a batch suitable for /configurations/preview. No network or state writes.
export function buildForwardingPath(snapshot, input, nextId) {
  const fail = code => { throw new Error(code); };
  const { hops, owner, name, protocol, mode, transport = 'plain' } = input;
  if (!Array.isArray(hops) || hops.length < 2 || hops.length > 16) fail('path_hops');
  if (new Set(hops.map(h => h.node_id)).size !== hops.length) fail('path_duplicate');
  if (!String(name || '').trim()) fail('path_name');
  if (!['forward', 'ss'].includes(mode) || !['tcp', 'udp', 'both'].includes(protocol)) fail('path_mode');
  if (!['plain', 'ws', 'wss'].includes(transport) || (transport !== 'plain' && (protocol !== 'tcp' || mode === 'ss'))) fail('path_transport');
  if (mode === 'ss' && !input.shadowsocks) fail('path_ss');
  if (mode === 'forward' && !input.targets?.length) fail('path_targets');
  const nodes = hops.map(h => snapshot.nodes.find(n => n.id === h.node_id));
  if (nodes.some(n => !n) || !owner || nodes.some(n => n.tenant_id !== owner.tenant_id)) fail('path_tenant');
  for (const h of hops) {
    if (!splitEndpoint(h.listen)) fail('path_listen');
    const endpoint = splitEndpoint(h.advertise);
    if (!endpoint || endpoint.wildcard) fail('path_advertise');
  }
  const ids = hops.map(() => nextId()), epoch = nextId();
  const updates = hops.map((hop, index) => {
    const base = snapshot.configs.find(c => c.node_id === hop.node_id);
    if (!base) fail('path_config');
    const last = index === hops.length - 1;
    const rule = {
      id: ids[index], tenant_id: owner.tenant_id, owner_id: owner.id,
      name: `${name.trim()} · ${index + 1}`, protocol, listen: hop.listen.trim(),
      advertise: hop.advertise.trim(), enabled: true, meter_epoch: epoch,
      allow_sources: hop.allow_sources || [],
      targets: last ? (mode === 'ss' ? [] : input.targets) : [{ address: hops[index + 1].advertise.trim(), weight: 1, via: { node_id: hops[index + 1].node_id, rule_id: ids[index + 1] } }],
    };
    if (last && mode === 'ss') rule.inbound_shadowsocks = input.shadowsocks;
    // SS terminates the client's encrypted stream. Optional wrappers end at relays.
    const wrapsInbound = index > 0 && !(last && mode === 'ss');
    const wrapsOutbound = !last && !(index === hops.length - 2 && mode === 'ss');
    if (transport !== 'plain') {
      if (wrapsInbound) rule.inbound_websocket = { path: input.ws_path, host: rule.advertise, allowed_origins: [] };
      if (wrapsOutbound) rule.targets[0].websocket = { path: input.ws_path, host: hops[index + 1].advertise.trim() };
    }
    if (transport === 'wss') {
      if (wrapsInbound) rule.inbound_tls = { identity: input.server_identity, client_ca: input.ca_identity };
      if (wrapsOutbound) rule.targets[0].tls = { server_name: hops[index + 1].tls_name, ca: input.ca_identity, identity: input.client_identity };
    }
    return { node_id: hop.node_id, expected_revision: base.revision, rules: [...base.rules, rule] };
  });
  return { updates };
}

// A share link is safe to derive only for an unambiguous, fixed-port path.
// Root address comes from the entry; SS credentials come from the terminal rule.
export function shadowsocksPath(snapshot, root) {
  const map = new Map(snapshot.configs.flatMap(c => c.rules.map(r => [`${c.node_id}/${r.id}`, { node_id: c.node_id, rule: r }])));
  const seen = new Set(), hops = []; let current = map.get(`${root.node_id}/${root.rule_id}`);
  if (!current || current.rule.inbound_tls || current.rule.inbound_websocket || current.rule.inbound_proxy || current.rule.inbound_multipath) return null;
  while (current) {
    const key = `${current.node_id}/${current.rule.id}`;
    if (seen.has(key) || current.rule.listen_end_port || current.rule.port_mapping === 'offset') return null;
    seen.add(key); hops.push(current);
    if (current.rule.inbound_shadowsocks) {
      const entry = hops[0].rule;
      return { hops, exit: current.rule, entry, endpoint: clientEndpoint(entry) };
    }
    if (serviceKind(current.rule) !== 'forward' || current.rule.outbound_multipath || current.rule.targets.length !== 1 || !current.rule.targets[0].via) return null;
    const next = current.rule.targets[0].via;
    current = map.get(`${next.node_id}/${next.rule_id}`);
  }
  return null;
}
