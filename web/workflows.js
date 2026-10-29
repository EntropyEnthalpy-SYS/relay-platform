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
  else if (protocol !== 'both') outbound.network = protocol;
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
