// Executes the shipped rule editor with form controls, including its submit
// handler. This checks saved rules; it is not a visual/browser acceptance test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const code = source.slice(source.indexOf('function gatewayConfig('), source.indexOf('const shadowsocksMethods'));
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.value = ''; this.checked = false; this.disabled = false; this.dataset = {}; this.classList = { toggle() {} }; }
  append(...items) { for (const item of items) { if (typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { this.children.unshift(...items); }
  addEventListener() {} setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input','select','textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
}
async function serialize(existing) {
  let form, handler, saved, healthReads = 0, targetReads = 0;
  const node = { id: 'node', tenant_id: 'tenant' };
  const context = {
    ...require('./web_i18n_helpers.cjs').loadI18n(),
    ...require('./web_i18n_helpers.cjs').loadWorkflows(),
    TextEncoder, Uint8Array, Uint32Array, btoa, crypto: require('node:crypto').webcrypto,
    document: { createTextNode: text => text },
    FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
    forwardingPathView: () => ({ box: new Element(), update() {} }), featureOn: () => false,
    state: { config: { node_id: 'node', revision: 3, rules: [existing] }, nodes: [node], actor: { id: 'owner' } },
    api: async () => ({ configs: [], nodes: [] }), el: tag => new Element(tag),
    field(parent, name, _label, value = '', type = 'text') { const label = new Element('label'), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type }); label.append(input); parent.append(label); return input; },
    select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0][0]); input.tag = 'select'; return input; },
    textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
    button: () => new Element('button'),
    healthEditor: (_form, spec) => () => { healthReads++; return spec; },
    multipathEditor: () => ({ mode: {}, read: () => ({}) }),
    targetEditor: (_form, targets) => { const read = () => { targetReads++; return targets; }; read.multipathPaths = () => []; read.preview = () => targets; read.onchange = () => {}; return read; },
    websocketEditor: (_name, spec) => ({ box: new Element(), read: () => spec }),
    submit: (value, _label, callback) => { form = value; handler = callback; }, modal() {},
    saveRules: async rules => { saved = rules[0]; },
    number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
  };
  for (const [helper, key] of [['shadowsocksEditor','inbound_shadowsocks'], ['socks5Editor','inbound_socks5'], ['httpConnectEditor','inbound_http_connect'], ['http2ConnectEditor','inbound_http2_connect']]) context[helper] = spec => ({ box: new Element(), read: () => spec, enabled: () => !!spec, onchange() {} });
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf('function sectionVisible('), source.indexOf('function websocketEditor(')) + code + '\nthis.editRule = editRule;', context);
  await context.editRule(existing);
  const values = new Map();
  for (const input of form.querySelectorAll()) if (input.name && !input.disabled && (input.type !== 'checkbox' || input.checked)) values.set(input.name, input.type === 'checkbox' ? 'on' : input.value);
  await handler({ get: key => values.has(key) ? values.get(key) : null });
  return { saved, healthReads, targetReads };
}
(async () => {
  const native = { id:'native', owner_id:'owner', name:'native', listen:'127.0.0.1:9000', protocol:'tcp', targets:[{address:'127.0.0.1:9001',weight:1}], mptcp:{inbound:'prefer',outbound:'require'}, health_check:{interval_ms:1000, timeout_ms:500, unhealthy_after:2, healthy_after:2} };
  let result = await serialize(native);
  assert.equal(JSON.stringify(result.saved.health_check), JSON.stringify(native.health_check), 'MPTCP edit lost health checks');
  assert.equal(result.saved.mptcp.outbound, 'require'); assert.equal(result.healthReads,1); assert.equal(result.targetReads,1);
  for (const type of ['vless','hysteria2','tuic','any_tls','trojan','vmess']) {
    const wire = { ...native, mptcp:null, protocol:type==='any_tls'?'tcp':'both', targets:[], health_check:null, protocol_gateway:{listen:'0.0.0.0:443',protocol:{type,uuid:'bf000d23-0752-40b4-affe-68f7707a9661',password:'secret-password-1234',vision:false},security:{type:'certificate',identity:'server',server_name:'relay.test'},allow_private_destinations:false} };
    result=await serialize(wire);
    assert.equal(result.saved.listen,wire.listen,'private bridge changed on no-change edit');
    assert.equal(result.saved.protocol_gateway.listen,'0.0.0.0:443');
    assert.equal(result.saved.protocol_gateway.protocol.type,type);
    assert.equal(result.saved.protocol_gateway.security.server_name,'relay.test');
    assert.equal(result.saved.targets.length,0); assert.equal(result.healthReads,0); assert.equal(result.targetReads,0);
    assert.equal(result.saved.inbound_tls,undefined);
  }
  const reality={ ...native, mptcp:null, targets:[], protocol_gateway:{listen:'[::]:443',protocol:{type:'vless',uuid:'bf000d23-0752-40b4-affe-68f7707a9661',vision:true},security:{type:'reality',server_name:'relay.test',handshake:'relay.test:443',private_key:'B'.repeat(43),short_id:'abcd'},allow_private_destinations:true} };
  result=await serialize(reality);
  assert.equal(JSON.stringify(result.saved.protocol_gateway),JSON.stringify(reality.protocol_gateway));
  // Options added in the engine form survive an unchanged edit, defaults stay
  // out of the saved rule, and invalid values are refused before saving.
  const options = (protocol, security = { type:'certificate', identity:'server', server_name:'relay.test' }) => ({ ...native, mptcp:null, protocol:'both', targets:[], health_check:null, protocol_gateway:{ listen:'0.0.0.0:443', protocol, security, allow_private_destinations:false } });
  const hysteria = options({ type:'hysteria2', password:'secret-password-1234', obfs:{ type:'salamander', password:'obfuscation-pass-1234' }, masquerade:{ type:'string', status_code:404, content:'<h1>gone</h1>' } });
  result = await serialize(hysteria);
  assert.equal(JSON.stringify(result.saved.protocol_gateway), JSON.stringify(hysteria.protocol_gateway));
  const tuic = options({ type:'tuic', uuid:'bf000d23-0752-40b4-affe-68f7707a9661', password:'secret-password-1234', congestion_control:'new_reno', zero_rtt_handshake:true });
  result = await serialize(tuic);
  assert.equal(JSON.stringify(result.saved.protocol_gateway), JSON.stringify(tuic.protocol_gateway));
  for (const type of ['hysteria2', 'tuic']) {
    const plain = options({ type, uuid:'bf000d23-0752-40b4-affe-68f7707a9661', password:'secret-password-1234' });
    result = await serialize(plain);
    for (const key of ['obfs', 'masquerade', 'congestion_control', 'zero_rtt_handshake']) assert.equal(result.saved.protocol_gateway.protocol[key], undefined, `${type} gained ${key}`);
  }
  const shortIds = { ...reality, protocol_gateway:{ ...reality.protocol_gateway, security:{ ...reality.protocol_gateway.security, short_id:'abcd', extra_short_ids:['01', 'fedcba9876543210'], max_time_difference_secs:90 } } };
  result = await serialize(shortIds);
  assert.equal(JSON.stringify(result.saved.protocol_gateway), JSON.stringify(shortIds.protocol_gateway));
  for (const invalid of [
    options({ ...hysteria.protocol_gateway.protocol, obfs:{ type:'salamander', password:'short' } }),
    options({ ...hysteria.protocol_gateway.protocol, masquerade:{ type:'string', status_code:600 } }),
    { ...shortIds, protocol_gateway:{ ...shortIds.protocol_gateway, security:{ ...shortIds.protocol_gateway.security, extra_short_ids:['ABCD'] } } },
    { ...shortIds, protocol_gateway:{ ...shortIds.protocol_gateway, security:{ ...shortIds.protocol_gateway.security, max_time_difference_secs:3601 } } },
  ]) await assert.rejects(serialize(invalid), /混淆|伪装|short ID|时钟|obfuscation|masquerade|short IDs|clock/);
  const conflict={...reality,inbound_socks5:{username:'test',password:'secret'}};
  await assert.rejects(serialize(conflict),/只能启用一种|Only one proxy inbound/);
  const invalid={...reality,protocol:'udp'}; await assert.rejects(serialize(invalid),/TCP/);
  // Gateway share links come from the controller, which also renders the QR code.
  const shareSource = source.slice(source.indexOf('function shareGateway('), source.indexOf('const subscriptionFormats'));
  const requests = [], dialog = { closed: false };
  let shown;
  const share = {
    ...require('./web_i18n_helpers.cjs').loadI18n(), URLSearchParams, encodeURIComponent, setTimeout, clearTimeout,
    el: (tag, text = '') => Object.assign(new Element(tag), { textContent: text, hidden: false, src: '' }),
    field(parent, name, _label, value = '') { const input = new Element('input'); Object.assign(input, { name, value: String(value ?? '') }); parent.append(input); return input; },
    button: () => new Element('button'), modal: (_title, body) => { shown = body; }, $: () => dialog, notify() {},
    clientEndpoint: rule => ({ host: rule.protocol_gateway.listen.startsWith('0.0.0.0') ? '' : '203.0.113.5', port: '443' }),
    splitEndpoint: value => /^(\[[^\]]+\]|[^:]+):\d+$/.test(value) ? {} : null,
    api: async path => { requests.push(path); return { uri: 'hysteria2://secret@203.0.113.5:443/?sni=relay.test#hy', qr_svg: '<svg/>' }; },
  };
  vm.createContext(share);
  vm.runInContext(shareSource + '\nthis.shareGateway = shareGateway;', share);
  const gatewayRule = { id: 'gw/1', name: 'hy', protocol_gateway: { listen: '[::]:443', protocol: { type: 'hysteria2' } } };
  share.shareGateway(gatewayRule, 'node 1');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 1);
  assert.equal(requests[0], '/nodes/node%201/rules/gw%2F1/share?host=203.0.113.5&port=443&name=hy');
  const nodes = []; const walk = n => { nodes.push(n); (n.children || []).forEach(c => typeof c === 'object' && walk(c)); }; walk(shown);
  assert.ok(nodes.some(n => n.textContent === 'hysteria2://secret@203.0.113.5:443/?sni=relay.test#hy'), 'link not shown');
  assert.ok(nodes.some(n => n.tag === 'img' && !n.hidden && n.src === `data:image/svg+xml;charset=utf-8,${encodeURIComponent('<svg/>')}`), 'QR code not shown');
  share.shareGateway({ ...gatewayRule, protocol_gateway: { ...gatewayRule.protocol_gateway, listen: '0.0.0.0:443' } }, 'node');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests.length, 1, 'a wildcard listener needs a public host before asking for a link');
  console.log('Rule submission preserves MPTCP + health, six typed gateways, Reality secrets, Hysteria2 / TUIC / Reality options, public/bridge addresses and rejects incompatible modes; gateway share dialog shows the controller link and QR code');
})().catch(error => { console.error(error); process.exitCode=1; });
