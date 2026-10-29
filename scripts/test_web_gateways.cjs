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
    forwardingPathView: () => ({ box: new Element(), update() {} }),
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
  const conflict={...reality,inbound_socks5:{username:'test',password:'secret'}};
  await assert.rejects(serialize(conflict),/只能启用一种|Only one proxy inbound/);
  const invalid={...reality,protocol:'udp'}; await assert.rejects(serialize(invalid),/TCP/);
  console.log('Rule submission preserves MPTCP + health, six typed gateways, Reality secrets, public/bridge addresses and rejects incompatible modes');
})().catch(error => { console.error(error); process.exitCode=1; });
