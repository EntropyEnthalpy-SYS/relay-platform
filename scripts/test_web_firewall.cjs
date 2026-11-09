// Executes the shipped firewall rule-set controls with form-control stubs and checks what they send and show:
// the set editor's rows (order, moving, single IPs as /32 and /128, port and size checks, direction and scope
// fixed after creation), the rule editor's inbound set (the rule tenant's inbound sets only, a protocol
// gateway's with its note, the old-agent warning), a server's bindings and its desired/confirmed state, the tester's
// requests and answers, block-record details and the controller's refusals, in the panel's language. Not a
// browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^function mbit\(.*$/m)
  + between('function sectionVisible(', 'function websocketEditor(')
  + between('// Quota and speed limits of a rule', 'async function saveRules(')
  + between('function gatewayConfig(', 'const shadowsocksMethods')
  + between('// Firewall rule sets: named', '// Connections: a rule\'s open sessions')
  + between('function firewallDetail(', 'function connectionHop(');

class Element {
  constructor(tag = 'div', text = '', className = '') {
    Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {}, hidden: false, attributes: {} });
    const self = this;
    this.classList = { toggle(name, on) { if (name === 'hidden') self.hidden = on; }, add() {}, remove() {}, contains: name => name === 'hidden' && self.hidden };
  }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelector(selector) { const name = /^\[name=(\w+)\]$/.exec(selector)?.[1]; return this.all().find(n => name && n.name === name) || null; }
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  visible() { for (let n = this; n; n = n.parentElement) if (n.hidden) return false; return true; }
  text() { return this.all().filter(n => n.visible()).map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text && n.visible());
const named = (root, name) => root.all().filter(n => n.name === name);
const options = select => select.children.filter(c => c.tag === 'option').map(c => [c.value, c.textContent]);

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };
// The whole message, exactly: errors thrown inside the vm context are not this realm's Error.
const literal = text => error => { assert.equal(error.message, text); return true; };
const plain = value => JSON.parse(JSON.stringify(value));

const sets = [
  { id: 'fs-t-in', scope: 'tenant', tenant_id: 't', name: 'Office only', direction: 'inbound', default_action: 'deny', rules: [{ action: 'allow', match: { sources: ['198.51.100.0/24'] } }], revision: 4, bindings: [] },
  { id: 'fs-t-out', scope: 'tenant', tenant_id: 't', name: 'Tenant outbound', direction: 'outbound', default_action: 'allow', rules: [], revision: 1, bindings: [] },
  { id: 'fs-other', scope: 'tenant', tenant_id: 'other', name: 'Other tenant', direction: 'inbound', default_action: 'allow', rules: [], revision: 1, bindings: [] },
  { id: 'fs-s-in', scope: 'system', tenant_id: null, name: 'Edge blocklist', direction: 'inbound', default_action: 'allow', rules: [{ action: 'deny', match: { sources: ['203.0.113.0/24'] } }], revision: 2, bindings: [{ layer: 'server_inbound', node_id: 'n1', node_name: 'Tokyo' }, { layer: 'rule_inbound', node_id: 'n1', node_name: 'Tokyo', rule_id: 'r2', rule_name: 'web' }] },
  { id: 'fs-s-out', scope: 'system', tenant_id: null, name: 'No mail', direction: 'outbound', default_action: 'allow', rules: [{ action: 'deny', match: { ports: ['25', '465-587'] } }], revision: 1, bindings: [] },
];
const forward = { id: 'r2', tenant_id: 't', owner_id: 'owner', name: 'web', listen: '0.0.0.0:20000', protocol: 'tcp', targets: [{ address: '192.0.2.10:443', weight: 1 }], enabled: true, meter_epoch: 'e1', quota_bytes: null, rate_bytes_per_sec: null, expires_at_ms: null };
const wire = { ...forward, id: 'r3', name: 'vless', protocol: 'both', targets: [], firewall_inbound_set: 'fs-t-in', protocol_gateway: { listen: '0.0.0.0:443', protocol: { type: 'vless', uuid: 'bf000d23-0752-40b4-affe-68f7707a9661', password: 'secret-password-1234', vision: false }, security: { type: 'certificate', identity: 'server', server_name: 'relay.test' }, allow_private_destinations: false } };
const desired = 'a'.repeat(64), confirmed = 'b'.repeat(64);
const tokyo = { id: 'n1', name: 'Tokyo', tenant_id: 't', firewall_support: false, stats: {}, firewall: { inbound_set_id: 'fs-s-in', inbound_set_name: 'Edge blocklist', outbound_set_id: null, outbound_set_name: null, rule_bindings: 1, desired_hash: desired, applied_hash: confirmed, error: null, state: 'too_old' } };
let form, handler, saved = null, title = '', content = new Element('main'), editing = forward.id;
const calls = [];
let answer = null;
const context = {
  ...i18n, ...helpers.loadWorkflows(),
  TextEncoder, Uint8Array, Uint32Array, btoa, crypto: require('node:crypto').webcrypto,
  document: { createTextNode: text => text },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  forwardingPathView: () => ({ box: new Element(), update() {} }), featureOn: () => false, canWrite: () => context.state.actor.role !== 'viewer',
  state: { view: 'firewall', config: { node_id: 'n1', revision: 3, rules: [forward] }, nodes: [tokyo], actor: { id: 'owner', role: 'system_admin', tenant_id: 't' } },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : plain(options.body) });
    if (path === '/nodes') return context.state.nodes;
    if (path === '/firewall/sets') return options.method ? sets[0] : sets;
    if (path === '/firewall/test') return answer;
    if (path === '/nodes/n1/config') return { node_id: 'n1', revision: 3, rules: [forward, wire] };
    return { configs: [], nodes: [] };
  },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, label, value = '', type = 'text', required = true) { const wrap = new Element('label', label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); wrap.append(input); parent.append(wrap); return input; },
  select(parent, name, label, choices, value) { const input = context.field(parent, name, label, value ?? choices[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of choices) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  checkbox(parent, name, text) { const wrap = new Element('label', text), input = new Element('input'); Object.assign(input, { name, type: 'checkbox' }); wrap.prepend(input); parent.append(wrap); return input; },
  button: (text, action, className) => { const n = Object.assign(new Element('button', text, className), { action }); n.addEventListener('click', action); return n; },
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  namedCell: (name, detail) => { const n = new Element('div'); n.append(new Element('strong', name), new Element('div', detail)); return n; },
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); n.rows = rows; for (const row of rows) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  panel: (heading, description, action) => { const n = new Element('section', heading); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  empty: (heading, description, action) => { const n = new Element('div', heading); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  healthEditor: (_form, spec) => () => spec,
  multipathEditor: () => ({ mode: {}, read: () => ({}) }),
  targetEditor: (_form, targets) => { const read = () => targets; read.multipathPaths = () => []; read.preview = () => targets; read.onchange = () => {}; return read; },
  websocketEditor: (_name, spec) => ({ box: new Element(), read: () => spec }),
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal: (heading, body) => { title = heading; if (body !== form) form = body; }, notify() {},
  saveRules: async rules => { saved = rules.find(r => r.id === editing); }, renderRules: async () => {}, refresh: async () => {},
  confirmAction: async () => true,
  $: selector => selector === '#content' ? content : { close() {} },
  number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
};
for (const helper of ['shadowsocksEditor', 'socks5Editor', 'httpConnectEditor', 'http2ConnectEditor']) context[helper] = spec => ({ box: new Element(), read: () => spec ?? null, enabled: () => !!spec, onchange() {}, setEnabled() {} });
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { editRule, editFirewallSet, deleteFirewallSet, serverFirewallFields, firewallStatusCell, firewallTesterPanel, firewallResult, firewallReason, firewallDetail, renderFirewall });', context);
const send = () => handler(new context.FormData(form));
const sent = () => calls.at(-1);

(async () => {
  // A new inbound set: rows keep their order, move up and down, and single IPs are saved as networks.
  context.editFirewallSet();
  assert.equal(title, translate('新建防火墙规则集'));
  const editor = form;
  named(editor, 'fw_name')[0].value = 'Clients';
  named(editor, 'fw_default')[0].value = 'deny';
  assert.ok(editor.text().includes(translate('没有规则：所有连接都按默认动作处理。')));
  await buttons(editor, translate('＋ 添加规则'))[0].fire('click');
  await buttons(editor, translate('＋ 添加规则'))[0].fire('click');
  const [first, second] = named(editor, 'fw_rule_sources');
  first.value = '203.0.113.7\n2001:db8::1'; named(editor, 'fw_rule_action')[0].value = 'deny';
  second.value = '198.51.100.0/24, 192.0.2.1'; named(editor, 'fw_rule_action')[1].value = 'allow';
  assert.ok(!named(editor, 'fw_rule_destinations')[0].parentElement.visible(), 'an inbound row has no destinations');
  const ups = buttons(editor, '↑'), downs = buttons(editor, '↓');
  assert.deepEqual([ups[0].disabled, downs[0].disabled, ups[1].disabled, downs[1].disabled], [true, false, false, true], 'the first row cannot move up nor the last down');
  await ups[1].fire('click');
  await send();
  assert.deepEqual(sent(), { path: '/firewall/sets', method: 'POST', body: { name: 'Clients', direction: 'inbound', default_action: 'deny', scope: 'tenant', tenant_id: 't', rules: [
    { action: 'allow', match: { sources: ['198.51.100.0/24', '192.0.2.1/32'] } },
    { action: 'deny', match: { sources: ['203.0.113.7/32', '2001:db8::1/128'] } },
  ] } }, 'moving the second row up puts it first');
  translated(editor, 'set editor');

  // Checks before anything is sent: an empty row, an empty name, more than 256 sources.
  calls.length = 0;
  await buttons(editor, translate('＋ 添加规则'))[0].fire('click');
  await assert.rejects(send(), literal(msg`第 ${3} 条规则：请填写至少一个来源 IP 或 CIDR`));
  named(editor, 'fw_rule_sources')[2].value = Array.from({ length: 257 }, (_, i) => `10.0.${i >> 8}.${i & 255}`).join('\n');
  await assert.rejects(send(), literal(msg`第 ${3} 条规则：来源最多 256 个`));
  await buttons(editor, translate('删除')).at(-1).fire('click');
  named(editor, 'fw_name')[0].value = '  ';
  await assert.rejects(send(), literal(translate('名称须为 1 到 120 个字符')));
  assert.equal(calls.length, 0, 'nothing is sent while the set is invalid');

  // Outbound rows match destinations and/or ports; a bad port or range is refused here.
  context.editFirewallSet();
  named(form, 'fw_name')[0].value = 'Egress';
  named(form, 'fw_direction')[0].value = 'outbound';
  await named(form, 'fw_direction')[0].fire('change');
  await buttons(form, translate('＋ 添加规则'))[0].fire('click');
  assert.ok(named(form, 'fw_rule_ports')[0].parentElement.visible() && !named(form, 'fw_rule_sources')[0].parentElement.visible());
  named(form, 'fw_rule_destinations')[0].value = '*.example.com\n192.0.2.0/24';
  named(form, 'fw_rule_ports')[0].value = '8080-8000';
  await assert.rejects(send(), literal(msg`第 ${1} 条规则：端口 ${'8080-8000'} 无效；请写成 443 或 8000-8080`));
  named(form, 'fw_rule_ports')[0].value = '70000';
  await assert.rejects(send(), literal(msg`第 ${1} 条规则：端口 ${'70000'} 无效；请写成 443 或 8000-8080`));
  named(form, 'fw_rule_ports')[0].value = '443, 8000-8080';
  named(form, 'fw_scope')[0].value = 'system';
  await send();
  assert.deepEqual(sent().body, { name: 'Egress', direction: 'outbound', default_action: 'allow', scope: 'system', rules: [{ action: 'deny', match: { destinations: ['*.example.com', '192.0.2.0/24'], ports: ['443', '8000-8080'] } }] }, 'a system set has no tenant');
  named(form, 'fw_rule_destinations')[0].value = '';
  named(form, 'fw_rule_ports')[0].value = '';
  await assert.rejects(send(), literal(msg`第 ${1} 条规则：请填写目的地、端口或两者`));

  // Editing: the direction, scope and tenant stay; the revision guards the update.
  context.editFirewallSet(sets[3]);
  assert.equal(title, msg`编辑规则集 · ${'Edge blocklist'}`);
  assert.ok(named(form, 'fw_direction')[0].disabled && named(form, 'fw_scope')[0].disabled, 'direction and scope are fixed after creation');
  assert.equal(named(form, 'fw_rule_sources')[0].value, '203.0.113.0/24');
  assert.ok(form.text().includes(msg`保存后，使用这个规则集的 ${2} 处会自动更新，无需重新发布配置。`));
  await send();
  assert.deepEqual(sent(), { path: '/firewall/sets/fs-s-in', method: 'PUT', body: { name: 'Edge blocklist', direction: 'inbound', default_action: 'allow', rules: [{ action: 'deny', match: { sources: ['203.0.113.0/24'] } }], expected_revision: 2 } });

  // A set in use cannot be deleted; the panel names where it is used before asking the controller.
  calls.length = 0;
  await assert.rejects(context.deleteFirewallSet(sets[3]), literal(msg`规则集 ${'Edge blocklist'} 仍在使用中（${[msg`${'Tokyo'} · ${translate('服务器入站')}`, msg`${'Tokyo'} · 规则 ${'web'}`].join('、')}）；请先解除这些绑定`));
  assert.equal(calls.length, 0);
  await context.deleteFirewallSet(sets[0]);
  assert.deepEqual(sent(), { path: '/firewall/sets/fs-t-in', method: 'DELETE', body: undefined });

  // The rule editor offers the rule tenant's inbound sets only, and saves the choice on the rule.
  saved = null;
  await context.editRule(forward);
  const pick = named(form, 'firewall_inbound_set')[0];
  assert.deepEqual(plain(options(pick)), [['', translate('不使用')], ['fs-t-in', 'Office only']], 'no system, outbound or other-tenant set');
  await send();
  assert.ok(saved && !('firewall_inbound_set' in saved), 'no set unless one is chosen');
  pick.value = 'fs-t-in'; await pick.fire('change');
  const warning = msg`服务器 ${'Tokyo'} 的 Agent 尚未报告支持防火墙规则集，发布会被拒绝；请先升级 Agent。`;
  assert.ok(pick.parentElement.parentElement.text().includes(warning), 'the old agent is named before publishing');
  translated(pick.parentElement.parentElement, 'rule editor firewall field');
  await send();
  assert.equal(saved.firewall_inbound_set, 'fs-t-in');
  tokyo.firewall_support = true;
  await context.editRule({ ...forward, firewall_inbound_set: 'fs-t-in' });
  assert.equal(named(form, 'firewall_inbound_set')[0].value, 'fs-t-in');
  assert.ok(!named(form, 'firewall_inbound_set')[0].parentElement.parentElement.text().includes(warning), 'no warning once the agent reports support');
  await send();
  assert.equal(saved.firewall_inbound_set, 'fs-t-in', 'an unchanged edit keeps the set');
  // A protocol gateway's Agent checks its clients before the engine: the set stays, with a note on newer Agents.
  editing = wire.id; context.state.config = { ...context.state.config, rules: [forward, wire] };
  await context.editRule(wire);
  const gatewayPick = named(form, 'firewall_inbound_set')[0];
  assert.ok(gatewayPick.visible() && gatewayPick.value === 'fs-t-in');
  assert.ok(gatewayPick.parentElement.parentElement.text().includes(translate('协议网关在 Agent 收到连接时就按客户端自己的地址检查，早于协议握手；需要较新的 Agent，旧版会拒绝发布。')));
  translated(gatewayPick.parentElement.parentElement, 'gateway firewall field');
  await send();
  assert.ok(saved.protocol_gateway && saved.firewall_inbound_set === 'fs-t-in', 'a gateway rule carries its set');

  // A server's bindings: system sets of the matching direction, and the desired/confirmed state.
  tokyo.firewall_support = false;
  const box = new Element('form'), server = context.serverFirewallFields(box, tokyo, sets);
  assert.deepEqual(plain(options(named(box, 'fw_server_inbound')[0])), [['', translate('不使用')], ['fs-s-in', 'Edge blocklist']]);
  assert.deepEqual(plain(options(named(box, 'fw_server_outbound')[0])), [['', translate('不使用')], ['fs-s-out', 'No mail']]);
  assert.equal(server.changed(), false);
  named(box, 'fw_server_outbound')[0].value = 'fs-s-out';
  assert.equal(server.changed(), true);
  assert.deepEqual(plain(server.read()), { inbound_set_id: 'fs-s-in', outbound_set_id: 'fs-s-out' });
  named(box, 'fw_server_inbound')[0].value = '';
  assert.deepEqual(plain(server.read()), { inbound_set_id: null, outbound_set_id: 'fs-s-out' }, 'None unbinds');
  assert.ok(box.text().includes(msg`服务器 ${'Tokyo'} 的 Agent 尚未报告支持防火墙规则集，绑定会被拒绝；请先升级 Agent。`));
  assert.ok(box.text().includes(translate('Agent 版本过旧，不支持规则集')));
  translated(box, 'server bindings');
  for (const [state, label] of [['waiting', '等待 Agent 确认'], ['offline', 'Agent 离线 · 重新连接后确认'], ['applied', '已生效']]) {
    const cell = context.firewallStatusCell({ ...tokyo.firewall, state, applied_hash: state === 'applied' ? desired : confirmed });
    assert.ok(cell.text().includes(translate(label)), state);
    assert.ok(cell.text().includes(msg`期望 ${desired.slice(0, 12)}`) && cell.text().includes(msg`已确认 ${(state === 'applied' ? desired : confirmed).slice(0, 12)}`), `${state} shows both hashes`);
    translated(cell, `${state} status`);
  }
  assert.ok(context.firewallStatusCell({ ...tokyo.firewall, state: 'waiting', applied_hash: null }).text().includes(msg`已确认 ${'—'}`), 'nothing confirmed yet');
  // Paths an older Agent leaves outside the bound sets are named, whatever the state.
  const uncovered = context.firewallStatusCell({ ...tokyo.firewall, state: 'applied', applied_hash: desired, uncovered: ['gateways', 'reverse_tunnels'] });
  for (const text of ['协议网关的客户端不受规则集检查：请升级 Agent', '反向隧道的目标不受出站规则集检查：请升级 Agent']) assert.ok(uncovered.text().includes(translate(text)), text);
  translated(uncovered, 'uncovered paths');
  assert.ok(!context.firewallStatusCell({ ...tokyo.firewall, state: 'applied', applied_hash: desired, uncovered: [] }).text().includes(translate('协议网关的客户端不受规则集检查：请升级 Agent')));

  // The tester: a set with a source, then a server and rule with a destination and its address.
  const tester = context.firewallTesterPanel(sets, [tokyo], { set_id: 'fs-s-in' });
  const testForm = tester.all().find(n => n.tag === 'form');
  assert.ok(!named(testForm, 'fw_test_node')[0].parentElement.visible() && named(testForm, 'fw_test_source')[0].parentElement.visible());
  named(testForm, 'fw_test_source')[0].value = ' 203.0.113.9 ';
  answer = { direction: 'inbound', decision: 'deny', layers: [{ layer: 'set', set_id: 'fs-s-in', set_name: 'Edge blocklist', rule_index: 0, default_action: false, result: 'deny' }] };
  await testForm.onsubmit({ preventDefault() {} });
  assert.deepEqual(sent(), { path: '/firewall/test', method: 'POST', body: { set_id: 'fs-s-in', source: '203.0.113.9' } });
  const result = tester.all().find(n => n.className === 'firewall-result');
  assert.ok(result.text().includes(msg`第 ${1} 条规则`), 'rule indexes count from 1 in the panel');
  assert.ok(result.text().includes(translate('最终结果：')) && result.text().includes(translate('拒绝')));
  translated(result, 'tester answer');
  await new Promise(resolve => setImmediate(resolve));
  named(testForm, 'fw_test_mode')[0].value = 'node'; await named(testForm, 'fw_test_mode')[0].fire('change');
  assert.deepEqual(plain(options(named(testForm, 'fw_test_rule')[0])), [['', translate('只测服务器绑定')], ['r2', 'web'], ['r3', 'vless']], 'gateway rules are tested like others');
  named(testForm, 'fw_test_rule')[0].value = 'r2';
  named(testForm, 'fw_test_kind')[0].value = 'outbound'; await named(testForm, 'fw_test_kind')[0].fire('change');
  assert.ok(!named(testForm, 'fw_test_source')[0].parentElement.visible() && named(testForm, 'fw_test_destination')[0].parentElement.visible());
  named(testForm, 'fw_test_destination')[0].value = 'smtp.example.com'; named(testForm, 'fw_test_port')[0].value = '465'; named(testForm, 'fw_test_address')[0].value = '192.0.2.25';
  answer = { direction: 'outbound', decision: 'deny', policy_hash: desired, layers: [
    { layer: 'server_outbound', set_id: 'fs-s-out', set_name: 'No mail', rule_index: 0, default_action: false, result: 'deny' },
    { layer: 'rule_lists', default_action: false, result: 'deny', detail: 'destination denied by rule policy' },
  ] };
  await testForm.onsubmit({ preventDefault() {} });
  assert.deepEqual(sent().body, { node_id: 'n1', rule_id: 'r2', destination: 'smtp.example.com', port: 465, address: '192.0.2.25' });
  const outbound = tester.all().find(n => n.className === 'firewall-result');
  assert.ok(outbound.text().includes(translate('服务器出站')) && outbound.text().includes(translate('被规则的目的地列表拒绝')));
  assert.ok(outbound.text().includes(msg`按服务器的期望策略 ${desired.slice(0, 12)} 计算。`));
  translated(outbound, 'outbound tester answer');
  const fallback = context.firewallResult({ direction: 'inbound', decision: 'allow', layers: [{ layer: 'server_inbound', set_id: 'fs-s-in', set_name: 'Edge blocklist', default_action: true, result: 'allow' }] });
  assert.ok(fallback.text().includes(translate('默认动作')) && !fallback.text().includes(msg`第 ${1} 条规则`), 'the default action is not a rule');
  // A tenant sees what a system set decided, not which set or rule.
  const hidden = context.firewallResult({ direction: 'inbound', decision: 'deny', layers: [{ layer: 'server_inbound', default_action: false, result: 'deny', detail: 'a rule set outside your tenant decides' }] });
  assert.ok(hidden.text().includes(translate('由租户之外的规则集决定')) && !hidden.text().includes(translate('列表允许')), 'a hidden layer does not read as a list');
  translated(hidden, 'hidden tester layer');

  // The page: sets with where they are used, and each server's state, for a system administrator.
  content = new Element('main');
  await context.renderFirewall();
  assert.ok(content.text().includes('Edge blocklist') && content.text().includes(msg`${'Tokyo'} · 规则 ${'web'}`));
  assert.ok(content.text().includes(translate('Agent 版本过旧，不支持规则集')));
  assert.equal(buttons(content, translate('绑定…')).length, 1);
  translated(content, 'firewall page');
  // A tenant administrator binds nothing to servers and keeps only tenant sets.
  context.state.actor = { id: 'owner', role: 'tenant_admin', tenant_id: 't' };
  content = new Element('main');
  await context.renderFirewall();
  assert.equal(buttons(content, translate('绑定…')).length, 0, 'server bindings are for system administrators');
  const rows = content.all().filter(n => n.tag === 'tr');
  assert.ok(rows.some(r => r.text().includes('Office only') && buttons(r, translate('编辑')).length === 1));
  assert.ok(rows.some(r => r.text().includes('Edge blocklist') && buttons(r, translate('编辑')).length === 0), 'a system set is not editable by a tenant');
  context.state.actor = { id: 'owner', role: 'system_admin', tenant_id: 't' };

  // Block records and refusals read in the panel's language; others stay as they are.
  assert.equal(context.firewallDetail('rule inbound rule set: rule 2 denies (Office only)'), msg`${translate('规则入站')}规则集「${'Office only'}」第 ${'2'} 条规则拒绝`);
  assert.equal(context.firewallDetail('server outbound rule set: default action denies (No mail)'), msg`${translate('服务器出站')}规则集「${'No mail'}」默认动作拒绝`);
  assert.equal(context.firewallDetail('server inbound rule set fs-x is not available here: refused'), msg`${translate('服务器入站')}规则集 ${'fs-x'} 在这台服务器上不可用：拒绝`);
  assert.equal(context.firewallDetail('egress proxy 203.0.113.20:1080: server outbound rule set: rule 1 denies (No mail)'), msg`出口代理 ${'203.0.113.20:1080'}：${msg`${translate('服务器出站')}规则集「${'No mail'}」第 ${'1'} 条规则拒绝`}`);
  assert.equal(context.firewallDetail('reverse tunnel private server: server outbound rule set: rule 1 denies (No lab)'), msg`反向隧道私有端：${msg`${translate('服务器出站')}规则集「${'No lab'}」第 ${'1'} 条规则拒绝`}`);
  assert.equal(context.firewallDetail('something else'), 'something else');
  const old = 'the agent on server Tokyo is too old for firewall rule sets; upgrade it first';
  assert.equal(context.firewallReason(old), msg`服务器 ${'Tokyo'} 的 Agent 版本过旧，不支持防火墙规则集；请先升级 Agent`);
  assert.equal(context.firewallReason('server Osaka has not connected to the panel yet; firewall rule sets need its agent to report in first'), msg`服务器 ${'Osaka'} 尚未连接面板；它的 Agent 回报后才能使用防火墙规则集`);
  assert.equal(context.firewallReason('rule set Edge is still bound: server Tokyo (inbound), rule web on server Tokyo; remove these bindings first'), msg`规则集 ${'Edge'} 仍在使用中（${'server Tokyo (inbound), rule web on server Tokyo'}）；请先解除这些绑定`);
  assert.equal(context.firewallReason('rule web: rule set No mail is an outbound set; a rule takes an inbound set'), msg`规则 ${'web'}：规则集 ${'No mail'} 是出站规则集，规则只能绑定入站规则集`);
  assert.equal(context.firewallReason('the direction of a rule set cannot change'), translate('规则集的方向创建后不能修改'));
  assert.equal(context.firewallReason('at most 64 firewall rule sets per tenant; delete one first'), msg`每个租户最多 ${'64'} 个防火墙规则集；请先删除一个`);
  assert.equal(context.firewallReason('at most 64 system firewall rule sets; delete one first'), msg`系统防火墙规则集最多 ${'64'} 个；请先删除一个`);
  assert.equal(context.firewallReason('a rule set is at most 1024 KiB; use fewer rules or entries'), msg`单个规则集最多 ${'1024'} KiB；请减少规则或条目`);
  const gateways = 'the agent on server Tokyo does not apply firewall rule sets to protocol gateways; upgrade it first';
  const tunnels = 'the agent on server Osaka does not apply its outbound firewall rule set to reverse tunnels; upgrade it first';
  assert.equal(context.firewallReason(gateways), msg`服务器 ${'Tokyo'} 的 Agent 不会用防火墙规则集检查协议网关的客户端；请先升级 Agent`);
  assert.equal(context.firewallReason('rule web listens on 0.0.0.0:443: disable it, publish that and wait until the server applies it before turning it into a protocol gateway there or back'), msg`规则 ${'web'} 正在 ${'0.0.0.0:443'} 上监听：请先停用并发布，等服务器应用后，再把它改成协议网关或改回普通规则`);
  assert.equal(context.firewallReason(tunnels), msg`服务器 ${'Osaka'} 的 Agent 不会用出站防火墙规则集检查反向隧道的目标；请先升级 Agent`);
  if (english) {
    assert.equal(context.firewallReason(gateways), 'The agent on server Tokyo does not apply firewall rule sets to protocol gateways; upgrade it first');
    assert.equal(context.firewallReason('rule web listens on 0.0.0.0:443: disable it, publish that and wait until the server applies it before turning it into a protocol gateway there or back'), 'Rule web listens on 0.0.0.0:443: disable it, publish that and wait until the server applies it before turning it into a protocol gateway there or back');
    assert.equal(context.firewallReason(tunnels), 'The agent on server Osaka does not apply its outbound firewall rule set to reverse tunnels; upgrade it first');
  }
  assert.equal(context.firewallReason('configuration changed; reload before saving'), null);
  assert.equal(context.firewallReason(undefined), null);
  if (english) assert.equal(context.firewallReason(old), 'The agent on server Tokyo is too old for firewall rule sets; upgrade it first');
  console.log(`Firewall (${i18n.getLanguage()}): set editor order, moves and checks, fixed direction, delete guard, rule editor field and gateway, uncovered paths, server bindings and states, tester requests and answers, page roles, block details and refusals passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
