// Executes the shipped shared-rule dialogs and the rule editor in shared mode with
// form-control stubs, and checks the request bodies they send. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const code = source.slice(source.indexOf('function gatewayConfig('), source.indexOf('const shadowsocksMethods'));
assert.ok(code.includes('function sharedLinesEditor(') && code.includes('async function editRule('), 'shared rule code not found');

class Element {
  constructor(tag = 'div', text = '') { Object.assign(this, { tag, textContent: text, children: [], value: '', checked: false, disabled: false, dataset: {}, classList: { toggle() {} } }); }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener() {} setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const button = (all, text) => {
  const found = all.filter(n => n.tag === 'button' && n.textContent === text);
  assert.equal(found.length, 1, `button ${text}`);
  return found[0];
};

const i18n = helpers.loadI18n(), { translate, msg } = i18n;
const nodes = [
  { id: 'a', name: 'Tokyo', tenant_id: 't', enrolled: true, last_seen_ms: Date.now(), desired_revision: 1, applied_revision: 1 },
  { id: 'b', name: 'Osaka', tenant_id: 't' },
  { id: 'c', name: 'Seoul', tenant_id: 't' },
  { id: 'x', name: 'Elsewhere', tenant_id: 'other' },
];
const target = { address: '192.0.2.10:443', weight: 1 };
let form, handler, calls = [], fail = null, clipboard = null;
const context = {
  ...helpers.loadI18n(), ...helpers.loadWorkflows(),
  TextEncoder, Uint8Array, Uint32Array, btoa, crypto: require('node:crypto').webcrypto,
  document: { createTextNode: text => text },
  navigator: { clipboard: { writeText: async text => { clipboard = text; } } },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  forwardingPathView: () => ({ box: new Element(), update() {} }), featureOn: () => false, canWrite: () => true,
  state: { config: null, nodes: [], actor: { id: 'owner', role: 'tenant_admin' }, selectedNode: 'b' },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    if (fail && path === fail.path) throw Object.assign(new Error('conflict'), { detail: fail.detail });
    if (path === '/nodes') return nodes;
    if (path.startsWith('/nodes/')) return { node_id: decodeURIComponent(path.split('/')[2]), revision: 4, rules: [] };
    if (path === '/topology') return { configs: [], nodes: [] };
    if (path === '/shared-rules/precheck') return { listen_port: options.body.listen_port ?? 25505, ok: true, error: null, lines: options.body.node_ids.map(id => ({ node_id: id, node_name: id, online: true, in_range: true, port_start: 20000, port_end: 29999, port_free: true, valid: true, error: null })) };
    return {};
  },
  el: (tag, text) => new Element(tag, text),
  field(parent, name, _label, value = '', type = 'text', required = true) { const label = new Element('label'), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); label.append(input); parent.append(label); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0][0]); input.tag = 'select'; input.options = options.map(([id]) => id); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  checkbox(parent, name, text) { const label = new Element('label', text), input = new Element('input'); Object.assign(input, { name, type: 'checkbox' }); label.prepend(input); parent.append(label); return input; },
  button: (text, handler) => Object.assign(new Element('button', text), { handler }),
  badge: text => new Element('span', text), namedCell: (name, detail) => { const n = new Element('div', name); n.append(new Element('div', detail)); return n; },
  table: (headers, rows) => { const n = new Element('table'); n.rows = rows; for (const row of rows) n.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); return n; },
  panel: (title, _description, action) => { const n = new Element('section', title); if (action) n.append(action); return n; },
  applicationBadge: node => new Element('span', node.id),
  healthEditor: (_form, spec) => () => spec,
  multipathEditor: () => ({ mode: {}, read: () => ({}) }),
  targetEditor: (_form, targets) => { const read = () => targets; read.multipathPaths = () => []; read.preview = () => targets; read.onchange = () => {}; return read; },
  websocketEditor: (_name, spec) => ({ box: new Element(), read: () => spec }),
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal() {}, notify() {}, refresh: async () => {},
  $: () => ({ close() {} }), confirmAction: async () => true,
  number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
};
for (const helper of ['shadowsocksEditor', 'socks5Editor', 'httpConnectEditor', 'http2ConnectEditor']) context[helper] = spec => ({ box: new Element(), read: () => spec ?? null, enabled: () => !!spec, onchange() {}, setEnabled() {} });
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function sectionVisible('), source.indexOf('function websocketEditor(')) + code + '\nObject.assign(this, { openSharedRule, extendRule, pauseSharedRule, deleteSharedRule, sharedRulesPanel });', context);
const send = () => handler(new context.FormData(form));
const last = path => calls.filter(call => call.path === path).at(-1);
const plain = value => JSON.parse(JSON.stringify(value));

(async () => {
  // New shared rule: lines come from the reference server's tenant, Auto pick asks
  // without a port and fills the answer in, and Create posts every chosen line.
  await context.openSharedRule();
  let all = form.all();
  const boxes = all.filter(n => n.tag === 'input' && n.type === 'checkbox' && !n.name);
  assert.deepEqual(boxes.map(n => n.value), ['a', 'b', 'c'], 'only servers of one tenant are offered');
  assert.ok(!all.find(n => n.name === 'rule_purpose').options.includes('gateway'), 'managed gateways cannot be shared');
  assert.ok(all.find(n => n.name === 'listen').disabled, 'the listen host is chosen per line');
  assert.ok(all.find(n => n.name === 'advertise').disabled && all.find(n => n.name === 'listen_end_port').disabled);
  boxes[0].checked = true; boxes[2].checked = true;
  all.find(n => n.name === 'name').value = 'Web';
  await button(all, translate('自动选号')).handler();
  let check = last('/shared-rules/precheck');
  assert.deepEqual(check.body.node_ids, ['a', 'c']);
  assert.equal(check.body.listen_port, null, 'Auto pick lets the controller choose');
  assert.equal(check.body.id, undefined);
  assert.equal(check.body.rule.targets[0].address, '127.0.0.1:8000', 'the precheck validates the rule in the form');
  const port = all.find(n => n.name === 'shared_port');
  assert.equal(port.value, '25505', 'the picked port is filled in');
  port.value = '26000';
  await button(all, translate('检查')).handler();
  assert.equal(last('/shared-rules/precheck').body.listen_port, 26000);
  await send();
  let saved = last('/shared-rules');
  assert.equal(saved.method, 'POST');
  assert.deepEqual(Object.keys(saved.body).sort(), ['listen_port', 'name', 'node_ids', 'rule']);
  assert.equal(saved.body.name, 'Web');
  assert.deepEqual(saved.body.node_ids, ['a', 'c']);
  assert.equal(saved.body.listen_port, 26000);
  assert.equal(saved.body.rule.name, 'Web');
  assert.equal(saved.body.rule.owner_id, 'owner');
  assert.equal(saved.body.rule.advertise, null);
  assert.equal(saved.body.rule.listen_end_port, null);
  assert.equal(saved.body.rule.protocol_gateway, undefined);
  boxes.forEach(box => { box.checked = false; });
  await assert.rejects(send(), /服务器|server/);

  // Editing starts from the first present line, keeps the shared rule's port and
  // lines, sends the id with a check and shows per-line errors from a refused save.
  const rule = { id: 'r-b', tenant_id: 't', owner_id: 'someone', name: 'Web', listen: '0.0.0.0:26000', protocol: 'tcp', targets: [target], enabled: false, meter_epoch: 'e', quota_bytes: 1000, rate_bytes_per_sec: null, expires_at_ms: null };
  const view = { id: 's 1', name: 'Web', listen_port: 26000, drift: ['rate_bytes_per_sec'], members: [
    { node_id: 'x-gone', rule_id: 'r-x', missing: true, node_name: null, rule: null, entry: null, drift: [] },
    { node_id: 'b', rule_id: 'r-b', missing: false, node_name: 'Osaka', rule, entry: 'osaka.example:26000', drift: [] },
    { node_id: 'c', rule_id: 'r-c', missing: false, node_name: 'Seoul', rule: { ...rule, id: 'r-c', listen: '10.0.0.3:26000', rate_bytes_per_sec: 5 }, entry: null, drift: ['rate_bytes_per_sec'] },
  ] };
  await context.openSharedRule(view);
  assert.equal(last('/nodes/b/config').method, 'GET', 'the first present line is the reference');
  all = form.all();
  assert.deepEqual(all.filter(n => n.tag === 'input' && n.type === 'checkbox' && !n.name && n.checked).map(n => n.value), ['b', 'c']);
  assert.equal(all.find(n => n.name === 'shared_port').value, '26000');
  assert.ok(form.text().includes('rate_bytes_per_sec'), 'the drift warning names the fields');
  await button(all, translate('检查')).handler();
  assert.equal(last('/shared-rules/precheck').body.id, 's 1', 'a check while editing excludes the rule\'s own lines');
  all.find(n => n.tag === 'input' && n.value === 'a').checked = true;
  all.find(n => n.name === 'shared_port').value = '26001';
  await send();
  saved = last('/shared-rules/s%201');
  assert.equal(saved.method, 'PUT');
  assert.deepEqual(saved.body.node_ids, ['a', 'b', 'c']);
  assert.equal(saved.body.listen_port, 26001);
  assert.equal(saved.body.rule.targets[0].address, target.address);
  assert.equal(saved.body.rule.quota_bytes, 1000);
  assert.equal(saved.body.rule.enabled, false, 'a paused shared rule stays paused');
  assert.equal(saved.body.rule.owner_id, 'someone');
  fail = { path: '/shared-rules/s%201', detail: { error: 'conflict', lines: [{ node_id: 'a', error: 'port 26001 is already used on this server' }] } };
  await assert.rejects(send(), /conflict/);
  assert.ok(form.text().includes('Tokyo') && form.text().includes('port 26001 is already used'), 'per-line errors are listed by server name');
  fail = null;

  // Extending a rule sends the source rule and only the added lines.
  context.state.nodes = nodes;
  const ordinary = { ...rule, id: 'r-a', listen: '0.0.0.0:21234' };
  context.extendRule({ node_id: 'a', revision: 3, rules: [ordinary] }, ordinary);
  all = form.all();
  assert.deepEqual(all.filter(n => n.tag === 'input' && n.type === 'checkbox').map(n => n.value), ['b', 'c']);
  assert.ok(all.find(n => n.name === 'shared_port').disabled, 'the port of the original rule is kept');
  assert.equal(all.filter(n => n.tag === 'button' && n.textContent === translate('自动选号')).length, 0);
  all.find(n => n.value === 'c').checked = true;
  await button(all, translate('检查')).handler();
  assert.deepEqual(plain(last('/shared-rules/precheck').body), { node_ids: ['c'], listen_port: 21234, rule: plain(ordinary) });
  await send();
  assert.deepEqual(last('/shared-rules/from-rule').body, { node_id: 'a', rule_id: 'r-a', add_node_ids: ['c'] });

  // Pause, resume and delete act on the whole shared rule.
  await context.pauseSharedRule(view, true);
  assert.deepEqual(last('/shared-rules/s%201/pause').body, { paused: true });
  await context.pauseSharedRule(view, false);
  assert.deepEqual(last('/shared-rules/s%201/pause').body, { paused: false });
  context.deleteSharedRule(view);
  assert.ok(form.text().includes(msg`${'Osaka'} · 端口 ${26000}`) && form.text().includes(msg`${'Seoul'} · 端口 ${26000}`), 'delete lists the lines and ports');
  await send();
  assert.equal(calls.at(-1).path, '/shared-rules/s%201');
  assert.equal(calls.at(-1).method, 'DELETE');
  context.deleteSharedRule(view);
  form.all().find(n => n.name === 'keep_rules').checked = true;
  await send();
  assert.equal(calls.at(-1).path, '/shared-rules/s%201?keep_rules=true');

  // The list counts lines, warns about drift and copies every known entry address.
  const listed = context.sharedRulesPanel([{ ...view, members: [...view.members, { ...view.members[2], node_id: 'a', node_name: 'Tokyo', entry: 'tokyo.example:26000', drift: [] }] }], nodes);
  assert.ok(listed.text().includes(msg`共同规则 · ${4} 条线路`));
  assert.ok(listed.text().includes(translate('线路配置不一致')));
  await button(listed.all(), translate('复制全部')).handler();
  assert.equal(clipboard, 'osaka.example:26000\ntokyo.example:26000');
  console.log(`Shared rules (${i18n.getLanguage()}): create with Auto pick and Check, edit with drift and per-line errors, extend, pause/resume, delete with and without keeping rules, and Copy all send the expected requests`);
})().catch(error => { console.error(error); process.exitCode = 1; });
