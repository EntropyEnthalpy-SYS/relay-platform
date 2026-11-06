// Executes the shipped endpoint group and saved chain dialogs, the "Use a saved chain" flow with
// the real publish preview, and the New forwarding chooser with form-control stubs, and checks
// the request bodies they send. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const code = between('// Endpoint groups and saved chains.', 'async function newTopologyChain(')
  + between('// `source` lets a caller supply', 'async function changeTopologyComponent(')
  + between('function chooseSetup() {', 'async function pickTemplate(');

class Element {
  constructor(tag = 'div', text = '', className = '') { Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {} }); this.classList = { add() {}, toggle() {}, contains: () => false }; }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().map(n => [n.textContent, n.placeholder || '', ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const button = (root, text) => {
  const found = root.all().filter(n => n.tag === 'button' && n.textContent === text);
  assert.equal(found.length, 1, `button ${text}`);
  return found[0];
};
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
// The rendered text of a dialog or panel must be fully translated in English.
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };
const nodes = [
  { id: 'e', name: 'Entry', tenant_id: 't' }, { id: 'a1', name: 'Tokyo', tenant_id: 't' }, { id: 'a2', name: 'Osaka', tenant_id: 't' },
  { id: 'b1', name: 'Frankfurt', tenant_id: 't' }, { id: 'b2', name: 'London', tenant_id: 't' }, { id: 'x', name: 'Elsewhere', tenant_id: 'other' },
];
const member = id => ({ node_id: id, node_name: nodes.find(n => n.id === id)?.name ?? null, missing: !nodes.some(n => n.id === id) });
const groups = [
  { id: 'g1', tenant_id: 't', name: 'Relays', description: 'IX', members: ['a2', 'a1'].map(member), used_by: [{ id: 'c1', name: 'Asia' }] },
  { id: 'g2', tenant_id: 't', name: 'Exits', description: '', members: ['b1', 'gone'].map(member), used_by: [] },
];
const chains = [
  { id: 'c1', tenant_id: 't', name: 'Asia', enabled: true, layers: [
    { group_id: 'g1', group_name: 'Relays', balance: 'source_hash', members: groups[0].members },
    { group_id: 'g2', group_name: 'Exits', balance: 'weighted_round_robin', members: [member('b1')] },
  ], uses: [{ entry_rule_id: 'r-e', entry_node_id: 'e', entry_node_name: 'Entry', name: 'Web · 1', missing: false, out_of_date: true, layers: [], changes: [{ layer: 2, added: ['b2'], removed: ['b1'] }] }] },
  { id: 'c2', tenant_id: 't', name: 'Fast', enabled: true, layers: [{ group_id: 'g2', group_name: 'Exits', balance: 'lowest_latency', members: [member('b1')] }], uses: [] },
  { id: 'c3', tenant_id: 't', name: 'Off', enabled: false, layers: [{ group_id: 'g2', group_name: 'Exits', balance: 'random', members: [member('b1')] }], uses: [] },
];
const rule = (id, advertise, targets) => ({ id, tenant_id: 't', owner_id: 'owner', name: 'Web', listen: '0.0.0.0:' + advertise.split(':')[1], advertise, protocol: 'both', enabled: true, targets });
const via = (node_id, rule_id, address) => ({ address, via: { node_id, rule_id }, weight: 1 });
const planned = [
  { node_id: 'e', expected_revision: 4, rules: [rule('r-e', 'entry.example:30007', [via('a2', 'r-a2', 'osaka.example:30100'), via('a1', 'r-a1', 'tokyo.example:30200')])] },
  { node_id: 'a2', expected_revision: 9, rules: [rule('r-a2', 'osaka.example:30100', [via('b1', 'r-b1', 'frankfurt.example:30300')])] },
  { node_id: 'a1', expected_revision: 2, rules: [rule('r-a1', 'tokyo.example:30200', [via('b1', 'r-b1', 'frankfurt.example:30300')])] },
  { node_id: 'b1', expected_revision: 7, rules: [rule('r-b1', 'frankfurt.example:30300', [{ address: '192.0.2.80:443', weight: 1 }])] },
];
const plan = {
  entry_rule_id: 'r-e', batch: { updates: planned },
  hops: planned.map((update, index) => ({ layer: [0, 1, 1, 2][index], node_id: update.node_id, node_name: update.node_id, rule_id: update.rules[0].id, listen: update.rules[0].listen, advertise: update.rules[0].advertise })),
  preview: { configs: planned.map(update => ({ node_id: update.node_id, revision: update.expected_revision + 1, rules: update.rules })), changes: planned.map(update => ({ node_id: update.node_id, from_revision: update.expected_revision, to_revision: update.expected_revision + 1, added: [update.rules[0].id], modified: [], removed: [], rule_changes: [] })) },
};

let form, handler, dialog, calls = [], confirmed = true, navigated = null, diagram = null, usedChain;
const context = {
  ...helpers.loadI18n(), ...helpers.loadWorkflows(),
  document: { createTextNode: text => text },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  canWrite: () => true, state: { actor: { id: 'owner', role: 'tenant_admin' }, selectedNode: 'a1', nodes: [] },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    if (path === '/nodes') return nodes;
    if (path === '/endpoint-groups' && !options.method) return groups;
    if (path === '/chains' && !options.method) return chains;
    if (path === '/users') return [{ id: 'owner', username: 'owner', tenant_id: 't' }, { id: 'other-user', username: 'other', tenant_id: 't' }];
    if (path === '/topology') return { nodes, configs: nodes.map(node => ({ node_id: node.id, revision: 1, rules: [] })) };
    if (path.endsWith('/plan')) return plan;
    if (path.startsWith('/configurations/')) throw new Error('a saved chain must not use the generic preview or publish');
    return {};
  },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, _label, value = '', type = 'text', required = true) { const label = new Element('label', _label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); label.append(input); parent.append(label); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  checkbox(parent, name, text) { const label = new Element('label', text), input = new Element('input'); Object.assign(input, { name, type: 'checkbox' }); label.prepend(input); parent.append(label); return input; },
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); for (const row of rows) n.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); return n; },
  panel: (title, description, action) => { const n = new Element('section', title); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  empty: (title, description, action) => { const n = new Element('div', title); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal: (_title, body) => { dialog = body; }, notify() {}, refresh: async () => {},
  navigate: async view => { navigated = view; }, $: () => ({ close() {} }), confirmAction: async () => confirmed,
  topologyKey: ref => `${ref.node_id}/${ref.rule_id}`,
  forwardingPathView: () => ({ box: new Element('figure'), update(model, stage) { diagram = { model, stage }; } }),
  setupRecipes: [], startSetup() {}, pickTemplate() {},
};
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { chainsPanel, openEndpointGroup, deleteEndpointGroup, openChain, deleteChain, useChain, chooseSetup, previewTopology });', context);
const send = () => handler(new context.FormData(form));
const last = path => calls.filter(call => call.path === path).at(-1);
const field = name => form.all().find(n => n.name === name);
const press = node => node.action();

(async () => {
  // The panel lists groups with ordered members and missing servers, and chains with their
  // layers, balances and out-of-date uses named by server.
  const shown = context.chainsPanel(groups, chains, nodes);
  const text = shown.text();
  assert.ok(text.indexOf('Osaka') < text.indexOf('Tokyo'), 'members keep the group order');
  assert.ok(text.includes(translate('服务器已删除')), 'a deleted member is marked');
  assert.ok(text.includes(translate('来源 IP 哈希')) && text.includes(translate('已停用')));
  assert.ok(text.includes(translate('组成员已变化')) && text.includes(msg`新增 ${'London'}`) && text.includes(msg`移除 ${'Frankfurt'}`), 'out-of-date uses name the changed servers');
  assert.equal(buttons(shown, translate('用此链新建转发')).length, 2, 'only enabled chains offer a new forwarding');
  translated(shown, 'panel');

  // New group: Add offers servers of the first member's tenant; Up and Down set the order.
  await context.openEndpointGroup();
  const choice = field('group_add');
  assert.deepEqual(choice.children.map(o => o.value), ['e', 'a1', 'a2', 'b1', 'b2', 'x']);
  choice.value = 'b2'; await press(button(form, translate('添加')));
  assert.deepEqual(choice.children.map(o => o.value), ['e', 'a1', 'a2', 'b1'], 'other tenants and chosen servers are not offered');
  choice.value = 'b1'; await press(button(form, translate('添加')));
  await press(buttons(form, translate('上移'))[1]);
  field('group_name').value = 'Exits';
  translated(form, 'group dialog');
  await send();
  assert.deepEqual(last('/endpoint-groups').body, { name: 'Exits', description: '', members: ['b1', 'b2'] });
  assert.equal(last('/endpoint-groups').method, 'POST');
  // Editing drops deleted members and keeps the order.
  await context.openEndpointGroup(groups[1]);
  assert.ok(form.text().includes(msg`${1} 台服务器已删除，保存时从组中移除。`));
  await send();
  assert.deepEqual(last('/endpoint-groups/g2'), { path: '/endpoint-groups/g2', method: 'PUT', body: { name: 'Exits', description: '', members: ['b1'] } });
  await press(button(form, translate('移除')));
  await assert.rejects(send(), new RegExp(translate('请至少添加一台服务器。')));
  // A used group is refused before asking; an unused one is deleted after confirmation.
  await assert.rejects(context.deleteEndpointGroup(groups[0]), /Asia/);
  await context.deleteEndpointGroup(groups[1]);
  assert.equal(calls.at(-1).method, 'DELETE'); assert.equal(calls.at(-1).path, '/endpoint-groups/g2');

  // New chain: layers in order with a balance each; Add layer picks an unused group.
  await context.openChain();
  assert.equal(field('layer_group_0').value, 'g1');
  await press(button(form, translate('＋ 添加层')));
  assert.equal(field('layer_group_1').value, 'g2');
  field('layer_balance_0').value = 'source_hash'; await field('layer_balance_0').fire('change');
  field('layer_balance_1').value = 'least_connections'; await field('layer_balance_1').fire('change');
  await press(buttons(form, translate('上移'))[1]);
  field('chain_name').value = 'Asia';
  translated(form, 'chain dialog');
  await send();
  assert.deepEqual(last('/chains'), { path: '/chains', method: 'POST', body: { name: 'Asia', enabled: true, layers: [{ group_id: 'g2', balance: 'least_connections' }, { group_id: 'g1', balance: 'source_hash' }] } });
  // Editing keeps the layers; turning the chain off sends enabled:false.
  await context.openChain(chains[0]);
  form.all().find(n => n.name === 'chain_enabled').checked = false;
  await send();
  assert.deepEqual(last('/chains/c1').body, { name: 'Asia', enabled: false, layers: [{ group_id: 'g1', balance: 'source_hash' }, { group_id: 'g2', balance: 'weighted_round_robin' }] });
  await context.deleteChain(chains[0]);
  assert.deepEqual(calls.at(-1), { path: '/chains/c1', method: 'DELETE', body: undefined });

  // Use a saved chain: entries exclude chain members and other tenants; the plan is reviewed in
  // the usual preview and published through apply with the plan's revisions.
  await context.useChain('c1');
  assert.deepEqual(field('chain').children.map(o => o.value), ['c1', 'c2'], 'disabled chains are not offered');
  assert.deepEqual(field('entry_node_id').children.map(o => o.value), ['e', 'b2']);
  assert.equal(field('entry_node_id').value, 'e');
  assert.ok(form.text().includes('Osaka · Tokyo'), 'the layers list their candidates');
  translated(form, 'use chain dialog');
  field('name').value = ' Web '; field('target').value = '192.0.2.80:443'; field('entry_port').value = '30007';
  await send();
  const body = { entry_node_id: 'e', name: 'Web', protocol: 'both', target: '192.0.2.80:443', entry_port: 30007 };
  assert.deepEqual(last('/chains/c1/plan'), { path: '/chains/c1/plan', method: 'POST', body });
  assert.equal(diagram.stage, 'validated');
  assert.deepEqual(diagram.model.root.children.map(child => child.next.name), ['Osaka', 'Tokyo'], 'the planned path shows layer 1 as candidates of the entry');
  assert.deepEqual(diagram.model.root.children[0].next.children.map(child => child.next.name), ['Frankfurt']);
  translated(dialog, 'preview');
  await press(button(dialog, translate('发布这些变更')));
  assert.deepEqual(last('/chains/c1/apply').body, { ...body, expected_revisions: { e: 4, a2: 9, a1: 2, b1: 7 } });
  assert.equal(navigated, 'topology');
  assert.equal(calls.filter(call => call.path.startsWith('/configurations/')).length, 0);
  // A lowest-latency chain is TCP only; an empty port lets the controller choose; another owner is sent.
  await context.useChain('c2');
  assert.equal(field('entry_node_id').value, 'a1', 'the selected server is the default entry when it is outside the chain');
  assert.equal(field('protocol').value, 'tcp'); assert.ok(field('protocol').disabled);
  field('name').value = 'Fast'; field('target').value = 'db.example:5432'; field('owner').value = 'other-user';
  await send();
  assert.deepEqual(last('/chains/c2/plan').body, { entry_node_id: 'a1', name: 'Fast', protocol: 'tcp', target: 'db.example:5432', entry_port: null, owner_id: 'other-user' });

  // New forwarding offers the saved chains next to the guided recipes.
  context.useChain = async () => { usedChain = true; };
  context.chooseSetup();
  const card = dialog.all().find(n => n.tag === 'button' && n.dataset.recipe === 'chain');
  assert.ok(card && card.text().includes(translate('使用已保存的转发链')));
  await press(card); assert.ok(usedChain);
  console.log(`Saved chains (${i18n.getLanguage()}): panel lists ordered members, layers and out-of-date uses; group and chain dialogs send ordered members and layers with balances; Use a saved chain plans, previews and applies with the planned revisions; New forwarding offers it`);
})().catch(error => { console.error(error); process.exitCode = 1; });
