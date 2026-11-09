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
  ], uses: [{ entry_rule_id: 'r-e', entry_node_id: 'e', entry_node_name: 'Entry', name: 'Web · 1', missing: false, out_of_date: true, layers: [], changes: [{ layer: 2, added: ['b2'], removed: ['b1'] }] },
    // A use whose automatic refresh is draining: one agent confirmed, one failed.
    { entry_rule_id: 'r-f', entry_node_id: 'e', entry_node_name: 'Entry', name: 'Game · 1', missing: false, out_of_date: true, layers: [], changes: [{ layer: 1, added: ['a2'], removed: [] }],
      auto_sync: { enabled_by: 'owner', enabled_at_ms: 1, timeout_secs: 600, failures: 1, next_attempt_ms: 0, last_result: 'timed out' },
      refresh: { id: 'f1', automatic: true, phase: 'draining', stage: 'updating', outcome: null, interrupted: true, error: null, retry_error: null, notes: [], problems: [], servers: [], unresolved: [],
        commits: [{ step: 'add', at_ms: 1, revisions: { a2: 3 } }, { step: 'pause', at_ms: 2, revisions: { e: 4, a2: 4 } }],
        waiting: [{ node_id: 'a1', error: 'Tokyo must be idle: 2 TCP sessions' }],
        agents: [{ node_id: 'e', node_name: 'Entry', step: 'pause', state: 'applied' }, { node_id: 'a2', node_name: 'Osaka', step: 'pause', state: 'failed', error: 'port 30100 is in use' }] } }] },
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
// A refresh preview of r-e: Frankfurt leaves layer 2 and London joins it, so the entry and layer 1
// stop; their three servers must be idle.
const server = (node_id, node_name, active_tcp, active_udp) => ({ node_id, node_name, enrolled: true, online: true, desired_revision: 3, applied_revision: 3, apply_error: null, active_tcp, active_udp, active_probes: 0, idle: !active_tcp && !active_udp });
const freshPlan = () => ({
  entry_rule_id: 'r-e', token: 'tok-1', up_to_date: false, interrupts: true, timeout_secs: 600,
  changes: [{ layer: 2, added: ['b2'], removed: ['b1'] }], conflicts: [], notes: [],
  warnings: [{ node_id: 'b2', rule_id: null, message: 'source lists on London are not updated' }],
  idle_servers: [server('e', 'Entry', 0, 0), server('a1', 'Tokyo', 2, 1), { ...server('a2', 'Osaka', 0, 0), enrolled: false, online: false }],
  hops: [{ layer: 2, node_id: 'b2', node_name: 'London', rule_id: 'r-b2', listen: '0.0.0.0:30400', advertise: 'london.example:30400' }],
  expected_revisions: { e: 3, a1: 3, a2: 3, b1: 3, b2: 1 },
  result: [{ node_id: 'a1', node_name: 'Tokyo', revision: 3, added: [], removed: [], modified: ['r-a1'], rule_changes: [{ rule_id: 'r-a1', before: { name: 'Web', targets: ['frankfurt.example:30300'] }, after: { name: 'Web', targets: ['london.example:30400'] } }] },
    { node_id: 'b1', node_name: 'Frankfurt', revision: 3, added: [], removed: ['r-b1'], modified: [], rule_changes: [{ rule_id: 'r-b1', before: { name: 'Web' }, after: null }] },
    { node_id: 'b2', node_name: 'London', revision: 1, added: ['r-b2'], removed: [], modified: [], rule_changes: [{ rule_id: 'r-b2', before: null, after: { name: 'Web' } }] }],
  preview: null,
});
let refreshPlan = freshPlan();
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
    if (path.endsWith('/refresh/plan')) return refreshPlan;
    if (path.endsWith('/plan')) return plan;
    if (path.startsWith('/configurations/')) throw new Error('a saved chain must not use the generic preview or publish');
    return {};
  },
  el: (tag, text, className) => new Element(tag, text, className),
  timestamp: ms => `at-${ms}`,
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
vm.runInContext(code + '\nObject.assign(this, { chainsPanel, openEndpointGroup, deleteEndpointGroup, openChain, deleteChain, useChain, chooseSetup, previewTopology, openChainRefresh });', context);
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

  // Refresh: an out-of-date use offers a preview; a running refresh shows its phase, what it
  // waits for, the controller commit apart from each agent's confirmation, and can be cancelled.
  assert.equal(buttons(shown, translate('预览更新…')).length, 1, 'no second refresh while one runs');
  assert.ok(text.includes(translate('更新中 · 已暂停新连接，等待会话结束')) && text.includes(translate('这条转发现在不接受新连接，现有连接保持。')));
  assert.ok(text.includes(msg`等待：${'Tokyo must be idle: 2 TCP sessions'}`));
  assert.ok(text.includes(msg`最近一次提交“${translate('暂停新连接')}”（${'Entry · Osaka'}）：控制器已提交；${1}/${2} 台服务器的 Agent 已确认`) && text.includes(msg`${'Osaka'} 应用失败：${'port 30100 is in use'}。它继续运行上一份已应用的配置；排除原因后 Agent 会自动重试。`));
  assert.ok(text.includes(msg`自动更新已开启 · 最长 ${600} 秒`) && text.includes(msg`自动更新连续 ${1} 次未成功：${'timed out'}`));
  // Waiting for a server that never connected is shown with what it waits for and when it looks
  // again, apart from any failures before it, and not as a failure reason.
  const reason = 'a refresh adds rules to server London, which has not connected to the panel yet; its agent (0.145.0 or later) must report in first';
  for (const failures of [0, 2]) {
    const waits = { ...chains[0], uses: [{ ...chains[0].uses[0], refresh: null, auto_sync: { enabled_by: 'owner', enabled_at_ms: 1, timeout_secs: 600, failures, next_attempt_ms: 300000, last_result: `waiting: ${reason}` } }] };
    const waitPanel = context.chainsPanel(groups, [waits], nodes), waitText = waitPanel.text();
    translated(waitPanel, 'waiting automatic update');
    assert.ok(waitText.includes(msg`自动更新在等待，不计为失败，${'at-300000'} 再检查：${reason}`), 'the wait names what it waits for');
    assert.ok(!waitText.includes('waiting:'), 'the wait is not shown as a failure reason');
    assert.equal(waitText.includes(msg`自动更新此前连续 ${2} 次未成功`), failures === 2, 'earlier failures are counted apart');
  }
  // A failed refresh names each server's problem and which servers have not confirmed the
  // restore, apart from the controller's commit; its notes are folded away.
  const failed = { ...chains[0], uses: [{ ...chains[0].uses[0], refresh: { id: 'f2', automatic: false, phase: 'finished', stage: 'finished', outcome: 'failed', interrupted: false, error: 'an agent could not apply the pause', retry_error: null, waiting: [], commits: [{ step: 'restore', at_ms: 3, revisions: { e: 6, a1: 6 } }], unresolved: [],
    problems: [{ node_id: 'a1', error: 'paused targets need a newer agent' }, { node_id: 'e', error: 'Entry could not apply revision 5: bind failed' }], notes: ['left as is: rule Web on Osaka was changed by someone else'],
    servers: [{ node_id: 'a1', node_name: 'Tokyo' }],
    agents: [{ node_id: 'e', node_name: 'Entry', step: 'restore', state: 'applied', online: true }, { node_id: 'a1', node_name: 'Tokyo', step: 'restore', state: 'pending', online: false }, { node_id: 'b2', node_name: 'London', step: 'cleanup', state: 'not_enrolled', online: false }] } }] };
  const failedPanel = context.chainsPanel(groups, [failed], nodes), failedText = failedPanel.text();
  translated(failedPanel, 'failed refresh');
  assert.ok(failedText.includes(translate('上次更新失败')) && failedText.includes(msg`原因：${'an agent could not apply the pause'}`));
  assert.ok(failedText.includes(msg`${'Tokyo'}：${'paused targets need a newer agent'}`), 'per-server problems are shown');
  assert.ok(failedText.includes('Entry could not apply revision 5') && !failedText.includes(msg`${'Entry'}：${'Entry could not'}`), 'a message naming its server is not prefixed again');
  assert.ok(failedText.includes(msg`最近一次提交“${translate('恢复原转发')}”（${'Entry · Tokyo'}）：控制器已提交；${1}/${2} 台服务器的 Agent 已确认`), 'the count is of the latest commit only');
  assert.ok(failedText.includes(msg`${'Tokyo'}：“${translate('恢复原转发')}”已提交，服务器离线，恢复连接后确认`) && failedText.includes(msg`${'London'}：“${translate('删除不再使用的规则')}”已提交，这台服务器还没有安装 Agent`));
  assert.ok(failedText.includes(msg`说明（${1}）`) && failedText.includes('left as is'));
  // While updating, saving a rule as disabled again does not keep it stopped: the panel says so.
  assert.ok(text.includes(translate('更新期间在规则编辑里再保存一次“停用”不会让规则保持停止；要保持停止，请用“取消并保持停止”。')));
  // A blocked rewire and a refused restore are shown as blocked, not as restored; rules left to an
  // operator are listed with what to do; a blocked refresh can be dismissed, not cancelled.
  const stuck = (id, phase, stage, extra) => ({ ...chains[0].uses[0], entry_rule_id: id, refresh: { id, automatic: false, phase, stage, outcome: 'failed', interrupted: true, error: 'an agent rejected the rewire', retry_error: null, waiting: [], commits: [], notes: [], problems: [], servers: [], agents: [], unresolved: [], ...extra } });
  const blocked = { ...chains[0], uses: [
    stuck('r-b', 'blocked', 'blocked', {}),
    stuck('r-r', 'restoring', 'restore_blocked', { retry_error: 'restoring is refused on some servers, retrying: Entry: too old', waiting: [{ node_id: 'e', error: 'Entry: too old' }],
      commits: [{ step: 'stop', at_ms: 1, revisions: { e: 5, a1: 5 } }], agents: [{ node_id: 'e', node_name: 'Entry', step: 'stop', state: 'applied' }, { node_id: 'a1', node_name: 'Tokyo', step: 'stop', state: 'applied' }] }),
    // Committed, but the entry's agent rejected it or never confirmed it: not shown as restored.
    stuck('r-f', 'restoring', 'restore_failed', { commits: [{ step: 'restore', at_ms: 1, revisions: { e: 6 } }], agents: [{ node_id: 'e', node_name: 'Entry', step: 'restore', state: 'failed', error: 'bind failed' }],
      waiting: [{ node_id: 'e', error: 'Entry rejected the restore (revision 6): bind failed' }] }),
    stuck('r-o', 'restoring', 'restore_overdue', { commits: [{ step: 'restore', at_ms: 1, revisions: { e: 6 } }], agents: [{ node_id: 'e', node_name: 'Entry', step: 'restore', state: 'pending', online: false }],
      waiting: [{ node_id: 'e', error: 'Entry: waiting for its agent to apply the restore (revision 6); the server is offline' }] }),
    stuck('r-u', 'finished', 'finished', { unresolved: [{ node_id: 'a1', rule_id: 'r-a1', error: 'rule Web on Tokyo stays disabled; enable it in the server rules' }] }),
  ] };
  const blockedPanel = context.chainsPanel(groups, [blocked], nodes), blockedText = blockedPanel.text();
  translated(blockedPanel, 'blocked refresh');
  assert.ok(blockedText.includes(translate('受阻 · 改向未被全部确认，需要处理')) && blockedText.includes(translate('恢复受阻 · 正在重试')));
  assert.ok(!blockedText.includes('retrying: Entry: too old'), 'the reasons are listed per server instead');
  // The count of a refused restore names the commit it counts (the stop), not the restore.
  assert.ok(blockedText.includes(msg`最近一次提交“${translate('停止规则')}”（${'Entry · Tokyo'}）：控制器已提交；${2}/${2} 台服务器的 Agent 已确认`));
  assert.ok(blockedText.includes(translate('控制器拒绝了部分恢复配置，逐台原因如下；相关配置或 Agent 能力变化时立即重试，否则每 30 秒重试一次。也可以“结束恢复…”，把还没恢复的规则交给人工处理。')) && blockedText.includes(msg`等待：${'Entry: too old'}`));
  assert.ok(blockedText.includes(translate('恢复受阻 · Agent 无法应用恢复配置')) && blockedText.includes(translate('恢复逾期 · Agent 未按时确认')));
  assert.ok(!blockedText.includes(translate('恢复配置已提交，等待 Agent 确认')), 'a rejected or overdue restore is not shown as waiting');
  assert.ok(blockedText.includes(translate('恢复配置已由控制器提交；路径上的 Agent 全部确认之前，转发还没有恢复可用。')) && blockedText.includes(translate('处理办法：按下列原因排除后，Agent 会自动重试；服务器已永久不可用时，吊销并删除它，更新就不再等它；也可以“结束恢复…”，把还没恢复的规则交给人工处理。')));
  assert.ok(blockedText.includes(msg`等待：${'Entry: waiting for its agent to apply the restore (revision 6); the server is offline'}`));
  assert.ok(blockedText.includes(msg`需要人工处理 · ${'a1'}${' · r-a1'}：${'rule Web on Tokyo stays disabled; enable it in the server rules'}`));
  assert.equal(buttons(blockedPanel, translate('取消更新')).length, 0, 'nothing to cancel after the rewire');
  await press(button(blockedPanel, translate('不再等待确认…')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-b/refresh/cancel', method: 'POST', body: undefined });
  // Each restoring refresh can be ended by hand.
  const ends = buttons(blockedPanel, translate('结束恢复…'));
  assert.equal(ends.length, 3, 'every restoring stage offers to end it');
  await press(ends[1]);
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-f/refresh/cancel', method: 'POST', body: undefined });
  // The preview states the interruption and its limit, the servers that must be idle with their
  // sessions of every rule, the new hop, warnings and the rule diff; confirming sends its token,
  // revisions and the chosen limit.
  await press(button(shown, translate('预览更新…')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-e/refresh/plan', method: 'POST', body: {} });
  const preview = dialog.text();
  assert.ok(preview.includes(msg`更新会中断这条转发：先暂停入口及上游规则的新连接，等下列服务器整机没有任何会话（包括其他规则的会话）后停止、改向并重新启用；现有连接保持到自然结束。从确认起最长 ${600} 秒，超时、取消或任一步失败都会恢复原转发。`));
  assert.ok(preview.includes(msg`第 ${2} 层`) && preview.includes(msg`新增 ${'London'}`) && preview.includes(msg`移除 ${'Frankfurt'}`), 'changes are named by server');
  assert.ok(preview.includes('Tokyo') && preview.includes('2 / 1') && preview.includes('london.example:30400') && preview.includes('source lists on London'));
  assert.ok(preview.includes(translate('等待安装 Agent')), 'a server without an agent is not shown as online');
  assert.ok(preview.includes(translate('暂停在最长用时到期时结束；若那时还没改向，新连接会因规则已停止而失败，直到改向完成或恢复原转发。恢复不等待会话结束。')), 'the pause can end first');
  assert.ok(preview.includes('london.example:30400') && preview.includes(msg`${'Tokyo'} · ${'Web'} · 查看更新前后配置`));
  translated(dialog, 'refresh preview');
  field('refresh_timeout').value = '900';
  await send();
  assert.deepEqual(last('/chains/c1/uses/r-e/refresh').body, { token: 'tok-1', expected_revisions: { e: 3, a1: 3, a2: 3, b1: 3, b2: 1 }, timeout_secs: 900 });
  // A conflict shows why and offers no confirmation; an up-to-date use says so.
  refreshPlan = { ...freshPlan(), conflicts: [{ node_id: 'a1', rule_id: 'r-a1', message: 'rule Web on Tokyo no longer routes to Osaka' }] };
  form = null; await context.openChainRefresh(chains[0], chains[0].uses[0]);
  assert.equal(form, null, 'no confirmation while there are conflicts');
  assert.ok(dialog.text().includes('no longer routes to Osaka') && dialog.text().includes(translate('有冲突时不能更新；解决后重新预览。')));
  refreshPlan = { ...freshPlan(), up_to_date: true };
  await context.openChainRefresh(chains[0], chains[0].uses[0]);
  assert.equal(form, null); assert.ok(dialog.text().includes(translate('这条转发已经使用端点组当前的服务器。')));
  translated(dialog, 'up-to-date preview');
  // Cancel asks first; automatic update asks before it is turned on and not before it is turned off.
  await press(button(shown, translate('取消更新')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-f/refresh/cancel', method: 'POST', body: undefined });
  await press(button(shown, translate('取消并保持停止…')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-f/refresh/cancel', method: 'POST', body: { keep_stopped: true } });
  confirmed = false; const before = calls.length;
  await press(button(shown, translate('开启自动更新…')));
  assert.equal(calls.length, before, 'declining the warning changes nothing');
  await press(button(shown, translate('关闭自动更新')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-f/sync', method: 'PUT', body: { auto_sync: false } });
  confirmed = true;
  await press(button(shown, translate('开启自动更新…')));
  assert.deepEqual(calls.at(-1), { path: '/chains/c1/uses/r-e/sync', method: 'PUT', body: { auto_sync: true } });

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
  console.log(`Saved chains (${i18n.getLanguage()}): panel lists ordered members, layers and out-of-date uses; group and chain dialogs send ordered members and layers with balances; Use a saved chain plans, previews and applies with the planned revisions; refresh previews show the interruption and idle servers, confirm with token and revisions, refuse conflicts, cancel or cancel keeping rules stopped, blocked, refused, rejected and overdue restore stages with the commit each count is of, ending a restore and rules left to an operator are shown, auto update asks before turning on and shows a wait apart from failures; New forwarding offers it`);
})().catch(error => { console.error(error); process.exitCode = 1; });
