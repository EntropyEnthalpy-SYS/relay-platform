// Executes the shipped speed-test controls with form-control stubs and checks what they send and show:
// the Diagnostics section's server ↔ Cloudflare and server ↔ server forms with their checks, live
// progress, cancelling and the history; the path speed test dialog with its path, the note that test
// traffic bypasses limits and metering, the limits along the path, per-segment results and the slowest
// segment; which rules offer the action; and the controller's refusals in the panel's language.
// Not a browser test.
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
  + between('const rateLanes = localize(', 'function burstState(')
  + between('// Speed tests: administrators', 'async function renderAudit(');
// The panel wires the section into Diagnostics and the action into both rule lists.
assert.match(source, /speedTestPanel\(nodes, speedTests\)/);
assert.equal(source.match(/canSpeedTestRule\(rule\)\) (actions|tools)\.append\(button\(translate\('路径测速…'\)/g)?.length, 2);
assert.match(source, /rateLimitReason\(result\.error\) \|\| speedTestReason\(result\.error\)/);

class Element {
  constructor(tag = 'div', text = '', className = '') {
    Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {}, hidden: false, isConnected: true });
    const self = this;
    this.classList = { toggle(name, on) { if (name === 'hidden') self.hidden = on; }, add() {}, remove() {}, contains: name => name === 'hidden' && self.hidden };
  }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().filter(n => !n.hidden && !n.parentElement?.hidden).map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };

const now = Date.now();
const nodes = [
  { id: 'n1', name: 'Tokyo', speed_test_support: true, last_seen_ms: now },
  { id: 'n2', name: 'Osaka', speed_test_support: true, last_seen_ms: now },
  { id: 'n3', name: 'Legacy', speed_test_support: false, last_seen_ms: now },
];
const result = (direction, average) => ({ direction, bytes: 117_500_000, measured_ms: 10_000, average_bps: average, peak_bps: average + 6_000_000, streams: 4 });
const job = (state, extra = {}) => ({ id: 'j1', kind: 'server', mode: 'cloudflare', tenant_id: 'default', started_by: 'admin', started_by_name: 'admin', params: { direction: 'both', duration_secs: 10, streams: 4 }, node_ids: ['n1'], segments: [{ from_node_id: 'n1', from_name: 'Tokyo', address: 'speed.cloudflare.com', state, results: state === 'finished' ? [result('upload', 94_000_000), result('download', 812_400_000)] : [] }], state, step: 0, created_at_ms: now, progress: null, slowest_segment: null, metered: false, ...extra });
let calls = [], replies = [], dialog = null, title = null, notified = null;
const context = {
  ...i18n, Date, Promise, encodeURIComponent,
  setTimeout: resolve => { resolve(); return 0; },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled).map(c => [c.name, c.value])); } get(key) { return this.values.get(key) ?? null; } },
  state: { actor: { id: 'admin', role: 'system_admin' } },
  canWrite: () => context.state.actor.role !== 'viewer',
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    assert.ok(reply !== undefined, `unexpected request ${options.method || 'GET'} ${path}`);
    return JSON.parse(JSON.stringify(reply));
  },
  el: (tag, text, className) => new Element(tag, text, className),
  panel(heading, description, action) { const n = new Element('section'); n.append(new Element('h2', heading), new Element('p', description)); if (action) n.append(action); return n; },
  field(parent, name, label, value = '', type = 'text', required = true) { const wrap = new Element('label', label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); wrap.append(input); parent.append(wrap); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); for (const row of rows) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  timestamp: n => `@${n}`, online: node => !!node.last_seen_ms,
  modal(heading, body) { title = heading; dialog = body; }, notify(message) { notified = message; },
};
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { speedTestPanel, openPathSpeedTest, canSpeedTestRule, speedTestReason, bitRate });', context);
const input = (root, name) => root.all().find(n => n.name === name);
const shown = (root, name) => !input(root, name).disabled && !input(root, name).parentElement.hidden;
const submit = root => root.all().find(n => n.tag === 'form').onsubmit({ preventDefault() {} });
const errorText = root => root.all().find(n => n.className === 'error').textContent;
const settle = () => new Promise(resolve => setImmediate(resolve));

(async () => {
  assert.equal(context.bitRate(812_400_000), '812.4 Mbit/s');
  assert.equal(context.bitRate(1_250_000_000), '1.25 Gbit/s');
  assert.equal(context.bitRate(64_000), '64 kbit/s');
  // Cloudflare stops serving a fast server partway: the result says so, and a refusal before any data says to wait.
  assert.ok(context.speedResultLines({ ...result('download', 2_625_000_000), limited: true }).includes(translate('测速服务在测试中途限制了请求量，结果只包含限制之前测到的部分。')));
  assert.ok(!context.speedResultLines(result('download', 2_625_000_000)).includes(translate('测速服务在测试中途限制了请求量，结果只包含限制之前测到的部分。')));
  assert.equal(context.speedTestReason('speed.cloudflare.com is limiting tests from this server (HTTP 429); try again in a few minutes'), translate('speed.cloudflare.com 正在限制这台服务器的测速请求（HTTP 429），请几分钟后再试'));
  assert.ok(context.speedResultLines({ ...result('download', 0), failed_streams: 2, errors: ['speed.cloudflare.com is limiting tests from this server (HTTP 429); try again in a few minutes'] }).includes(msg`${2} 个流失败：${translate('speed.cloudflare.com 正在限制这台服务器的测速请求（HTTP 429），请几分钟后再试')}`));

  // The Diagnostics section: Cloudflare first, with only the fixed public endpoints.
  replies = [];
  const section = context.speedTestPanel(nodes, []);
  translated(section, 'speed test section');
  assert.equal(input(section, 'mode').value, 'cloudflare');
  assert.ok(!shown(section, 'peer_node_id') && !shown(section, 'port') && shown(section, 'duration_secs') && !shown(section, 'megabytes'));
  assert.ok(section.text().includes('speed.cloudflare.com'));
  assert.ok(section.text().includes(translate('测速流量不经过任何规则：不受规则和服务器的限速，不计入流量账本、规则配额和共享额度。结果反映服务器之间或到公共测速服务的线路能力，不等于经过规则、限速后的业务速度。')));
  assert.ok(section.text().includes(msg`${'Legacy'}（Agent 不支持测速）`), 'servers whose agent cannot test are marked');
  assert.ok(section.text().includes(translate('还没有测速记录。')));
  // Bounds are checked before anything is sent.
  for (const [name, value, message] of [['duration_secs', '61', '时长必须是 5 到 60 之间的整数秒'], ['duration_secs', '4.5', '时长必须是 5 到 60 之间的整数秒'], ['streams', '9', '并行流数必须是 1 到 8 之间的整数']]) {
    const before = input(section, name).value; input(section, name).value = value;
    await submit(section);
    assert.equal(errorText(section), translate(message)); input(section, name).value = before;
  }
  assert.equal(calls.length, 0);
  // Started: the body carries the mode, server and bounded parameters, then progress, then results.
  const running = job('running', { progress: { segment: 0, direction: 'download', elapsed_ms: 4000, bytes: 50_000_000, current_bps: 120_000_000 } });
  replies = [running, [job('finished')]];
  await submit(section); await settle();
  assert.deepEqual(calls[0], { path: '/speed-tests', method: 'POST', body: { mode: 'cloudflare', node_id: 'n1', direction: 'both', streams: 4, duration_secs: 10 } });
  assert.equal(notified, translate('测速已开始，结果会显示在下方。'));
  assert.deepEqual(calls.map(c => c.path), ['/speed-tests', '/speed-tests']);
  const history = section.text();
  translated(section, 'speed test history');
  assert.ok(history.includes(msg`${'↑'} ${translate('上行')} 平均 ${'94 Mbit/s'} · 峰值（1 秒）${'100 Mbit/s'}`), history);
  assert.ok(history.includes(msg`${'↓'} ${translate('下行')} 平均 ${'812.4 Mbit/s'} · 峰值（1 秒）${'818.4 Mbit/s'}`), history);
  assert.ok(history.includes(msg`测量 ${'112.06 MiB'} / ${'10.0'} 秒 · ${4} 个流`), history);
  assert.ok(history.includes(translate('已完成')) && history.includes(msg`由 ${'admin'} 发起`));

  // Server ↔ server: the peer and the optional port appear and are checked; byte amounts go as bytes.
  calls = [];
  input(section, 'mode').value = 'server'; await input(section, 'mode').fire('change');
  assert.ok(shown(section, 'peer_node_id') && shown(section, 'port'));
  assert.ok(section.text().includes(translate('上行：测速服务器 → 对端服务器；下行：对端服务器 → 测速服务器。测速服务器连接对端的转发地址（按 NAT 端口映射换算），请在对端的防火墙 / 安全组放行该 TCP 端口。连接须带本次测速的随机令牌，测完或超时后端口关闭。')));
  input(section, 'peer_node_id').value = 'n1';
  await submit(section);
  assert.equal(errorText(section), translate('请选择两台不同的服务器'));
  input(section, 'peer_node_id').value = 'n2'; input(section, 'port').value = '80';
  await submit(section);
  assert.equal(errorText(section), translate('端口必须是 1024 到 65535 之间的整数，或留空自动选择'));
  input(section, 'port').value = '29999'; input(section, 'amount').value = 'bytes'; await input(section, 'amount').fire('change');
  assert.ok(!shown(section, 'duration_secs') && shown(section, 'megabytes'));
  input(section, 'megabytes').value = '50'; input(section, 'direction').value = 'upload'; input(section, 'streams').value = '2';
  const pair = job('running', { mode: 'server', params: { direction: 'upload', bytes: 50_000_000, streams: 2 }, node_ids: ['n1', 'n2'], segments: [{ from_node_id: 'n1', from_name: 'Tokyo', to_node_id: 'n2', to_name: 'Osaka', address: 'osaka.example.net:29999', state: 'running', results: [] }] });
  replies = [pair, [pair]];
  // Polling stops while the test is still running once the section is gone.
  const box = section.all().find(n => n.className === 'speed-history');
  const originalApi = context.api;
  context.api = async (...args) => { const answer = await originalApi(...args); if (calls.length >= 2) box.isConnected = false; return answer; };
  await submit(section); await settle();
  assert.deepEqual(calls[0].body, { mode: 'server', node_id: 'n1', direction: 'upload', streams: 2, bytes: 50_000_000, peer_node_id: 'n2', port: 29999 });
  assert.equal(calls.length, 2, 'polling stopped with the section');
  context.api = originalApi;
  assert.ok(section.text().includes(`Tokyo → Osaka`) && section.text().includes(msg`每个方向 ${'47.68 MiB'}`));
  // Cancel stops it on both servers.
  const cancelled = { ...pair, state: 'cancelled', segments: [{ ...pair.segments[0], state: 'cancelled' }] };
  replies = [cancelled, [cancelled]];
  calls = [];
  await buttons(section, translate('取消'))[0].action();
  assert.deepEqual(calls.map(c => [c.method, c.path]), [['DELETE', '/speed-tests/j1'], ['GET', '/speed-tests']]);
  assert.equal(notified, translate('已取消测速，两端服务器会立即停止。'));
  assert.ok(section.text().includes(translate('已取消')) && !buttons(section, translate('取消')).length);

  // The path dialog: path, note, limits along it, then per-segment results and the slowest segment.
  const rule = { id: 'r1', name: 'web', targets: [{ address: '203.0.113.20:30001' }] };
  const plan = {
    node_id: 'n1', rule_id: 'r1', rule_name: 'web', metered: false, reason: null,
    hops: [{ node_id: 'n1', node_name: 'Tokyo', rule_id: 'r1', rule_name: 'web' }, { node_id: 'n2', node_name: 'Osaka', rule_id: 'r2', rule_name: 'web-relay' }, { node_id: 'n4', node_name: 'Seoul', rule_id: 'r3', rule_name: 'web-exit' }],
    segments: [{ from_node_id: 'n1', from_name: 'Tokyo', to_node_id: 'n2', to_name: 'Osaka', rule_id: 'r1', target_address: '203.0.113.20:30001' }, { from_node_id: 'n2', from_name: 'Osaka', to_node_id: 'n4', to_name: 'Seoul', rule_id: 'r2', target_address: '198.51.100.7:30002' }],
    target: { node_id: 'n4', node_name: 'Seoul', rule_id: 'r3', address: '192.0.2.10:443' },
    limits: [{ kind: 'rule', node_id: 'n1', node_name: 'Tokyo', rule_id: 'r1', rule_name: 'web', rate_bytes_per_sec: 125000, quota_bytes: null }, { kind: 'server', node_id: 'n2', node_name: 'Osaka', rate_bytes_per_sec: null, rate_limits: { download_bytes_per_sec: 1250000 } }],
  };
  calls = []; replies = [plan];
  await context.openPathSpeedTest('n1', rule);
  assert.deepEqual(calls[0], { path: '/speed-tests/path?node_id=n1&rule_id=r1', method: 'GET', body: undefined });
  assert.equal(title, msg`路径测速 · ${'web'}`);
  translated(dialog, 'path speed test dialog');
  const shownPath = dialog.text();
  assert.ok(shownPath.includes('Tokyo → Osaka → Seoul → 192.0.2.10:443'), shownPath);
  assert.ok(shownPath.includes(msg`${'Tokyo'} → ${'Osaka'}：测速服务器连接 ${'Osaka'} 时使用与规则目标 ${'203.0.113.20:30001'} 相同的主机，端口为临时测试端口`));
  assert.ok(shownPath.includes(msg`${'Seoul'} → 目标 ${'192.0.2.10:443'}：只测 TCP 连接耗时，不发送数据`));
  assert.ok(shownPath.includes(translate('测速流量不经过任何规则：不受规则和服务器的限速，不计入流量账本、规则配额和共享额度。结果反映服务器之间或到公共测速服务的线路能力，不等于经过规则、限速后的业务速度。')));
  assert.ok(shownPath.includes(`1 Mbit/s · ${translate('不限量')}`) && shownPath.includes(msg`${translate('下载')} ${'10 Mbit/s'}`), shownPath);
  const segment = (from, to, average, state = 'finished') => ({ from_node_id: from[0], from_name: from[1], to_node_id: to[0], to_name: to[1], address: 'x:1', state, results: state === 'finished' ? [{ ...result('upload', average), streams: 2 }] : [] });
  const pathJob = (state, extra) => ({ ...job(state), kind: 'path', mode: 'server', rule: { node_id: 'n1', rule_id: 'r1', name: 'web' }, params: { direction: 'upload', duration_secs: 5, streams: 2 }, target: { node_id: 'n4', node_name: 'Seoul', rule_id: 'r3', address: '192.0.2.10:443', state: 'pending' }, ...extra });
  const first = pathJob('running', { step: 1, progress: { segment: 1, direction: 'upload', elapsed_ms: 3000, bytes: 9_000_000, current_bps: 31_000_000 }, segments: [segment(['n1', 'Tokyo'], ['n2', 'Osaka'], 480_000_000), segment(['n2', 'Osaka'], ['n4', 'Seoul'], 0, 'running')] });
  const done = pathJob('finished', { slowest_segment: 1, segments: [segment(['n1', 'Tokyo'], ['n2', 'Osaka'], 480_000_000), segment(['n2', 'Osaka'], ['n4', 'Seoul'], 37_500_000)], target: { ...first.target, state: 'finished', connect_us: 12_345 } });
  const results = dialog.all().find(n => n.className === 'speed-results');
  let drawnRunning = null;
  replies = [first, done];
  input(dialog, 'direction').value = 'upload'; input(dialog, 'duration_secs').value = '5'; input(dialog, 'streams').value = '2';
  context.setTimeout = resolve => { drawnRunning ??= results.text(); resolve(); return 0; };
  calls = [];
  await submit(dialog);
  assert.equal(errorText(dialog), '');
  assert.deepEqual(calls[0], { path: '/speed-tests/path', method: 'POST', body: { node_id: 'n1', rule_id: 'r1', direction: 'upload', streams: 2, duration_secs: 5 } });
  assert.deepEqual(calls[1], { path: '/speed-tests/j1', method: 'GET', body: undefined });
  assert.ok(drawnRunning.includes(msg`正在测 ${translate('上行')} · ${3} 秒 · 当前 ${'31 Mbit/s'}`), drawnRunning);
  const finished = results.text();
  translated(results, 'path speed test results');
  assert.ok(finished.includes(msg`最慢的一段：${'Osaka → Seoul'}（${'37.5 Mbit/s'}）`), finished);
  assert.ok(finished.includes(msg`${'Seoul'} 到目标 ${'192.0.2.10:443'} 的 TCP 连接耗时 ${'12.3'} 毫秒`), finished);
  assert.ok(finished.includes('1. Tokyo → Osaka') && finished.includes('2. Osaka → Seoul'));
  // Refused at the controller: the reason in the panel's language, and the dialog says why.
  replies = [new Error(context.speedTestReason('wait 42 s before starting another speed test'))];
  await submit(dialog);
  assert.equal(errorText(dialog), msg`请 ${'42'} 秒后再开始下一次测速`);
  replies = [{ ...plan, reason: 'server Osaka is already running a speed test' }];
  await context.openPathSpeedTest('n1', rule);
  translated(dialog, 'blocked path dialog');
  assert.ok(dialog.text().includes(msg`服务器 ${'Osaka'} 正在测速；请等它结束后再试`));
  assert.ok(!dialog.all().some(n => n.tag === 'form'), 'no start while blocked');

  // Which rules offer the action, and for whom.
  assert.ok(context.canSpeedTestRule(rule));
  for (const other of [{ ...rule, targets: [] }, { ...rule, protocol_gateway: {} }, { ...rule, reverse_tunnel: 't1' }, { ...rule, id: 'fed-g1-1' }]) assert.ok(!context.canSpeedTestRule(other), JSON.stringify(other));
  context.state.actor = { id: 'v', role: 'viewer' };
  assert.ok(!context.canSpeedTestRule(rule));
  context.state.actor = { id: 'admin', role: 'system_admin' };

  // The controller's English refusals in the panel's language; unknown ones stay as sent.
  for (const [sent, shown] of [
    ['the agent on server Tokyo is too old for speed tests; upgrade it first', msg`服务器 ${'Tokyo'} 的 Agent 版本过旧，不支持测速；请先升级 Agent`],
    ['server Osaka has not connected to the panel yet; speed tests need its agent to report in first', msg`服务器 ${'Osaka'} 尚未连接面板；它的 Agent 回报后才能测速`],
    ['server Osaka is offline', msg`服务器 ${'Osaka'} 离线，无法测速`],
    ['server Osaka has no forwarding host; set the forwarding address and port range in its settings first', msg`服务器 ${'Osaka'} 没有转发地址；请先在它的转发设置中填写地址和端口范围`],
    ['port 29999 on server Osaka is used by a rule, reverse tunnel or share; choose another port', msg`服务器 ${'Osaka'} 的端口 ${'29999'} 已被规则、反向隧道或共享占用；请换一个端口`],
    ['this rule is a proxy service or protocol gateway with no fixed target; there is no path to test', translate('这条规则是代理服务或协议网关，没有固定目标，没有可测的路径')],
    ['this speed test has already ended', translate('这次测速已经结束')],
  ]) assert.equal(context.speedTestReason(sent), shown);
  assert.equal(context.speedTestReason('configuration changed; reload before saving'), null);
  if (english) assert.equal(context.speedTestReason('server Osaka is offline'), 'Server Osaka is offline and cannot run a speed test');
  console.log(`Speed tests (${i18n.getLanguage()}): Diagnostics section forms, checks, progress, history and cancel, path dialog with limits, segments and slowest segment, rule actions and refusals passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
