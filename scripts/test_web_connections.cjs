// Executes the shipped connection views with element stubs and checks what they request and show: the
// rule dialog's live sessions (client, protocol, target or requested destination, next hop, start and
// duration, bytes), "N of M shown", the text filter, the counters with the per-target distribution and
// refusals by reason, the rule's block records, polling while the agent has not answered and its end,
// and the messages for old agents, offline servers, no answer and too many waiting snapshots; then the
// per-server block records with their rule filter; and which views offer the actions. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^function namedCell\(.*$/m) + line(/^function durationText\(.*$/m)
  + between('// Connections: a rule', '// Speed tests: administrators');
// Both rule lists offer the dialog to everyone who can read the rules, not only to editors; the
// By server toolbar opens the server's block records.
const byServer = source.indexOf("actions.append(button(translate('连接…'), () => openRuleConnections(config.node_id, rule), 'table-action'))");
assert.ok(byServer > 0 && byServer < source.indexOf("else if (canWrite()) { actions.append(button(translate('编辑')"), 'By server offers Connections… outside the editor-only actions');
assert.match(source, /if \(rule\) tools\.append\(button\(translate\('连接…'\), \(\) => openRuleConnections\(root\.node_id, rule\), 'table-action'\)\);/);
assert.match(source, /nodeTools\.append\(button\(translate\('拦截记录'\), \(\) => openNodeBlocks\(state\.nodes\.find\(n => n\.id === nodeId\), config\)\)\);/);

class Element {
  constructor(tag = 'div', text = '', className = '') {
    Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', disabled: false, events: {}, hidden: false, isConnected: true });
    this.classList = { toggle() {}, add() {}, remove() {}, contains: () => false };
  }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);
const rows = root => root.all().filter(n => n.tag === 'tr').map(row => row.children.map(cell => cell.text().trim().replace(/\s+/g, ' ')));
const headers = root => root.all().filter(n => n.tag === 'th').map(n => n.textContent);
const tables = root => root.all().filter(n => n.tag === 'table');

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };

let calls = [], replies = [], dialog = null, title = null, timers = [];
const context = {
  ...i18n, Date, Promise, Map, encodeURIComponent,
  setTimeout: (resolve, ms) => { timers.push({ resolve, ms }); return 0; },
  state: { actor: { id: 'u1', role: 'viewer' }, nodes: [{ id: 'n1', name: 'Tokyo' }, { id: 'n2', name: 'Osaka' }] },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET' });
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    assert.ok(reply !== undefined, `unexpected request ${options.method || 'GET'} ${path}`);
    return JSON.parse(JSON.stringify(reply));
  },
  el: (tag, text, className) => new Element(tag, text, className),
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  table: (head, body) => { const n = new Element('table'); n.append(...head.map(h => new Element('th', h))); for (const row of body) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  timestamp: n => `@${n}`,
  modal(heading, body) { title = heading; dialog = body; },
};
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { openRuleConnections, openNodeBlocks, connectionsReason });', context);
const settle = async () => { for (let i = 0; i < 5; i += 1) await new Promise(resolve => setImmediate(resolve)); };
// A dialog that waits forever must not pass by leaving nothing to run.
let finished = false;
process.on('exit', code => { if (!code && !finished) { console.error('the test stopped before its end'); process.exitCode = 1; } });
const fail = (status, error) => Object.assign(new Error(error), { detail: { error } });

const now = 1_800_000_000_000;
const counts = (attempts, connected, extra = {}) => ({ attempts, connected, timeout: 0, refused: 0, dns: 0, closed: 0, other: 0, connect_us: connected * 1500, ...extra });
const counters = (refused = []) => ({ inbound: counts(4, 3, { closed: 1 }), targets: [{ target_index: 0, target_address: '10.0.0.1:443', counts: counts(6, 3, { timeout: 2, refused: 1 }) }, { target_index: 1, target_address: 'osaka.example:8443', via: { node_id: 'n2', rule_id: 'hop-1' }, counts: counts(1, 1, { connect_us: 87 }) }], refused });
const sessions = [
  { id: 2, protocol: 'tcp', client: '203.0.113.7:50001', started_ms: now - 125_000, target_index: 1, target: 'osaka.example:8443', remote: '198.51.100.9:8443', via: { node_id: 'n2', rule_id: 'hop-1' }, upload_bytes: 2048, download_bytes: 5 * 1024 * 1024 },
  { id: 1, protocol: 'udp', udp: true, client: '[2001:db8::5]:4000', started_ms: now - 4_000, target_index: 0, target: '10.0.0.1:443', remote: '10.0.0.1:443', upload_bytes: 0, download_bytes: 300 },
];
const rule = { id: 'r1', name: 'Web' };
const blocks = (supported, list = []) => ({ supported, blocks: list });
const record = { rule_id: 'r1', protocol: 'tcp', source: '192.0.2.4', reason: 'source_denied', detail: 'matched deny 192.0.2.0/24', first_ms: now - 50_000, last_ms: now - 2_000, count: 3 };
const view = (state, extra = {}) => ({ state, totals: { tcp: 0, udp: 0 }, sessions: [], truncated: false, counters: counters(), ...extra });

(async () => {
  // Asked: the agent has not answered yet, so the dialog says so and asks again after a second.
  replies = [view('pending'), blocks(true, [record])];
  const done = context.openRuleConnections('n1', rule); await settle();
  assert.equal(title, msg`连接 · ${'Web'}`);
  assert.deepEqual(calls.map(c => c.path), ['/nodes/n1/rules/r1/connections', '/nodes/n1/blocks?rule_id=r1&limit=200']);
  assert.ok(dialog.text().includes(translate('正在等待服务器回报当前连接…')));
  assert.ok(dialog.text().includes(translate('按原因统计的拒绝次数在服务器回报当前连接后显示。')));
  assert.deepEqual(timers.map(t => t.ms), [1000]);
  translated(dialog, 'pending dialog');
  // The block records of the rule: newest change, first seen, source, reason with its detail, count.
  const blockTable = tables(dialog).at(-1);
  assert.deepEqual(headers(blockTable), [translate('最近一次'), translate('来源'), translate('协议'), translate('原因 / 详情'), translate('次数')]);
  assert.deepEqual(rows(blockTable), [[`@${now - 2_000} ${msg`首次 ${`@${now - 50_000}`}`}`, '192.0.2.4', 'TCP', `${translate('来源在拒绝列表')} matched deny 192.0.2.0/24`, '3']]);

  // Answered: two sessions out of 205, newest first, then every 3 seconds while the dialog is open.
  replies = [view('ready', { taken_at_ms: now, totals: { tcp: 200, udp: 5 }, sessions, truncated: true, counters: counters([{ reason: 'source_denied', count: 3 }, { reason: 'connection_limit', count: 2 }]) }), blocks(true, [record])];
  timers.shift().resolve(); await settle();
  assert.deepEqual(timers.map(t => t.ms), [3000]);
  const text = dialog.text();
  translated(dialog, 'ready dialog');
  assert.ok(text.includes(msg`服务器于 ${`@${now}`} 回报`), text);
  assert.ok(text.includes(msg`TCP 连接 ${200} · UDP 会话 ${5}`) && text.includes(msg`显示最新的 ${2} 个，共 ${205} 个`), 'totals and N of M shown');
  const sessionTable = tables(dialog)[0];
  assert.deepEqual(headers(sessionTable), [translate('客户端'), translate('协议'), translate('目标 / 真实目的地'), translate('下一跳'), translate('开始 / 时长'), translate('上传'), translate('下载')]);
  assert.deepEqual(rows(sessionTable), [
    ['203.0.113.7:50001', 'TCP', 'osaka.example:8443 198.51.100.9:8443', 'Osaka hop-1', `@${now - 125_000} ${msg`${2} 分钟`}`, '2.00 KiB', '5.00 MiB'],
    ['[2001:db8::5]:4000', 'UDP', '10.0.0.1:443', '—', `@${now - 4_000} ${msg`${4} 秒`}`, '0 B', '300 B'],
  ]);
  // Counters: inbound setup, each target with its share of successful connects and failures by cause.
  const counterTable = tables(dialog)[1];
  assert.deepEqual(rows(counterTable), [
    [`${translate('已接受的连接')} ${translate('入站建立，含 PROXY 头、TLS 和 WebSocket 握手')}`, '—', '4', '3', '—', `${translate('对端断开')} 1`, '1.5 ms'],
    [`${msg`目标 ${1}`} 10.0.0.1:443`, '—', '6', '3', '75%', `${translate('超时')} 2 · ${translate('被拒绝')} 1`, '1.5 ms'],
    [`${msg`目标 ${2}`} osaka.example:8443`, 'Osaka hop-1', '1', '1', '25%', '0', '87 µs'],
  ]);
  assert.ok(text.includes(msg`拒绝 ${5} 次：${`${translate('来源在拒绝列表')} 3 · ${translate('达到连接数上限')} 2`}`), text);
  // The filter narrows the rows it shows and says how many match.
  const search = dialog.all().find(n => n.tag === 'input');
  search.value = 'osaka'; await search.fire('input');
  assert.equal(rows(tables(dialog)[0]).length, 1);
  assert.ok(dialog.text().includes(msg`筛选后 ${1} 个`));
  search.value = '2001:DB8'; await search.fire('input');
  assert.deepEqual(rows(tables(dialog)[0]).map(r => r[0]), ['[2001:db8::5]:4000']);
  search.value = 'nothing'; await search.fire('input');
  assert.ok(!tables(dialog).some(t => headers(t).includes(translate('客户端'))) && dialog.text().includes(translate('没有符合条件的连接。')));
  search.value = '';
  // While the agent takes a new snapshot, the last one stays with its time.
  calls = []; replies = [view('pending', { taken_at_ms: now, totals: { tcp: 200, udp: 5 }, sessions, truncated: true, counters: counters() }), blocks(true)];
  timers.shift().resolve(); await settle();
  assert.ok(dialog.text().includes(msg`下面是 ${`@${now}`} 的数据，正在刷新…`) && rows(tables(dialog)[0]).length === 2);
  assert.deepEqual(timers.map(t => t.ms), [1000]);
  replies = [view('ready', { taken_at_ms: now + 500, totals: { tcp: 0, udp: 0 } }), blocks(true)];
  timers.shift().resolve(); await settle();
  assert.deepEqual(timers.map(t => t.ms), [3000]);
  // Refresh while polling loads once more without starting a second polling loop.
  calls = []; replies = [view('ready', { taken_at_ms: now + 1000, totals: { tcp: 0, udp: 0 } }), blocks(true)];
  const again = buttons(dialog, translate('刷新'))[0].action(); await settle();
  assert.equal(calls.length, 2); assert.deepEqual(timers.map(t => t.ms), [3000]);
  assert.ok(dialog.text().includes(msg`服务器于 ${`@${now + 1000}`} 回报`));
  await again;
  // Closing the dialog ends the polling: the next wait finds it gone and asks nothing more.
  calls = []; replies = [view('ready', { taken_at_ms: now + 3000, totals: { tcp: 0, udp: 0 } }), blocks(true)];
  timers.shift().resolve(); await settle();
  assert.equal(calls.length, 2); assert.deepEqual(timers.map(t => t.ms), [3000]);
  dialog.isConnected = false; calls = [];
  timers.shift().resolve(); await done;
  assert.equal(calls.length, 0, 'no request after the dialog closed');

  // A proxy rule: the requested destination is what the client asked for; the configured target is absent.
  replies = [view('ready', { taken_at_ms: now, totals: { tcp: 2, udp: 0 }, sessions: [{ id: 9, protocol: 'socks5', client: '127.0.0.1:41000', started_ms: now, destination: 'example.com:443', remote: '93.184.216.34:443', upload_bytes: 10, download_bytes: 20 }, { id: 8, protocol: 'gateway', client: '127.0.0.1:41001', started_ms: now, destination: 'example.net:443', target_index: 0, target: 'upstream.example:1080', remote: '192.0.2.80:1080', upload_bytes: 0, download_bytes: 0 }], counters: { targets: [], refused: [] } }), blocks(true, [{ ...record, protocol: 'socks5', reason: 'destination_denied', detail: 'example.org:25 is outside the destination rules', count: 1, first_ms: now, last_ms: now }])];
  const proxy = context.openRuleConnections('n1', { id: 'socks', name: 'Proxy' }); await settle();
  assert.deepEqual(rows(tables(dialog)[0]).map(r => r.slice(0, 3)), [['127.0.0.1:41000', 'SOCKS5', 'example.com:443 93.184.216.34:443'], ['127.0.0.1:41001', translate('协议网关'), 'example.net:443 upstream.example:1080 → 192.0.2.80:1080']]);
  assert.ok(dialog.text().includes(translate('Agent 启动以来这条规则还没有建立过连接。')) && dialog.text().includes(translate('Agent 启动以来没有拒绝过这条规则的连接。')));
  assert.deepEqual(rows(tables(dialog).at(-1))[0].slice(2), ['SOCKS5', `${translate('目的地址不在允许范围')} example.org:25 is outside the destination rules`, '1']);
  translated(dialog, 'proxy dialog');
  dialog.isConnected = false; timers.shift().resolve(); await proxy;

  // States that stop polling: an old agent, an offline server and no answer, each with its message.
  for (const [state, message] of [['unsupported', '这台服务器的 Agent 版本过旧，不记录当前连接和拦截记录；请先升级 Agent。下方的累计统计仍然有效。'], ['offline', '服务器离线，无法获取当前连接。'], ['no_answer', '服务器 30 秒内没有回报当前连接，它可能正忙或刚断开；请稍后点“刷新”重试。']]) {
    calls = []; timers = [];
    replies = [view(state), blocks(state !== 'unsupported')];
    await context.openRuleConnections('n1', rule);
    assert.equal(calls.length, 2); assert.equal(timers.length, 0, `${state} stops polling`);
    const status = dialog.all().find(n => n.textContent === translate(message));
    assert.ok(status && status.className === 'workflow-callout', `${state} message`);
    assert.equal(rows(tables(dialog)[0]).length, 3, `${state} still shows the counters`);
    // Without a snapshot there are no totals to show: zeros would be wrong.
    assert.ok(!dialog.text().includes(msg`TCP 连接 ${0} · UDP 会话 ${0}`), `${state} shows no totals`);
    if (state === 'unsupported') assert.ok(dialog.text().includes(translate('这台服务器的 Agent 升级后才有拦截记录。')) && !dialog.text().includes(translate('按原因统计的拒绝次数在服务器回报当前连接后显示。')));
    translated(dialog, `${state} dialog`);
    // Refresh asks again and follows a new request until it is answered.
    if (state === 'no_answer') {
      calls = []; replies = [view('pending'), blocks(true)];
      const refresh = buttons(dialog, translate('刷新'))[0].action(); await settle();
      assert.equal(calls.length, 2); assert.deepEqual(timers.map(t => t.ms), [1000]);
      replies = [view('no_answer'), blocks(true)];
      timers.shift().resolve(); await refresh;
      assert.equal(timers.length, 0);
    }
  }
  // Too many snapshots waiting for the server: said in the panel's language, polling stops.
  calls = []; timers = [];
  replies = [fail(429, 'too many connection snapshots are waiting for this server; try again in a few seconds'), blocks(true)];
  await context.openRuleConnections('n1', rule);
  assert.equal(dialog.all().find(n => n.className === 'error').textContent, translate('这台服务器有太多连接快照在等待回报；请几秒后再试'));
  assert.equal(timers.length, 0);
  replies = [fail(404, 'rule not found'), blocks(true)];
  await buttons(dialog, translate('刷新'))[0].action();
  assert.equal(dialog.all().find(n => n.className === 'error').textContent, 'rule not found');

  // The per-server view: all rules first, with a rule column; the filter asks for one rule's records.
  calls = [];
  const config = { rules: [{ id: 'r1', name: 'Web' }, { id: 'socks', name: 'Proxy' }] };
  replies = [blocks(true, [record, { ...record, rule_id: 'socks', reason: 'auth_failed', detail: '', source: '198.51.100.2', count: 1, first_ms: now, last_ms: now }])];
  await context.openNodeBlocks({ id: 'n1', name: 'Tokyo' }, config);
  assert.equal(title, msg`拦截记录 · ${'Tokyo'}`);
  assert.deepEqual(calls.map(c => c.path), ['/nodes/n1/blocks?limit=1000']);
  assert.deepEqual(headers(tables(dialog)[0]), [translate('最近一次'), translate('来源'), translate('规则'), translate('协议'), translate('原因 / 详情'), translate('次数')]);
  assert.deepEqual(rows(tables(dialog)[0]).map(r => r.slice(1)), [['192.0.2.4', 'Web', 'TCP', `${translate('来源在拒绝列表')} matched deny 192.0.2.0/24`, '3'], ['198.51.100.2', 'Proxy', 'TCP', translate('代理认证失败'), '1']]);
  translated(dialog, 'server blocks');
  const filter = dialog.all().find(n => n.tag === 'select');
  assert.deepEqual(filter.children.map(o => [o.value, o.textContent]), [['', translate('全部规则')], ['r1', 'Web'], ['socks', 'Proxy']]);
  calls = []; replies = [blocks(true)];
  filter.value = 'socks'; await filter.fire('change');
  assert.deepEqual(calls.map(c => c.path), ['/nodes/n1/blocks?limit=1000&rule_id=socks']);
  assert.ok(dialog.text().includes(translate('没有拦截记录。')));
  replies = [blocks(false)];
  await context.openNodeBlocks({ id: 'n3', name: 'Legacy' }, { rules: [] });
  assert.ok(dialog.text().includes(translate('这台服务器的 Agent 版本过旧，不记录拦截记录；请先升级 Agent。')));
  translated(dialog, 'old agent blocks');
  assert.equal(replies.length, 0);
  finished = true;
  console.log(`Connections panel (${i18n.getLanguage()}): sessions, N of M shown, filter, counters and distribution, refusals, block records, polling and its end, old agents, offline, no answer, 429 and per-server records passed`);
})().catch(error => { console.error(error); process.exit(1); });
