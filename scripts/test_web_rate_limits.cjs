// Executes the shipped speed-limit controls with form-control stubs and checks what they send and
// show: the rule editor's combined / separate / combined-and-separate modes and bursts, the server
// limit dialog, the user total dialog with its upload and download shares, the rules table cell with
// burst credit, the cross-panel share summary, and the refusals for agents too old, in the panel's
// language. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^function mbit\(.*$/m) + line(/^function userRateText\(.*$/m)
  + between('function sectionVisible(', 'function websocketEditor(')
  + between('// Quota and speed limits of a rule', 'async function saveRules(')
  + between('function gatewayConfig(', 'const shadowsocksMethods')
  + between('async function editUserRate(', 'async function renderAccount(')
  + between('const fedStates = localize(', 'function fedUsage(');

class Element {
  constructor(tag = 'div', text = '', className = '') {
    Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {}, hidden: false });
    const self = this;
    this.classList = { toggle(name, on) { if (name === 'hidden') self.hidden = on; }, add() {}, remove() {}, contains: name => name === 'hidden' && self.hidden };
  }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().filter(n => !n.hidden).map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };
const exactly = key => new RegExp(translate(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

const forward = { id: 'r1', tenant_id: 't', owner_id: 'owner', name: 'web', listen: '0.0.0.0:20000', protocol: 'tcp', targets: [{ address: '192.0.2.10:443', weight: 1 }], enabled: true, meter_epoch: 'e1', quota_bytes: null, rate_bytes_per_sec: null, expires_at_ms: null };
let form, handler, calls = [], saved = null, notified = null, dialog = null, view = null;
const context = {
  ...i18n, ...helpers.loadWorkflows(),
  TextEncoder, Uint8Array, Uint32Array, btoa, crypto: require('node:crypto').webcrypto,
  document: { createTextNode: text => text },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  forwardingPathView: () => ({ box: new Element(), update() {} }), featureOn: () => false, canWrite: () => true,
  state: { config: { node_id: 'n1', revision: 3, rules: [forward] }, nodes: [{ id: 'n1', name: 'Tokyo', tenant_id: 't', rate_limit_support: false, stats: {} }], actor: { id: 'owner', role: 'system_admin' } },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    if (path === '/nodes') return context.state.nodes;
    if (path === '/firewall/sets') return [];
    if (path.startsWith('/users/') && !options.method) return JSON.parse(JSON.stringify(view));
    return { configs: [], nodes: [] };
  },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, label, value = '', type = 'text', required = true) { const wrap = new Element('label', label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); wrap.append(input); parent.append(wrap); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  checkbox(parent, name, text) { const wrap = new Element('label', text), input = new Element('input'); Object.assign(input, { name, type: 'checkbox' }); wrap.prepend(input); parent.append(wrap); return input; },
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  namedCell: (name, detail) => { const n = new Element('div'); n.append(new Element('strong', name), new Element('div', detail)); return n; },
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); for (const row of rows) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  healthEditor: (_form, spec) => () => spec,
  multipathEditor: () => ({ mode: {}, read: () => ({}) }),
  targetEditor: (_form, targets) => { const read = () => targets; read.multipathPaths = () => []; read.preview = () => targets; read.onchange = () => {}; return read; },
  websocketEditor: (_name, spec) => ({ box: new Element(), read: () => spec }),
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal: (_title, body) => { dialog = body; }, notify(message) { notified = message; },
  saveRules: async rules => { saved = rules.find(r => r.id === forward.id); }, renderRules: async () => {}, renderUsers: async () => {},
  $: () => ({ close() {} }),
  number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
};
for (const helper of ['shadowsocksEditor', 'socks5Editor', 'httpConnectEditor', 'http2ConnectEditor']) context[helper] = spec => ({ box: new Element(), read: () => spec ?? null, enabled: () => !!spec, onchange() {}, setEnabled() {} });
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { editRule, editNodeRate, editUserRate, limitCell, fedLimits, rateLimitReason, rateText });', context);
const send = () => handler(new context.FormData(form));
const input = name => form.all().find(n => n.name === name);
const lastWrite = () => calls.filter(call => call.method !== 'GET').at(-1);
const plain = value => JSON.parse(JSON.stringify(value));
async function mode(value) { input('rate_mode').value = value; await input('rate_mode').fire('change'); }
const shown = name => !input(name).disabled && !input(name).parentElement.hidden;

(async () => {
  // The rule editor: a rule with only a combined limit keeps exactly the fields it had.
  await context.editRule({ ...forward, rate_bytes_per_sec: 125000 });
  assert.equal(input('rate_mode').value, 'combined');
  assert.ok(shown('rate_bytes_per_sec') && !shown('rate_upload') && !shown('rate_download') && !shown('burst_upload_rate'));
  await send();
  assert.equal(saved.rate_bytes_per_sec, 125000);
  assert.ok(!('rate_limits' in saved), 'no new field for a combined limit');

  // Upload only: no combined limit, and the hidden inputs send nothing.
  await mode('separate');
  assert.ok(!shown('rate_bytes_per_sec') && shown('rate_upload') && shown('rate_download') && shown('burst_download_secs') && !shown('burst_combined_rate'));
  input('rate_upload').value = '250000';
  await send();
  assert.equal(saved.rate_bytes_per_sec, null);
  assert.deepEqual(plain(saved.rate_limits), { upload_bytes_per_sec: 250000 });

  // Every mix at once, with a burst on the combined and on the download limit.
  await mode('both');
  Object.assign(input('rate_bytes_per_sec'), { value: '1000000' }); input('rate_download').value = '600000';
  input('burst_combined_rate').value = '4000000'; input('burst_combined_secs').value = '10';
  input('burst_download_rate').value = '900000'; input('burst_download_secs').value = '300';
  await send();
  assert.equal(saved.rate_bytes_per_sec, 1000000);
  const mixed = { upload_bytes_per_sec: 250000, download_bytes_per_sec: 600000, burst: { bytes_per_sec: 4000000, secs: 10 }, download_burst: { bytes_per_sec: 900000, secs: 300 } };
  assert.deepEqual(plain(saved.rate_limits), mixed);

  // Bursts are checked before anything is saved.
  saved = null;
  input('burst_download_secs').value = '';
  await assert.rejects(send(), exactly('突发速率和突发时长要同时填写，或都留空'));
  input('burst_download_secs').value = '300'; input('burst_download_rate').value = '600000';
  await assert.rejects(send(), exactly('突发速率必须高于对应的限速'));
  input('burst_download_rate').value = '900000'; input('burst_download_secs').value = '86401';
  await assert.rejects(send(), exactly('突发时长必须是 1 到 86400 之间的整数秒'));
  input('burst_download_secs').value = '300'; input('rate_upload').value = ''; input('burst_upload_rate').value = '500000'; input('burst_upload_secs').value = '5';
  await assert.rejects(send(), exactly('设置突发前，请先填写对应的限速'));
  input('burst_upload_rate').value = ''; input('burst_upload_secs').value = ''; input('rate_download').value = '1.5';
  await assert.rejects(send(), exactly('速率必须是正整数 bytes/s，留空不限。'));
  assert.equal(saved, null, 'nothing is saved while the limits are invalid');

  // Editing a rule fills each limit and burst, and an unchanged edit keeps them.
  const limited = { ...forward, rate_bytes_per_sec: 1000000, rate_limits: mixed };
  await context.editRule(limited);
  assert.equal(input('rate_mode').value, 'both');
  assert.deepEqual(['rate_bytes_per_sec', 'rate_upload', 'rate_download', 'burst_combined_rate', 'burst_combined_secs', 'burst_download_rate', 'burst_download_secs'].map(n => input(n).value), ['1000000', '250000', '600000', '4000000', '10', '900000', '300']);
  await send();
  assert.deepEqual(plain(saved.rate_limits), mixed);
  // Back to a combined limit: the other limits and bursts go.
  await mode('combined');
  input('burst_combined_rate').value = ''; input('burst_combined_secs').value = '';
  await send();
  assert.equal(saved.rate_bytes_per_sec, 1000000);
  assert.ok(!('rate_limits' in saved));

  // The rules table: a combined limit reads as before; other limits and burst credit are listed.
  assert.equal(context.limitCell({ ...forward, rate_bytes_per_sec: 1024 }, null), `${translate('不限量')} / 1.00 KiB/s`);
  assert.equal(context.limitCell(forward, null), `${translate('不限量')} / ${translate('不限速')}`);
  const node = { id: 'n1', stats: { rate_limits: { bursts: [{ rule_id: 'r1', direction: 'download', credit_bytes: 45000000, capacity_bytes: 90000000 }, { direction: 'combined', credit_bytes: 0, capacity_bytes: 10 }] } } };
  const cell = context.limitCell({ ...forward, rate_limits: { download_bytes_per_sec: 1048576, download_burst: { bytes_per_sec: 2097152, secs: 300 } } }, node);
  assert.ok(cell.text().includes(msg`${msg`${translate('下载')} ${'1.00 MiB/s'}`}（突发 ${'2.00 MiB/s'} · ${300} 秒）`), cell.text());
  assert.ok(cell.text().includes(msg`${translate('下载')}突发额度 ${50}%`) && !cell.text().includes(msg`${translate('合计')}突发额度 ${0}%`), 'only this rule\'s credit');
  translated(cell, 'rules table cell');

  // Server limit: an agent that has not reported support is explained; the body carries every limit.
  context.editNodeRate({ node_id: 'n1', revision: 7, rules: [forward], rate_bytes_per_sec: 1250000, rate_limits: null });
  translated(form, 'server limit dialog');
  assert.ok(form.text().includes(translate('这台服务器的 Agent 尚未报告支持分别限制上传/下载或突发限速；只有上下行合计可以发布，其他方式会被拒绝。请先升级 Agent。')));
  assert.equal(input('mbit').value, '10');
  await mode('both');
  input('mbit').value = '100'; input('rate_upload').value = '20'; input('rate_download').value = '50';
  input('burst_download_rate').value = '80'; input('burst_download_secs').value = '300';
  await send();
  assert.deepEqual(lastWrite(), { path: '/nodes/n1/config', method: 'PUT', body: { expected_revision: 7, rules: [forward], rate_bytes_per_sec: 12500000, rate_limits: { upload_bytes_per_sec: 2500000, download_bytes_per_sec: 6250000, download_burst: { bytes_per_sec: 10000000, secs: 300 } } } });
  assert.equal(notified, msg`已发布节点总限速 ${context.rateText(12500000, lastWrite().body.rate_limits)}。`);
  input('mbit').value = '9000000';
  await assert.rejects(send(), exactly('请输入 0.008 到 8,000,000 之间的 Mbit/s'));
  // Combined only clears the others, with null; nothing at all removes the limit.
  context.state.nodes[0].rate_limit_support = true;
  context.editNodeRate({ node_id: 'n1', revision: 8, rules: [], rate_bytes_per_sec: 12500000, rate_limits: { upload_bytes_per_sec: 2500000, burst: { bytes_per_sec: 25000000, secs: 60 } } });
  assert.ok(!form.text().includes(translate('这台服务器的 Agent 尚未报告支持分别限制上传/下载或突发限速；只有上下行合计可以发布，其他方式会被拒绝。请先升级 Agent。')));
  assert.deepEqual(['rate_mode', 'mbit', 'rate_upload', 'burst_combined_rate', 'burst_combined_secs'].map(n => input(n).value), ['both', '100', '20', '200', '60']);
  await mode('combined'); input('burst_combined_rate').value = ''; input('burst_combined_secs').value = '';
  await send();
  assert.deepEqual(lastWrite().body, { expected_revision: 8, rules: [], rate_bytes_per_sec: 12500000, rate_limits: null });
  input('mbit').value = '';
  await send();
  assert.equal(lastWrite().body.rate_bytes_per_sec, null);
  assert.equal(notified, translate('已取消节点总限速。'));

  // User total: upload and download shares per node, no burst, null clears a direction.
  view = { user_id: 'u1', rate_bytes_per_sec: null, nodes: [], upload_bytes_per_sec: 1250000, upload_nodes: [{ node_id: 'n1', share_bytes_per_sec: 625000, enforced_bytes_per_sec: 625000, measured_bytes_per_sec: 600000, saturated: true, seen_ms_ago: 500 }], download_bytes_per_sec: null, download_nodes: [] };
  await context.editUserRate({ id: 'u1', username: 'alice' });
  translated(dialog, 'user limit dialog');
  assert.equal(input('rate_mode').value, 'separate');
  assert.ok(!form.all().some(n => String(n.name).startsWith('burst_')), 'user totals have no burst');
  assert.ok(dialog.text().includes(translate('上传份额')) && dialog.text().includes('5 Mbit/s') && dialog.text().includes(translate('已用满')));
  input('rate_download').value = '20';
  await send();
  assert.deepEqual(lastWrite(), { path: '/users/u1/rate', method: 'PUT', body: { rate_bytes_per_sec: null, upload_bytes_per_sec: 1250000, download_bytes_per_sec: 2500000 } });
  await mode('combined');
  input('mbit').value = '8';
  await send();
  assert.deepEqual(lastWrite().body, { rate_bytes_per_sec: 1000000, upload_bytes_per_sec: null, download_bytes_per_sec: null });
  assert.equal(notified, msg`${'alice'} 的跨节点总限速为 ${'8 Mbit/s'}。`);
  input('mbit').value = '0.001';
  await assert.rejects(send(), exactly('请输入 0.009 到 8,796,093 之间的 Mbit/s'));

  // A cross-panel share lists its upload and download bandwidth.
  const share = { kinds: ['forward'], rules: [], max_rules: 2, rate_bytes_per_sec: null, upload_bytes_per_sec: 1250000, download_bytes_per_sec: 2500000, quota_bytes: null, expires_at_ms: null };
  const summary = context.fedLimits(share);
  assert.ok(summary.includes(msg`带宽 ${`${msg`${translate('上传')} ${'10 Mbit/s'}`} · ${msg`${translate('下载')} ${'20 Mbit/s'}`}`}`), summary);
  assert.ok(context.fedLimits({ ...share, upload_bytes_per_sec: null, download_bytes_per_sec: null }).includes(translate('不限速')));

  // Refusals for agents too old or not yet connected read in the panel's language; others stay as sent.
  const old = 'the agent on server Tokyo is too old for separate upload/download or burst speed limits; upgrade it first';
  const fresh = 'server Osaka has not connected to the panel yet; separate upload/download or burst speed limits need its agent to report in first';
  assert.equal(context.rateLimitReason(old), msg`服务器 ${'Tokyo'} 的 Agent 版本过旧，不支持分别限制上传/下载或突发限速；请先升级 Agent`);
  assert.equal(context.rateLimitReason(fresh), msg`服务器 ${'Osaka'} 尚未连接面板；它的 Agent 回报后才能设置分别的上传/下载限速或突发限速`);
  assert.equal(context.rateLimitReason(`user alice has separate upload/download speed limits: ${old}`), msg`用户 ${'alice'} 设有分别的上传/下载总限速：${msg`服务器 ${'Tokyo'} 的 Agent 版本过旧，不支持分别限制上传/下载或突发限速；请先升级 Agent`}`);
  assert.equal(context.rateLimitReason('configuration changed; reload before saving'), null);
  if (english) assert.equal(context.rateLimitReason(old), 'The agent on server Tokyo is too old for separate upload/download or burst speed limits; upgrade it first');
  console.log(`Rate limits (${i18n.getLanguage()}): rule editor modes, bursts and validation, rules table credit, server and user limit bodies with shares, share summary and old-agent refusals passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
