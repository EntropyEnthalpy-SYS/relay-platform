// Executes the shipped Wallet & orders page and plan editor with form-control stubs and checks the
// traffic cycle and automatic top-up parts: the request bodies the plan editor sends for each reset
// policy and top-up, its validation, the user's cycle tiles and top-up switch, the administrator's
// Reset traffic now and switch, and top-up orders in the order list. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^function number\(.*$/m)
  + between('const orderStatuses = localize(', 'async function renderAnnouncements(');

class Element {
  constructor(tag = 'div', text = '', className = '') { Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', disabled: false, events: {} }); }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);
const button = (root, text) => { const found = buttons(root, text); assert.equal(found.length, 1, `button ${text}`); return found[0]; };

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };
const exactly = key => new RegExp(translate(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

const DAY = 86_400_000, start = Date.UTC(2026, 10, 1), GIB = 1024 ** 3;
const topUp = { bytes: 10 * GIB, price_cents: 500, max_per_cycle: 3 };
const plans = [
  { id: 'weekly', name: 'Weekly', description: '', price_cents: 3000, duration_days: 28, traffic_bytes: 100 * GIB, enabled: true, created_at_ms: 1, traffic_reset: { every_days: 7 }, top_up: topUp },
  { id: 'monthly', name: 'Monthly', description: '', price_cents: 5000, duration_days: 30, traffic_bytes: 200 * GIB, enabled: true, created_at_ms: 1, traffic_reset: 'billing' },
  { id: 'pack', name: 'Pack', description: '', price_cents: 1000, duration_days: 365, traffic_bytes: null, enabled: true, created_at_ms: 1, traffic_reset: 'none' },
];
const cycle = { policy: { every_days: 7 }, started_at_ms: start, ends_at_ms: start + 7 * DAY, next_reset_at_ms: start + 7 * DAY, allowance_bytes: 110 * GIB, top_up_bytes: 10 * GIB, used_bytes: 104 * GIB, reserved_bytes: 4 * 1024 ** 2, remaining_bytes: 0, top_ups: 1, top_up: topUp, last_failure: { reason: 'insufficient_balance', at_ms: start + 3 * DAY } };
const mine = { user_id: 'u1', username: 'buyer', state: 'active', base_bytes: 0, expires_at_ms: start + 28 * DAY, grants: [{ order_id: 'o1', revoked_at_ms: null }], auto_top_up: false, cycles: 1, budget: { limit_bytes: 110 * GIB, consumed_bytes: 104 * GIB, committed_bytes: 104 * GIB + 4 * 1024 ** 2 }, current_cycle: cycle };
const cumulative = { user_id: 'u2', username: 'old', state: 'active', base_bytes: 0, expires_at_ms: start + 300 * DAY, grants: [{ order_id: 'o3' }], auto_top_up: false, cycles: 0, budget: { limit_bytes: 200 * GIB, consumed_bytes: GIB, committed_bytes: GIB } };
const orders = [
  { id: 'o2', kind: 'top_up', user_id: 'u1', plan_id: 'weekly', plan_name: 'Weekly', amount_cents: 500, currency: 'CNY', duration_days: 0, traffic_bytes: 10 * GIB, status: 'paid', channel: 'wallet', created_at_ms: start + DAY, paid_at_ms: start + DAY },
  { id: 'o1', kind: 'plan', user_id: 'u1', plan_id: 'weekly', plan_name: 'Weekly', amount_cents: 3000, currency: 'CNY', duration_days: 28, traffic_bytes: 100 * GIB, status: 'paid', channel: 'wallet', created_at_ms: start, paid_at_ms: start },
];

let form, handler, calls = [], content = null, confirmed = true;
const context = {
  ...i18n,
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled).map(c => [c.name, c.value])); } get(key) { return this.values.get(key) ?? null; } },
  state: { view: 'commerce', actor: { id: 'u1', role: 'viewer' } },
  featureOn: name => name === 'plan-entitlements',
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    if (options.method) return {};
    return {
      '/commerce/wallet': { wallet: { balance_cents: 0, currency: 'CNY' }, entries: [{ delta_cents: -500, kind: 'purchase', description: 'top-up Weekly', reference: 'top_up:u1:1:1', created_at_ms: start + DAY }] },
      '/commerce/plans': plans, '/commerce/orders': orders, '/commerce/webhook': { enabled: false, secret_set: false }, '/commerce/coupons': [], '/commerce/gift-codes': [],
      '/commerce/entitlement': JSON.parse(JSON.stringify(mine)), '/commerce/entitlements': JSON.parse(JSON.stringify([{ ...mine, auto_top_up: true }, cumulative])),
    }[path];
  },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, label, value = '', type = 'text', required = true) { const wrap = new Element('label', label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); wrap.append(input); parent.append(wrap); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  meter: (_ratio, label) => new Element('div', label, 'meter'),
  timestamp: ms => new Date(ms).toISOString(),
  namedCell: (name, detail) => { const n = new Element('div'); n.append(new Element('strong', name), new Element('div', detail)); return n; },
  empty: (title, description) => new Element('div', `${title} ${description}`),
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); for (const row of rows) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  panel: (title, description, action) => { const n = new Element('section', title); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal() {}, notify() {},
  $: selector => selector === '#content' ? { replaceChildren: (...panels) => { content = new Element('main'); content.append(...panels); } } : { close() {} },
  confirmAction: async () => confirmed, promptValue: async () => '', navigator: {},
};
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { renderCommerce, planForm });', context);
const send = () => handler(new context.FormData(form));
// Each write re-renders the page, so later reads follow it.
const writes = () => calls.filter(call => call.method !== 'GET');
const lastWrite = () => writes().at(-1);
const input = name => form.all().find(n => n.name === name);
const rows = root => root.all().filter(n => n.tag === 'tr');
const section = title => content.children.find(n => n.textContent === translate(title));

(async () => {
  // New plan: every 7 days with a top-up of 1 GiB for ¥2.50, at most 3 per cycle.
  context.planForm(null);
  translated(form, 'plan editor');
  Object.assign(input('name'), { value: ' Weekly ' }); input('price').value = '30'; input('days').value = '28'; input('traffic').value = '107374182400';
  input('reset').value = 'every_days'; input('reset_days').value = '7';
  input('top_up_bytes').value = '1073741824'; input('top_up_price').value = '2.50'; input('top_up_max').value = '3';
  await send();
  assert.deepEqual(lastWrite(), { path: '/commerce/plans', method: 'POST', body: { name: 'Weekly', description: '', price_cents: 3000, duration_days: 28, traffic_bytes: 107374182400, enabled: true, traffic_reset: { every_days: 7 }, top_up: { bytes: 1073741824, price_cents: 250, max_per_cycle: 3 } } });

  // Invalid combinations send nothing.
  const before = writes().length;
  input('reset_days').value = '0';
  await assert.rejects(send(), exactly('重置间隔须为 1..366 天'));
  input('reset_days').value = '7'; input('top_up_max').value = '0';
  await assert.rejects(send(), exactly('每周期最多补流量次数须为 1..1000'));
  input('top_up_max').value = '3'; input('top_up_price').value = '';
  await assert.rejects(send(), exactly('请填写有效的补流量大小和价格'));
  input('top_up_price').value = '2.50'; input('reset').value = 'none';
  await assert.rejects(send(), exactly('自动补流量需要设置流量和流量重置方式'));
  input('reset').value = 'billing'; input('traffic').value = '';
  await assert.rejects(send(), exactly('自动补流量需要设置流量和流量重置方式'));
  assert.equal(writes().length, before);

  // Editing fills the stored policy; billing without a top-up, and no reset, are sent as such.
  context.planForm(plans[0]);
  assert.deepEqual(['reset', 'reset_days', 'top_up_bytes', 'top_up_price', 'top_up_max'].map(n => input(n).value), ['every_days', '7', String(10 * GIB), '5.00', '3']);
  input('reset').value = 'billing'; input('top_up_bytes').value = '';
  await send();
  assert.deepEqual(lastWrite(), { path: '/commerce/plans/weekly', method: 'PUT', body: { name: 'Weekly', description: '', price_cents: 3000, duration_days: 28, traffic_bytes: 100 * GIB, enabled: true, traffic_reset: 'billing', top_up: null } });
  context.planForm(plans[1]);
  assert.equal(input('reset').value, 'billing');
  input('reset').value = 'none'; input('reset_days').value = '9';
  await send();
  assert.deepEqual(lastWrite().body.traffic_reset, 'none', 'the interval only matters for every N days');
  assert.equal(lastWrite().body.top_up, null);

  // The buyer's page: the cycle, its next reset, top-ups against the cap, the last failure and the switch.
  await context.renderCommerce();
  translated(content, 'wallet page');
  const plan = section('我的套餐');
  for (const text of [translate('本周期已用'), bytes(104 * GIB), translate('本周期额度'), bytes(110 * GIB), translate('剩余'), translate('下次重置'), new Date(start + 7 * DAY).toLocaleDateString(i18n.getLanguage()), translate('本周期补流量'), '1 / 3', translate('钱包余额不足'), msg`每 ${7} 天重置`, msg`服务器已领取、尚未上报的 ${bytes(4 * 1024 ** 2)} 也占用本周期流量。`]) assert.ok(plan.text().includes(text), `My plan shows ${text}`);
  assert.ok(!buttons(content, translate('立即重置流量')).length, 'users cannot reset their traffic');
  await button(plan, translate('开启“用完自动补流量”')).action();
  assert.deepEqual(lastWrite(), { path: '/commerce/entitlements/u1/auto-top-up', method: 'PUT', body: { enabled: true } });
  // Plans list their reset policy and top-up.
  const [weekly, monthly, pack] = rows(section('套餐'));
  assert.ok(weekly.text().includes(msg`每 ${7} 天重置`) && weekly.text().includes(msg`补流量 ${bytes(10 * GIB)} · ${'¥5.00'}`) && weekly.text().includes(msg`每周期最多 ${3} 次`));
  assert.ok(monthly.text().includes(translate('跟随计费周期')) && !monthly.text().includes(msg`每周期最多 ${3} 次`), 'a plan without top-up shows none');
  assert.ok(pack.text().includes(translate('不重置')));
  // Top-up orders are listed with their traffic and cannot be refunded.
  const [topUpOrder, planOrder] = rows(section('订单'));
  assert.ok(topUpOrder.text().includes(msg`补流量 ${bytes(10 * GIB)}`) && planOrder.text().includes(translate('套餐购买')));

  // An administrator: Reset traffic now and the switch for each plan that resets; refunds for plan orders only.
  context.state.actor = { id: 'admin', role: 'system_admin' };
  await context.renderCommerce();
  translated(content, 'administrator page');
  const [cycled, old] = rows(section('套餐权益'));
  assert.ok(cycled.text().includes(msg`下次重置 ${new Date(start + 7 * DAY).toLocaleDateString(i18n.getLanguage())}`) && cycled.text().includes(msg`本周期补流量 ${'1 / 3'}`) && cycled.text().includes(translate('钱包余额不足')));
  assert.ok(!buttons(old, translate('立即重置流量')).length && !buttons(old, translate('开启补流量')).length, 'a plan without cycles has neither');
  confirmed = false;
  const count = writes().length;
  await button(cycled, translate('立即重置流量')).action();
  assert.equal(writes().length, count, 'cancel sends nothing');
  confirmed = true;
  await button(cycled, translate('立即重置流量')).action();
  assert.deepEqual(lastWrite(), { path: '/commerce/entitlements/u1/reset', method: 'POST', body: undefined });
  await button(cycled, translate('关闭补流量')).action();
  assert.deepEqual(lastWrite(), { path: '/commerce/entitlements/u1/auto-top-up', method: 'PUT', body: { enabled: false } });
  const [adminTopUp, adminPlan] = rows(section('订单'));
  assert.equal(buttons(adminTopUp, translate('退款')).length, 0);
  assert.equal(buttons(adminPlan, translate('退款')).length, 1);
  console.log(`Traffic cycles (${i18n.getLanguage()}): plan editor bodies and validation, cycle tiles, top-up switch, Reset traffic now and top-up orders passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
function bytes(n) { return context.bytes(n); }
