// Exercise missing telemetry and delayed API responses against the shipped UI.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('web/app.js', 'utf8');
function definition(name) {
  const match = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(source);
  assert.ok(match, `${name} missing`);
  const firstLineEnd = source.indexOf('\n', match.index);
  if (source.slice(match.index, firstLineEnd).endsWith('}')) return source.slice(match.index, firstLineEnd);
  const end = source.indexOf('\n}', match.index);
  assert.ok(end > match.index, `${name} must be a top-level multiline function`);
  return source.slice(match.index, end + 2);
}
const constants = source.match(/^const SPAN_MS = .*;$/m)[0];
const telemetry = vm.runInNewContext(`${constants}\n${definition('nodeSeries')}\n${definition('currentRate')}\n({ nodeSeries, currentRate });`);
const now = 1_000_000;
const sample = (at_ms, forwarded_bytes) => ({ at_ms, forwarded_bytes, active_sessions: 7, probe_latency_us: null });
assert.ok(telemetry.nodeSeries([], now).rate.every(v => v === null), 'empty telemetry must not create a zero-rate observation');
assert.equal(telemetry.currentRate([]), null);
const first = sample(now - 20_000, 1_000), next = sample(now - 5_000, 16_000);
assert.ok(telemetry.nodeSeries([first], now).rate.every(v => v === null), 'one counter sample cannot establish throughput');
assert.equal(telemetry.currentRate([first]), null);
assert.equal(telemetry.currentRate([first, next]), 1_000, 'observed byte deltas must retain their rate');
const measured = telemetry.nodeSeries([first, next], now).rate.filter(v => v !== null);
assert.equal(measured.reduce((sum, value) => sum + value * 15, 0), 15_000, 'chart bins must preserve the measured byte delta');
assert.equal(telemetry.currentRate([first, sample(next.at_ms, first.forwarded_bytes)]), 0, 'measured zero must remain distinct from unknown');
assert.equal(telemetry.currentRate([first, sample(first.at_ms, 2_000)]), null, 'duplicate timestamps must not yield infinity');
assert.ok(telemetry.nodeSeries([first, sample(first.at_ms, 2_000)], now).rate.every(v => v === null));
assert.equal(telemetry.currentRate([first, sample(next.at_ms, 1)]), null, 'a restarted counter has no valid delta');
assert.ok(telemetry.nodeSeries([first, sample(next.at_ms, 1)], now).rate.every(v => v === null));

async function lateResponse(name, view, transition) {
  const actor = { id: 'original', role: 'system_admin' }, state = { actor, view, nodes: [], nodeFilter: {} }, pending = [];
  const forbidden = () => { throw new Error(`${name} rendered a response after ${transition}`); };
  const request = () => new Promise(resolve => pending.push(resolve));
  // History is fetched through a cache; the 24-hour range makes Overview request it too.
  const context = { state, URLSearchParams, api: request, loadFeatures: request, featureOn: () => true, monitoringHistory: request, readOverviewRange: () => '24h', $: forbidden, panel: forbidden, translate: value => value };
  vm.createContext(context);
  vm.runInContext(`${definition(name)}\nthis.run = ${name};`, context);
  const result = context.run();
  assert.ok(pending.length, `${name} never requested data`);
  if (transition === 'navigation') state.view = view === 'overview' ? 'nodes' : 'overview';
  else if (transition === 'logout') state.actor = null;
  else state.actor = { id: 'replacement', role: 'system_admin' };
  pending.forEach(resolve => resolve([]));
  await result;
}
async function expiredResponse(replaced, path = '/nodes') {
  const state = { token: 'original-session' }; let finish, logouts = 0;
  const context = { state, loggedOut: () => logouts++, fetch: (_url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer original-session');
    return new Promise(resolve => { finish = resolve; });
  } };
  vm.createContext(context); vm.runInContext(`${definition('api')}\nthis.run = api;`, context);
  const result = context.run(path);
  if (replaced) state.token = 'new-session';
  finish({ ok: false, status: 401, text: async () => '{"error":"expired"}' });
  await assert.rejects(result, /expired/);
  assert.equal(logouts, replaced || path === '/auth/login' ? 0 : 1, 'an old request must not sign out a new session');
}
// Users paste their own proxies as share links; each must fill the same fields the panel exports.
const methods = source.match(/^const shadowsocksMethods = .*;$/m)[0];
const links = vm.runInNewContext(`${methods}\n${['shadowsocksLink', 'socks5Link', 'base64Text', 'parseUpstreamLink'].map(definition).join('\n')}\n({ shadowsocksLink, socks5Link, parseUpstreamLink });`,
  { localize: value => value, translate: text => text, msg: (parts, ...values) => parts.reduce((out, part, i) => out + values[i - 1] + part), atob, btoa, TextEncoder, TextDecoder, Uint8Array });
const key = Buffer.alloc(32, 1).toString('base64');
for (const [link, expected] of [
  [links.shadowsocksLink({ method: '2022-blake3-aes-256-gcm', password: key }, '2001:db8::1', 9443, 'Tokyo #1'), { name: 'Tokyo #1', type: 'shadowsocks', server: '2001:db8::1', port: 9443, method: '2022-blake3-aes-256-gcm', password: key }],
  [links.shadowsocksLink({ method: 'aes-256-gcm', password: 'p@ss:w/rd' }, 'ss.example', 8388, 'Office'), { name: 'Office', type: 'shadowsocks', server: 'ss.example', port: 8388, method: 'aes-256-gcm', password: 'p@ss:w/rd' }],
  [`ss://${Buffer.from('chacha20-ietf-poly1305:pw@203.0.113.9:80').toString('base64')}`, { name: 'SS 203.0.113.9', type: 'shadowsocks', server: '203.0.113.9', port: 80, method: 'chacha20-ietf-poly1305', password: 'pw' }],
  [links.socks5Link({ username: 'a:b', password: 'p&w' }, 'home.example', 1080, 'Home'), { name: 'Home', type: 'socks5', server: 'home.example', port: 1080, username: 'a:b', password: 'p&w' }],
]) assert.deepEqual({ ...links.parseUpstreamLink(link) }, expected, link);
for (const link of ['http://h:1', 'socks5://h', 'socks5://h:70000', 'ss://YWVzLTI1Ni1nY206cHc@h:1/?plugin=obfs-local', `ss://${Buffer.from('rc4-md5:pw').toString('base64url')}@h:1`])
  assert.throws(() => links.parseUpstreamLink(link), undefined, link);

// The subscription form edits a link in place and rotation can keep the old link for a grace period.
async function subscriptionDialogs() {
  class Node {
    constructor(tag, text = '') { Object.assign(this, { tag, textContent: text, children: [], value: '', classList: { toggle() {} }, firstChild: { nodeValue: text } }); }
    append(...items) { for (const item of items) if (item && typeof item === 'object') { item.parentElement = this; this.children.push(item); } }
    addEventListener() {} remove() {} closest() { return this.parentElement || this; }
    inputs() { return this.children.flatMap(c => [...(c.name ? [c] : []), ...c.inputs()]); }
  }
  const calls = []; let handler, form;
  const context = {
    state: { actor: { id: 'admin', role: 'system_admin' } }, Date, roleNames: {}, MAX_UPSTREAMS: 8, shadowsocksMethods: [['aes-256-gcm', 'aes-256-gcm']],
    translate: text => text, msg: (parts, ...values) => parts.reduce((out, part, i) => out + values[i - 1] + part),
    el: (tag, text) => new Node(tag, text), button: text => new Node('button', text),
    field(parent, name, text, value = '', type = 'text', required = true) { const label = new Node('label', text), input = new Node('input'); Object.assign(input, { name, type, required, value: String(value ?? '') }); label.append(input); parent.append(label); return input; },
    select(parent, name, text, options, value) { return context.field(parent, name, text, value ?? options[0][0], 'select'); },
    textarea(parent, name, text, value = '') { return context.field(parent, name, text, value, 'textarea', false); },
    submit(value, _label, callback) { form = value; handler = callback; }, modal() {}, notify() {}, $: () => ({ close() {} }),
    api: async (path, options) => { calls.push([path, options]); return path === '/users' ? [] : { token: 'rsub_new', subscription: { name: 'phone', previous_token_expires_at_ms: null } }; },
    renderSubscriptions: async () => {}, showSubscriptionToken() {}, timestamp: String, subscriptionFormats: { clash: 'Clash', sing_box: 'sing-box' },
    number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
  };
  vm.createContext(context);
  vm.runInContext(['parseUpstreamLink', 'upstreamEditor', 'subscriptionSources', 'subscriptionForm', 'rotateSubscription'].map(definition).join('\n') + '\nthis.edit = subscriptionForm; this.rotate = rotateSubscription;', context);
  const send = async (changes = {}) => { const values = new Map(form.inputs().map(i => [i.name, i.value])); for (const [k, v] of Object.entries(changes)) values.set(k, v); await handler({ get: k => values.has(k) ? values.get(k) : null }); return calls.at(-1); };
  const item = { id: 's1', name: 'phone', format: 'clash', allow_sources: ['203.0.113.0/24'], template: { name_prefix: 'Relay ', host: 'edge.example', node_tags: ['prod', 'hk'], udp: false, upstreams: [{ name: 'Home', type: 'socks5', server: 'home.example', port: 1080, username: 'a', password: 'b' }] } };
  await context.edit(item);
  let [path, options] = await send();
  assert.equal(path, '/subscriptions/s1'); assert.equal(options.method, 'PUT');
  assert.deepEqual(JSON.parse(JSON.stringify(options.body)), { name: 'phone', format: 'clash', template: item.template, allow_sources: ['203.0.113.0/24'] }, 'an unchanged edit must send the stored settings and keep the expiry');
  [, options] = await send({ days: '30', allow_sources: '198.51.100.7\n2001:db8::/32, 2001:db8::9' });
  assert.equal(options.body.expires_in_days, 30);
  assert.deepEqual([...options.body.allow_sources], ['198.51.100.7/32', '2001:db8::/32', '2001:db8::9/128']);
  await context.edit();
  [path, options] = await send({ name: 'tablet' });
  assert.equal(path, '/subscriptions'); assert.equal(options.method, 'POST');
  assert.equal(options.body.expires_in_days, 365); assert.deepEqual([...options.body.allow_sources], []);
  await context.rotate(item);
  [path, options] = await send({ grace_minutes: '15' });
  assert.equal(path, '/subscriptions/s1/rotate'); assert.deepEqual({ ...options.body }, { grace_minutes: 15 });
  [, options] = await send({ grace_minutes: '' });
  assert.deepEqual({ ...options.body }, { grace_minutes: 0 });
}

(async () => {
  await subscriptionDialogs();
  for (const [name, view] of [['renderOverview', 'overview'], ['renderNodes', 'nodes'], ['renderTemplates', 'templates'], ['renderSubscriptions', 'subscriptions'], ['renderUsage', 'usage'], ['renderUsers', 'users'], ['renderAccount', 'account'], ['renderAudit', 'audit'], ['renderAlerts', 'alerts'], ['renderCapabilities', 'capabilities'], ['renderFeatures', 'features'], ['renderBudgets', 'budgets'], ['renderRecovery', 'recovery'], ['renderTopology', 'topology'], ['renderRules', 'rules'], ['renderHealth', 'health'], ['renderTickets', 'tickets'], ['renderCommerce', 'commerce'], ['renderAnnouncements', 'announcements'], ['renderDns', 'dns']]) {
    for (const transition of ['navigation', 'logout', 'account change']) await lateResponse(name, view, transition);
  }
  await expiredResponse(false); await expiredResponse(true); await expiredResponse(false, '/auth/login');
  console.log('UI runtime passed: unknown/zero telemetry, byte conservation, repeated timestamps, counter reset and 57 delayed-response cases across all 19 API-backed pages');
  console.log('Authentication runtime passed: current-session expiry, old-session expiry and failed sign-in');
  console.log('Subscription dialogs passed: in-place edit keeps settings and expiry, source lists, create defaults and rotation grace');
})().catch(error => { console.error(error); process.exitCode = 1; });
