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
  const context = { state, URLSearchParams, api: () => new Promise(resolve => pending.push(resolve)), $: forbidden, panel: forbidden, translate: value => value };
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
(async () => {
  for (const [name, view] of [['renderOverview', 'overview'], ['renderNodes', 'nodes'], ['renderTemplates', 'templates'], ['renderSubscriptions', 'subscriptions'], ['renderUsage', 'usage'], ['renderUsers', 'users'], ['renderAccount', 'account'], ['renderAudit', 'audit'], ['renderAlerts', 'alerts'], ['renderCapabilities', 'capabilities'], ['renderBudgets', 'budgets'], ['renderRecovery', 'recovery'], ['renderTopology', 'topology'], ['renderRules', 'rules'], ['renderHealth', 'health'], ['renderTickets', 'tickets'], ['renderCommerce', 'commerce'], ['renderAnnouncements', 'announcements'], ['renderDns', 'dns']]) {
    for (const transition of ['navigation', 'logout', 'account change']) await lateResponse(name, view, transition);
  }
  await expiredResponse(false); await expiredResponse(true); await expiredResponse(false, '/auth/login');
  console.log('UI runtime passed: unknown/zero telemetry, byte conservation, repeated timestamps, counter reset and 57 delayed-response cases across all 19 API-backed pages');
  console.log('Authentication runtime passed: current-session expiry, old-session expiry and failed sign-in');
})().catch(error => { console.error(error); process.exitCode = 1; });
