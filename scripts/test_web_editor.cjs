// Serialization check for the rule editor. It runs the shipped targetEditor
// with form-control stubs; it is not a browser or visual acceptance test.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const start = source.indexOf('function targetEditor(');
const end = source.indexOf('\nfunction multipathEditor(');
assert.ok(start >= 0 && end > start, 'targetEditor not found in web/app.js');
const localDateTime = source.match(/^function localDateTime\(.*$/m);
assert.ok(localDateTime, 'localDateTime not found in web/app.js');

function control(kind, value) {
  return {
    kind,
    value: value == null ? '' : String(value),
    checked: false,
    append() {}, addEventListener() {}, removeEventListener() {}, remove() {},
    querySelectorAll() { return []; },
    classList: { toggle() {} },
  };
}

function serialize(target, drainValue, pause = {}) {
  const context = {
    ...require('./web_i18n_helpers.cjs').loadI18n(),
    el() { return control('div'); },
    field(_parent, name, _label, value) {
      if (name.startsWith('target-pause-until-')) return control('field', pause.until ?? value);
      return control('field', value);
    },
    select(_parent, name, _label, _options, value) {
      if (name.startsWith('target-draining-')) return control('select', drainValue ?? value);
      if (name.startsWith('target-pause-')) { pause.loaded = value; return control('select', pause.mode ?? value); }
      return control('select', value);
    },
    button() { return control('button'); },
    websocketEditor(_prefix, value) { return { box: control('div'), read: () => value ?? null }; },
  };
  vm.createContext(context);
  vm.runInContext(localDateTime[0] + '\n' + source.slice(start, end) + '\nthis.targetEditor = targetEditor;', context);
  const form = control('form');
  const editor = context.targetEditor(
    form,
    [target],
    { configs: [], nodes: [] },
    'tenant',
    'current',
  );
  return editor();
}

const input = {
  address: 'relay.example:9000',
  weight: 3,
  priority: 7,
  max_sessions: 42,
  prewarm: 2,
  draining: true,
  tls: { server_name: 'relay.example', ca: null, identity: null },
  proxy_protocol: { version: 'v2', placement: 'before_tls', checksum: true },
  websocket: { path: '/ws', host: null, origin: null },
  via: { node_id: 'downstream', rule_id: 'r' },
};
const preserved = serialize(input)[0];
assert.equal(preserved.draining, true, 'a no-change edit dropped target.draining');
assert.equal(preserved.max_sessions, 42);
assert.equal(preserved.prewarm, 2);
assert.equal(preserved.priority, 7);
const same = (actual, expected, label) =>
  assert.equal(JSON.stringify(actual), JSON.stringify(expected), label);
same(preserved.via, { node_id: 'downstream', rule_id: 'r' }, 'via changed');
same(preserved.proxy_protocol, input.proxy_protocol, 'PROXY settings changed');
same(preserved.tls, input.tls, 'TLS settings changed');
same(preserved.websocket, input.websocket, 'WebSocket settings changed');

// The control can also end maintenance deliberately.
const ended = serialize(input, 'off')[0];
assert.equal(ended.draining, undefined, 'choosing normal use kept draining');

// An ordinary target without the field stays ordinary.
const plain = serialize({ address: 'relay.example:9001', weight: 1 }, 'off')[0];
assert.equal(plain.draining, undefined);

// Pausing: until resumed, until a time, and an elapsed time that no longer pauses.
assert.equal(preserved.paused, undefined, 'an unpaused target gained a pause');
const hour = Date.now() + 3_600_000;
const held = serialize({ ...input, paused: true }, undefined)[0];
assert.equal(held.paused, true, 'a no-change edit dropped target.paused');
assert.equal(held.paused_until_ms, undefined);
const timedLoad = {};
const timed = serialize({ ...input, paused: true, paused_until_ms: hour }, undefined, timedLoad)[0];
assert.equal(timedLoad.loaded, 'until');
assert.equal(timed.paused, true);
assert.ok(Math.abs(timed.paused_until_ms - hour) < 1000, 'the pause end moved on a no-change edit');
const elapsedLoad = {};
const elapsed = serialize({ ...input, paused: true, paused_until_ms: Date.now() - 1000 }, undefined, elapsedLoad)[0];
assert.equal(elapsedLoad.loaded, 'off', 'an elapsed pause must load as not paused');
assert.equal(elapsed.paused, undefined);
assert.equal(elapsed.paused_until_ms, undefined);
const resumed = serialize({ ...input, paused: true }, undefined, { mode: 'off' })[0];
assert.equal(resumed.paused, undefined, 'resuming kept the pause');
assert.throws(() => serialize(input, undefined, { mode: 'until', until: '2001-01-01T00:00' }), /暂停结束时间|pause must end/);
const chosen = serialize(input, undefined, { mode: 'until', until: '2099-01-02T03:04' })[0];
assert.equal(chosen.paused_until_ms, new Date('2099-01-02T03:04').getTime());

console.log(JSON.stringify({
  paused: { held: held.paused, timed: timed.paused_until_ms === undefined ? null : 'kept', elapsed: elapsed.paused ?? false },
  preserved: { draining: preserved.draining, max_sessions: preserved.max_sessions, via: preserved.via },
  ended_draining: ended.draining,
  plain_draining: plain.draining,
}));
