// Serialization check for the rule editor. It runs the shipped targetEditor
// with form-control stubs; it is not a browser or visual acceptance test.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const start = source.indexOf('function targetEditor(');
const end = source.indexOf('\nfunction multipathEditor(');
assert.ok(start >= 0 && end > start, 'targetEditor not found in web/app.js');

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

function serialize(target, drainValue) {
  const context = {
    ...require('./web_i18n_helpers.cjs').loadI18n(),
    el() { return control('div'); },
    field(_parent, name, _label, value) { return control('field', value); },
    select(_parent, name, _label, _options, value) {
      if (name.startsWith('target-draining-')) return control('select', drainValue ?? value);
      return control('select', value);
    },
    button() { return control('button'); },
    websocketEditor(_prefix, value) { return { box: control('div'), read: () => value ?? null }; },
  };
  vm.createContext(context);
  vm.runInContext(source.slice(start, end) + '\nthis.targetEditor = targetEditor;', context);
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

console.log(JSON.stringify({
  preserved: { draining: preserved.draining, max_sessions: preserved.max_sessions, via: preserved.via },
  ended_draining: ended.draining,
  plain_draining: plain.draining,
}));
