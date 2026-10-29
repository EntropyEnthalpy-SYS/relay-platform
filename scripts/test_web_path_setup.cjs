// Execute the real guided form and submit handler. Browser acceptance is separate.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const { loadI18n, loadWorkflows } = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync('web/app.js', 'utf8');
class Element {
  constructor(tag, text = '') { Object.assign(this, { tag, textContent: text, children: [], value: '', dataset: {}, events: {}, disabled: false, checked: false }); this.classes = new Set(); this.classList = { add: x => this.classes.add(x), toggle: (x, on) => on ? this.classes.add(x) : this.classes.delete(x), contains: x => this.classes.has(x) }; }
  append(...items) { for (const item of items) { if (item?.parentElement) item.parentElement.children = item.parentElement.children.filter(x => x !== item); item.parentElement = this; this.children.push(item); } }
  prepend(...items) { this.append(...items); this.children.unshift(...this.children.splice(-items.length)); }
  replaceChildren(...items) { for (const item of this.children) item.parentElement = null; this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  get options() { return this.children; }
  all() { return this.children.flatMap(x => [x, ...x.all()]); }
  querySelectorAll() { return this.all().filter(x => ['input', 'select', 'textarea'].includes(x.tag)); }
}
async function fixture(single = false, entryNode) {
  let form, handler, preview, diagram, pending, delayed = false, savedProfiles = 0;
  const nodes = [1,2,3,4].map(i => ({ id: 'node-' + i, name: 'VPS ' + i, tenant_id: 'tenant', enrolled: true, profile: { revision: 2, settings: { notes: 'Preserve metadata', forwarding: i === 3 ? null : { host: '192.0.2.' + i, port_start: 20000, port_end: 29999 } } } }));
  const snapshot = { nodes, configs: nodes.map(n => ({ node_id: n.id, revision: 5, rules: [{ id: 'keep-' + n.id }] })) };
  const actor = { id: 'admin', tenant_id: 'tenant' };
  const ctx = { ...loadI18n(), ...loadWorkflows(), crypto: require('node:crypto').webcrypto, state: { actor },
    setTimeout: fn => { pending = fn; return 1; }, clearTimeout: () => { pending = null; },
    el: (tag, text) => new Element(tag, text),
    button: (text, fn) => { const b = new Element('button', text); b.action = fn; return b; },
    modal: (_title, body) => { form = body; }, notify: message => { throw Error(message); },
    submit: (_form, _text, fn) => { handler = fn; },
    forwardingPathView: () => ({ box: new Element('div'), update: value => { diagram = value; } }),
    shadowsocksEditor: () => { let on = false; return { box: new Element('details'), setEnabled: value => { on = value; }, read: () => on ? { method: '2022-blake3-aes-256-gcm', password: 'test-key', udp_over_tcp: true } : null }; },
    previewTopology: async (current, input) => { preview = { current, input }; },
    api: async (path, options) => {
      if (path === '/users') return [actor];
      if (path.endsWith('/profile')) {
        ++savedProfiles; const n = nodes.find(n => path.includes(n.id));
        assert.equal(options.body.expected_revision, n.profile.revision);
        assert.equal(options.body.settings.notes, 'Preserve metadata');
        return { node_id: n.id, profile: { revision: 3, settings: options.body.settings } };
      }
      assert.equal(path, '/configurations/allocate-endpoints', 'form must never publish before explicit review');
      const value = { endpoints: options.body.hops.map((hop, i) => {
        const d = nodes.find(n => n.id === hop.node_id).profile.settings.forwarding;
        return { node_id: hop.node_id, listen: hop.listen || (d ? '0.0.0.0:' + (20000 + i) : null), advertise: hop.advertise || (d ? d.host + ':' + (20000 + i) : null), defaults: d, error: !d && !hop.listen ? 'address_required' : null };
      }), configs: snapshot.configs.map(c => ({ ...c, revision: 8, rules: [...c.rules, { id: 'concurrent-' + c.node_id }] })) };
      if (delayed) { delayed = false; return new Promise((resolve, reject) => { ctx.resolveOld = () => resolve(value); ctx.rejectOld = () => reject(new Error('stale allocation failed')); }); }
      return value;
    }
  };
  vm.createContext(ctx);
  const controls = source.slice(source.indexOf('function field('), source.indexOf('function submit('));
  const visibility = source.slice(source.indexOf('function sectionVisible('), source.indexOf('function websocketEditor('));
  const defaults = source.slice(source.indexOf('function forwardingDefaultsEditor('), source.indexOf('function nodeSettingsEditor('));
  const wizard = source.slice(source.indexOf('async function newTopologyChain('), source.indexOf('function editTopologyBatch('));
  vm.runInContext(controls + visibility + defaults + wizard + '\nthis.wizard = newTopologyChain;', ctx);
  await ctx.wizard(snapshot, { name: 'Test route', mode: 'ss', single, entryNode });
  return { ctx, nodes, get form() { return form; }, get preview() { return preview; }, get diagram() { return diagram; }, get savedProfiles() { return savedProfiles; },
    control: name => form.all().find(x => x.name === name),
    button: text => form.all().find(x => x.tag === 'button' && x.textContent === ctx.translate(text)),
    orderedNodes: () => form.all().filter(x => x.tag === 'select' && x.name.startsWith('node-')).map(x => x.value),
    flush: async () => { const fn = pending; pending = null; if (fn) await fn(); },
    delayNext: () => { delayed = true; },
    submit: () => handler({ get: name => form.all().find(x => x.name === name)?.value ?? null })
  };
}
(async () => {
  const f = await fixture();
  assert.deepEqual(f.orderedNodes(), ['node-1','node-2']);
  assert.equal(f.control('advertise-0').value, '192.0.2.1:20000');
  assert.equal(f.control('listen-0').readOnly, true);
  await f.button('＋ 添加中转 VPS（可选）').action(); await f.flush();
  assert.deepEqual(f.orderedNodes(), ['node-1','node-3','node-2'], 'relay must be inserted before the fixed exit');
  await assert.rejects(f.submit(), /Save a reachable|可达地址/);
  f.control('defaults-2-host').value = '203.0.113.3';
  const saves = f.form.all().filter(x => x.tag === 'button' && x.textContent === f.ctx.translate('保存 VPS 地址并自动分配'));
  f.control('defaults-2-host').value = '';
  await saves[1].action();
  assert.ok(f.form.all().some(x => /Save a reachable|可达地址/.test(x.textContent)), 'missing address error belongs inside the form');
  f.control('defaults-2-host').value = '203.0.113.3';
  await saves[1].action();
  assert.equal(f.savedProfiles, 1);
  assert.equal(f.nodes[2].profile.revision, 3, 'response envelope must not replace the profile');
  assert.equal(f.control('advertise-2').value, '203.0.113.3:20001');
  await f.button('＋ 添加中转 VPS（可选）').action(); await f.flush();
  assert.deepEqual(f.orderedNodes(), ['node-1','node-3','node-4','node-2']);
  const ups = f.form.all().filter(x => x.textContent === f.ctx.translate('上移'));
  await ups[2].action(); await f.flush();
  assert.deepEqual(f.orderedNodes(), ['node-1','node-4','node-3','node-2']);
  f.control('manual-0').checked = true; await f.control('manual-0').fire('change');
  f.control('listen-0').value = '0.0.0.0:33333'; f.control('advertise-0').value = 'entry.example:44444'; await f.flush();
  await f.submit();
  const batch = f.preview.input;
  assert.equal(batch.updates.length, 4);
  for (const c of batch.updates) { assert.equal(c.expected_revision, 8); assert.equal(c.rules[1].id, 'concurrent-' + c.node_id, 'fresh allocation must preserve concurrent saved rules'); }
  assert.equal(batch.updates[0].rules.at(-1).advertise, 'entry.example:44444');
  assert.equal(batch.updates.filter(c => c.rules.at(-1).inbound_shadowsocks).length, 1);
  assert.equal(batch.updates.at(-1).node_id, 'node-2');
  assert.equal(batch.updates.at(-1).rules.at(-1).inbound_shadowsocks.password, 'test-key');
  assert.ok(!JSON.stringify(f.diagram).includes('test-key'));
  const s = await fixture(true); await s.submit();
  assert.equal(s.preview.input.updates.length, 1);
  assert.equal(s.preview.input.updates[0].rules.at(-1).inbound_shadowsocks.password, 'test-key');
  const selected = await fixture(true, 'node-2');
  assert.deepEqual(selected.orderedNodes(), ['node-2'], 'setup must retain the VPS selected on Node rules');
  const race = await fixture(); race.delayNext();
  race.control('node-1').value = 'node-4'; await race.control('node-1').fire('change');
  const old = race.flush();
  race.control('node-1').value = 'node-2'; await race.control('node-1').fire('change'); await race.flush();
  race.ctx.resolveOld(); await old;
  assert.equal(race.control('advertise-1').value, '192.0.2.2:20001', 'late response must not overwrite a changed selection');
  race.control('node-0').value = 'node-2'; await race.control('node-0').fire('change'); await race.flush();
  assert.deepEqual(race.orderedNodes(), ['node-2', 'node-1'], 'entry and exit can be swapped without a third VPS');
  race.delayNext(); race.control('node-1').value = 'node-4'; await race.control('node-1').fire('change');
  const oldFailure = race.flush();
  race.control('node-1').value = 'node-1'; await race.control('node-1').fire('change'); await race.flush();
  race.ctx.rejectOld(); await oldFailure;
  assert.ok(!race.form.all().some(x => x.textContent === 'stale allocation failed'), 'late rejection must not overwrite current allocation status');
  console.log('Guided setup passed: automatic endpoints, fixed exit on relay insertion/reorder, one-time address setup, manual override, fresh config preservation, exit-only SS, single VPS, preview-only submit and stale response rejection');
})().catch(error => { console.error(error); process.exitCode = 1; });
