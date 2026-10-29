// Real diagram rendering and published-rule dispatch, without a browser runtime.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const { loadI18n, loadWorkflows } = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync('web/app.js', 'utf8'), document = { activeElement: null };
class Element {
  constructor(tag, text = '', cls = '') { Object.assign(this, { tag, textContent: text, children: [], dataset: {}, attributes: {}, scrollLeft: 0, classes: new Set(cls.split(/\s+/).filter(Boolean)) }); this.classList = { add: x => this.classes.add(x), toggle: (x,on) => on ? this.classes.add(x) : this.classes.delete(x) }; }
  append(...items) { for (const item of items) { item.parentElement = this; this.children.push(item); } }
  replaceChildren() { this.children = []; }
  setAttribute(name, value) { this.attributes[name] = value; }
  get lastChild() { return this.children.at(-1); }
  all() { return this.children.flatMap(x => [x, ...x.all()]); }
  querySelector(selector) { return this.all().find(x => x.classes.has(selector.slice(1))) || null; }
  focus() { document.activeElement = this; }
  scrollIntoView() { this.scrolled = true; }
}
let clicked, currentSelection;
const context = { ...loadI18n(), ...loadWorkflows(), document,
  el: (tag, text, cls) => new Element(tag, text, cls), badge: text => new Element('span', text),
  button: (text, handler, cls) => { const b = new Element('button', text, cls); b.type = 'button'; b.click = handler; return b; }
};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('const topologyKey ='), source.indexOf('async function editDiagramRule(')) + '\nthis.make = forwardingPathView;', context);
const nodes = [1,2,3].map(i => ({ id: 'n'+i, name: 'VPS '+i, tenant_id: 't', enrolled: true }));
const model = context.forwardingPathDiagram({ nodes }, { hops: nodes.map((n,i) => ({ node_id: n.id, listen: '0.0.0.0:'+(20000+i), advertise: 'node'+i+'.example:'+(20000+i) })), mode: 'ss', protocol: 'both', transport: 'plain' });
const ref = { node_id: 'n3', rule_id: 'diagram-2' };
const view = context.make({ onSelect: item => { clicked = item; }, selected: () => currentSelection });
view.update(model);
const cards = () => view.box.all().filter(x => x.tag === 'button');
assert.equal(cards().length, 3, 'each VPS is clickable, client/external destinations are not');
assert.ok(cards().every(x => x.type === 'button' && x.attributes['aria-label'] && x.attributes['aria-pressed'] === 'false'), 'native buttons support keyboard activation without submitting the form');
cards()[2].click(); assert.equal(clicked.node_id, 'n3');
currentSelection = ref;
const oldTrack = view.box.querySelector('.flow-track'); oldTrack.scrollLeft = 123; cards()[2].focus();
view.update(model);
assert.equal(cards()[2].attributes['aria-pressed'], 'true');
assert.ok(cards()[2].classes.has('flow-selected'));
assert.equal(document.activeElement, cards()[2], 'async diagram redraw should preserve focused card');
assert.equal(view.box.querySelector('.flow-track').scrollLeft, 123, 'redraw should not reset horizontal inspection');
view.focusNode(ref); assert.equal(document.activeElement, cards()[2]); assert.ok(cards()[2].scrolled);
const readOnly = context.make(); readOnly.update(model, 'saved');
assert.equal(readOnly.box.all().filter(x => x.tag === 'button').length, 0, 'read-only views must not advertise an edit action');
const rootOnly = context.make({ onSelect() {}, canSelect: item => item.node_id === 'n1' }); rootOnly.update(model, 'validated');
assert.equal(rootOnly.box.all().filter(x => x.tag === 'button').length, 1, 'single-rule review must not pretend to edit downstream rules');

let opened, writable = true;
const dispatch = { ...loadI18n(), state: { nodes: [], selectedNode: 'wrong', config: { node_id: 'wrong', rules: [] } },
  canWrite: () => writable,
  api: async path => path === '/nodes' ? [{ id: 'n3' }] : { node_id: 'n3', revision: 17, rules: [{ id: 'wanted', name: 'Fresh rule' }] },
  editRule: async rule => { opened = { rule, config: dispatch.state.config, node: dispatch.state.selectedNode }; }
};
vm.createContext(dispatch);
vm.runInContext(source.slice(source.indexOf('async function editDiagramRule('), source.indexOf('async function renderTopology(')) + '\nthis.open=editDiagramRule;', dispatch);
(async () => {
  await dispatch.open({ node_id: 'n3', rule_id: 'wanted' });
  assert.equal(opened.node, 'n3'); assert.equal(opened.config.revision, 17); assert.equal(opened.rule.id, 'wanted');
  opened = null; await assert.rejects(dispatch.open({ node_id: 'n3', rule_id: 'deleted' }), /changed|变化/); assert.equal(opened, null);
  writable = false; await dispatch.open({ node_id: 'n3', rule_id: 'wanted' }); assert.equal(opened, null);
  console.log('Diagram editor passed: native keyboard buttons, selection state, redraw focus/scroll, read-only behavior, root-only review scope, fresh matching saved rule and deleted/viewer rejection');
})().catch(error => { console.error(error); process.exitCode = 1; });
