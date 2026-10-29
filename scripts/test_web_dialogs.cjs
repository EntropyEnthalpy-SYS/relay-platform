const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('web/app.js', 'utf8');
assert.ok(!/\b(?:prompt|confirm)\(/.test(source), 'embedded browsers must not need native prompts');
const listeners = new Set(), queued = [];
let handler, input;
const dialog = {
  open: false,
  addEventListener(_type, fn) { listeners.add(fn); },
  removeEventListener(_type, fn) { listeners.delete(fn); },
  close() { if (this.open) { this.open = false; queued.push(() => [...listeners].forEach(fn => fn())); } },
};
const context = {
  $: () => dialog, translate: text => text,
  el: () => ({ append() {} }),
  field(_form, _name, _label, initial) { input = { value: initial, focus() {} }; return input; },
  submit(_form, _label, fn) { handler = fn; },
  modal() { dialog.open = true; },
};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function panelQuestion('), source.indexOf("$('#dialog-close').onclick")) + '\nthis.confirmAction=confirmAction;this.promptValue=promptValue;', context);
const flush = () => { while (queued.length) queued.shift()(); };
(async () => {
  let decision = context.confirmAction('Delete a test rule?');
  dialog.close(); flush(); assert.equal(await decision, false, 'cancel must not run a mutation');
  decision = context.confirmAction('Publish?'); handler(); assert.equal(await decision, true);
  // A new prompt may open before the prior dialog's asynchronous close event.
  const answer = context.promptValue('Name', 'initial');
  flush(); assert.equal(dialog.open, true, 'a stale close event cancelled the next prompt');
  input.value = '  keep intentional spaces  '; handler(); assert.equal(await answer, '  keep intentional spaces  ');
  flush();
  const cancelled = context.promptValue('Description', ''); dialog.close(); flush();
  assert.equal(await cancelled, null, 'cancel and an empty submitted value must be distinct');
  const blank = context.promptValue('Optional', ''); handler(); assert.equal(await blank, ''); flush();
  assert.equal(listeners.size, 0, 'dialog listeners leaked');
  console.log('Panel dialogs passed: accept, cancel/escape, blank values, sequential prompts, stale close events and listener cleanup');
})().catch(error => { console.error(error); process.exitCode = 1; });
