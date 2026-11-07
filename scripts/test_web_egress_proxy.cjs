// Executes the shipped egress proxy controls with form-control stubs and checks what they send and show:
// socks5:// link import with percent-decoding, the field checks and their error line, the rule editor's
// section (shown only for a proxy service, TCP only), the body it saves, the rules table badge, the next
// hop in the connections view and the refusals for agents too old, in the panel's language. Not a
// browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^function mbit\(.*$/m)
  + between('function sectionVisible(', 'function websocketEditor(')
  + between('// Quota and speed limits of a rule', 'async function saveRules(')
  + between('function gatewayConfig(', 'const shadowsocksMethods');

class Element {
  constructor(tag = 'div', text = '', className = '') {
    Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {}, hidden: false, attributes: {} });
    const self = this;
    this.classList = { toggle(name, on) { if (name === 'hidden') self.hidden = on; }, add() {}, remove() {}, contains: name => name === 'hidden' && self.hidden };
  }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelector(selector) { const name = /^\[name=(\w+)\]$/.exec(selector)?.[1]; return this.all().find(n => name && n.name === name) || null; }
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  visible() { for (let n = this; n; n = n.parentElement) if (n.hidden) return false; return true; }
  text() { return this.all().filter(n => n.visible()).map(n => [n.textContent, ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };
// The whole message, exactly: errors thrown inside the vm context are not this realm's Error.
const literal = text => error => { assert.equal(error.message, text); return true; };
const exactly = key => literal(translate(key));

const socks = { id: 'r1', tenant_id: 't', owner_id: 'owner', name: 'proxy', listen: '0.0.0.0:1080', protocol: 'tcp', targets: [], enabled: true, meter_epoch: 'e1', quota_bytes: null, rate_bytes_per_sec: null, expires_at_ms: null, inbound_socks5: { username: 'client', password: 'inbound-secret' } };
const forward = { id: 'r2', tenant_id: 't', owner_id: 'owner', name: 'web', listen: '0.0.0.0:20000', protocol: 'tcp', targets: [{ address: '192.0.2.10:443', weight: 1 }], enabled: true, meter_epoch: 'e1', quota_bytes: null, rate_bytes_per_sec: null, expires_at_ms: null };
let form, handler, saved = null;
const context = {
  ...i18n, ...helpers.loadWorkflows(),
  TextEncoder, Uint8Array, Uint32Array, btoa, crypto: require('node:crypto').webcrypto,
  document: { createTextNode: text => text },
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  forwardingPathView: () => ({ box: new Element(), update() {} }), featureOn: () => false, canWrite: () => true,
  state: { config: { node_id: 'n1', revision: 3, rules: [socks, forward] }, nodes: [{ id: 'n1', name: 'Tokyo', tenant_id: 't', egress_proxy_support: false, stats: {} }], actor: { id: 'owner', role: 'system_admin' } },
  async api(path) { if (path === '/nodes') return context.state.nodes; return { configs: [], nodes: [] }; },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, label, value = '', type = 'text', required = true) { const wrap = new Element('label', label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); wrap.append(input); parent.append(wrap); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  checkbox(parent, name, text) { const wrap = new Element('label', text), input = new Element('input'); Object.assign(input, { name, type: 'checkbox' }); wrap.prepend(input); parent.append(wrap); return input; },
  button: (text, action, className) => { const n = Object.assign(new Element('button', text, className), { action }); n.addEventListener('click', action); return n; },
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  namedCell: (name, detail) => { const n = new Element('div'); n.append(new Element('strong', name), new Element('div', detail)); return n; },
  healthEditor: (_form, spec) => () => spec,
  multipathEditor: () => ({ mode: {}, read: () => ({}) }),
  targetEditor: (_form, targets) => { const read = () => targets; read.multipathPaths = () => []; read.preview = () => targets; read.onchange = () => {}; return read; },
  websocketEditor: (_name, spec) => ({ box: new Element(), read: () => spec }),
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal: () => {}, notify() {},
  saveRules: async rules => { saved = rules.find(r => r.id === socks.id || r.id === forward.id); }, renderRules: async () => {},
  $: () => ({ close() {} }),
  number: (data, key) => data.get(key) === '' || data.get(key) === null ? null : Number(data.get(key)),
};
// A proxy service stub keeps the spec it was given, so a rule's inbound stays as it was.
for (const helper of ['socks5Editor', 'httpConnectEditor', 'http2ConnectEditor']) context[helper] = spec => ({ box: new Element(), read: () => spec ?? null, enabled: () => !!spec, onchange() {}, setEnabled() {} });
context.shadowsocksEditor = spec => { const box = new Element(); context.select(box, 'ss_uot', 'UoT', [['no', 'no'], ['yes', 'yes']], spec?.udp_over_tcp ? 'yes' : 'no'); return { box, read: () => spec ? { ...spec, udp_over_tcp: box.querySelector('[name=ss_uot]').value === 'yes' } : null, enabled: () => !!spec, onchange() {}, setEnabled() {} }; };
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { editRule, egressCell, egressProxyReason, parseEgressLink, egressProxyConfig });', context);
const send = () => handler(new context.FormData(form));
const input = name => form.all().find(n => n.name === name);
const plain = value => JSON.parse(JSON.stringify(value));
const section = () => input('egress_mode').parentElement.parentElement.parentElement;
const problem = () => form.all().find(n => n.tag === 'p' && n.attributes.role === 'alert' && n.parentElement !== form);
async function mode(value) { input('egress_mode').value = value; await input('egress_mode').fire('change'); }

(async () => {
  // Links: percent-decoded after splitting, so encoded ':' and '@' stay in the username and password.
  assert.deepEqual(plain(context.parseEgressLink(' socks5://us%3Aer:p%40ss%3Aw%20rd@proxy.example.com:1080#Tokyo ')), { server: 'proxy.example.com:1080', username: 'us:er', password: 'p@ss:w rd' });
  assert.deepEqual(plain(context.parseEgressLink('SOCKS5H://[2001:db8::1]:1080/')), { server: '[2001:db8::1]:1080', username: '', password: '' });
  assert.deepEqual(plain(context.parseEgressLink('socks5://%E7%94%A8%E6%88%B7:secret@203.0.113.5:443?remarks=x')), { server: '203.0.113.5:443', username: '用户', password: 'secret' });
  assert.throws(() => context.parseEgressLink('hysteria2://pass@example.com:443'), literal(msg`暂不支持 ${'hysteria2'}:// 出口代理；目前只支持 SOCKS5（socks5://）`));
  assert.throws(() => context.parseEgressLink('tuic://uuid:pass@example.com:443'), literal(msg`暂不支持 ${'tuic'}:// 出口代理；目前只支持 SOCKS5（socks5://）`));
  assert.throws(() => context.parseEgressLink('proxy.example.com:1080'), exactly('无法识别的链接；请粘贴 socks5:// 开头的链接'));
  assert.throws(() => context.parseEgressLink('socks5://user:pass@proxy.example.com:70000'), exactly('无法识别链接中的服务器地址和端口'));
  assert.throws(() => context.parseEgressLink('socks5://user:pass@2001:db8::1:1080'), exactly('无法识别链接中的服务器地址和端口'));
  assert.throws(() => context.parseEgressLink('socks5://user:%ZZ@proxy.example.com:1080'), exactly('链接中的用户名或密码编码无效'));

  // Field checks, the same limits as the controller's.
  assert.equal(context.egressProxyConfig('off', 'a:1', 'u', 'p'), null);
  assert.deepEqual(plain(context.egressProxyConfig('socks5', ' p1.example.com:1080 \n\n[2001:db8::1]:1080\r\n198.51.100.7:1080', '', '')), { kind: 'socks5', servers: ['p1.example.com:1080', '[2001:db8::1]:1080', '198.51.100.7:1080'] });
  assert.deepEqual(plain(context.egressProxyConfig('socks5', 'p1.example.com:1080', 'alice', 's3cret')), { kind: 'socks5', servers: ['p1.example.com:1080'], username: 'alice', password: 's3cret' });
  assert.throws(() => context.egressProxyConfig('socks5', ' \n ', '', ''), exactly('请至少填写一个上游代理地址'));
  assert.throws(() => context.egressProxyConfig('socks5', Array.from({ length: 9 }, (_, i) => `p${i}.example.com:1080`).join('\n'), '', ''), literal(msg`上游代理地址最多 ${8} 个`));
  for (const bad of ['p1.example.com', '2001:db8::1:1080', 'p1.example.com:0', 'p1.example.com:65536', '300.1.1.1:1080', 'http://p1.example.com:1080', 'bad_host!:1080']) {
    assert.throws(() => context.egressProxyConfig('socks5', `ok.example.com:1080\n${bad}`, '', ''), literal(msg`第 ${2} 行上游代理地址无效：请写成 host:port，IPv6 地址加方括号，如 [2001:db8::1]:1080`), bad);
  }
  assert.throws(() => context.egressProxyConfig('socks5', 'P1.example.com:1080\np1.EXAMPLE.com:1080', '', ''), literal(msg`上游代理地址 ${'p1.EXAMPLE.com:1080'} 重复`));
  assert.throws(() => context.egressProxyConfig('socks5', 'p1.example.com:1080', 'alice', ''), exactly('上游代理的用户名和密码必须同时填写或同时留空'));
  assert.throws(() => context.egressProxyConfig('socks5', 'p1.example.com:1080', '', 'secret'), exactly('上游代理的用户名和密码必须同时填写或同时留空'));
  assert.throws(() => context.egressProxyConfig('socks5', 'p1.example.com:1080', 'alice', 'é'.repeat(128)), literal(msg`${translate('上游代理密码')}须为 1 到 255 字节，不含控制字符`), '256 bytes in 128 characters');
  assert.ok(context.egressProxyConfig('socks5', 'p1.example.com:1080', 'alice', 'x'.repeat(255)), '255 bytes is the limit');
  assert.throws(() => context.egressProxyConfig('socks5', 'p1.example.com:1080', 'al\u0007ice', 'secret'), literal(msg`${translate('上游代理用户名')}须为 1 到 255 字节，不含控制字符`));

  // The rule editor on a SOCKS5 service: off by default, and the saved rule has no egress_proxy at all.
  await context.editRule(socks);
  assert.ok(section().visible(), 'shown for a proxy service');
  assert.equal(input('egress_mode').value, 'off');
  assert.ok(!input('egress_servers').visible() && input('egress_servers').disabled, 'the fields hide and send nothing while off');
  await send();
  assert.ok(saved && !('egress_proxy' in saved), 'no egress_proxy while off');
  assert.deepEqual(plain(saved.inbound_socks5), socks.inbound_socks5, 'the inbound credentials stay separate');

  // Turning it on: the agent has not reported support, which the editor says before anything is sent.
  input('protocol').value = 'both';
  await mode('socks5');
  assert.equal(input('protocol').value, 'tcp', 'an egress proxy switches the rule to TCP');
  assert.ok(input('egress_servers').visible() && !input('egress_servers').disabled);
  assert.ok(section().text().includes(msg`服务器 ${'Tokyo'} 的 Agent 尚未报告支持出口代理，发布会被拒绝；请先升级 Agent。`));
  translated(section(), 'egress proxy section');

  // Importing a link fills the address and the shared credentials, and appends rather than replacing.
  input('egress_servers').value = 'first.example.com:1080';
  input('egress_link').value = 'socks5://al%40ice:p%3Ass@[2001:db8::7]:1081';
  await buttons(form, translate('导入链接'))[0].fire('click');
  assert.deepEqual([input('egress_servers').value, input('egress_user').value, input('egress_password').value, input('egress_link').value], ['first.example.com:1080\n[2001:db8::7]:1081', 'al@ice', 'p:ss', '']);
  input('egress_link').value = 'hysteria2://secret@example.com:443';
  await buttons(form, translate('导入链接'))[0].fire('click');
  assert.equal(problem().textContent, msg`暂不支持 ${'hysteria2'}:// 出口代理；目前只支持 SOCKS5（socks5://）`, 'a bad link shows in the error line');
  assert.equal(input('egress_servers').value, 'first.example.com:1080\n[2001:db8::7]:1081', 'a bad link changes nothing');
  await send();
  assert.equal(problem().textContent, '', 'a successful save clears the error line');
  assert.equal(saved.protocol, 'tcp');
  assert.deepEqual(plain(saved.egress_proxy), { kind: 'socks5', servers: ['first.example.com:1080', '[2001:db8::7]:1081'], username: 'al@ice', password: 'p:ss' });

  // Invalid input shows in the section's error line and saves nothing.
  saved = null;
  input('egress_servers').value = 'first.example.com:1080\nnot a host';
  await assert.rejects(send(), literal(msg`第 ${2} 行上游代理地址无效：请写成 host:port，IPv6 地址加方括号，如 [2001:db8::1]:1080`));
  assert.equal(problem().textContent, msg`第 ${2} 行上游代理地址无效：请写成 host:port，IPv6 地址加方括号，如 [2001:db8::1]:1080`);
  input('egress_servers').value = 'first.example.com:1080'; input('egress_password').value = '';
  await assert.rejects(send(), exactly('上游代理的用户名和密码必须同时填写或同时留空'));
  input('egress_password').value = 'p:ss'; input('protocol').value = 'both';
  await assert.rejects(send(), exactly('出口代理只转发 TCP：请把传输协议设为 TCP'));
  assert.equal(saved, null, 'nothing is saved while the egress proxy is invalid');

  // Editing a rule that has one fills the fields; an unchanged save keeps it, and Off removes it.
  const proxied = { ...socks, egress_proxy: { kind: 'socks5', servers: ['a.example.com:1080', 'b.example.com:1080'], username: 'u', password: 'secret' } };
  context.state.nodes[0].egress_proxy_support = true;
  await context.editRule(proxied);
  assert.deepEqual(['egress_mode', 'egress_servers', 'egress_user', 'egress_password'].map(n => input(n).value), ['socks5', 'a.example.com:1080\nb.example.com:1080', 'u', 'secret']);
  assert.ok(!section().text().includes(msg`服务器 ${'Tokyo'} 的 Agent 尚未报告支持出口代理，发布会被拒绝；请先升级 Agent。`), 'no warning once the agent reports support');
  await send();
  assert.deepEqual(plain(saved.egress_proxy), proxied.egress_proxy);
  await mode('off');
  await send();
  assert.ok(!('egress_proxy' in saved), 'Off removes the egress proxy');

  // Shadowsocks: turning the egress proxy on turns UDP over TCP off; a forward rule never shows it.
  await context.editRule({ ...socks, inbound_socks5: undefined, inbound_shadowsocks: { method: '2022-blake3-aes-256-gcm', password: 'k', allow_private_destinations: false, udp_over_tcp: true } });
  assert.ok(section().visible());
  await mode('socks5');
  input('egress_servers').value = 'a.example.com:1080';
  assert.equal(input('ss_uot').value, 'no');
  await send();
  assert.equal(saved.inbound_shadowsocks.udp_over_tcp, false);
  assert.deepEqual(plain(saved.egress_proxy), { kind: 'socks5', servers: ['a.example.com:1080'] });
  await context.editRule(forward);
  assert.ok(!section().visible(), 'hidden for a plain forward');
  await send();
  assert.ok(!('egress_proxy' in saved));

  // The rules table names the upstream.
  const cell = context.egressCell(proxied, new Element('div'));
  assert.ok(cell.text().includes(msg`出口代理 · ${'a.example.com:1080'} 等 ${2} 个`), cell.text());
  assert.ok(!cell.text().includes('secret'), 'the table never shows the password');
  assert.ok(context.egressCell({ ...proxied, egress_proxy: { kind: 'socks5', servers: ['a.example.com:1080'] } }, new Element('div')).text().includes(msg`出口代理 · ${'a.example.com:1080'}`));
  assert.equal(context.egressCell(socks, new Element('div')).children.length, 0, 'no badge without an egress proxy');
  translated(cell, 'rules table cell');

  // Refusals for agents too old or not yet connected read in the panel's language; others stay as sent.
  const old = 'the agent on server Tokyo is too old for egress proxies; upgrade it first';
  const fresh = 'server Osaka has not connected to the panel yet; egress proxies need its agent to report in first';
  assert.equal(context.egressProxyReason(old), msg`服务器 ${'Tokyo'} 的 Agent 版本过旧，不支持出口代理；请先升级 Agent`);
  assert.equal(context.egressProxyReason(fresh), msg`服务器 ${'Osaka'} 尚未连接面板；它的 Agent 回报后才能使用出口代理`);
  assert.equal(context.egressProxyReason("rule web belongs to share s1; a share's rules cannot have an egress proxy"), msg`规则 ${'web'} 属于共享 ${'s1'}，共享的规则不能设置出口代理`);
  assert.equal(context.egressProxyReason("an egress proxy carries TCP only; set the rule's protocol to TCP (UDP is never sent around the egress proxy)"), translate('出口代理只转发 TCP：请把传输协议设为 TCP'));
  assert.equal(context.egressProxyReason('configuration changed; reload before saving'), null);
  assert.equal(context.egressProxyReason(undefined), null);
  if (english) assert.equal(context.egressProxyReason(old), 'The agent on server Tokyo is too old for egress proxies; upgrade it first');
  console.log(`Egress proxy (${i18n.getLanguage()}): link import, field checks, rule editor section and body, TCP only, rules table badge and old-agent refusals passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
