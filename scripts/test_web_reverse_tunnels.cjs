// Executes the shipped Reverse tunnels panel and dialogs with form-control stubs and checks what
// they show and the request bodies they send: the list with states and reasons, the New form with
// tenant-filtered private servers and the Auto port pick, edit, disable, delete and the access and
// limits of the public end. Not a browser test.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const helpers = require('./web_i18n_helpers.cjs');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const between = (start, end) => {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} not found`);
  return source.slice(from, to);
};
const line = pattern => { const found = source.match(pattern); assert.ok(found, `${pattern} not found`); return found[0] + '\n'; };
const code = line(/^function bytes\(.*$/m) + line(/^const listenPort = .*$/m)
  + between('// Reverse tunnels (NAT traversal).', '// Endpoint groups and saved chains.');

class Element {
  constructor(tag = 'div', text = '', className = '') { Object.assign(this, { tag, textContent: text ?? '', className, children: [], value: '', checked: false, disabled: false, dataset: {}, events: {} }); this.classList = { add() {}, toggle() {}, contains: () => false }; }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') item.parentElement = this; this.children.push(item); } }
  prepend(...items) { for (const item of items) if (item && typeof item === 'object') item.parentElement = this; this.children.unshift(...items); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(type, handler) { (this.events[type] ||= []).push(handler); }
  async fire(type) { for (const handler of this.events[type] || []) await handler(); }
  setAttribute() {}
  querySelectorAll() { return this.children.filter(c => typeof c === 'object').flatMap(c => [...(['input', 'select', 'textarea'].includes(c.tag) ? [c] : []), ...c.querySelectorAll()]); }
  all() { return [this, ...this.children.filter(c => typeof c === 'object').flatMap(c => c.all())]; }
  text() { return this.all().map(n => [n.textContent, n.placeholder || '', ...n.children.filter(c => typeof c === 'string')].join(' ')).join(' '); }
}
const buttons = (root, text) => root.all().filter(n => n.tag === 'button' && n.textContent === text);
const button = (root, text) => { const found = buttons(root, text); assert.equal(found.length, 1, `button ${text}`); return found[0]; };

const i18n = helpers.loadI18n(), { translate, msg } = i18n, english = i18n.getLanguage() === 'en';
const translated = (node, what) => { if (english) assert.ok(!/[\u3400-\u9fff]/.test(node.text()), `${what} has untranslated text: ${node.text().match(/[^ ]*[\u3400-\u9fff][^ ]*/)}`); };

const range = { host: 'gw.example.net', listen_ip: null, port_start: 20000, port_end: 20012, public_port_start: null };
const nodes = [
  { id: 'pub', name: 'Tokyo', tenant_id: 't', profile: { settings: { forwarding: range } } },
  { id: 'home', name: 'Home NAS', tenant_id: 't', profile: { settings: {} } },
  { id: 'office', name: 'Office', tenant_id: 't', profile: { settings: {} } },
  { id: 'x-pub', name: 'Elsewhere', tenant_id: 'x', profile: { settings: {} } },
  { id: 'x-home', name: 'Their NAS', tenant_id: 'x', profile: { settings: {} } },
];
const view = (id, fields) => ({ id, tenant_id: 't', name: id, public_node_id: 'pub', private_node_id: 'home', public_port: 20005, listen_ip: null, protocol: 'tcp', target: '127.0.0.1:8080', tunnel_port: 29123, enabled: true, public_node_name: 'Tokyo', private_node_name: 'Home NAS', public_missing: false, private_missing: false, state: 'waiting', reason: null, connected_since_ms: null, connected_for_secs: null, entry: 'gw.example.net:20005', rule_id: null, upload_bytes: 0, download_bytes: 0, ...fields });
const tunnels = [
  view('web', { state: 'connected', connected_for_secs: 7300, rule_id: 'rt-web', upload_bytes: 1536, download_bytes: 3 * 1024 * 1024, protocol: 'tcp_udp' }),
  view('game', { public_port: 20006, tunnel_port: 20007, state: 'waiting', reason: "waiting for the public server's key", listen_ip: '203.0.113.5', entry: null }),
  view('old', { public_port: 20009, state: 'waiting', reason: "the private server's agent is too old for reverse tunnels; upgrade it", private_node_id: 'office', private_node_name: 'Office' }),
  view('broken', { public_port: 20010, state: 'error', reason: 'cannot connect to gw.example.net:29123: Connection refused (os error 111)' }),
  view('gone', { public_port: 20001, state: 'error', reason: 'the private server was deleted', private_missing: true, private_node_name: null, private_node_id: 'deleted-node' }),
  view('off', { public_port: 20002, enabled: false, state: 'disabled', rule_id: 'rt-off' }),
];
// Rules on the public server: one port, a range, a gateway port and the public end of `web`.
const publicConfig = { node_id: 'pub', revision: 12, rules: [
  { id: 'r1', name: 'one', listen: '0.0.0.0:20000', protocol: 'tcp', targets: [] },
  { id: 'r2', name: 'range', listen: '0.0.0.0:20001', listen_end_port: 20003, protocol: 'tcp', targets: [] },
  { id: 'r3', name: 'gateway', listen: '0.0.0.0:9443', protocol: 'tcp', targets: [], protocol_gateway: { listen: '0.0.0.0:20004' } },
  { id: 'rt-web', name: 'web', listen: '0.0.0.0:20005', protocol: 'both', targets: [{ address: '127.0.0.1:8080', weight: 1 }], reverse_tunnel: 'web', allow_sources: [], deny_sources: ['198.51.100.7/32'], rate_bytes_per_sec: null, max_connections: 4096, meter_epoch: 'e1' },
] };

let form, handler, dialog, calls = [], confirmed = true, copied = null, notified = null;
const context = {
  ...helpers.loadI18n(), ...helpers.loadWorkflows(),
  FormData: class { constructor(element) { this.values = new Map(element.querySelectorAll().filter(c => c.name && !c.disabled && (c.type !== 'checkbox' || c.checked)).map(c => [c.name, c.type === 'checkbox' ? 'on' : c.value])); } get(key) { return this.values.get(key) ?? null; } },
  canWrite: () => true, state: { actor: { id: 'owner', role: 'tenant_admin' }, selectedNode: 'pub', nodes: [] },
  navigator: { clipboard: { writeText: async text => { copied = text; } } },
  async api(path, options = {}) {
    calls.push({ path, method: options.method || 'GET', body: options.body === undefined ? undefined : JSON.parse(JSON.stringify(options.body)) });
    if (path === '/nodes') return nodes;
    if (path === '/reverse-tunnels' && !options.method) return tunnels;
    if (path === '/nodes/pub/config' && !options.method) return JSON.parse(JSON.stringify(publicConfig));
    if (path.startsWith('/nodes/') && !options.method) return { node_id: path.split('/')[2], revision: 1, rules: [] };
    return {};
  },
  el: (tag, text, className) => new Element(tag, text, className),
  field(parent, name, _label, value = '', type = 'text', required = true) { const label = new Element('label', _label), input = new Element('input'); Object.assign(input, { name, value: String(value ?? ''), type, required }); label.append(input); parent.append(label); return input; },
  select(parent, name, label, options, value) { const input = context.field(parent, name, label, value ?? options[0]?.[0] ?? ''); input.tag = 'select'; for (const [id, text] of options) input.append(Object.assign(new Element('option', text), { value: id })); return input; },
  textarea(parent, name, label, value = '') { const input = context.field(parent, name, label, value); input.tag = 'textarea'; return input; },
  button: (text, action, className) => Object.assign(new Element('button', text, className), { action }),
  badge: (text, color) => new Element('span', text, `badge ${color || ''}`),
  table: (headers, rows) => { const n = new Element('table'); n.append(...headers.map(h => new Element('th', h))); for (const row of rows) { const tr = new Element('tr'); tr.append(...row.map(cell => cell instanceof Element ? cell : new Element('td', String(cell)))); n.append(tr); } return n; },
  panel: (title, description, action) => { const n = new Element('section', title); n.append(new Element('p', description)); if (action) n.append(action); return n; },
  submit: (value, _label, callback) => { form = value; handler = callback; }, modal: (_title, body) => { dialog = body; }, notify(message) { notified = message; }, refresh: async () => {},
  $: () => ({ close() {} }), confirmAction: async () => confirmed,
};
vm.createContext(context);
vm.runInContext(code + '\nObject.assign(this, { reverseTunnelsPanel, openReverseTunnel, switchReverseTunnel, deleteReverseTunnel, limitReverseTunnel, forwardingRootsWithoutTunnels });', context);
const send = () => handler(new context.FormData(form));
const last = path => calls.filter(call => call.path === path).at(-1);
const field = name => form.all().find(n => n.name === name);
const press = node => node.action();
const rows = shown => shown.all().filter(n => n.tag === 'tr');
const exactly = key => new RegExp(translate(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

(async () => {
  // The list: each tunnel's servers, ports, state with its reason in the panel's language (other
  // reasons as the agent sent them), the entry with Copy, traffic and actions.
  const shown = context.reverseTunnelsPanel(tunnels);
  const [web, game, old, broken, gone, off] = rows(shown);
  assert.ok(web.text().includes(translate('已连接')) && web.text().includes(msg`已建立 ${msg`${2} 小时`}`), 'connected for 7300 s is two hours');
  assert.ok(web.text().includes('TCP + UDP') && web.text().includes('↑ 1.50 KiB') && web.text().includes('↓ 3.00 MiB'));
  assert.ok(web.text().includes(msg`公网端口 ${20005}`) && web.text().includes(msg`隧道端口 ${29123}`) && game.text().includes(msg`隧道端口 ${20007}`));
  assert.ok(game.text().includes(translate('等待中')) && game.text().includes(translate('等待公网服务器的密钥')));
  assert.ok(game.text().includes(translate('未设置转发地址')) && !buttons(game, translate('复制')).length);
  assert.ok(old.text().includes(translate('Agent 版本过旧：内网服务器的 Agent 不支持反向隧道，请升级')));
  assert.ok(broken.text().includes('cannot connect to gw.example.net:29123: Connection refused (os error 111)'), 'agent errors are shown as sent');
  assert.ok(gone.text().includes(translate('服务器已删除')) && gone.text().includes('deleted-node'));
  assert.deepEqual(buttons(gone, translate('删除')).length + buttons(gone, translate('编辑')).length + buttons(gone, translate('停用')).length, 1, 'a tunnel with a deleted server can only be deleted');
  assert.equal(buttons(off, translate('启用')).length, 1);
  assert.equal(buttons(shown, translate('访问与限速')).length, 2, 'only running public ends have limits');
  translated(shown, 'panel');
  await press(button(web, translate('复制')));
  assert.equal(copied, 'gw.example.net:20005');

  // All forwarding lists the public end with its tunnel, not as a path of its own.
  const roots = context.forwardingRootsWithoutTunnels({ nodes, configs: [publicConfig, { node_id: 'home', revision: 1, rules: [{ id: 'rt-web', name: 'same id elsewhere', listen: '0.0.0.0:80', protocol: 'tcp', targets: [{ address: '127.0.0.1:8080', weight: 1 }] }] }] });
  assert.deepEqual(JSON.parse(JSON.stringify(roots)), [{ node_id: 'pub', rule_id: 'r1' }, { node_id: 'pub', rule_id: 'r2' }, { node_id: 'pub', rule_id: 'r3' }, { node_id: 'home', rule_id: 'rt-web' }]);

  // New: private servers are those of the public server's tenant except itself; Auto picks the
  // lowest port of the forwarding range that no rule (single, range or gateway port), no other
  // tunnel (public or tunnel port) and not the form's own tunnel port holds.
  await context.openReverseTunnel();
  assert.equal(field('public_node_id').value, 'pub');
  assert.deepEqual(field('private_node_id').children.map(o => o.value), ['home', 'office']);
  field('public_node_id').value = 'x-pub'; await field('public_node_id').fire('change');
  assert.deepEqual(field('private_node_id').children.map(o => o.value), ['x-home']);
  await assert.rejects(press(button(form, translate('自动选择'))), exactly('公网服务器没有设置转发端口范围；请手动填写公网端口，或先在服务器的转发设置中设置端口范围。'));
  field('public_node_id').value = 'pub'; await field('public_node_id').fire('change');
  field('tunnel_port').value = '20008';
  await press(button(form, translate('自动选择')));
  // 20000 rule · 20001–20003 range · 20004 gateway · 20005 web · 20006/20007 game · 20008 the
  // form's tunnel port · 20009 old · 20010 broken: each skipped check would pick a lower port.
  assert.equal(field('public_port').value, '20011');
  translated(form, 'new tunnel dialog');
  assert.ok(form.text().includes(translate('目标里的 127.0.0.1 指内网服务器自己；也可以填写内网服务器能访问的局域网地址，例如 192.168.10.20:8080。')));
  field('tunnel_name').value = ' Home lab '; field('private_node_id').value = 'office'; field('protocol').value = 'tcp_udp';
  const before = calls.length;
  field('target').value = '192.168.10.20';
  await assert.rejects(send(), exactly('目标必须是 host:端口，例如 127.0.0.1:8080 或 192.168.10.20:8080。'));
  field('target').value = '192.168.10.20:8080';
  field('public_port').value = '20008';
  await assert.rejects(send(), exactly('公网端口和隧道端口不能相同。'));
  field('public_port').value = '20011';
  await send();
  assert.equal(calls.length, before + 1, 'invalid input sends nothing');
  assert.deepEqual(calls.at(-1), { path: '/reverse-tunnels', method: 'POST', body: { name: 'Home lab', public_node_id: 'pub', private_node_id: 'office', public_port: 20011, listen_ip: null, protocol: 'tcp_udp', target: '192.168.10.20:8080', tunnel_port: 20008, enabled: true } });

  // Edit keeps the switch and the advanced fields; Auto may reuse the tunnel's own port and rule.
  await context.openReverseTunnel(tunnels[1]);
  assert.equal(field('listen_ip').value, '203.0.113.5');
  assert.equal(field('tunnel_port').value, '20007');
  await press(button(form, translate('自动选择')));
  assert.equal(field('public_port').value, '20006', 'its own public port is free for it');
  await context.openReverseTunnel(tunnels[0]);
  assert.equal(field('private_node_id').value, 'home');
  await press(button(form, translate('自动选择')));
  assert.equal(field('public_port').value, '20005', 'its own public end does not hold its port');
  field('target').value = '[fd00::20]:8443'; field('listen_ip').value = ' ';
  await send();
  assert.deepEqual(last('/reverse-tunnels/web'), { path: '/reverse-tunnels/web', method: 'PUT', body: { name: 'web', public_node_id: 'pub', private_node_id: 'home', public_port: 20005, listen_ip: null, protocol: 'tcp_udp', target: '[fd00::20]:8443', tunnel_port: 29123, enabled: true } });
  await context.openReverseTunnel(tunnels[5]);
  await send();
  assert.equal(last('/reverse-tunnels/off').body.enabled, false, 'saving a disabled tunnel keeps it disabled');
  translated(form, 'edit dialog');

  // Disable asks first and sends the tunnel unchanged but switched; Enable does not ask.
  confirmed = false;
  await context.switchReverseTunnel(tunnels[1]);
  assert.equal(last('/reverse-tunnels/game'), undefined);
  confirmed = true;
  await context.switchReverseTunnel(tunnels[1]);
  assert.deepEqual(last('/reverse-tunnels/game').body, { name: 'game', public_node_id: 'pub', private_node_id: 'home', public_port: 20006, listen_ip: '203.0.113.5', protocol: 'tcp', target: '127.0.0.1:8080', tunnel_port: 20007, enabled: false });
  confirmed = false;
  await context.switchReverseTunnel(tunnels[5]);
  assert.equal(last('/reverse-tunnels/off').method, 'PUT');
  assert.equal(last('/reverse-tunnels/off').body.enabled, true);
  // Delete only after confirmation.
  await context.deleteReverseTunnel(tunnels[4]);
  assert.equal(last('/reverse-tunnels/gone'), undefined);
  confirmed = true;
  await context.deleteReverseTunnel(tunnels[4]);
  assert.deepEqual(last('/reverse-tunnels/gone'), { path: '/reverse-tunnels/gone', method: 'DELETE', body: undefined });

  // Access and limits change only those fields of the public end, at the read revision.
  await context.limitReverseTunnel(tunnels[0]);
  assert.equal(field('deny_sources').value, '198.51.100.7/32');
  translated(form, 'limits dialog');
  field('allow_sources').value = '203.0.113.0/24\n 2001:db8::/32 \n';
  field('deny_sources').value = '';
  field('rate_bytes_per_sec').value = '1.5';
  await assert.rejects(send(), exactly('速率必须是正整数 bytes/s，留空不限。'));
  field('rate_bytes_per_sec').value = '125000'; field('max_connections').value = '7';
  await send();
  const published = last('/nodes/pub/config');
  assert.equal(published.method, 'PUT');
  assert.equal(published.body.expected_revision, 12);
  assert.deepEqual(published.body.rules.slice(0, 3), publicConfig.rules.slice(0, 3), 'other rules are sent unchanged');
  assert.deepEqual(published.body.rules[3], { ...publicConfig.rules[3], allow_sources: ['203.0.113.0/24', '2001:db8::/32'], deny_sources: [], rate_bytes_per_sec: 125000, max_connections: 7 });
  await assert.rejects(context.limitReverseTunnel({ ...tunnels[1], rule_id: 'rt-missing' }), exactly('公网端还没有运行；两台服务器就绪后再设置。'));
  console.log(`Reverse tunnels (${i18n.getLanguage()}): panel shows states, reasons, entries and traffic; New filters private servers by tenant and Auto skips rule, range, gateway, tunnel and own tunnel ports; edit, disable, delete and access limits send the expected bodies`);
})().catch(error => { console.error(error); process.exitCode = 1; });
