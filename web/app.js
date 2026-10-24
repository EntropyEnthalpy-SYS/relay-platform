const $ = (s, root = document) => root.querySelector(s);
const state = { token: sessionStorage.getItem('relay-session'), actor: null, view: 'nodes', nodes: [], usage: [], selectedNode: null, config: null, busy: false };
const titles = { nodes: '节点总览', rules: '转发规则', usage: '流量账本', budgets: '共享额度', users: '用户与权限', audit: '操作审计', recovery: '恢复保护', capabilities: '功能进度' };
const roleNames = { system_admin: '系统管理员', tenant_admin: '租户管理员', viewer: '只读用户' };
const canWrite = () => state.actor?.role !== 'viewer';
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notify(message, failure = false) { const n = $('#notification'); n.textContent = message; n.classList.remove('hidden'); n.classList.toggle('failure', failure); }
function button(text, handler, cls = 'subtle') { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', () => Promise.resolve().then(handler).catch(e => notify(e.message, true))); return n; }
function bytes(n) { n = Number(n); if (!n) return '0 B'; const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1); return `${(n / 1024 ** i).toFixed(i ? 2 : 0)} ${u[i]}`; }
function timestamp(n) { return n ? new Date(n).toLocaleString('zh-CN', { hour12: false }) : '尚未回报'; }
function badge(text, color = '') { return el('span', text, `badge ${color}`); }
function online(node) { return node.last_seen_ms && Date.now() - node.last_seen_ms < 30_000; }
async function api(path, options = {}) {
  const response = await fetch(`/api/v1${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...options.headers }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  const text = await response.text(); let result; try { result = JSON.parse(text); } catch { result = { error: text || `HTTP ${response.status}` }; }
  if (!response.ok) { if (response.status === 401 && path !== '/auth/login') loggedOut(); throw new Error(result.error || `请求失败 HTTP ${response.status}`); } return result;
}
function loggedOut() { state.token = null; state.actor = null; sessionStorage.removeItem('relay-session'); $('#application').classList.add('hidden'); $('#login-screen').classList.remove('hidden'); $('#dialog').close(); }
function modal(title, content) { $('#dialog-title').textContent = title; $('#dialog-body').replaceChildren(content); $('#dialog').showModal(); }
$('#dialog-close').onclick = () => { $('#dialog').close(); $('#dialog-body').replaceChildren(); };
$('#dialog').addEventListener('close', () => $('#dialog-body').replaceChildren());
function panel(title, description, action) { const n = el('section', undefined, 'panel'); const head = el('div', undefined, 'panel-head'); const info = el('div'); info.append(el('h2', title)); if (description) info.append(el('p', description)); head.append(info); if (action) head.append(action); n.append(head); return n; }
function empty(title, description, action) { const n = el('div', undefined, 'empty'); n.append(el('div', '◇', 'empty-symbol'), el('h2', title), el('p', description)); if (action) n.append(action); return n; }
function table(headers, rows) { const wrap = el('div', undefined, 'table-wrap'), t = el('table'), head = el('thead'), tr = el('tr'), body = el('tbody'); headers.forEach(h => tr.append(el('th', h))); head.append(tr); rows.forEach(values => { const row = el('tr'); values.forEach(value => { const cell = el('td'); value instanceof Node ? cell.append(value) : cell.textContent = value; row.append(cell); }); body.append(row); }); t.append(head, body); wrap.append(t); return wrap; }
function namedCell(name, detail) { const n = el('div'); n.append(el('strong', name), el('div', detail, 'subline mono')); return n; }
function field(form, name, text, value = '', type = 'text', required = true) { const label = el('label', text); const input = el('input'); input.name = name; input.type = type; input.value = value ?? ''; input.required = required; label.append(input); form.append(label); return input; }
function select(form, name, text, options, value) { const label = el('label', text), input = el('select'); input.name = name; options.forEach(([id, label]) => { const option = el('option', label); option.value = id; input.append(option); }); input.value = value; label.append(input); form.append(label); return input; }
function textarea(form, name, text, value = '', required = false) { const label = el('label', text), input = el('textarea'); input.name = name; input.value = value; input.required = required; label.append(input); form.append(label); return input; }
function submit(form, text, handler) { const actions = el('div', undefined, 'dialog-actions'); actions.append(button('取消', () => $('#dialog').close())); const save = el('button', text, 'primary'); save.type = 'submit'; actions.append(save); form.append(actions); const error = el('p', undefined, 'error'); error.setAttribute('role', 'alert'); form.append(error); form.onsubmit = async e => { e.preventDefault(); save.disabled = true; error.textContent = ''; try { await handler(new FormData(form)); } catch (err) { error.textContent = err.message; } finally { save.disabled = false; } }; }
function number(data, key) { const raw = data.get(key); if (raw === '') return null; const n = Number(raw); if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${key} 必须为安全范围内的非负整数`); return n; }
function targetEditor(form, targets) {
  const container = el('div'), rows = []; let serial = 0;
  function add(target = { address: '', weight: 1 }) {
    if (rows.length >= 32) return;
    const id = serial++, box = el('fieldset', undefined, 'target-editor'), grid = el('div', undefined, 'form-grid');
    box.append(el('legend', '转发目标'));
    const address = field(grid, `target-address-${id}`, '目标地址 / host:port', target.address);
    const weight = field(grid, `target-weight-${id}`, '权重', target.weight, 'number'); weight.min = 1; weight.max = 1000;
    const mode = select(grid, `target-mode-${id}`, '连接目标的安全方式', [['plain', '普通 TCP / UDP'], ['tls', 'TLS（验证目标证书）']], target.tls ? 'tls' : 'plain'); box.append(grid);
    const secure = el('div', undefined, 'form-grid');
    const name = field(secure, `target-server-name-${id}`, '证书中的服务名或 IP', target.tls?.server_name || '', 'text', false);
    const ca = field(secure, `target-ca-${id}`, 'CA 编号（留空使用公共 CA）', target.tls?.ca || '', 'text', false);
    const identity = field(secure, `target-identity-${id}`, '客户端证书编号（双向认证时填写）', target.tls?.identity || '', 'text', false);
    const row = { box, address, weight, mode, name, ca, identity }; rows.push(row);
    function showSecurity() { const enabled = mode.value === 'tls'; secure.classList.toggle('hidden', !enabled); name.required = enabled; [name, ca, identity].forEach(input => { input.disabled = !enabled; }); }
    mode.onchange = showSecurity; showSecurity(); box.append(secure, button('移除此目标', () => { rows.splice(rows.indexOf(row), 1); box.remove(); }, 'table-action danger')); container.append(box);
  }
  targets.forEach(add); form.append(container, button('＋ 添加目标', () => add()));
  return () => { if (!rows.length) throw new Error('至少保留一个转发目标'); return rows.map(row => ({ address: row.address.value.trim(), weight: Number(row.weight.value), ...(row.mode.value === 'tls' ? { tls: { server_name: row.name.value.trim(), ca: row.ca.value.trim() || null, identity: row.identity.value.trim() || null } } : {}) })); };
}

$('#login-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, b = $('button', form); b.disabled = true; $('#login-error').textContent = ''; try { const f = new FormData(form); const result = await api('/auth/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password') } }); state.token = result.token; state.actor = result.user; sessionStorage.setItem('relay-session', result.token); $('[name=password]', form).value = ''; await enter(); } catch (error) { $('#login-error').textContent = error.message; } finally { b.disabled = false; } };
document.querySelectorAll('[data-logout]').forEach(b => { b.onclick = async () => { try { await api('/auth/logout', { method: 'POST' }); } finally { loggedOut(); } }; });
$('#refresh').onclick = () => refresh().catch(e => notify(e.message, true));
document.querySelectorAll('[data-view]').forEach(n => n.addEventListener('click', () => navigate(n.dataset.view)));
async function enter() { $('#login-screen').classList.add('hidden'); $('#application').classList.remove('hidden'); $('#identity').textContent = `${state.actor.username} · ${roleNames[state.actor.role]}`; document.querySelectorAll('.admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role !== 'system_admin')); await refresh(); }
async function navigate(view) { state.view = view; $('#notification').classList.add('hidden'); document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === view)); $('#view-title').textContent = titles[view]; try { await refresh(); } catch (e) { notify(e.message, true); } }
async function refresh() {
  if (!state.actor || state.busy) return; const requestedView = state.view, requestedNode = state.selectedNode; state.busy = true; $('#refresh').disabled = true;
  try { await ({ nodes: renderNodes, rules: renderRules, usage: renderUsage, budgets: renderBudgets, users: renderUsers, audit: renderAudit, recovery: renderRecovery, capabilities: renderCapabilities })[state.view](); $('#refreshed').textContent = `更新于 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`; }
  finally { state.busy = false; $('#refresh').disabled = false; if (state.actor && (state.view !== requestedView || (requestedView === 'rules' && requestedNode !== state.selectedNode))) queueMicrotask(() => refresh().catch(e => notify(e.message, true))); }
}

async function renderNodes() {
  const [nodes, usage] = await Promise.all([api('/nodes'), api('/usage')]); state.nodes = nodes; state.usage = usage;
  const metric = el('div', undefined, 'metrics');
  [['节点总数', nodes.length, '当前账号可见的节点'], ['控制在线', nodes.filter(online).length, '最近 30 秒收到心跳'], ['活跃连接', nodes.filter(online).reduce((s, n) => s + n.stats.active_tcp + n.stats.active_udp, 0), '在线节点的 TCP + UDP 会话'], ['近期上报负载', bytes(usage.reduce((s, u) => s + u.upload_bytes + u.download_bytes, 0)), '最近 2,000 个计量周期 · 上下行合计']].forEach(([title, value, foot]) => { const n = el('div', undefined, 'metric'); n.append(el('div', title, 'metric-label'), el('div', String(value), 'metric-value'), el('div', foot, 'metric-foot')); metric.append(n); });
  const p = panel('节点', '注册节点、确认配置生效，并检查实际回报。', canWrite() ? button('＋ 注册节点', newNode, 'primary') : null);
  if (!nodes.length) p.append(empty('接入你的第一个节点', '注册生成一次性令牌，在节点启动 Agent 后即可配置转发。', canWrite() ? button('注册节点', newNode, 'primary') : null));
  else p.append(table(['节点 / ID', '控制连接', '配置修订', '活跃会话', '最近回报', '操作'], nodes.map(node => [namedCell(node.name, node.id), badge(node.enrolled ? online(node) ? '● 控制在线' : '○ 无近期回报' : '待注册', online(node) ? 'green' : ''), node.apply_error ? namedCell(`应用失败 · ${node.applied_revision} / ${node.desired_revision}`, node.apply_error) : badge(`${node.applied_revision} / ${node.desired_revision}`, node.applied_revision === node.desired_revision && node.enrolled ? 'green' : 'orange'), online(node) ? `${node.stats.active_tcp} TCP / ${node.stats.active_udp} UDP` : '—', timestamp(node.last_seen_ms), button('管理规则 →', async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action')])));
  if (state.view === 'nodes') $('#content').replaceChildren(metric, p);
}
function newNode() { const form = el('form'); field(form, 'name', '节点名称', '', 'text').maxLength = 120; form.append(el('p', '节点归属当前租户；注册令牌仅显示一次，并在成功注册后失效。', 'fine')); submit(form, '创建节点', async data => { const result = await api('/nodes', { method: 'POST', body: { name: data.get('name') } }); const body = el('div'); body.append(el('p', '请将此令牌保存为节点上的私有文件（权限 0600）。'), el('div', result.enrollment_token, 'secret-box')); const command = `relay agent --controller ${location.origin} --node-id ${result.node.id} --enrollment-token-file /path/to/enrollment.secret --state /var/lib/relay-agent`; body.append(el('p', '节点启动命令', 'fine'), el('pre', command), el('p', '跨机器接入须使用 HTTPS 控制地址。本机 HTTP 地址仅用于本地验收。', 'fine'), button('我已保存令牌', () => $('#dialog').close(), 'primary')); $('#dialog').close(); modal('节点已创建 · 保存一次性令牌', body); state.selectedNode = result.node.id; await renderNodes(); }); modal('注册节点', form); }

async function renderRules() {
  state.nodes = await api('/nodes'); const content = $('#content');
  if (!state.nodes.length) { content.replaceChildren(empty('还没有节点', '先注册节点，再创建规则。', button('前往节点总览', () => navigate('nodes'), 'primary'))); return; }
  if (!state.nodes.some(n => n.id === state.selectedNode)) state.selectedNode = state.nodes[0].id;
  const toolbar = el('div', undefined, 'toolbar'), selector = el('select'); selector.setAttribute('aria-label', '选择节点'); state.nodes.forEach(n => { const option = el('option', n.name); option.value = n.id; selector.append(option); }); selector.value = state.selectedNode; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; toolbar.append(selector);
  const nodeId = state.selectedNode; const config = await api(`/nodes/${nodeId}/config`); if (state.view !== 'rules' || state.selectedNode !== nodeId) return; state.config = config;
  toolbar.append(badge(`期望修订 v${config.revision}`), button('版本历史', history));
  const p = panel('转发规则', '配额按上下行接纳字节合计。更改安全策略会终止关联会话。', canWrite() ? button('＋ 添加规则', () => editRule(), 'primary') : null);
  if (!config.rules.length) p.append(empty('创建一条真实转发规则', '支持 TCP、UDP 和双协议，可设置多个目标、配额、速率和来源网段。', canWrite() ? button('添加规则', () => editRule(), 'primary') : null));
  else p.append(table(['名称', '监听 / 协议', '目标', '配额 / 限速', '状态', '操作'], config.rules.map(rule => { const actions = el('div'); if (canWrite()) { actions.append(button('编辑', () => editRule(rule), 'table-action'), button(rule.enabled ? '停用' : '启用', () => saveRules(config.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r), config), 'table-action'), button('删除', async () => { if (confirm(`删除「${rule.name}」会终止其会话，历史账本保留。`)) await saveRules(config.rules.filter(r => r.id !== rule.id), config); }, 'table-action danger')); } return [namedCell(rule.name, rule.id), namedCell(rule.listen, rule.protocol.toUpperCase()), namedCell(rule.targets[0].address, `${rule.targets.length} 个目标 · ${rule.balance}`), `${rule.quota_bytes === null ? '不限量' : bytes(rule.quota_bytes)} / ${rule.rate_bytes_per_sec === null ? '不限速' : bytes(rule.rate_bytes_per_sec) + '/s'}`, badge(rule.enabled ? '已启用' : '已停用', rule.enabled ? 'green' : ''), actions]; })));
  content.replaceChildren(toolbar, p);
}
async function saveRules(rules, baseConfig) { const expected_revision = baseConfig.revision; await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision, rules } }); $('#dialog').close(); notify('配置已发布。请在节点总览确认实际应用修订号。'); await renderRules(); }
function editRule(existing) {
  const baseConfig = state.config; const form = el('form'), grid = el('div', undefined, 'form-grid'), r = existing || {};
  field(grid, 'name', '规则名称', r.name || '').maxLength = 120;
  select(grid, 'protocol', '协议', [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], r.protocol || 'tcp');
  field(grid, 'listen', '监听地址', r.listen || '127.0.0.1:9000');
  select(grid, 'balance', '目标分配', [['weighted_round_robin', '加权轮询'], ['source_hash', '来源 IP 哈希'], ['least_connections', '最少连接']], r.balance || 'weighted_round_robin'); form.append(grid);
  const readTargets = targetEditor(form, r.targets || [{ address: '127.0.0.1:8000', weight: 1 }]);
  const transport = el('details'); transport.append(el('summary', '入口 TLS 与客户端认证')); const tlsFields = el('div', undefined, 'form-grid');
  field(tlsFields, 'tls_identity', '入口证书编号（留空使用普通连接）', r.inbound_tls?.identity || '', 'text', false);
  field(tlsFields, 'tls_client_ca', '允许客户端的 CA 编号（留空不要求客户端证书）', r.inbound_tls?.client_ca || '', 'text', false); transport.append(tlsFields, el('p', '证书和私钥预先放在节点本地，面板只保存编号。TLS 仅用于 TCP；一条规则的所有出口必须使用相同的安全方式。', 'fine')); form.append(transport);
  const limits = el('div', undefined, 'form-grid'); field(limits, 'quota_bytes', '合并配额 / bytes（留空不限，0 禁止流量）', r.quota_bytes, 'number', false).min = 0; field(limits, 'rate_bytes_per_sec', '合并速率 / bytes/s（留空不限）', r.rate_bytes_per_sec, 'number', false).min = 1; form.append(limits);
  const details = el('details'); details.append(el('summary', '高级：超时、会话上限、到期和来源网段')); const advanced = el('div', undefined, 'form-grid');
  for (const [name, label, fallback, min, max] of [['connect_timeout_ms', '连接超时 / ms', 5000, 100, 60000], ['idle_timeout_secs', '空闲回收 / 秒', 120, 1, 86400], ['max_connections', 'TCP 最大连接', 4096, 1, 1000000], ['udp_max_sessions', 'UDP 最大会话', 1024, 1, 100000]]) { const input = field(advanced, name, label, r[name] ?? fallback, 'number'); input.min = min; input.max = max; }
  const expiry = field(advanced, 'expires_at_ms', '到期 / Unix 毫秒（留空永不过期）', r.expires_at_ms, 'number', false); expiry.min = 0; details.append(advanced); textarea(details, 'allow_sources', '允许来源 CIDR（留空允许所有未拒绝来源，每行一个）', (r.allow_sources || []).join('\n')); textarea(details, 'deny_sources', '拒绝来源 CIDR（优先于允许列表，每行一个）', (r.deny_sources || []).join('\n')); form.append(details);
  const enabledLabel = el('label', undefined, 'inline-check'), enabled = el('input'); enabled.name = 'enabled'; enabled.type = 'checkbox'; enabled.checked = r.enabled ?? true; enabledLabel.append(enabled, document.createTextNode('启用规则')); form.append(enabledLabel);
  form.append(el('p', '同一规则的所有连接共享额度和速率。速率桶允许 max(64 KiB, 一秒额度) 的突发；这不是跨节点用户总限速。', 'fine'));
  submit(form, existing ? '发布修改' : '创建并发布', async data => {
    const node = state.nodes.find(n => n.id === baseConfig.node_id), lines = key => String(data.get(key)).split('\n').map(s => s.trim()).filter(Boolean);
    const rule = { id: r.id || crypto.randomUUID(), tenant_id: node.tenant_id, owner_id: r.owner_id || state.actor.id, name: data.get('name'), protocol: data.get('protocol'), listen: data.get('listen'), balance: data.get('balance'), enabled: data.get('enabled') === 'on', targets: readTargets(), meter_epoch: r.meter_epoch || crypto.randomUUID(), allow_sources: lines('allow_sources'), deny_sources: lines('deny_sources') };
    const identity = String(data.get('tls_identity')).trim(), clientCa = String(data.get('tls_client_ca')).trim();
    if (clientCa && !identity) throw new Error('要求客户端证书时，请同时填写入口证书编号');
    if (identity) rule.inbound_tls = { identity, client_ca: clientCa || null };
    for (const key of ['quota_bytes', 'rate_bytes_per_sec', 'expires_at_ms', 'connect_timeout_ms', 'idle_timeout_secs', 'max_connections', 'udp_max_sessions']) rule[key] = number(data, key);
    await saveRules(existing ? baseConfig.rules.map(item => item.id === r.id ? rule : item) : [...baseConfig.rules, rule], baseConfig);
  }); modal(existing ? '编辑转发规则' : '添加转发规则', form);
}
async function history() { const baseConfig = state.config; const revisions = await api(`/nodes/${baseConfig.node_id}/history`); const body = table(['修订', '操作者', '时间', '操作'], revisions.map(r => [`v${r.revision}`, r.actor_id, timestamp(r.created_at_ms), canWrite() ? button('发布此版本', async () => { await api(`/nodes/${baseConfig.node_id}/rollback`, { method: 'POST', body: { revision: r.revision, expected_revision: baseConfig.revision } }); $('#dialog').close(); notify('历史配置已作为新修订发布。账本不回滚。'); await renderRules(); }, 'table-action') : '只读'])); modal('最近 100 次配置修订', body); }
async function renderUsage() { const records = await api('/usage'); const p = panel('已接纳应用负载', '累计值按节点、规则与计量周期去重；发送失败也可能已经接纳计量。最多显示最近 2,000 条周期记录。'); if (!records.length) p.append(empty('还没有流量记录', '让一条转发规则通过真实流量，Agent 会在同步后上报。')); else p.append(table(['规则 / 周期', '节点', '上行', '下行', '序号', '最近上报'], records.map(r => [namedCell(r.rule_id, r.meter_epoch), r.node_id, bytes(r.upload_bytes), bytes(r.download_bytes), r.sequence, timestamp(r.reported_at_ms)]))); if (state.view === 'usage') $('#content').replaceChildren(p); }
async function renderUsers() { const users = await api('/users'); const p = panel('用户与会话', '权限由服务端校验；撤销后已有 Web 会话立即失效。', canWrite() ? button('＋ 添加用户', newUser, 'primary') : null); p.append(table(['账号', '角色', '租户', '操作'], users.map(u => [namedCell(u.username, u.id), roleNames[u.role], u.tenant_id, canWrite() || u.id === state.actor.id ? button('撤销全部会话', async () => { await api(`/users/${u.id}/revoke-sessions`, { method: 'POST' }); if (u.id === state.actor.id) loggedOut(); else notify('该用户现有会话已撤销。'); }, 'table-action') : '—']))); if (state.view === 'users') $('#content').replaceChildren(p); }
function newUser() { const form = el('form'); field(form, 'username', '用户名').maxLength = 80; const p = field(form, 'password', '初始密码（至少 12 个字节）', '', 'password'); p.minLength = 12; p.autocomplete = 'new-password'; const roles = [['viewer', '只读用户'], ['tenant_admin', '租户管理员']]; if (state.actor.role === 'system_admin') roles.push(['system_admin', '系统管理员']); select(form, 'role', '角色', roles, 'viewer'); submit(form, '创建用户', async data => { await api('/users', { method: 'POST', body: Object.fromEntries(data) }); $('#dialog').close(); await renderUsers(); }); modal('添加用户', form); }
async function renderAudit() { const rows = await api('/audit'); const p = panel('操作审计', '记录配置发布、节点注册、身份及会话操作。最近 200 条。'); p.append(table(['时间', '操作者', '操作', '对象', '详情'], rows.map(r => [timestamp(r.at_ms), r.actor_id, r.action, r.resource, r.detail]))); if (state.view === 'audit') $('#content').replaceChildren(p); }
async function renderCapabilities() { const c = await api('/capabilities'); const names = { tcp: 'TCP 转发', udp: 'UDP 转发', ipv4: 'IPv4', ipv6: 'IPv6', 'dns-targets': '域名目标', 'weighted-round-robin': '加权轮询', 'source-hash': '来源 IP 哈希', 'least-connections': '最少连接', 'source-cidr-acl': '来源网段 ACL', 'per-rule-quota': '规则共享配额', 'per-rule-bandwidth': '规则共享速率', 'durable-usage': '持久化流量账本', 'config-revisions': '版本与回滚', 'tenant-isolation': '租户隔离', 'session-revocation': '会话撤销', 'tls-data-transport': 'TLS 数据传输', 'mutual-tls': 'TLS 双向证书认证', 'backup-reconciliation': '旧备份用量对账', websocket: 'WebSocket 隧道', mptcp: 'MPTCP', 'multipath-aggregation': '单连接多路径聚合', 'global-user-budgets': '跨节点用户总额度', 'hierarchical-budgets': '租户 / 节点分层额度', 'budget-reservation-return': '空闲预留归还', 'controller-recovery-log': '控制器恢复日志', 'budget-disaster-recovery': '预算完整灾难恢复', 'global-rate-limits': '跨节点总限速', wireguard: 'WireGuard 组网', 'nat-traversal': 'NAT 穿透', commerce: '套餐与交易', subscriptions: '客户端订阅', 'dns-management': 'DNS 管理', federation: '跨面板共享', 'postgresql-ha': 'PostgreSQL 与控制面高可用' }; const grid = el('div', undefined, 'capabilities'); for (const [title, list, status, color] of [['已接入开发版本', c.available, '可用', 'green'], ['后续完整范围', c.pending, '待实现', '']]) { const p = panel(title, '最终验收以源码中的完整清单和测试证据为准。'), body = el('div', undefined, 'panel-body'); for (const key of list) { const row = el('div', undefined, 'capability'); row.append(el('span', names[key] || key), badge(status, color)); body.append(row); } p.append(body); grid.append(p); } if (state.view === 'capabilities') $('#content').replaceChildren(grid); }

setInterval(() => { if (state.actor && !document.hidden && !$('#dialog').open && ['nodes', 'usage', 'budgets', 'recovery'].includes(state.view)) refresh().catch(e => notify(e.message, true)); }, 5000);
if (state.token) { api('/session').then(user => { state.actor = user; return enter(); }).catch(e => { loggedOut(); $('#login-error').textContent = e.message; }); }

const budgetScopeNames = { user: '用户', tenant: '租户', node: '节点' };
async function renderBudgets() {
  const [overview, users, nodes] = await Promise.all([api('/budgets'), api('/users'), api('/nodes')]);
  const p = panel('跨节点共享额度', '已用 + 尚未归还的预留不能超过总额度。同一笔流量受适用的用户、租户和节点额度共同约束。', canWrite() && !overview.allocation_paused ? button('＋ 创建额度', () => editBudget(null, users, nodes), 'primary') : null);
  if (overview.allocation_paused) p.append(el('p', '控制器已从备份恢复，新增额度分配暂停。恢复完整的预留记录前，系统不会重复发放旧备份中遗漏的额度。', 'error'));
  function scopeLabel(b) { return b.scope === 'user' ? users.find(u => u.id === b.scope_id)?.username || b.scope_id : b.scope === 'node' ? nodes.find(n => n.id === b.scope_id)?.name || b.scope_id : b.scope_id; }
  if (!overview.budgets.length) p.append(empty('为多个入口设置一个总额度', '创建前先暂停该范围内的规则，并确认所有相关节点已应用；之后重新启用规则，系统会自动绑定额度。'));
  else p.append(table(['名称 / 范围', '总额度', '已上报用量', '尚未归还预留', '可分配', '操作'], overview.budgets.map(b => [namedCell(b.name, `${budgetScopeNames[b.scope]} · ${scopeLabel(b)}`), bytes(b.limit_bytes), bytes(b.consumed_bytes), bytes(b.committed_bytes - b.consumed_bytes), bytes(b.limit_bytes - b.committed_bytes), canWrite() && !overview.allocation_paused ? button('调整额度', () => editBudget(b, users, nodes), 'table-action') : '只读'])));
  p.append(el('p', '节点按需领取预留。全节点会话空闲或正常停机后可归还未用部分；异常退出留下的未确认预留会继续占用额度。增加总额度不会清零已有账。', 'fine'));
  if (state.view === 'budgets') $('#content').replaceChildren(p);
}
function editBudget(existing, users, nodes) {
  const form = el('form');
  if (!existing) {
    field(form, 'name', '额度名称').maxLength = 120;
    const scope = select(form, 'scope', '适用范围', [['user', '用户：跨节点共享'], ['tenant', '租户：包含租户内所有用户'], ['node', '节点：包含节点所有规则']], 'user');
    const target = select(form, 'scope_id', '选择对象', [], '');
    function showTargets() {
      const options = scope.value === 'user' ? users.map(u => [u.id, `${u.username} · ${u.tenant_id}`]) : scope.value === 'node' ? nodes.map(n => [n.id, n.name]) : [...new Set([state.actor.tenant_id, ...users.map(u => u.tenant_id)])].map(id => [id, id]);
      target.replaceChildren(); options.forEach(([id, label]) => { const option = el('option', label); option.value = id; target.append(option); }); target.required = true;
    }
    scope.onchange = showTargets; showTargets();
  } else form.append(el('p', `${existing.name} · 修订 ${existing.revision}。调整下限为已用与尚未归还预留的合计。`, 'fine'));
  const limit = field(form, 'limit_bytes', '总额度 / bytes（0 禁止新增分配）', existing?.limit_bytes ?? 1073741824, 'number'); limit.min = existing?.committed_bytes ?? 0;
  const quantum = field(form, 'quantum_bytes', '目标预留大小 / bytes', existing?.quantum_bytes ?? 4194304, 'number'); quantum.min = 1; quantum.max = 67108864;
  form.append(el('p', '较大的预留减少补额频率，但失联后会占用更多未确认额度。为容纳一个 UDP 报文，单次预留可能提高到报文所需大小，最大 64 KiB。', 'fine'));
  submit(form, existing ? '保存额度' : '创建额度', async data => {
    const body = { limit_bytes: number(data, 'limit_bytes'), quantum_bytes: number(data, 'quantum_bytes') };
    if (existing) { body.expected_revision = existing.revision; await api(`/budgets/${existing.id}`, { method: 'PUT', body }); }
    else { Object.assign(body, { name: data.get('name'), scope: data.get('scope'), scope_id: data.get('scope_id') }); await api('/budgets', { method: 'POST', body }); }
    $('#dialog').close(); await renderBudgets();
  });
  modal(existing ? '调整共享额度' : '创建共享额度', form);
}

async function renderRecovery() {
  const [status, metrics] = await Promise.all([api('/recovery'), api('/control/metrics')]);
  const p = panel('控制器恢复保护', '将数据库备份与最新恢复日志、进度清单一起保管。恢复会重放备份之后已经确认的变更。');
  const body = el('div', undefined, 'panel-body');
  body.append(badge(status.enabled && status.healthy ? '已启用 · 写入正常' : status.enabled ? '写入停止 · 需要检查' : '未启用', status.enabled && status.healthy ? 'green' : ''));
  if (status.head) body.append(table(['项目', '当前已确认记录'], [
    ['日志身份', status.head.journal_id], ['事务序号', String(status.head.sequence)],
    ['已提交日志大小', bytes(status.head.committed_bytes)], ['当前校验值', status.head.sha256]
  ]));
  body.append(el('p', '恢复前停止原控制器，使用完整日志及其最新进度清单，将恢复结果写入一个新的状态目录。原备份和日志保持原样。只有备份而缺少后续日志时，无法推断遗漏的额度分配。', 'fine'));
  const command = el('pre', 'relay restore --backup backups/controller.sqlite --recovery-log state/controller/recovery.log --output state/restored-controller', 'mono');
  body.append(command, el('p', '恢复日志包含身份和配置数据，须按数据库的私有权限保护。当前保护覆盖控制器记录；节点异常退出后的未知消费、密钥目录迁移、自动归档和异地日志复制仍需后续完善。', 'fine'));
  body.append(el('h3', '节点同步'), el('p', '本次控制器运行期间的同步统计。队列拥塞时节点会稍后重试；提交完成后才确认额度和用量。', 'fine'), table(['项目', '次数'], [
    ['已处理请求', metrics.processed_requests], ['完成提交批次', metrics.committed_batches],
    ['最大合并请求数', metrics.largest_batch], ['拥塞退回', metrics.queue_full_rejections], ['提交失败', metrics.failed_batches]
  ]));
  p.append(body); if (state.view === 'recovery') $('#content').replaceChildren(p);
}
