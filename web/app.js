const $ = (s, root = document) => root.querySelector(s);
const state = { token: sessionStorage.getItem('relay-session'), actor: null, view: 'overview', overviewFilter: '', nodes: [], usage: [], nodeFilter: {}, selectedNodes: new Set(), selectedNode: null, dnsZone: null, config: null, busy: false };
const titles = { overview: '运行总览', nodes: '节点管理', rules: '转发规则', topology: '多跳拓扑', health: '目标健康', usage: '流量账本', subscriptions: '客户端订阅', dns: 'DNS 管理', announcements: '公告', commerce: '钱包与订单', tickets: '工单', templates: '规则模板', budgets: '共享额度', users: '用户与权限', account: '账户安全', audit: '操作审计', alerts: '告警通知', recovery: '恢复保护', capabilities: '功能进度' };
const roleNames = { system_admin: '系统管理员', tenant_admin: '租户管理员', viewer: '只读用户' };
const canWrite = () => state.actor?.role !== 'viewer';
const scopeNames = { read: '读取全部可见数据', 'nodes:write': '节点与配置写入', 'budgets:write': '共享额度写入', 'users:write': '用户与租户写入' };
// Dark is the stylesheet default; a saved choice of light overrides it.
// Switch without per-element color fades, which briefly mix the two themes.
const applyTheme = theme => { const root = document.documentElement; root.classList.add('theme-switching'); root.dataset.theme = theme; localStorage.setItem('relay-theme', theme); requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('theme-switching'))); };
if (localStorage.getItem('relay-theme') === 'light') applyTheme('light');
$('#theme').onclick = () => applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
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
  if (!response.ok) { if (response.status === 401 && path !== '/auth/login') loggedOut(); throw Object.assign(new Error(result.error || `请求失败 HTTP ${response.status}`), { detail: result }); } return result;
}
function loggedOut() { state.token = null; state.actor = null; state.nodes = []; state.nodeFilter = {}; state.selectedNodes.clear(); sessionStorage.removeItem('relay-session'); resetSecondFactor(); $('#application').classList.add('hidden'); $('#login-screen').classList.remove('hidden'); $('#dialog').close(); }
function modal(title, content) { $('#dialog-title').textContent = title; $('#dialog-body').replaceChildren(content); $('#dialog').showModal(); }
$('#dialog-close').onclick = () => { $('#dialog').close(); $('#dialog-body').replaceChildren(); };
// The close event is queued; a follow-up modal may already have reopened the dialog with new content.
$('#dialog').addEventListener('close', () => { if (!$('#dialog').open) $('#dialog-body').replaceChildren(); });
function panel(title, description, action) { const n = el('section', undefined, 'panel'); const head = el('div', undefined, 'panel-head'); const info = el('div'); info.append(el('h2', title)); if (description) info.append(el('p', description)); head.append(info); if (action) head.append(action); n.append(head); return n; }
function empty(title, description, action) { const n = el('div', undefined, 'empty'); n.append(el('div', '◇', 'empty-symbol'), el('h2', title), el('p', description)); if (action) n.append(action); return n; }
function table(headers, rows) { const wrap = el('div', undefined, 'table-wrap'), t = el('table'), head = el('thead'), tr = el('tr'), body = el('tbody'); headers.forEach(h => tr.append(el('th', h))); head.append(tr); rows.forEach(values => { const row = el('tr'); values.forEach(value => { const cell = el('td'); value instanceof Node ? cell.append(value) : cell.textContent = value; row.append(cell); }); body.append(row); }); t.append(head, body); wrap.append(t); return wrap; }
function namedCell(name, detail) { const n = el('div'); n.append(el('strong', name), el('div', detail, 'subline mono')); return n; }
function field(form, name, text, value = '', type = 'text', required = true) { const label = el('label', text); const input = el('input'); input.name = name; input.type = type; input.value = value ?? ''; input.required = required; label.append(input); form.append(label); return input; }
function select(form, name, text, options, value) { const label = el('label', text), input = el('select'); input.name = name; options.forEach(([id, label]) => { const option = el('option', label); option.value = id; input.append(option); }); input.value = value; label.append(input); form.append(label); return input; }
function textarea(form, name, text, value = '', required = false) { const label = el('label', text), input = el('textarea'); input.name = name; input.value = value; input.required = required; label.append(input); form.append(label); return input; }
function checkbox(form, name, text) { const label = el('label', text), input = el('input'); input.type = 'checkbox'; input.name = name; label.prepend(input); form.append(label); return input; }
function submit(form, text, handler) { const actions = el('div', undefined, 'dialog-actions'); actions.append(button('取消', () => $('#dialog').close())); const save = el('button', text, 'primary'); save.type = 'submit'; actions.append(save); form.append(actions); const error = el('p', undefined, 'error'); error.setAttribute('role', 'alert'); form.append(error); form.onsubmit = async e => { e.preventDefault(); save.disabled = true; error.textContent = ''; try { await handler(new FormData(form)); } catch (err) { error.textContent = err.message; } finally { save.disabled = false; } }; }
function number(data, key) { const raw = data.get(key); if (raw === '') return null; const n = Number(raw); if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${key} 必须为安全范围内的非负整数`); return n; }
function websocketEditor(id, spec, inbound, defaultHost = () => '') {
  const box = el('details'); box.open = !!spec; box.append(el('summary', inbound ? '入口 WebSocket / WSS 隧道' : '出口 WebSocket / WSS 隧道'));
  const mode = select(box, `${id}-mode`, 'WebSocket 封装', [['off', '关闭'], ['on', '启用 · TCP 流隧道']], spec ? 'on' : 'off');
  const fields = el('div', undefined, 'form-grid');
  const path = field(fields, `${id}-path`, '路径（含可选查询参数，须与对端完全一致）', spec?.path || '/relay'); path.maxLength = 1024;
  const host = field(fields, `${id}-host`, inbound ? '允许的 Host（留空不限，可带端口）' : 'HTTP Host（可带端口，与 TLS 服务名分别配置）', spec?.host || (inbound ? '' : defaultHost()), 'text', !inbound); host.maxLength = 255;
  const origins = inbound ? textarea(fields, `${id}-origins`, '允许的浏览器 Origin（每行一个，留空拒绝携带 Origin 的连接）', (spec?.allowed_origins || []).join('\n')) : field(fields, `${id}-origin`, '发送的 Origin（节点连接通常留空）', spec?.origin || '', 'text', false);
  if (!inbound) origins.maxLength = 512;
  function show() { const enabled = mode.value === 'on'; fields.classList.toggle('hidden', !enabled); fields.querySelectorAll('input, textarea').forEach(input => { input.disabled = !enabled; }); if (enabled && !inbound && !host.value) host.value = defaultHost(); }
  mode.addEventListener('change', show); show();
  box.append(fields, el('p', '两端使用 relay-stream-v1 子协议。启用对应 TLS 后即为 WSS；只支持 TCP，不承载 UDP。Origin 不是登录凭据，未携带 Origin 的节点连接仍按来源与证书策略检查。', 'fine'));
  return { box, read: () => mode.value === 'off' ? null : { path: path.value.trim(), host: host.value.trim() || null, ...(inbound ? { allowed_origins: origins.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean) } : { origin: origins.value.trim() || null }) } };
}
function targetEditor(form, targets, topology, sourceTenant, currentRule, multipathPaths, multipathMode) {
  const container = el('div'), rows = []; let serial = 0;
  function add(target = { address: '', weight: 1 }, path = {}) {
    if (rows.length >= 32) return;
    const id = serial++, box = el('fieldset', undefined, 'target-editor'), grid = el('div', undefined, 'form-grid');
    box.append(el('legend', '转发目标'));
    const address = field(grid, `target-address-${id}`, '目标地址 / host:port', target.address);
    const endpoints = (topology?.configs || []).flatMap(config => config.rules.filter(rule => rule.advertise && rule.tenant_id === sourceTenant && rule.id !== currentRule).map(rule => ({ key: `${config.node_id}/${rule.id}`, config, rule })));
    const selected = target.via ? `${target.via.node_id}/${target.via.rule_id}` : '';
    const choices = [['', '外部目标 · 手动输入地址'], ...endpoints.map(item => [item.key, `${topology.nodes.find(node => node.id === item.config.node_id)?.name || item.config.node_id} → ${item.rule.name}`])];
    if (selected && !choices.some(([key]) => key === selected)) choices.push([selected, '当前引用暂不可选择 · 保留原配置']);
    const via = select(grid, `target-via-${id}`, '下一跳规则（聚合模式下须选择同一汇聚规则）', choices, selected);
    function chooseEndpoint(update) { const endpoint = endpoints.find(item => item.key === via.value); address.readOnly = !!via.value && !endpoint?.rule.inbound_multipath; if (update && endpoint) address.value = endpoint.rule.advertise; }
    via.addEventListener('change', () => chooseEndpoint(true)); chooseEndpoint(false);
    const weight = field(grid, `target-weight-${id}`, '权重', target.weight, 'number'); weight.min = 1; weight.max = 1000;
    const priority = field(grid, `target-priority-${id}`, '优先级（越小越优先，同级按均衡策略）', target.priority ?? 0, 'number'); priority.min = 0; priority.max = 65535;
    const draining = select(grid, `target-draining-${id}`, '维护排空（新会话优先走其他目标，已有会话保持）', [['off', '正常使用'], ['on', '维护排空']], target.draining ? 'on' : 'off');
    const maximum = field(grid, `target-max-${id}`, '目标会话上限（TCP + UDP，留空不限）', target.max_sessions, 'number', false); maximum.min = 1; maximum.max = 1000000;
    const prewarm = field(grid, `target-prewarm-${id}`, '预热连接数（提前建好、待用的 TCP 连接，留空关闭；需启用 PROXY）', target.prewarm, 'number', false); prewarm.min = 1; prewarm.max = 32;
    const mode = select(grid, `target-mode-${id}`, '连接目标的安全方式', [['plain', '普通 TCP / UDP'], ['tls', 'TLS（验证目标证书）']], target.tls ? 'tls' : 'plain'); box.append(grid);
    const secure = el('div', undefined, 'form-grid');
    const name = field(secure, `target-server-name-${id}`, '证书中的服务名或 IP', target.tls?.server_name || '', 'text', false);
    const ca = field(secure, `target-ca-${id}`, 'CA 编号（留空使用公共 CA）', target.tls?.ca || '', 'text', false);
    const identity = field(secure, `target-identity-${id}`, '客户端证书编号（双向认证时填写）', target.tls?.identity || '', 'text', false);
    const proxyFields = el('div', undefined, 'form-grid');
    const proxyMode = select(proxyFields, `target-proxy-${id}`, '向目标传递原始地址（PROXY protocol）', [['off', '关闭'], ['v1', 'v1 · TCP 文本报头'], ['v2', 'v2 · TCP / UDP 二进制报头']], target.proxy_protocol?.version || 'off');
    const proxyPlacement = select(proxyFields, `target-proxy-placement-${id}`, 'PROXY 报头位置', [['before_tls', 'TLS 之前（普通连接也选此项）'], ['inside_tls', 'TLS 加密连接内（对端须配置一致）']], target.proxy_protocol?.placement || 'before_tls');
    const proxyCrc = select(proxyFields, `target-proxy-crc-${id}`, 'v2 报头校验和', [['off', '不附加'], ['on', '附加 CRC32C']], target.proxy_protocol?.checksum ? 'on' : 'off');
    function showProxy() { proxyPlacement.disabled = proxyMode.value === 'off'; proxyCrc.disabled = proxyMode.value !== 'v2'; } proxyMode.addEventListener('change', showProxy); showProxy();
    const ws = websocketEditor(`target-ws-${id}`, target.websocket, false, () => address.value.trim());
    const mp = el('fieldset'); mp.append(el('legend', '此子流的方向与出口'));
    const up = field(mp, 'mp-up-' + id, '上行权重（0 不发送上行数据）', path.upload_weight ?? 1, 'number');
    const down = field(mp, 'mp-down-' + id, '下行权重（0 不发送下行数据）', path.download_weight ?? 1, 'number');
    for (const input of [up, down]) { input.min = 0; input.max = 1000; }
    const bindIp = field(mp, 'mp-ip-' + id, '子流出口 IP（留空继承规则）', path.outbound_bind?.ip || '', 'text', false);
    const bindInterface = field(mp, 'mp-iface-' + id, '子流出口网卡（留空继承规则）', path.outbound_bind?.interface || '', 'text', false);
    mp.append(el('p', '目标必须汇聚到同一条规则。引用汇聚端口段时，可为各子流填写段内不同端口。不同端口本身不代表独立带宽。', 'fine'));
    function showMultipath() { const on = !!multipathMode && multipathMode.value !== 'off'; mp.classList.toggle('hidden', !on); mp.querySelectorAll('input').forEach(input => { input.disabled = !on; }); }
    multipathMode?.addEventListener('change', showMultipath); showMultipath();
    const row = { box, address, via, weight, priority, draining, maximum, prewarm, mode, name, ca, identity, proxyMode, proxyPlacement, proxyCrc, ws, up, down, bindIp, bindInterface }; rows.push(row);
    function showSecurity() { const enabled = mode.value === 'tls'; secure.classList.toggle('hidden', !enabled); name.required = enabled; [name, ca, identity].forEach(input => { input.disabled = !enabled; }); }
    mode.onchange = showSecurity; showSecurity(); box.append(secure, proxyFields, ws.box, mp, button('移除此目标', () => { multipathMode?.removeEventListener('change', showMultipath); rows.splice(rows.indexOf(row), 1); box.remove(); }, 'table-action danger')); container.append(box);
  }
  targets.forEach((target, index) => add(target, multipathPaths?.[index])); form.append(container, button('＋ 添加目标', () => add()));
  const read = () => { if (!rows.length) throw new Error('至少保留一个转发目标'); return rows.map(row => {
    const target = { address: row.address.value.trim(), weight: Number(row.weight.value), priority: Number(row.priority.value), max_sessions: row.maximum.value === '' ? null : Number(row.maximum.value), ...(row.draining.value === 'on' ? { draining: true } : {}), ...(row.prewarm.value === '' ? {} : { prewarm: Number(row.prewarm.value) }), ...(row.mode.value === 'tls' ? { tls: { server_name: row.name.value.trim(), ca: row.ca.value.trim() || null, identity: row.identity.value.trim() || null } } : {}) };
    if (row.proxyMode.value !== 'off') {
      if (row.proxyPlacement.value === 'inside_tls' && row.mode.value !== 'tls') throw new Error('将 PROXY 放入加密连接前，请启用目标 TLS');
      target.proxy_protocol = { version: row.proxyMode.value, placement: row.proxyPlacement.value, checksum: row.proxyMode.value === 'v2' && row.proxyCrc.value === 'on' };
    }
    const websocket = row.ws.read(); if (websocket) target.websocket = websocket;
    if (row.via.value) { const [node_id, rule_id] = row.via.value.split('/'); target.via = { node_id, rule_id }; }
    return target;
  }); };
  read.multipathPaths = () => rows.map(row => {
    const ip = row.bindIp.value.trim(), iface = row.bindInterface.value.trim();
    return { upload_weight: Number(row.up.value), download_weight: Number(row.down.value), ...(ip || iface ? { outbound_bind: { ip: ip || null, interface: iface || null } } : {}) };
  });
  return read;
}

function multipathEditor(form, rule) {
  const box = el('details'); box.open = !!(rule.inbound_multipath || rule.outbound_multipath);
  box.append(el('summary', '单连接多路径聚合'));
  box.append(el('p', '仅支持 TCP，两端每条子流都需要双向 TLS。可叠加 WSS。聚合规则更改会终止已有连接；内核 MPTCP 与此功能分别配置和验收。', 'fine'));
  function limits(parent, prefix, spec) {
    const inputs = {};
    for (const [key, label, fallback, min, max] of [
      ['window_frames', '发送 / 重排窗口帧数（每帧最多 16 KiB）', 64, 4, 256],
      ['max_sessions', '聚合会话上限', 64, 1, 1024],
      ['retransmit_ms', '未确认数据重传间隔 / ms', 500, 50, 10000],
      ['stall_timeout_ms', '无确认进展的中止时间 / ms', 30000, 1000, 120000]
    ]) {
      const input = field(parent, prefix + key, label, spec?.[key] ?? fallback, 'number');
      input.min = min; input.max = max; inputs[key] = input;
    }
    return () => Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, Number(input.value)]));
  }
  const inbound = select(box, 'mp-inbound', '接收聚合连接', [['off', '关闭'], ['on', '作为汇聚端']], rule.inbound_multipath ? 'on' : 'off');
  const server = el('fieldset'); server.append(el('legend', '汇聚端限制'));
  const serverLimits = limits(server, 'mp-server-', rule.inbound_multipath?.limits);
  const maximum = field(server, 'mp-server-paths', '每个连接的子流上限', rule.inbound_multipath?.max_paths ?? 4, 'number'); maximum.min = 1; maximum.max = 8;
  const replication = select(server, 'mp-server-replication', '允许上游使用复制模式', [['no', '不允许'], ['yes', '允许']], rule.inbound_multipath?.allow_replication ? 'yes' : 'no');
  const mode = select(box, 'mp-outbound', '连接目标的聚合方式', [['off', '关闭'], ['stripe', '分片：跨可用路径传输'], ['replicate', '复制：向所有可用路径发送']], rule.outbound_multipath?.mode || 'off');
  const client = el('fieldset'); client.append(el('legend', '发起端限制'));
  const clientLimits = limits(client, 'mp-client-', rule.outbound_multipath?.limits);
  const minimum = field(client, 'mp-client-minimum', '建立时最少成功子流数', rule.outbound_multipath?.min_paths ?? 2, 'number'); minimum.min = 1; minimum.max = 8;
  client.append(el('p', '下方每个目标对应一条子流，最多 8 条，均应通往同一汇聚规则。使用每条子流的上下行权重，目标优先级须为 0。运行中路径失效会在剩余可用方向上重传；当前不会自动补建子流。', 'fine'));
  function show() {
    for (const [section, on] of [[server, inbound.value === 'on'], [client, mode.value !== 'off']]) {
      section.classList.toggle('hidden', !on); section.querySelectorAll('input, select').forEach(input => { input.disabled = !on; });
    }
  }
  inbound.addEventListener('change', show); mode.addEventListener('change', show);
  box.append(server, client, el('p', '单侧规则发送与重排窗口预留合计上限 256 MiB，节点合计上限 512 MiB；另有有界读写队列及操作系统缓冲。复制和重传统计在节点运行诊断中查看，应用配额按重组后的数据计算。', 'fine'));
  form.append(box); show();
  return { mode, read(paths) {
    return {
      ...(inbound.value === 'on' ? { inbound_multipath: { limits: serverLimits(), max_paths: Number(maximum.value), allow_replication: replication.value === 'yes' } } : {}),
      ...(mode.value !== 'off' ? { outbound_multipath: { limits: clientLimits(), mode: mode.value, min_paths: Number(minimum.value), paths } } : {})
    };
  } };
}

$('#login-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, b = $('button', form), factor = $('#second-factor-field'); b.disabled = true; $('#login-error').textContent = ''; try { const f = new FormData(form); const result = await api('/auth/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password'), ...(factor.classList.contains('hidden') ? {} : { second_factor: String(f.get('second_factor')).trim() }) } }); state.token = result.token; state.actor = result.user; sessionStorage.setItem('relay-session', result.token); $('[name=password]', form).value = ''; resetSecondFactor(); await enter(); } catch (error) { const code = $('input', factor); if (error.detail?.second_factor_required) { factor.classList.remove('hidden'); code.required = true; code.focus(); $('#login-error').textContent = '此账号已启用两步验证，请输入身份验证器中的验证码。'; } else { code.value = ''; $('#login-error').textContent = error.message; } } finally { b.disabled = false; } };
function resetSecondFactor() { const factor = $('#second-factor-field'), code = $('input', factor); factor.classList.add('hidden'); code.required = false; code.value = ''; }
document.querySelectorAll('[data-logout]').forEach(b => { b.onclick = async () => { try { await api('/auth/logout', { method: 'POST' }); } finally { loggedOut(); } }; });
$('#refresh').onclick = () => refresh().catch(e => notify(e.message, true));
document.querySelectorAll('[data-view]').forEach(n => n.addEventListener('click', () => navigate(n.dataset.view)));
async function enter() { $('#login-screen').classList.add('hidden'); $('#application').classList.remove('hidden'); $('#identity').textContent = `${state.actor.username} · ${roleNames[state.actor.role]}`; document.querySelectorAll('.admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role !== 'system_admin')); await refresh(); }
async function navigate(view) { state.view = view; $('#notification').classList.add('hidden'); document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === view)); $('#view-title').textContent = titles[view]; $('#status-pill').classList.toggle('hidden', view !== 'overview'); try { await refresh(); } catch (e) { notify(e.message, true); } }
async function refresh() {
  if (!state.actor || state.busy) return; const requestedView = state.view, requestedNode = state.selectedNode; state.busy = true; $('#refresh').disabled = true;
  try { await ({ overview: renderOverview, nodes: renderNodes, rules: renderRules, usage: renderUsage, subscriptions: renderSubscriptions, dns: renderDns, announcements: renderAnnouncements, commerce: renderCommerce, tickets: renderTickets, templates: renderTemplates, budgets: renderBudgets, users: renderUsers, account: renderAccount, audit: renderAudit, alerts: renderAlerts, recovery: renderRecovery, topology: renderTopology, health: renderHealth, capabilities: renderCapabilities })[state.view](); $('#refreshed').textContent = `更新于 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`; }
  finally { state.busy = false; $('#refresh').disabled = false; if (state.actor && (state.view !== requestedView || (['rules', 'health'].includes(requestedView) && requestedNode !== state.selectedNode))) queueMicrotask(() => refresh().catch(e => notify(e.message, true))); }
}

// Overview: per-node samples from /telemetry over the last 15 minutes, drawn as
// sparklines; the chain graph comes from declared `via` targets in /topology.
const SPAN_MS = 15 * 60_000, BINS = 60, BIN_MS = SPAN_MS / BINS;
function svg(tag, attrs = {}, cls) { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (cls) n.setAttribute('class', cls); return n; }
function bits(bytesPerSecond) { let n = bytesPerSecond * 8, i = 0; const u = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return `${n.toFixed(i === 0 || n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${u[i]}`; }
function millis(us) { if (us == null) return '—'; const n = us / 1000; return `${n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)} ms`; }
function ago(at, now) { const s = Math.max(0, Math.round((now - at) / 1000)); return s < 60 ? `${s} 秒前` : s < 3600 ? `${Math.floor(s / 60)} 分钟前` : `${Math.floor(s / 3600)} 小时前`; }
function median(values) { const v = values.filter(x => x != null).sort((a, b) => a - b); return v.length ? v[Math.floor(v.length / 2)] : null; }
// Each report's byte delta is spread over the bins its interval covers.
// Counters restart with the agent process, so a falling counter contributes nothing.
function nodeSeries(samples, now) {
  const start = now - SPAN_MS, bin = t => Math.min(BINS - 1, Math.floor((t - start) / BIN_MS));
  const rate = Array(BINS).fill(null), sessions = Array(BINS).fill(null), latency = Array.from({ length: BINS }, () => []);
  samples.forEach((s, i) => {
    const b = bin(s.at_ms); if (b < 0) return;
    sessions[b] = s.active_sessions; if (s.probe_latency_us != null) latency[b].push(s.probe_latency_us);
    const prev = samples[i - 1]; if (!prev || s.forwarded_bytes < prev.forwarded_bytes || s.at_ms <= prev.at_ms) { rate[b] ??= 0; return; }
    const perMs = (s.forwarded_bytes - prev.forwarded_bytes) / (s.at_ms - prev.at_ms);
    for (let k = Math.max(0, bin(prev.at_ms)); k <= b; k++) {
      const overlap = Math.min(s.at_ms, start + (k + 1) * BIN_MS) - Math.max(prev.at_ms, start + k * BIN_MS);
      rate[k] = (rate[k] ?? 0) + Math.max(0, overlap) * perMs / (BIN_MS / 1000);
    }
  });
  return { rate, sessions, latency };
}
function currentRate(samples) {
  const last = samples.at(-1), first = samples.find(s => s.at_ms >= last?.at_ms - 20_000);
  if (!last || first === last || last.forwarded_bytes < first.forwarded_bytes) return null;
  return (last.forwarded_bytes - first.forwarded_bytes) / ((last.at_ms - first.at_ms) / 1000);
}
function sumBins(list) { return Array.from({ length: BINS }, (_, i) => { const v = list.map(s => s[i]).filter(x => x != null); return v.length ? v.reduce((a, b) => a + b, 0) : null; }); }
function spark(values, cls, width = 160, height = 44) {
  const box = svg('svg', { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' }, `spark ${cls}`);
  const top = Math.max(0, ...values.filter(v => v != null)) || 1, x = i => i / (values.length - 1) * width, y = v => height - 2 - v / top * (height - 6);
  const runs = []; let run = [];
  values.forEach((v, i) => { if (v == null) { if (run.length) runs.push(run); run = []; } else run.push([x(i), y(v)]); }); if (run.length) runs.push(run);
  box.append(svg('line', { x1: 0, x2: width, y1: height - 2, y2: height - 2 }, 'spark-empty'));
  for (const r of runs) {
    if (r.length === 1) r.push([r[0][0] + 2, r[0][1]]);
    const line = r.map(([px, py], i) => `${i ? 'L' : 'M'}${px.toFixed(1)} ${py.toFixed(1)}`).join('');
    box.append(svg('path', { d: `${line}L${r.at(-1)[0].toFixed(1)} ${height}L${r[0][0].toFixed(1)} ${height}Z` }, 'spark-area'), svg('path', { d: line }, 'spark-line'));
  }
  return box;
}
function meter(ratio, label) {
  const cell = el('div', undefined, 'meter'), bar = svg('svg', { viewBox: '0 0 100 6', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const level = ratio == null ? '' : ratio >= .85 ? 'high' : ratio >= .6 ? 'mid' : 'low';
  bar.append(svg('rect', { width: 100, height: 6, rx: 3 }, 'meter-track'), svg('rect', { width: Math.max(0, Math.min(1, ratio ?? 0)) * 100, height: 6, rx: 3 }, `meter-fill ${level}`));
  cell.append(el('span', label, 'meter-label'), bar); return cell;
}
function kpi(label, value, foot, chart) { const n = el('div', undefined, 'kpi'), text = el('div', undefined, 'kpi-text'); text.append(el('div', label, 'metric-label'), el('div', value, 'metric-value'), el('div', foot, 'metric-foot')); n.append(text, chart); return n; }
function overviewStatus(node, latest) {
  if (!node.enrolled) return ['待注册', '', 'idle'];
  if (!online(node)) return ['离线', 'red', 'down'];
  if (node.lifecycle && node.lifecycle !== 'active') return ['已暂停', 'orange', 'partial'];
  if (node.apply_error) return ['配置异常', 'orange', 'partial'];
  if (latest && latest.healthy_targets < latest.probed_targets) return ['降级', 'orange', 'partial'];
  return ['正常', 'green', 'up'];
}
async function renderOverview() {
  const [telemetry, nodes, topology] = await Promise.all([api('/telemetry'), api('/nodes'), api('/topology')]);
  const now = telemetry.generated_at_ms, byId = new Map(nodes.map(n => [n.id, n]));
  const rows = telemetry.nodes.filter(t => byId.has(t.id)).map(t => { const node = byId.get(t.id), latest = online(node) ? t.samples.at(-1) : null; return { node, samples: t.samples, latest, series: nodeSeries(t.samples, now), rate: online(node) ? currentRate(t.samples) : null, status: overviewStatus(node, latest) }; });
  const live = rows.filter(r => r.latest), enrolled = rows.filter(r => r.node.enrolled);
  const rate = sumBins(rows.map(r => r.series.rate)), sessions = sumBins(rows.map(r => r.series.sessions));
  const latency = Array.from({ length: BINS }, (_, i) => median(rows.flatMap(r => r.series.latency[i])));
  const healthy = live.reduce((s, r) => s + r.latest.healthy_targets, 0), probed = live.reduce((s, r) => s + r.latest.probed_targets, 0);
  const peak = Math.max(0, ...rate.filter(v => v != null));
  const fleet = el('div', undefined, 'fleet-bar'); enrolled.forEach(r => fleet.append(el('i', undefined, r.status[2])));
  const kpis = el('div', undefined, 'kpis');
  kpis.append(
    kpi('实时吞吐', live.length ? bits(live.reduce((s, r) => s + (r.rate ?? 0), 0)) : '—', `多跳流量逐跳计入 · 峰值 ${bits(peak)}`, spark(rate, 'accent')),
    kpi('活跃会话', String(live.reduce((s, r) => s + r.latest.active_sessions, 0)), 'TCP 连接 + UDP 会话', spark(sessions, 'blue')),
    kpi('探测往返中位数', millis(median(live.map(r => r.latest.probe_latency_us))), '节点到目标的探测，不含客户端一段', spark(latency, 'violet')),
    kpi('节点在线', `${live.length} / ${enrolled.length}`, probed ? `目标可用 ${healthy} / ${probed}` : '尚无目标探测', fleet));
  const events = telemetry.events.slice().reverse(), attention = rows.filter(r => r.status[2] === 'down' || r.status[2] === 'partial').length;
  const pill = $('#status-pill'); pill.className = `status-pill ${rows.some(r => r.status[2] === 'down') ? 'red' : attention ? 'orange' : 'green'}`;
  pill.textContent = attention ? `${attention} 个节点需要关注` : `运行正常 · ${enrolled.length} 个节点`;
  const graphPanel = panel('转发链路', '按规则声明的下一跳绘制；连线颜色为该段目标的最新探测结果，点击节点查看规则。', legend());
  graphPanel.classList.add('graph-panel'); graphPanel.append(chainGraph(topology, byId));
  const incidents = panel('事件', `最近 1 小时 · 共 ${events.length} 条`, events.length ? button('全部事件', () => modal('全部事件', eventTable(events, byId, now)), 'table-action') : undefined);
  incidents.classList.add('incident-panel');
  const list = el('ol', undefined, 'incidents');
  if (!events.length) list.append(el('li', '最近 1 小时没有目标故障、配置拒绝或节点离线。', 'incident-empty'));
  events.slice(0, 6).forEach(e => { const item = el('li', undefined, `incident ${e.severity}`), text = el('div'); text.append(Object.assign(el('div', e.message, 'incident-message'), { title: e.message }), el('div', byId.get(e.node_id)?.name || e.node_id, 'subline')); item.append(el('i'), text, el('time', ago(e.at_ms, now))); list.append(item); });
  incidents.append(list);
  const middle = el('div', undefined, 'overview-grid'); middle.append(graphPanel, incidents);
  const search = el('input'); search.type = 'search'; search.placeholder = '按名称、ID 或分组筛选'; search.value = state.overviewFilter || ''; search.setAttribute('aria-label', '筛选节点');
  const nodePanel = panel('中转节点', `${enrolled.length} 个已注册 · 采样来自每次节点回报`, search);
  const t = table(['节点', '状态', '探测往返', '吞吐（15 分钟）', 'CPU', '内存', '会话', '配置修订', '最近回报', ''], rows.map(r => {
    const { node, latest } = r, memory = latest?.memory_total_bytes ? 1 - latest.memory_available_bytes / latest.memory_total_bytes : null;
    const throughput = el('div', undefined, 'throughput'); throughput.append(spark(r.series.rate, 'accent'), el('span', r.rate == null ? '—' : bits(r.rate)));
    return [namedCell(node.name, node.profile?.settings.group || node.id.slice(0, 8)), badge(r.status[0], r.status[1]), latest ? millis(latest.probe_latency_us) : '—', throughput,
      latest?.cpu_percent != null ? meter(latest.cpu_percent / 100, `${latest.cpu_percent.toFixed(0)}%`) : '—',
      memory != null ? meter(memory, `${bytes(latest.memory_total_bytes - latest.memory_available_bytes)} / ${bytes(latest.memory_total_bytes)}`) : '—',
      latest ? (node.stats?.prewarmed_connections ? namedCell(String(latest.active_sessions), `预热接手 ${node.stats.prewarmed_connections}`) : String(latest.active_sessions)) : '—', node.apply_error ? namedCell(`${node.applied_revision} / ${node.desired_revision}`, '应用失败') : `${node.applied_revision} / ${node.desired_revision}`,
      node.last_seen_ms ? ago(node.last_seen_ms, now) : '尚未回报', button('规则 →', async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action')];
  }));
  const trs = [...t.querySelectorAll('tbody tr')], keys = rows.map(r => [r.node.name, r.node.id, r.node.profile?.settings.group || ''].join(' ').toLowerCase());
  const filter = () => { state.overviewFilter = search.value; const q = search.value.trim().toLowerCase(); trs.forEach((tr, i) => tr.classList.toggle('hidden', !!q && !keys[i].includes(q))); };
  search.addEventListener('input', filter); filter();
  nodePanel.append(rows.length ? t : empty('还没有节点', '注册节点并启动 Agent 后，这里会显示实时吞吐、资源和事件。', button('前往节点管理', () => navigate('nodes'))));
  if (state.view === 'overview') $('#content').replaceChildren(kpis, middle, nodePanel);
}
function legend() { const n = el('div', undefined, 'legend'); for (const [text, cls] of [['正常', 'up'], ['部分可用', 'partial'], ['不可用', 'down'], ['未探测', 'unknown']]) { const item = el('span'); item.append(el('i', undefined, cls), text); n.append(item); } return n; }
function eventTable(events, byId, now) {
  const names = { info: '信息', recovered: '恢复', warning: '警告', critical: '严重' }, colors = { recovered: 'green', warning: 'orange', critical: 'red' };
  return table(['时间', '节点', '级别', '内容'], events.map(e => [`${timestamp(e.at_ms)} · ${ago(e.at_ms, now)}`, byId.get(e.node_id)?.name || e.node_id, badge(names[e.severity] || e.severity, colors[e.severity]), e.message]));
}
// Columns follow the longest declared path from an entry node; external
// targets share one sink so each node shows one summarized outgoing link.
function chainGraph(topology, byId) {
  const health = new Map(), edges = new Map(), referenced = new Set(), ruleCount = new Map();
  for (const n of topology.nodes) for (const h of n.stats?.target_health || []) { const key = `${n.id}/${h.rule_id}/${h.target_index}`; health.set(key, [...(health.get(key) || []), h]); }
  const addEdge = (from, to, reports) => {
    const key = `${from}>${to}`, e = edges.get(key) || { from, to, states: [], latency: [] }; edges.set(key, e);
    e.states.push(!reports.length ? 'unknown' : reports.every(h => h.eligible) ? 'up' : reports.some(h => h.eligible) ? 'partial' : 'down');
    e.latency.push(...reports.filter(h => h.eligible).map(h => h.latency_ewma_us));
  };
  for (const config of topology.configs || []) for (const rule of config.rules) {
    if (!rule.enabled) continue; ruleCount.set(config.node_id, (ruleCount.get(config.node_id) || 0) + 1);
    rule.targets.forEach((target, i) => { if (target.via) referenced.add(`${target.via.node_id}/${target.via.rule_id}`); addEdge(config.node_id, target.via ? target.via.node_id : 'sink', health.get(`${config.node_id}/${rule.id}/${i}`) || []); });
  }
  for (const config of topology.configs || []) if (config.rules.some(rule => rule.enabled && !referenced.has(`${config.node_id}/${rule.id}`))) addEdge('client', config.node_id, []);
  const ids = topology.nodes.filter(n => n.enrolled || ruleCount.has(n.id)).map(n => n.id), depth = new Map();
  const depthOf = (id, seen = new Set()) => { if (depth.has(id)) return depth.get(id); if (seen.has(id)) return 1; seen.add(id); const parents = [...edges.values()].filter(e => e.to === id && e.from !== 'client').map(e => depthOf(e.from, seen)); const d = parents.length ? Math.max(...parents) + 1 : 1; depth.set(id, d); return d; };
  ids.forEach(id => depthOf(id));
  const last = Math.max(1, ...depth.values()) + 1, columns = Array.from({ length: last + 1 }, () => []);
  ids.forEach(id => columns[depth.get(id)].push(id)); if ([...edges.values()].some(e => e.from === 'client')) columns[0].push('client'); if ([...edges.values()].some(e => e.to === 'sink')) columns[last].push('sink');
  // Lay out at the panel's current pixel size so text stays at its CSS size; the viewBox rescales between refreshes.
  const beside = window.innerWidth > 1600, W = Math.max(640, ($('#content').clientWidth || 1100) - (beside ? 376 : 0) - 36);
  // Client and target terminals are narrow; node columns share the width between them.
  const tw = 80, left = 12 + (columns[0].length ? tw + 40 : 0), right = W - 12 - (columns[last].length ? tw + 40 : 0), step = (right - left) / (last - 1);
  const bw = Math.max(112, Math.min(176, step - 44)), bh = 52, gap = 84, H = Math.max(beside ? 400 : 300, Math.max(...columns.map(c => c.length)) * gap + 60), pos = new Map(), labels = [];
  columns.forEach((column, c) => column.forEach((id, r) => pos.set(id, [c === 0 ? 12 : c === last ? W - 12 - tw : left + (c - 1) * step + (step - bw) / 2, (H - column.length * gap) / 2 + r * gap + (gap - bh) / 2, c === 0 || c === last ? tw : bw])));
  const box = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': '转发链路图' }, 'chain');
  // A link is up only if every probed target is, and down only if none is; unprobed targets do not count.
  const summary = states => { const known = states.filter(s => s !== 'unknown'); return !known.length ? 'unknown' : known.every(s => s === 'up') ? 'up' : known.every(s => s === 'down') ? 'down' : 'partial'; };
  for (const e of edges.values()) {
    const a = pos.get(e.from), b = pos.get(e.to); if (!a || !b) continue;
    const x1 = a[0] + a[2], y1 = a[1] + bh / 2, x2 = b[0], y2 = b[1] + bh / 2, dx = (x2 - x1) / 2, state = e.from === 'client' ? 'client' : summary(e.states);
    box.append(svg('path', { d: `M${x1} ${y1}C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}` }, `edge ${state}`));
    const lat = median(e.latency); if (lat != null) { const label = svg('text', { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 7, 'text-anchor': 'middle' }, 'edge-label'); label.textContent = millis(lat); labels.push(label); }
  }
  for (const [id, [x, y, w]] of pos) {
    const g = svg('g', { transform: `translate(${x} ${y})` }), node = byId.get(id);
    if (id === 'client' || id === 'sink') {
      g.setAttribute('class', 'terminal'); g.append(svg('rect', { width: w, height: bh, rx: 26 }));
      const title = svg('text', { x: w / 2, y: bh / 2 + 4, 'text-anchor': 'middle' }); title.textContent = id === 'client' ? '客户端' : '目标服务'; g.append(title);
    } else {
      const status = node ? overviewStatus(node, null)[2] : 'idle';
      g.setAttribute('class', `chain-node ${status}`); g.setAttribute('tabindex', '0'); g.setAttribute('role', 'button'); g.setAttribute('aria-label', `${node?.name || id} 的规则`);
      const open = async () => { state.selectedNode = id; await navigate('rules'); };
      g.addEventListener('click', open); g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      g.append(svg('rect', { width: w, height: bh, rx: 9 }), svg('circle', { cx: 14, cy: 19, r: 4.5 }, 'dot'));
      const full = node?.name || id, fit = Math.floor((w - 32) / 7.4), name = svg('text', { x: 26, y: 23 }, 'name'), sub = svg('text', { x: 14, y: 41 }, 'sub');
      name.textContent = full.length > fit ? full.slice(0, fit - 1) + '…' : full; name.append(svg('title')); name.lastChild.textContent = full; sub.textContent = !node?.enrolled ? '待注册' : !online(node) ? '离线' : `${ruleCount.get(id) || 0} 条规则 · ${node.stats.active_tcp + node.stats.active_udp} 会话`;
      g.append(name, sub);
    }
    box.append(g);
  }
  box.append(...labels);
  const wrap = el('div', undefined, 'chain-wrap'); wrap.append(box);
  if (!ids.length) return empty('还没有节点', '注册节点并配置规则后显示转发链路。');
  return wrap;
}

async function renderNodes() {
  const query = new URLSearchParams(state.nodeFilter).toString();
  const [nodes, usage, topology] = await Promise.all([api('/nodes' + (query ? '?' + query : '')), api('/usage'), api('/topology').catch(() => null)]); state.nodes = nodes; state.usage = usage;
  state.inbound = {}; for (const c of topology?.configs || []) for (const r of c.rules) for (const t of r.targets) if (t.via) { const n = state.inbound[t.via.node_id] ||= { total: 0, draining: 0 }; n.total++; if (t.draining) n.draining++; }
  state.selectedNodes = new Set([...state.selectedNodes].filter(id => nodes.some(n => n.id === id)));
  const metric = el('div', undefined, 'metrics');
  [['节点数量', nodes.length, query ? '当前筛选范围' : '当前账号可见的节点'], ['控制在线', nodes.filter(online).length, '最近 30 秒收到心跳'], ['活跃连接', nodes.filter(online).reduce((s,n) => s+n.stats.active_tcp+n.stats.active_udp,0), '当前范围的 TCP + UDP 会话'], ['近期上报负载', bytes(usage.reduce((s,u) => s+u.upload_bytes+u.download_bytes,0)), '全部可见节点最近 2,000 个计量周期']].forEach(([title,value,foot]) => { const n=el('div',undefined,'metric'); n.append(el('div',title,'metric-label'),el('div',String(value),'metric-value'),el('div',foot,'metric-foot'));metric.append(n); });
  const controls=el('div',undefined,'toolbar node-tools'); controls.append(button('筛选节点',filterNodes));
  if(query) controls.append(button('清除筛选',async()=>{state.nodeFilter={};state.selectedNodes.clear();await renderNodes();}));
  if(canWrite()) controls.append(button('选择 / 取消本页',async()=>{if(nodes.every(n=>state.selectedNodes.has(n.id)))state.selectedNodes.clear();else nodes.forEach(n=>state.selectedNodes.add(n.id));await renderNodes();}),button('批量编辑已选节点',batchNodeProfiles),button('＋ 注册节点',newNode,'primary'));
  const p=panel('节点','管理资料、运行许可与实际回报分别显示。',controls); p.classList.add('node-panel');
  if(!nodes.length) p.append(empty(query?'没有匹配的节点':'接入你的第一个节点',query?'调整筛选条件后重试。':'注册后启动 Agent，再配置转发。'));
  else p.append(table(['选择','节点 / ID','类型 / 分组 / 成本','运行许可 / 到期','控制连接','运行保护','配置修订','活跃会话','操作'],nodes.map(node=>{
    let choice='—';if(canWrite()){choice=el('input');choice.className='node-choice';choice.type='checkbox';choice.checked=state.selectedNodes.has(node.id);choice.setAttribute('aria-label','选择 '+node.name);choice.onchange=()=>choice.checked?state.selectedNodes.add(node.id):state.selectedNodes.delete(node.id);}
    const id=namedCell(node.name,node.id.slice(0,8)+'…');id.title=node.id;
    return [choice,id,nodeInventoryCell(node),nodeLifecycleCell(node),namedCell(node.credential_phase==='revoked'?'身份已撤销':node.credential_phase==='replacement_pending'?'等待替换注册':node.enrolled?online(node)?'控制在线':'无近期回报':'待注册',timestamp(node.last_seen_ms)),nodeLeaseBadge(node),node.apply_error?namedCell(`应用失败 · ${node.applied_revision} / ${node.desired_revision}`,node.apply_error):`${node.applied_revision} / ${node.desired_revision}`,nodeSessionsCell(node),nodeActions(node)];
  })));
  if(state.view==='nodes') $('#content').replaceChildren(metric,p);
}
function nodeLeaseBadge(node) {
  const lease = node.lease;
  if (!lease) return badge('未提供', '');
  if (!lease.policy) return badge('离线模式', 'orange');
  if (lease.recovery_wait_ms > 0) return badge('恢复等待', 'orange');
  return badge(lease.active ? '有效租约' : '未持有', lease.active ? 'green' : '');
}
function timingRow(label, value) {
  if (!value) return [label, '未提供', '—', '—'];
  return [label, String(value.samples), value.samples ? (value.total_us / value.samples / 1000).toFixed(3) : '—', value.samples ? (value.max_us / 1000).toFixed(3) : '—'];
}
function nodeSessionsCell(node) {
  const text = online(node) ? `${node.stats.active_tcp} TCP / ${node.stats.active_udp} UDP` : '—';
  return state.inbound?.[node.id]?.draining ? namedCell(text, '维护中 · 不接新连接') : text;
}
async function drainNode(node, draining) {
  const inbound = state.inbound[node.id];
  if (!confirm(draining ? `「${node.name}」有 ${inbound.total} 个上游目标指向它。排空后，新连接改走其他目标（没有其他可用目标时仍会使用它），已有连接继续直到结束。会话数降到 0 后即可安全重启或升级。` : `结束「${node.name}」的维护，上游恢复按原优先级和权重分配新连接？`)) return;
  const result = await api(`/nodes/${node.id}/drain`, { method: 'POST', body: { draining } });
  notify(draining ? `已排空：${result.configs.length} 个上游节点发布了新修订。` : `已结束维护：${result.configs.length} 个上游节点发布了新修订。`); await renderNodes();
}
function nodeActions(node) {
  const actions = el('div', undefined, 'node-actions');
  const inbound = state.inbound?.[node.id];
  if (canWrite() && inbound?.total) actions.append(button(inbound.draining ? '结束维护' : '维护排空', () => drainNode(node, !inbound.draining), 'table-action'));
  actions.append(button(canWrite() ? '编辑资料' : '查看资料', () => editNode(node), 'table-action'), button('管理规则 →', async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action'), button('运行诊断', () => nodeDiagnostics(node), 'table-action'));
  actions.append(button('节点身份', () => nodeCredential(node), 'table-action'));
  return actions;
}
async function nodeCredential(node) {
  node = (await api('/nodes')).find(n=>n.id===node.id) || node;
  const status = await api(`/nodes/${node.id}/credential`), body = el('div');
  const phase = status.phase || (node.enrolled ? 'active' : 'not_enrolled');
  body.append(el('p', node.name), table(['项目', '状态'], [
    ['身份状态', { active:'已绑定', not_enrolled:'待首次注册', revoked:'已撤销', replacement_pending:'等待替换实例注册' }[phase] || phase],
    ['当前凭据版本', status.revision],
    ['轮换任务', status.pending ? '等待节点执行' : '无待执行任务'],
    ['请求时间', status.pending ? timestamp(status.pending.requested_at_ms) : '—'],
    ['上次完成', status.last_rotation ? timestamp(status.last_rotation.completed_at_ms) : '—']
  ]), el('p', '节点自行生成并保存新凭据，控制器确认后旧凭据失效。在线节点自动处理，离线或暂停的节点恢复运行后处理；旧版本 Agent 需要先升级。这里不会显示密钥。', 'fine'),
  el('p', '常规轮换保留配置和运行。紧急撤销会拒绝旧凭据并中断业务；已授执行窗口仍须等待结束，未知流量预留继续保留。', 'fine'));
  if (status.revocation) body.append(el('p', `最近撤销：${timestamp(status.revocation.at_ms)} · ${status.revocation.reason}`, 'fine'));
  if (status.replacement) body.append(el('p', `替换票据到期：${timestamp(status.replacement.expires_at_ms)} · ${status.replacement.enrolled_at_ms ? '已注册' : '尚未使用'}`, 'fine'));
  if (status.blocked_quota_periods?.length) body.append(el('p', '以下旧配额周期可能存在未上报消费，替换实例会等待。请停用对应规则，或在规则编辑中明确开始新周期。旧账和共享预算不会清零。', 'fine'), table(['规则', '受保护的旧周期'], status.blocked_quota_periods.map(p => [p.rule_id,p.meter_epoch])));
  if (status.pending) body.append(el('p', `任务编号：${status.pending.id}`, 'fine'));
  if (canWrite() && phase === 'active' && !status.pending) {
    const action = button('发起凭据轮换', async () => {
      action.disabled = true;
      try {
        await api(`/nodes/${node.id}/credential/rotate`, { method: 'POST', body: { expected_revision: status.revision } });
        await nodeCredential(node);
      } finally { action.disabled = false; }
    }, 'primary');
    body.append(action);
  }
  if (canWrite()) {
    body.append(button(phase === 'not_enrolled' ? '撤销遗失的注册令牌' : '紧急撤销身份', () => revokeNodeIdentity(node,status), 'danger'));
    if (phase === 'revoked' || phase === 'replacement_pending') body.append(button('签发替换票据', () => replaceNodeIdentity(node,status), 'primary'));
  }
  body.append(button('刷新状态', () => nodeCredential(node)));
  modal('节点身份与凭据', body);
}
function revokeNodeIdentity(node,status) {
  const form = el('form');
  form.append(el('p', `撤销「${node.name}」的当前凭据、待执行轮换和注册票据。规则与历史账本保留，无法撤回此动作；恢复运行需要签发新票据。`));
  field(form,'reason','撤销原因（最多 512 字节）','','text').maxLength=512;
  const operation = crypto.randomUUID();
  let request = null;
  submit(form,'确认撤销身份',async data=>{
    const reason=String(data.get('reason')).trim();
    if (!request && (!reason || new TextEncoder().encode(reason).length>512 || /[\x00-\x1f\x7f-\x9f]/.test(reason))) throw new Error('请填写不含控制字符、最多 512 字节的撤销原因。');
    request ||= {operation_id:operation,expected_revision:status.revision,reason};
    await api(`/nodes/${node.id}/credential/revoke`,{method:'POST',body:request});
    await nodeCredential(node);
    notify('撤销操作已确认，请以当前身份状态为准。严格节点按已授期限停止；离线实例需要外部停止。');
  });
  modal('紧急撤销节点身份',form);
}
function replaceNodeIdentity(node,status) {
  const form=el('form');
  form.append(el('p','替换实例须使用新的私有状态目录。控制器保留配置和已知账本，不恢复未知消费，也不会提前跳过旧执行窗口。票据只显示在此处，请保存为权限 0600 的文件。'));
  const ttl=field(form,'valid_for_seconds','票据有效秒数',600,'number');ttl.min=1;ttl.max=86400;
  let offline=null;
  if (!node.lease?.policy) {
    const label=el('label',undefined,'inline-check');offline=el('input');offline.type='checkbox';offline.required=true;label.append(offline,document.createTextNode('我已通过服务器管理渠道停止所有旧离线实例及副本'));form.append(label,el('p','平台不能证明旧离线程序已停止。新身份将启用 30 秒严格租约。','fine'));
  }
  const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);
  const enrollment=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
  const operation=crypto.randomUUID();let request=null;
  submit(form,'签发一次性替换票据',async data=>{
    request ||= {operation_id:operation,expected_revision:status.revision,enrollment_token:enrollment,valid_for_seconds:number(data,'valid_for_seconds'),offline_stop_attested:!!offline?.checked,lease_policy:offline?{ttl_ms:30000}:null};
    const result=await api(`/nodes/${node.id}/credential/replace`,{method:'POST',body:request});
    if (result.phase!=='replacement_pending' || result.replacement?.id!==operation || result.replacement.revision!==status.revision+1 || result.replacement.enrolled_at_ms) {
      await nodeCredential(node);
      notify('该签发操作已处理，票据已经使用或被后续操作替代。请查看当前身份状态。');
      return;
    }
    const content=el('div');content.append(el('p',`票据到期：${timestamp(result.replacement.expires_at_ms)}`),el('div',enrollment,'secret-box'),el('pre',`relay agent --controller ${location.origin} --node-id ${node.id} --enrollment-token-file /path/to/replacement.secret --state /var/lib/relay-agent-replacement`),el('p','不要把此命令指向旧状态目录。丢失此票据可重新签发，之前的票据将失效；重试同一请求不会再次更换票据。','fine'));
    modal('保存替换票据',content);
  });
  modal('替换节点身份',form);
}
function nodeDiagnostics(node) {
  const body = el('div'), stats = node.stats, meter = stats.meter;
  body.append(el('p', `${node.name} · 最近回报 ${timestamp(node.last_seen_ms)}`), el('p', online(node) ? '以下为最近一次节点采样。' : '节点没有近期回报，以下是旧采样。', 'fine'));
  if (node.lease) {
    const lease = node.lease;
    body.append(table(['运行保护', '控制器当前观测'], [
      ['策略', lease.policy ? '严格租约 · ' + (lease.policy.ttl_ms / 1000) + ' 秒' : '离线运行'],
      ['所有权代数', lease.generation], ['最近运行编号', lease.holder_run_id || '—'],
      ['服务端剩余保留 / 秒', (lease.remaining_ms / 1000).toFixed(2)], ['恢复等待 / 秒', (lease.recovery_wait_ms / 1000).toFixed(2)]
    ]), el('p', '租约保留不等于业务健康。严格模式失去续租后停止业务，离线模式不提供跨机器互斥。租约到期不会自动退还未知消费的额度。', 'fine'));
  }
  if (stats.budget_recovery) {
    const recovery = stats.budget_recovery;
    body.append(table(['最近额度恢复', '节点确认结果'], [
      ['运行编号', recovery.run_id], ['确认时间', timestamp(recovery.at_ms)], ['已核对预留', recovery.validated_grants],
      ['找回未收到的预留', recovery.recovered_pending_grants], ['取消未发放请求', recovery.cancelled_requests], ['恢复后可用预留笔数', recovery.open_grants]
    ]), el('p', '此记录表示开启监听前已核对原状态；不是当前余额，也不能证明旧备份中的未知消费。', 'fine'));
  }
  if (!meter) body.append(empty('尚无计量诊断', '节点需要支持计量诊断的版本，并完成一次状态上报。'));
  else {
    body.append(table(['诊断阶段', '已完成采样数', '平均 / ms', '最大 / ms'], [timingRow('本地计量批次', meter.admission_batches), timingRow('额度等待片段', meter.budget_wait)]));
    body.append(table(['项目', '最近采样'], [['计量请求（包含重试）', meter.admission_requests], ['计量批次失败', meter.failed_batches], ['正在等待额度的方向 / 会话', meter.budget_waiting], ['额度等待超时', meter.budget_timeouts], ['累计额度等待 / 秒', (meter.budget_wait.total_us / 1000000).toFixed(3)], ['活跃 TCP / UDP / 探测', `${stats.active_tcp} / ${stats.active_udp} / ${stats.active_probes || 0}`]]));
    body.append(el('p', '本地计量耗时包括线程池调度、数据库锁等待与事务执行，不是纯磁盘时间。额度等待按每次休眠片段计数，包含被取消的片段；并发等待时间可重叠相加。统计从进程启动累计，不作为用量或额度依据。', 'fine'));
  }
  if (stats.multipath) {
    const mp = stats.multipath;
    body.append(el('h3', '多路径传输'), table(['项目', '最近采样'], [
      ['活跃聚合连接 / 子流', mp.active_sessions + ' / ' + mp.active_paths], ['累计聚合连接', mp.sessions], ['失效子流', mp.failed_paths],
      ['发送负载（含额外副本）', bytes(mp.sent_payload_bytes)], ['复制额外负载', bytes(mp.replicated_payload_bytes)],
      ['重传额外负载', bytes(mp.retransmitted_payload_bytes)], ['收到的重复负载', bytes(mp.duplicate_payload_bytes)],
      ['重组交付负载', bytes(mp.delivered_payload_bytes)], ['帧头与确认位图发送量', bytes(mp.framing_sent_bytes)],
      ['单连接发送窗口峰值', bytes(mp.peak_send_window_bytes)], ['单连接重排窗口峰值', bytes(mp.peak_reorder_bytes)]
    ]), table(['子流位置（跨规则累计）', '实际发送负载'], mp.path_sent_payload_bytes.map((value, index) => [String(index + 1), bytes(value)])),
    el('p', '以上为本次进程累计，含健康探测建立的聚合连接。负载统计不含 TLS、WebSocket、TCP/IP 报头及内核重传；不是网卡总流量或持久化账单。子流位置按配置中目标顺序编号。', 'fine'));
  }
  modal('节点运行诊断', body);
}
const nodeKindNames = { ingress: '入口', relay: '中转', egress: '出口', ix: 'IX', nat: 'NAT' };
const costPeriodNames = { monthly: '每月', yearly: '每年', one_time: '一次性' };
function costAmount(micros) { const value = BigInt(micros), fraction = (value % 1000000n).toString().padStart(6, '0').replace(/0+$/, ''); return (value / 1000000n).toString() + (fraction ? '.' + fraction : ''); }
function costLabel(cost) { return cost ? `${cost.currency} ${costAmount(cost.amount_micros)} · ${costPeriodNames[cost.period]}` : '未记录'; }
function localDateTime(value) { if (!value) return ''; const d = new Date(value), pad = (n, size = 2) => String(n).padStart(size, '0'); return `${pad(d.getFullYear(), 4)}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`; }
function nodeSettingsEditor(form, settings = {}, strict = () => true) {
  const kinds = el('fieldset', undefined, 'target-editor'); kinds.append(el('legend', '节点类型（用途标注，可多选）'));
  for (const [value, label] of Object.entries(nodeKindNames)) { const item = el('label', label, 'inline-check'), input = el('input'); input.type = 'checkbox'; input.name = 'node_kind'; input.value = value; input.checked = (settings.kinds || []).includes(value); item.prepend(input); kinds.append(item); } form.append(kinds);
  field(form, 'node_group', '分组', settings.group || '', 'text', false).maxLength = 64;
  textarea(form, 'node_tags', '标签（每行一个，最多 32 个）', (settings.tags || []).join('\n'));
  textarea(form, 'node_notes', '备注', settings.notes || '').maxLength = 4096;
  field(form, 'cost_amount', '成本金额（最多 6 位小数；留空不记录）', settings.cost ? costAmount(settings.cost.amount_micros) : '', 'text', false).inputMode = 'decimal';
  field(form, 'cost_currency', '成本币种（三个字母，例如 CNY、USD）', settings.cost?.currency || 'CNY', 'text', false).maxLength = 3;
  select(form, 'cost_period', '成本周期', Object.entries(costPeriodNames), settings.cost?.period || 'monthly');
  const enabled = select(form, 'node_enabled', '运行许可', [['true', '允许运行'], ['false', '暂停运行']], String(settings.enabled !== false));
  const expiry = field(form, 'node_expiry', `到期时间（${Intl.DateTimeFormat().resolvedOptions().timeZone}；留空不设）`, localDateTime(settings.expires_at_ms), 'datetime-local', false); expiry.step = '0.001';
  const originalExpiryText = expiry.value;
  form.append(el('p', '类型、分组和成本用于管理，不自动改变转发路径或创建 NAT。暂停和到期仅支持严格租约：停止在当前授权窗口内收敛，不清零用量或退款。恢复允许状态后，已退出的 Agent 需要重新启动。', 'fine'));
  const policy = () => { enabled.disabled = expiry.disabled = !strict(); if (!strict()) { enabled.value = 'true'; expiry.value = ''; } }; policy();
  return { policy, read(data) {
    const amount = String(data.get('cost_amount') || '').trim(); let cost = null;
    if (amount) { if (!/^\d+(\.\d{1,6})?$/.test(amount)) throw new Error('成本必须为非负十进制数，最多 6 位小数'); const [whole, fraction = ''] = amount.split('.'), micros = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0')); if (micros > 9000000000000000n) throw new Error('成本超出可记录范围'); cost = { currency: String(data.get('cost_currency')).trim().toUpperCase(), amount_micros: Number(micros), period: data.get('cost_period') }; }
    let expires = null;
    if (strict() && expiry.value) { expires = expiry.value === originalExpiryText ? settings.expires_at_ms : new Date(expiry.value).getTime(); if (!Number.isSafeInteger(expires) || expires <= 0) throw new Error('请输入有效的到期时间'); }
    return { kinds: data.getAll('node_kind'), group: String(data.get('node_group') || '').trim() || null, tags: String(data.get('node_tags') || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean), notes: String(data.get('node_notes') || ''), cost, enabled: strict() ? enabled.value === 'true' : true, expires_at_ms: expires };
  } };
}
function editNode(node) {
  const settings = node.profile.settings;
  if (!canWrite()) { const body = el('div'); body.append(table(['资料', '当前记录'], [['名称', node.name], ['类型', settings.kinds.map(k => nodeKindNames[k]).join('、') || '未标注'], ['分组', settings.group || '未分组'], ['标签', settings.tags.join('、') || '无'], ['成本', costLabel(settings.cost)], ['到期时间', settings.expires_at_ms ? timestamp(settings.expires_at_ms) : '未设置']])); body.append(el('pre', settings.notes || '无备注')); modal('节点资料', body); return; }
  const form = el('form'); field(form, 'node_name', '节点名称', node.name).maxLength = 120;
  const editor = nodeSettingsEditor(form, settings, () => !!node.lease.policy);
  submit(form, '保存资料', async data => { await api(`/nodes/${node.id}/profile`, { method: 'PUT', body: { expected_revision: node.profile.revision, name: String(data.get('node_name')).trim(), settings: editor.read(data) } }); $('#dialog').close(); await renderNodes(); notify('节点资料已保存；转发配置保持原修订。'); }); modal('编辑节点 · ' + node.name, form);
}
function filterNodes() {
  const form = el('form'), current = state.nodeFilter;
  field(form, 'q', '搜索名称、ID、标签或备注', current.q || '', 'text', false);
  select(form, 'kind', '节点类型', [['', '全部类型'], ...Object.entries(nodeKindNames)], current.kind || '');
  field(form, 'group', '分组（精确匹配）', current.group || '', 'text', false);
  field(form, 'tag', '标签（精确匹配）', current.tag || '', 'text', false);
  select(form, 'lifecycle', '运行许可', [['', '全部'], ['active', '允许运行且未到期'], ['disabled', '已暂停'], ['expired', '已到期']], current.lifecycle || '');
  submit(form, '应用筛选', async data => { state.nodeFilter = Object.fromEntries([...data.entries()].map(([k,v]) => [k,String(v).trim()]).filter(([,v]) => v)); state.selectedNodes.clear(); $('#dialog').close(); await renderNodes(); }); modal('筛选节点', form);
}
function batchNodeProfiles() {
  const selected = state.nodes.filter(node => state.selectedNodes.has(node.id));
  if (!selected.length) throw new Error('请先勾选要编辑的节点');
  if (selected.length > 100) throw new Error('每次最多编辑 100 个节点');
  const form = el('form'); form.append(el('p', `已选择 ${selected.length} 个节点：${selected.map(n => n.name).join('、')}`));
  const operation = select(form, 'operation', '批量操作', [['group','设置或清空分组'], ['add_tags','增加标签'], ['remove_tags','移除标签'], ['pause','暂停运行'], ['enable','允许运行']], 'group');
  const value = textarea(form, 'value', '分组名称，或每行一个标签', '');
  operation.onchange = () => { value.disabled = ['pause','enable'].includes(operation.value); };
  form.append(el('p', '所有节点验证通过后一起保存。任一节点资料过期或权限不符，整批均不修改；重新打开后再编辑。暂停仅支持严格租约，不自动退款；允许运行后仍须检查到期时间和 Agent 状态。', 'fine'));
  submit(form, '保存选中节点', async data => {
    const action = data.get('operation'), text = String(data.get('value') || '').trim(), tags = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const updates = selected.map(node => { const settings = structuredClone(node.profile.settings);
      if (action === 'group') settings.group = text || null;
      if (action === 'add_tags') settings.tags = [...new Set([...settings.tags, ...tags])];
      if (action === 'remove_tags') settings.tags = settings.tags.filter(t => !tags.includes(t));
      if (action === 'pause') settings.enabled = false;
      if (action === 'enable') settings.enabled = true;
      return { node_id: node.id, update: { expected_revision: node.profile.revision, name: node.name, settings } };
    });
    const results = await api('/nodes/profiles', { method: 'POST', body: { updates } }); state.selectedNodes.clear(); $('#dialog').close(); await renderNodes(); const body = el('div'); body.append(table(['节点', '资料修订', '运行许可'], results.map(r => [r.name, r.profile.revision, {active:'允许运行',disabled:'已暂停',expired:'已到期'}[r.lifecycle]]))); modal('批量保存完成', body);
  }); modal('批量编辑节点资料', form);
}
function nodeInventoryCell(node) { const s = node.profile.settings, cell = el('div'); cell.append(el('strong', s.kinds.map(k => nodeKindNames[k]).join(' / ') || '未标注'), el('div', [s.group || '未分组', ...s.tags].join(' · '), 'subline'), el('div', costLabel(s.cost), 'subline')); return cell; }
function nodeLifecycleCell(node) { const cell = el('div'), names = { active: '允许运行', disabled: '已暂停', expired: '已到期' }; cell.append(badge(names[node.lifecycle], node.lifecycle === 'active' ? 'green' : 'orange')); if (node.profile.settings.expires_at_ms) cell.append(el('div', timestamp(node.profile.settings.expires_at_ms), 'subline')); if (node.lifecycle !== 'active' && node.lease.active) cell.append(el('div', '现有租约尚在收敛', 'subline')); return cell; }

function newNode() {
  const form=el('form');field(form,'name','节点名称','','text').maxLength=120;
  const mode=select(form,'lease_mode','运行保护策略',[['offline','可用优先（推荐）：控制器离线时继续转发'],['strict','严格租约：按量计费节点']],'offline');
  const ttl=field(form,'lease_ttl','租约窗口 / 秒',30,'number');ttl.min=5;ttl.max=120;ttl.disabled=true;
  const editor=nodeSettingsEditor(form,{},()=>mode.value==='strict');mode.onchange=()=>{ttl.disabled=mode.value!=='strict';editor.policy();};
  form.append(el('p','节点归属当前租户。可用优先：控制器离线时按最后配置继续转发，崩溃后约 1 秒恢复；不能阻止复制的节点身份同时运行，控制器离线期间额度不能严格限制，也不支持暂停或到期。严格租约：与控制器失联超过租约窗口会停止转发，崩溃后要等旧租约过期。运行策略创建后固定。注册令牌只显示一次。','fine'));
  submit(form,'创建节点',async data=>{const result=await api('/nodes',{method:'POST',body:{name:String(data.get('name')).trim(),lease_policy:mode.value==='strict'?{ttl_ms:number(data,'lease_ttl')*1000}:null,settings:editor.read(data)}});const body=el('div');body.append(el('p','请将此令牌保存为节点上的私有文件（权限 0600）。'),el('div',result.enrollment_token,'secret-box'));body.append(el('p','节点启动命令','fine'),el('pre',`relay agent --controller ${location.origin} --node-id ${result.node.id} --enrollment-token-file /path/to/enrollment.secret --state /var/lib/relay-agent`),el('p','跨机器接入须使用 HTTPS。本机 HTTP 地址仅用于本地验收。','fine'),button('我已保存令牌',()=>$('#dialog').close(),'primary'));$('#dialog').close();modal('节点已创建 · 保存一次性令牌',body);state.selectedNode=result.node.id;await renderNodes();});modal('注册节点',form);
}


async function renderRules() {
  state.nodes = await api('/nodes'); const content = $('#content');
  if (!state.nodes.length) { content.replaceChildren(empty('还没有节点', '先注册节点，再创建规则。', button('前往节点管理', () => navigate('nodes'), 'primary'))); return; }
  if (!state.nodes.some(n => n.id === state.selectedNode)) state.selectedNode = state.nodes[0].id;
  const toolbar = el('div', undefined, 'toolbar'), selector = el('select'); selector.setAttribute('aria-label', '选择节点'); state.nodes.forEach(n => { const option = el('option', n.name); option.value = n.id; selector.append(option); }); selector.value = state.selectedNode; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; toolbar.append(selector);
  const nodeId = state.selectedNode; const config = await api(`/nodes/${nodeId}/config`); if (state.view !== 'rules' || state.selectedNode !== nodeId) return; state.config = config;
  toolbar.append(badge(`期望修订 v${config.revision}`), badge(config.rate_bytes_per_sec ? `节点总限速 ${mbit(config.rate_bytes_per_sec)}` : '节点不限速', config.rate_bytes_per_sec ? 'orange' : ''), button('版本历史', history)); if (canWrite()) toolbar.append(button('节点总限速', () => editNodeRate(config)));
  const p = panel('转发规则', '配额按上下行接纳字节合计。更改安全策略会终止关联会话。', canWrite() ? button('＋ 添加规则', () => editRule(), 'primary') : null);
  if (!config.rules.length) p.append(empty('创建一条真实转发规则', '支持 TCP、UDP 和双协议，可设置多个目标、配额、速率和来源网段。', canWrite() ? button('添加规则', () => editRule(), 'primary') : null));
  else p.append(table(['名称', '监听 / 协议', '目标', '配额 / 限速', '状态', '操作'], config.rules.map(rule => { const actions = el('div'); if (rule.inbound_shadowsocks) actions.append(button('分享链接', () => shareShadowsocks(rule), 'table-action')); if (rule.inbound_socks5) actions.append(button('分享链接', () => shareSocks5(rule), 'table-action')); if (rule.inbound_http_connect) actions.append(button('分享链接', () => shareHttpConnect(rule), 'table-action')); if (canWrite()) { if (state.actor.role !== 'viewer') actions.append(button('存为模板', () => saveTemplate(rule), 'table-action')); actions.append(button('编辑', () => editRule(rule), 'table-action'), button(rule.enabled ? '停用' : '启用', () => saveRules(config.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r), config), 'table-action'), button('删除', async () => { if (confirm(`删除「${rule.name}」会终止其会话，历史账本保留。`)) await saveRules(config.rules.filter(r => r.id !== rule.id), config); }, 'table-action danger')); } return [namedCell(rule.name, rule.id), namedCell(rule.listen + (rule.listen_end_port ? ` → ${rule.listen_end_port}` : ''), rule.protocol.toUpperCase()), rule.inbound_shadowsocks ? namedCell('Shadowsocks 代理服务', rule.inbound_shadowsocks.method) : rule.inbound_socks5 ? namedCell('SOCKS5 代理服务', rule.inbound_socks5.username ? '用户名密码认证' : '无认证') : rule.inbound_http_connect ? namedCell('HTTP CONNECT 代理服务', rule.inbound_http_connect.username ? 'Basic 认证' : '无认证') : namedCell(rule.targets[0].address, `${rule.targets.length} 个目标 · ${rule.balance}`), `${rule.quota_bytes === null ? '不限量' : bytes(rule.quota_bytes)} / ${rule.rate_bytes_per_sec === null ? '不限速' : bytes(rule.rate_bytes_per_sec) + '/s'}`, badge(rule.enabled ? '已启用' : '已停用', rule.enabled ? 'green' : ''), actions]; })));
  content.replaceChildren(toolbar, p);
}
function mbit(rate) { return `${+(rate * 8 / 1e6).toFixed(2)} Mbit/s`; }
function editNodeRate(baseConfig) {
  const form = el('form'), grid = el('div', undefined, 'form-grid'); const input = field(grid, 'mbit', '本节点所有规则上下行合计 / Mbit/s（留空不限速）', baseConfig.rate_bytes_per_sec ? +(baseConfig.rate_bytes_per_sec * 8 / 1e6).toFixed(3) : '', 'number', false); input.min = 0.008; input.step = 'any'; form.append(grid, el('p', '与规则自身的限速同时生效，取较严者。立即作用于已有连接，不会断开会话；健康探测不计入。', 'muted'));
  submit(form, '发布限速', async data => { const raw = String(data.get('mbit')).trim(); const rate = raw === '' ? null : Math.round(Number(raw) * 1e6 / 8); if (rate !== null && !(rate >= 1 && rate <= 1e12)) throw new Error('请输入 0.008 到 8,000,000 之间的 Mbit/s'); await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision: baseConfig.revision, rules: baseConfig.rules, rate_bytes_per_sec: rate } }); $('#dialog').close(); notify(rate ? `已发布节点总限速 ${mbit(rate)}。` : '已取消节点总限速。'); await renderRules(); });
  modal('节点总限速', form);
}
async function saveRules(rules, baseConfig) { const expected_revision = baseConfig.revision; await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision, rules } }); $('#dialog').close(); notify('配置已发布。请在节点总览确认实际应用修订号。'); await renderRules(); }
async function editRule(existing) {
  const baseConfig = state.config; const topology = await api('/topology'); const form = el('form'), grid = el('div', undefined, 'form-grid'), r = existing || {};
  field(grid, 'name', '规则名称', r.name || '').maxLength = 120;
  const protocolControl = select(grid, 'protocol', '协议', [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], r.protocol || 'tcp');
  field(grid, 'listen', '监听地址', r.listen || '127.0.0.1:9000');
  field(grid, 'advertise', '供其他节点连接的地址（跨节点引用时填写）', r.advertise || '', 'text', false);
  const endPort = field(grid, 'listen_end_port', '结束端口（留空只监听一个端口，最多 256 个）', r.listen_end_port, 'number', false); endPort.min = 1; endPort.max = 65535;
  select(grid, 'port_mapping', '端口段的目标映射', [['fixed', '全部入口连接同一目标端口'], ['offset', '按入口端口偏移目标端口']], r.port_mapping || 'fixed');
  const balance = select(grid, 'balance', '目标分配', [['weighted_round_robin', '加权轮询'], ['source_hash', '来源 IP 哈希'], ['least_connections', '最少连接'], ['lowest_latency', '最低延迟（须启用健康探测）']], r.balance || 'weighted_round_robin'); form.append(grid);
  const shadowsocks = shadowsocksEditor(r.inbound_shadowsocks); form.append(shadowsocks.box);
  const socks5 = socks5Editor(r.inbound_socks5); form.append(socks5.box);
  const httpConnect = httpConnectEditor(r.inbound_http_connect); form.append(httpConnect.box);
  const routed = el('div'); form.append(routed);
  const readHealth = healthEditor(routed, r.health_check, protocolControl);
  const multipath = multipathEditor(routed, r);
  const readTargets = targetEditor(routed, r.targets?.length ? r.targets : [{ address: '127.0.0.1:8000', weight: 1 }], topology, state.nodes.find(node => node.id === baseConfig.node_id).tenant_id, r.id, r.outbound_multipath?.paths, multipath.mode);
  // A Shadowsocks server goes where each client asks, so it has no targets.
  function showRouted() { const server = shadowsocks.enabled() || socks5.enabled() || httpConnect.enabled(), parts = [routed, transport, inboundWs.box]; parts.forEach(part => part.classList.toggle('hidden', server)); balance.parentElement.classList.toggle('hidden', server); parts.flatMap(part => [...part.querySelectorAll('input, select, textarea')]).forEach(input => { if (server) { input.dataset.wasDisabled ??= String(input.disabled); input.disabled = true; } else if (input.dataset.wasDisabled !== undefined) { input.disabled = input.dataset.wasDisabled === 'true'; delete input.dataset.wasDisabled; } }); }
  const routing = el('details'); routing.append(el('summary', '出口绑定与 DNS 缓存')); const routeFields = el('div', undefined, 'form-grid');
  field(routeFields, 'outbound_ip', '出口源 IP（留空由系统选择）', r.outbound_bind?.ip || '', 'text', false);
  field(routeFields, 'outbound_interface', '出口网卡名称（留空由系统选择）', r.outbound_bind?.interface || '', 'text', false);
  const dnsMode = select(routeFields, 'dns_mode', '目标域名解析', [['system', '沿用系统解析'], ['cache', '启用按 TTL 缓存']], r.dns_cache ? 'cache' : 'system'); routing.append(routeFields);
  const dnsFields = el('div', undefined, 'form-grid');
  textarea(dnsFields, 'dns_servers', 'DNS 服务器 IP:端口，每行一个（留空读取系统配置）', (r.dns_cache?.servers || []).join('\n'));
  for (const [key, label, fallback, min, max] of [['capacity', '缓存响应数上限', 1024, 1, 4096], ['max_ttl_secs', '正响应 TTL 上限 / 秒（0 不缓存）', 300, 0, 3600], ['negative_max_ttl_secs', '不存在记录的 TTL 上限 / 秒', 5, 0, 60]]) { const input = field(dnsFields, `dns_${key}`, label, r.dns_cache?.[key] ?? fallback, 'number'); input.min = min; input.max = max; }
  function showDns() { const enabled = dnsMode.value === 'cache'; dnsFields.classList.toggle('hidden', !enabled); dnsFields.querySelectorAll('input, textarea').forEach(input => { input.disabled = !enabled; }); } dnsMode.addEventListener('change', showDns); showDns();
  routing.append(dnsFields, el('p', '出口绑定只约束业务连接；绑定失败时配置不会生效。DNS 查询沿用系统路由。缓存遵守响应 TTL，不会延长短 TTL。IPv6 监听只接收 IPv6。', 'fine')); form.append(routing);
  const transport = el('details'); transport.append(el('summary', '入口 TLS 与客户端认证')); const tlsFields = el('div', undefined, 'form-grid');
  field(tlsFields, 'tls_identity', '入口证书编号（留空使用普通连接）', r.inbound_tls?.identity || '', 'text', false);
  field(tlsFields, 'tls_client_ca', '允许客户端的 CA 编号（留空不要求客户端证书）', r.inbound_tls?.client_ca || '', 'text', false); transport.append(tlsFields, el('p', '证书和私钥预先放在节点本地，面板只保存编号。TLS 仅用于 TCP；一条规则的所有出口必须使用相同的安全方式。', 'fine')); form.append(transport);
  const inboundWs = websocketEditor('inbound-ws', r.inbound_websocket, true); form.append(inboundWs.box);
  // Clients also send QUIC, DNS and games over UDP, so a new server carries both.
  shadowsocks.onchange(() => { if (!existing && shadowsocks.enabled() && protocolControl.value === 'tcp') protocolControl.value = 'both'; showRouted(); }); socks5.onchange(() => { if (!existing && socks5.enabled()) protocolControl.value = 'tcp'; showRouted(); }); httpConnect.onchange(() => { if (!existing && httpConnect.enabled()) protocolControl.value = 'tcp'; showRouted(); }); showRouted();
  const proxyInput = el('details'); proxyInput.append(el('summary', '接收可信上游传递的原始地址（PROXY protocol）'));
  const proxyMode = select(proxyInput, 'proxy_input_version', '入口 PROXY 报头', [['off', '关闭'], ['v1', '要求 v1 · 仅 TCP'], ['v2', '要求 v2 · TCP / UDP'], ['any', '要求 v1 或 v2 · 仅 TCP']], r.inbound_proxy?.version || 'off');
  const proxyOptions = el('div', undefined, 'form-grid');
  textarea(proxyOptions, 'proxy_trusted_sources', '允许发送报头的代理 CIDR（每行一个，不能为空）', (r.inbound_proxy?.trusted_sources || ['127.0.0.0/8', '::1/128']).join('\n'), true);
  select(proxyOptions, 'proxy_input_placement', 'PROXY 报头位置', [['before_tls', 'TLS 之前（普通连接也选此项）'], ['inside_tls', 'TLS 加密连接内（须同时启用入口 TLS）']], r.inbound_proxy?.placement || 'before_tls');
  const proxyLimit = field(proxyOptions, 'proxy_header_limit', '报头字节上限', r.inbound_proxy?.max_header_bytes ?? 4096, 'number'); proxyLimit.min = 16; proxyLimit.max = 65551;
  select(proxyOptions, 'proxy_accept_prewarmed', '接受上一跳的预热连接', [['no', '不接受 · 报头须在连接超时内到达'], ['yes', '接受 · 最长等待 30 秒报头再连接目标']], r.inbound_proxy?.accept_prewarmed ? 'yes' : 'no');
  function showProxyInput() { const enabled = proxyMode.value !== 'off'; proxyOptions.classList.toggle('hidden', !enabled); proxyOptions.querySelectorAll('input, select, textarea').forEach(input => { input.disabled = !enabled; }); } proxyMode.addEventListener('change', showProxyInput); showProxyInput();
  proxyInput.append(proxyOptions, el('p', '启用后必须携带正确报头；直接客户端将被拒绝。来源 ACL 和来源哈希按报头中的客户端地址执行。PROXY 和 CRC32C 不提供身份认证；可信网段应只包含你的代理。UDP 每包都须携带 v2，回复为普通业务数据。', 'fine')); form.append(proxyInput);
  const limits = el('div', undefined, 'form-grid'); field(limits, 'quota_bytes', '合并配额 / bytes（留空不限，0 禁止流量）', r.quota_bytes, 'number', false).min = 0; field(limits, 'rate_bytes_per_sec', '合并速率 / bytes/s（留空不限）', r.rate_bytes_per_sec, 'number', false).min = 1; form.append(limits);
  if(existing){const label=el('label',undefined,'inline-check'),fresh=el('input');fresh.type='checkbox';fresh.name='new_meter_period';label.append(fresh,document.createTextNode('明确开始新计量周期：旧账保留，重新发放本规则额度；共享预算不重置'));form.append(label);}
  const details = el('details'); details.append(el('summary', '高级：超时、会话上限、到期和来源网段')); const advanced = el('div', undefined, 'form-grid');
  for (const [name, label, fallback, min, max] of [['connect_timeout_ms', '连接超时 / ms', 5000, 100, 60000], ['idle_timeout_secs', '空闲回收 / 秒', 120, 1, 86400], ['max_connections', 'TCP 最大连接', 4096, 1, 1000000], ['udp_max_sessions', 'UDP 最大会话', 1024, 1, 100000]]) { const input = field(advanced, name, label, r[name] ?? fallback, 'number'); input.min = min; input.max = max; }
  const expiry = field(advanced, 'expires_at_ms', '到期 / Unix 毫秒（留空永不过期）', r.expires_at_ms, 'number', false); expiry.min = 0; details.append(advanced); textarea(details, 'allow_sources', '允许来源 CIDR（留空允许所有未拒绝来源，每行一个）', (r.allow_sources || []).join('\n')); textarea(details, 'deny_sources', '拒绝来源 CIDR（优先于允许列表，每行一个）', (r.deny_sources || []).join('\n')); textarea(details, 'allow_destinations', '允许目的地（IP/CIDR/域名/*.example.com，留空允许所有未拒绝，每行一个）', (r.allow_destinations || []).join('\n')); textarea(details, 'deny_destinations', '拒绝目的地（优先于允许列表，每行一个）', (r.deny_destinations || []).join('\n')); form.append(details);
  const enabledLabel = el('label', undefined, 'inline-check'), enabled = el('input'); enabled.name = 'enabled'; enabled.type = 'checkbox'; enabled.checked = r.enabled ?? true; enabledLabel.append(enabled, document.createTextNode('启用规则')); form.append(enabledLabel);
  form.append(el('p', '同一规则的所有连接共享额度和速率。速率桶允许 max(64 KiB, 一秒额度) 的突发；这不是跨节点用户总限速。', 'fine'));
  submit(form, existing ? '发布修改' : '创建并发布', async data => {
    const node = state.nodes.find(n => n.id === baseConfig.node_id), lines = key => String(data.get(key)).split('\n').map(s => s.trim()).filter(Boolean);
    const server = shadowsocks.read(), socks = socks5.read(), http = httpConnect.read();
    const rule = { id: r.id || crypto.randomUUID(), tenant_id: node.tenant_id, owner_id: r.owner_id || state.actor.id, name: data.get('name'), protocol: data.get('protocol'), listen: data.get('listen'), balance: data.get('balance'), enabled: data.get('enabled') === 'on', targets: server || socks || http ? [] : readTargets(), meter_epoch: data.get('new_meter_period')==='on'?crypto.randomUUID():(r.meter_epoch || crypto.randomUUID()), allow_sources: lines('allow_sources'), deny_sources: lines('deny_sources'), allow_destinations: lines('allow_destinations'), deny_destinations: lines('deny_destinations') };
    if (server) rule.inbound_shadowsocks = server;
    else if (socks) rule.inbound_socks5 = socks;
    else if (http) rule.inbound_http_connect = http;
    else { rule.health_check = readHealth(); Object.assign(rule, multipath.read(readTargets.multipathPaths())); }
    rule.advertise = String(data.get('advertise')).trim() || null;
    rule.listen_end_port = number(data, 'listen_end_port'); rule.port_mapping = data.get('port_mapping');
    const outboundIp = String(data.get('outbound_ip')).trim(), outboundInterface = String(data.get('outbound_interface')).trim();
    if (outboundIp || outboundInterface) rule.outbound_bind = { ip: outboundIp || null, interface: outboundInterface || null };
    if (data.get('dns_mode') === 'cache') rule.dns_cache = { servers: lines('dns_servers'), capacity: number(data, 'dns_capacity'), max_ttl_secs: number(data, 'dns_max_ttl_secs'), negative_max_ttl_secs: number(data, 'dns_negative_max_ttl_secs') };
    // Hidden for a Shadowsocks server, so absent from the form data.
    const identity = String(data.get('tls_identity') ?? '').trim(), clientCa = String(data.get('tls_client_ca') ?? '').trim();
    if (clientCa && !identity) throw new Error('要求客户端证书时，请同时填写入口证书编号');
    if (identity) rule.inbound_tls = { identity, client_ca: clientCa || null };
    const websocket = inboundWs.read(); if (websocket) rule.inbound_websocket = websocket;
    if (rule.protocol !== 'tcp' && (websocket || rule.targets.some(target => target.websocket))) throw new Error('WebSocket / WSS 流隧道只支持 TCP，请调整规则协议');
    if (data.get('proxy_input_version') !== 'off') rule.inbound_proxy = { version: data.get('proxy_input_version'), trusted_sources: lines('proxy_trusted_sources'), placement: data.get('proxy_input_placement'), max_header_bytes: number(data, 'proxy_header_limit'), accept_prewarmed: data.get('proxy_accept_prewarmed') === 'yes' };
    for (const key of ['quota_bytes', 'rate_bytes_per_sec', 'expires_at_ms', 'connect_timeout_ms', 'idle_timeout_secs', 'max_connections', 'udp_max_sessions']) rule[key] = number(data, key);
    await saveRules(existing ? baseConfig.rules.map(item => item.id === r.id ? rule : item) : [...baseConfig.rules, rule], baseConfig);
  }); modal(existing ? '编辑转发规则' : '添加转发规则', form);
}
const shadowsocksMethods = [['2022-blake3-aes-256-gcm', '2022-blake3-aes-256-gcm（推荐 · 防重放）'], ['2022-blake3-aes-128-gcm', '2022-blake3-aes-128-gcm（防重放）'], ['2022-blake3-chacha20-poly1305', '2022-blake3-chacha20-poly1305（无 AES 加速的设备）'], ['aes-256-gcm', 'aes-256-gcm（旧客户端兼容）'], ['aes-128-gcm', 'aes-128-gcm（旧客户端兼容）'], ['chacha20-ietf-poly1305', 'chacha20-ietf-poly1305（旧客户端兼容）']];
function shadowsocksKey(method) {
  const bytes = crypto.getRandomValues(new Uint8Array(method.includes('128') ? 16 : 32)), text = btoa(String.fromCharCode(...bytes));
  // 2022 methods take a key of exactly this length; older ones a password.
  return method.startsWith('2022-') ? text : text.replace(/[+/=]/g, '').slice(0, 24);
}
function shadowsocksEditor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', 'Shadowsocks 代理服务（客户端自选目的地）'));
  const method = select(box, 'ss_method', '加密方式', [['off', '关闭 · 按下方目标转发'], ...shadowsocksMethods], spec?.method || 'off');
  const fields = el('div', undefined, 'form-grid');
  const password = field(fields, 'ss_password', '密钥', spec?.password || ''); password.autocomplete = 'off'; password.classList.add('mono');
  select(fields, 'ss_private', '允许访问内网 / 本机地址', [['no', '不允许（推荐）'], ['yes', '允许 · 客户端可访问本节点所在内网']], spec?.allow_private_destinations ? 'yes' : 'no');
  const regenerate = button('生成新密钥', () => { password.value = shadowsocksKey(method.value); });
  let last = method.value;
  function show() {
    const enabled = method.value !== 'off'; box.querySelectorAll('.ss-fields').forEach(n => n.classList.toggle('hidden', !enabled)); fields.querySelectorAll('input, select').forEach(input => { input.disabled = !enabled; });
    // Key lengths differ between methods; a key that no longer fits is replaced.
    if (enabled && (!password.value || last.startsWith('2022-') !== method.value.startsWith('2022-') || (method.value.startsWith('2022-') && last.includes('128') !== method.value.includes('128')))) password.value = shadowsocksKey(method.value);
    last = method.value;
  }
  const note = el('p', '启用后本规则不设目标：客户端（Shadowrocket、Clash、sing-box、v2rayN 等）在每个连接里指定要访问的网站，本节点直接连接。保存后在规则列表点“分享链接”导入客户端。协议选 TCP + UDP 时客户端的 QUIC、DNS、游戏和语音也经过本节点。2022 方式要求两端时钟误差在 30 秒内。', 'fine');
  fields.classList.add('ss-fields'); regenerate.classList.add('ss-fields'); note.classList.add('ss-fields');
  box.append(fields, regenerate, note);
  method.addEventListener('change', show); show();
  return { box, enabled: () => method.value !== 'off', onchange: f => method.addEventListener('change', f), read: () => method.value === 'off' ? null : { method: method.value, password: password.value.trim(), allow_private_destinations: fields.querySelector('[name=ss_private]').value === 'yes' } };
}
function shadowsocksLink(spec, host, port, tag) {
  const userinfo = spec.method.startsWith('2022-') ? `${encodeURIComponent(spec.method)}:${encodeURIComponent(spec.password)}`
    : btoa(String.fromCharCode(...new TextEncoder().encode(`${spec.method}:${spec.password}`))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `ss://${userinfo}@${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}#${encodeURIComponent(tag)}`;
}
function shareShadowsocks(rule) {
  const split = address => { const at = address.lastIndexOf(':'); return [address.slice(0, at).replace(/^\[|\]$/g, ''), address.slice(at + 1)]; };
  const [listenHost, listenPort] = split(rule.listen), [advertiseHost, advertisePort] = rule.advertise ? split(rule.advertise) : [];
  const body = el('div'), grid = el('div', undefined, 'form-grid');
  const host = field(grid, 'host', '客户端连接的地址（公网 IP 或域名）', advertiseHost || (['0.0.0.0', '::'].includes(listenHost) ? location.hostname : listenHost));
  const port = field(grid, 'port', '端口', advertisePort || listenPort, 'number'); port.min = 1; port.max = 65535;
  const tag = field(grid, 'tag', '客户端里显示的名称', rule.name);
  const link = el('div', '', 'secret-box mono');
  const update = () => { link.textContent = shadowsocksLink(rule.inbound_shadowsocks, host.value.trim(), port.value.trim(), tag.value.trim()); };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button('关闭', () => $('#dialog').close()), button('复制链接', async () => { await navigator.clipboard.writeText(link.textContent); notify('链接已复制。'); }, 'primary'));
  body.append(grid, link, el('p', '客户端先连到入口节点再中转到这里时，请填写入口节点的地址和端口。链接包含密钥，持有者即可使用本节点上网，请只发给使用者本人；需要停用时更换密钥或停用规则。', 'fine'), actions);
  modal(`分享 ${rule.name}`, body);
}
async function history() { const baseConfig = state.config; const revisions = await api(`/nodes/${baseConfig.node_id}/history`); const body = table(['修订', '操作者', '时间', '操作'], revisions.map(r => [`v${r.revision}`, r.actor_id, timestamp(r.created_at_ms), canWrite() ? button('发布此版本', async () => { await api(`/nodes/${baseConfig.node_id}/rollback`, { method: 'POST', body: { revision: r.revision, expected_revision: baseConfig.revision } }); $('#dialog').close(); notify('历史配置已作为新修订发布。账本不回滚。'); await renderRules(); }, 'table-action') : '只读'])); modal('最近 100 次配置修订', body); }
function httpConnectEditor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', 'HTTP CONNECT 入口（TCP）'));
  const fields = el('div', undefined, 'form-grid');
  const enabled = select(fields, 'http_connect_enabled', 'HTTP CONNECT 服务', [['off', '关闭 · 按下方目标转发'], ['on', '启用 · 客户端指定 CONNECT 目的地']], spec ? 'on' : 'off');
  const username = field(fields, 'http_connect_user', '用户名（留空不认证）', spec?.username || '', 'text', false); username.maxLength = 255;
  const password = field(fields, 'http_connect_password', '密码（与用户名同时填写）', spec?.password || '', 'password', false); password.maxLength = 255;
  const privateMode = select(fields, 'http_connect_private', '允许连接内网/回环目的地', [['no', '拒绝（推荐）'], ['yes', '允许']], spec?.allow_private_destinations ? 'yes' : 'no');
  const note = el('p', '只接受 HTTP/1.x CONNECT；其它方法返回 405。启用认证时要求 Proxy-Authorization: Basic。启用后规则不能有固定目标，协议必须为 TCP。', 'fine');
  function show() { const on = enabled.value === 'on'; username.disabled = password.disabled = !on; privateMode.disabled = !on; note.classList.toggle('hidden', !on); }
  enabled.addEventListener('change', show); show(); box.append(fields, note);
  return { box, enabled: () => enabled.value === 'on', onchange: fn => enabled.addEventListener('change', fn), read: () => {
    if (enabled.value !== 'on') return null;
    const user = username.value.trim(), pass = password.value;
    if (!!user !== !!pass) throw new Error('HTTP CONNECT 用户名和密码必须同时填写或同时留空');
    return { username: user || null, password: pass || null, allow_private_destinations: privateMode.value === 'yes' };
  }};
}
function httpConnectLink(config, host, port, tag) {
  const auth = config.username ? `${encodeURIComponent(config.username)}:${encodeURIComponent(config.password)}@` : '';
  const address = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return `http://${auth}${address}:${port}#${encodeURIComponent(tag)}`;
}
function shareHttpConnect(rule) {
  const body = el('div'); const grid = el('div', undefined, 'form-grid');
  const host = field(grid, 'host', '客户端连接的地址', location.hostname || '127.0.0.1');
  const port = field(grid, 'port', '端口', rule.listen.split(':').pop(), 'number');
  const tag = field(grid, 'tag', '显示名称', rule.name);
  const link = el('div', undefined, 'secret-box'); const update = () => { link.textContent = httpConnectLink(rule.inbound_http_connect, host.value.trim(), port.value.trim(), tag.value.trim()); };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button('复制链接', async () => { await navigator.clipboard.writeText(link.textContent); notify('HTTP CONNECT 链接已复制。'); }, 'primary'));
  body.append(grid, link, el('p', '链接包含认证信息；这是 HTTP 代理地址，不是普通网页。', 'fine'), actions);
  modal(`分享 ${rule.name}`, body);
}
function socks5Editor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', 'SOCKS5 入口（TCP CONNECT）'));
  const fields = el('div', undefined, 'form-grid');
  const enabled = select(fields, 'socks5_enabled', 'SOCKS5 服务', [['off', '关闭 · 按下方目标转发'], ['on', '启用 · 客户端指定目的地']], spec ? 'on' : 'off');
  const username = field(fields, 'socks5_user', '用户名（留空不认证）', spec?.username || '', 'text', false); username.maxLength = 255;
  const password = field(fields, 'socks5_password', '密码（与用户名同时填写）', spec?.password || '', 'password', false); password.maxLength = 255;
  select(fields, 'socks5_private', '允许连接内网/回环目的地', [['no', '拒绝（推荐）'], ['yes', '允许']], spec?.allow_private_destinations ? 'yes' : 'no');
  const note = el('p', '支持 TCP CONNECT 与 UDP ASSOCIATE。使用 UDP 时请把协议设为 TCP + UDP；启用后规则不能有固定目标。用户名和密码要么都留空（无认证），要么都填写。分享链接包含密码，请只发给使用者。', 'fine');
  function show() { const on = enabled.value === 'on'; username.disabled = password.disabled = !on; fields.querySelectorAll('select')[1].disabled = !on; note.classList.toggle('hidden', !on); }
  enabled.addEventListener('change', show); show(); box.append(fields, note);
  return { box, enabled: () => enabled.value === 'on', onchange: fn => enabled.addEventListener('change', fn), read: () => {
    if (enabled.value !== 'on') return null;
    const user = username.value.trim(), pass = password.value;
    if (!!user !== !!pass) throw new Error('SOCKS5 用户名和密码必须同时填写或同时留空');
    return { username: user || null, password: pass || null, allow_private_destinations: fields.querySelector('[name=socks5_private]').value === 'yes' };
  }};
}
function socks5Link(config, host, port, tag) {
  const auth = config.username ? `${encodeURIComponent(config.username)}:${encodeURIComponent(config.password)}@` : '';
  const address = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return `socks5://${auth}${address}:${port}#${encodeURIComponent(tag)}`;
}
function shareSocks5(rule) {
  const body = el('div'); const grid = el('div', undefined, 'form-grid');
  const host = field(grid, 'host', '客户端连接的地址', location.hostname || '127.0.0.1');
  const port = field(grid, 'port', '端口', rule.listen.split(':').pop(), 'number');
  const tag = field(grid, 'tag', '显示名称', rule.name);
  const link = el('div', undefined, 'secret-box'); const update = () => { link.textContent = socks5Link(rule.inbound_socks5, host.value.trim(), port.value.trim(), tag.value.trim()); };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button('复制链接', async () => { await navigator.clipboard.writeText(link.textContent); notify('SOCKS5 链接已复制。'); }, 'primary'));
  body.append(grid, link, el('p', '链接包含认证信息；需要停用时删除规则或修改用户名/密码。', 'fine'), actions);
  modal(`分享 ${rule.name}`, body);
}
const subscriptionFormats = { v2ray: 'V2Ray / Base64（ss:// 列表）', clash: 'Clash / mihomo（YAML）', surge: 'Surge（文本）', shadowrocket: 'Shadowrocket（ss:// 列表）' };
const dnsModes = { observe: '观察（只读，不写服务商）', apply: '应用（创建/更新/删除托管记录）' };
const dnsRecordTypes = ['A', 'AAAA', 'CNAME'];
const announcementSeverities = { info: '信息', warning: '警告', critical: '严重' };
function announcementTime(ms) { return timestamp(ms); }
function announcementDateTime(ms) { const d = new Date(ms || Date.now()); const pad = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
const ticketStatuses = { open: '待处理', pending: '处理中', closed: '已关闭' };
const ticketPriorities = { low: '低', normal: '普通', high: '高' };
async function renderTemplates() {
  const templates = await api('/templates');
  const p = panel('规则模板', '模板保存一份已验证的规则内容；应用时生成新的规则 ID、名称、监听地址和计量周期，并走正常配置校验。', null);
  if (!templates.length) p.append(empty('还没有模板', '在“转发规则”表格中把一条规则存为模板。'));
  else p.append(table(['名称', '范围', '说明', '源监听', '操作'], templates.map(template => {
    const actions = el('div'); if (state.actor.role !== 'viewer') actions.append(button('应用', () => applyTemplate(template), 'table-action'));
    if (state.actor.role === 'system_admin' || template.tenant_id === state.actor.tenant_id) actions.append(button('删除', () => deleteTemplate(template), 'table-action danger'));
    return [namedCell(template.name, template.id), template.tenant_id || '全局', template.description || '—', template.rule.listen, actions];
  })));
  $('#content').replaceChildren(p);
}
async function saveTemplate(source) {
  const name = prompt('模板名称', source.name); if (!name) return;
  const description = prompt('模板说明（可留空）', '') || '';
  const tenant_id = state.actor.role === 'system_admin' ? null : state.actor.tenant_id;
  await api('/templates', { method: 'POST', body: { tenant_id, name, description, rule: source } });
  notify('规则已保存为模板。'); await renderTemplates();
}
async function deleteTemplate(template) {
  if (!confirm(`删除模板「${template.name}」？`)) return;
  await api(`/templates/${template.id}`, { method: 'DELETE' }); notify('模板已删除。'); await renderTemplates();
}
async function applyTemplate(template) {
  const nodes = state.nodes; const form = el('form'), grid = el('div', undefined, 'form-grid');
  const node = select(grid, 'node', '节点', nodes.map(n => [n.id, n.name || n.id]), nodes[0]?.id);
  field(grid, 'name', '新规则名称', template.name).maxLength = 120;
  field(grid, 'listen', '监听地址', '127.0.0.1:9000');
  form.append(grid, el('p', '应用会创建一个新修订；并发的配置编辑会以 409 拒绝，不会覆盖。', 'fine'));
  submit(form, '应用到节点', async data => {
    const config = await api(`/nodes/${node.value}/config`);
    await api(`/nodes/${node.value}/templates/${template.id}`, { method: 'POST', body: { expected_revision: config.revision, name: String(data.get('name')).trim(), listen: String(data.get('listen')).trim() } });
    $('#dialog').close(); notify('模板已应用，请在节点总览确认实际应用修订。'); await renderRules();
  });
  modal(`应用模板 · ${template.name}`, form);
}

async function renderTickets() {
  const tickets = await api('/tickets');
  const p = panel('工单', state.actor.role === 'system_admin' ? '系统管理员可查看全部租户工单。' : state.actor.role === 'tenant_admin' ? '租户管理员可查看本租户工单并添加内部备注。' : '你只能看到自己提交的工单。', button('＋ 新建工单', ticketForm, 'primary'));
  if (!tickets.length) p.append(empty('没有工单', '遇到问题时提交工单，管理员回复后会在这里显示。'));
  else p.append(table(['主题', '状态', '优先级', '更新', '操作'], tickets.map(ticket => {
    const actions = el('div'); actions.append(button('查看/回复', () => openTicket(ticket.id), 'table-action'));
    return [namedCell(ticket.subject, ticket.id), badge(ticketStatuses[ticket.status] || ticket.status, ticket.status === 'closed' ? '' : ticket.status === 'open' ? 'orange' : 'green'), ticketPriorities[ticket.priority] || ticket.priority, timestamp(ticket.updated_at_ms), actions];
  })));
  $('#content').replaceChildren(p);
}
function ticketForm() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'subject', '主题', '').maxLength = 200;
  textarea(grid, 'body', '问题描述', '').maxLength = 10000;
  select(grid, 'priority', '优先级', Object.entries(ticketPriorities), 'normal');
  form.append(grid);
  submit(form, '提交工单', async data => {
    await api('/tickets', { method: 'POST', body: { subject: String(data.get('subject')).trim(), body: String(data.get('body')), priority: data.get('priority') } });
    $('#dialog').close(); notify('工单已提交。'); await renderTickets();
  });
  modal('新建工单', form);
}
async function openTicket(id) {
  const view = await api(`/tickets/${id}`), t = view.ticket;
  const body = el('div');
  body.append(el('div', `${ticketStatuses[t.status] || t.status} · ${ticketPriorities[t.priority] || t.priority} · ${timestamp(t.created_at_ms)}`, 'muted'));
  const thread = el('div', undefined, 'ticket-thread');
  for (const message of view.messages) {
    const item = el('div', undefined, `ticket-message${message.internal ? ' internal' : ''}`);
    item.append(el('div', `${message.author_id === state.actor.id ? '我' : message.author_id}${message.internal ? ' · 内部备注' : ''}`, 'muted'), el('p', message.body));
    thread.append(item);
  }
  body.append(thread);
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  const reply = textarea(grid, 'reply', '回复内容', ''); reply.maxLength = 10000;
  const internal = state.actor.role !== 'viewer' ? checkbox(grid, 'internal', '内部备注（仅管理员可见）') : null;
  const actions = el('div', undefined, 'dialog-actions');
  if (t.status !== 'closed') {
    const send = button('发送回复', async () => {
      if (!reply.value.trim()) throw new Error('请输入回复内容');
      await api(`/tickets/${id}/messages`, { method: 'POST', body: { body: reply.value, internal: !!internal?.checked } });
      $('#dialog').close(); notify('回复已发送。'); await renderTickets();
    }, 'primary'); actions.append(send);
    if (state.actor.role !== 'viewer') actions.append(button('标记处理中', async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'pending' } }); $('#dialog').close(); await renderTickets(); }, 'table-action'));
  }
  if (t.status !== 'closed') actions.append(button('关闭工单', async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'closed' } }); $('#dialog').close(); notify('工单已关闭。'); await renderTickets(); }, 'table-action danger'));
  else if (state.actor.role !== 'viewer') actions.append(button('重新打开', async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'open' } }); $('#dialog').close(); await renderTickets(); }, 'table-action'));
  form.append(grid, actions); body.append(form);
  modal(`工单 · ${t.subject}`, body);
}
const orderStatuses = { pending: '待支付', paid: '已支付', refunded: '已退款' };
const orderChannels = { wallet: '钱包', external: '外部支付' };
const ledgerKinds = { adjustment: '调整', credit: '充值', purchase: '购买', refund: '退款' };
function money(cents) { return `¥${(cents / 100).toFixed(2)}`; }
async function renderCommerce() {
  const [wallet, plans, orders] = await Promise.all([api('/commerce/wallet'), api('/commerce/plans'), api('/commerce/orders')]);
  const webhook = state.actor.role === 'system_admin' ? await api('/commerce/webhook') : null;
  const coupons = state.actor.role === 'system_admin' ? await api('/commerce/coupons') : [];
  const gifts = state.actor.role === 'system_admin' ? await api('/commerce/gift-codes') : [];
  const walletActions = el('div'); walletActions.append(button('兑换礼品码', redeemGift, 'primary'));
  if (state.actor.role === 'system_admin') walletActions.append(button('调整用户钱包', adjustWallet, 'table-action'));
  const p = panel('钱包', `余额 ${money(wallet.wallet.balance_cents)} · ${wallet.wallet.currency}。余额可通过管理员调整、退款或礼品码入账；购买会即时扣款。`, walletActions);
  p.append(table(['金额', '类型', '说明', '引用', '时间'], wallet.entries.map(entry => [money(entry.delta_cents), ledgerKinds[entry.kind] || entry.kind, entry.description, entry.reference, timestamp(entry.created_at_ms)])));
  if (!wallet.entries.length) p.append(el('p', '还没有资金流水。', 'muted'));
  const plansPanel = panel('套餐', '价格以人民币分保存；购买订单保存套餐快照，后续改价不影响已创建订单。', state.actor.role === 'system_admin' ? button('＋ 新建套餐', () => planForm(null), 'primary') : null);
  if (!plans.length) plansPanel.append(empty('暂无可用套餐', '管理员创建并启用套餐后，用户可以创建订单。'));
  else plansPanel.append(table(['套餐', '说明', '价格', '时长', '流量', '操作'], plans.map(plan => {
    const actions = el('div'); actions.append(button('钱包购买', () => buyPlan(plan), 'table-action'), button('创建待支付订单', () => createPendingOrder(plan), 'table-action'));
    if (state.actor.role === 'system_admin') actions.append(button('编辑', () => planForm(plan), 'table-action'), button('删除', () => deletePlan(plan), 'table-action danger'));
    return [namedCell(plan.name, plan.id), plan.description || '—', money(plan.price_cents), `${plan.duration_days} 天`, plan.traffic_bytes ? bytes(plan.traffic_bytes) : '不限', actions];
  })));
  const ordersPanel = panel('订单', '订单只记录计费结果；套餐权益的自动发放/到期执行仍未实现。', null);
  if (!orders.length) ordersPanel.append(empty('还没有订单', '选择套餐购买后会生成订单。'));
  else ordersPanel.append(table(['套餐', '金额', '状态', '通道', '创建', '支付/退款', '操作'], orders.map(order => {
    const actions = el('div');
    if (order.status === 'pending') actions.append(button('钱包支付', async () => { await api(`/commerce/orders/${order.id}/pay`, { method: 'POST' }); notify('订单已支付。'); await renderCommerce(); }, 'table-action'), button('外部支付', () => externalPayment(order), 'table-action'));
    if (order.status === 'paid' && order.channel === 'wallet' && state.actor.role === 'system_admin') actions.append(button('退款', async () => { if (!confirm(`退款 ${money(order.amount_cents)} 到用户钱包？`)) return; await api(`/commerce/orders/${order.id}/refund`, { method: 'POST' }); notify('订单已退款。'); await renderCommerce(); }, 'table-action danger'));
    return [order.plan_name, money(order.amount_cents), badge(orderStatuses[order.status] || order.status, order.status === 'paid' ? 'green' : order.status === 'refunded' ? 'orange' : ''), orderChannels[order.channel] || order.channel || '钱包', timestamp(order.created_at_ms), order.paid_at_ms ? timestamp(order.paid_at_ms) : order.refunded_at_ms ? timestamp(order.refunded_at_ms) : '—', actions];
  })));
  const panels = [p, plansPanel, ordersPanel];
  if (state.actor.role === 'system_admin') {
    const g = panel('礼品码', '用户兑换后直接增加钱包余额；同一用户同一码只能兑换一次，次数上限和窗口仍然生效。', button('＋ 新建礼品码', () => giftForm(null), 'primary'));
    if (!gifts.length) g.append(empty('还没有礼品码', '创建后可让用户兑换。'));
    else g.append(table(['代码', '金额', '已用', '状态', '操作'], gifts.map(gift => { const actions = el('div'); actions.append(button('编辑', () => giftForm(gift), 'table-action'), button('删除', () => deleteGift(gift), 'table-action danger')); return [gift.code, money(gift.amount_cents), `${gift.redeemed}${gift.max_redemptions ? ' / ' + gift.max_redemptions : ''}`, gift.enabled ? badge('启用', 'green') : badge('停用', ''), actions]; })));
    panels.push(g);
    const c = panel('优惠码', '百分比按订单原价向下取整；固定金额不超过原价。订单保存原价、折扣和最终金额快照。', button('＋ 新建优惠码', () => couponForm(null), 'primary'));
    if (!coupons.length) c.append(empty('还没有优惠码', '创建后可让用户在创建订单时输入。'));
    else c.append(table(['代码', '类型', '优惠', '最低原价', '已用', '状态', '操作'], coupons.map(coupon => { const actions = el('div'); actions.append(button('编辑', () => couponForm(coupon), 'table-action'), button('删除', () => deleteCoupon(coupon), 'table-action danger')); return [coupon.code, coupon.kind === 'percent' ? '百分比' : '固定金额', coupon.kind === 'percent' ? `${coupon.value}%` : money(coupon.value), money(coupon.min_amount_cents), `${coupon.redeemed}${coupon.max_redemptions ? ' / ' + coupon.max_redemptions : ''}`, coupon.enabled ? badge('启用', 'green') : badge('停用', ''), actions]; })));
    panels.push(c);
  }
  if (webhook) {
    const w = panel('支付回调', '外部支付回调使用 HMAC-SHA256 验证原始请求体；配置/轮换密钥会使旧签名失效。', button('配置回调密钥', webhookForm, 'primary'));
    w.append(table(['状态', '密钥'], [[webhook.enabled ? badge('启用', 'green') : badge('停用', ''), webhook.secret_set ? badge('已设置', 'green') : badge('未设置', 'red')]]));
    panels.push(w);
  }
  $('#content').replaceChildren(...panels);
}
function redeemGift() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', '礼品码', '').maxLength = 32;
  form.append(grid, el('p', '兑换成功后金额立即进入钱包，并生成一条“充值”流水。每个用户每个码只能兑换一次。', 'fine'));
  submit(form, '兑换', async data => {
    const wallet = await api('/commerce/gift-codes/redeem', { method: 'POST', body: { code: String(data.get('code')).trim() } });
    $('#dialog').close(); notify(`已兑换，当前余额 ${money(wallet.balance_cents)}。`); await renderCommerce();
  });
  modal('兑换礼品码', form);
}
function giftForm(gift) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', '代码（6..32，字母数字/ - _）', gift?.code || '').maxLength = 32;
  field(grid, 'amount', '金额（元）', gift ? (gift.amount_cents / 100).toFixed(2) : '0.00', 'number').step = '0.01';
  field(grid, 'max', '最多兑换次数（留空不限）', gift?.max_redemptions ?? '', 'number', false).min = 1;
  select(grid, 'enabled', '状态', [['yes', '启用'], ['no', '停用']], gift?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', '礼品码创建后立即生效；每个用户每个码只能兑换一次。已有兑换时不能删除，只能停用。', 'fine'));
  submit(form, gift ? '保存礼品码' : '创建礼品码', async data => {
    const body = { code: String(data.get('code')).trim(), amount_cents: Math.round(Number(data.get('amount')) * 100), max_redemptions: number(data, 'max'), enabled: data.get('enabled') === 'yes' };
    if (!(body.amount_cents > 0)) throw new Error('礼品金额必须大于 0');
    if (gift) await api(`/commerce/gift-codes/${gift.id}`, { method: 'PUT', body });
    else await api('/commerce/gift-codes', { method: 'POST', body });
    $('#dialog').close(); notify('礼品码已保存。'); await renderCommerce();
  });
  modal(gift ? `编辑礼品码 · ${gift.code}` : '新建礼品码', form);
}
async function deleteGift(gift) {
  if (!confirm(`删除礼品码「${gift.code}」？已有兑换时会被拒绝。`)) return;
  await api(`/commerce/gift-codes/${gift.id}`, { method: 'DELETE' }); notify('礼品码已删除。'); await renderCommerce();
}
async function buyPlan(plan) {
  const coupon = prompt('优惠码（可留空）') || '';
  if (!confirm(`购买「${plan.name}」并立即从钱包扣款？`)) return;
  const order = await api('/commerce/orders', { method: 'POST', body: { plan_id: plan.id, coupon_code: coupon.trim() || null } });
  await api(`/commerce/orders/${order.id}/pay`, { method: 'POST' });
  notify('订单已支付。'); await renderCommerce();
}
async function createPendingOrder(plan) {
  const coupon = prompt('优惠码（可留空）') || '';
  await api('/commerce/orders', { method: 'POST', body: { plan_id: plan.id, coupon_code: coupon.trim() || null } });
  notify('订单已创建，可在订单中选择钱包或外部支付。'); await renderCommerce();
}
function couponForm(coupon) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', '代码（3..32，字母数字/ - _）', coupon?.code || '').maxLength = 32;
  select(grid, 'kind', '类型', [['percent', '百分比'], ['fixed', '固定金额（元）']], coupon?.kind || 'percent');
  const value = field(grid, 'value', '优惠值（百分比或元）', coupon ? (coupon.kind === 'percent' ? coupon.value : coupon.value / 100) : '', 'number'); value.step = '0.01'; value.min = 0;
  field(grid, 'min', '最低原价（元）', coupon ? (coupon.min_amount_cents / 100).toFixed(2) : '0.00', 'number').step = '0.01';
  field(grid, 'max', '最多使用次数（留空不限）', coupon?.max_redemptions ?? '', 'number', false).min = 1;
  select(grid, 'enabled', '状态', [['yes', '启用'], ['no', '停用']], coupon?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', '优惠码创建后立即可用；窗口从创建时开始，暂不提供定时窗口编辑。已有订单不会重新计算。', 'fine'));
  submit(form, coupon ? '保存优惠码' : '创建优惠码', async data => {
    const kind = String(data.get('kind')), raw = Number(data.get('value'));
    const body = { code: String(data.get('code')).trim(), kind, value: kind === 'percent' ? Math.round(raw) : Math.round(raw * 100), min_amount_cents: Math.round(Number(data.get('min')) * 100), max_redemptions: number(data, 'max'), enabled: data.get('enabled') === 'yes' };
    if (kind === 'percent' && !(body.value >= 1 && body.value <= 100)) throw new Error('百分比须为 1..100');
    if (kind === 'fixed' && !(body.value > 0)) throw new Error('固定金额须大于 0');
    if (coupon) await api(`/commerce/coupons/${coupon.id}`, { method: 'PUT', body });
    else await api('/commerce/coupons', { method: 'POST', body });
    $('#dialog').close(); notify('优惠码已保存。'); await renderCommerce();
  });
  modal(coupon ? `编辑优惠码 · ${coupon.code}` : '新建优惠码', form);
}
async function deleteCoupon(coupon) {
  if (!confirm(`删除优惠码「${coupon.code}」？已有使用时会被拒绝。`)) return;
  await api(`/commerce/coupons/${coupon.id}`, { method: 'DELETE' }); notify('优惠码已删除。'); await renderCommerce();
}
async function externalPayment(order) {
  const payment = await api(`/commerce/orders/${order.id}/payment`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', '把以下付款编号交给支付网关；网关回调必须携带对原始 JSON 的 HMAC-SHA256 签名。回调成功后订单变为已支付，但不会增加钱包余额。', 'fine'));
  body.append(el('div', payment.id, 'secret-box'), el('p', `回调地址：/api/v1/commerce/payments/callback`, 'mono'), el('p', `金额：${money(payment.amount_cents)} · 状态：${payment.status}`, 'mono'));
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button('复制付款编号', async () => { await navigator.clipboard.writeText(payment.id); notify('付款编号已复制。'); }, 'primary'), button('关闭', () => $('#dialog').close()));
  body.append(actions); modal(`外部支付 · ${order.plan_name}`, body);
}
function webhookForm() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'secret', '新 HMAC 密钥（至少 16 字节）', '', 'password').maxLength = 512;
  select(grid, 'enabled', '回调状态', [['yes', '启用'], ['no', '停用']], 'yes');
  form.append(grid, el('p', '密钥只用于验证回调，不在接口返回原文。回调头为 X-Relay-Signature，值为原始请求体的 HMAC-SHA256 十六进制（可带 sha256= 前缀）。', 'fine'));
  submit(form, '保存密钥', async data => {
    await api('/commerce/webhook', { method: 'PUT', body: { secret: String(data.get('secret')), enabled: data.get('enabled') === 'yes' } });
    $('#dialog').close(); notify('支付回调密钥已保存。'); await renderCommerce();
  });
  modal('配置支付回调', form);
}
function planForm(plan) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', '套餐名称', plan?.name || '').maxLength = 120;
  textarea(grid, 'description', '说明', plan?.description || '').maxLength = 5000;
  const price = field(grid, 'price', '价格（元）', plan ? (plan.price_cents / 100).toFixed(2) : '0.00', 'number'); price.min = 0; price.step = '0.01';
  const days = field(grid, 'days', '时长 / 天', plan?.duration_days ?? 30, 'number'); days.min = 1; days.max = 3650;
  field(grid, 'traffic', '流量 / bytes（留空不限）', plan?.traffic_bytes ?? '', 'number', false).min = 1;
  select(grid, 'enabled', '状态', [['yes', '启用'], ['no', '停用']], plan?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', '价格转换为人民币分保存；已有订单使用创建时快照。', 'fine'));
  submit(form, plan ? '保存套餐' : '创建套餐', async data => {
    const body = { name: String(data.get('name')).trim(), description: String(data.get('description')), price_cents: Math.round(Number(data.get('price')) * 100), duration_days: number(data, 'days'), traffic_bytes: number(data, 'traffic'), enabled: data.get('enabled') === 'yes' };
    if (!Number.isSafeInteger(body.price_cents) || body.price_cents < 0) throw new Error('价格无效');
    if (plan) await api(`/commerce/plans/${plan.id}`, { method: 'PUT', body });
    else await api('/commerce/plans', { method: 'POST', body });
    $('#dialog').close(); notify('套餐已保存。'); await renderCommerce();
  });
  modal(plan ? `编辑套餐 · ${plan.name}` : '新建套餐', form);
}
async function deletePlan(plan) {
  if (!confirm(`删除套餐「${plan.name}」？已有订单时会被拒绝。`)) return;
  await api(`/commerce/plans/${plan.id}`, { method: 'DELETE' }); notify('套餐已删除。'); await renderCommerce();
}
function adjustWallet() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'user_id', '用户 ID', '', 'text').maxLength = 120;
  const delta = field(grid, 'delta', '调整金额（元，正数入账/负数扣款）', '', 'number'); delta.step = '0.01';
  field(grid, 'reference', '幂等引用（唯一，如 bank-2026-001）', '', 'text').maxLength = 120;
  field(grid, 'description', '说明', '', 'text', false).maxLength = 500;
  form.append(grid, el('p', '同一引用只能入账一次；余额不得为负。此操作只调整钱包，不创建订单或发放权益。', 'fine'));
  submit(form, '调整钱包', async data => {
    const body = { delta_cents: Math.round(Number(data.get('delta')) * 100), reference: String(data.get('reference')).trim(), description: String(data.get('description')) };
    if (!Number.isSafeInteger(body.delta_cents) || body.delta_cents === 0) throw new Error('调整金额无效');
    await api(`/commerce/wallets/${String(data.get('user_id')).trim()}/adjust`, { method: 'POST', body });
    $('#dialog').close(); notify('钱包已调整。'); await renderCommerce();
  });
  modal('调整用户钱包', form);
}

async function renderAnnouncements() {
  const active = await api('/announcements');
  const canManage = state.actor.role !== 'viewer';
  const managed = canManage ? await api('/announcements/manage') : [];
  const p = panel('当前公告', '只显示已启用且处于发布窗口内的公告；全局公告对所有租户可见。', canManage ? button('＋ 新建公告', () => announcementForm(null), 'primary') : null);
  if (!active.length) p.append(empty('没有生效中的公告', '管理员可以创建全局或租户范围内的维护、变更和安全公告。'));
  else p.append(table(['级别', '标题', '内容', '生效时间'], active.map(item => [badge(announcementSeverities[item.severity], item.severity === 'critical' ? 'red' : item.severity === 'warning' ? 'orange' : 'green'), item.title, item.body, `${announcementTime(item.starts_at_ms)}${item.ends_at_ms ? ' → ' + announcementTime(item.ends_at_ms) : ''}`])));
  const page = el('div'); page.append(p);
  if (canManage) {
    const m = panel('公告管理', '租户管理员只能编辑/删除本租户公告；全局公告只读。', null);
    if (!managed.length) m.append(empty('还没有公告', '新建一条公告后，用户会在发布窗口内看到。'));
    else m.append(table(['范围', '级别', '标题', '开始', '结束', '状态', '操作'], managed.map(item => {
      const actions = el('div');
      const editable = state.actor.role === 'system_admin' || item.tenant_id === state.actor.tenant_id;
      if (editable) actions.append(button('编辑', () => announcementForm(item), 'table-action'), button('删除', () => deleteAnnouncement(item), 'table-action danger'));
      else actions.append(el('span', '只读', 'muted'));
      return [item.tenant_id || '全局', announcementSeverities[item.severity], item.title, announcementTime(item.starts_at_ms), item.ends_at_ms ? announcementTime(item.ends_at_ms) : '长期', item.enabled ? badge('启用', 'green') : badge('停用', '') , actions];
    })));
    page.append(m);
  }
  $('#content').replaceChildren(page);
}
function announcementForm(item) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'title', '标题', item?.title || '').maxLength = 200;
  textarea(grid, 'body', '内容（最多 10000 字节）', item?.body || '').maxLength = 10000;
  select(grid, 'severity', '级别', Object.entries(announcementSeverities), item?.severity || 'info');
  const tenant = field(grid, 'tenant_id', '租户 ID（留空为全局；租户管理员必须填写自己的租户）', item?.tenant_id || '', 'text', false); tenant.maxLength = 120;
  const starts = field(grid, 'starts', '开始时间（本地）', announcementDateTime(item?.starts_at_ms), 'datetime-local'); starts.required = true;
  const ends = field(grid, 'ends', '结束时间（本地，留空长期）', item?.ends_at_ms ? announcementDateTime(item.ends_at_ms) : '', 'datetime-local', false);
  select(grid, 'enabled', '状态', [['yes', '启用'], ['no', '停用']], item?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', '全局公告只有系统管理员可以创建；租户管理员只能发布到自己的租户。时间按浏览器本地时区输入，服务端保存 Unix 毫秒。', 'fine'));
  submit(form, item ? '保存公告' : '发布公告', async data => {
    const body = {
      title: String(data.get('title')).trim(),
      body: String(data.get('body')),
      severity: data.get('severity'),
      tenant_id: String(data.get('tenant_id') || '').trim() || null,
      starts_at_ms: new Date(String(data.get('starts'))).getTime(),
      ends_at_ms: String(data.get('ends') || '') ? new Date(String(data.get('ends'))).getTime() : null,
      enabled: data.get('enabled') === 'yes'
    };
    if (!Number.isFinite(body.starts_at_ms) || (body.ends_at_ms !== null && !Number.isFinite(body.ends_at_ms))) throw new Error('时间格式无效');
    if (item) await api(`/announcements/${item.id}`, { method: 'PUT', body });
    else await api('/announcements', { method: 'POST', body });
    $('#dialog').close(); notify('公告已保存。'); await renderAnnouncements();
  });
  modal(item ? `编辑公告 · ${item.title}` : '新建公告', form);
}
async function deleteAnnouncement(item) {
  if (!confirm(`删除公告「${item.title}」？`)) return;
  await api(`/announcements/${item.id}`, { method: 'DELETE' }); notify('公告已删除。'); await renderAnnouncements();
}

async function renderDns() {
  if (state.actor.role !== 'system_admin') { $('#content').replaceChildren(empty('仅系统管理员可见', 'DNS 服务商令牌可修改外部 DNS，因此只向系统管理员开放。')); return; }
  const [providers, zones, nodes] = await Promise.all([api('/dns/providers'), api('/dns/zones'), api('/nodes')]);
  const providerNames = Object.fromEntries(providers.map(p => [p.id, p.name]));
  const p = panel('DNS 服务商', '保存 Cloudflare 兼容 API 的地址和令牌。令牌可逆保存以调用服务商，接口只显示是否已设置；仅系统管理员可读写。', button('＋ 新增服务商', () => dnsProviderForm(null), 'primary'));
  if (!providers.length) p.append(empty('还没有 DNS 服务商', '先添加服务商，再创建区域和托管记录。'));
  else p.append(table(['名称', '类型', 'API 地址', '令牌', '操作'], providers.map(provider => {
    const actions = el('div'); actions.append(button('编辑', () => dnsProviderForm(provider), 'table-action'), button('删除', () => deleteDnsProvider(provider), 'table-action danger'));
    return [namedCell(provider.name, provider.id), provider.kind, provider.endpoint, provider.token_set ? badge('已设置', 'green') : badge('未设置', 'red'), actions];
  })));
  const z = panel('DNS 区域', '区域名是服务商的 zone 名称或 ID。观察模式只读取服务商并报告差异；应用模式只管理由本平台创建、带 relay 标记的记录。', providers.length ? button('＋ 新增区域', () => dnsZoneForm(null, providers), 'primary') : null);
  if (!zones.length) z.append(empty('还没有 DNS 区域', '添加区域后可以创建 A/AAAA/CNAME 托管记录并执行一次同步。'));
  else z.append(table(['区域', '服务商', '模式', '最少保留', '操作'], zones.map(zone => {
    const actions = el('div');
    actions.append(button('记录', async () => { state.dnsZone = zone.id; await renderDns(); }, 'table-action'));
    actions.append(button('立即同步', () => reconcileDns(zone), 'table-action'));
    actions.append(button('编辑', () => dnsZoneForm(zone, providers), 'table-action'), button('删除', () => deleteDnsZone(zone), 'table-action danger'));
    return [namedCell(zone.name, zone.id), providerNames[zone.provider_id] || zone.provider_id, dnsModes[zone.mode] || zone.mode, zone.min_keep, actions];
  })));
  const selected = zones.find(zone => zone.id === state.dnsZone) || zones[0];
  if (selected) {
    state.dnsZone = selected.id;
    const records = await api(`/dns/zones/${selected.id}/records`);
    const r = panel(`托管记录 · ${selected.name}`, '每条记录带 relay 标记。删除记录时应用模式会同时删除服务商记录；观察模式只删除本地记录。健康摘除只在节点心跳新鲜且至少一个目标健康时保留记录。', button('＋ 新增记录', () => dnsRecordForm(selected, null, nodes), 'primary'));
    if (!records.length) r.append(empty('还没有托管记录', '创建 A/AAAA/CNAME 记录，然后执行“立即同步”。'));
    else r.append(table(['名称', '类型', '内容', 'TTL', '状态', '健康摘除', '服务商记录', '操作'], records.map(record => {
      const actions = el('div');
      actions.append(button('编辑', () => dnsRecordForm(selected, record, nodes), 'table-action'));
      if (record.type === 'A' || record.type === 'AAAA') actions.append(button('DDNS', () => ddnsRecord(record), 'table-action'));
      actions.append(button(record.enabled ? '停用' : '启用', async () => { await api(`/dns/records/${record.id}`, { method: 'PUT', body: { enabled: !record.enabled } }); await renderDns(); }, 'table-action'));
      actions.append(button('删除', () => deleteDnsRecord(record), 'table-action danger'));
      const stateBadge = record.last_error ? badge('错误', 'red') : record.enabled ? badge('启用', 'green') : badge('停用', '');
      return [namedCell(record.name, record.id), record.type, record.content, record.ttl, stateBadge, record.health ? `${record.health.node_id} / ${record.health.rule_id}` : '—', record.provider_record_id || '—', actions];
    })));
    if (records.some(record => record.last_error)) r.append(el('p', records.filter(record => record.last_error).map(record => `${record.name}: ${record.last_error}`).join('；'), 'error-text'));
    $('#content').replaceChildren(p, z, r);
  } else {
    $('#content').replaceChildren(p, z);
  }
}
function dnsProviderForm(provider) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', '名称', provider?.name || '').maxLength = 120;
  select(grid, 'kind', '服务商类型', [['cloudflare', 'Cloudflare 兼容 API']], provider?.kind || 'cloudflare');
  field(grid, 'endpoint', 'API 基础地址', provider?.endpoint || 'https://api.cloudflare.com/client/v4').maxLength = 500;
  const token = field(grid, 'token', provider ? '令牌（留空保留原值）' : 'API 令牌', '', 'password', false); token.maxLength = 4096;
  form.append(grid, el('p', '令牌只应授予 DNS 编辑权限；接口不会返回令牌原文。HTTP 只允许回环地址用于本机测试。', 'fine'));
  submit(form, provider ? '保存服务商' : '添加服务商', async data => {
    const body = { name: String(data.get('name')).trim(), kind: data.get('kind'), endpoint: String(data.get('endpoint')).trim() };
    if (String(data.get('token') || '')) body.token = String(data.get('token'));
    if (provider) await api(`/dns/providers/${provider.id}`, { method: 'PUT', body });
    else await api('/dns/providers', { method: 'POST', body });
    $('#dialog').close(); notify('DNS 服务商已保存。'); await renderDns();
  });
  modal(provider ? `编辑 DNS 服务商 · ${provider.name}` : '新增 DNS 服务商', form);
}
function dnsZoneForm(zone, providers) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', '区域名称 / ID', zone?.name || '').maxLength = 253;
  select(grid, 'provider_id', '服务商', providers.map(provider => [provider.id, provider.name]), zone?.provider_id || providers[0]?.id || '');
  select(grid, 'mode', '模式', Object.entries(dnsModes), zone?.mode || 'observe');
  const keep = field(grid, 'min_keep', '最少保留记录数', zone?.min_keep ?? 1, 'number'); keep.min = 0; keep.max = 1000;
  form.append(grid, el('p', '观察模式适合先核对现有记录。应用模式只创建/更新/删除本平台带 relay 标记的记录，不会接管同名的外部记录。', 'fine'));
  submit(form, zone ? '保存区域' : '添加区域', async data => {
    const body = { name: String(data.get('name')).trim(), provider_id: data.get('provider_id'), mode: data.get('mode'), min_keep: number(data, 'min_keep') };
    if (zone) await api(`/dns/zones/${zone.id}`, { method: 'PUT', body });
    else { const created = await api('/dns/zones', { method: 'POST', body }); state.dnsZone = created.id; }
    $('#dialog').close(); notify('DNS 区域已保存。'); await renderDns();
  });
  modal(zone ? `编辑 DNS 区域 · ${zone.name}` : '新增 DNS 区域', form);
}
function dnsRecordForm(zone, record, nodes) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', '记录名称', record?.name || '').maxLength = 253;
  select(grid, 'type', '类型', dnsRecordTypes.map(type => [type, type]), record?.type || 'A');
  field(grid, 'content', '内容（IP 或 CNAME）', record?.content || '').maxLength = 253;
  const ttl = field(grid, 'ttl', 'TTL（秒）', record?.ttl ?? 300, 'number'); ttl.min = 1; ttl.max = 86400;
  select(grid, 'proxied', 'Cloudflare 代理', [['no', '不代理'], ['yes', '代理']], record?.proxied ? 'yes' : 'no');
  select(grid, 'health_node', '入口健康摘除节点', [['', '不启用'], ...nodes.map(node => [node.id, node.name])], record?.health?.node_id || '');
  field(grid, 'health_rule', '健康摘除规则 ID（可选）', record?.health?.rule_id || '').maxLength = 128;
  if (record?.health) select(grid, 'health_clear', '健康摘除设置', [['no', '保留现有设置'], ['yes', '清除健康摘除']], 'no');
  form.append(grid, el('p', '应用模式同步后会写入服务商；观察模式只显示“将创建/将更新”。CNAME 内容必须是主机名，A/AAAA 内容必须是 IP。填写节点和规则 ID 后，节点心跳超过 90 秒或没有健康目标时，应用模式会摘除该记录；恢复后自动重建。', 'fine'));
  submit(form, record ? '保存记录' : '添加记录', async data => {
    const body = { name: String(data.get('name')).trim(), type: data.get('type'), content: String(data.get('content')).trim(), ttl: number(data, 'ttl'), proxied: data.get('proxied') === 'yes' };
    const healthNode = String(data.get('health_node') || ''), healthRule = String(data.get('health_rule') || '').trim();
    if (data.get('health_clear') === 'yes') body.clear_health = true;
    else if (healthNode && healthRule) body.health = { node_id: healthNode, rule_id: healthRule };
    if (record) await api(`/dns/records/${record.id}`, { method: 'PUT', body });
    else await api(`/dns/zones/${zone.id}/records`, { method: 'POST', body });
    $('#dialog').close(); notify('DNS 记录已保存；执行“立即同步”后写入服务商。'); await renderDns();
  });
  modal(record ? `编辑 DNS 记录 · ${record.name}` : '新增 DNS 记录', form);
}
async function reconcileDns(zone) {
  const result = await api(`/dns/zones/${zone.id}/reconcile`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', `${dnsModes[zone.mode]}：观察 ${result.observed} 条，创建 ${result.created}，更新 ${result.updated}，删除 ${result.deleted}，未变 ${result.unchanged}，保留 ${result.kept}，错误 ${result.errors}。`));
  if (result.actions.length) body.append(table(['记录', '动作', '详情'], result.actions.map(action => [action.record_id, action.action, action.detail])));
  modal(`同步结果 · ${zone.name}`, body); await renderDns();
}
async function deleteDnsProvider(provider) {
  if (!confirm(`删除 DNS 服务商「${provider.name}」？存在区域时会被拒绝。`)) return;
  await api(`/dns/providers/${provider.id}`, { method: 'DELETE' }); notify('DNS 服务商已删除。'); await renderDns();
}
async function deleteDnsZone(zone) {
  if (!confirm(`删除 DNS 区域「${zone.name}」？存在托管记录时会被拒绝。`)) return;
  await api(`/dns/zones/${zone.id}`, { method: 'DELETE' }); if (state.dnsZone === zone.id) state.dnsZone = null; notify('DNS 区域已删除。'); await renderDns();
}
async function deleteDnsRecord(record) {
  if (!confirm(`删除 DNS 记录「${record.name}」？应用模式会同时删除服务商记录。`)) return;
  await api(`/dns/records/${record.id}`, { method: 'DELETE' }); notify('DNS 记录已删除。'); await renderDns();
}
async function ddnsRecord(record) {
  const content = prompt(`为「${record.name}」输入新的 ${record.type} 地址（DDNS）；当前 ${record.content}`, record.content);
  if (!content || content.trim() === record.content) return;
  await api(`/dns/records/${record.id}/ddns`, { method: 'POST', body: { content: content.trim() } }); notify('DDNS 已更新并同步；观察模式只报告差异。'); await renderDns();
}

async function renderSubscriptions() {
  const subscriptions = await api('/subscriptions');
  const p = panel('客户端订阅', '把 Shadowsocks 规则快照成可撤销的订阅链接。链接只包含客户端连接参数，不包含控制器会话或节点凭据；轮换后旧链接立即失效。', canWrite() ? button('＋ 新建订阅', newSubscription, 'primary') : null);
  if (!subscriptions.length) p.append(empty('还没有订阅链接', '先创建至少一条启用中的 Shadowsocks 规则，再按客户端格式生成订阅。'));
  else p.append(table(['名称', '格式', '所有者', '到期', '最近使用', '操作'], subscriptions.map(item => {
    const actions = el('div');
    actions.append(button('预览', () => previewSubscription(item), 'table-action'));
    if (canWrite()) {
      actions.append(button('轮换链接', () => rotateSubscription(item), 'table-action'));
      actions.append(button('删除', () => deleteSubscription(item), 'table-action danger'));
    }
    return [namedCell(item.name, item.id), subscriptionFormats[item.format] || item.format, item.owner_id, item.expires_at_ms ? timestamp(item.expires_at_ms) : '不过期', item.last_used_ms ? `${timestamp(item.last_used_ms)} · ${item.uses} 次` : '尚未使用', actions];
  })));
  if (state.view === 'subscriptions') $('#content').replaceChildren(p);
}
async function newSubscription() {
  const users = state.actor.role === 'viewer' ? [] : await api('/users').catch(() => []);
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', '名称（说明用途，如“手机订阅”）').maxLength = 120;
  select(grid, 'format', '客户端格式', Object.entries(subscriptionFormats), 'v2ray');
  field(grid, 'prefix', '客户端显示名称前缀（可选）', 'Relay ').maxLength = 64;
  const host = field(grid, 'host', '替换所有节点地址（可选，NAT / 域名场景）', '', 'text', false); host.maxLength = 253;
  const tags = field(grid, 'tags', '只包含这些节点标签（逗号分隔，留空全部）', '', 'text', false);
  select(grid, 'udp', '在客户端启用 UDP', [['yes', '启用'], ['no', '不启用']], 'yes');
  const days = field(grid, 'days', '有效天数（1–3650）', 365, 'number'); days.min = 1; days.max = 3650;
  if (state.actor.role !== 'viewer' && users.length > 1) {
    const owner = select(grid, 'user_id', '订阅所有者', [['', '当前账号'], ...users.map(u => [u.id, `${u.username} · ${roleNames[u.role]}`])], '');
    owner.required = false;
  }
  form.append(grid, el('p', '名称前缀和节点标签会作为快照保存在订阅记录中；节点后续改名不会改变已生成链接的显示名。只读账号不能创建或轮换链接。', 'fine'));
  submit(form, '创建订阅', async data => {
    const result = await api('/subscriptions', { method: 'POST', body: {
      name: String(data.get('name')).trim(),
      format: data.get('format'),
      expires_in_days: number(data, 'days'),
      ...(String(data.get('user_id') || '') ? { user_id: String(data.get('user_id')) } : {}),
      template: {
        name_prefix: String(data.get('prefix') || ''),
        host: String(data.get('host') || '').trim() || null,
        node_tags: String(data.get('tags') || '').split(',').map(t => t.trim()).filter(Boolean),
        udp: data.get('udp') === 'yes'
      }
    }});
    $('#dialog').close();
    showSubscriptionToken(result.subscription.name, result.token);
    await renderSubscriptions();
  });
  modal('新建客户端订阅', form);
}
function showSubscriptionToken(name, token) {
  const body = el('div');
  const url = `${location.origin}/sub/${token}`;
  body.append(el('p', '订阅链接只显示这一次。任何持有链接的人都能读取节点连接参数；请像密码一样保存，泄露时立即轮换。', 'fine'), el('div', url, 'secret-box'));
  const actions = el('div', undefined, 'dialog-actions');
  actions.append(button('关闭', () => $('#dialog').close()), button('复制链接', async () => { await navigator.clipboard.writeText(url); notify('订阅链接已复制。'); }, 'primary'));
  body.append(actions);
  modal(`订阅已创建 · ${name}`, body);
}
async function previewSubscription(item) {
  const preview = await api(`/subscriptions/${item.id}/preview`);
  const body = el('div');
  if (preview.entries.length) body.append(table(['客户端名称', '服务器', '端口', '加密方式'], preview.entries.map(entry => [entry.name, entry.host, entry.port, entry.method])));
  else body.append(el('p', '没有可生成的条目，原因见下方跳过列表。', 'muted'));
  if (preview.skipped.length) body.append(el('h3', '跳过规则'), table(['规则', '原因'], preview.skipped.map(s => [namedCell(s.rule_name, s.rule_id), s.reason])));
  const details = el('details'); details.append(el('summary', '查看生成内容'), el('pre', preview.content, 'subscription-preview')); body.append(details);
  modal(`预览 · ${item.name}`, body);
}
async function rotateSubscription(item) {
  if (!confirm(`轮换「${item.name}」的订阅链接？旧链接会立即失效，已导入的客户端需要重新导入。`)) return;
  const result = await api(`/subscriptions/${item.id}/rotate`, { method: 'POST' });
  showSubscriptionToken(item.name, result.token);
  await renderSubscriptions();
}
async function deleteSubscription(item) {
  if (!confirm(`删除订阅「${item.name}」？使用该链接的客户端将立即无法更新。`)) return;
  await api(`/subscriptions/${item.id}`, { method: 'DELETE' });
  notify('订阅已删除。');
  await renderSubscriptions();
}

async function renderUsage() { const records = await api('/usage'); const p = panel('已接纳应用负载', '累计值按节点、规则与计量周期去重；发送失败也可能已经接纳计量。最多显示最近 2,000 条周期记录。'); if (!records.length) p.append(empty('还没有流量记录', '让一条转发规则通过真实流量，Agent 会在同步后上报。')); else p.append(table(['规则 / 周期', '节点', '上行', '下行', '序号', '最近上报'], records.map(r => [namedCell(r.rule_id, r.meter_epoch), r.node_id, bytes(r.upload_bytes), bytes(r.download_bytes), r.sequence, timestamp(r.reported_at_ms)]))); if (state.view === 'usage') $('#content').replaceChildren(p); }
async function renderUsers() { const users = await api('/users'); const p = panel('用户与会话', '权限由服务端校验；撤销、停用、改密或删除后，该用户已有的 Web 会话和 API 令牌立即失效。', canWrite() ? button('＋ 添加用户', newUser, 'primary') : null); p.append(table(['账号', '角色', '租户', '状态', '两步验证', '跨节点总限速', '操作'], users.map(u => [namedCell(u.username, u.id), roleNames[u.role], u.tenant_id, u.disabled ? badge('已停用', 'red') : badge('启用', 'green'), u.mfa_enabled ? badge('已启用', 'green') : badge('未启用'), u.rate_bytes_per_sec ? badge(mbit(u.rate_bytes_per_sec), 'orange') : badge('不限速'), userActions(u)]))); if (state.view === 'users') $('#content').replaceChildren(p); }
function userActions(u) {
  if (!canWrite() && u.id !== state.actor.id) return '—';
  const actions = el('div');
  actions.append(button('撤销全部会话', async () => { await api(`/users/${u.id}/revoke-sessions`, { method: 'POST' }); if (u.id === state.actor.id) loggedOut(); else notify('该用户现有会话和 API 令牌已撤销。'); }, 'table-action'));
  if (state.actor.role === 'system_admin' || u.rate_bytes_per_sec) actions.append(button('总限速', () => editUserRate(u), 'table-action'));
  if (canWrite() && u.id !== state.actor.id) {
    actions.append(button('改密', () => adminPassword(u), 'table-action'));
    actions.append(button(u.disabled ? '启用' : '停用', () => toggleUserDisabled(u), 'table-action'));
    actions.append(button('删除', () => deleteUser(u), 'table-action danger'));
  }
  if (canWrite() && u.mfa_enabled && u.id !== state.actor.id) actions.append(button('重置两步验证', async () => { if (!confirm(`重置 ${u.username} 的两步验证？其会话和 API 令牌会同时失效；之后可只用密码登录并重新启用。`)) return; await api(`/users/${u.id}/mfa/reset`, { method: 'POST' }); notify(`${u.username} 的两步验证已重置。`); await renderUsers(); }, 'table-action danger'));
  return actions;
}
function adminPassword(u) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'password', `为 ${u.username} 设置新密码`, '', 'password').maxLength = 1024;
  form.append(grid, el('p', '保存后该用户的全部 Web 会话和 API 令牌立即失效，需要使用新密码重新登录。密码至少 12 字节。', 'fine'));
  submit(form, '重置密码', async data => {
    await api(`/users/${u.id}/password`, { method: 'POST', body: { password: String(data.get('password')) } });
    $('#dialog').close(); notify(`${u.username} 的密码已重置。`); await renderUsers();
  });
  modal(`重置密码 · ${u.username}`, form);
}
async function toggleUserDisabled(u) {
  if (!confirm(`${u.disabled ? '启用' : '停用'} ${u.username}？${u.disabled ? '旧密码仍有效，可重新登录。' : '现有会话和 API 令牌会立即失效，之后可重新启用。'}`)) return;
  await api(`/users/${u.id}/disabled`, { method: 'PUT', body: { disabled: !u.disabled } });
  notify(`${u.username} 已${u.disabled ? '启用' : '停用'}。`); await renderUsers();
}
async function deleteUser(u) {
  if (!confirm(`永久删除 ${u.username}？其会话、API 令牌、两步验证和限速设置会删除；拥有规则或订阅时服务端会拒绝。`)) return;
  await api(`/users/${u.id}`, { method: 'DELETE' });
  notify(`${u.username} 已删除。`); await renderUsers();
}
async function changeOwnPassword() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'current', '当前密码', '', 'password').maxLength = 1024;
  field(grid, 'next', '新密码（至少 12 字节）', '', 'password').maxLength = 1024;
  field(grid, 'confirm', '再次输入新密码', '', 'password').maxLength = 1024;
  form.append(grid, el('p', '修改成功后当前会话保留，其他 Web 会话失效；API 令牌不受影响。忘记当前密码时需其他管理员重置。', 'fine'));
  submit(form, '修改密码', async data => {
    const next = String(data.get('next'));
    if (next !== String(data.get('confirm'))) throw new Error('两次输入的新密码不一致');
    await api('/account/password', { method: 'POST', body: { current_password: String(data.get('current')), new_password: next } });
    $('#dialog').close(); notify('密码已修改。'); await renderAccount();
  });
  modal('修改登录密码', form);
}
async function editUserRate(u) {
  const [view, nodes] = await Promise.all([api(`/users/${u.id}/rate`), api('/nodes').catch(() => [])]);
  const names = Object.fromEntries(nodes.map(n => [n.id, n.name]));
  const form = el('form');
  if (state.actor.role === 'system_admin') {
    const grid = el('div', undefined, 'form-grid'); const input = field(grid, 'mbit', '该用户所有节点入口规则的上下行合计 / Mbit/s（留空不限速）', view.rate_bytes_per_sec ? +(view.rate_bytes_per_sec * 8 / 1e6).toFixed(3) : '', 'number', false); input.min = 0.009; input.step = 'any';
    form.append(grid, el('p', '控制器按各节点的实际用量动态分配份额，忙的节点多分；节点与控制器失联 15 秒后退回平均份额。与规则、节点限速同时生效，取较严者。只计入口规则；已停用或到期的节点不占份额，长期离线的节点请停用。', 'muted'));
  }
  if (view.nodes.length) form.append(table(['节点', '当前份额', '实测', '状态'], view.nodes.map(n => [namedCell(names[n.node_id] || n.node_id, n.node_id), mbit(n.share_bytes_per_sec), n.measured_bytes_per_sec == null ? '—' : mbit(n.measured_bytes_per_sec), n.seen_ms_ago == null ? badge('未连接，预留平均份额', 'red') : n.seen_ms_ago > 20000 ? badge('失联，按平均份额', 'red') : n.saturated ? badge('已用满', 'orange') : badge('有余量', 'green')])));
  else if (view.rate_bytes_per_sec) form.append(el('p', '各节点下次同步后显示份额。', 'muted'));
  if (state.actor.role === 'system_admin') submit(form, '保存总限速', async data => { const raw = String(data.get('mbit')).trim(); const rate = raw === '' ? null : Math.round(Number(raw) * 1e6 / 8); if (rate !== null && !(rate >= 1024 && rate <= 2 ** 40)) throw new Error('请输入 0.009 到 8,796,093 之间的 Mbit/s'); await api(`/users/${u.id}/rate`, { method: 'PUT', body: { rate_bytes_per_sec: rate } }); $('#dialog').close(); notify(rate ? `${u.username} 的跨节点总限速为 ${mbit(rate)}。` : `已取消 ${u.username} 的跨节点总限速。`); await renderUsers(); });
  modal(`${u.username} 的跨节点总限速`, form);
}
async function renderAccount() {
  const [factor, tokens] = await Promise.all([api('/account/mfa'), api('/api-tokens')]);
  const security = panel('两步验证', '登录时除密码外，还需输入手机身份验证器（如 Google Authenticator、Microsoft Authenticator、1Password）生成的 6 位验证码。', factor.enabled ? button('停用两步验证', disableSecondFactor, 'subtle danger') : button('启用两步验证', setupSecondFactor, 'primary'));
  const status = el('div', undefined, 'panel-body');
  for (const [label, value] of [['状态', factor.enabled ? badge('已启用', 'green') : badge(factor.pending ? '设置未完成' : '未启用', factor.pending ? 'orange' : '')], ...(factor.enabled ? [['剩余恢复码', badge(`${factor.recovery_codes_remaining} 个`, factor.recovery_codes_remaining <= 2 ? 'orange' : '')]] : [])]) { const row = el('div', undefined, 'capability'); row.append(el('span', label), value); status.append(row); }
  status.append(el('p', factor.enabled ? '手机丢失时可用恢复码登录；恢复码用完或丢失时，请其他管理员在“用户与权限”中重置。' : '启用后，此账号的每次登录都需要验证码。API 令牌不受影响，但只能在登录后创建。', 'fine'));
  security.append(status);
  const password = panel('登录密码', '修改后当前会话保留，其他 Web 会话失效；API 令牌不受影响。', button('修改密码', changeOwnPassword, 'primary'));
  password.append(el('p', '密码至少 12 字节。忘记密码时请其他管理员在“用户与权限”中重置。', 'fine'));
  const keys = panel('API 令牌', '供脚本和自动化调用 API。令牌权限是所选范围与你的角色权限的交集；令牌不能创建令牌或修改两步验证。', button('＋ 创建令牌', createApiToken, 'primary'));
  if (!tokens.length) keys.append(empty('尚无 API 令牌', '令牌创建后只显示一次，到期后自动失效。'));
  else keys.append(table(['名称', '权限范围', '创建时间', '到期时间', '操作'], tokens.map(t => [namedCell(t.name, t.id), t.scopes.map(scope => scopeNames[scope] || scope).join('、'), timestamp(t.created_at_ms), t.expires_at_ms <= Date.now() ? badge('已过期', 'red') : timestamp(t.expires_at_ms), button('撤销', async () => { if (!confirm(`撤销令牌“${t.name}”？使用它的脚本将立即失效。`)) return; await api(`/api-tokens/${t.id}`, { method: 'DELETE' }); notify('令牌已撤销。'); await renderAccount(); }, 'table-action danger')])));
  const page = el('div'); page.append(password, security, keys);
  if (state.view === 'account') $('#content').replaceChildren(page);
}
function setupSecondFactor() {
  const form = el('form'); form.append(el('p', '为防止他人用未关闭的浏览器绑定自己的手机，请先确认当前密码。', 'fine'));
  field(form, 'password', '当前密码', '', 'password').autocomplete = 'current-password';
  submit(form, '下一步', async data => { const setup = await api('/account/mfa/setup', { method: 'POST', body: { password: data.get('password') } }); $('#dialog').close(); confirmSecondFactor(setup); });
  modal('启用两步验证', form);
}
function confirmSecondFactor(setup) {
  const form = el('form'), qr = el('img', undefined, 'qr-code'); qr.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}`; qr.alt = '两步验证二维码';
  form.append(el('p', '1. 用身份验证器扫描二维码。无法扫描时，选择手动输入并填写下面的密钥（基于时间）。'), qr, el('div', setup.secret.match(/.{1,4}/g).join(' '), 'secret-box'), el('p', '2. 输入应用当前显示的 6 位验证码完成启用。'));
  const code = field(form, 'code', '验证码'); code.inputMode = 'numeric'; code.autocomplete = 'one-time-code'; code.maxLength = 6; code.pattern = '[0-9]{6}';
  submit(form, '确认启用', async data => { const result = await api('/account/mfa/enable', { method: 'POST', body: { code: String(data.get('code')).trim() } }); $('#dialog').close(); showRecoveryCodes(result.recovery_codes); });
  modal('启用两步验证', form); code.focus();
}
function showRecoveryCodes(codes) {
  const body = el('div'); body.append(el('p', '两步验证已启用。手机丢失时，每个恢复码可代替验证码登录一次。请离线保存，关闭后无法再次查看。'), el('div', codes.join('\n'), 'secret-box recovery-codes'), button('我已保存恢复码', () => $('#dialog').close(), 'primary'));
  modal('保存恢复码', body); renderAccount().catch(e => notify(e.message, true));
}
function disableSecondFactor() {
  const form = el('form'); form.append(el('p', '停用后登录只需要密码。请确认密码，并输入当前验证码或一个恢复码。', 'fine'));
  field(form, 'password', '当前密码', '', 'password').autocomplete = 'current-password';
  const code = field(form, 'code', '验证码或恢复码'); code.autocomplete = 'one-time-code'; code.maxLength = 32;
  submit(form, '停用两步验证', async data => { await api('/account/mfa/disable', { method: 'POST', body: { password: data.get('password'), code: String(data.get('code')).trim() } }); $('#dialog').close(); notify('两步验证已停用。'); await renderAccount(); });
  modal('停用两步验证', form);
}
function createApiToken() {
  const form = el('form'); field(form, 'name', '名称（说明用途，如“监控脚本”）').maxLength = 80;
  const scopes = el('fieldset'); scopes.append(el('legend', '权限范围'));
  for (const [value, label] of Object.entries(scopeNames)) { const item = el('label', label, 'inline-check'), input = el('input'); input.type = 'checkbox'; input.name = 'scope'; input.value = value; input.checked = value === 'read'; item.prepend(input); scopes.append(item); }
  scopes.append(el('p', '写入范围通常还需要“读取”，以便先取得当前版本号。只读用户的令牌仍不能写入。', 'fine')); form.append(scopes);
  const days = field(form, 'days', '有效天数（1–365）', 90, 'number'); days.min = 1; days.max = 365;
  submit(form, '创建令牌', async data => { if (!data.getAll('scope').length) throw new Error('至少选择一个权限范围'); const result = await api('/api-tokens', { method: 'POST', body: { name: String(data.get('name')).trim(), scopes: data.getAll('scope'), expires_in_days: number(data, 'days') } }); const body = el('div'); body.append(el('p', '令牌只显示这一次。请保存到密码管理器或脚本的密钥配置中，不要写入代码仓库或聊天记录。'), el('div', result.token, 'secret-box'), el('p', '调用示例（先把令牌放入环境变量 RELAY_TOKEN）', 'fine'), el('pre', `curl -H "Authorization: Bearer $RELAY_TOKEN" ${location.origin}/api/v1/nodes`), button('我已保存令牌', () => $('#dialog').close(), 'primary')); $('#dialog').close(); modal('API 令牌已创建', body); await renderAccount(); });
  modal('创建 API 令牌', form);
}
function newUser() { const form = el('form'); field(form, 'username', '用户名').maxLength = 80; const p = field(form, 'password', '初始密码（至少 12 个字节）', '', 'password'); p.minLength = 12; p.autocomplete = 'new-password'; const roles = [['viewer', '只读用户'], ['tenant_admin', '租户管理员']]; if (state.actor.role === 'system_admin') roles.push(['system_admin', '系统管理员']); select(form, 'role', '角色', roles, 'viewer'); submit(form, '创建用户', async data => { await api('/users', { method: 'POST', body: Object.fromEntries(data) }); $('#dialog').close(); await renderUsers(); }); modal('添加用户', form); }
async function renderAudit() { const rows = await api('/audit'); const p = panel('操作审计', '记录配置发布、节点注册、身份及会话操作。最近 200 条。'); p.append(table(['时间', '操作者', '操作', '对象', '详情'], rows.map(r => [timestamp(r.at_ms), r.actor_id, r.action, r.resource, r.detail]))); if (state.view === 'audit') $('#content').replaceChildren(p); }
const alertKinds = { webhook: 'Webhook', telegram: 'Telegram', wecom: '企业微信', feishu: '飞书', dingtalk: '钉钉' };
const alertFields = { webhook: [['url', 'Webhook 地址'], ['secret', '签名密钥（可选，HMAC-SHA256）', true]], telegram: [['bot_token', 'Bot Token'], ['chat_id', 'Chat ID']], wecom: [['url', '群机器人 Webhook 地址']], feishu: [['url', '自定义机器人 Webhook 地址'], ['secret', '签名校验密钥（可选）', true]], dingtalk: [['url', '自定义机器人 Webhook 地址'], ['secret', '加签密钥（可选）', true]] };
const severityNames = { warning: '警告及以上', critical: '仅严重' };
async function renderAlerts() {
  const data = await api('/alerts'), now = Date.now(), { settings, channels, incidents } = data;
  const until = settings.maintenance_until_ms, maintaining = until && until > now;
  const grid = el('div', undefined, 'alert-grid');
  const status = panel('通知状态', maintaining ? `维护模式至 ${timestamp(until)}。期间不发送新告警，结束时仍未恢复的问题会补发。` : '目标不可用、节点拒绝配置和节点离线会通知已启用的通道。同时出现的问题合并为一条消息；同一问题 5 分钟内反复出现只算一次。');
  const strip = el('div', undefined, 'alert-status');
  for (const [label, value, color] of [['当前告警', incidents.open.length, incidents.open.length ? 'red' : 'green'], ['启用通道', channels.filter(c => c.enabled).length, channels.some(c => c.enabled) ? 'green' : 'orange'], ['发送失败', incidents.deliveries.filter(d => d.status === 'failed').length, incidents.deliveries.some(d => d.status === 'failed') ? 'red' : '']]) { const item = el('div', undefined, `alert-stat ${color}`); item.append(el('div', String(value), 'metric-value'), el('div', label, 'metric-label')); strip.append(item); }
  const actions = el('div', undefined, 'alert-actions');
  const maintain = ms => api('/alerts/settings', { method: 'PUT', body: { maintenance_until_ms: ms } }).then(renderAlerts);
  actions.append(maintaining ? button('结束维护', () => maintain(null), 'primary') : badge('正常通知', 'green'), button('维护 1 小时', () => maintain(Date.now() + 3600_000)), button('维护 4 小时', () => maintain(Date.now() + 4 * 3600_000)));
  strip.append(actions); status.append(strip); grid.append(status);
  const list = panel('通知通道', '地址、令牌和密钥保存后不再显示。编辑时留空表示保留原值。最多 20 个。', button('＋ 添加通道', () => editAlertChannel(), 'primary'));
  if (!channels.length) list.append(empty('还没有通知通道', '添加一个 Webhook、Telegram、企业微信、飞书或钉钉机器人，然后发送测试消息确认可以收到。', button('＋ 添加通道', () => editAlertChannel(), 'primary')));
  else list.append(table(['名称', '类型', '发送到', '级别', '状态', '操作'], channels.map(c => { const ops = el('div', undefined, 'row-actions'); ops.append(button('测试', async () => { notify(`正在向 ${c.name} 发送测试消息…`); try { await api(`/alerts/channels/${c.id}/test`, { method: 'POST' }); notify(`测试消息已发送到 ${c.name}，请确认已收到。`); } finally { await renderAlerts(); } }, 'table-action'), button('编辑', () => editAlertChannel(c), 'table-action'), button('删除', async () => { if (!confirm(`删除通知通道“${c.name}”？`)) return; await api(`/alerts/channels/${c.id}`, { method: 'DELETE' }); await renderAlerts(); }, 'table-action danger')); return [namedCell(c.name, c.secret_set ? '已设置密钥' : '未设置密钥'), alertKinds[c.kind], el('span', c.destination, 'mono'), severityNames[c.min_severity], badge(c.enabled ? '已启用' : '已停用', c.enabled ? 'green' : ''), ops]; })));
  grid.append(list);
  const levels = { warning: ['警告', 'orange'], critical: ['严重', 'red'] };
  const incidentRows = (items, resolved) => items.map(i => [resolved ? `${timestamp(i.resolved_at_ms)} · ${ago(i.resolved_at_ms, now)}` : `${timestamp(i.opened_at_ms)} · ${ago(i.opened_at_ms, now)}`, i.node_name, badge(...(levels[i.severity] || [i.severity])), el('span', i.summary, 'wrap'), i.repeats ? `${i.repeats} 次` : '—', resolved ? (i.last_notice_ms ? '已通知恢复' : '未通知') : i.notified ? badge('已通知', 'green') : badge(maintaining ? '维护中暂缓' : '等待发送', 'orange')]);
  const open = panel('当前告警', '仍未恢复的问题。控制器重启后会在 1 分钟内重新检测。');
  open.append(incidents.open.length ? table(['开始', '节点', '级别', '内容', '反复', '通知'], incidentRows(incidents.open, false)) : empty('一切正常', '没有未恢复的告警。'));
  grid.append(open);
  if (incidents.resolved.length) { const done = panel('最近恢复', '最近 200 条，保存在控制器内存中。'); done.append(table(['恢复', '节点', '级别', '内容', '反复', '通知'], incidentRows(incidents.resolved.slice(0, 50), true))); grid.append(done); }
  const statusNames = { sent: ['已送达', 'green'], failed: ['失败', 'red'], retrying: ['重试中', 'orange'], pending: ['发送中', ''] }, noticeNames = { opened: '告警', resolved: '恢复', test: '测试' };
  const log = panel('发送记录', '失败会在 10 秒、1 分钟、5 分钟后重试。最近 200 条。');
  log.append(incidents.deliveries.length ? table(['时间', '通道', '类型', '结果', '尝试', '错误'], incidents.deliveries.slice(0, 100).map(d => [timestamp(d.created_at_ms), d.channel_name, d.incidents > 1 ? `${noticeNames[d.notice]} · 合并 ${d.incidents} 条` : noticeNames[d.notice], badge(...statusNames[d.status]), String(d.attempts), d.error ? Object.assign(el('span', d.error, 'clip mono'), { title: d.error }) : '—'])) : empty('还没有发送记录', '发送测试消息或出现告警后会显示在这里。'));
  grid.append(log);
  if (state.view === 'alerts') $('#content').replaceChildren(grid);
}
function editAlertChannel(existing) {
  const form = el('form'), kind = existing?.kind || 'webhook';
  field(form, 'name', '名称（如“值班群”）', existing?.name).maxLength = 80;
  const kindSelect = select(form, 'kind', '类型', Object.entries(alertKinds), kind);
  select(form, 'min_severity', '通知级别', [['warning', '警告及以上（目标不可用、配置拒绝、节点离线）'], ['critical', '仅严重（配置拒绝、节点离线）']], existing?.min_severity || 'warning');
  const enabled = el('label', '启用', 'inline-check'), check = el('input'); check.type = 'checkbox'; check.name = 'enabled'; check.checked = existing?.enabled ?? true; enabled.prepend(check); form.append(enabled);
  const box = el('div', undefined, 'alert-fields'); form.append(box);
  const fillFields = () => { box.replaceChildren(); const keep = existing && kindSelect.value === existing.kind; for (const [name, label, optional] of alertFields[kindSelect.value]) { const input = field(box, name, label, '', name === 'url' ? 'url' : 'text', !optional && !keep); input.autocomplete = 'off'; if (keep) input.placeholder = '留空则保留原值'; } if (kindSelect.value === 'webhook') box.append(el('p', '以 JSON POST {"text","sent_at_ms"}。设置密钥后请求头带 X-Relay-Signature: sha256=<正文的 HMAC 十六进制>。', 'fine')); };
  kindSelect.onchange = fillFields; fillFields();
  submit(form, existing ? '保存' : '添加通道', async data => {
    const target = { kind: data.get('kind') }; for (const [name] of alertFields[target.kind]) target[name] = String(data.get(name) || '').trim();
    const body = { name: String(data.get('name')).trim(), enabled: data.get('enabled') === 'on', min_severity: data.get('min_severity'), target };
    await api(existing ? `/alerts/channels/${existing.id}` : '/alerts/channels', { method: existing ? 'PUT' : 'POST', body }); $('#dialog').close(); notify(existing ? '通知通道已保存。' : '通知通道已添加。建议点击“测试”确认可以收到。'); await renderAlerts();
  });
  modal(existing ? `编辑通知通道 · ${existing.name}` : '添加通知通道', form);
}
async function renderCapabilities() { const c = await api('/capabilities'); const names = { tcp: 'TCP 转发', udp: 'UDP 转发', ipv4: 'IPv4', ipv6: 'IPv6', 'dns-targets': '域名目标', 'port-ranges': '端口段与偏移映射', 'outbound-binding': '业务出口 IP / 网卡绑定', 'dns-ttl-cache': '目标 DNS TTL 缓存', 'node-local-loop-protection': '节点内监听环路检查', 'proxy-protocol-tcp-v1-v2': 'TCP PROXY v1 / v2', 'proxy-protocol-udp-v2': 'UDP PROXY v2', 'udp-destination-tracking': 'UDP 通配监听真实目标地址', 'weighted-round-robin': '加权轮询', 'source-hash': '来源 IP 哈希', 'least-connections': '最少连接', 'source-cidr-acl': '来源网段 ACL', 'per-rule-quota': '规则共享配额', 'per-rule-bandwidth': '规则共享速率', 'durable-usage': '持久化流量账本', 'config-revisions': '版本与回滚', 'tenant-isolation': '租户隔离', 'session-revocation': '会话撤销', 'tls-data-transport': 'TLS 数据传输', 'mutual-tls': 'TLS 双向证书认证', 'backup-reconciliation': '旧备份用量对账', websocket: 'WebSocket 流隧道（v1）', 'secure-websocket': 'WSS 与双向证书验证', 'declared-multi-node-topology': '跨节点多跳引用与环路检查', 'atomic-config-batch': '多节点配置预览与事务发布', 'target-health-checks': '目标探测与故障恢复', 'priority-capacity-selection': '优先级与目标容量选路', 'lowest-latency-selection': '按探测耗时自动选择最快目标', 'node-telemetry': '节点资源、吞吐与事件历史', 'connection-prewarm': '中转间预热连接', 'alert-notifications': '告警通知（Webhook / Telegram / 企业微信 / 飞书 / 钉钉）', mptcp: 'MPTCP', 'node-execution-leases': '节点执行租约', 'node-inventory-lifecycle': '节点资料、批量编辑与暂停到期', 'durable-budget-run-recovery': '原状态额度恢复与预留诊断', 'multipath-aggregation': '单连接多路径聚合（自有 v1）', 'global-user-budgets': '跨节点用户总额度', 'hierarchical-budgets': '租户 / 节点分层额度', 'budget-reservation-return': '空闲预留归还', 'controller-recovery-log': '控制器恢复日志', 'budget-disaster-recovery': '预算完整灾难恢复', 'global-rate-limits': '跨节点总限速', wireguard: 'WireGuard 组网', 'nat-traversal': 'NAT 穿透', commerce: '套餐与交易', tickets: '支持工单', 'commerce-wallet': '钱包与资金流水', 'commerce-orders': '订单与退款', 'commerce-payments': '支付网关与回调验签', 'commerce-coupons': '优惠码', 'commerce-gifts': '礼品码', 'http-connect': 'HTTP CONNECT 入站', 'destination-acl': '目的地 ACL', 'config-templates': '规则模板', 'mptcp-diagnostics': 'MPTCP 能力观测', 'commerce-entitlements': '套餐权益执行', 'client-subscriptions': '客户端订阅', announcements: '公告', 'dns-records': 'DNS 托管记录与 DDNS', 'dns-health-removal': 'DNS 健康摘除', 'dns-authoritative-pool': '独立权威 DNS 池', 'dns-management': 'DNS 管理', federation: '跨面板共享', 'postgresql-ha': 'PostgreSQL 与控制面高可用' }; const grid = el('div', undefined, 'capabilities'); for (const [title, list, status, color] of [['已接入开发版本', c.available, '可用', 'green'], ['后续完整范围', c.pending, '待实现', '']]) { const p = panel(title, '最终验收以源码中的完整清单和测试证据为准。'), body = el('div', undefined, 'panel-body'); for (const key of list) { const row = el('div', undefined, 'capability'); row.append(el('span', names[key] || key), badge(status, color)); body.append(row); } p.append(body); grid.append(p); } if (state.view === 'capabilities') $('#content').replaceChildren(grid); }

// Skip while typing in the page so a re-render does not take the input away.
setInterval(() => { const typing = $('#content').contains(document.activeElement) && document.activeElement.matches('input, select, textarea'); if (state.actor && !document.hidden && !typing && !$('#dialog').open && ['overview', 'nodes', 'usage', 'budgets', 'alerts', 'recovery', 'topology', 'health'].includes(state.view)) refresh().catch(e => notify(e.message, true)); }, 5000);
if (state.token) { api('/session').then(user => { state.actor = user; return enter(); }).catch(e => { loggedOut(); $('#login-error').textContent = e.message; }); }

const budgetScopeNames = { user: '用户', tenant: '租户', node: '节点' };
async function renderBudgets() {
  const [overview, users, nodes] = await Promise.all([api('/budgets'), api('/users'), api('/nodes')]);
  const p = panel('跨节点共享额度', '已用 + 尚未归还的预留不能超过总额度。同一笔流量受适用的用户、租户和节点额度共同约束。', canWrite() && !overview.allocation_paused ? button('＋ 创建额度', () => editBudget(null, users, nodes), 'primary') : null);
  if (overview.allocation_paused) p.append(el('p', '控制器已从备份恢复，新增额度分配暂停。恢复完整的预留记录前，系统不会重复发放旧备份中遗漏的额度。', 'error'));
  function scopeLabel(b) { return b.scope === 'user' ? users.find(u => u.id === b.scope_id)?.username || b.scope_id : b.scope === 'node' ? nodes.find(n => n.id === b.scope_id)?.name || b.scope_id : b.scope_id; }
  if (!overview.budgets.length) p.append(empty('为多个入口设置一个总额度', '创建前先暂停该范围内的规则，并确认所有相关节点已应用；之后重新启用规则，系统会自动绑定额度。'));
  else p.append(table(['名称 / 范围', '总额度', '已上报用量', '尚未归还预留', '可分配', '操作'], overview.budgets.map(b => [namedCell(b.name, `${budgetScopeNames[b.scope]} · ${scopeLabel(b)}`), bytes(b.limit_bytes), bytes(b.consumed_bytes), bytes(b.committed_bytes - b.consumed_bytes), bytes(b.limit_bytes - b.committed_bytes), budgetActions(b, users, nodes, overview.allocation_paused)])));
  p.append(el('p', '节点按需领取预留。全节点会话空闲或正常停机后可归还未用部分；严格节点保留原状态且交接历史连续时，重启会先核对并恢复预留；旧备份或无法确认的部分继续占额。预留明细显示当前记录，增加总额度不会清零已有账。', 'fine'));
  if (state.view === 'budgets') $('#content').replaceChildren(p);
}
function budgetActions(budget, users, nodes, paused) {
  const actions = el('div');
  actions.append(button('预留明细', () => showBudgetReservations(budget), 'table-action'));
  if (canWrite() && !paused) actions.append(button('调整额度', () => editBudget(budget, users, nodes), 'table-action'));
  return actions;
}
async function showBudgetReservations(budget) {
  const body = el('div'), rows = [], content = el('div'), controls = el('div');
  body.append(el('p', '未归还部分可能包含尚未上报的消费，不能直接当作可退款余额。此列表按页读取当前记录；有变化时重新打开刷新。', 'fine'), content, controls);
  modal('预留明细 · ' + budget.name, body);
  async function load(after) {
    controls.replaceChildren(el('p', '加载中…', 'fine'));
    const page = await api(`/budgets/${budget.id}/reservations${after ? '?after=' + encodeURIComponent(after) : ''}`);
    rows.push(...page.reservations);
    content.replaceChildren(rows.length ? table(['节点 / 运行', '预留编号', '已分配', '已确认消费', '未归还', '运行保护'], rows.map(row => [
      namedCell(row.node_name, row.run_id), row.grant_id, bytes(row.allocated_bytes), bytes(row.confirmed_consumed_bytes), bytes(row.outstanding_bytes),
      !row.node_lease.policy ? '离线模式' : row.node_lease.active && row.node_lease.holder_run_id === row.run_id ? '当前运行持有租约' : '当前无此运行租约'
    ])) : empty('没有尚未关闭的预留', '已正常结算的预留不在此列表中。'));
    controls.replaceChildren();
    if (page.next) controls.append(button('加载下一页', () => load(page.next), 'table-action'));
  }
  await load(null);
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
  body.append(table(['同步阶段', '采样数', '平均 / ms', '最大 / ms'], [timingRow('排队与合并', metrics.queue_time), timingRow('数据库处理批次', metrics.storage_batch_time), timingRow('请求处理总时间', metrics.request_time)]), el('p', '数据库阶段包含线程池、数据库锁、SQL 和恢复日志提交；总时间到持久化结果返回，不包含响应传输与 Agent 本地写入。失败的已处理请求也计入耗时，429 拥塞退回不计入。', 'fine'));
  p.append(body); if (state.view === 'recovery') $('#content').replaceChildren(p);
}

const topologyKey = ref => `${ref.node_id}/${ref.rule_id}`;
async function renderTopology() {
  const snapshot = await api('/topology');
  const names = new Map(snapshot.nodes.map(node => [node.id, node.name]));
  const rules = snapshot.configs.flatMap(config => config.rules.map(rule => ({ config, rule, key: `${config.node_id}/${rule.id}` })));
  const byKey = new Map(rules.map(item => [item.key, item]));
  const displayed = rules.filter(item => item.rule.advertise || item.rule.targets.some(target => target.via));
  const actions = el('div'); if (canWrite()) actions.append(button('批量编辑', () => editTopologyBatch(snapshot)), button('＋ 创建多跳链路', () => newTopologyChain(snapshot), 'primary'));
  const p = panel('跨节点链路', '每行是一条实际规则；普通规则的多个下一跳是候选组，聚合规则表示通往同一汇聚端的子流，顺序中转由下一跳规则继续连接。每跳独立计量，同一用户额度会累计各跳接纳量。', actions);
  if (!displayed.length) p.append(empty('创建入口、中转和出口', '先注册节点，再为链路填写各节点监听与可达地址。'));
  else p.append(table(['节点 / 规则', '监听 / 可达地址', '下一跳或最终目标', '状态', '操作'], displayed.map(item => {
    const r = item.rule, targets = el('div');
    r.targets.forEach((target, index) => {
      const next = target.via ? byKey.get(topologyKey(target.via)) : null, path = r.outbound_multipath?.paths[index];
      const label = next ? names.get(next.config.node_id) + ' / ' + next.rule.name : target.address;
      const policy = path ? '子流 · 上/下权重 ' + path.upload_weight + '/' + path.download_weight : '候选 · 权重 ' + target.weight;
      targets.append(el('div', '→ ' + label + ' · ' + policy));
    });
    const actions = el('div'); actions.append(button('编辑节点规则', async () => { state.selectedNode = item.config.node_id; await navigate('rules'); }, 'table-action'));
    if (canWrite()) actions.append(button(r.enabled ? '停用关联链路' : '启用关联链路', () => changeTopologyComponent(snapshot, item.key, !r.enabled), 'table-action'));
    return [namedCell(names.get(item.config.node_id), r.name), namedCell(r.listen, r.advertise || '未声明可达地址'), targets, badge(r.enabled ? '期望启用' : '期望停用', r.enabled ? 'green' : ''), actions];
  })));
  const ids = new Set(displayed.map(item => item.config.node_id));
  const status = panel('节点应用状态', '配置在控制器一次提交，各节点异步应用。修订一致不代表业务探测成功；改向前需停用相关链路，并确认涉及节点的全部活跃会话归零。');
  status.append(table(['节点', '实际 / 期望修订', '活跃 TCP / UDP', '回报', '应用结果'], snapshot.nodes.filter(node => ids.has(node.id)).map(node => [node.name, `${node.applied_revision} / ${node.desired_revision}`, `${node.stats.active_tcp} / ${node.stats.active_udp}`, timestamp(node.last_seen_ms), node.apply_error || (node.enrolled && node.applied_revision === node.desired_revision ? '配置已确认' : '等待节点')])));
  if (state.view === 'topology') $('#content').replaceChildren(p, status);
}
async function previewTopology(snapshot, input) {
  const preview = await api('/configurations/preview', { method: 'POST', body: input });
  const body = el('div');
  body.append(el('p', '下面是服务器校验后的变更。发布会同时提交期望配置；节点应用结果请在拓扑页逐项确认。'), table(['节点', '修订', '新增 / 修改 / 删除规则'], preview.changes.map(change => [snapshot.nodes.find(node => node.id === change.node_id)?.name || change.node_id, `${change.from_revision} → ${change.to_revision}`, `${change.added.length} / ${change.modified.length} / ${change.removed.length}`])));
  for (const change of preview.changes) for (const diff of change.rule_changes) { const details = el('details'); details.append(el('summary', `${diff.after?.name || diff.before?.name} · 查看发布前后配置`), el('pre', JSON.stringify({ before: diff.before, after: diff.after }, null, 2))); body.append(details); }
  body.append(button('发布这些变更', async () => { await api('/configurations/publish', { method: 'POST', body: input }); $('#dialog').close(); notify('期望配置已同时提交，正在等待各节点应用。'); if (state.view === 'topology') await renderTopology(); }, 'primary'));
  modal('多节点发布预览', body);
}
async function changeTopologyComponent(snapshot, seed, enabled) {
  const selected = new Set([seed]); let changed = true;
  while (changed) { changed = false; for (const edge of snapshot.graph.edges) { const a = topologyKey(edge.from), b = topologyKey(edge.to); if (selected.has(a) || selected.has(b)) { if (!selected.has(a) || !selected.has(b)) changed = true; selected.add(a); selected.add(b); } } }
  const updates = snapshot.configs.filter(config => config.rules.some(rule => selected.has(`${config.node_id}/${rule.id}`))).map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: config.rules.map(rule => selected.has(`${config.node_id}/${rule.id}`) ? { ...rule, enabled } : rule) }));
  await previewTopology(snapshot, { updates });
}
async function newTopologyChain(snapshot) {
  if (!snapshot.nodes.length) { notify('先注册节点，再创建链路。', true); return; }
  const users = await api('/users');
  const form = el('form'), rows = [], holder = el('div');
  field(form, 'name', '链路名称').maxLength = 80;
  const ownerField = select(form, 'owner', '规则所有者（须与所有节点同一租户）', users.map(user => [user.id, `${user.username} · ${user.tenant_id}`]), state.actor.id);
  const protocol = select(form, 'protocol', '业务协议', [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], 'tcp');
  const transport = select(form, 'transport', '节点间传输', [['plain', '原生 TCP / UDP'], ['ws', 'WS 流隧道 · 仅 TCP'], ['wss', 'WSS 双向证书 · 仅 TCP']], 'plain');
  const secure = el('div', undefined, 'form-grid');
  const identity = field(secure, 'server_identity', '中转 / 出口的服务器证书编号', 'server');
  const authority = field(secure, 'ca_identity', '各节点的信任 CA 编号', 'root');
  const clientIdentity = field(secure, 'client_identity', '入口 / 中转的客户端证书编号', 'client');
  const wsFields = el('div'); const wsPath = field(wsFields, 'ws_path', 'WebSocket 路径', '/relay'); wsPath.maxLength = 1024;
  function showTransport() { const ws = transport.value !== 'plain', tls = transport.value === 'wss'; if (ws) protocol.value = 'tcp'; protocol.disabled = ws; secure.classList.toggle('hidden', !tls); [identity, authority, clientIdentity].forEach(input => { input.disabled = !tls; }); wsFields.classList.toggle('hidden', !ws); wsPath.disabled = !ws; rows.forEach((row, index) => { row.tlsName.disabled = !tls || index === 0; row.tlsName.required = tls && index > 0; row.tlsLabel.classList.toggle('hidden', !tls || index === 0); }); }
  transport.addEventListener('change', showTransport); form.append(secure, wsFields);
  form.append(el('p', '按顺序添加入口、中转、出口，可达地址必须从前一节点实际可连接。WSS 证书需要预先放在各节点本地；各节点可在相同证书编号下使用自己的证书内容。前后两端其他参数可通过高级批量编辑同时调整。', 'fine'));
  function add() {
    if (rows.length >= 16) return;
    const index = rows.length, card = el('fieldset'); card.append(el('legend', `第 ${index + 1} 跳`));
    const node = select(card, `node-${index}`, '节点', snapshot.nodes.map(n => [n.id, `${n.name} · ${n.tenant_id}`]), snapshot.nodes[Math.min(index, snapshot.nodes.length - 1)].id);
    const listen = field(card, `listen-${index}`, '本机监听地址', `0.0.0.0:${19001 + index}`);
    const advertise = field(card, `advertise-${index}`, '供前一节点连接的地址'); advertise.placeholder = `node.example.com:${19001 + index}`;
    const tlsName = field(card, `tls_name-${index}`, '此节点证书中的服务名', '', 'text', false); tlsName.placeholder = 'relay.example.com';
    rows.push({ node, listen, advertise, tlsName, tlsLabel: tlsName.parentElement }); holder.append(card); showTransport();
  }
  add(); add(); form.append(holder, button('＋ 添加一跳', add));
  textarea(form, 'targets', '出口最终目标（每行一个；多个目标为加权相同的候选）', '', true);
  textarea(form, 'allow_sources', '允许来源 CIDR（每行一个，留空不限；中转默认看到前一节点地址）');
  submit(form, '校验并预览链路', async data => {
    const selected = rows.map(row => snapshot.nodes.find(node => node.id === row.node.value));
    if (selected.some(node => node.tenant_id !== selected[0].tenant_id)) throw new Error('同一链路的节点必须属于同一租户');
    const owner = users.find(user => user.id === ownerField.value);
    if (!owner || owner.tenant_id !== selected[0].tenant_id) throw new Error('规则所有者必须属于节点所在租户');
    const ids = rows.map(() => crypto.randomUUID()), epoch = crypto.randomUUID();
    const targets = String(data.get('targets')).split(/\r?\n/).map(value => value.trim()).filter(Boolean).map(address => ({ address, weight: 1 }));
    const configs = new Map(), ws = transport.value !== 'plain', tls = transport.value === 'wss';
    rows.forEach((row, index) => {
      const nodeId = row.node.value, base = snapshot.configs.find(config => config.node_id === nodeId);
      if (!configs.has(nodeId)) configs.set(nodeId, { node_id: nodeId, expected_revision: base.revision, rules: [...base.rules] });
      const rule = { id: ids[index], tenant_id: selected[0].tenant_id, owner_id: owner.id, name: `${data.get('name')} · ${index + 1}`, protocol: protocol.value, listen: row.listen.value.trim(), advertise: row.advertise.value.trim(), enabled: true, meter_epoch: epoch, targets: index === rows.length - 1 ? targets : [{ address: rows[index + 1].advertise.value.trim(), weight: 1, via: { node_id: rows[index + 1].node.value, rule_id: ids[index + 1] } }], allow_sources: String(data.get('allow_sources')).split(/\r?\n/).map(value => value.trim()).filter(Boolean) };
      if (index > 0 && ws) rule.inbound_websocket = { path: wsPath.value.trim(), host: rule.advertise, allowed_origins: [] };
      if (index > 0 && tls) rule.inbound_tls = { identity: identity.value.trim(), client_ca: authority.value.trim() };
      if (index < rows.length - 1 && ws) rule.targets[0].websocket = { path: wsPath.value.trim(), host: rows[index + 1].advertise.value.trim() };
      if (index < rows.length - 1 && tls) rule.targets[0].tls = { server_name: rows[index + 1].tlsName.value.trim(), ca: authority.value.trim(), identity: clientIdentity.value.trim() };
      configs.get(nodeId).rules.push(rule);
    });
    await previewTopology(snapshot, { updates: [...configs.values()] });
  });
  showTransport(); modal('创建顺序链路', form);
}
function editTopologyBatch(snapshot) {
  const form = el('form'); const input = textarea(form, 'batch', '节点配置批次（删除不需要发布的节点）', JSON.stringify({ updates: snapshot.configs.map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: config.rules })) }, null, 2), true); input.rows = 20;
  form.append(el('p', '保留每个节点的其他规则；省略的规则表示删除。服务器会校验所有引用、修订和停止确认条件。', 'fine'));
  submit(form, '校验并预览', async data => previewTopology(snapshot, JSON.parse(data.get('batch')))); modal('批量编辑配置', form);
}

function healthEditor(form, spec, protocol) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', '目标健康、故障摘除与恢复'));
  const enabled = select(box, 'health_enabled', '主动探测', [['off', '关闭'], ['on', '启用 · 仅选择已通过探测的目标']], spec ? 'on' : 'off');
  const grid = el('div', undefined, 'form-grid'), numbers = {};
  for (const [key, label, fallback, min, max] of [['interval_ms', '探测间隔 / 毫秒', 1000, 100, 300000], ['timeout_ms', '单次超时 / 毫秒（不超过间隔）', 1000, 25, 60000], ['unhealthy_threshold', '连续失败几次摘除', 2, 1, 20], ['healthy_threshold', '连续成功几次接纳 / 恢复', 2, 1, 20], ['recovery_delay_ms', '恢复后的持续观察 / 毫秒', 5000, 0, 600000], ['max_age_ms', '结果有效期 / 毫秒（至少间隔 + 超时）', 10000, 125, 3600000]]) { const input = field(grid, `health_${key}`, label, spec?.[key] ?? fallback, 'number'); input.min = min; input.max = max; numbers[key] = input; }
  const tcp = el('fieldset'); tcp.append(el('legend', 'TCP 目标'));
  const tcpMode = select(tcp, 'health_tcp_kind', '成功条件', [['connect', '建立传输 · 含 TLS / WS 握手，不验证业务回复'], ['exchange', '发送探测请求，并校验响应前缀']], spec?.tcp?.kind || 'connect');
  const tcpFields = el('div');
  const tcpRequest = textarea(tcpFields, 'health_tcp_request', '请求内容 / Base64（最多 1024 字节，可留空等待欢迎消息）', spec?.tcp?.request_base64 || '');
  const tcpExpected = textarea(tcpFields, 'health_tcp_expected', '预期响应前缀 / Base64（1～1024 字节）', spec?.tcp?.expected_base64 || '', true);
  const halfClose = select(tcpFields, 'health_tcp_fin', '发送请求后关闭写方向', [['no', '保持写方向'], ['yes', '发送 FIN，继续等待回复']], spec?.tcp?.half_close ? 'yes' : 'no');
  tcp.append(tcpFields);
  const udp = el('fieldset'); udp.append(el('legend', 'UDP 目标 · 必须收到完整且匹配的响应包'));
  const udpRequest = textarea(udp, 'health_udp_request', '请求包 / Base64（1～1024 字节）', spec?.udp?.request_base64 || '', true);
  const udpExpected = textarea(udp, 'health_udp_expected', '完整预期回复 / Base64（1～1024 字节）', spec?.udp?.expected_base64 || '', true);
  for (const input of [tcpRequest, tcpExpected, udpRequest, udpExpected]) input.maxLength = 1368;
  function show() {
    const on = enabled.value === 'on', hasTcp = protocol.value !== 'udp', hasUdp = protocol.value !== 'tcp';
    grid.classList.toggle('hidden', !on); Object.values(numbers).forEach(input => { input.disabled = !on; });
    tcp.classList.toggle('hidden', !on || !hasTcp); tcpMode.disabled = !on || !hasTcp;
    const exchange = on && hasTcp && tcpMode.value === 'exchange'; tcpFields.classList.toggle('hidden', !exchange); [tcpRequest, tcpExpected, halfClose].forEach(input => { input.disabled = !exchange; });
    udp.classList.toggle('hidden', !on || !hasUdp); [udpRequest, udpExpected].forEach(input => { input.disabled = !on || !hasUdp; });
  }
  for (const input of [enabled, tcpMode, protocol]) input.addEventListener('change', show);
  box.append(grid, tcp, udp, el('p', '首次通过探测前、结果过期或全部目标不可用时，新业务会被拒绝。探测使用节点实际出口与传输参数，报文应能重复执行。源节点探测统计单列；经过中转时，下游规则仍按收到的应用负载计量。', 'fine')); form.append(box); show();
  const encoded = input => input.value.replace(/\s/g, '');
  return () => {
    if (enabled.value === 'off') return null;
    const value = Object.fromEntries(Object.entries(numbers).map(([key, input]) => [key, Number(input.value)]));
    if (protocol.value !== 'udp') value.tcp = tcpMode.value === 'connect' ? { kind: 'connect' } : { kind: 'exchange', request_base64: encoded(tcpRequest), expected_base64: encoded(tcpExpected), half_close: halfClose.value === 'yes' };
    if (protocol.value !== 'tcp') value.udp = { request_base64: encoded(udpRequest), expected_base64: encoded(udpExpected) };
    return value;
  };
}

async function renderHealth() {
  const nodes = await api('/nodes');
  if (!nodes.length) { if (state.view === 'health') $('#content').replaceChildren(empty('还没有节点', '先接入节点，再在规则中设置目标健康探测。')); return; }
  if (!nodes.some(n => n.id === state.selectedNode)) state.selectedNode = nodes[0].id;
  const selected = state.selectedNode, toolbar = el('div', undefined, 'toolbar'), selector = el('select'); selector.setAttribute('aria-label', '选择节点');
  nodes.forEach(node => { const option = el('option', node.name); option.value = node.id; selector.append(option); }); selector.value = selected; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; toolbar.append(selector);
  const snapshot = await api(`/nodes/${selected}/health`);
  if (state.view !== 'health' || state.selectedNode !== selected) return;
  const node = nodes.find(n => n.id === selected);
  toolbar.append(badge(`生效 v${snapshot.applied_revision} / 期望 v${snapshot.desired_revision}`), badge(online(node) ? '控制在线' : '无近期控制回报', online(node) ? 'green' : 'orange'), button('配置规则', () => navigate('rules')));
  const panelHealth = panel('目标观测与选路', 'TCP 与 UDP 独立判断；同优先级按规则的均衡策略分配，低优先级目标作为候选后备。已有 TCP 不会因单次健康状态变化被强制迁移。丢包与抖动按每个端点最近 20 次探测计算；“最低延迟”选路把丢包计入耗时。');
  const kinds = { tcp_connect: '传输建立', tcp_exchange: 'TCP 响应前缀', udp_exchange: 'UDP 完整回复' };
  const statuses = { unknown: '尚未确认', healthy: '探测通过', unhealthy: '已摘除', recovering: '恢复观察', stale: '结果过期' };
  const reasons = { eligible: '参与优先池', standby: '后备候选', unknown: '等待探测确认', unhealthy: '故障排除', recovering: '等待持续成功', stale: '等待新结果', at_capacity: '会话已满', expired: '规则已到期' };
  const errors = { dns: '域名解析失败', transport: '连接、握手或路径检查失败', timeout: '探测超时', io: '收发失败', unexpected_response: '回复不符或提前关闭', expired: '规则已到期' };
  const info = el('div', undefined, 'panel-body'); info.append(el('p', `最近节点回报：${timestamp(snapshot.last_seen_ms)} · ${snapshot.reports.length} / ${snapshot.expected_endpoints} 个配置端点有记录 · 当前探测 ${snapshot.active_probes} 个`)); if (snapshot.apply_error) info.append(el('p', `配置应用失败：${snapshot.apply_error}`, 'error')); panelHealth.append(info);
  if (!snapshot.reports.length) panelHealth.append(empty('暂无目标探测结果', snapshot.expected_endpoints ? '节点尚未上报这些端点的结果，不能视为健康。' : '在规则编辑器启用健康探测，填写对应业务的成功条件。'));
  else panelHealth.append(table(['规则 / 目标', '端口 / 成功条件', '观测状态', '选路原因', '优先级 / 会话', '耗时 / 丢包 · 抖动', '连续成功 / 失败', '诊断'], snapshot.reports.map(r => {
    const diagnostic = el('details'); diagnostic.append(el('summary', r.last_error ? errors[r.last_error] : '查看探测统计'), el('p', `完成 ${r.completed_checks} 次，成功 ${r.successful_checks} 次`), el('p', `结果年龄 ${r.sample_age_ms === null ? '—' : `${(r.sample_age_ms / 1000).toFixed(1)} 秒`}，有效期 ${(r.max_age_ms / 1000).toFixed(1)} 秒`), el('p', `源节点探测应用量：发送 ${bytes(r.probe_sent_bytes)} / 接收 ${bytes(r.probe_received_bytes)}`), el('p', `节点记录时间：${timestamp(r.checked_at_ms)}`));
    return [namedCell(snapshot.rule_names?.[r.rule_id] || r.rule_id, r.target_address), `${r.listen_port} / ${kinds[r.probe_kind]}`, badge(statuses[r.status], r.eligible ? 'green' : 'orange'), r.selection_reason === 'degraded' ? namedCell('丢包降级', '同级暂作后备') : r.selection_reason === 'draining' ? namedCell('维护排空', '仅作最后备用') : reasons[r.selection_reason] || r.selection_reason, `${r.priority} / ${r.active_sessions} / ${r.max_sessions ?? '不限'}`, namedCell(r.latency_ewma_us === null ? '—' : `${(r.latency_ewma_us / 1000).toFixed(2)} ms`, r.window_checks ? `丢包 ${Math.round(100 * r.window_failures / r.window_checks)}% · 抖动 ${r.jitter_us == null ? '—' : `${(r.jitter_us / 1000).toFixed(2)} ms`}` : '尚无探测'), `${r.consecutive_successes} / ${r.consecutive_failures}`, diagnostic];
  })));
  $('#content').replaceChildren(toolbar, panelHealth);
}
