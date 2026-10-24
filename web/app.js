const $ = (s, root = document) => root.querySelector(s);
const state = { token: sessionStorage.getItem('relay-session'), actor: null, view: 'nodes', nodes: [], usage: [], selectedNode: null, config: null, busy: false };
const titles = { nodes: '节点总览', rules: '转发规则', topology: '多跳拓扑', health: '目标健康', usage: '流量账本', budgets: '共享额度', users: '用户与权限', audit: '操作审计', recovery: '恢复保护', capabilities: '功能进度' };
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
    const maximum = field(grid, `target-max-${id}`, '目标会话上限（TCP + UDP，留空不限）', target.max_sessions, 'number', false); maximum.min = 1; maximum.max = 1000000;
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
    const row = { box, address, via, weight, priority, maximum, mode, name, ca, identity, proxyMode, proxyPlacement, proxyCrc, ws, up, down, bindIp, bindInterface }; rows.push(row);
    function showSecurity() { const enabled = mode.value === 'tls'; secure.classList.toggle('hidden', !enabled); name.required = enabled; [name, ca, identity].forEach(input => { input.disabled = !enabled; }); }
    mode.onchange = showSecurity; showSecurity(); box.append(secure, proxyFields, ws.box, mp, button('移除此目标', () => { multipathMode?.removeEventListener('change', showMultipath); rows.splice(rows.indexOf(row), 1); box.remove(); }, 'table-action danger')); container.append(box);
  }
  targets.forEach((target, index) => add(target, multipathPaths?.[index])); form.append(container, button('＋ 添加目标', () => add()));
  const read = () => { if (!rows.length) throw new Error('至少保留一个转发目标'); return rows.map(row => {
    const target = { address: row.address.value.trim(), weight: Number(row.weight.value), priority: Number(row.priority.value), max_sessions: row.maximum.value === '' ? null : Number(row.maximum.value), ...(row.mode.value === 'tls' ? { tls: { server_name: row.name.value.trim(), ca: row.ca.value.trim() || null, identity: row.identity.value.trim() || null } } : {}) };
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

$('#login-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, b = $('button', form); b.disabled = true; $('#login-error').textContent = ''; try { const f = new FormData(form); const result = await api('/auth/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password') } }); state.token = result.token; state.actor = result.user; sessionStorage.setItem('relay-session', result.token); $('[name=password]', form).value = ''; await enter(); } catch (error) { $('#login-error').textContent = error.message; } finally { b.disabled = false; } };
document.querySelectorAll('[data-logout]').forEach(b => { b.onclick = async () => { try { await api('/auth/logout', { method: 'POST' }); } finally { loggedOut(); } }; });
$('#refresh').onclick = () => refresh().catch(e => notify(e.message, true));
document.querySelectorAll('[data-view]').forEach(n => n.addEventListener('click', () => navigate(n.dataset.view)));
async function enter() { $('#login-screen').classList.add('hidden'); $('#application').classList.remove('hidden'); $('#identity').textContent = `${state.actor.username} · ${roleNames[state.actor.role]}`; document.querySelectorAll('.admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role !== 'system_admin')); await refresh(); }
async function navigate(view) { state.view = view; $('#notification').classList.add('hidden'); document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === view)); $('#view-title').textContent = titles[view]; try { await refresh(); } catch (e) { notify(e.message, true); } }
async function refresh() {
  if (!state.actor || state.busy) return; const requestedView = state.view, requestedNode = state.selectedNode; state.busy = true; $('#refresh').disabled = true;
  try { await ({ nodes: renderNodes, rules: renderRules, usage: renderUsage, budgets: renderBudgets, users: renderUsers, audit: renderAudit, recovery: renderRecovery, topology: renderTopology, health: renderHealth, capabilities: renderCapabilities })[state.view](); $('#refreshed').textContent = `更新于 ${new Date().toLocaleTimeString('zh-CN', { hour12: false })}`; }
  finally { state.busy = false; $('#refresh').disabled = false; if (state.actor && (state.view !== requestedView || (['rules', 'health'].includes(requestedView) && requestedNode !== state.selectedNode))) queueMicrotask(() => refresh().catch(e => notify(e.message, true))); }
}

async function renderNodes() {
  const [nodes, usage] = await Promise.all([api('/nodes'), api('/usage')]); state.nodes = nodes; state.usage = usage;
  const metric = el('div', undefined, 'metrics');
  [['节点总数', nodes.length, '当前账号可见的节点'], ['控制在线', nodes.filter(online).length, '最近 30 秒收到心跳'], ['活跃连接', nodes.filter(online).reduce((s, n) => s + n.stats.active_tcp + n.stats.active_udp, 0), '在线节点的 TCP + UDP 会话'], ['近期上报负载', bytes(usage.reduce((s, u) => s + u.upload_bytes + u.download_bytes, 0)), '最近 2,000 个计量周期 · 上下行合计']].forEach(([title, value, foot]) => { const n = el('div', undefined, 'metric'); n.append(el('div', title, 'metric-label'), el('div', String(value), 'metric-value'), el('div', foot, 'metric-foot')); metric.append(n); });
  const p = panel('节点', '注册节点、确认配置生效，并检查实际回报。', canWrite() ? button('＋ 注册节点', newNode, 'primary') : null);
  if (!nodes.length) p.append(empty('接入你的第一个节点', '注册生成一次性令牌，在节点启动 Agent 后即可配置转发。', canWrite() ? button('注册节点', newNode, 'primary') : null));
  else p.append(table(['节点 / ID', '控制连接', '配置修订', '活跃会话', '最近回报', '操作'], nodes.map(node => [namedCell(node.name, node.id), badge(node.enrolled ? online(node) ? '● 控制在线' : '○ 无近期回报' : '待注册', online(node) ? 'green' : ''), node.apply_error ? namedCell(`应用失败 · ${node.applied_revision} / ${node.desired_revision}`, node.apply_error) : badge(`${node.applied_revision} / ${node.desired_revision}`, node.applied_revision === node.desired_revision && node.enrolled ? 'green' : 'orange'), online(node) ? `${node.stats.active_tcp} TCP / ${node.stats.active_udp} UDP` : '—', timestamp(node.last_seen_ms), nodeActions(node)])));
  if (state.view === 'nodes') $('#content').replaceChildren(metric, p);
}
function timingRow(label, value) {
  if (!value) return [label, '未提供', '—', '—'];
  return [label, String(value.samples), value.samples ? (value.total_us / value.samples / 1000).toFixed(3) : '—', value.samples ? (value.max_us / 1000).toFixed(3) : '—'];
}
function nodeActions(node) {
  const actions = el('div');
  actions.append(button('管理规则 →', async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action'), button('运行诊断', () => nodeDiagnostics(node), 'table-action'));
  return actions;
}
function nodeDiagnostics(node) {
  const body = el('div'), stats = node.stats, meter = stats.meter;
  body.append(el('p', `${node.name} · 最近回报 ${timestamp(node.last_seen_ms)}`), el('p', online(node) ? '以下为最近一次节点采样。' : '节点没有近期回报，以下是旧采样。', 'fine'));
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
  else p.append(table(['名称', '监听 / 协议', '目标', '配额 / 限速', '状态', '操作'], config.rules.map(rule => { const actions = el('div'); if (canWrite()) { actions.append(button('编辑', () => editRule(rule), 'table-action'), button(rule.enabled ? '停用' : '启用', () => saveRules(config.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r), config), 'table-action'), button('删除', async () => { if (confirm(`删除「${rule.name}」会终止其会话，历史账本保留。`)) await saveRules(config.rules.filter(r => r.id !== rule.id), config); }, 'table-action danger')); } return [namedCell(rule.name, rule.id), namedCell(rule.listen + (rule.listen_end_port ? ` → ${rule.listen_end_port}` : ''), rule.protocol.toUpperCase()), namedCell(rule.targets[0].address, `${rule.targets.length} 个目标 · ${rule.balance}`), `${rule.quota_bytes === null ? '不限量' : bytes(rule.quota_bytes)} / ${rule.rate_bytes_per_sec === null ? '不限速' : bytes(rule.rate_bytes_per_sec) + '/s'}`, badge(rule.enabled ? '已启用' : '已停用', rule.enabled ? 'green' : ''), actions]; })));
  content.replaceChildren(toolbar, p);
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
  select(grid, 'balance', '目标分配', [['weighted_round_robin', '加权轮询'], ['source_hash', '来源 IP 哈希'], ['least_connections', '最少连接']], r.balance || 'weighted_round_robin'); form.append(grid);
  const readHealth = healthEditor(form, r.health_check, protocolControl);
  const multipath = multipathEditor(form, r);
  const readTargets = targetEditor(form, r.targets || [{ address: '127.0.0.1:8000', weight: 1 }], topology, state.nodes.find(node => node.id === baseConfig.node_id).tenant_id, r.id, r.outbound_multipath?.paths, multipath.mode);
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
  const proxyInput = el('details'); proxyInput.append(el('summary', '接收可信上游传递的原始地址（PROXY protocol）'));
  const proxyMode = select(proxyInput, 'proxy_input_version', '入口 PROXY 报头', [['off', '关闭'], ['v1', '要求 v1 · 仅 TCP'], ['v2', '要求 v2 · TCP / UDP'], ['any', '要求 v1 或 v2 · 仅 TCP']], r.inbound_proxy?.version || 'off');
  const proxyOptions = el('div', undefined, 'form-grid');
  textarea(proxyOptions, 'proxy_trusted_sources', '允许发送报头的代理 CIDR（每行一个，不能为空）', (r.inbound_proxy?.trusted_sources || ['127.0.0.0/8', '::1/128']).join('\n'), true);
  select(proxyOptions, 'proxy_input_placement', 'PROXY 报头位置', [['before_tls', 'TLS 之前（普通连接也选此项）'], ['inside_tls', 'TLS 加密连接内（须同时启用入口 TLS）']], r.inbound_proxy?.placement || 'before_tls');
  const proxyLimit = field(proxyOptions, 'proxy_header_limit', '报头字节上限', r.inbound_proxy?.max_header_bytes ?? 4096, 'number'); proxyLimit.min = 16; proxyLimit.max = 65551;
  function showProxyInput() { const enabled = proxyMode.value !== 'off'; proxyOptions.classList.toggle('hidden', !enabled); proxyOptions.querySelectorAll('input, select, textarea').forEach(input => { input.disabled = !enabled; }); } proxyMode.addEventListener('change', showProxyInput); showProxyInput();
  proxyInput.append(proxyOptions, el('p', '启用后必须携带正确报头；直接客户端将被拒绝。来源 ACL 和来源哈希按报头中的客户端地址执行。PROXY 和 CRC32C 不提供身份认证；可信网段应只包含你的代理。UDP 每包都须携带 v2，回复为普通业务数据。', 'fine')); form.append(proxyInput);
  const limits = el('div', undefined, 'form-grid'); field(limits, 'quota_bytes', '合并配额 / bytes（留空不限，0 禁止流量）', r.quota_bytes, 'number', false).min = 0; field(limits, 'rate_bytes_per_sec', '合并速率 / bytes/s（留空不限）', r.rate_bytes_per_sec, 'number', false).min = 1; form.append(limits);
  const details = el('details'); details.append(el('summary', '高级：超时、会话上限、到期和来源网段')); const advanced = el('div', undefined, 'form-grid');
  for (const [name, label, fallback, min, max] of [['connect_timeout_ms', '连接超时 / ms', 5000, 100, 60000], ['idle_timeout_secs', '空闲回收 / 秒', 120, 1, 86400], ['max_connections', 'TCP 最大连接', 4096, 1, 1000000], ['udp_max_sessions', 'UDP 最大会话', 1024, 1, 100000]]) { const input = field(advanced, name, label, r[name] ?? fallback, 'number'); input.min = min; input.max = max; }
  const expiry = field(advanced, 'expires_at_ms', '到期 / Unix 毫秒（留空永不过期）', r.expires_at_ms, 'number', false); expiry.min = 0; details.append(advanced); textarea(details, 'allow_sources', '允许来源 CIDR（留空允许所有未拒绝来源，每行一个）', (r.allow_sources || []).join('\n')); textarea(details, 'deny_sources', '拒绝来源 CIDR（优先于允许列表，每行一个）', (r.deny_sources || []).join('\n')); form.append(details);
  const enabledLabel = el('label', undefined, 'inline-check'), enabled = el('input'); enabled.name = 'enabled'; enabled.type = 'checkbox'; enabled.checked = r.enabled ?? true; enabledLabel.append(enabled, document.createTextNode('启用规则')); form.append(enabledLabel);
  form.append(el('p', '同一规则的所有连接共享额度和速率。速率桶允许 max(64 KiB, 一秒额度) 的突发；这不是跨节点用户总限速。', 'fine'));
  submit(form, existing ? '发布修改' : '创建并发布', async data => {
    const node = state.nodes.find(n => n.id === baseConfig.node_id), lines = key => String(data.get(key)).split('\n').map(s => s.trim()).filter(Boolean);
    const rule = { id: r.id || crypto.randomUUID(), tenant_id: node.tenant_id, owner_id: r.owner_id || state.actor.id, name: data.get('name'), protocol: data.get('protocol'), listen: data.get('listen'), balance: data.get('balance'), enabled: data.get('enabled') === 'on', targets: readTargets(), meter_epoch: r.meter_epoch || crypto.randomUUID(), allow_sources: lines('allow_sources'), deny_sources: lines('deny_sources') };
    rule.health_check = readHealth();
    Object.assign(rule, multipath.read(readTargets.multipathPaths()));
    rule.advertise = String(data.get('advertise')).trim() || null;
    rule.listen_end_port = number(data, 'listen_end_port'); rule.port_mapping = data.get('port_mapping');
    const outboundIp = String(data.get('outbound_ip')).trim(), outboundInterface = String(data.get('outbound_interface')).trim();
    if (outboundIp || outboundInterface) rule.outbound_bind = { ip: outboundIp || null, interface: outboundInterface || null };
    if (data.get('dns_mode') === 'cache') rule.dns_cache = { servers: lines('dns_servers'), capacity: number(data, 'dns_capacity'), max_ttl_secs: number(data, 'dns_max_ttl_secs'), negative_max_ttl_secs: number(data, 'dns_negative_max_ttl_secs') };
    const identity = String(data.get('tls_identity')).trim(), clientCa = String(data.get('tls_client_ca')).trim();
    if (clientCa && !identity) throw new Error('要求客户端证书时，请同时填写入口证书编号');
    if (identity) rule.inbound_tls = { identity, client_ca: clientCa || null };
    const websocket = inboundWs.read(); if (websocket) rule.inbound_websocket = websocket;
    if (rule.protocol !== 'tcp' && (websocket || rule.targets.some(target => target.websocket))) throw new Error('WebSocket / WSS 流隧道只支持 TCP，请调整规则协议');
    if (data.get('proxy_input_version') !== 'off') rule.inbound_proxy = { version: data.get('proxy_input_version'), trusted_sources: lines('proxy_trusted_sources'), placement: data.get('proxy_input_placement'), max_header_bytes: number(data, 'proxy_header_limit') };
    for (const key of ['quota_bytes', 'rate_bytes_per_sec', 'expires_at_ms', 'connect_timeout_ms', 'idle_timeout_secs', 'max_connections', 'udp_max_sessions']) rule[key] = number(data, key);
    await saveRules(existing ? baseConfig.rules.map(item => item.id === r.id ? rule : item) : [...baseConfig.rules, rule], baseConfig);
  }); modal(existing ? '编辑转发规则' : '添加转发规则', form);
}
async function history() { const baseConfig = state.config; const revisions = await api(`/nodes/${baseConfig.node_id}/history`); const body = table(['修订', '操作者', '时间', '操作'], revisions.map(r => [`v${r.revision}`, r.actor_id, timestamp(r.created_at_ms), canWrite() ? button('发布此版本', async () => { await api(`/nodes/${baseConfig.node_id}/rollback`, { method: 'POST', body: { revision: r.revision, expected_revision: baseConfig.revision } }); $('#dialog').close(); notify('历史配置已作为新修订发布。账本不回滚。'); await renderRules(); }, 'table-action') : '只读'])); modal('最近 100 次配置修订', body); }
async function renderUsage() { const records = await api('/usage'); const p = panel('已接纳应用负载', '累计值按节点、规则与计量周期去重；发送失败也可能已经接纳计量。最多显示最近 2,000 条周期记录。'); if (!records.length) p.append(empty('还没有流量记录', '让一条转发规则通过真实流量，Agent 会在同步后上报。')); else p.append(table(['规则 / 周期', '节点', '上行', '下行', '序号', '最近上报'], records.map(r => [namedCell(r.rule_id, r.meter_epoch), r.node_id, bytes(r.upload_bytes), bytes(r.download_bytes), r.sequence, timestamp(r.reported_at_ms)]))); if (state.view === 'usage') $('#content').replaceChildren(p); }
async function renderUsers() { const users = await api('/users'); const p = panel('用户与会话', '权限由服务端校验；撤销后已有 Web 会话立即失效。', canWrite() ? button('＋ 添加用户', newUser, 'primary') : null); p.append(table(['账号', '角色', '租户', '操作'], users.map(u => [namedCell(u.username, u.id), roleNames[u.role], u.tenant_id, canWrite() || u.id === state.actor.id ? button('撤销全部会话', async () => { await api(`/users/${u.id}/revoke-sessions`, { method: 'POST' }); if (u.id === state.actor.id) loggedOut(); else notify('该用户现有会话已撤销。'); }, 'table-action') : '—']))); if (state.view === 'users') $('#content').replaceChildren(p); }
function newUser() { const form = el('form'); field(form, 'username', '用户名').maxLength = 80; const p = field(form, 'password', '初始密码（至少 12 个字节）', '', 'password'); p.minLength = 12; p.autocomplete = 'new-password'; const roles = [['viewer', '只读用户'], ['tenant_admin', '租户管理员']]; if (state.actor.role === 'system_admin') roles.push(['system_admin', '系统管理员']); select(form, 'role', '角色', roles, 'viewer'); submit(form, '创建用户', async data => { await api('/users', { method: 'POST', body: Object.fromEntries(data) }); $('#dialog').close(); await renderUsers(); }); modal('添加用户', form); }
async function renderAudit() { const rows = await api('/audit'); const p = panel('操作审计', '记录配置发布、节点注册、身份及会话操作。最近 200 条。'); p.append(table(['时间', '操作者', '操作', '对象', '详情'], rows.map(r => [timestamp(r.at_ms), r.actor_id, r.action, r.resource, r.detail]))); if (state.view === 'audit') $('#content').replaceChildren(p); }
async function renderCapabilities() { const c = await api('/capabilities'); const names = { tcp: 'TCP 转发', udp: 'UDP 转发', ipv4: 'IPv4', ipv6: 'IPv6', 'dns-targets': '域名目标', 'port-ranges': '端口段与偏移映射', 'outbound-binding': '业务出口 IP / 网卡绑定', 'dns-ttl-cache': '目标 DNS TTL 缓存', 'node-local-loop-protection': '节点内监听环路检查', 'proxy-protocol-tcp-v1-v2': 'TCP PROXY v1 / v2', 'proxy-protocol-udp-v2': 'UDP PROXY v2', 'udp-destination-tracking': 'UDP 通配监听真实目标地址', 'weighted-round-robin': '加权轮询', 'source-hash': '来源 IP 哈希', 'least-connections': '最少连接', 'source-cidr-acl': '来源网段 ACL', 'per-rule-quota': '规则共享配额', 'per-rule-bandwidth': '规则共享速率', 'durable-usage': '持久化流量账本', 'config-revisions': '版本与回滚', 'tenant-isolation': '租户隔离', 'session-revocation': '会话撤销', 'tls-data-transport': 'TLS 数据传输', 'mutual-tls': 'TLS 双向证书认证', 'backup-reconciliation': '旧备份用量对账', websocket: 'WebSocket 流隧道（v1）', 'secure-websocket': 'WSS 与双向证书验证', 'declared-multi-node-topology': '跨节点多跳引用与环路检查', 'atomic-config-batch': '多节点配置预览与事务发布', 'target-health-checks': '目标探测与故障恢复', 'priority-capacity-selection': '优先级与目标容量选路', mptcp: 'MPTCP', 'multipath-aggregation': '单连接多路径聚合（自有 v1）', 'global-user-budgets': '跨节点用户总额度', 'hierarchical-budgets': '租户 / 节点分层额度', 'budget-reservation-return': '空闲预留归还', 'controller-recovery-log': '控制器恢复日志', 'budget-disaster-recovery': '预算完整灾难恢复', 'global-rate-limits': '跨节点总限速', wireguard: 'WireGuard 组网', 'nat-traversal': 'NAT 穿透', commerce: '套餐与交易', subscriptions: '客户端订阅', 'dns-management': 'DNS 管理', federation: '跨面板共享', 'postgresql-ha': 'PostgreSQL 与控制面高可用' }; const grid = el('div', undefined, 'capabilities'); for (const [title, list, status, color] of [['已接入开发版本', c.available, '可用', 'green'], ['后续完整范围', c.pending, '待实现', '']]) { const p = panel(title, '最终验收以源码中的完整清单和测试证据为准。'), body = el('div', undefined, 'panel-body'); for (const key of list) { const row = el('div', undefined, 'capability'); row.append(el('span', names[key] || key), badge(status, color)); body.append(row); } p.append(body); grid.append(p); } if (state.view === 'capabilities') $('#content').replaceChildren(grid); }

setInterval(() => { if (state.actor && !document.hidden && !$('#dialog').open && ['nodes', 'usage', 'budgets', 'recovery', 'topology', 'health'].includes(state.view)) refresh().catch(e => notify(e.message, true)); }, 5000);
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
  for (const [key, label, fallback, min, max] of [['interval_ms', '探测间隔 / 毫秒', 5000, 100, 300000], ['timeout_ms', '单次超时 / 毫秒（不超过间隔）', 2000, 25, 60000], ['unhealthy_threshold', '连续失败几次摘除', 3, 1, 20], ['healthy_threshold', '连续成功几次接纳 / 恢复', 2, 1, 20], ['recovery_delay_ms', '恢复后的持续观察 / 毫秒', 5000, 0, 600000], ['max_age_ms', '结果有效期 / 毫秒（至少间隔 + 超时）', 20000, 125, 3600000]]) { const input = field(grid, `health_${key}`, label, spec?.[key] ?? fallback, 'number'); input.min = min; input.max = max; numbers[key] = input; }
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
  const panelHealth = panel('目标观测与选路', 'TCP 与 UDP 独立判断；同优先级按规则的均衡策略分配，低优先级目标作为候选后备。已有 TCP 不会因单次健康状态变化被强制迁移。');
  const kinds = { tcp_connect: '传输建立', tcp_exchange: 'TCP 响应前缀', udp_exchange: 'UDP 完整回复' };
  const statuses = { unknown: '尚未确认', healthy: '探测通过', unhealthy: '已摘除', recovering: '恢复观察', stale: '结果过期' };
  const reasons = { eligible: '参与优先池', standby: '后备候选', unknown: '等待探测确认', unhealthy: '故障排除', recovering: '等待持续成功', stale: '等待新结果', at_capacity: '会话已满', expired: '规则已到期' };
  const errors = { dns: '域名解析失败', transport: '连接、握手或路径检查失败', timeout: '探测超时', io: '收发失败', unexpected_response: '回复不符或提前关闭', expired: '规则已到期' };
  const info = el('div', undefined, 'panel-body'); info.append(el('p', `最近节点回报：${timestamp(snapshot.last_seen_ms)} · ${snapshot.reports.length} / ${snapshot.expected_endpoints} 个配置端点有记录 · 当前探测 ${snapshot.active_probes} 个`)); if (snapshot.apply_error) info.append(el('p', `配置应用失败：${snapshot.apply_error}`, 'error')); panelHealth.append(info);
  if (!snapshot.reports.length) panelHealth.append(empty('暂无目标探测结果', snapshot.expected_endpoints ? '节点尚未上报这些端点的结果，不能视为健康。' : '在规则编辑器启用健康探测，填写对应业务的成功条件。'));
  else panelHealth.append(table(['规则 / 目标', '端口 / 成功条件', '观测状态', '选路原因', '优先级 / 会话', '耗时 EWMA', '结果年龄', '连续成功 / 失败', '诊断'], snapshot.reports.map(r => {
    const diagnostic = el('details'); diagnostic.append(el('summary', r.last_error ? errors[r.last_error] : '查看探测统计'), el('p', `完成 ${r.completed_checks} 次，成功 ${r.successful_checks} 次`), el('p', `源节点探测应用量：发送 ${bytes(r.probe_sent_bytes)} / 接收 ${bytes(r.probe_received_bytes)}`), el('p', `节点记录时间：${timestamp(r.checked_at_ms)}`));
    return [namedCell(snapshot.rule_names?.[r.rule_id] || r.rule_id, r.target_address), `${r.listen_port} / ${kinds[r.probe_kind]}`, badge(statuses[r.status], r.eligible ? 'green' : 'orange'), reasons[r.selection_reason] || r.selection_reason, `${r.priority} / ${r.active_sessions} / ${r.max_sessions ?? '不限'}`, r.latency_ewma_us === null ? '—' : `${(r.latency_ewma_us / 1000).toFixed(2)} ms`, r.sample_age_ms === null ? '—' : `${(r.sample_age_ms / 1000).toFixed(1)} / ${(r.max_age_ms / 1000).toFixed(1)} s`, `${r.consecutive_successes} / ${r.consecutive_failures}`, diagnostic];
  })));
  $('#content').replaceChildren(toolbar, panelHealth);
}
