import { t as translate, msg, localize, getLanguage, setupLanguageSwitcher, eventMessage } from '/assets/i18n.js';
import { createConsoleUI, canVisit, parseRoute } from '/assets/console-ui.js';
import { serviceKind, splitEndpoint, clientEndpoint, applicationState, buildForwardingPath, shadowsocksPath, shadowsocksClientProfile, forwardingDiagram, forwardingPathDiagram, forwardingPathRoots } from '/assets/workflows.js';
const $ = (s, root = document) => root.querySelector(s);
const state = { token: sessionStorage.getItem('relay-session'), actor: null, view: 'overview', overviewFilter: '', nodes: [], usage: [], nodeFilter: {}, selectedNodes: new Set(), selectedNode: null, dnsZone: null, config: null, busy: false };
const titles = localize({ overview: '运行总览', nodes: '节点管理', rules: '节点规则', topology: '转发路径', health: '目标健康', usage: '流量账本', subscriptions: '客户端订阅', dns: 'DNS 管理', announcements: '公告', commerce: '钱包与订单', tickets: '工单', templates: '模板库', budgets: '共享额度', users: '用户与权限', account: '账户安全', audit: '操作审计', alerts: '告警通知', recovery: '恢复保护', capabilities: '功能进度', guide: '使用指南' });
const roleNames = localize({ system_admin: '系统管理员', tenant_admin: '租户管理员', viewer: '只读用户' });
const canWrite = () => state.actor?.role !== 'viewer';
const scopeNames = localize({ read: '读取全部可见数据', 'nodes:write': '节点与配置写入', 'budgets:write': '共享额度写入', 'users:write': '用户与租户写入' });
// Paper is the default; preserve an explicitly saved light or dark choice.
// Switch without per-element color fades, which briefly mix the two themes.
const applyTheme = theme => { const root = document.documentElement; root.classList.add('theme-switching'); root.dataset.theme = theme; $('#theme').setAttribute('aria-pressed', String(theme === 'dark')); try { localStorage.setItem('relay-theme', theme); } catch { /* Theme still works with storage blocked. */ } requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('theme-switching'))); };
let savedTheme; try { savedTheme = localStorage.getItem('relay-theme'); } catch { /* Use the default. */ }
applyTheme(savedTheme === 'dark' ? 'dark' : 'light');
$('#theme').onclick = () => applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notify(message, failure = false) { const n = $('#notification'); n.textContent = message; n.classList.remove('hidden'); n.classList.toggle('failure', failure); }
function button(text, handler, cls = 'subtle') { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', () => Promise.resolve().then(handler).catch(e => notify(e.message, true))); return n; }
function bytes(n) { n = Number(n); if (!n) return '0 B'; const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1); return `${(n / 1024 ** i).toFixed(i ? 2 : 0)} ${u[i]}`; }
function timestamp(n) { return n ? new Date(n).toLocaleString(getLanguage(), { hour12: false }) : translate('尚未回报'); }
function badge(text, color = '') { return el('span', text, `badge ${color}`); }
function online(node) { return node.last_seen_ms && Date.now() - node.last_seen_ms < 30_000; }
async function api(path, options = {}) {
  const response = await fetch(`/api/v1${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}), ...options.headers }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  const text = await response.text(); let result; try { result = JSON.parse(text); } catch { result = { error: text || `HTTP ${response.status}` }; }
  if (!response.ok) { if (response.status === 401 && path !== '/auth/login') loggedOut(); throw Object.assign(new Error(result.error || msg`请求失败 HTTP ${response.status}`), { detail: result }); } return result;
}
setupLanguageSwitcher(() => {
  if (!state.actor) { document.title = translate('Relay · 独立转发平台'); return; }
  $('#identity').textContent = `${state.actor.username} · ${roleNames[state.actor.role]}`;
  $('#view-title').textContent = titles[state.view];
  $('#notification').classList.add('hidden');
  consoleUI.sync(state.view);
  refresh().catch(error => notify(error.message, true));
});
const consoleUI = createConsoleUI({ navigate, getActor: () => state.actor, getView: () => state.view, el, button, modal, titles });
function loggedOut() { consoleUI.reset(); state.view = 'overview'; state.token = null; state.actor = null; state.nodes = []; state.nodeFilter = {}; state.selectedNodes.clear(); sessionStorage.removeItem('relay-session'); resetSecondFactor(); $('#application').classList.add('hidden'); $('#login-screen').classList.remove('hidden'); $('#dialog').close(); state.config = null; state.selectedNode = null; $('#content').replaceChildren(); $('#identity').textContent = ''; $('#status-pill').textContent = ''; document.title = translate('Relay · 独立转发平台'); window.scrollTo({ top: 0 }); $('#login-form [name=username]').focus(); }
function modal(title, content) { $('#dialog-title').textContent = title; $('#dialog-body').replaceChildren(content); $('#dialog').showModal(); $('#dialog').scrollTop = 0; }
// Native prompt/confirm is unavailable in some embedded browsers. Keep all
// decisions in accessible panel dialogs, including a safe cancel/escape path.
function panelQuestion(message, initial, promptMode) {
  return new Promise(resolve => {
    const dialog = $('#dialog'), form = el('form'); let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true; dialog.removeEventListener('close', cancelled);
      dialog.close(); resolve(value);
    };
    const cancelled = () => { if (!dialog.open) finish(promptMode ? null : false); };
    dialog.addEventListener('close', cancelled);
    let input;
    if (promptMode) input = field(form, 'answer', message, initial || '', 'text', false);
    else form.append(el('p', message, 'workflow-callout'));
    submit(form, promptMode ? translate('继续') : translate('确认操作'), () => finish(promptMode ? input.value : true));
    modal(promptMode ? translate('输入信息') : translate('确认操作'), form);
    if (input) input.focus();
  });
}
const confirmAction = message => panelQuestion(message, '', false);
const promptValue = (message, initial = '') => panelQuestion(message, initial, true);
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
function submit(form, text, handler) { const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('取消'), () => $('#dialog').close())); const save = el('button', text, 'primary'); save.type = 'submit'; actions.append(save); form.append(actions); const error = el('p', undefined, 'error'); error.setAttribute('role', 'alert'); form.append(error); form.onsubmit = async e => { e.preventDefault(); save.disabled = true; error.textContent = ''; try { await handler(new FormData(form)); } catch (err) { error.textContent = err.message; } finally { save.disabled = false; } }; }
function number(data, key) { const raw = data.get(key); if (raw === '' || raw === null) return null; const n = Number(raw); if (!Number.isSafeInteger(n) || n < 0) throw new Error(msg`${key} 必须为安全范围内的非负整数`); return n; }
function applicationBadge(node) {
  const labels = localize({ not_enrolled: '等待安装 Agent', offline: '节点离线 · 状态未确认', paused: '节点已暂停', expired: '节点已到期', rejected: '应用失败 · 旧配置可能仍在运行', pending: '等待节点应用', applied: '配置已确认 · 业务待验证' });
  const status = applicationState(node);
  return badge(labels[status], status === 'applied' ? 'green' : status === 'rejected' ? 'red' : 'orange');
}
function sectionVisible(part, visible) {
  part.classList.toggle('hidden', !visible);
  part.querySelectorAll('input, select, textarea').forEach(input => {
    if (!visible) { input.dataset.sectionDisabled ??= String(input.disabled); input.disabled = true; }
    else if (input.dataset.sectionDisabled !== undefined) { input.disabled = input.dataset.sectionDisabled === 'true'; delete input.dataset.sectionDisabled; }
  });
}
function websocketEditor(id, spec, inbound, defaultHost = () => '') {
  const box = el('details'); box.open = !!spec; box.append(el('summary', inbound ? translate('入口 WebSocket / WSS 隧道') : translate('出口 WebSocket / WSS 隧道')));
  const mode = select(box, `${id}-mode`, translate('WebSocket 封装'), [['off', translate('关闭')], ['on', translate('启用 · TCP 流隧道')]], spec ? 'on' : 'off');
  const fields = el('div', undefined, 'form-grid');
  const path = field(fields, `${id}-path`, translate('路径（含可选查询参数，须与对端完全一致）'), spec?.path || '/relay'); path.maxLength = 1024;
  const host = field(fields, `${id}-host`, inbound ? translate('允许的 Host（留空不限，可带端口）') : translate('HTTP Host（可带端口，与 TLS 服务名分别配置）'), spec?.host || (inbound ? '' : defaultHost()), 'text', !inbound); host.maxLength = 255;
  const origins = inbound ? textarea(fields, `${id}-origins`, translate('允许的浏览器 Origin（每行一个，留空拒绝携带 Origin 的连接）'), (spec?.allowed_origins || []).join('\n')) : field(fields, `${id}-origin`, translate('发送的 Origin（节点连接通常留空）'), spec?.origin || '', 'text', false);
  if (!inbound) origins.maxLength = 512;
  function show() { const enabled = mode.value === 'on'; fields.classList.toggle('hidden', !enabled); fields.querySelectorAll('input, textarea').forEach(input => { input.disabled = !enabled; }); if (enabled && !inbound && !host.value) host.value = defaultHost(); }
  mode.addEventListener('change', show); show();
  box.append(fields, el('p', translate('两端使用 relay-stream-v1 子协议。启用对应 TLS 后即为 WSS；只支持 TCP，不承载 UDP。Origin 不是登录凭据，未携带 Origin 的节点连接仍按来源与证书策略检查。'), 'fine'));
  return { box, read: () => mode.value === 'off' ? null : { path: path.value.trim(), host: host.value.trim() || null, ...(inbound ? { allowed_origins: origins.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean) } : { origin: origins.value.trim() || null }) } };
}
function targetEditor(form, targets, topology, sourceTenant, currentRule, multipathPaths, multipathMode) {
  const container = el('div'), rows = []; let serial = 0, changed = () => {};
  function add(target = { address: '', weight: 1 }, path = {}) {
    if (rows.length >= 32) return;
    const id = serial++, box = el('fieldset', undefined, 'target-editor'), grid = el('div', undefined, 'form-grid');
    const options = el('details'), tuning = el('div', undefined, 'form-grid');
    options.append(el('summary', translate('目标高级选项：均衡、TLS 与传输')));
    options.open = !!(target.tls || target.proxy_protocol || target.websocket || target.draining || multipathPaths);
    box.append(el('legend', translate('转发目标')));
    const address = field(grid, `target-address-${id}`, translate('目标地址 / host:port'), target.address); address.placeholder = '203.0.113.10:443';
    const endpoints = (topology?.configs || []).flatMap(config => config.rules.filter(rule => rule.advertise && rule.tenant_id === sourceTenant && rule.id !== currentRule).map(rule => ({ key: `${config.node_id}/${rule.id}`, config, rule })));
    const selected = target.via ? `${target.via.node_id}/${target.via.rule_id}` : '';
    const choices = [['', translate('外部目标 · 手动输入地址')], ...endpoints.map(item => [item.key, `${topology.nodes.find(node => node.id === item.config.node_id)?.name || item.config.node_id} → ${item.rule.name}`])];
    if (selected && !choices.some(([key]) => key === selected)) choices.push([selected, translate('当前引用暂不可选择 · 保留原配置')]);
    const via = select(grid, `target-via-${id}`, translate('已有下一跳规则（可选）'), choices, selected);
    function chooseEndpoint(update) { const endpoint = endpoints.find(item => item.key === via.value); address.readOnly = !!via.value && !endpoint?.rule.inbound_multipath; if (update && endpoint) address.value = endpoint.rule.advertise; }
    via.addEventListener('change', () => chooseEndpoint(true)); chooseEndpoint(false);
    const weight = field(tuning, `target-weight-${id}`, translate('权重'), target.weight, 'number'); weight.min = 1; weight.max = 1000;
    const priority = field(tuning, `target-priority-${id}`, translate('优先级（越小越优先，同级按均衡策略）'), target.priority ?? 0, 'number'); priority.min = 0; priority.max = 65535;
    const draining = select(tuning, `target-draining-${id}`, translate('维护排空（新会话优先走其他目标，已有会话保持）'), [['off', translate('正常使用')], ['on', translate('维护排空')]], target.draining ? 'on' : 'off');
    const maximum = field(tuning, `target-max-${id}`, translate('目标会话上限（TCP + UDP，留空不限）'), target.max_sessions, 'number', false); maximum.min = 1; maximum.max = 1000000;
    const prewarm = field(tuning, `target-prewarm-${id}`, translate('预热连接数（提前建好、待用的 TCP 连接，留空关闭；需启用 PROXY）'), target.prewarm, 'number', false); prewarm.min = 1; prewarm.max = 32;
    const mode = select(tuning, `target-mode-${id}`, translate('连接目标的安全方式'), [['plain', translate('普通 TCP / UDP')], ['tls', translate('TLS（验证目标证书）')]], target.tls ? 'tls' : 'plain'); box.append(grid); options.append(tuning);
    const secure = el('div', undefined, 'form-grid');
    const name = field(secure, `target-server-name-${id}`, translate('证书中的服务名或 IP'), target.tls?.server_name || '', 'text', false);
    const ca = field(secure, `target-ca-${id}`, translate('CA 编号（留空使用公共 CA）'), target.tls?.ca || '', 'text', false);
    const identity = field(secure, `target-identity-${id}`, translate('客户端证书编号（双向认证时填写）'), target.tls?.identity || '', 'text', false);
    const proxyFields = el('div', undefined, 'form-grid');
    const proxyMode = select(proxyFields, `target-proxy-${id}`, translate('向目标传递原始地址（PROXY protocol）'), [['off', translate('关闭')], ['v1', translate('v1 · TCP 文本报头')], ['v2', translate('v2 · TCP / UDP 二进制报头')]], target.proxy_protocol?.version || 'off');
    const proxyPlacement = select(proxyFields, `target-proxy-placement-${id}`, translate('PROXY 报头位置'), [['before_tls', translate('TLS 之前（普通连接也选此项）')], ['inside_tls', translate('TLS 加密连接内（对端须配置一致）')]], target.proxy_protocol?.placement || 'before_tls');
    const proxyCrc = select(proxyFields, `target-proxy-crc-${id}`, translate('v2 报头校验和'), [['off', translate('不附加')], ['on', translate('附加 CRC32C')]], target.proxy_protocol?.checksum ? 'on' : 'off');
    function showProxy() { proxyPlacement.disabled = proxyMode.value === 'off'; proxyCrc.disabled = proxyMode.value !== 'v2'; } proxyMode.addEventListener('change', showProxy); showProxy();
    const ws = websocketEditor(`target-ws-${id}`, target.websocket, false, () => address.value.trim());
    const mp = el('fieldset'); mp.append(el('legend', translate('此子流的方向与出口')));
    const up = field(mp, 'mp-up-' + id, translate('上行权重（0 不发送上行数据）'), path.upload_weight ?? 1, 'number');
    const down = field(mp, 'mp-down-' + id, translate('下行权重（0 不发送下行数据）'), path.download_weight ?? 1, 'number');
    for (const input of [up, down]) { input.min = 0; input.max = 1000; }
    const bindIp = field(mp, 'mp-ip-' + id, translate('子流出口 IP（留空继承规则）'), path.outbound_bind?.ip || '', 'text', false);
    const bindInterface = field(mp, 'mp-iface-' + id, translate('子流出口网卡（留空继承规则）'), path.outbound_bind?.interface || '', 'text', false);
    mp.append(el('p', translate('目标必须汇聚到同一条规则。引用汇聚端口段时，可为各子流填写段内不同端口。不同端口本身不代表独立带宽。'), 'fine'));
    function showMultipath() { const on = !!multipathMode && multipathMode.value !== 'off'; mp.classList.toggle('hidden', !on); mp.querySelectorAll('input').forEach(input => { input.disabled = !on; }); }
    multipathMode?.addEventListener('change', showMultipath); showMultipath();
    const row = { box, address, via, weight, priority, draining, maximum, prewarm, mode, name, ca, identity, proxyMode, proxyPlacement, proxyCrc, ws, up, down, bindIp, bindInterface }; rows.push(row);
    function showSecurity() { const enabled = mode.value === 'tls'; secure.classList.toggle('hidden', !enabled); name.required = enabled; [name, ca, identity].forEach(input => { input.disabled = !enabled; }); }
    mode.onchange = showSecurity; showSecurity(); options.append(secure, proxyFields, ws.box, mp); box.append(options, button(translate('移除此目标'), () => { multipathMode?.removeEventListener('change', showMultipath); rows.splice(rows.indexOf(row), 1); box.remove(); changed(); }, 'table-action danger')); container.append(box); changed();
  }
  targets.forEach((target, index) => add(target, multipathPaths?.[index])); form.append(container, button(translate('＋ 添加目标'), () => add()));
  const read = () => { if (!rows.length) throw new Error(translate('至少保留一个转发目标')); return rows.map(row => {
    const target = { address: row.address.value.trim(), weight: Number(row.weight.value), priority: Number(row.priority.value), max_sessions: row.maximum.value === '' ? null : Number(row.maximum.value), ...(row.draining.value === 'on' ? { draining: true } : {}), ...(row.prewarm.value === '' ? {} : { prewarm: Number(row.prewarm.value) }), ...(row.mode.value === 'tls' ? { tls: { server_name: row.name.value.trim(), ca: row.ca.value.trim() || null, identity: row.identity.value.trim() || null } } : {}) };
    if (row.proxyMode.value !== 'off') {
      if (row.proxyPlacement.value === 'inside_tls' && row.mode.value !== 'tls') throw new Error(translate('将 PROXY 放入加密连接前，请启用目标 TLS'));
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
  read.preview = () => rows.map(row => ({ address: row.address.value.trim(), weight: Number(row.weight.value), priority: Number(row.priority.value), draining: row.draining.value === 'on',
    ...(row.mode.value === 'tls' ? { tls: {} } : {}),
    ...(row.via.value ? { via: { node_id: row.via.value.split('/')[0], rule_id: row.via.value.split('/')[1] } } : {}),
    ...(row.ws.read() ? { websocket: {} } : {}),
  }));
  read.onchange = callback => { changed = callback; };
  return read;
}

function multipathEditor(form, rule) {
  const box = el('details'); box.open = !!(rule.inbound_multipath || rule.outbound_multipath);
  box.append(el('summary', translate('单连接多路径聚合')));
  box.append(el('p', translate('仅支持 TCP，两端每条子流都需要双向 TLS。可叠加 WSS。聚合规则更改会终止已有连接；内核 MPTCP 与此功能分别配置和验收。'), 'fine'));
  function limits(parent, prefix, spec) {
    const inputs = {};
    for (const [key, label, fallback, min, max] of [
      ['window_frames', translate('发送 / 重排窗口帧数（每帧最多 16 KiB）'), 64, 4, 256],
      ['max_sessions', translate('聚合会话上限'), 64, 1, 1024],
      ['retransmit_ms', translate('未确认数据重传间隔 / ms'), 500, 50, 10000],
      ['stall_timeout_ms', translate('无确认进展的中止时间 / ms'), 30000, 1000, 120000]
    ]) {
      const input = field(parent, prefix + key, label, spec?.[key] ?? fallback, 'number');
      input.min = min; input.max = max; inputs[key] = input;
    }
    return () => Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, Number(input.value)]));
  }
  const inbound = select(box, 'mp-inbound', translate('接收聚合连接'), [['off', translate('关闭')], ['on', translate('作为汇聚端')]], rule.inbound_multipath ? 'on' : 'off');
  const server = el('fieldset'); server.append(el('legend', translate('汇聚端限制')));
  const serverLimits = limits(server, 'mp-server-', rule.inbound_multipath?.limits);
  const maximum = field(server, 'mp-server-paths', translate('每个连接的子流上限'), rule.inbound_multipath?.max_paths ?? 4, 'number'); maximum.min = 1; maximum.max = 8;
  const replication = select(server, 'mp-server-replication', translate('允许上游使用复制模式'), [['no', translate('不允许')], ['yes', translate('允许')]], rule.inbound_multipath?.allow_replication ? 'yes' : 'no');
  const mode = select(box, 'mp-outbound', translate('连接目标的聚合方式'), [['off', translate('关闭')], ['stripe', translate('分片：跨可用路径传输')], ['replicate', translate('复制：向所有可用路径发送')]], rule.outbound_multipath?.mode || 'off');
  const client = el('fieldset'); client.append(el('legend', translate('发起端限制')));
  const clientLimits = limits(client, 'mp-client-', rule.outbound_multipath?.limits);
  const minimum = field(client, 'mp-client-minimum', translate('建立时最少成功子流数'), rule.outbound_multipath?.min_paths ?? 2, 'number'); minimum.min = 1; minimum.max = 8;
  client.append(el('p', translate('下方每个目标对应一条子流，最多 8 条，均应通往同一汇聚规则。使用每条子流的上下行权重，目标优先级须为 0。运行中路径失效会在剩余可用方向上重传；当前不会自动补建子流。'), 'fine'));
  function show() {
    for (const [section, on] of [[server, inbound.value === 'on'], [client, mode.value !== 'off']]) {
      section.classList.toggle('hidden', !on); section.querySelectorAll('input, select').forEach(input => { input.disabled = !on; });
    }
  }
  inbound.addEventListener('change', show); mode.addEventListener('change', show);
  box.append(server, client, el('p', translate('单侧规则发送与重排窗口预留合计上限 256 MiB，节点合计上限 512 MiB；另有有界读写队列及操作系统缓冲。复制和重传统计在节点运行诊断中查看，应用配额按重组后的数据计算。'), 'fine'));
  form.append(box); show();
  return { mode, read(paths) {
    return {
      ...(inbound.value === 'on' ? { inbound_multipath: { limits: serverLimits(), max_paths: Number(maximum.value), allow_replication: replication.value === 'yes' } } : {}),
      ...(mode.value !== 'off' ? { outbound_multipath: { limits: clientLimits(), mode: mode.value, min_paths: Number(minimum.value), paths } } : {})
    };
  } };
}

$('#login-form').onsubmit = async event => { event.preventDefault(); const form = event.currentTarget, b = $('button', form), factor = $('#second-factor-field'); b.disabled = true; $('#login-error').textContent = ''; try { const f = new FormData(form); const result = await api('/auth/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password'), ...(factor.classList.contains('hidden') ? {} : { second_factor: String(f.get('second_factor')).trim() }) } }); state.token = result.token; state.actor = result.user; sessionStorage.setItem('relay-session', result.token); $('[name=password]', form).value = ''; resetSecondFactor(); await enter(); } catch (error) { const code = $('input', factor); if (error.detail?.second_factor_required) { factor.classList.remove('hidden'); code.required = true; code.focus(); $('#login-error').textContent = translate('此账号已启用两步验证，请输入身份验证器中的验证码。'); } else { code.value = ''; $('#login-error').textContent = error.message; } } finally { b.disabled = false; } };
function resetSecondFactor() { const factor = $('#second-factor-field'), code = $('input', factor); factor.classList.add('hidden'); code.required = false; code.value = ''; }
document.querySelectorAll('[data-logout]').forEach(b => { b.onclick = async () => { try { await api('/auth/logout', { method: 'POST' }); } finally { loggedOut(); } }; });
$('#refresh').onclick = () => refresh().catch(e => notify(e.message, true));
document.querySelectorAll('[data-view]').forEach(n => n.addEventListener('click', () => navigate(n.dataset.view)));
async function enter() {
  $('#login-screen').classList.add('hidden'); $('#application').classList.remove('hidden');
  $('#identity').textContent = `${state.actor.username} · ${roleNames[state.actor.role]}`;
  document.querySelectorAll('.admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role !== 'system_admin'));
  document.querySelectorAll('.tenant-admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role === 'viewer'));
  const route = parseRoute(location.hash); await navigate(route.view, { topic: route.topic, history: false });
}
async function navigate(view, options = {}) {
  if (!state.actor) return;
  if (!canVisit(view, state.actor)) view = 'overview';
  const topic = parseRoute(`#guide/${options.topic || 'quickstart'}`).topic;
  const hash = `#${view}${view === 'guide' ? '/' + topic : ''}`;
  if (location.hash !== hash) window.history[options.history === false ? 'replaceState' : 'pushState'](null, '', hash);
  state.view = view; $('#notification').classList.add('hidden');
  document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  $('#view-title').textContent = titles[view]; $('#status-pill').classList.toggle('hidden', view !== 'overview');
  consoleUI.sync(view); $('#content').replaceChildren(el('p', translate('正在加载…'), 'loading-state')); window.scrollTo({ top: 0 });
  $('#main-content').focus({ preventScroll: true });
  try { await refresh(); } catch (e) { notify(e.message, true); }
}
async function renderGuide() { consoleUI.renderGuide($('#content')); }
async function refresh() {
  if (!state.actor || state.busy) return; const requestedView = state.view, requestedNode = state.selectedNode, requestedHash = location.hash, requestedLanguage = getLanguage(); state.busy = true; $('#refresh').disabled = true;
  try { await ({ overview: renderOverview, nodes: renderNodes, rules: renderRules, usage: renderUsage, subscriptions: renderSubscriptions, dns: renderDns, announcements: renderAnnouncements, commerce: renderCommerce, tickets: renderTickets, templates: renderTemplates, budgets: renderBudgets, users: renderUsers, account: renderAccount, audit: renderAudit, alerts: renderAlerts, recovery: renderRecovery, topology: renderTopology, health: renderHealth, capabilities: renderCapabilities, guide: renderGuide })[state.view](); $('#refreshed').textContent = msg`更新于 ${new Date().toLocaleTimeString(getLanguage(), { hour12: false })}`; }
  catch (error) { if (state.actor && state.view === requestedView && location.hash === requestedHash && $('#content .loading-state')) $('#content').replaceChildren(empty(translate('页面暂时无法加载'), error.message, button(translate('重新加载'), () => { $('#notification').classList.add('hidden'); return refresh(); }, 'primary'))); throw error; }
  finally { state.busy = false; $('#refresh').disabled = false; if (state.actor && (getLanguage() !== requestedLanguage || state.view !== requestedView || location.hash !== requestedHash || (['rules', 'health'].includes(requestedView) && requestedNode !== state.selectedNode))) queueMicrotask(() => refresh().catch(e => notify(e.message, true))); }
}

// Overview: per-node samples from /telemetry over the last 15 minutes, drawn as
// sparklines; the chain graph comes from declared `via` targets in /topology.
const SPAN_MS = 15 * 60_000, BINS = 60, BIN_MS = SPAN_MS / BINS;
function svg(tag, attrs = {}, cls) { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (cls) n.setAttribute('class', cls); return n; }
function bits(bytesPerSecond) { let n = bytesPerSecond * 8, i = 0; const u = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return `${n.toFixed(i === 0 || n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${u[i]}`; }
function millis(us) { if (us == null) return '—'; const n = us / 1000; return `${n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)} ms`; }
function ago(at, now) { const s = Math.max(0, Math.round((now - at) / 1000)); return s < 60 ? msg`${s} 秒前` : s < 3600 ? msg`${Math.floor(s / 60)} 分钟前` : msg`${Math.floor(s / 3600)} 小时前`; }
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
  if (!node.enrolled) return [translate('待注册'), '', 'idle'];
  if (!online(node)) return [translate('离线'), 'red', 'down'];
  if (node.lifecycle && node.lifecycle !== 'active') return [translate('已暂停'), 'orange', 'partial'];
  if (node.apply_error) return [translate('配置异常'), 'orange', 'partial'];
  if (latest && latest.healthy_targets < latest.probed_targets) return [translate('降级'), 'orange', 'partial'];
  if (node.applied_revision !== node.desired_revision) return [translate('等待节点应用'), 'orange', 'partial'];
  return [translate('控制在线'), 'green', 'up'];
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
    kpi(translate('实时吞吐'), live.length ? bits(live.reduce((s, r) => s + (r.rate ?? 0), 0)) : '—', msg`多跳流量逐跳计入 · 峰值 ${bits(peak)}`, spark(rate, 'accent')),
    kpi(translate('活跃会话'), String(live.reduce((s, r) => s + r.latest.active_sessions, 0)), translate('TCP 连接 + UDP 会话'), spark(sessions, 'blue')),
    kpi(translate('探测往返中位数'), millis(median(live.map(r => r.latest.probe_latency_us))), translate('节点到目标的探测，不含客户端一段'), spark(latency, 'violet')),
    kpi(translate('节点在线'), `${live.length} / ${enrolled.length}`, probed ? msg`目标可用 ${healthy} / ${probed}` : translate('尚无目标探测'), fleet));
  const events = telemetry.events.slice().reverse(), attention = rows.filter(r => r.status[2] === 'down' || r.status[2] === 'partial').length;
  const pill = $('#status-pill'); pill.className = `status-pill ${rows.some(r => r.status[2] === 'down') ? 'red' : attention ? 'orange' : 'green'}`;
  pill.textContent = !enrolled.length ? translate('等待节点注册') : !live.length ? translate('等待节点回报') : attention ? msg`${attention} 个节点需要关注` : msg`控制在线 · ${live.length} 个节点`;
  if (!live.length) pill.className = 'status-pill neutral';
  const graphPanel = panel(translate('转发链路'), translate('按规则声明的下一跳绘制；连线颜色为该段目标的最新探测结果，点击节点查看规则。'), legend());
  graphPanel.classList.add('graph-panel'); graphPanel.append(chainGraph(topology, byId));
  const incidents = panel(translate('事件'), msg`最近 24 小时 · 共 ${events.length} 条`, events.length ? button(translate('全部事件'), () => modal(translate('全部事件'), eventTable(events, byId, now)), 'table-action') : undefined);
  incidents.classList.add('incident-panel');
  const list = el('ol', undefined, 'incidents');
  if (!events.length) list.append(el('li', translate('最近 24 小时没有目标故障、配置拒绝或节点离线。'), 'incident-empty'));
  events.slice(0, 6).forEach(e => { const item = el('li', undefined, `incident ${e.severity}`), text = el('div'); text.append(Object.assign(el('div', eventMessage(e), 'incident-message'), { title: e.message }), el('div', byId.get(e.node_id)?.name || e.node_id, 'subline')); item.append(el('i'), text, el('time', ago(e.at_ms, now))); list.append(item); });
  incidents.append(list);
  const middle = el('div', undefined, 'overview-grid'); middle.append(graphPanel, incidents);
  const search = el('input'); search.type = 'search'; search.placeholder = translate('按名称、ID 或分组筛选'); search.value = state.overviewFilter || ''; search.setAttribute('aria-label', translate('筛选节点'));
  const nodePanel = panel(translate('中转节点'), msg`${enrolled.length} 个已注册 · 采样来自每次节点回报`, search);
  const t = table([translate('节点'), translate('状态'), translate('探测往返'), translate('吞吐（15 分钟）'), 'CPU', translate('内存'), translate('会话'), translate('配置修订'), translate('最近回报'), ''], rows.map(r => {
    const { node, latest } = r, memory = latest?.memory_total_bytes ? 1 - latest.memory_available_bytes / latest.memory_total_bytes : null;
    const throughput = el('div', undefined, 'throughput'); throughput.append(spark(r.series.rate, 'accent'), el('span', r.rate == null ? '—' : bits(r.rate)));
    return [namedCell(node.name, node.profile?.settings.group || node.id.slice(0, 8)), badge(r.status[0], r.status[1]), latest ? millis(latest.probe_latency_us) : '—', throughput,
      latest?.cpu_percent != null ? meter(latest.cpu_percent / 100, `${latest.cpu_percent.toFixed(0)}%`) : '—',
      memory != null ? meter(memory, `${bytes(latest.memory_total_bytes - latest.memory_available_bytes)} / ${bytes(latest.memory_total_bytes)}`) : '—',
      latest ? (node.stats?.prewarmed_connections ? namedCell(String(latest.active_sessions), msg`预热接手 ${node.stats.prewarmed_connections}`) : String(latest.active_sessions)) : '—', node.apply_error ? namedCell(`${node.applied_revision} / ${node.desired_revision}`, translate('应用失败')) : `${node.applied_revision} / ${node.desired_revision}`,
      node.last_seen_ms ? ago(node.last_seen_ms, now) : translate('尚未回报'), button(translate('规则 →'), async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action')];
  }));
  const trs = [...t.querySelectorAll('tbody tr')], keys = rows.map(r => [r.node.name, r.node.id, r.node.profile?.settings.group || ''].join(' ').toLowerCase());
  const filter = () => { state.overviewFilter = search.value; const q = search.value.trim().toLowerCase(); trs.forEach((tr, i) => tr.classList.toggle('hidden', !!q && !keys[i].includes(q))); };
  search.addEventListener('input', filter); filter();
  nodePanel.append(rows.length ? t : empty(translate('还没有节点'), translate('注册节点并启动 Agent 后，这里会显示实时吞吐、资源和事件。'), button(translate('前往节点管理'), () => navigate('nodes'))));
  if (state.view === 'overview') $('#content').replaceChildren(kpis, middle, nodePanel);
}
function legend() { const n = el('div', undefined, 'legend'); for (const [text, cls] of [[translate('正常'), 'up'], [translate('部分可用'), 'partial'], [translate('不可用'), 'down'], [translate('未探测'), 'unknown']]) { const item = el('span'); item.append(el('i', undefined, cls), text); n.append(item); } return n; }
function eventTable(events, byId, now) {
  const names = { info: translate('信息'), recovered: translate('恢复'), warning: translate('警告'), critical: translate('严重') }, colors = { recovered: 'green', warning: 'orange', critical: 'red' };
  return table([translate('时间'), translate('节点'), translate('级别'), translate('内容')], events.map(e => [`${timestamp(e.at_ms)} · ${ago(e.at_ms, now)}`, byId.get(e.node_id)?.name || e.node_id, badge(names[e.severity] || e.severity, colors[e.severity]), eventMessage(e)]));
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
    if (serviceKind(rule) !== 'forward') addEdge(config.node_id, 'sink', []);
    rule.targets.forEach((target, i) => { if (target.via) referenced.add(`${target.via.node_id}/${target.via.rule_id}`); addEdge(config.node_id, target.via ? target.via.node_id : 'sink', health.get(`${config.node_id}/${rule.id}/${i}`) || []); });
  }
  for (const config of topology.configs || []) if (config.rules.some(rule => rule.enabled && !referenced.has(`${config.node_id}/${rule.id}`))) addEdge('client', config.node_id, []);
  const ids = topology.nodes.filter(n => n.enrolled || ruleCount.has(n.id)).map(n => n.id), depth = new Map();
  const depthOf = (id, seen = new Set()) => { if (depth.has(id)) return depth.get(id); if (seen.has(id)) return 1; seen.add(id); const parents = [...edges.values()].filter(e => e.to === id && e.from !== 'client').map(e => depthOf(e.from, seen)); const d = parents.length ? Math.max(...parents) + 1 : 1; depth.set(id, d); return d; };
  ids.forEach(id => depthOf(id));
  const last = Math.max(1, ...depth.values()) + 1, columns = Array.from({ length: last + 1 }, () => []);
  ids.forEach(id => columns[depth.get(id)].push(id)); if ([...edges.values()].some(e => e.from === 'client')) columns[0].push('client'); if ([...edges.values()].some(e => e.to === 'sink')) columns[last].push('sink');
  // Lay out at the panel's current pixel size so text stays at its CSS size; the viewBox rescales between refreshes.
  const beside = window.innerWidth > 1390, W = Math.max(640, ($('#content').clientWidth || 1100) - (beside ? 316 : 0) - 36);
  // Client and target terminals are narrow; node columns share the width between them.
  const tw = 80, left = 12 + (columns[0].length ? tw + 40 : 0), right = W - 12 - (columns[last].length ? tw + 40 : 0), step = (right - left) / (last - 1);
  const bw = Math.max(112, Math.min(176, step - 44)), bh = 52, gap = 84, H = Math.max(190, Math.max(...columns.map(c => c.length)) * gap + 60), pos = new Map(), labels = [];
  columns.forEach((column, c) => column.forEach((id, r) => pos.set(id, [c === 0 ? 12 : c === last ? W - 12 - tw : left + (c - 1) * step + (step - bw) / 2, (H - column.length * gap) / 2 + r * gap + (gap - bh) / 2, c === 0 || c === last ? tw : bw])));
  const box = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': translate('转发链路图') }, 'chain');
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
      const title = svg('text', { x: w / 2, y: bh / 2 + 4, 'text-anchor': 'middle' }); title.textContent = id === 'client' ? translate('客户端') : translate('目标服务'); g.append(title);
    } else {
      const status = node ? overviewStatus(node, null)[2] : 'idle';
      g.setAttribute('class', `chain-node ${status}`); g.setAttribute('tabindex', '0'); g.setAttribute('role', 'button'); g.setAttribute('aria-label', msg`${node?.name || id} 的规则`);
      const open = async () => { state.selectedNode = id; await navigate('rules'); };
      g.addEventListener('click', open); g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      g.append(svg('rect', { width: w, height: bh, rx: 9 }), svg('circle', { cx: 14, cy: 19, r: 4.5 }, 'dot'));
      const full = node?.name || id, fit = Math.floor((w - 32) / 7.4), name = svg('text', { x: 26, y: 23 }, 'name'), sub = svg('text', { x: 14, y: 41 }, 'sub');
      name.textContent = full.length > fit ? full.slice(0, fit - 1) + '…' : full; name.append(svg('title')); name.lastChild.textContent = full; sub.textContent = !node?.enrolled ? translate('待注册') : !online(node) ? translate('离线') : msg`${ruleCount.get(id) || 0} 条规则 · ${node.stats.active_tcp + node.stats.active_udp} 会话`;
      g.append(name, sub);
    }
    box.append(g);
  }
  box.append(...labels);
  const wrap = el('div', undefined, 'chain-wrap'); wrap.append(box);
  if (!ids.length) return empty(translate('还没有节点'), translate('注册节点并配置规则后显示转发链路。'));
  return wrap;
}

async function renderNodes() {
  const query = new URLSearchParams(state.nodeFilter).toString();
  const [nodes, usage, topology] = await Promise.all([api('/nodes' + (query ? '?' + query : '')), api('/usage'), api('/topology').catch(() => null)]); state.nodes = nodes; state.usage = usage;
  state.inbound = {}; for (const c of topology?.configs || []) for (const r of c.rules) for (const t of r.targets) if (t.via) { const n = state.inbound[t.via.node_id] ||= { total: 0, draining: 0 }; n.total++; if (t.draining) n.draining++; }
  state.selectedNodes = new Set([...state.selectedNodes].filter(id => nodes.some(n => n.id === id)));
  const metric = el('div', undefined, 'metrics');
  [[translate('节点数量'), nodes.length, query ? translate('当前筛选范围') : translate('当前账号可见的节点')], [translate('控制在线'), nodes.filter(online).length, translate('最近 30 秒收到心跳')], [translate('活跃连接'), nodes.filter(online).reduce((s,n) => s+n.stats.active_tcp+n.stats.active_udp,0), translate('当前范围的 TCP + UDP 会话')], [translate('近期上报负载'), bytes(usage.reduce((s,u) => s+u.upload_bytes+u.download_bytes,0)), translate('全部可见节点最近 2,000 个计量周期')]].forEach(([title,value,foot]) => { const n=el('div',undefined,'metric'); n.append(el('div',title,'metric-label'),el('div',String(value),'metric-value'),el('div',foot,'metric-foot'));metric.append(n); });
  const controls=el('div',undefined,'toolbar node-tools'); controls.append(button(translate('筛选节点'),filterNodes));
  if(query) controls.append(button(translate('清除筛选'),async()=>{state.nodeFilter={};state.selectedNodes.clear();await renderNodes();}));
  if(canWrite()) controls.append(button(translate('选择 / 取消本页'),async()=>{if(nodes.every(n=>state.selectedNodes.has(n.id)))state.selectedNodes.clear();else nodes.forEach(n=>state.selectedNodes.add(n.id));await renderNodes();}),button(translate('批量编辑已选节点'),batchNodeProfiles),button(translate('＋ 注册节点'),newNode,'primary'));
  const p=panel(translate('节点'),translate('管理资料、运行许可与实际回报分别显示。'),controls); p.classList.add('node-panel');
  if(!nodes.length) p.append(empty(query?translate('没有匹配的节点'):translate('接入你的第一个节点'),query?translate('调整筛选条件后重试。'):translate('注册后启动 Agent，再配置转发。')));
  else p.append(table([translate('选择'),translate('节点 / ID'),translate('类型 / 分组 / 成本'),translate('运行许可 / 到期'),translate('控制连接'),translate('运行保护'),translate('配置修订'),translate('活跃会话'),translate('操作')],nodes.map(node=>{
    let choice='—';if(canWrite()){choice=el('input');choice.className='node-choice';choice.type='checkbox';choice.checked=state.selectedNodes.has(node.id);choice.setAttribute('aria-label',translate('选择 ')+node.name);choice.onchange=()=>choice.checked?state.selectedNodes.add(node.id):state.selectedNodes.delete(node.id);}
    const id=namedCell(node.name,node.id.slice(0,8)+'…');id.title=node.id;
    return [choice,id,nodeInventoryCell(node),nodeLifecycleCell(node),namedCell(node.credential_phase==='revoked'?translate('身份已撤销'):node.credential_phase==='replacement_pending'?translate('等待替换注册'):node.enrolled?online(node)?translate('控制在线'):translate('无近期回报'):translate('待注册'),timestamp(node.last_seen_ms)),nodeLeaseBadge(node),node.apply_error?namedCell(msg`应用失败 · ${node.applied_revision} / ${node.desired_revision}`,node.apply_error):`${node.applied_revision} / ${node.desired_revision}`,nodeSessionsCell(node),nodeActions(node)];
  })));
  if(state.view==='nodes') $('#content').replaceChildren(metric,p);
}
function nodeLeaseBadge(node) {
  const lease = node.lease;
  if (!lease) return badge(translate('未提供'), '');
  if (!lease.policy) return badge(translate('离线模式'), 'orange');
  if (lease.recovery_wait_ms > 0) return badge(translate('恢复等待'), 'orange');
  return badge(lease.active ? translate('有效租约') : translate('未持有'), lease.active ? 'green' : '');
}
function timingRow(label, value) {
  if (!value) return [label, translate('未提供'), '—', '—'];
  return [label, String(value.samples), value.samples ? (value.total_us / value.samples / 1000).toFixed(3) : '—', value.samples ? (value.max_us / 1000).toFixed(3) : '—'];
}
function nodeSessionsCell(node) {
  const text = online(node) ? `${node.stats.active_tcp} TCP / ${node.stats.active_udp} UDP` : '—';
  return state.inbound?.[node.id]?.draining ? namedCell(text, translate('维护中 · 不接新连接')) : text;
}
async function drainNode(node, draining) {
  const inbound = state.inbound[node.id];
  if (!await confirmAction(draining ? msg`「${node.name}」有 ${inbound.total} 个上游目标指向它。排空后，新连接改走其他目标（没有其他可用目标时仍会使用它），已有连接继续直到结束。会话数降到 0 后即可安全重启或升级。` : msg`结束「${node.name}」的维护，上游恢复按原优先级和权重分配新连接？`)) return;
  const result = await api(`/nodes/${node.id}/drain`, { method: 'POST', body: { draining } });
  notify(draining ? msg`已排空：${result.configs.length} 个上游节点发布了新修订。` : msg`已结束维护：${result.configs.length} 个上游节点发布了新修订。`); await renderNodes();
}
function nodeActions(node) {
  const actions = el('div', undefined, 'node-actions');
  const inbound = state.inbound?.[node.id];
  if (canWrite() && inbound?.total) actions.append(button(inbound.draining ? translate('结束维护') : translate('维护排空'), () => drainNode(node, !inbound.draining), 'table-action'));
  actions.append(button(canWrite() ? translate('编辑资料') : translate('查看资料'), () => editNode(node), 'table-action'), button(translate('管理规则 →'), async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action'), button(translate('运行诊断'), () => nodeDiagnostics(node), 'table-action'));
  actions.append(button(translate('节点身份'), () => nodeCredential(node), 'table-action'));
  return actions;
}
async function nodeCredential(node) {
  node = (await api('/nodes')).find(n=>n.id===node.id) || node;
  const status = await api(`/nodes/${node.id}/credential`), body = el('div');
  const phase = status.phase || (node.enrolled ? 'active' : 'not_enrolled');
  body.append(el('p', node.name), table([translate('项目'), translate('状态')], [
    [translate('身份状态'), { active:translate('已绑定'), not_enrolled:translate('待首次注册'), revoked:translate('已撤销'), replacement_pending:translate('等待替换实例注册') }[phase] || phase],
    [translate('当前凭据版本'), status.revision],
    [translate('轮换任务'), status.pending ? translate('等待节点执行') : translate('无待执行任务')],
    [translate('请求时间'), status.pending ? timestamp(status.pending.requested_at_ms) : '—'],
    [translate('上次完成'), status.last_rotation ? timestamp(status.last_rotation.completed_at_ms) : '—']
  ]), el('p', translate('节点自行生成并保存新凭据，控制器确认后旧凭据失效。在线节点自动处理，离线或暂停的节点恢复运行后处理；旧版本 Agent 需要先升级。这里不会显示密钥。'), 'fine'),
  el('p', translate('常规轮换保留配置和运行。紧急撤销会拒绝旧凭据并中断业务；已授执行窗口仍须等待结束，未知流量预留继续保留。'), 'fine'));
  if (status.revocation) body.append(el('p', msg`最近撤销：${timestamp(status.revocation.at_ms)} · ${status.revocation.reason}`, 'fine'));
  if (status.replacement) body.append(el('p', msg`替换票据到期：${timestamp(status.replacement.expires_at_ms)} · ${status.replacement.enrolled_at_ms ? translate('已注册') : translate('尚未使用')}`, 'fine'));
  if (status.blocked_quota_periods?.length) body.append(el('p', translate('以下旧配额周期可能存在未上报消费，替换实例会等待。请停用对应规则，或在规则编辑中明确开始新周期。旧账和共享预算不会清零。'), 'fine'), table([translate('规则'), translate('受保护的旧周期')], status.blocked_quota_periods.map(p => [p.rule_id,p.meter_epoch])));
  if (status.pending) body.append(el('p', msg`任务编号：${status.pending.id}`, 'fine'));
  if (canWrite() && phase === 'active' && !status.pending) {
    const action = button(translate('发起凭据轮换'), async () => {
      action.disabled = true;
      try {
        await api(`/nodes/${node.id}/credential/rotate`, { method: 'POST', body: { expected_revision: status.revision } });
        await nodeCredential(node);
      } finally { action.disabled = false; }
    }, 'primary');
    body.append(action);
  }
  if (canWrite()) {
    body.append(button(phase === 'not_enrolled' ? translate('撤销遗失的注册令牌') : translate('紧急撤销身份'), () => revokeNodeIdentity(node,status), 'danger'));
    if (phase === 'revoked' || phase === 'replacement_pending') body.append(button(translate('签发替换票据'), () => replaceNodeIdentity(node,status), 'primary'));
  }
  body.append(button(translate('刷新状态'), () => nodeCredential(node)));
  modal(translate('节点身份与凭据'), body);
}
function revokeNodeIdentity(node,status) {
  const form = el('form');
  form.append(el('p', msg`撤销「${node.name}」的当前凭据、待执行轮换和注册票据。规则与历史账本保留，无法撤回此动作；恢复运行需要签发新票据。`));
  field(form,'reason',translate('撤销原因（最多 512 字节）'),'','text').maxLength=512;
  const operation = crypto.randomUUID();
  let request = null;
  submit(form,translate('确认撤销身份'),async data=>{
    const reason=String(data.get('reason')).trim();
    if (!request && (!reason || new TextEncoder().encode(reason).length>512 || /[\x00-\x1f\x7f-\x9f]/.test(reason))) throw new Error(translate('请填写不含控制字符、最多 512 字节的撤销原因。'));
    request ||= {operation_id:operation,expected_revision:status.revision,reason};
    await api(`/nodes/${node.id}/credential/revoke`,{method:'POST',body:request});
    await nodeCredential(node);
    notify(translate('撤销操作已确认，请以当前身份状态为准。严格节点按已授期限停止；离线实例需要外部停止。'));
  });
  modal(translate('紧急撤销节点身份'),form);
}
function replaceNodeIdentity(node,status) {
  const form=el('form');
  form.append(el('p',translate('替换实例须使用新的私有状态目录。控制器保留配置和已知账本，不恢复未知消费，也不会提前跳过旧执行窗口。票据只显示在此处，请保存为权限 0600 的文件。')));
  const ttl=field(form,'valid_for_seconds',translate('票据有效秒数'),600,'number');ttl.min=1;ttl.max=86400;
  let offline=null;
  if (!node.lease?.policy) {
    const label=el('label',undefined,'inline-check');offline=el('input');offline.type='checkbox';offline.required=true;label.append(offline,document.createTextNode(translate('我已通过服务器管理渠道停止所有旧离线实例及副本')));form.append(label,el('p',translate('平台不能证明旧离线程序已停止。新身份将启用 30 秒严格租约。'),'fine'));
  }
  const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);
  const enrollment=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
  const operation=crypto.randomUUID();let request=null;
  submit(form,translate('签发一次性替换票据'),async data=>{
    request ||= {operation_id:operation,expected_revision:status.revision,enrollment_token:enrollment,valid_for_seconds:number(data,'valid_for_seconds'),offline_stop_attested:!!offline?.checked,lease_policy:offline?{ttl_ms:30000}:null};
    const result=await api(`/nodes/${node.id}/credential/replace`,{method:'POST',body:request});
    if (result.phase!=='replacement_pending' || result.replacement?.id!==operation || result.replacement.revision!==status.revision+1 || result.replacement.enrolled_at_ms) {
      await nodeCredential(node);
      notify(translate('该签发操作已处理，票据已经使用或被后续操作替代。请查看当前身份状态。'));
      return;
    }
    const content=el('div');content.append(el('p',msg`票据到期：${timestamp(result.replacement.expires_at_ms)}`),el('div',enrollment,'secret-box'),el('pre',`relay agent --controller ${location.origin} --node-id ${node.id} --enrollment-token-file /path/to/replacement.secret --state /var/lib/relay-agent-replacement`),el('p',translate('不要把此命令指向旧状态目录。丢失此票据可重新签发，之前的票据将失效；重试同一请求不会再次更换票据。'),'fine'));
    modal(translate('保存替换票据'),content);
  });
  modal(translate('替换节点身份'),form);
}
function nodeDiagnostics(node) {
  const body = el('div'), stats = node.stats, meter = stats.meter;
  body.append(el('p', msg`${node.name} · 最近回报 ${timestamp(node.last_seen_ms)}`), el('p', online(node) ? translate('以下为最近一次节点采样。') : translate('节点没有近期回报，以下是旧采样。'), 'fine'));
  if (node.lease) {
    const lease = node.lease;
    body.append(table([translate('运行保护'), translate('控制器当前观测')], [
      [translate('策略'), lease.policy ? translate('严格租约 · ') + (lease.policy.ttl_ms / 1000) + translate(' 秒') : translate('离线运行')],
      [translate('所有权代数'), lease.generation], [translate('最近运行编号'), lease.holder_run_id || '—'],
      [translate('服务端剩余保留 / 秒'), (lease.remaining_ms / 1000).toFixed(2)], [translate('恢复等待 / 秒'), (lease.recovery_wait_ms / 1000).toFixed(2)]
    ]), el('p', translate('租约保留不等于业务健康。严格模式失去续租后停止业务，离线模式不提供跨机器互斥。租约到期不会自动退还未知消费的额度。'), 'fine'));
  }
  if (stats.budget_recovery) {
    const recovery = stats.budget_recovery;
    body.append(table([translate('最近额度恢复'), translate('节点确认结果')], [
      [translate('运行编号'), recovery.run_id], [translate('确认时间'), timestamp(recovery.at_ms)], [translate('已核对预留'), recovery.validated_grants],
      [translate('找回未收到的预留'), recovery.recovered_pending_grants], [translate('取消未发放请求'), recovery.cancelled_requests], [translate('恢复后可用预留笔数'), recovery.open_grants]
    ]), el('p', translate('此记录表示开启监听前已核对原状态；不是当前余额，也不能证明旧备份中的未知消费。'), 'fine'));
  }
  if (!meter) body.append(empty(translate('尚无计量诊断'), translate('节点需要支持计量诊断的版本，并完成一次状态上报。')));
  else {
    body.append(table([translate('诊断阶段'), translate('已完成采样数'), translate('平均 / ms'), translate('最大 / ms')], [timingRow(translate('本地计量批次'), meter.admission_batches), timingRow(translate('额度等待片段'), meter.budget_wait)]));
    body.append(table([translate('项目'), translate('最近采样')], [[translate('计量请求（包含重试）'), meter.admission_requests], [translate('计量批次失败'), meter.failed_batches], [translate('正在等待额度的方向 / 会话'), meter.budget_waiting], [translate('额度等待超时'), meter.budget_timeouts], [translate('累计额度等待 / 秒'), (meter.budget_wait.total_us / 1000000).toFixed(3)], [translate('活跃 TCP / UDP / 探测'), `${stats.active_tcp} / ${stats.active_udp} / ${stats.active_probes || 0}`], [translate('HTTP/2 活跃隧道'), stats.active_http2_streams || 0], [translate('MPTCP 观测中的连接'), stats.mptcp?.active_sockets || 0], [translate('MPTCP 协商 / TCP 回退 / 无法确定（累计）'), `${stats.mptcp?.negotiated_total || 0} / ${stats.mptcp?.fallback_total || 0} / ${stats.mptcp?.unknown_total || 0}`]]));
    body.append(el('p', translate('本地计量耗时包括线程池调度、数据库锁等待与事务执行，不是纯磁盘时间。额度等待按每次休眠片段计数，包含被取消的片段；并发等待时间可重叠相加。统计从进程启动累计，不作为用量或额度依据。'), 'fine'));
  }
  if (stats.protocol_gateway) {
    const g = stats.protocol_gateway;
    body.append(el('h3', translate('协议引擎')), table([translate('项目'), translate('最近采样')], [[translate('引擎版本'), g.engine_version], [translate('受管入口'), g.gateways], [translate('进程状态'), g.running ? translate('运行中') : translate('已停止')], [translate('累计自动重启'), g.restarts], [translate('最近错误'), g.last_error || '—']]));
  }
  if (stats.mptcp) {
    body.append(el('h3', translate('内核 MPTCP 连接')), table([translate('规则'), translate('方向'), translate('本地 / 对端'), translate('协商'), translate('实际子流数')], stats.mptcp.connections.map(c => [c.rule_id, c.direction, `${c.local} → ${c.peer}`, c.info.negotiated === null ? translate('未知') : c.info.negotiated ? 'MPTCP' : translate('TCP 回退'), c.info.total_subflows ?? translate('内核未提供')])));
    body.append(el('p', translate('最多观测 128 个活跃 socket；子流数取自内核，不等于独立线路数。每次节点上报重新采样。'), 'fine'));
  }
  if (stats.multipath) {
    const mp = stats.multipath;
    body.append(el('h3', translate('多路径传输')), table([translate('项目'), translate('最近采样')], [
      [translate('活跃聚合连接 / 子流'), mp.active_sessions + ' / ' + mp.active_paths], [translate('累计聚合连接'), mp.sessions], [translate('失效子流'), mp.failed_paths],
      [translate('发送负载（含额外副本）'), bytes(mp.sent_payload_bytes)], [translate('复制额外负载'), bytes(mp.replicated_payload_bytes)],
      [translate('重传额外负载'), bytes(mp.retransmitted_payload_bytes)], [translate('收到的重复负载'), bytes(mp.duplicate_payload_bytes)],
      [translate('重组交付负载'), bytes(mp.delivered_payload_bytes)], [translate('帧头与确认位图发送量'), bytes(mp.framing_sent_bytes)],
      [translate('单连接发送窗口峰值'), bytes(mp.peak_send_window_bytes)], [translate('单连接重排窗口峰值'), bytes(mp.peak_reorder_bytes)]
    ]), table([translate('子流位置（跨规则累计）'), translate('实际发送负载')], mp.path_sent_payload_bytes.map((value, index) => [String(index + 1), bytes(value)])),
    el('p', translate('以上为本次进程累计，含健康探测建立的聚合连接。负载统计不含 TLS、WebSocket、TCP/IP 报头及内核重传；不是网卡总流量或持久化账单。子流位置按配置中目标顺序编号。'), 'fine'));
  }
  modal(translate('节点运行诊断'), body);
}
const nodeKindNames = localize({ ingress: '入口', relay: '中转', egress: '出口', ix: 'IX', nat: 'NAT' });
const costPeriodNames = localize({ monthly: '每月', yearly: '每年', one_time: '一次性' });
function costAmount(micros) { const value = BigInt(micros), fraction = (value % 1000000n).toString().padStart(6, '0').replace(/0+$/, ''); return (value / 1000000n).toString() + (fraction ? '.' + fraction : ''); }
function costLabel(cost) { return cost ? `${cost.currency} ${costAmount(cost.amount_micros)} · ${costPeriodNames[cost.period]}` : translate('未记录'); }
function localDateTime(value) { if (!value) return ''; const d = new Date(value), pad = (n, size = 2) => String(n).padStart(size, '0'); return `${pad(d.getFullYear(), 4)}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`; }
function nodeSettingsEditor(form, settings = {}, strict = () => true) {
  const kinds = el('fieldset', undefined, 'target-editor'); kinds.append(el('legend', translate('节点类型（用途标注，可多选）')));
  for (const [value, label] of Object.entries(nodeKindNames)) { const item = el('label', label, 'inline-check'), input = el('input'); input.type = 'checkbox'; input.name = 'node_kind'; input.value = value; input.checked = (settings.kinds || []).includes(value); item.prepend(input); kinds.append(item); } form.append(kinds);
  field(form, 'node_group', translate('分组'), settings.group || '', 'text', false).maxLength = 64;
  textarea(form, 'node_tags', translate('标签（每行一个，最多 32 个）'), (settings.tags || []).join('\n'));
  textarea(form, 'node_notes', translate('备注'), settings.notes || '').maxLength = 4096;
  field(form, 'cost_amount', translate('成本金额（最多 6 位小数；留空不记录）'), settings.cost ? costAmount(settings.cost.amount_micros) : '', 'text', false).inputMode = 'decimal';
  field(form, 'cost_currency', translate('成本币种（三个字母，例如 CNY、USD）'), settings.cost?.currency || 'CNY', 'text', false).maxLength = 3;
  select(form, 'cost_period', translate('成本周期'), Object.entries(costPeriodNames), settings.cost?.period || 'monthly');
  const enabled = select(form, 'node_enabled', translate('运行许可'), [['true', translate('允许运行')], ['false', translate('暂停运行')]], String(settings.enabled !== false));
  const expiry = field(form, 'node_expiry', msg`到期时间（${Intl.DateTimeFormat().resolvedOptions().timeZone}；留空不设）`, localDateTime(settings.expires_at_ms), 'datetime-local', false); expiry.step = '0.001';
  const originalExpiryText = expiry.value;
  form.append(el('p', translate('类型、分组和成本用于管理，不自动改变转发路径或创建 NAT。暂停和到期仅支持严格租约：停止在当前授权窗口内收敛，不清零用量或退款。恢复允许状态后，已退出的 Agent 需要重新启动。'), 'fine'));
  const policy = () => { enabled.disabled = expiry.disabled = !strict(); if (!strict()) { enabled.value = 'true'; expiry.value = ''; } }; policy();
  return { policy, read(data) {
    const amount = String(data.get('cost_amount') || '').trim(); let cost = null;
    if (amount) { if (!/^\d+(\.\d{1,6})?$/.test(amount)) throw new Error(translate('成本必须为非负十进制数，最多 6 位小数')); const [whole, fraction = ''] = amount.split('.'), micros = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0')); if (micros > 9000000000000000n) throw new Error(translate('成本超出可记录范围')); cost = { currency: String(data.get('cost_currency')).trim().toUpperCase(), amount_micros: Number(micros), period: data.get('cost_period') }; }
    let expires = null;
    if (strict() && expiry.value) { expires = expiry.value === originalExpiryText ? settings.expires_at_ms : new Date(expiry.value).getTime(); if (!Number.isSafeInteger(expires) || expires <= 0) throw new Error(translate('请输入有效的到期时间')); }
    return { kinds: data.getAll('node_kind'), group: String(data.get('node_group') || '').trim() || null, tags: String(data.get('node_tags') || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean), notes: String(data.get('node_notes') || ''), cost, enabled: strict() ? enabled.value === 'true' : true, expires_at_ms: expires };
  } };
}
function editNode(node) {
  const settings = node.profile.settings;
  if (!canWrite()) { const body = el('div'); body.append(table([translate('资料'), translate('当前记录')], [[translate('名称'), node.name], [translate('类型'), settings.kinds.map(k => nodeKindNames[k]).join('、') || translate('未标注')], [translate('分组'), settings.group || translate('未分组')], [translate('标签'), settings.tags.join('、') || translate('无')], [translate('成本'), costLabel(settings.cost)], [translate('到期时间'), settings.expires_at_ms ? timestamp(settings.expires_at_ms) : translate('未设置')]])); body.append(el('pre', settings.notes || translate('无备注'))); modal(translate('节点资料'), body); return; }
  const form = el('form'); field(form, 'node_name', translate('节点名称'), node.name).maxLength = 120;
  const editor = nodeSettingsEditor(form, settings, () => !!node.lease.policy);
  submit(form, translate('保存资料'), async data => { await api(`/nodes/${node.id}/profile`, { method: 'PUT', body: { expected_revision: node.profile.revision, name: String(data.get('node_name')).trim(), settings: editor.read(data) } }); $('#dialog').close(); await renderNodes(); notify(translate('节点资料已保存；转发配置保持原修订。')); }); modal(translate('编辑节点 · ') + node.name, form);
}
function filterNodes() {
  const form = el('form'), current = state.nodeFilter;
  field(form, 'q', translate('搜索名称、ID、标签或备注'), current.q || '', 'text', false);
  select(form, 'kind', translate('节点类型'), [['', translate('全部类型')], ...Object.entries(nodeKindNames)], current.kind || '');
  field(form, 'group', translate('分组（精确匹配）'), current.group || '', 'text', false);
  field(form, 'tag', translate('标签（精确匹配）'), current.tag || '', 'text', false);
  select(form, 'lifecycle', translate('运行许可'), [['', translate('全部')], ['active', translate('允许运行且未到期')], ['disabled', translate('已暂停')], ['expired', translate('已到期')]], current.lifecycle || '');
  submit(form, translate('应用筛选'), async data => { state.nodeFilter = Object.fromEntries([...data.entries()].map(([k,v]) => [k,String(v).trim()]).filter(([,v]) => v)); state.selectedNodes.clear(); $('#dialog').close(); await renderNodes(); }); modal(translate('筛选节点'), form);
}
function batchNodeProfiles() {
  const selected = state.nodes.filter(node => state.selectedNodes.has(node.id));
  if (!selected.length) throw new Error(translate('请先勾选要编辑的节点'));
  if (selected.length > 100) throw new Error(translate('每次最多编辑 100 个节点'));
  const form = el('form'); form.append(el('p', msg`已选择 ${selected.length} 个节点：${selected.map(n => n.name).join('、')}`));
  const operation = select(form, 'operation', translate('批量操作'), [['group',translate('设置或清空分组')], ['add_tags',translate('增加标签')], ['remove_tags',translate('移除标签')], ['pause',translate('暂停运行')], ['enable',translate('允许运行')]], 'group');
  const value = textarea(form, 'value', translate('分组名称，或每行一个标签'), '');
  operation.onchange = () => { value.disabled = ['pause','enable'].includes(operation.value); };
  form.append(el('p', translate('所有节点验证通过后一起保存。任一节点资料过期或权限不符，整批均不修改；重新打开后再编辑。暂停仅支持严格租约，不自动退款；允许运行后仍须检查到期时间和 Agent 状态。'), 'fine'));
  submit(form, translate('保存选中节点'), async data => {
    const action = data.get('operation'), text = String(data.get('value') || '').trim(), tags = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const updates = selected.map(node => { const settings = structuredClone(node.profile.settings);
      if (action === 'group') settings.group = text || null;
      if (action === 'add_tags') settings.tags = [...new Set([...settings.tags, ...tags])];
      if (action === 'remove_tags') settings.tags = settings.tags.filter(t => !tags.includes(t));
      if (action === 'pause') settings.enabled = false;
      if (action === 'enable') settings.enabled = true;
      return { node_id: node.id, update: { expected_revision: node.profile.revision, name: node.name, settings } };
    });
    const results = await api('/nodes/profiles', { method: 'POST', body: { updates } }); state.selectedNodes.clear(); $('#dialog').close(); await renderNodes(); const body = el('div'); body.append(table([translate('节点'), translate('资料修订'), translate('运行许可')], results.map(r => [r.name, r.profile.revision, {active:translate('允许运行'),disabled:translate('已暂停'),expired:translate('已到期')}[r.lifecycle]]))); modal(translate('批量保存完成'), body);
  }); modal(translate('批量编辑节点资料'), form);
}
function nodeInventoryCell(node) { const s = node.profile.settings, cell = el('div'); cell.append(el('strong', s.kinds.map(k => nodeKindNames[k]).join(' / ') || translate('未标注')), el('div', [s.group || translate('未分组'), ...s.tags].join(' · '), 'subline'), el('div', costLabel(s.cost), 'subline')); return cell; }
function nodeLifecycleCell(node) { const cell = el('div'), names = { active: translate('允许运行'), disabled: translate('已暂停'), expired: translate('已到期') }; cell.append(badge(names[node.lifecycle], node.lifecycle === 'active' ? 'green' : 'orange')); if (node.profile.settings.expires_at_ms) cell.append(el('div', timestamp(node.profile.settings.expires_at_ms), 'subline')); if (node.lifecycle !== 'active' && node.lease.active) cell.append(el('div', translate('现有租约尚在收敛'), 'subline')); return cell; }

function newNode() {
  const form=el('form');form.append(el('p',translate('注册节点只创建面板记录。请在目标 VPS 安装并启动 Agent；此操作不会自动 SSH 登录或安装。'),'workflow-callout'));field(form,'name',translate('节点名称'),'','text').maxLength=120;
  const mode=select(form,'lease_mode',translate('运行保护策略'),[['offline',translate('可用优先（推荐）：控制器离线时继续转发')],['strict',translate('严格租约：按量计费节点')]],'offline');
  const ttl=field(form,'lease_ttl',translate('租约窗口 / 秒'),30,'number');ttl.min=5;ttl.max=120;ttl.disabled=true;
  const editor=nodeSettingsEditor(form,{},()=>mode.value==='strict');mode.onchange=()=>{ttl.disabled=mode.value!=='strict';editor.policy();};
  form.append(el('p',translate('节点归属当前租户。可用优先：控制器离线时按最后配置继续转发，崩溃后约 1 秒恢复；不能阻止复制的节点身份同时运行，控制器离线期间额度不能严格限制，也不支持暂停或到期。严格租约：与控制器失联超过租约窗口会停止转发，崩溃后要等旧租约过期。运行策略创建后固定。注册令牌只显示一次。'),'fine'));
  submit(form,translate('创建节点'),async data=>{const result=await api('/nodes',{method:'POST',body:{name:String(data.get('name')).trim(),lease_policy:mode.value==='strict'?{ttl_ms:number(data,'lease_ttl')*1000}:null,settings:editor.read(data)}});const body=el('div');body.append(el('p',translate('请将此令牌保存为节点上的私有文件（权限 0600）。')),el('div',result.enrollment_token,'secret-box'));body.append(el('p',translate('节点启动命令'),'fine'),el('pre',`relay agent --controller ${location.origin} --node-id ${result.node.id} --enrollment-token-file /path/to/enrollment.secret --state /var/lib/relay-agent`),el('p',translate('跨机器接入须使用 HTTPS。本机 HTTP 地址仅用于本地验收。'),'fine'),button(translate('我已保存令牌'),()=>$('#dialog').close(),'primary'));$('#dialog').close();modal(translate('节点已创建 · 保存一次性令牌'),body);state.selectedNode=result.node.id;await renderNodes();});modal(translate('注册节点'),form);
}


const setupRecipes = localize([
  { id: 'forward', title: '单 VPS 端口转发', scope: '1 台 VPS', route: '客户端 → VPS → 固定目标', description: '把一个监听端口的 TCP / UDP 流量转发到已有服务。', mode: 'forward', path: false },
  { id: 'ss', title: '单 VPS Shadowsocks', scope: '1 台 VPS', route: '客户端 → VPS（SS）→ 网站 / 服务', description: '在所选 VPS 运行 SS，由客户端指定目的地。', mode: 'ss', path: false },
  { id: 'forward-path', title: '多跳端口转发', scope: '2 台或更多 VPS', route: '客户端 → 入口 → 中转 / 出口 → 固定目标', description: '按顺序连接多台 VPS，把流量送到固定目标。', mode: 'forward', path: true },
  { id: 'ss-path', title: '多跳 Shadowsocks', scope: '2 台或更多 VPS', route: '客户端 → 入口 → 出口（SS）→ 网站 / 服务', description: '前面的 VPS 转发加密流量，只在最后一台 VPS 运行 SS。', mode: 'ss', path: true },
]);
function setupCards(pathOnly = false) {
  const grid = el('div', undefined, 'setup-cards');
  for (const recipe of setupRecipes.filter(recipe => !pathOnly || recipe.path)) {
    const card = el('article', undefined, 'setup-card'); card.dataset.recipe = recipe.id;
    card.append(badge(recipe.scope), el('h3', recipe.title), el('p', recipe.description), el('p', recipe.route, 'setup-route'));
    card.append(button(translate('使用此模板'), () => startSetup(recipe.id), 'primary'));
    grid.append(card);
  }
  return grid;
}
function chooseSetup(pathOnly = false) {
  const body = el('div');
  body.append(el('p', translate('先选择要实现的连接方式。下一步选择 VPS 和地址，检查路径后再发布。'), 'workflow-callout'), setupCards(pathOnly));
  if (!pathOnly) body.append(button(translate('其他协议 / 高级规则'), () => startSetup('advanced')));
  modal(translate('你想建立什么连接？'), body);
}
async function startSetup(id) {
  const recipe = setupRecipes.find(recipe => recipe.id === id), snapshot = await api('/topology');
  state.nodes = snapshot.nodes;
  if (snapshot.nodes.length < (recipe?.path ? 2 : 1)) {
    const body = empty(translate('先连接所需的 VPS'), recipe?.path ? translate('多跳模板需要至少两个节点。注册 VPS 并启动 Agent 后，再选择入口和出口。') : translate('先注册一台 VPS 并启动 Agent，再用模板创建服务。'), button(translate('前往节点管理'), () => { $('#dialog').close(); return navigate('nodes'); }, 'primary'));
    modal(translate('准备节点'), body); return;
  }
  if (recipe?.path) return newTopologyChain(snapshot, { mode: recipe.mode, protocol: 'both', name: recipe.title });
  const node = snapshot.nodes.find(n => n.id === state.selectedNode) || snapshot.nodes.find(n => n.tenant_id === state.actor.tenant_id) || snapshot.nodes[0];
  state.selectedNode = node.id; state.config = snapshot.configs.find(config => config.node_id === node.id);
  const seed = recipe ? { name: recipe.title, protocol: 'both', listen: '0.0.0.0:9000', targets: [{ address: '', weight: 1 }],
    ...(recipe.mode === 'ss' ? { inbound_shadowsocks: { method: '2022-blake3-aes-256-gcm', password: shadowsocksKey('2022-blake3-aes-256-gcm'), udp_over_tcp: true } } : {}) } : {};
  return editRule(null, seed);
}

async function renderRules() {
  state.nodes = await api('/nodes'); const content = $('#content');
  if (!state.nodes.length) { content.replaceChildren(empty(translate('还没有节点'), translate('先注册节点，再创建规则。'), button(translate('前往节点管理'), () => navigate('nodes'), 'primary'))); return; }
  if (!state.nodes.some(n => n.id === state.selectedNode)) state.selectedNode = state.nodes[0].id;
  const toolbar = el('div', undefined, 'toolbar'), selector = el('select'); selector.setAttribute('aria-label', translate('选择节点')); state.nodes.forEach(n => { const option = el('option', n.name); option.value = n.id; selector.append(option); }); selector.value = state.selectedNode; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; const nodeLabel = el('label', translate('运行节点 / VPS')); nodeLabel.append(selector); toolbar.append(nodeLabel);
  const nodeId = state.selectedNode; const config = await api(`/nodes/${nodeId}/config`); if (state.view !== 'rules' || state.selectedNode !== nodeId) return; state.config = config;
  toolbar.append(badge(msg`期望修订 v${config.revision}`), badge(config.rate_bytes_per_sec ? msg`节点总限速 ${mbit(config.rate_bytes_per_sec)}` : translate('节点不限速'), config.rate_bytes_per_sec ? 'orange' : ''), button(translate('版本历史'), history)); if (canWrite()) toolbar.append(button(translate('节点总限速'), () => editNodeRate(config)));
  const actions = el('div'); if (canWrite()) actions.append(button(translate('查看完整路径'), () => navigate('topology')), button(translate('＋ 添加规则'), () => chooseSetup(), 'primary'));
  toolbar.append(applicationBadge(state.nodes.find(n => n.id === nodeId)));
  const p = panel(translate('所选 VPS 的规则'), translate('这里管理单台 VPS 的监听和服务。一条多跳路径会在每台参与的 VPS 上各创建一条规则。'), actions);
  const applyError = state.nodes.find(n => n.id === nodeId)?.apply_error;
  if (applyError) p.append(el('p', msg`节点应用错误：${applyError}`, 'error workflow-callout'));
  if (!config.rules.length) p.append(empty(translate('此 VPS 还没有规则'), translate('选择一个模板，说明这台 VPS 是转发流量还是提供代理服务。'), canWrite() ? button(translate('从模板开始'), () => chooseSetup(), 'primary') : null));
  else p.append(table([translate('名称'), translate('监听 / 协议'), translate('目标'), translate('配额 / 限速'), translate('状态'), translate('操作')], config.rules.map(rule => { const actions = el('div'); if (rule.inbound_shadowsocks) actions.append(button(translate('分享链接'), () => shareShadowsocks(rule), 'table-action')); if (rule.inbound_socks5) actions.append(button(translate('分享链接'), () => shareSocks5(rule), 'table-action')); if (rule.inbound_http_connect) actions.append(button(translate('分享链接'), () => shareHttpConnect(rule), 'table-action')); if (canWrite()) { if (state.actor.role !== 'viewer') actions.append(button(translate('存为模板'), () => saveTemplate(rule), 'table-action')); actions.append(button(translate('编辑'), () => editRule(rule), 'table-action'), button(rule.enabled ? translate('停用') : translate('启用'), () => saveRules(config.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r), config), 'table-action'), button(translate('删除'), async () => { if (await confirmAction(msg`删除「${rule.name}」会终止其会话，历史账本保留。`)) await saveRules(config.rules.filter(r => r.id !== rule.id), config); }, 'table-action danger')); } return [namedCell(rule.name, rule.id), namedCell((rule.protocol_gateway?.listen || rule.listen) + (rule.listen_end_port ? ` → ${rule.listen_end_port}` : ''), rule.protocol.toUpperCase()), rule.protocol_gateway ? namedCell(rule.protocol_gateway.protocol.type.toUpperCase(), rule.protocol_gateway.security.type === 'reality' ? 'Reality' : 'TLS') : rule.inbound_shadowsocks ? namedCell(translate('Shadowsocks 代理服务'), rule.inbound_shadowsocks.method) : rule.inbound_socks5 ? namedCell(translate('SOCKS5 代理服务'), rule.inbound_socks5.username ? translate('用户名密码认证') : translate('无认证')) : rule.inbound_http_connect ? namedCell(translate('HTTP CONNECT 代理服务'), rule.inbound_http_connect.username ? translate('Basic 认证') : translate('无认证')) : rule.inbound_http2_connect ? namedCell('HTTP/2 CONNECT', msg`并发隧道上限 ${rule.inbound_http2_connect.max_concurrent_streams || 128} · ${rule.inbound_tls ? 'TLS' : 'h2c'}`) : namedCell(rule.targets[0].address, msg`${rule.targets.length} 个目标 · ${rule.balance}`), `${rule.quota_bytes === null ? translate('不限量') : bytes(rule.quota_bytes)} / ${rule.rate_bytes_per_sec === null ? translate('不限速') : bytes(rule.rate_bytes_per_sec) + '/s'}`, badge(rule.enabled ? translate('期望启用') : translate('期望停用'), rule.enabled ? '' : ''), actions]; })));
  content.replaceChildren(toolbar, p);
}
function mbit(rate) { return `${+(rate * 8 / 1e6).toFixed(2)} Mbit/s`; }
function editNodeRate(baseConfig) {
  const form = el('form'), grid = el('div', undefined, 'form-grid'); const input = field(grid, 'mbit', translate('本节点所有规则上下行合计 / Mbit/s（留空不限速）'), baseConfig.rate_bytes_per_sec ? +(baseConfig.rate_bytes_per_sec * 8 / 1e6).toFixed(3) : '', 'number', false); input.min = 0.008; input.step = 'any'; form.append(grid, el('p', translate('与规则自身的限速同时生效，取较严者。立即作用于已有连接，不会断开会话；健康探测不计入。'), 'muted'));
  submit(form, translate('发布限速'), async data => { const raw = String(data.get('mbit')).trim(); const rate = raw === '' ? null : Math.round(Number(raw) * 1e6 / 8); if (rate !== null && !(rate >= 1 && rate <= 1e12)) throw new Error(translate('请输入 0.008 到 8,000,000 之间的 Mbit/s')); await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision: baseConfig.revision, rules: baseConfig.rules, rate_bytes_per_sec: rate } }); $('#dialog').close(); notify(rate ? msg`已发布节点总限速 ${mbit(rate)}。` : translate('已取消节点总限速。')); await renderRules(); });
  modal(translate('节点总限速'), form);
}
async function saveRules(rules, baseConfig) { const expected_revision = baseConfig.revision; await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision, rules } }); $('#dialog').close(); notify(translate('配置已发布。请在节点总览确认实际应用修订号。')); await renderRules(); }
function gatewayConfig(type, listen, uuid, password, vision, security, identity, serverName, handshake, privateKey, shortId, allowPrivate, payload) {
  if (type === 'off') return null;
  if (!['vless', 'hysteria2', 'tuic', 'any_tls', 'trojan', 'vmess'].includes(type)) throw new Error(translate('未知协议'));
  if (payload === 'udp' || (type === 'any_tls' && payload !== 'tcp')) throw new Error(translate('协议入口需要 TCP 控制连接；AnyTLS 当前仅支持 TCP 业务'));
  const protocol = { type };
  if (['vless', 'vmess', 'tuic'].includes(type)) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(uuid)) throw new Error(translate('请填写有效的非空 UUID'));
    protocol.uuid = uuid;
  }
  if (['hysteria2', 'tuic', 'any_tls', 'trojan'].includes(type)) {
    if (new TextEncoder().encode(password).length < 16 || new TextEncoder().encode(password).length > 256 || /[\x00-\x1f\x7f]/.test(password)) throw new Error(translate('协议密码需要 16–256 字节，不能含控制字符'));
    protocol.password = password;
  }
  if (type === 'vless') protocol.vision = vision === 'yes';
  let secure;
  if (security === 'certificate') {
    if (!identity.trim()) throw new Error(translate('请填写节点本地证书编号'));
    secure = { type: 'certificate', identity: identity.trim() };
    if (serverName.trim()) secure.server_name = serverName.trim();
  } else if (security === 'reality' && type === 'vless') {
    if (!serverName.trim() || !handshake.trim() || !/^[A-Za-z0-9_-]{43}$/.test(privateKey) || !/^(?:[0-9a-f]{2}){1,8}$/i.test(shortId)) throw new Error(translate('Reality 需要服务器名称、握手地址、32 字节 Base64URL 私钥和 2–16 位偶数长度十六进制 short ID'));
    secure = { type: 'reality', server_name: serverName.trim(), handshake: handshake.trim(), private_key: privateKey, short_id: shortId };
  } else throw new Error(translate('Reality 仅支持 VLESS'));
  return { listen, protocol, security: secure, allow_private_destinations: allowPrivate === 'yes' };
}
function gatewayBridge(existing, rules, publicListen) {
  if (existing?.protocol_gateway) return existing.listen;
  const ports = new Set(rules.flatMap(r => [r.listen, r.protocol_gateway?.listen]).filter(Boolean).map(v => Number(v.slice(v.lastIndexOf(':') + 1))));
  ports.add(Number(publicListen.slice(publicListen.lastIndexOf(':') + 1)));
  const start = crypto.getRandomValues(new Uint32Array(1))[0] % 40000;
  for (let n = 0; n < 40000; n++) { const port = 20000 + (start + n) % 40000; if (!ports.has(port) && !rules.some(r => port >= Number(r.listen.slice(r.listen.lastIndexOf(':') + 1)) && port <= (r.listen_end_port || Number(r.listen.slice(r.listen.lastIndexOf(':') + 1))))) return `127.0.0.1:${port}`; }
  throw new Error(translate('没有可分配的内部监听端口'));
}
function gatewayEditor(spec, payload, publicListen) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', 'VLESS / Reality / Hysteria2 / TUIC / AnyTLS / Trojan / VMess'));
  const type = select(box, 'gateway_type', translate('协议入口'), [['off', translate('关闭')], ['vless', 'VLESS'], ['hysteria2', 'Hysteria2'], ['tuic', 'TUIC'], ['any_tls', 'AnyTLS'], ['trojan', 'Trojan'], ['vmess', 'VMess']], spec?.protocol.type || 'off');
  const fields = el('div', undefined, 'form-grid');
  const uuid = field(fields, 'gateway_uuid', translate('客户端 UUID'), spec?.protocol.uuid || '', 'text', false);
  const password = field(fields, 'gateway_password', translate('客户端密码'), spec?.protocol.password || '', 'password', false);
  const vision = select(fields, 'gateway_vision', 'VLESS Vision', [['no', translate('关闭')], ['yes', 'xtls-rprx-vision']], spec?.protocol.vision ? 'yes' : 'no');
  const security = select(fields, 'gateway_security', translate('安全传输'), [['certificate', translate('TLS 证书')], ['reality', translate('Reality（仅 VLESS）')]], spec?.security.type || 'certificate');
  const identity = field(fields, 'gateway_identity', translate('节点证书编号'), spec?.security.identity || '', 'text', false);
  const serverName = field(fields, 'gateway_sni', translate('客户端 TLS 服务器名称（证书模式留空沿用订阅域名）'), spec?.security.server_name || '', 'text', false);
  const handshake = field(fields, 'gateway_handshake', translate('Reality 握手服务器 host:port'), spec?.security.handshake || '', 'text', false);
  const privateKey = field(fields, 'gateway_private_key', translate('Reality 私钥'), spec?.security.private_key || '', 'password', false);
  const shortId = field(fields, 'gateway_short_id', 'Reality short ID', spec?.security.short_id || '', 'text', false);
  const allowPrivate = select(fields, 'gateway_private', translate('内网 / 回环目的地'), [['no', translate('拒绝（推荐）')], ['yes', translate('允许')]], spec?.allow_private_destinations ? 'yes' : 'no');
  const generate = button(translate('生成客户端凭据'), () => {
    uuid.value = crypto.randomUUID();
    password.value = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');
  });
  const keys = button(translate('生成 Reality 密钥'), () => {
    privateKey.value = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    shortId.value = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
  });
  function show() {
    const on = type.value !== 'off', reality = security.value === 'reality';
    for (const [control, visible] of [[uuid, ['vless', 'vmess', 'tuic'].includes(type.value)], [password, ['hysteria2', 'tuic', 'any_tls', 'trojan'].includes(type.value)], [vision, type.value === 'vless'], [identity, !reality], [handshake, reality], [privateKey, reality], [shortId, reality], [security, true], [serverName, true], [allowPrivate, true]]) {
      control.disabled = !on || !visible; control.parentElement.classList.toggle('hidden', !visible);
    }
    fields.classList.toggle('hidden', !on); generate.disabled = !on; keys.disabled = !on || !reality;
  }
  type.addEventListener('change', () => { if (type.value !== 'vless') security.value = 'certificate'; if (type.value !== 'off') payload.value = type.value === 'any_tls' ? 'tcp' : 'both'; show(); });
  security.addEventListener('change', show);
  box.append(fields, generate, keys, el('p', translate('节点需要安装受支持的协议引擎。面板负责规则权限、流量账本、配额、限速和目的地 ACL。上方监听地址用于客户端连接；来源 ACL 使用实际客户端 IP。订阅请选择 sing-box JSON 或 mihomo YAML。证书模式须让客户端信任签发 CA。Reality 握手与伪装回落流量也计入配额并受目的地限制；请允许握手服务器地址与端口。来源 ACL 不替代握手前的主机防火墙。'), 'fine')); show();
  return { box, setEnabled(on) { type.value = on ? (type.value === 'off' ? 'vless' : type.value) : 'off'; if (on && !uuid.value) uuid.value = crypto.randomUUID(); show(); }, enabled: () => type.value !== 'off', onchange: f => type.addEventListener('change', f), read: () => gatewayConfig(type.value, publicListen.value, uuid.value, password.value, vision.value, security.value, identity.value, serverName.value, handshake.value, privateKey.value, shortId.value, allowPrivate.value, payload.value) };
}
function mptcpConfig(inbound, outbound, protocol) {
  const allowed = ['off', 'prefer', 'require'];
  if (!allowed.includes(inbound) || !allowed.includes(outbound)) throw new Error(translate('无效的 MPTCP 策略'));
  if (inbound === 'off' && outbound === 'off') return null;
  if (protocol === 'udp') throw new Error(translate('MPTCP 只适用于 TCP，不能用于纯 UDP 规则'));
  return { inbound, outbound };
}
function mptcpEditor(value) {
  const box = el('details'); box.append(el('summary', 'Linux MPTCP'));
  const options = [['off', translate('普通 TCP')], ['prefer', translate('优先 MPTCP · 允许 TCP 回退')], ['require', translate('必须协商 MPTCP · 否则拒绝')]];
  const inbound = select(box, 'mptcp_inbound', translate('入口传输'), options, value?.inbound || 'off');
  const outbound = select(box, 'mptcp_outbound', translate('出口传输'), options, value?.outbound || 'off');
  box.append(el('p', translate('MPTCP 需要 Linux 内核与对端支持。额外路径由节点网络配置决定；协商成功不代表已聚合多条线路。更改入口模式前请先停用并发布规则。'), 'fine'));
  return { box, gateway(on) { inbound.parentElement.classList.toggle('hidden', on); inbound.disabled = on; }, read: (protocol, gateway = false) => mptcpConfig(gateway ? 'off' : inbound.value, outbound.value, protocol) };
}
async function editRule(existing, seed = {}) {
  let baseConfig = state.config, nodeLoad = null;
  const topology = await api('/topology'); const form = el('form'), grid = el('div', undefined, 'form-grid'), r = existing || seed;
  form.append(el('h3', translate('1. 选择运行 VPS 与服务'), 'setup-step'));
  const extraGrid = el('div', undefined, 'form-grid');
  if ([r.inbound_shadowsocks, r.inbound_socks5, r.inbound_http_connect, r.inbound_http2_connect, r.protocol_gateway].filter(Boolean).length > 1) throw new Error(translate('每条规则只能启用一种代理入口'));
  const tenant = state.nodes.find(n => n.id === baseConfig.node_id).tenant_id;
  const runOn = select(grid, 'run_on', translate('运行节点 / VPS'), state.nodes.filter(n => n.tenant_id === tenant).map(n => [n.id, n.name || n.id]), baseConfig.node_id);
  runOn.disabled = !!existing;
  const purpose = select(grid, 'rule_purpose', translate('规则用途'), localize([['forward', '端口转发 · 入口或中转'], ['ss', 'Shadowsocks · 出口代理服务'], ['socks5', 'SOCKS5 · 代理服务'], ['http', 'HTTP CONNECT · 代理服务'], ['h2', 'HTTP/2 CONNECT · 代理服务'], ['gateway', '受管协议 · VLESS / Reality / Hysteria2 / TUIC / AnyTLS / Trojan / VMess']]), serviceKind(r));
  field(grid, 'name', translate('规则名称'), r.name || '').maxLength = 120;
  const protocolControl = select(grid, 'protocol', translate('传输协议（TCP / UDP）'), [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], r.protocol || 'tcp');
  const listenControl = field(grid, 'listen', translate('监听地址'), r.protocol_gateway?.listen || r.listen || '127.0.0.1:9000');
  const advertise = field(grid, 'advertise', translate('客户端 / 上一跳连接地址（VPS 公网 IP 或域名:端口）'), r.advertise || '', 'text', !!seed.name); advertise.placeholder = 'vps.example.com:9000';
  const endPort = field(extraGrid, 'listen_end_port', translate('结束端口（留空只监听一个端口，最多 256 个）'), r.listen_end_port, 'number', false); endPort.min = 1; endPort.max = 65535;
  const mapping = select(extraGrid, 'port_mapping', translate('端口段的目标映射'), [['fixed', translate('全部入口连接同一目标端口')], ['offset', translate('按入口端口偏移目标端口')]], r.port_mapping || 'fixed');
  const balance = select(extraGrid, 'balance', translate('目标分配'), [['weighted_round_robin', translate('加权轮询')], ['source_hash', translate('来源 IP 哈希')], ['least_connections', translate('最少连接')], ['lowest_latency', translate('最低延迟（须启用健康探测）')]], r.balance || 'weighted_round_robin'); form.append(grid);
  const placement = el('p', '', 'workflow-callout'), reachability = el('p', '', 'fine'); form.append(placement, reachability);
  function describePlacement() {
    const node = state.nodes.find(n => n.id === runOn.value);
    placement.textContent = purpose.value === 'forward' ? msg`运行于 ${node.name}：将流量转发到下方目标。完整多跳路径请使用“创建转发路径”。` : purpose.value === 'gateway' ? msg`服务运行于 ${node.name}。此节点须先安装受支持的协议引擎并准备证书或 Reality 配置；保存规则不会自动下载安装引擎。` : msg`代理服务运行于 ${node.name}，由此节点连接客户端请求的目的地。Agent 已内置该服务，无需另装服务端。`;
    reachability.textContent = splitEndpoint(listenControl.value)?.loopback ? translate('当前监听仅限本机。其他 VPS 无法直接连接；跨 VPS 请使用可达网卡地址，并允许对应端口。') : translate('监听地址属于所选 VPS；可达地址用于客户端或上一跳连接。发布配置不会自动修改防火墙。');
  }
  runOn.addEventListener('change', () => {
    describePlacement();
    const id = runOn.value;
    nodeLoad = api(`/nodes/${id}/config`).then(config => { if (runOn.value === id) baseConfig = config; });
    nodeLoad.catch(error => notify(error.message, true));
  });
  listenControl.addEventListener('input', describePlacement);
  form.append(el('h3', translate('2. 设置目标或代理凭据'), 'setup-step'));
  const shadowsocks = shadowsocksEditor(r.inbound_shadowsocks); form.append(shadowsocks.box);
  const socks5 = socks5Editor(r.inbound_socks5); form.append(socks5.box);
  const httpConnect = httpConnectEditor(r.inbound_http_connect); form.append(httpConnect.box);
  const http2Connect = http2ConnectEditor(r.inbound_http2_connect); form.append(http2Connect.box);
  const gateway = gatewayEditor(r.protocol_gateway, protocolControl, listenControl); form.append(gateway.box);
  const services = { ss: shadowsocks, socks5, http: httpConnect, h2: http2Connect, gateway };
  const mptcp = mptcpEditor(r.mptcp); form.append(mptcp.box);
  const routed = el('div'); form.append(routed);
  const routedOptions = el('details'); routedOptions.append(el('summary', translate('高级路由：健康检查与多路径')));
  const readHealth = healthEditor(routedOptions, r.health_check, protocolControl);
  const multipath = multipathEditor(routedOptions, r);
  const readTargets = targetEditor(routed, r.targets?.length ? r.targets : [{ address: '127.0.0.1:8000', weight: 1 }], topology, state.nodes.find(node => node.id === baseConfig.node_id).tenant_id, r.id, r.outbound_multipath?.paths, multipath.mode);
  routed.append(routedOptions);
  let proxyInput;
  // A proxy server goes where each client asks, so it has no fixed targets.
  function showRouted() {
    const legacy = shadowsocks.enabled() || socks5.enabled() || httpConnect.enabled() || gateway.enabled(), server = legacy || http2Connect.enabled();
    for (const [part, hidden] of [[routed, server], [transport, shadowsocks.enabled() || gateway.enabled()], [inboundWs.box, shadowsocks.enabled() || http2Connect.enabled() || gateway.enabled()]]) {
      part.classList.toggle('hidden', hidden);
      part.querySelectorAll('input, select, textarea').forEach(input => {
        if (hidden) { input.dataset.wasDisabled ??= String(input.disabled); input.disabled = true; }
        else if (input.dataset.wasDisabled !== undefined) { input.disabled = input.dataset.wasDisabled === 'true'; delete input.dataset.wasDisabled; }
      });
    }
    balance.parentElement.classList.toggle('hidden', server);
    sectionVisible(advertise.parentElement, !gateway.enabled());
    sectionVisible(endPort.parentElement, !gateway.enabled());
    sectionVisible(mapping.parentElement, !server);
    mptcp.gateway(gateway.enabled());
    if (proxyInput) sectionVisible(proxyInput, !gateway.enabled());
    for (const [kind, editor] of Object.entries(services)) { sectionVisible(editor.box, purpose.value === kind); if (purpose.value === kind) editor.box.open = true; }
    describePlacement();
  }
  const routing = el('details'); routing.append(el('summary', translate('出口绑定与 DNS 缓存'))); const routeFields = el('div', undefined, 'form-grid');
  field(routeFields, 'outbound_ip', translate('出口源 IP（留空由系统选择）'), r.outbound_bind?.ip || '', 'text', false);
  field(routeFields, 'outbound_interface', translate('出口网卡名称（留空由系统选择）'), r.outbound_bind?.interface || '', 'text', false);
  const dnsMode = select(routeFields, 'dns_mode', translate('目标域名解析'), [['system', translate('沿用系统解析')], ['cache', translate('启用按 TTL 缓存')]], r.dns_cache ? 'cache' : 'system'); routing.append(routeFields);
  const dnsFields = el('div', undefined, 'form-grid');
  textarea(dnsFields, 'dns_servers', translate('DNS 服务器 IP:端口，每行一个（留空读取系统配置）'), (r.dns_cache?.servers || []).join('\n'));
  for (const [key, label, fallback, min, max] of [['capacity', translate('缓存响应数上限'), 1024, 1, 4096], ['max_ttl_secs', translate('正响应 TTL 上限 / 秒（0 不缓存）'), 300, 0, 3600], ['negative_max_ttl_secs', translate('不存在记录的 TTL 上限 / 秒'), 5, 0, 60]]) { const input = field(dnsFields, `dns_${key}`, label, r.dns_cache?.[key] ?? fallback, 'number'); input.min = min; input.max = max; }
  function showDns() { const enabled = dnsMode.value === 'cache'; dnsFields.classList.toggle('hidden', !enabled); dnsFields.querySelectorAll('input, textarea').forEach(input => { input.disabled = !enabled; }); } dnsMode.addEventListener('change', showDns); showDns();
  routing.append(dnsFields, el('p', translate('出口绑定只约束业务连接；绑定失败时配置不会生效。DNS 查询沿用系统路由。缓存遵守响应 TTL，不会延长短 TTL。IPv6 监听只接收 IPv6。'), 'fine')); form.append(routing);
  const transport = el('details'); transport.append(el('summary', translate('入口 TLS 与客户端认证'))); const tlsFields = el('div', undefined, 'form-grid');
  field(tlsFields, 'tls_identity', translate('入口证书编号（留空使用普通连接）'), r.inbound_tls?.identity || '', 'text', false);
  field(tlsFields, 'tls_client_ca', translate('允许客户端的 CA 编号（留空不要求客户端证书）'), r.inbound_tls?.client_ca || '', 'text', false); transport.append(tlsFields, el('p', translate('证书和私钥预先放在节点本地，面板只保存编号。TLS 仅用于 TCP；一条规则的所有出口必须使用相同的安全方式。'), 'fine')); form.append(transport);
  const inboundWs = websocketEditor('inbound-ws', r.inbound_websocket, true); form.append(inboundWs.box);
  // Clients also send QUIC, DNS and games over UDP, so a new server carries both.
  shadowsocks.onchange(() => { if (!existing && shadowsocks.enabled() && protocolControl.value === 'tcp') protocolControl.value = 'both'; showRouted(); }); socks5.onchange(() => { if (!existing && socks5.enabled()) protocolControl.value = 'tcp'; showRouted(); }); httpConnect.onchange(() => { if (!existing && httpConnect.enabled()) protocolControl.value = 'tcp'; showRouted(); }); http2Connect.onchange(() => { if (http2Connect.enabled()) protocolControl.value = 'tcp'; showRouted(); }); showRouted();
  gateway.onchange(showRouted);
  for (const [kind, editor] of Object.entries(services)) editor.onchange(() => {
    if (!editor.enabled() && purpose.value === kind) purpose.value = 'forward';
    showRouted();
  });
  purpose.addEventListener('change', () => {
    // Restore controls before the editor sets its own field requirements.
    for (const editor of Object.values(services)) sectionVisible(editor.box, true);
    for (const [kind, editor] of Object.entries(services)) editor.setEnabled(purpose.value === kind);
    if (['ss', 'socks5', 'gateway'].includes(purpose.value)) protocolControl.value = 'both';
    if (['http', 'h2'].includes(purpose.value)) protocolControl.value = 'tcp';
    showRouted();
  });
  proxyInput = el('details'); proxyInput.append(el('summary', translate('接收可信上游传递的原始地址（PROXY protocol）')));
  const proxyMode = select(proxyInput, 'proxy_input_version', translate('入口 PROXY 报头'), [['off', translate('关闭')], ['v1', translate('要求 v1 · 仅 TCP')], ['v2', translate('要求 v2 · TCP / UDP')], ['any', translate('要求 v1 或 v2 · 仅 TCP')]], r.inbound_proxy?.version || 'off');
  const proxyOptions = el('div', undefined, 'form-grid');
  textarea(proxyOptions, 'proxy_trusted_sources', translate('允许发送报头的代理 CIDR（每行一个，不能为空）'), (r.inbound_proxy?.trusted_sources || ['127.0.0.0/8', '::1/128']).join('\n'), true);
  select(proxyOptions, 'proxy_input_placement', translate('PROXY 报头位置'), [['before_tls', translate('TLS 之前（普通连接也选此项）')], ['inside_tls', translate('TLS 加密连接内（须同时启用入口 TLS）')]], r.inbound_proxy?.placement || 'before_tls');
  const proxyLimit = field(proxyOptions, 'proxy_header_limit', translate('报头字节上限'), r.inbound_proxy?.max_header_bytes ?? 4096, 'number'); proxyLimit.min = 16; proxyLimit.max = 65551;
  select(proxyOptions, 'proxy_accept_prewarmed', translate('接受上一跳的预热连接'), [['no', translate('不接受 · 报头须在连接超时内到达')], ['yes', translate('接受 · 最长等待 30 秒报头再连接目标')]], r.inbound_proxy?.accept_prewarmed ? 'yes' : 'no');
  function showProxyInput() { const enabled = proxyMode.value !== 'off'; proxyOptions.classList.toggle('hidden', !enabled); proxyOptions.querySelectorAll('input, select, textarea').forEach(input => { input.disabled = !enabled; }); } proxyMode.addEventListener('change', showProxyInput); showProxyInput();
  proxyInput.append(proxyOptions, el('p', translate('启用后必须携带正确报头；直接客户端将被拒绝。来源 ACL 和来源哈希按报头中的客户端地址执行。PROXY 和 CRC32C 不提供身份认证；可信网段应只包含你的代理。UDP 每包都须携带 v2，回复为普通业务数据。'), 'fine')); form.append(proxyInput);
  showRouted();
  const limits = el('div', undefined, 'form-grid'); field(limits, 'quota_bytes', translate('合并配额 / bytes（留空不限，0 禁止流量）'), r.quota_bytes, 'number', false).min = 0; field(limits, 'rate_bytes_per_sec', translate('合并速率 / bytes/s（留空不限）'), r.rate_bytes_per_sec, 'number', false).min = 1; form.append(limits);
  if(existing){const label=el('label',undefined,'inline-check'),fresh=el('input');fresh.type='checkbox';fresh.name='new_meter_period';label.append(fresh,document.createTextNode(translate('明确开始新计量周期：旧账保留，重新发放本规则额度；共享预算不重置')));form.append(label);}
  const details = el('details'); details.append(el('summary', translate('高级：超时、会话上限、到期和来源网段'))); const advanced = el('div', undefined, 'form-grid');
  for (const [name, label, fallback, min, max] of [['connect_timeout_ms', translate('连接超时 / ms'), 5000, 100, 60000], ['idle_timeout_secs', translate('空闲回收 / 秒'), 120, 1, 86400], ['max_connections', translate('TCP 最大连接'), 4096, 1, 1000000], ['udp_max_sessions', translate('UDP 最大会话'), 1024, 1, 100000]]) { const input = field(advanced, name, label, r[name] ?? fallback, 'number'); input.min = min; input.max = max; }
  const expiry = field(advanced, 'expires_at_ms', translate('到期 / Unix 毫秒（留空永不过期）'), r.expires_at_ms, 'number', false); expiry.min = 0; details.append(advanced); textarea(details, 'allow_sources', translate('允许来源 CIDR（留空允许所有未拒绝来源，每行一个）'), (r.allow_sources || []).join('\n')); textarea(details, 'deny_sources', translate('拒绝来源 CIDR（优先于允许列表，每行一个）'), (r.deny_sources || []).join('\n')); textarea(details, 'allow_destinations', translate('允许目的地（IP/CIDR/域名/*.example.com，留空允许所有未拒绝，每行一个）'), (r.allow_destinations || []).join('\n')); textarea(details, 'deny_destinations', translate('拒绝目的地（优先于允许列表，每行一个）'), (r.deny_destinations || []).join('\n')); textarea(details, 'allow_destination_ports', translate('允许目的地端口（443、8000-8080、*，留空允许所有，每行一个）'), (r.allow_destination_ports || []).join('\n')); textarea(details, 'deny_destination_ports', translate('拒绝目的地端口（优先于允许列表，每行一个）'), (r.deny_destination_ports || []).join('\n')); form.append(details);
  const enabledLabel = el('label', undefined, 'inline-check'), enabled = el('input'); enabled.name = 'enabled'; enabled.type = 'checkbox'; enabled.checked = r.enabled ?? true; enabledLabel.append(enabled, document.createTextNode(translate('启用规则'))); form.append(enabledLabel);
  limits.append(el('p', translate('同一规则的所有连接共享额度和速率。速率桶允许 max(64 KiB, 一秒额度) 的突发；这不是跨节点用户总限速。'), 'fine'));
  async function readRule(data) {
    if (nodeLoad) await nodeLoad;
    if (baseConfig.node_id !== runOn.value) throw new Error(translate('节点配置仍在加载，请稍后再试。'));
    const node = state.nodes.find(n => n.id === baseConfig.node_id), lines = key => String(data.get(key)).split('\n').map(s => s.trim()).filter(Boolean);
    const server = shadowsocks.read(), socks = socks5.read(), http = httpConnect.read(), h2 = http2Connect.read(), wire = gateway.read();
    if ([server, socks, http, h2, wire].filter(Boolean).length > 1) throw new Error(translate('每条规则只能启用一种代理入口'));
    if (h2 && data.get('protocol') !== 'tcp') throw new Error(translate('HTTP/2 CONNECT 必须使用 TCP'));
    const rule = { id: r.id || crypto.randomUUID(), tenant_id: node.tenant_id, owner_id: r.owner_id || state.actor.id, name: data.get('name'), protocol: data.get('protocol'), listen: data.get('listen'), balance: server || socks || http || h2 || wire ? 'weighted_round_robin' : data.get('balance'), enabled: data.get('enabled') === 'on', targets: server || socks || http || h2 || wire ? [] : readTargets(), meter_epoch: data.get('new_meter_period')==='on'?crypto.randomUUID():(r.meter_epoch || crypto.randomUUID()), allow_sources: lines('allow_sources'), deny_sources: lines('deny_sources'), allow_destinations: lines('allow_destinations'), deny_destinations: lines('deny_destinations'), allow_destination_ports: lines('allow_destination_ports'), deny_destination_ports: lines('deny_destination_ports') };
    if (server) rule.inbound_shadowsocks = server;
    else if (socks) rule.inbound_socks5 = socks;
    else if (http) rule.inbound_http_connect = http;
    else if (h2) rule.inbound_http2_connect = h2;
    if (wire) { rule.protocol_gateway = wire; rule.targets = []; rule.listen = gatewayBridge(r, baseConfig.rules, wire.listen); }
    if (!server && !socks && !http && !h2 && !wire) { rule.health_check = readHealth(); Object.assign(rule, multipath.read(readTargets.multipathPaths())); }
    const kernelMultipath = mptcp.read(rule.protocol, !!wire); if (kernelMultipath) rule.mptcp = kernelMultipath;
    rule.advertise = wire ? null : String(data.get('advertise') ?? '').trim() || null;
    rule.listen_end_port = wire ? null : number(data, 'listen_end_port'); rule.port_mapping = data.get('port_mapping') || 'fixed';
    const outboundIp = String(data.get('outbound_ip')).trim(), outboundInterface = String(data.get('outbound_interface')).trim();
    if (outboundIp || outboundInterface) rule.outbound_bind = { ip: outboundIp || null, interface: outboundInterface || null };
    if (data.get('dns_mode') === 'cache') rule.dns_cache = { servers: lines('dns_servers'), capacity: number(data, 'dns_capacity'), max_ttl_secs: number(data, 'dns_max_ttl_secs'), negative_max_ttl_secs: number(data, 'dns_negative_max_ttl_secs') };
    // Hidden for a Shadowsocks server, so absent from the form data.
    const identity = String(data.get('tls_identity') ?? '').trim(), clientCa = String(data.get('tls_client_ca') ?? '').trim();
    if (clientCa && !identity) throw new Error(translate('要求客户端证书时，请同时填写入口证书编号'));
    if (identity) rule.inbound_tls = { identity, client_ca: clientCa || null };
    const websocket = server || h2 || wire ? null : inboundWs.read(); if (websocket) rule.inbound_websocket = websocket;
    if (rule.protocol !== 'tcp' && (websocket || rule.targets.some(target => target.websocket))) throw new Error(translate('WebSocket / WSS 流隧道只支持 TCP，请调整规则协议'));
    if (!wire && data.get('proxy_input_version') !== 'off') rule.inbound_proxy = { version: data.get('proxy_input_version'), trusted_sources: lines('proxy_trusted_sources'), placement: data.get('proxy_input_placement'), max_header_bytes: number(data, 'proxy_header_limit'), accept_prewarmed: data.get('proxy_accept_prewarmed') === 'yes' };
    for (const key of ['quota_bytes', 'rate_bytes_per_sec', 'expires_at_ms', 'connect_timeout_ms', 'idle_timeout_secs', 'max_connections', 'udp_max_sessions']) rule[key] = number(data, key);
    return rule;
  }
  const options = el('details'); options.append(el('summary', translate('配额、端口范围与高级选项')), extraGrid, mptcp.box, routing, transport, inboundWs.box, proxyInput, limits, details);
  form.append(options);
  const pathView = forwardingPathView(); form.append(el('h3', translate('3. 检查并预览发布'), 'setup-step'), pathView.box);
  function redrawPath() {
    const data = new FormData(form), draft = { id: r.id || 'draft', tenant_id: tenant, protocol: protocolControl.value,
      listen: listenControl.value, advertise: purpose.value === 'gateway' ? null : advertise.value, listen_end_port: endPort.value, port_mapping: mapping.value,
      enabled: enabled.checked, targets: purpose.value === 'forward' ? readTargets.preview() : [],
      ...(multipath.mode.value !== 'off' ? { outbound_multipath: {} } : {}),
    };
    const property = { ss: 'inbound_shadowsocks', socks5: 'inbound_socks5', http: 'inbound_http_connect', h2: 'inbound_http2_connect', gateway: 'protocol_gateway' }[purpose.value];
    if (property) draft[property] = { listen: listenControl.value, udp_over_tcp: data.get('ss_uot') === 'yes' };
    if (data.get('tls_identity')) draft.inbound_tls = {};
    if (data.get('inbound-ws-mode') === 'on') draft.inbound_websocket = {};
    pathView.update(forwardingDiagram(topology, { node_id: runOn.value, rule_id: draft.id }, draft));
  }
  form.addEventListener('input', redrawPath); form.addEventListener('change', redrawPath); readTargets.onchange(redrawPath); redrawPath();
  const rulesFor = rule => existing ? baseConfig.rules.map(item => item.id === r.id ? rule : item) : [...baseConfig.rules, rule];
  if (existing) form.append(button(translate('检查配置与路径'), async () => {
    if (!form.reportValidity()) return;
    const rule = await readRule(new FormData(form));
    await previewTopology(topology, { updates: [{ node_id: baseConfig.node_id, expected_revision: baseConfig.revision, rules: rulesFor(rule) }] }, '',
      () => modal(existing ? translate('编辑节点规则') : translate('添加节点规则或代理服务'), form), [{ node_id: baseConfig.node_id, rule_id: rule.id }]);
  }));
  submit(form, existing ? translate('发布修改') : translate('检查并预览发布'), async data => {
    const rule = await readRule(data); state.selectedNode = baseConfig.node_id;
    if (existing) await saveRules(rulesFor(rule), baseConfig);
    else await previewTopology(topology, { updates: [{ node_id: baseConfig.node_id, expected_revision: baseConfig.revision, rules: rulesFor(rule) }] }, placement.textContent,
      () => modal(translate('添加节点规则或代理服务'), form), [{ node_id: baseConfig.node_id, rule_id: rule.id }]);
  }); modal(existing ? translate('编辑节点规则') : translate('添加节点规则或代理服务'), form);
}
const shadowsocksMethods = localize([['2022-blake3-aes-256-gcm', '2022-blake3-aes-256-gcm（推荐 · 防重放）'], ['2022-blake3-aes-128-gcm', '2022-blake3-aes-128-gcm（防重放）'], ['2022-blake3-chacha20-poly1305', '2022-blake3-chacha20-poly1305（无 AES 加速的设备）'], ['aes-256-gcm', 'aes-256-gcm（旧客户端兼容）'], ['aes-128-gcm', 'aes-128-gcm（旧客户端兼容）'], ['chacha20-ietf-poly1305', 'chacha20-ietf-poly1305（旧客户端兼容）']]);
function shadowsocksKey(method) {
  const bytes = crypto.getRandomValues(new Uint8Array(method.includes('128') ? 16 : 32)), text = btoa(String.fromCharCode(...bytes));
  // 2022 methods take a key of exactly this length; older ones a password.
  return method.startsWith('2022-') ? text : text.replace(/[+/=]/g, '').slice(0, 24);
}
function shadowsocksEditor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', translate('Shadowsocks 代理服务（客户端自选目的地）')));
  const method = select(box, 'ss_method', translate('加密方式'), [['off', translate('关闭 · 按下方目标转发')], ...shadowsocksMethods], spec?.method || 'off');
  const fields = el('div', undefined, 'form-grid');
  const password = field(fields, 'ss_password', translate('密钥'), spec?.password || '', 'password'); password.autocomplete = 'off'; password.classList.add('mono');
  select(fields, 'ss_private', translate('允许访问内网 / 本机地址'), [['no', translate('不允许（推荐）')], ['yes', translate('允许 · 客户端可访问本节点所在内网')]], spec?.allow_private_destinations ? 'yes' : 'no');
  select(fields, 'ss_uot', translate('UDP 传输兼容'), [['no', translate('仅原生 UDP')], ['yes', translate('同时支持 UDP over TCP · 适合 UDP 分片受限网络')]], spec ? (spec.udp_over_tcp ? 'yes' : 'no') : 'yes');
  const regenerate = button(translate('生成新密钥'), () => { password.value = shadowsocksKey(method.value); });
  const reveal = button(translate('显示密钥'), () => { password.type = password.type === 'password' ? 'text' : 'password'; reveal.textContent = password.type === 'password' ? translate('显示密钥') : translate('隐藏密钥'); });
  let last = method.value;
  function show() {
    const enabled = method.value !== 'off'; box.querySelectorAll('.ss-fields').forEach(n => n.classList.toggle('hidden', !enabled)); fields.querySelectorAll('input, select').forEach(input => { input.disabled = !enabled; });
    // Key lengths differ between methods; a key that no longer fits is replaced.
    if (enabled && (!password.value || last.startsWith('2022-') !== method.value.startsWith('2022-') || (method.value.startsWith('2022-') && last.includes('128') !== method.value.includes('128')))) password.value = shadowsocksKey(method.value);
    last = method.value;
  }
  const note = el('p', translate('启用后本规则不设目标：客户端（Shadowrocket、Clash、sing-box、v2rayN 等）在每个连接里指定要访问的网站，本节点直接连接。保存后在规则列表点“分享链接”导入客户端。协议选 TCP + UDP 时客户端的 QUIC、DNS、游戏和语音也经过本节点。2022 方式要求两端时钟误差在 30 秒内。'), 'fine');
  fields.classList.add('ss-fields'); regenerate.classList.add('ss-fields'); reveal.classList.add('ss-fields'); note.classList.add('ss-fields');
  box.append(fields, regenerate, reveal, note);
  method.addEventListener('change', show); show();
  return { box, setEnabled(on) { method.value = on ? (method.value === 'off' ? '2022-blake3-aes-256-gcm' : method.value) : 'off'; show(); }, enabled: () => method.value !== 'off', onchange: f => method.addEventListener('change', f), read: () => method.value === 'off' ? null : { method: method.value, password: password.value.trim(), allow_private_destinations: fields.querySelector('[name=ss_private]').value === 'yes', udp_over_tcp: fields.querySelector('[name=ss_uot]').value === 'yes' } };
}
function shadowsocksLink(spec, host, port, tag) {
  const userinfo = spec.method.startsWith('2022-') ? `${encodeURIComponent(spec.method)}:${encodeURIComponent(spec.password)}`
    : btoa(String.fromCharCode(...new TextEncoder().encode(`${spec.method}:${spec.password}`))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `ss://${userinfo}@${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}#${encodeURIComponent(tag)}`;
}
function shareShadowsocks(rule, entry = rule, pathNames = '') {
  const endpoint = clientEndpoint(entry);
  const body = el('div'), grid = el('div', undefined, 'form-grid');
  const host = field(grid, 'host', translate('客户端连接的地址（公网 IP 或域名）'), endpoint.host);
  const port = field(grid, 'port', translate('端口'), endpoint.port, 'number'); port.min = 1; port.max = 65535;
  const tag = field(grid, 'tag', translate('客户端里显示的名称'), entry.name);
  if (pathNames) body.append(el('p', pathNames, 'workflow-callout'));
  body.append(el('p', translate('连接地址来自入口，SS 凭据来自出口。所有节点应用配置后仍须用真实客户端验证。'), 'fine'));
  const formats = [['uri', translate('标准 ss:// 链接 · 原生 UDP')], ['sing_box', translate('sing-box / Relay 客户端 JSON')]];
  const format = select(grid, 'ss_export_format', translate('客户端配置格式'), formats, rule.inbound_shadowsocks.udp_over_tcp ? 'sing_box' : 'uri');
  const link = el('pre', '', 'secret-box mono');
  const update = () => { const endpoint = splitEndpoint(`${host.value.trim().includes(':') ? '[' + host.value.trim().replace(/^\[|\]$/g, '') + ']' : host.value.trim()}:${port.value.trim()}`); link.textContent = !endpoint || endpoint.wildcard ? '' : format.value === 'sing_box' ? JSON.stringify(shadowsocksClientProfile(rule.inbound_shadowsocks, endpoint, tag.value.trim(), rule.protocol), null, 2) : shadowsocksLink(rule.inbound_shadowsocks, endpoint.host, endpoint.port, tag.value.trim()); };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); format.addEventListener('change', update); update();
  body.append(el('p', translate('UDP over TCP 需要双方支持。JSON 配置会启用出口已开放的兼容模式；标准 ss:// 链接仍使用原生 UDP。需要 TCP 半关闭兼容时，请使用随源码提供的 Relay SS 客户端构建。'), 'fine'));
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('关闭对话框'), () => $('#dialog').close()), button(translate('复制客户端配置'), async () => { if (!link.textContent) throw new Error(translate('请填写入口的有效 IP 或域名和端口。')); await navigator.clipboard.writeText(link.textContent); notify(translate('链接已复制。')); }, 'primary'));
  body.append(grid, link, el('p', translate('客户端先连到入口节点再中转到这里时，请填写入口节点的地址和端口。链接包含密钥，持有者即可使用本节点上网，请只发给使用者本人；需要停用时更换密钥或停用规则。'), 'fine'), actions);
  modal(msg`分享 ${rule.name}`, body);
}
async function history() { const baseConfig = state.config; const revisions = await api(`/nodes/${baseConfig.node_id}/history`); const body = table([translate('修订'), translate('操作者'), translate('时间'), translate('操作')], revisions.map(r => [`v${r.revision}`, r.actor_id, timestamp(r.created_at_ms), canWrite() ? button(translate('发布此版本'), async () => { await api(`/nodes/${baseConfig.node_id}/rollback`, { method: 'POST', body: { revision: r.revision, expected_revision: baseConfig.revision } }); $('#dialog').close(); notify(translate('历史配置已作为新修订发布。账本不回滚。')); await renderRules(); }, 'table-action') : translate('只读')])); modal(translate('最近 100 次配置修订'), body); }
function http2ConnectConfig(username, password, hashes, privateMode, streams, socketBuffer = '') {
  const user = username.trim(), digests = hashes.split(/\s+/).filter(Boolean).map(v => v.toLowerCase());
  if (!!user !== !!password) throw new Error(translate('Basic 用户名和密码必须同时填写'));
  if (digests.length > 8 || new Set(digests).size !== digests.length || digests.some(v => !/^[a-f0-9]{64}$/.test(v))) throw new Error(translate('Bearer 需填写最多 8 个不重复的 SHA-256 十六进制摘要'));
  const limit = Number(streams);
  if (!Number.isInteger(limit) || limit < 1 || limit > 4096) throw new Error(translate('HTTP/2 并发隧道上限为 1–4096'));
  const buffer = String(socketBuffer).trim() === '' ? null : Number(socketBuffer);
  if (buffer !== null && (!Number.isInteger(buffer) || buffer < 16384 || buffer > 4194304)) throw new Error(translate('TCP 缓冲请求为 16384–4194304 字节，留空由系统自动调整'));
  return { username: user || null, password: password || null, bearer_token_sha256: digests, allow_private_destinations: privateMode === 'yes', max_concurrent_streams: limit, socket_buffer_bytes: buffer };
}
function http2ConnectEditor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', translate('HTTP/2 CONNECT 入口（TLS / h2c）')));
  const fields = el('div', undefined, 'form-grid');
  const enabled = select(box, 'h2_enabled', translate('HTTP/2 服务'), [['off', translate('关闭')], ['on', translate('启用')]], spec ? 'on' : 'off');
  const username = field(fields, 'h2_user', translate('Basic 用户名（可选）'), spec?.username || '', 'text', false);
  const password = field(fields, 'h2_password', translate('Basic 密码'), spec?.password || '', 'password', false);
  const hashes = textarea(fields, 'h2_hashes', translate('Bearer SHA-256 摘要（每行一个，可同时保留新旧令牌）'), (spec?.bearer_token_sha256 || []).join('\n'));
  const streams = field(fields, 'h2_streams', translate('整条规则的并发隧道上限'), spec?.max_concurrent_streams ?? 128, 'number'); streams.min = 1; streams.max = 4096;
  const socketBuffer = field(fields, 'h2_socket_buffer', translate('每方向 TCP 缓冲请求 / bytes（留空自动，手动值需按实际负载验证）'), spec?.socket_buffer_bytes ?? '', 'number', false); socketBuffer.min = 16384; socketBuffer.max = 4194304;
  const privateMode = select(fields, 'h2_private', translate('内网 / 回环目的地'), [['no', translate('拒绝（推荐）')], ['yes', translate('允许')]], spec?.allow_private_destinations ? 'yes' : 'no');
  const secret = el('pre', '', 'secret-box mono'); secret.hidden = true;
  const generate = button(translate('生成 Bearer 令牌'), async () => {
    if (!crypto.subtle) throw new Error(translate('生成令牌需要 HTTPS 或 localhost 面板连接'));
    if (hashes.value.split(/\s+/).filter(Boolean).length >= 8) throw new Error(translate('请先删除旧摘要，最多保留 8 个'));
    const token = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))), b => b.toString(16).padStart(2, '0')).join('');
    hashes.value = [hashes.value.trim(), digest].filter(Boolean).join('\n'); secret.textContent = token; secret.hidden = false;
  });
  const note = el('p', translate('令牌原文仅在本次对话框显示，请保存后发给客户端。服务器仅保存摘要。删除旧摘要并发布会关闭已有连接。Basic 和 Bearer 都留空时无需认证；身份与计费归属规则所有者。公网使用下方入口 TLS，可选客户端 CA。h2c 仅供受信网络。HTTP/2 客户端必须支持 CONNECT；curl 使用 --proxy-http2。'), 'fine');
  function show() { const on = enabled.value === 'on'; fields.querySelectorAll('input, select, textarea').forEach(v => { v.disabled = !on; }); fields.classList.toggle('hidden', !on); generate.disabled = !on; }
  enabled.addEventListener('change', show); box.append(fields, generate, secret, note); show();
  return { box, setEnabled(on) { enabled.value = on ? 'on' : 'off'; show(); }, enabled: () => enabled.value === 'on', onchange: f => enabled.addEventListener('change', f), read: () => enabled.value === 'on' ? http2ConnectConfig(username.value, password.value, hashes.value, privateMode.value, streams.value, socketBuffer.value) : null };
}
function httpConnectEditor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', translate('HTTP CONNECT 入口（TCP）')));
  const fields = el('div', undefined, 'form-grid');
  const enabled = select(fields, 'http_connect_enabled', translate('HTTP CONNECT 服务'), [['off', translate('关闭 · 按下方目标转发')], ['on', translate('启用 · 客户端指定 CONNECT 目的地')]], spec ? 'on' : 'off');
  const username = field(fields, 'http_connect_user', translate('用户名（留空不认证）'), spec?.username || '', 'text', false); username.maxLength = 255;
  const password = field(fields, 'http_connect_password', translate('密码（与用户名同时填写）'), spec?.password || '', 'password', false); password.maxLength = 255;
  const privateMode = select(fields, 'http_connect_private', translate('允许连接内网/回环目的地'), [['no', translate('拒绝（推荐）')], ['yes', translate('允许')]], spec?.allow_private_destinations ? 'yes' : 'no');
  const note = el('p', translate('只接受 HTTP/1.x CONNECT；其它方法返回 405。启用认证时要求 Proxy-Authorization: Basic。启用后规则不能有固定目标，协议必须为 TCP。'), 'fine');
  function show() { const on = enabled.value === 'on'; username.disabled = password.disabled = !on; privateMode.disabled = !on; note.classList.toggle('hidden', !on); }
  enabled.addEventListener('change', show); show(); box.append(fields, note);
  return { box, setEnabled(on) { enabled.value = on ? 'on' : 'off'; show(); }, enabled: () => enabled.value === 'on', onchange: fn => enabled.addEventListener('change', fn), read: () => {
    if (enabled.value !== 'on') return null;
    const user = username.value.trim(), pass = password.value;
    if (!!user !== !!pass) throw new Error(translate('HTTP CONNECT 用户名和密码必须同时填写或同时留空'));
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
  const endpoint = clientEndpoint(rule);
  const host = field(grid, 'host', translate('客户端连接的地址'), endpoint.host);
  const port = field(grid, 'port', translate('端口'), endpoint.port, 'number');
  const tag = field(grid, 'tag', translate('显示名称'), rule.name);
  const link = el('div', undefined, 'secret-box'); const update = () => { link.textContent = host.value.trim() && splitEndpoint(host.value.trim() + ':' + port.value.trim()) ? httpConnectLink(rule.inbound_http_connect, host.value.trim(), port.value.trim(), tag.value.trim()) : ''; };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('复制链接'), async () => { if (!link.textContent) throw new Error(translate('请填写入口的有效 IP 或域名和端口。')); await navigator.clipboard.writeText(link.textContent); notify(translate('HTTP CONNECT 链接已复制。')); }, 'primary'));
  body.append(grid, link, el('p', translate('链接包含认证信息；这是 HTTP 代理地址，不是普通网页。'), 'fine'), actions);
  modal(msg`分享 ${rule.name}`, body);
}
function socks5Editor(spec) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', translate('SOCKS5 入口（TCP CONNECT）')));
  const fields = el('div', undefined, 'form-grid');
  const enabled = select(fields, 'socks5_enabled', translate('SOCKS5 服务'), [['off', translate('关闭 · 按下方目标转发')], ['on', translate('启用 · 客户端指定目的地')]], spec ? 'on' : 'off');
  const username = field(fields, 'socks5_user', translate('用户名（留空不认证）'), spec?.username || '', 'text', false); username.maxLength = 255;
  const password = field(fields, 'socks5_password', translate('密码（与用户名同时填写）'), spec?.password || '', 'password', false); password.maxLength = 255;
  select(fields, 'socks5_private', translate('允许连接内网/回环目的地'), [['no', translate('拒绝（推荐）')], ['yes', translate('允许')]], spec?.allow_private_destinations ? 'yes' : 'no');
  const note = el('p', translate('支持 TCP CONNECT 与 UDP ASSOCIATE。使用 UDP 时请把协议设为 TCP + UDP；启用后规则不能有固定目标。用户名和密码要么都留空（无认证），要么都填写。分享链接包含密码，请只发给使用者。'), 'fine');
  function show() { const on = enabled.value === 'on'; username.disabled = password.disabled = !on; fields.querySelectorAll('select')[1].disabled = !on; note.classList.toggle('hidden', !on); }
  enabled.addEventListener('change', show); show(); box.append(fields, note);
  return { box, setEnabled(on) { enabled.value = on ? 'on' : 'off'; show(); }, enabled: () => enabled.value === 'on', onchange: fn => enabled.addEventListener('change', fn), read: () => {
    if (enabled.value !== 'on') return null;
    const user = username.value.trim(), pass = password.value;
    if (!!user !== !!pass) throw new Error(translate('SOCKS5 用户名和密码必须同时填写或同时留空'));
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
  const endpoint = clientEndpoint(rule);
  const host = field(grid, 'host', translate('客户端连接的地址'), endpoint.host);
  const port = field(grid, 'port', translate('端口'), endpoint.port, 'number');
  const tag = field(grid, 'tag', translate('显示名称'), rule.name);
  const link = el('div', undefined, 'secret-box'); const update = () => { link.textContent = host.value.trim() && splitEndpoint(host.value.trim() + ':' + port.value.trim()) ? socks5Link(rule.inbound_socks5, host.value.trim(), port.value.trim(), tag.value.trim()) : ''; };
  [host, port, tag].forEach(input => input.addEventListener('input', update)); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('复制链接'), async () => { if (!link.textContent) throw new Error(translate('请填写入口的有效 IP 或域名和端口。')); await navigator.clipboard.writeText(link.textContent); notify(translate('SOCKS5 链接已复制。')); }, 'primary'));
  body.append(grid, link, el('p', translate('链接包含认证信息；需要停用时删除规则或修改用户名/密码。'), 'fine'), actions);
  modal(msg`分享 ${rule.name}`, body);
}
const subscriptionFormats = localize({ sing_box: 'sing-box JSON（SS 与受管协议）', v2ray: 'V2Ray / Base64（ss:// 列表）', clash: 'mihomo / Clash Meta（YAML）', surge: 'Surge（Shadowsocks 文本）', shadowrocket: 'Shadowrocket（ss:// 列表）' });
const dnsModes = localize({ observe: '观察（只读，不写服务商）', apply: '应用（创建/更新/删除托管记录）' });
const dnsRecordTypes = ['A', 'AAAA', 'CNAME'];
const announcementSeverities = localize({ info: '信息', warning: '警告', critical: '严重' });
function announcementTime(ms) { return timestamp(ms); }
function announcementDateTime(ms) { const d = new Date(ms || Date.now()); const pad = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
const ticketStatuses = localize({ open: '待处理', pending: '处理中', closed: '已关闭' });
const ticketPriorities = localize({ low: '低', normal: '普通', high: '高' });
async function renderTemplates() {
  const [templates, nodes] = await Promise.all([api('/templates'), api('/nodes')]); state.nodes = nodes;
  const starters = panel(translate('选择一个起点'), translate('内置模板会打开配置向导。填写实际 VPS、端口和目标后，先预览再发布。'));
  starters.append(setupCards());
  const p = panel(translate('我的规则模板'), translate('从节点规则保存的可复用配置。应用时生成新的规则身份与计量周期，并校验端口和引用。'), null);
  if (!templates.length) p.append(empty(translate('还没有自定义模板'), translate('上方内置模板可以直接使用。配置好规则后，点击“存为模板”即可在这里复用。')));
  else p.append(table([translate('名称'), translate('范围'), translate('说明'), translate('源监听'), translate('操作')], templates.map(template => {
    const actions = el('div'); if (state.actor.role !== 'viewer') { actions.append(button(translate('使用此模板'), () => applyTemplate(template), 'table-action')); actions.append(button(translate('批量应用'), () => rolloutTemplate(template), 'table-action')); actions.append(button(translate('版本'), () => templateVersions(template), 'table-action')); actions.append(button(translate('差异'), () => templateDiff(template), 'table-action')); }
    if (state.actor.role === 'system_admin' || template.tenant_id === state.actor.tenant_id) actions.append(button(translate('删除'), () => deleteTemplate(template), 'table-action danger'));
    return [namedCell(template.name, template.id), template.tenant_id || translate('全局'), template.description || '—', template.rule.protocol_gateway?.listen || template.rule.listen, actions];
  })));
  if (state.view === 'templates') $('#content').replaceChildren(starters, p);
}
async function saveTemplate(source) {
  const name = await promptValue(translate('模板名称'), source.name); if (!name) return;
  const description = await promptValue(translate('模板说明（可留空）'), ''); if (description === null) return;
  const tenant_id = state.actor.role === 'system_admin' ? null : state.actor.tenant_id;
  await api('/templates', { method: 'POST', body: { tenant_id, name, description, rule: source } });
  await navigate('templates'); notify(translate('规则已保存为模板。'));
}
async function deleteTemplate(template) {
  if (!await confirmAction(msg`删除模板「${template.name}」？`)) return;
  await api(`/templates/${template.id}`, { method: 'DELETE' }); notify(translate('模板已删除。')); await renderTemplates();
}
async function templateDiff(template) {
  const from = await promptValue(translate('旧版本号'), '1');
  if (!from) return;
  const to = await promptValue(translate('新版本号'), String(template.version));
  if (!to) return;
  const diff = await api(`/templates/${template.id}/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  const content = el('div');
  if (!diff.changes.length) content.append(el('p', translate('两个版本内容相同。'), 'fine'));
  const list = el('div', undefined, 'version-list');
  for (const change of diff.changes) {
    const row = el('div', undefined, 'version-row');
    row.append(el('code', change.path), el('span', `${JSON.stringify(change.from)} → ${JSON.stringify(change.to)}`));
    list.append(row);
  }
  content.append(list); modal(msg`差异 · ${template.name}`, content);
}

async function templateVersions(template) {
  const versions = await api(`/templates/${template.id}/versions`);
  const content = el('div'); content.append(el('p', msg`当前版本 ${template.version}；保留 ${versions.length} 个版本。`, 'fine'));
  const list = el('div', undefined, 'version-list');
  for (const version of versions) {
    const row = el('div', undefined, 'version-row');
    row.append(el('span', `v${version.version} · ${version.name}`));
    if (version.version < template.version && (state.actor.role === 'system_admin' || template.tenant_id === state.actor.tenant_id)) row.append(button(translate('回滚'), async () => {
      const rolled = await api(`/templates/${template.id}/versions/${version.version}/rollback`, { method: 'POST' });
      $('#dialog').close(); renderTemplates(); modal(translate('已回滚'), el('pre', JSON.stringify(rolled, null, 2), 'json-preview'));
    }, 'table-action'));
    list.append(row);
  }
  content.append(list); modal(msg`版本 · ${template.name}`, content);
}

async function rolloutTemplate(template) {
  const snapshot = await api('/topology'); const nodes = snapshot.nodes;
  if (!nodes.length) throw new Error(translate('先注册节点，再创建规则。')); const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'batch_size', translate('每批节点数（1–50）'), '1', 'number');
  field(grid, 'canary_percent', translate('首批百分比（留空使用批大小）'), '', 'number', false);
  field(grid, 'wait_for_apply_ms', translate('应用回执等待 / ms（留空不等待）'), '', 'number', false);
  const rollback = el('label'); rollback.append(el('span', translate('失败时移除本次已发布规则')), Object.assign(el('input'), { type: 'checkbox', name: 'rollback_on_failure' })); grid.append(rollback);
  const healthy = el('label'); healthy.append(el('span', translate('仅健康节点（90 秒内有同步且无应用错误）')), Object.assign(el('input'), { type: 'checkbox', name: 'require_healthy' })); grid.append(healthy);
  const targetHealth = el('label'); targetHealth.append(el('span', translate('目标健康门控（本次修订与规则的有效健康报告）')), Object.assign(el('input'), { type: 'checkbox', name: 'require_target_health' })); grid.append(targetHealth);
  const targets = textarea(grid, 'targets', translate('目标 JSON（node_id/expected_revision/name/listen 数组）'),
    JSON.stringify(nodes.slice(0, 1).map(n => ({ node_id: n.id, expected_revision: snapshot.configs.find(c => c.node_id === n.id).revision, name: template.name, listen: '127.0.0.1:9000' })), null, 2));
  targets.rows = 10;
  form.append(grid, el('p', translate('按顺序分批应用；某批失败后停止后续批次，成功节点仍保留，并返回每个节点的结果。'), 'fine'));
  submit(form, translate('开始批量应用'), async data => {
    const parsed = JSON.parse(String(data.get('targets')));
    const report = await api(`/templates/${template.id}/rollout`, { method: 'POST', body: { batch_size: Number(data.get('batch_size')), canary_percent: data.get('canary_percent') ? Number(data.get('canary_percent')) : null, require_healthy: data.get('require_healthy') === 'on', require_target_health: data.get('require_target_health') === 'on', wait_for_apply_ms: data.get('wait_for_apply_ms') ? Number(data.get('wait_for_apply_ms')) : null, rollback_on_failure: data.get('rollback_on_failure') === 'on', targets: parsed } });
    $('#dialog').close();
    const content = el('div');
    const renderReport = current => {
      content.replaceChildren(el('p', translate('applied 表示已发布；acknowledged 表示已回执；healthy 表示健康合格；completed 表示通过所选门控。'), 'fine'), el('pre', JSON.stringify(current, null, 2), 'json-preview'));
      if (current.aborted) content.append(button(translate('重新检查并继续批量'), async () => {
        const retry = await api(`/templates/${template.id}/rollouts/${current.id}/retry`, { method: 'POST' });
        renderReport(retry);
      }));
    };
    renderReport(report);
    modal(msg`批量结果 · ${template.name}`, content);
  });
  modal(msg`批量应用 · ${template.name}`, form);
}

async function applyTemplate(template) {
  const nodes = state.nodes; if (!nodes.length) throw new Error(translate('先注册节点，再创建规则。')); const form = el('form'), grid = el('div', undefined, 'form-grid');
  const node = select(grid, 'node', translate('节点'), nodes.map(n => [n.id, n.name || n.id]), nodes[0]?.id);
  field(grid, 'name', translate('新规则名称'), template.name).maxLength = 120;
  field(grid, 'listen', translate('监听地址'), '127.0.0.1:9000');
  const advertise = field(grid, 'advertise', translate('客户端 / 上一跳连接地址（VPS 公网 IP 或域名:端口）'), '', 'text', false); advertise.placeholder = 'vps.example.com:9000';
  advertise.disabled = !!template.rule.protocol_gateway;
  form.append(grid, el('p', translate('保留模板的目标与策略；请填写这台 VPS 的新监听和可达地址。下一步检查完整路径，不会立即发布。'), 'fine'));
  submit(form, translate('检查并预览发布'), async data => {
    const snapshot = await api('/topology'), config = snapshot.configs.find(config => config.node_id === node.value);
    if (!config) throw new Error(translate('配置已变化，请重新检查模板。'));
    const preview = await api(`/nodes/${node.value}/templates/${template.id}/preview`, { method: 'POST', body: { name: String(data.get('name')).trim(), listen: String(data.get('listen')).trim() } });
    if (preview.current_revision !== config.revision) throw new Error(translate('配置已变化，请重新检查模板。'));
    const rule = { ...preview.rule, advertise: advertise.disabled ? null : advertise.value.trim() || null };
    state.selectedNode = node.value;
    await previewTopology(snapshot, { updates: [{ node_id: node.value, expected_revision: config.revision, rules: [...config.rules, rule] }] }, '',
      () => modal(msg`应用模板 · ${template.name}`, form), [{ node_id: node.value, rule_id: rule.id }]);
  });
  modal(msg`应用模板 · ${template.name}`, form);
}

async function renderTickets() {
  const tickets = await api('/tickets');
  const p = panel(translate('工单'), state.actor.role === 'system_admin' ? translate('系统管理员可查看全部租户工单。') : state.actor.role === 'tenant_admin' ? translate('租户管理员可查看本租户工单并添加内部备注。') : translate('你只能看到自己提交的工单。'), button(translate('＋ 新建工单'), ticketForm, 'primary'));
  if (!tickets.length) p.append(empty(translate('没有工单'), translate('遇到问题时提交工单，管理员回复后会在这里显示。')));
  else p.append(table([translate('主题'), translate('状态'), translate('优先级'), translate('更新'), translate('操作')], tickets.map(ticket => {
    const actions = el('div'); actions.append(button(translate('查看/回复'), () => openTicket(ticket.id), 'table-action'));
    return [namedCell(ticket.subject, ticket.id), badge(ticketStatuses[ticket.status] || ticket.status, ticket.status === 'closed' ? '' : ticket.status === 'open' ? 'orange' : 'green'), ticketPriorities[ticket.priority] || ticket.priority, timestamp(ticket.updated_at_ms), actions];
  })));
  $('#content').replaceChildren(p);
}
function ticketForm() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'subject', translate('主题'), '').maxLength = 200;
  textarea(grid, 'body', translate('问题描述'), '').maxLength = 10000;
  select(grid, 'priority', translate('优先级'), Object.entries(ticketPriorities), 'normal');
  form.append(grid);
  submit(form, translate('提交工单'), async data => {
    await api('/tickets', { method: 'POST', body: { subject: String(data.get('subject')).trim(), body: String(data.get('body')), priority: data.get('priority') } });
    $('#dialog').close(); notify(translate('工单已提交。')); await renderTickets();
  });
  modal(translate('新建工单'), form);
}
async function openTicket(id) {
  const view = await api(`/tickets/${id}`), t = view.ticket;
  const body = el('div');
  body.append(el('div', `${ticketStatuses[t.status] || t.status} · ${ticketPriorities[t.priority] || t.priority} · ${timestamp(t.created_at_ms)}`, 'muted'));
  const thread = el('div', undefined, 'ticket-thread');
  for (const message of view.messages) {
    const item = el('div', undefined, `ticket-message${message.internal ? ' internal' : ''}`);
    item.append(el('div', `${message.author_id === state.actor.id ? translate('我') : message.author_id}${message.internal ? translate(' · 内部备注') : ''}`, 'muted'), el('p', message.body));
    thread.append(item);
  }
  body.append(thread);
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  const reply = textarea(grid, 'reply', translate('回复内容'), ''); reply.maxLength = 10000;
  const internal = state.actor.role !== 'viewer' ? checkbox(grid, 'internal', translate('内部备注（仅管理员可见）')) : null;
  const actions = el('div', undefined, 'dialog-actions');
  if (t.status !== 'closed') {
    const send = button(translate('发送回复'), async () => {
      if (!reply.value.trim()) throw new Error(translate('请输入回复内容'));
      await api(`/tickets/${id}/messages`, { method: 'POST', body: { body: reply.value, internal: !!internal?.checked } });
      $('#dialog').close(); notify(translate('回复已发送。')); await renderTickets();
    }, 'primary'); actions.append(send);
    if (state.actor.role !== 'viewer') actions.append(button(translate('标记处理中'), async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'pending' } }); $('#dialog').close(); await renderTickets(); }, 'table-action'));
  }
  if (t.status !== 'closed') actions.append(button(translate('关闭工单'), async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'closed' } }); $('#dialog').close(); notify(translate('工单已关闭。')); await renderTickets(); }, 'table-action danger'));
  else if (state.actor.role !== 'viewer') actions.append(button(translate('重新打开'), async () => { await api(`/tickets/${id}/status`, { method: 'PUT', body: { status: 'open' } }); $('#dialog').close(); await renderTickets(); }, 'table-action'));
  form.append(grid, actions); body.append(form);
  modal(msg`工单 · ${t.subject}`, body);
}
const orderStatuses = localize({ pending: '待支付', paid: '已支付', refunded: '已退款' });
const orderChannels = localize({ wallet: '钱包', external: '外部支付' });
const ledgerKinds = localize({ adjustment: '调整', credit: '充值', purchase: '购买', refund: '退款' });
function money(cents) { return `¥${(cents / 100).toFixed(2)}`; }
async function renderCommerce() {
  const [wallet, plans, orders] = await Promise.all([api('/commerce/wallet'), api('/commerce/plans'), api('/commerce/orders')]);
  const webhook = state.actor.role === 'system_admin' ? await api('/commerce/webhook') : null;
  const coupons = state.actor.role === 'system_admin' ? await api('/commerce/coupons') : [];
  const gifts = state.actor.role === 'system_admin' ? await api('/commerce/gift-codes') : [];
  const walletActions = el('div'); walletActions.append(button(translate('兑换礼品码'), redeemGift, 'primary'));
  if (state.actor.role === 'system_admin') walletActions.append(button(translate('调整用户钱包'), adjustWallet, 'table-action'));
  const p = panel(translate('钱包'), msg`余额 ${money(wallet.wallet.balance_cents)} · ${wallet.wallet.currency}。余额可通过管理员调整、退款或礼品码入账；购买会即时扣款。`, walletActions);
  p.append(table([translate('金额'), translate('类型'), translate('说明'), translate('引用'), translate('时间')], wallet.entries.map(entry => [money(entry.delta_cents), ledgerKinds[entry.kind] || entry.kind, entry.description, entry.reference, timestamp(entry.created_at_ms)])));
  if (!wallet.entries.length) p.append(el('p', translate('还没有资金流水。'), 'muted'));
  const plansPanel = panel(translate('套餐'), translate('价格以人民币分保存；购买订单保存套餐快照，后续改价不影响已创建订单。'), state.actor.role === 'system_admin' ? button(translate('＋ 新建套餐'), () => planForm(null), 'primary') : null);
  if (!plans.length) plansPanel.append(empty(translate('暂无可用套餐'), translate('管理员创建并启用套餐后，用户可以创建订单。')));
  else plansPanel.append(table([translate('套餐'), translate('说明'), translate('价格'), translate('时长'), translate('流量'), translate('操作')], plans.map(plan => {
    const actions = el('div'); actions.append(button(translate('钱包购买'), () => buyPlan(plan), 'table-action'), button(translate('创建待支付订单'), () => createPendingOrder(plan), 'table-action'));
    if (state.actor.role === 'system_admin') actions.append(button(translate('编辑'), () => planForm(plan), 'table-action'), button(translate('删除'), () => deletePlan(plan), 'table-action danger'));
    return [namedCell(plan.name, plan.id), plan.description || '—', money(plan.price_cents), msg`${plan.duration_days} 天`, plan.traffic_bytes ? bytes(plan.traffic_bytes) : translate('不限'), actions];
  })));
  const ordersPanel = panel(translate('订单'), translate('订单只记录计费结果；套餐权益的自动发放/到期执行仍未实现。'), null);
  if (!orders.length) ordersPanel.append(empty(translate('还没有订单'), translate('选择套餐购买后会生成订单。')));
  else ordersPanel.append(table([translate('套餐'), translate('金额'), translate('状态'), translate('通道'), translate('创建'), translate('支付/退款'), translate('操作')], orders.map(order => {
    const actions = el('div');
    if (order.status === 'pending') actions.append(button(translate('钱包支付'), async () => { await api(`/commerce/orders/${order.id}/pay`, { method: 'POST' }); notify(translate('订单已支付。')); await renderCommerce(); }, 'table-action'), button(translate('外部支付'), () => externalPayment(order), 'table-action'));
    if (order.status === 'paid' && order.channel === 'wallet' && state.actor.role === 'system_admin') actions.append(button(translate('退款'), async () => { if (!await confirmAction(msg`退款 ${money(order.amount_cents)} 到用户钱包？`)) return; await api(`/commerce/orders/${order.id}/refund`, { method: 'POST' }); notify(translate('订单已退款。')); await renderCommerce(); }, 'table-action danger'));
    return [order.plan_name, money(order.amount_cents), badge(orderStatuses[order.status] || order.status, order.status === 'paid' ? 'green' : order.status === 'refunded' ? 'orange' : ''), orderChannels[order.channel] || order.channel || translate('钱包'), timestamp(order.created_at_ms), order.paid_at_ms ? timestamp(order.paid_at_ms) : order.refunded_at_ms ? timestamp(order.refunded_at_ms) : '—', actions];
  })));
  const panels = [p, plansPanel, ordersPanel];
  if (state.actor.role === 'system_admin') {
    const g = panel(translate('礼品码'), translate('用户兑换后直接增加钱包余额；同一用户同一码只能兑换一次，次数上限和窗口仍然生效。'), button(translate('＋ 新建礼品码'), () => giftForm(null), 'primary'));
    if (!gifts.length) g.append(empty(translate('还没有礼品码'), translate('创建后可让用户兑换。')));
    else g.append(table([translate('代码'), translate('金额'), translate('已用'), translate('状态'), translate('操作')], gifts.map(gift => { const actions = el('div'); actions.append(button(translate('编辑'), () => giftForm(gift), 'table-action'), button(translate('删除'), () => deleteGift(gift), 'table-action danger')); return [gift.code, money(gift.amount_cents), `${gift.redeemed}${gift.max_redemptions ? ' / ' + gift.max_redemptions : ''}`, gift.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), ''), actions]; })));
    panels.push(g);
    const c = panel(translate('优惠码'), translate('百分比按订单原价向下取整；固定金额不超过原价。订单保存原价、折扣和最终金额快照。'), button(translate('＋ 新建优惠码'), () => couponForm(null), 'primary'));
    if (!coupons.length) c.append(empty(translate('还没有优惠码'), translate('创建后可让用户在创建订单时输入。')));
    else c.append(table([translate('代码'), translate('类型'), translate('优惠'), translate('最低原价'), translate('已用'), translate('状态'), translate('操作')], coupons.map(coupon => { const actions = el('div'); actions.append(button(translate('编辑'), () => couponForm(coupon), 'table-action'), button(translate('删除'), () => deleteCoupon(coupon), 'table-action danger')); return [coupon.code, coupon.kind === 'percent' ? translate('百分比') : translate('固定金额'), coupon.kind === 'percent' ? `${coupon.value}%` : money(coupon.value), money(coupon.min_amount_cents), `${coupon.redeemed}${coupon.max_redemptions ? ' / ' + coupon.max_redemptions : ''}`, coupon.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), ''), actions]; })));
    panels.push(c);
  }
  if (webhook) {
    const w = panel(translate('支付回调'), translate('外部支付回调使用 HMAC-SHA256 验证原始请求体；配置/轮换密钥会使旧签名失效。'), button(translate('配置回调密钥'), webhookForm, 'primary'));
    w.append(table([translate('状态'), translate('密钥')], [[webhook.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), ''), webhook.secret_set ? badge(translate('已设置'), 'green') : badge(translate('未设置'), 'red')]]));
    panels.push(w);
  }
  $('#content').replaceChildren(...panels);
}
function redeemGift() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', translate('礼品码'), '').maxLength = 32;
  form.append(grid, el('p', translate('兑换成功后金额立即进入钱包，并生成一条“充值”流水。每个用户每个码只能兑换一次。'), 'fine'));
  submit(form, translate('兑换'), async data => {
    const wallet = await api('/commerce/gift-codes/redeem', { method: 'POST', body: { code: String(data.get('code')).trim() } });
    $('#dialog').close(); notify(msg`已兑换，当前余额 ${money(wallet.balance_cents)}。`); await renderCommerce();
  });
  modal(translate('兑换礼品码'), form);
}
function giftForm(gift) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', translate('代码（6..32，字母数字/ - _）'), gift?.code || '').maxLength = 32;
  field(grid, 'amount', translate('金额（元）'), gift ? (gift.amount_cents / 100).toFixed(2) : '0.00', 'number').step = '0.01';
  field(grid, 'max', translate('最多兑换次数（留空不限）'), gift?.max_redemptions ?? '', 'number', false).min = 1;
  select(grid, 'enabled', translate('状态'), [['yes', translate('启用')], ['no', translate('停用')]], gift?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', translate('礼品码创建后立即生效；每个用户每个码只能兑换一次。已有兑换时不能删除，只能停用。'), 'fine'));
  submit(form, gift ? translate('保存礼品码') : translate('创建礼品码'), async data => {
    const body = { code: String(data.get('code')).trim(), amount_cents: Math.round(Number(data.get('amount')) * 100), max_redemptions: number(data, 'max'), enabled: data.get('enabled') === 'yes' };
    if (!(body.amount_cents > 0)) throw new Error(translate('礼品金额必须大于 0'));
    if (gift) await api(`/commerce/gift-codes/${gift.id}`, { method: 'PUT', body });
    else await api('/commerce/gift-codes', { method: 'POST', body });
    $('#dialog').close(); notify(translate('礼品码已保存。')); await renderCommerce();
  });
  modal(gift ? msg`编辑礼品码 · ${gift.code}` : translate('新建礼品码'), form);
}
async function deleteGift(gift) {
  if (!await confirmAction(msg`删除礼品码「${gift.code}」？已有兑换时会被拒绝。`)) return;
  await api(`/commerce/gift-codes/${gift.id}`, { method: 'DELETE' }); notify(translate('礼品码已删除。')); await renderCommerce();
}
async function buyPlan(plan) {
  const coupon = await promptValue(translate('优惠码（可留空）')); if (coupon === null) return;
  if (!await confirmAction(msg`购买「${plan.name}」并立即从钱包扣款？`)) return;
  const order = await api('/commerce/orders', { method: 'POST', body: { plan_id: plan.id, coupon_code: coupon.trim() || null } });
  await api(`/commerce/orders/${order.id}/pay`, { method: 'POST' });
  notify(translate('订单已支付。')); await renderCommerce();
}
async function createPendingOrder(plan) {
  const coupon = await promptValue(translate('优惠码（可留空）')); if (coupon === null) return;
  await api('/commerce/orders', { method: 'POST', body: { plan_id: plan.id, coupon_code: coupon.trim() || null } });
  notify(translate('订单已创建，可在订单中选择钱包或外部支付。')); await renderCommerce();
}
function couponForm(coupon) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'code', translate('代码（3..32，字母数字/ - _）'), coupon?.code || '').maxLength = 32;
  select(grid, 'kind', translate('类型'), [['percent', translate('百分比')], ['fixed', translate('固定金额（元）')]], coupon?.kind || 'percent');
  const value = field(grid, 'value', translate('优惠值（百分比或元）'), coupon ? (coupon.kind === 'percent' ? coupon.value : coupon.value / 100) : '', 'number'); value.step = '0.01'; value.min = 0;
  field(grid, 'min', translate('最低原价（元）'), coupon ? (coupon.min_amount_cents / 100).toFixed(2) : '0.00', 'number').step = '0.01';
  field(grid, 'max', translate('最多使用次数（留空不限）'), coupon?.max_redemptions ?? '', 'number', false).min = 1;
  select(grid, 'enabled', translate('状态'), [['yes', translate('启用')], ['no', translate('停用')]], coupon?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', translate('优惠码创建后立即可用；窗口从创建时开始，暂不提供定时窗口编辑。已有订单不会重新计算。'), 'fine'));
  submit(form, coupon ? translate('保存优惠码') : translate('创建优惠码'), async data => {
    const kind = String(data.get('kind')), raw = Number(data.get('value'));
    const body = { code: String(data.get('code')).trim(), kind, value: kind === 'percent' ? Math.round(raw) : Math.round(raw * 100), min_amount_cents: Math.round(Number(data.get('min')) * 100), max_redemptions: number(data, 'max'), enabled: data.get('enabled') === 'yes' };
    if (kind === 'percent' && !(body.value >= 1 && body.value <= 100)) throw new Error(translate('百分比须为 1..100'));
    if (kind === 'fixed' && !(body.value > 0)) throw new Error(translate('固定金额须大于 0'));
    if (coupon) await api(`/commerce/coupons/${coupon.id}`, { method: 'PUT', body });
    else await api('/commerce/coupons', { method: 'POST', body });
    $('#dialog').close(); notify(translate('优惠码已保存。')); await renderCommerce();
  });
  modal(coupon ? msg`编辑优惠码 · ${coupon.code}` : translate('新建优惠码'), form);
}
async function deleteCoupon(coupon) {
  if (!await confirmAction(msg`删除优惠码「${coupon.code}」？已有使用时会被拒绝。`)) return;
  await api(`/commerce/coupons/${coupon.id}`, { method: 'DELETE' }); notify(translate('优惠码已删除。')); await renderCommerce();
}
async function externalPayment(order) {
  const payment = await api(`/commerce/orders/${order.id}/payment`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', translate('把以下付款编号交给支付网关；网关回调必须携带对原始 JSON 的 HMAC-SHA256 签名。回调成功后订单变为已支付，但不会增加钱包余额。'), 'fine'));
  body.append(el('div', payment.id, 'secret-box'), el('p', msg`回调地址：/api/v1/commerce/payments/callback`, 'mono'), el('p', msg`金额：${money(payment.amount_cents)} · 状态：${payment.status}`, 'mono'));
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('复制付款编号'), async () => { await navigator.clipboard.writeText(payment.id); notify(translate('付款编号已复制。')); }, 'primary'), button(translate('关闭对话框'), () => $('#dialog').close()));
  body.append(actions); modal(msg`外部支付 · ${order.plan_name}`, body);
}
function webhookForm() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'secret', translate('新 HMAC 密钥（至少 16 字节）'), '', 'password').maxLength = 512;
  select(grid, 'enabled', translate('回调状态'), [['yes', translate('启用')], ['no', translate('停用')]], 'yes');
  form.append(grid, el('p', translate('密钥只用于验证回调，不在接口返回原文。回调头为 X-Relay-Signature，值为原始请求体的 HMAC-SHA256 十六进制（可带 sha256= 前缀）。'), 'fine'));
  submit(form, translate('保存密钥'), async data => {
    await api('/commerce/webhook', { method: 'PUT', body: { secret: String(data.get('secret')), enabled: data.get('enabled') === 'yes' } });
    $('#dialog').close(); notify(translate('支付回调密钥已保存。')); await renderCommerce();
  });
  modal(translate('配置支付回调'), form);
}
function planForm(plan) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('套餐名称'), plan?.name || '').maxLength = 120;
  textarea(grid, 'description', translate('说明'), plan?.description || '').maxLength = 5000;
  const price = field(grid, 'price', translate('价格（元）'), plan ? (plan.price_cents / 100).toFixed(2) : '0.00', 'number'); price.min = 0; price.step = '0.01';
  const days = field(grid, 'days', translate('时长 / 天'), plan?.duration_days ?? 30, 'number'); days.min = 1; days.max = 3650;
  field(grid, 'traffic', translate('流量 / bytes（留空不限）'), plan?.traffic_bytes ?? '', 'number', false).min = 1;
  select(grid, 'enabled', translate('状态'), [['yes', translate('启用')], ['no', translate('停用')]], plan?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', translate('价格转换为人民币分保存；已有订单使用创建时快照。'), 'fine'));
  submit(form, plan ? translate('保存套餐') : translate('创建套餐'), async data => {
    const body = { name: String(data.get('name')).trim(), description: String(data.get('description')), price_cents: Math.round(Number(data.get('price')) * 100), duration_days: number(data, 'days'), traffic_bytes: number(data, 'traffic'), enabled: data.get('enabled') === 'yes' };
    if (!Number.isSafeInteger(body.price_cents) || body.price_cents < 0) throw new Error(translate('价格无效'));
    if (plan) await api(`/commerce/plans/${plan.id}`, { method: 'PUT', body });
    else await api('/commerce/plans', { method: 'POST', body });
    $('#dialog').close(); notify(translate('套餐已保存。')); await renderCommerce();
  });
  modal(plan ? msg`编辑套餐 · ${plan.name}` : translate('新建套餐'), form);
}
async function deletePlan(plan) {
  if (!await confirmAction(msg`删除套餐「${plan.name}」？已有订单时会被拒绝。`)) return;
  await api(`/commerce/plans/${plan.id}`, { method: 'DELETE' }); notify(translate('套餐已删除。')); await renderCommerce();
}
function adjustWallet() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'user_id', translate('用户 ID'), '', 'text').maxLength = 120;
  const delta = field(grid, 'delta', translate('调整金额（元，正数入账/负数扣款）'), '', 'number'); delta.step = '0.01';
  field(grid, 'reference', translate('幂等引用（唯一，如 bank-2026-001）'), '', 'text').maxLength = 120;
  field(grid, 'description', translate('说明'), '', 'text', false).maxLength = 500;
  form.append(grid, el('p', translate('同一引用只能入账一次；余额不得为负。此操作只调整钱包，不创建订单或发放权益。'), 'fine'));
  submit(form, translate('调整钱包'), async data => {
    const body = { delta_cents: Math.round(Number(data.get('delta')) * 100), reference: String(data.get('reference')).trim(), description: String(data.get('description')) };
    if (!Number.isSafeInteger(body.delta_cents) || body.delta_cents === 0) throw new Error(translate('调整金额无效'));
    await api(`/commerce/wallets/${String(data.get('user_id')).trim()}/adjust`, { method: 'POST', body });
    $('#dialog').close(); notify(translate('钱包已调整。')); await renderCommerce();
  });
  modal(translate('调整用户钱包'), form);
}

async function renderAnnouncements() {
  const active = await api('/announcements');
  const canManage = state.actor.role !== 'viewer';
  const managed = canManage ? await api('/announcements/manage') : [];
  const p = panel(translate('当前公告'), translate('只显示已启用且处于发布窗口内的公告；全局公告对所有租户可见。'), canManage ? button(translate('＋ 新建公告'), () => announcementForm(null), 'primary') : null);
  if (!active.length) p.append(empty(translate('没有生效中的公告'), translate('管理员可以创建全局或租户范围内的维护、变更和安全公告。')));
  else p.append(table([translate('级别'), translate('标题'), translate('内容'), translate('生效时间')], active.map(item => [badge(announcementSeverities[item.severity], item.severity === 'critical' ? 'red' : item.severity === 'warning' ? 'orange' : 'green'), item.title, item.body, `${announcementTime(item.starts_at_ms)}${item.ends_at_ms ? ' → ' + announcementTime(item.ends_at_ms) : ''}`])));
  const page = el('div'); page.append(p);
  if (canManage) {
    const m = panel(translate('公告管理'), translate('租户管理员只能编辑/删除本租户公告；全局公告只读。'), null);
    if (!managed.length) m.append(empty(translate('还没有公告'), translate('新建一条公告后，用户会在发布窗口内看到。')));
    else m.append(table([translate('范围'), translate('级别'), translate('标题'), translate('开始'), translate('结束'), translate('状态'), translate('操作')], managed.map(item => {
      const actions = el('div');
      const editable = state.actor.role === 'system_admin' || item.tenant_id === state.actor.tenant_id;
      if (editable) actions.append(button(translate('编辑'), () => announcementForm(item), 'table-action'), button(translate('删除'), () => deleteAnnouncement(item), 'table-action danger'));
      else actions.append(el('span', translate('只读'), 'muted'));
      return [item.tenant_id || translate('全局'), announcementSeverities[item.severity], item.title, announcementTime(item.starts_at_ms), item.ends_at_ms ? announcementTime(item.ends_at_ms) : translate('长期'), item.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), '') , actions];
    })));
    page.append(m);
  }
  $('#content').replaceChildren(page);
}
function announcementForm(item) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'title', translate('标题'), item?.title || '').maxLength = 200;
  textarea(grid, 'body', translate('内容（最多 10000 字节）'), item?.body || '').maxLength = 10000;
  select(grid, 'severity', translate('级别'), Object.entries(announcementSeverities), item?.severity || 'info');
  const tenant = field(grid, 'tenant_id', translate('租户 ID（留空为全局；租户管理员必须填写自己的租户）'), item?.tenant_id || '', 'text', false); tenant.maxLength = 120;
  const starts = field(grid, 'starts', translate('开始时间（本地）'), announcementDateTime(item?.starts_at_ms), 'datetime-local'); starts.required = true;
  const ends = field(grid, 'ends', translate('结束时间（本地，留空长期）'), item?.ends_at_ms ? announcementDateTime(item.ends_at_ms) : '', 'datetime-local', false);
  select(grid, 'enabled', translate('状态'), [['yes', translate('启用')], ['no', translate('停用')]], item?.enabled === false ? 'no' : 'yes');
  form.append(grid, el('p', translate('全局公告只有系统管理员可以创建；租户管理员只能发布到自己的租户。时间按浏览器本地时区输入，服务端保存 Unix 毫秒。'), 'fine'));
  submit(form, item ? translate('保存公告') : translate('发布公告'), async data => {
    const body = {
      title: String(data.get('title')).trim(),
      body: String(data.get('body')),
      severity: data.get('severity'),
      tenant_id: String(data.get('tenant_id') || '').trim() || null,
      starts_at_ms: new Date(String(data.get('starts'))).getTime(),
      ends_at_ms: String(data.get('ends') || '') ? new Date(String(data.get('ends'))).getTime() : null,
      enabled: data.get('enabled') === 'yes'
    };
    if (!Number.isFinite(body.starts_at_ms) || (body.ends_at_ms !== null && !Number.isFinite(body.ends_at_ms))) throw new Error(translate('时间格式无效'));
    if (item) await api(`/announcements/${item.id}`, { method: 'PUT', body });
    else await api('/announcements', { method: 'POST', body });
    $('#dialog').close(); notify(translate('公告已保存。')); await renderAnnouncements();
  });
  modal(item ? msg`编辑公告 · ${item.title}` : translate('新建公告'), form);
}
async function deleteAnnouncement(item) {
  if (!await confirmAction(msg`删除公告「${item.title}」？`)) return;
  await api(`/announcements/${item.id}`, { method: 'DELETE' }); notify(translate('公告已删除。')); await renderAnnouncements();
}

async function renderDns() {
  if (state.actor.role !== 'system_admin') { $('#content').replaceChildren(empty(translate('仅系统管理员可见'), translate('DNS 服务商令牌可修改外部 DNS，因此只向系统管理员开放。'))); return; }
  const [providers, zones, nodes] = await Promise.all([api('/dns/providers'), api('/dns/zones'), api('/nodes')]);
  const providerNames = Object.fromEntries(providers.map(p => [p.id, p.name]));
  const p = panel(translate('DNS 服务商'), translate('保存 Cloudflare 兼容 API 的地址和令牌。令牌可逆保存以调用服务商，接口只显示是否已设置；仅系统管理员可读写。'), button(translate('＋ 新增服务商'), () => dnsProviderForm(null), 'primary'));
  if (!providers.length) p.append(empty(translate('还没有 DNS 服务商'), translate('先添加服务商，再创建区域和托管记录。')));
  else p.append(table([translate('名称'), translate('类型'), translate('API 地址'), translate('令牌'), translate('操作')], providers.map(provider => {
    const actions = el('div'); actions.append(button(translate('编辑'), () => dnsProviderForm(provider), 'table-action'), button(translate('删除'), () => deleteDnsProvider(provider), 'table-action danger'));
    return [namedCell(provider.name, provider.id), provider.kind, provider.endpoint, provider.token_set ? badge(translate('已设置'), 'green') : badge(translate('未设置'), 'red'), actions];
  })));
  const z = panel(translate('DNS 区域'), translate('区域名是服务商的 zone 名称或 ID。观察模式只读取服务商并报告差异；应用模式只管理由本平台创建、带 relay 标记的记录。'), providers.length ? button(translate('＋ 新增区域'), () => dnsZoneForm(null, providers), 'primary') : null);
  if (!zones.length) z.append(empty(translate('还没有 DNS 区域'), translate('添加区域后可以创建 A/AAAA/CNAME 托管记录并执行一次同步。')));
  else z.append(table([translate('区域'), translate('服务商'), translate('模式'), translate('最少保留'), translate('操作')], zones.map(zone => {
    const actions = el('div');
    actions.append(button(translate('记录'), async () => { state.dnsZone = zone.id; await renderDns(); }, 'table-action'));
    actions.append(button(translate('立即同步'), () => reconcileDns(zone), 'table-action'));
    actions.append(button(translate('编辑'), () => dnsZoneForm(zone, providers), 'table-action'), button(translate('删除'), () => deleteDnsZone(zone), 'table-action danger'));
    return [namedCell(zone.name, zone.id), providerNames[zone.provider_id] || zone.provider_id, dnsModes[zone.mode] || zone.mode, zone.min_keep, actions];
  })));
  const selected = zones.find(zone => zone.id === state.dnsZone) || zones[0];
  if (selected) {
    state.dnsZone = selected.id;
    const records = await api(`/dns/zones/${selected.id}/records`);
    const r = panel(msg`托管记录 · ${selected.name}`, translate('每条记录带 relay 标记。删除记录时应用模式会同时删除服务商记录；观察模式只删除本地记录。健康摘除只在节点心跳新鲜且至少一个目标健康时保留记录。'), button(translate('＋ 新增记录'), () => dnsRecordForm(selected, null, nodes), 'primary'));
    if (!records.length) r.append(empty(translate('还没有托管记录'), translate('创建 A/AAAA/CNAME 记录，然后执行“立即同步”。')));
    else r.append(table([translate('名称'), translate('类型'), translate('内容'), 'TTL', translate('状态'), translate('健康摘除'), translate('服务商记录'), translate('操作')], records.map(record => {
      const actions = el('div');
      actions.append(button(translate('编辑'), () => dnsRecordForm(selected, record, nodes), 'table-action'));
      if (record.type === 'A' || record.type === 'AAAA') actions.append(button('DDNS', () => ddnsRecord(record), 'table-action'));
      actions.append(button(record.enabled ? translate('停用') : translate('启用'), async () => { await api(`/dns/records/${record.id}`, { method: 'PUT', body: { enabled: !record.enabled } }); await renderDns(); }, 'table-action'));
      actions.append(button(translate('删除'), () => deleteDnsRecord(record), 'table-action danger'));
      const stateBadge = record.last_error ? badge(translate('错误'), 'red') : record.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), '');
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
  field(grid, 'name', translate('名称'), provider?.name || '').maxLength = 120;
  select(grid, 'kind', translate('服务商类型'), [['cloudflare', translate('Cloudflare 兼容 API')]], provider?.kind || 'cloudflare');
  field(grid, 'endpoint', translate('API 基础地址'), provider?.endpoint || 'https://api.cloudflare.com/client/v4').maxLength = 500;
  const token = field(grid, 'token', provider ? translate('令牌（留空保留原值）') : translate('API 令牌'), '', 'password', false); token.maxLength = 4096;
  form.append(grid, el('p', translate('令牌只应授予 DNS 编辑权限；接口不会返回令牌原文。HTTP 只允许回环地址用于本机测试。'), 'fine'));
  submit(form, provider ? translate('保存服务商') : translate('添加服务商'), async data => {
    const body = { name: String(data.get('name')).trim(), kind: data.get('kind'), endpoint: String(data.get('endpoint')).trim() };
    if (String(data.get('token') || '')) body.token = String(data.get('token'));
    if (provider) await api(`/dns/providers/${provider.id}`, { method: 'PUT', body });
    else await api('/dns/providers', { method: 'POST', body });
    $('#dialog').close(); notify(translate('DNS 服务商已保存。')); await renderDns();
  });
  modal(provider ? msg`编辑 DNS 服务商 · ${provider.name}` : translate('新增 DNS 服务商'), form);
}
function dnsZoneForm(zone, providers) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('区域名称 / ID'), zone?.name || '').maxLength = 253;
  select(grid, 'provider_id', translate('服务商'), providers.map(provider => [provider.id, provider.name]), zone?.provider_id || providers[0]?.id || '');
  select(grid, 'mode', translate('模式'), Object.entries(dnsModes), zone?.mode || 'observe');
  const keep = field(grid, 'min_keep', translate('最少保留记录数'), zone?.min_keep ?? 1, 'number'); keep.min = 0; keep.max = 1000;
  form.append(grid, el('p', translate('观察模式适合先核对现有记录。应用模式只创建/更新/删除本平台带 relay 标记的记录，不会接管同名的外部记录。'), 'fine'));
  submit(form, zone ? translate('保存区域') : translate('添加区域'), async data => {
    const body = { name: String(data.get('name')).trim(), provider_id: data.get('provider_id'), mode: data.get('mode'), min_keep: number(data, 'min_keep') };
    if (zone) await api(`/dns/zones/${zone.id}`, { method: 'PUT', body });
    else { const created = await api('/dns/zones', { method: 'POST', body }); state.dnsZone = created.id; }
    $('#dialog').close(); notify(translate('DNS 区域已保存。')); await renderDns();
  });
  modal(zone ? msg`编辑 DNS 区域 · ${zone.name}` : translate('新增 DNS 区域'), form);
}
function dnsRecordForm(zone, record, nodes) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('记录名称'), record?.name || '').maxLength = 253;
  select(grid, 'type', translate('类型'), dnsRecordTypes.map(type => [type, type]), record?.type || 'A');
  field(grid, 'content', translate('内容（IP 或 CNAME）'), record?.content || '').maxLength = 253;
  const ttl = field(grid, 'ttl', translate('TTL（秒）'), record?.ttl ?? 300, 'number'); ttl.min = 1; ttl.max = 86400;
  select(grid, 'proxied', translate('Cloudflare 代理'), [['no', translate('不代理')], ['yes', translate('代理')]], record?.proxied ? 'yes' : 'no');
  select(grid, 'health_node', translate('入口健康摘除节点'), [['', translate('不启用')], ...nodes.map(node => [node.id, node.name])], record?.health?.node_id || '');
  field(grid, 'health_rule', translate('健康摘除规则 ID（可选）'), record?.health?.rule_id || '').maxLength = 128;
  if (record?.health) select(grid, 'health_clear', translate('健康摘除设置'), [['no', translate('保留现有设置')], ['yes', translate('清除健康摘除')]], 'no');
  form.append(grid, el('p', translate('应用模式同步后会写入服务商；观察模式只显示“将创建/将更新”。CNAME 内容必须是主机名，A/AAAA 内容必须是 IP。填写节点和规则 ID 后，节点心跳超过 90 秒或没有健康目标时，应用模式会摘除该记录；恢复后自动重建。'), 'fine'));
  submit(form, record ? translate('保存记录') : translate('添加记录'), async data => {
    const body = { name: String(data.get('name')).trim(), type: data.get('type'), content: String(data.get('content')).trim(), ttl: number(data, 'ttl'), proxied: data.get('proxied') === 'yes' };
    const healthNode = String(data.get('health_node') || ''), healthRule = String(data.get('health_rule') || '').trim();
    if (data.get('health_clear') === 'yes') body.clear_health = true;
    else if (healthNode && healthRule) body.health = { node_id: healthNode, rule_id: healthRule };
    if (record) await api(`/dns/records/${record.id}`, { method: 'PUT', body });
    else await api(`/dns/zones/${zone.id}/records`, { method: 'POST', body });
    $('#dialog').close(); notify(translate('DNS 记录已保存；执行“立即同步”后写入服务商。')); await renderDns();
  });
  modal(record ? msg`编辑 DNS 记录 · ${record.name}` : translate('新增 DNS 记录'), form);
}
async function reconcileDns(zone) {
  const result = await api(`/dns/zones/${zone.id}/reconcile`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', msg`${dnsModes[zone.mode]}：观察 ${result.observed} 条，创建 ${result.created}，更新 ${result.updated}，删除 ${result.deleted}，未变 ${result.unchanged}，保留 ${result.kept}，错误 ${result.errors}。`));
  if (result.actions.length) body.append(table([translate('记录'), translate('动作'), translate('详情')], result.actions.map(action => [action.record_id, action.action, action.detail])));
  modal(msg`同步结果 · ${zone.name}`, body); await renderDns();
}
async function deleteDnsProvider(provider) {
  if (!await confirmAction(msg`删除 DNS 服务商「${provider.name}」？存在区域时会被拒绝。`)) return;
  await api(`/dns/providers/${provider.id}`, { method: 'DELETE' }); notify(translate('DNS 服务商已删除。')); await renderDns();
}
async function deleteDnsZone(zone) {
  if (!await confirmAction(msg`删除 DNS 区域「${zone.name}」？存在托管记录时会被拒绝。`)) return;
  await api(`/dns/zones/${zone.id}`, { method: 'DELETE' }); if (state.dnsZone === zone.id) state.dnsZone = null; notify(translate('DNS 区域已删除。')); await renderDns();
}
async function deleteDnsRecord(record) {
  if (!await confirmAction(msg`删除 DNS 记录「${record.name}」？应用模式会同时删除服务商记录。`)) return;
  await api(`/dns/records/${record.id}`, { method: 'DELETE' }); notify(translate('DNS 记录已删除。')); await renderDns();
}
async function ddnsRecord(record) {
  const content = await promptValue(msg`为「${record.name}」输入新的 ${record.type} 地址（DDNS）；当前 ${record.content}`, record.content);
  if (!content || content.trim() === record.content) return;
  await api(`/dns/records/${record.id}/ddns`, { method: 'POST', body: { content: content.trim() } }); notify(translate('DDNS 已更新并同步；观察模式只报告差异。')); await renderDns();
}

async function renderSubscriptions() {
  const subscriptions = await api('/subscriptions');
  const p = panel(translate('客户端订阅'), translate('把支持的代理规则快照成可撤销的订阅链接。链接只包含客户端连接参数，不包含控制器会话或节点凭据；轮换后旧链接立即失效。'), canWrite() ? button(translate('＋ 新建订阅'), newSubscription, 'primary') : null);
  if (!subscriptions.length) p.append(empty(translate('还没有订阅链接'), translate('先创建至少一条启用中的 Shadowsocks 或受管协议规则，再按客户端格式生成订阅。')));
  else p.append(table([translate('名称'), translate('格式'), translate('所有者'), translate('到期'), translate('最近使用'), translate('操作')], subscriptions.map(item => {
    const actions = el('div');
    actions.append(button(translate('预览'), () => previewSubscription(item), 'table-action'));
    if (canWrite()) {
      actions.append(button(translate('轮换链接'), () => rotateSubscription(item), 'table-action'));
      actions.append(button(translate('删除'), () => deleteSubscription(item), 'table-action danger'));
    }
    return [namedCell(item.name, item.id), subscriptionFormats[item.format] || item.format, item.owner_id, item.expires_at_ms ? timestamp(item.expires_at_ms) : translate('不过期'), item.last_used_ms ? msg`${timestamp(item.last_used_ms)} · ${item.uses} 次` : translate('尚未使用'), actions];
  })));
  if (state.view === 'subscriptions') $('#content').replaceChildren(p);
}
async function newSubscription() {
  const users = state.actor.role === 'viewer' ? [] : await api('/users').catch(() => []);
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('名称（说明用途，如“手机订阅”）')).maxLength = 120;
  select(grid, 'format', translate('客户端格式'), Object.entries(subscriptionFormats), 'sing_box');
  form.append(el('p', translate('订阅按所有者和节点标签收集兼容规则，保存当前端点快照。多跳 SS 请使用转发路径页的入口客户端链接；此处不会自动改写入口端口。'), 'workflow-callout'));
  field(grid, 'prefix', translate('客户端显示名称前缀（可选）'), 'Relay ').maxLength = 64;
  const host = field(grid, 'host', translate('替换所有节点地址（可选，NAT / 域名场景）'), '', 'text', false); host.maxLength = 253;
  const tags = field(grid, 'tags', translate('只包含这些节点标签（逗号分隔，留空全部）'), '', 'text', false);
  select(grid, 'udp', translate('在客户端启用 UDP'), [['yes', translate('启用')], ['no', translate('不启用')]], 'yes');
  const days = field(grid, 'days', translate('有效天数（1–3650）'), 365, 'number'); days.min = 1; days.max = 3650;
  if (state.actor.role !== 'viewer' && users.length > 1) {
    const owner = select(grid, 'user_id', translate('订阅所有者'), [['', translate('当前账号')], ...users.map(u => [u.id, `${u.username} · ${roleNames[u.role]}`])], '');
    owner.required = false;
  }
  form.append(grid, el('p', translate('名称前缀和节点标签会作为快照保存在订阅记录中；节点后续改名不会改变已生成链接的显示名。只读账号不能创建或轮换链接。'), 'fine'));
  submit(form, translate('创建订阅'), async data => {
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
  modal(translate('新建客户端订阅'), form);
}
function showSubscriptionToken(name, token) {
  const body = el('div');
  const url = `${location.origin}/sub/${token}`;
  body.append(el('p', translate('订阅链接只显示这一次。任何持有链接的人都能读取节点连接参数；请像密码一样保存，泄露时立即轮换。'), 'fine'), el('div', url, 'secret-box'));
  const actions = el('div', undefined, 'dialog-actions');
  actions.append(button(translate('关闭对话框'), () => $('#dialog').close()), button(translate('复制链接'), async () => { await navigator.clipboard.writeText(url); notify(translate('订阅链接已复制。')); }, 'primary'));
  body.append(actions);
  modal(msg`订阅已创建 · ${name}`, body);
}
async function previewSubscription(item) {
  const preview = await api(`/subscriptions/${item.id}/preview`);
  const body = el('div');
  if (preview.entries.length) body.append(table([translate('客户端名称'), translate('服务器'), translate('端口'), translate('加密方式')], preview.entries.map(entry => [entry.name, entry.host, entry.port, entry.method])));
  else body.append(el('p', translate('没有可生成的条目，原因见下方跳过列表。'), 'muted'));
  if (preview.skipped.length) body.append(el('h3', translate('跳过规则')), table([translate('规则'), translate('原因')], preview.skipped.map(s => [namedCell(s.rule_name, s.rule_id), s.reason])));
  const details = el('details'); details.append(el('summary', translate('查看生成内容')), el('pre', preview.content, 'subscription-preview')); body.append(details);
  modal(msg`预览 · ${item.name}`, body);
}
async function rotateSubscription(item) {
  if (!await confirmAction(msg`轮换「${item.name}」的订阅链接？旧链接会立即失效，已导入的客户端需要重新导入。`)) return;
  const result = await api(`/subscriptions/${item.id}/rotate`, { method: 'POST' });
  showSubscriptionToken(item.name, result.token);
  await renderSubscriptions();
}
async function deleteSubscription(item) {
  if (!await confirmAction(msg`删除订阅「${item.name}」？使用该链接的客户端将立即无法更新。`)) return;
  await api(`/subscriptions/${item.id}`, { method: 'DELETE' });
  notify(translate('订阅已删除。'));
  await renderSubscriptions();
}

async function renderUsage() { const records = await api('/usage'); const p = panel(translate('已接纳应用负载'), translate('累计值按节点、规则与计量周期去重；发送失败也可能已经接纳计量。最多显示最近 2,000 条周期记录。')); if (!records.length) p.append(empty(translate('还没有流量记录'), translate('让一条转发规则通过真实流量，Agent 会在同步后上报。'))); else p.append(table([translate('规则 / 周期'), translate('节点'), translate('上行'), translate('下行'), translate('序号'), translate('最近上报')], records.map(r => [namedCell(r.rule_id, r.meter_epoch), r.node_id, bytes(r.upload_bytes), bytes(r.download_bytes), r.sequence, timestamp(r.reported_at_ms)]))); if (state.view === 'usage') $('#content').replaceChildren(p); }
async function renderUsers() { const users = await api('/users'); const p = panel(translate('用户与会话'), translate('权限由服务端校验；撤销、停用、改密或删除后，该用户已有的 Web 会话和 API 令牌立即失效。'), canWrite() ? button(translate('＋ 添加用户'), newUser, 'primary') : null); p.append(table([translate('账号'), translate('角色'), translate('租户'), translate('状态'), translate('两步验证'), translate('跨节点总限速'), translate('操作')], users.map(u => [namedCell(u.username, u.id), roleNames[u.role], u.tenant_id, u.disabled ? badge(translate('已停用'), 'red') : badge(translate('启用'), 'green'), u.mfa_enabled ? badge(translate('已启用'), 'green') : badge(translate('未启用')), u.rate_bytes_per_sec ? badge(mbit(u.rate_bytes_per_sec), 'orange') : badge(translate('不限速')), userActions(u)]))); if (state.view === 'users') $('#content').replaceChildren(p); }
function userActions(u) {
  if (!canWrite() && u.id !== state.actor.id) return '—';
  const actions = el('div');
  actions.append(button(translate('撤销全部会话'), async () => { await api(`/users/${u.id}/revoke-sessions`, { method: 'POST' }); if (u.id === state.actor.id) loggedOut(); else notify(translate('该用户现有会话和 API 令牌已撤销。')); }, 'table-action'));
  if (state.actor.role === 'system_admin' || u.rate_bytes_per_sec) actions.append(button(translate('总限速'), () => editUserRate(u), 'table-action'));
  if (canWrite() && u.id !== state.actor.id) {
    actions.append(button(translate('改密'), () => adminPassword(u), 'table-action'));
    actions.append(button(u.disabled ? translate('启用') : translate('停用'), () => toggleUserDisabled(u), 'table-action'));
    actions.append(button(translate('删除'), () => deleteUser(u), 'table-action danger'));
  }
  if (canWrite() && u.mfa_enabled && u.id !== state.actor.id) actions.append(button(translate('重置两步验证'), async () => { if (!await confirmAction(msg`重置 ${u.username} 的两步验证？其会话和 API 令牌会同时失效；之后可只用密码登录并重新启用。`)) return; await api(`/users/${u.id}/mfa/reset`, { method: 'POST' }); notify(msg`${u.username} 的两步验证已重置。`); await renderUsers(); }, 'table-action danger'));
  return actions;
}
function adminPassword(u) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'password', msg`为 ${u.username} 设置新密码`, '', 'password').maxLength = 1024;
  form.append(grid, el('p', translate('保存后该用户的全部 Web 会话和 API 令牌立即失效，需要使用新密码重新登录。密码至少 12 字节。'), 'fine'));
  submit(form, translate('重置密码'), async data => {
    await api(`/users/${u.id}/password`, { method: 'POST', body: { password: String(data.get('password')) } });
    $('#dialog').close(); notify(msg`${u.username} 的密码已重置。`); await renderUsers();
  });
  modal(msg`重置密码 · ${u.username}`, form);
}
async function toggleUserDisabled(u) {
  if (!await confirmAction(`${u.disabled ? translate('启用') : translate('停用')} ${u.username}？${u.disabled ? translate('旧密码仍有效，可重新登录。') : translate('现有会话和 API 令牌会立即失效，之后可重新启用。')}`)) return;
  await api(`/users/${u.id}/disabled`, { method: 'PUT', body: { disabled: !u.disabled } });
  notify(msg`${u.username} 已${u.disabled ? translate('启用') : translate('停用')}。`); await renderUsers();
}
async function deleteUser(u) {
  if (!await confirmAction(msg`永久删除 ${u.username}？其会话、API 令牌、两步验证和限速设置会删除；拥有规则或订阅时服务端会拒绝。`)) return;
  await api(`/users/${u.id}`, { method: 'DELETE' });
  notify(msg`${u.username} 已删除。`); await renderUsers();
}
async function changeOwnPassword() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'current', translate('当前密码'), '', 'password').maxLength = 1024;
  field(grid, 'next', translate('新密码（至少 12 字节）'), '', 'password').maxLength = 1024;
  field(grid, 'confirm', translate('再次输入新密码'), '', 'password').maxLength = 1024;
  form.append(grid, el('p', translate('修改成功后当前会话保留，其他 Web 会话失效；API 令牌不受影响。忘记当前密码时需其他管理员重置。'), 'fine'));
  submit(form, translate('修改密码'), async data => {
    const next = String(data.get('next'));
    if (next !== String(data.get('confirm'))) throw new Error(translate('两次输入的新密码不一致'));
    await api('/account/password', { method: 'POST', body: { current_password: String(data.get('current')), new_password: next } });
    $('#dialog').close(); notify(translate('密码已修改。')); await renderAccount();
  });
  modal(translate('修改登录密码'), form);
}
async function editUserRate(u) {
  const [view, nodes] = await Promise.all([api(`/users/${u.id}/rate`), api('/nodes').catch(() => [])]);
  const names = Object.fromEntries(nodes.map(n => [n.id, n.name]));
  const form = el('form');
  if (state.actor.role === 'system_admin') {
    const grid = el('div', undefined, 'form-grid'); const input = field(grid, 'mbit', translate('该用户所有节点入口规则的上下行合计 / Mbit/s（留空不限速）'), view.rate_bytes_per_sec ? +(view.rate_bytes_per_sec * 8 / 1e6).toFixed(3) : '', 'number', false); input.min = 0.009; input.step = 'any';
    form.append(grid, el('p', translate('控制器按各节点的实际用量动态分配份额，忙的节点多分；节点与控制器失联 15 秒后退回平均份额。与规则、节点限速同时生效，取较严者。只计入口规则；已停用或到期的节点不占份额，长期离线的节点请停用。'), 'muted'));
  }
  if (view.nodes.length) form.append(table([translate('节点'), translate('当前份额'), translate('实测'), translate('状态')], view.nodes.map(n => [namedCell(names[n.node_id] || n.node_id, n.node_id), mbit(n.share_bytes_per_sec), n.measured_bytes_per_sec == null ? '—' : mbit(n.measured_bytes_per_sec), n.seen_ms_ago == null ? badge(translate('未连接，预留平均份额'), 'red') : n.seen_ms_ago > 20000 ? badge(translate('失联，按平均份额'), 'red') : n.saturated ? badge(translate('已用满'), 'orange') : badge(translate('有余量'), 'green')])));
  else if (view.rate_bytes_per_sec) form.append(el('p', translate('各节点下次同步后显示份额。'), 'muted'));
  if (state.actor.role === 'system_admin') submit(form, translate('保存总限速'), async data => { const raw = String(data.get('mbit')).trim(); const rate = raw === '' ? null : Math.round(Number(raw) * 1e6 / 8); if (rate !== null && !(rate >= 1024 && rate <= 2 ** 40)) throw new Error(translate('请输入 0.009 到 8,796,093 之间的 Mbit/s')); await api(`/users/${u.id}/rate`, { method: 'PUT', body: { rate_bytes_per_sec: rate } }); $('#dialog').close(); notify(rate ? msg`${u.username} 的跨节点总限速为 ${mbit(rate)}。` : msg`已取消 ${u.username} 的跨节点总限速。`); await renderUsers(); });
  modal(msg`${u.username} 的跨节点总限速`, form);
}
async function renderAccount() {
  const [factor, tokens] = await Promise.all([api('/account/mfa'), api('/api-tokens')]);
  const security = panel(translate('两步验证'), translate('登录时除密码外，还需输入手机身份验证器（如 Google Authenticator、Microsoft Authenticator、1Password）生成的 6 位验证码。'), factor.enabled ? button(translate('停用两步验证'), disableSecondFactor, 'subtle danger') : button(translate('启用两步验证'), setupSecondFactor, 'primary'));
  const status = el('div', undefined, 'panel-body');
  for (const [label, value] of [[translate('状态'), factor.enabled ? badge(translate('已启用'), 'green') : badge(factor.pending ? translate('设置未完成') : translate('未启用'), factor.pending ? 'orange' : '')], ...(factor.enabled ? [[translate('剩余恢复码'), badge(msg`${factor.recovery_codes_remaining} 个`, factor.recovery_codes_remaining <= 2 ? 'orange' : '')]] : [])]) { const row = el('div', undefined, 'capability'); row.append(el('span', label), value); status.append(row); }
  status.append(el('p', factor.enabled ? translate('手机丢失时可用恢复码登录；恢复码用完或丢失时，请其他管理员在“用户与权限”中重置。') : translate('启用后，此账号的每次登录都需要验证码。API 令牌不受影响，但只能在登录后创建。'), 'fine'));
  security.append(status);
  const password = panel(translate('登录密码'), translate('修改后当前会话保留，其他 Web 会话失效；API 令牌不受影响。'), button(translate('修改密码'), changeOwnPassword, 'primary'));
  password.append(el('p', translate('密码至少 12 字节。忘记密码时请其他管理员在“用户与权限”中重置。'), 'fine'));
  const keys = panel(translate('API 令牌'), translate('供脚本和自动化调用 API。令牌权限是所选范围与你的角色权限的交集；令牌不能创建令牌或修改两步验证。'), button(translate('＋ 创建令牌'), createApiToken, 'primary'));
  if (!tokens.length) keys.append(empty(translate('尚无 API 令牌'), translate('令牌创建后只显示一次，到期后自动失效。')));
  else keys.append(table([translate('名称'), translate('权限范围'), translate('创建时间'), translate('到期时间'), translate('操作')], tokens.map(t => [namedCell(t.name, t.id), t.scopes.map(scope => scopeNames[scope] || scope).join('、'), timestamp(t.created_at_ms), t.expires_at_ms <= Date.now() ? badge(translate('已过期'), 'red') : timestamp(t.expires_at_ms), button(translate('撤销'), async () => { if (!await confirmAction(msg`撤销令牌“${t.name}”？使用它的脚本将立即失效。`)) return; await api(`/api-tokens/${t.id}`, { method: 'DELETE' }); notify(translate('令牌已撤销。')); await renderAccount(); }, 'table-action danger')])));
  const page = el('div'); page.append(password, security, keys);
  if (state.view === 'account') $('#content').replaceChildren(page);
}
function setupSecondFactor() {
  const form = el('form'); form.append(el('p', translate('为防止他人用未关闭的浏览器绑定自己的手机，请先确认当前密码。'), 'fine'));
  field(form, 'password', translate('当前密码'), '', 'password').autocomplete = 'current-password';
  submit(form, translate('下一步'), async data => { const setup = await api('/account/mfa/setup', { method: 'POST', body: { password: data.get('password') } }); $('#dialog').close(); confirmSecondFactor(setup); });
  modal(translate('启用两步验证'), form);
}
function confirmSecondFactor(setup) {
  const form = el('form'), qr = el('img', undefined, 'qr-code'); qr.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}`; qr.alt = translate('两步验证二维码');
  form.append(el('p', translate('1. 用身份验证器扫描二维码。无法扫描时，选择手动输入并填写下面的密钥（基于时间）。')), qr, el('div', setup.secret.match(/.{1,4}/g).join(' '), 'secret-box'), el('p', translate('2. 输入应用当前显示的 6 位验证码完成启用。')));
  const code = field(form, 'code', translate('验证码')); code.inputMode = 'numeric'; code.autocomplete = 'one-time-code'; code.maxLength = 6; code.pattern = '[0-9]{6}';
  submit(form, translate('确认启用'), async data => { const result = await api('/account/mfa/enable', { method: 'POST', body: { code: String(data.get('code')).trim() } }); $('#dialog').close(); showRecoveryCodes(result.recovery_codes); });
  modal(translate('启用两步验证'), form); code.focus();
}
function showRecoveryCodes(codes) {
  const body = el('div'); body.append(el('p', translate('两步验证已启用。手机丢失时，每个恢复码可代替验证码登录一次。请离线保存，关闭后无法再次查看。')), el('div', codes.join('\n'), 'secret-box recovery-codes'), button(translate('我已保存恢复码'), () => $('#dialog').close(), 'primary'));
  modal(translate('保存恢复码'), body); renderAccount().catch(e => notify(e.message, true));
}
function disableSecondFactor() {
  const form = el('form'); form.append(el('p', translate('停用后登录只需要密码。请确认密码，并输入当前验证码或一个恢复码。'), 'fine'));
  field(form, 'password', translate('当前密码'), '', 'password').autocomplete = 'current-password';
  const code = field(form, 'code', translate('验证码或恢复码')); code.autocomplete = 'one-time-code'; code.maxLength = 32;
  submit(form, translate('停用两步验证'), async data => { await api('/account/mfa/disable', { method: 'POST', body: { password: data.get('password'), code: String(data.get('code')).trim() } }); $('#dialog').close(); notify(translate('两步验证已停用。')); await renderAccount(); });
  modal(translate('停用两步验证'), form);
}
function createApiToken() {
  const form = el('form'); field(form, 'name', translate('名称（说明用途，如“监控脚本”）')).maxLength = 80;
  const scopes = el('fieldset'); scopes.append(el('legend', translate('权限范围')));
  for (const [value, label] of Object.entries(scopeNames)) { const item = el('label', label, 'inline-check'), input = el('input'); input.type = 'checkbox'; input.name = 'scope'; input.value = value; input.checked = value === 'read'; item.prepend(input); scopes.append(item); }
  scopes.append(el('p', translate('写入范围通常还需要“读取”，以便先取得当前版本号。只读用户的令牌仍不能写入。'), 'fine')); form.append(scopes);
  const days = field(form, 'days', translate('有效天数（1–365）'), 90, 'number'); days.min = 1; days.max = 365;
  submit(form, translate('创建令牌'), async data => { if (!data.getAll('scope').length) throw new Error(translate('至少选择一个权限范围')); const result = await api('/api-tokens', { method: 'POST', body: { name: String(data.get('name')).trim(), scopes: data.getAll('scope'), expires_in_days: number(data, 'days') } }); const body = el('div'); body.append(el('p', translate('令牌只显示这一次。请保存到密码管理器或脚本的密钥配置中，不要写入代码仓库或聊天记录。')), el('div', result.token, 'secret-box'), el('p', translate('调用示例（先把令牌放入环境变量 RELAY_TOKEN）'), 'fine'), el('pre', `curl -H "Authorization: Bearer $RELAY_TOKEN" ${location.origin}/api/v1/nodes`), button(translate('我已保存令牌'), () => $('#dialog').close(), 'primary')); $('#dialog').close(); modal(translate('API 令牌已创建'), body); await renderAccount(); });
  modal(translate('创建 API 令牌'), form);
}
function newUser() { const form = el('form'); field(form, 'username', translate('用户名')).maxLength = 80; const p = field(form, 'password', translate('初始密码（至少 12 个字节）'), '', 'password'); p.minLength = 12; p.autocomplete = 'new-password'; const roles = [['viewer', translate('只读用户')], ['tenant_admin', translate('租户管理员')]]; if (state.actor.role === 'system_admin') roles.push(['system_admin', translate('系统管理员')]); select(form, 'role', translate('角色'), roles, 'viewer'); submit(form, translate('创建用户'), async data => { await api('/users', { method: 'POST', body: Object.fromEntries(data) }); $('#dialog').close(); await renderUsers(); }); modal(translate('添加用户'), form); }
async function renderAudit() { const rows = await api('/audit'); const p = panel(translate('操作审计'), translate('记录配置发布、节点注册、身份及会话操作。最近 200 条。')); p.append(table([translate('时间'), translate('操作者'), translate('操作'), translate('对象'), translate('详情')], rows.map(r => [timestamp(r.at_ms), r.actor_id, r.action, r.resource, r.detail]))); if (state.view === 'audit') $('#content').replaceChildren(p); }
const alertKinds = localize({ smtp: 'Email / SMTP', webhook: 'Webhook', telegram: 'Telegram', wecom: '企业微信', feishu: '飞书', dingtalk: '钉钉' });
const alertFields = localize({ smtp: [], webhook: [['url', 'Webhook 地址'], ['secret', '签名密钥（可选，HMAC-SHA256）', true]], telegram: [['bot_token', 'Bot Token'], ['chat_id', 'Chat ID']], wecom: [['url', '群机器人 Webhook 地址']], feishu: [['url', '自定义机器人 Webhook 地址'], ['secret', '签名校验密钥（可选）', true]], dingtalk: [['url', '自定义机器人 Webhook 地址'], ['secret', '加签密钥（可选）', true]] });
const severityNames = localize({ warning: '警告及以上', critical: '仅严重' });
async function renderAlerts() {
  const data = await api('/alerts'), now = Date.now(), { settings, channels, incidents, can_manage } = data;
  const until = settings.maintenance_until_ms, maintaining = until && until > now;
  const grid = el('div', undefined, 'alert-grid');
  const status = panel(translate('通知状态'), maintaining ? msg`维护模式至 ${timestamp(until)}。期间不发送新告警，结束时仍未恢复的问题会补发。` : translate('目标不可用、节点拒绝配置和节点离线会通知已启用的通道。同时出现的问题合并为一条消息；同一问题 5 分钟内反复出现只算一次。'));
  const strip = el('div', undefined, 'alert-status');
  for (const [label, value, color] of [[translate('当前告警'), incidents.open.length, incidents.open.length ? 'red' : 'green'], [translate('启用通道'), channels.filter(c => c.enabled).length, channels.some(c => c.enabled) ? 'green' : 'orange'], [translate('发送失败'), incidents.deliveries.filter(d => d.status === 'failed').length, incidents.deliveries.some(d => d.status === 'failed') ? 'red' : '']]) { const item = el('div', undefined, `alert-stat ${color}`); item.append(el('div', String(value), 'metric-value'), el('div', label, 'metric-label')); strip.append(item); }
  const actions = el('div', undefined, 'alert-actions');
  const maintain = ms => api('/alerts/settings', { method: 'PUT', body: { maintenance_until_ms: ms } }).then(renderAlerts);
  if (can_manage) actions.append(maintaining ? button(translate('结束维护'), () => maintain(null), 'primary') : badge(translate('正常通知'), 'green'), button(translate('维护 1 小时'), () => maintain(Date.now() + 3600_000)), button(translate('维护 4 小时'), () => maintain(Date.now() + 4 * 3600_000)));
  strip.append(actions); status.append(strip); grid.append(status);
  const list = panel(translate('通知通道'), can_manage ? translate('可向全局或指定租户发送通知。密钥保存后不再显示。最多 20 个通道。') : translate('仅显示本租户专用通道和事件。通道由系统管理员配置。'), can_manage ? button(translate('＋ 添加通道'), () => editAlertChannel(), 'primary') : null);
  if (!channels.length) list.append(empty(translate('还没有通知通道'), translate('系统管理员可添加 Email、Webhook 或聊天机器人通道。'), can_manage ? button(translate('＋ 添加通道'), () => editAlertChannel(), 'primary') : null));
  else list.append(table([translate('名称'), translate('租户范围'), translate('类型'), translate('发送到'), translate('级别'), translate('状态'), translate('操作')], channels.map(c => { const ops = el('div', undefined, 'row-actions'); if (can_manage) ops.append(button(translate('测试'), async () => { notify(msg`正在向 ${c.name} 发送测试消息…`); try { await api(`/alerts/channels/${c.id}/test`, { method: 'POST' }); notify(msg`测试消息已发送到 ${c.name}，请确认已收到。`); } finally { await renderAlerts(); } }, 'table-action'), button(translate('编辑'), () => editAlertChannel(c), 'table-action'), button(translate('删除'), async () => { if (!await confirmAction(msg`删除通知通道“${c.name}”？`)) return; await api(`/alerts/channels/${c.id}`, { method: 'DELETE' }); await renderAlerts(); }, 'table-action danger')); return [namedCell(c.name, c.secret_set ? translate('已设置密钥') : translate('未设置密钥')), c.tenant_id || translate('全部租户'), alertKinds[c.kind], el('span', c.destination, 'mono'), severityNames[c.min_severity], badge(c.enabled ? translate('已启用') : translate('已停用'), c.enabled ? 'green' : ''), ops]; })));
  grid.append(list);
  const levels = { warning: [translate('警告'), 'orange'], critical: [translate('严重'), 'red'] };
  const incidentRows = (items, resolved) => items.map(i => [resolved ? `${timestamp(i.resolved_at_ms)} · ${ago(i.resolved_at_ms, now)}` : `${timestamp(i.opened_at_ms)} · ${ago(i.opened_at_ms, now)}`, i.node_name, badge(...(levels[i.severity] || [i.severity])), el('span', i.summary, 'wrap'), i.repeats ? msg`${i.repeats} 次` : '—', resolved ? (i.last_notice_ms ? translate('已通知恢复') : translate('未通知')) : i.notified ? badge(translate('已通知'), 'green') : badge(maintaining ? translate('维护中暂缓') : translate('等待发送'), 'orange')]);
  const open = panel(translate('当前告警'), translate('仍未恢复的问题。控制器重启后会在 1 分钟内重新检测。'));
  open.append(incidents.open.length ? table([translate('开始'), translate('节点'), translate('级别'), translate('内容'), translate('反复'), translate('通知')], incidentRows(incidents.open, false)) : empty(translate('一切正常'), translate('没有未恢复的告警。')));
  grid.append(open);
  if (incidents.resolved.length) { const done = panel(translate('最近恢复'), translate('最近 200 条，保存在控制器内存中。')); done.append(table([translate('恢复'), translate('节点'), translate('级别'), translate('内容'), translate('反复'), translate('通知')], incidentRows(incidents.resolved.slice(0, 50), true))); grid.append(done); }
  const statusNames = { cancelled: [translate('已取消'), ''], sent: [translate('已送达'), 'green'], failed: [translate('失败'), 'red'], retrying: [translate('重试中'), 'orange'], pending: [translate('发送中'), ''] }, noticeNames = { opened: translate('告警'), resolved: translate('恢复'), test: translate('测试') };
  const log = panel(translate('发送记录'), translate('失败会在 10 秒、1 分钟、5 分钟后重试。最近 200 条。'));
  log.append(incidents.deliveries.length ? table([translate('时间'), translate('通道'), translate('类型'), translate('结果'), translate('尝试'), translate('错误')], incidents.deliveries.slice(0, 100).map(d => [timestamp(d.created_at_ms), d.channel_name, d.incidents > 1 ? msg`${noticeNames[d.notice]} · 合并 ${d.incidents} 条` : noticeNames[d.notice], badge(...statusNames[d.status]), String(d.attempts), d.error ? Object.assign(el('span', d.error, 'clip mono'), { title: d.error }) : '—'])) : empty(translate('还没有发送记录'), translate('发送测试消息或出现告警后会显示在这里。')));
  grid.append(log);
  if (state.view === 'alerts') $('#content').replaceChildren(grid);
}
function smtpConfig(data) {
  const value = key => String(data.get(key) || '').trim();
  const port = Number(value('port')), security = value('security');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(translate('SMTP 端口必须为 1–65535'));
  if (!['starttls', 'implicit_tls', 'local_relay'].includes(security)) throw new Error(translate('无效的 SMTP 安全模式'));
  return { host: value('host'), port, security, from: value('from'), to: value('to').split(/[\n,]/).map(v => v.trim()).filter(Boolean), username: value('username'), password: String(data.get('password') || ''), ca_pem: value('ca_pem') };
}
function editAlertChannel(existing) {
  const form = el('form'), kind = existing?.kind || 'webhook';
  field(form, 'name', translate('名称（如“值班群”）'), existing?.name).maxLength = 80;
  field(form, 'tenant_id', translate('租户 ID（留空表示全部租户）'), existing?.tenant_id || '', 'text', false);
  const kindSelect = select(form, 'kind', translate('类型'), Object.entries(alertKinds), kind);
  select(form, 'min_severity', translate('通知级别'), [['warning', translate('警告及以上（目标不可用、配置拒绝、节点离线）')], ['critical', translate('仅严重（配置拒绝、节点离线）')]], existing?.min_severity || 'warning');
  const enabled = el('label', translate('启用'), 'inline-check'), check = el('input'); check.type = 'checkbox'; check.name = 'enabled'; check.checked = existing?.enabled ?? true; enabled.prepend(check); form.append(enabled);
  const box = el('div', undefined, 'alert-fields'); form.append(box);
  const fillFields = () => { box.replaceChildren(); const keep = existing && kindSelect.value === existing.kind;
    if (kindSelect.value === 'smtp') {
      const smtp = keep ? existing.smtp || {} : {};
      field(box, 'host', translate('SMTP 主机'), smtp.host || '');
      const port = field(box, 'port', translate('SMTP 端口'), smtp.port || 587, 'number'); port.min = 1; port.max = 65535;
      select(box, 'security', translate('连接保护'), [['starttls', translate('必须升级 STARTTLS')], ['implicit_tls', translate('直接 TLS')], ['local_relay', translate('本机邮件中继 · 仅回环 IP')]], smtp.security || 'starttls');
      field(box, 'from', translate('发件地址'), smtp.from || '');
      textarea(box, 'to', translate('收件地址，每行一个（最多 20 个）'), (smtp.to || []).join('\n'), true);
      field(box, 'username', translate('SMTP 用户名（不认证时留空）'), smtp.username || '', 'text', false);
      const password = field(box, 'password', translate('SMTP 密码'), '', 'password', false); password.autocomplete = 'new-password';
      textarea(box, 'ca_pem', translate('私有 CA 证书 PEM（可选；不填则使用公开信任根）'), smtp.ca_pem || '');
      box.append(el('p', translate('留空密码仅在主机、端口、用户名和安全模式均未改变时保留原密码。更改这些设置后请重新输入。连接要求证书验证，本机明文中继禁止认证。'), 'fine'));
      return;
    }
    for (const [name, label, optional] of alertFields[kindSelect.value]) { const input = field(box, name, label, '', name === 'url' ? 'url' : 'text', !optional && !keep); input.autocomplete = 'off'; if (keep) input.placeholder = translate('留空则保留原值'); } if (kindSelect.value === 'webhook') box.append(el('p', translate('以 JSON POST {"text","sent_at_ms"}。设置密钥后请求头带 X-Relay-Signature: sha256=<正文的 HMAC 十六进制>。'), 'fine')); };
  kindSelect.onchange = fillFields; fillFields();
  submit(form, existing ? translate('保存') : translate('添加通道'), async data => {
    const target = { kind: data.get('kind') }; if (target.kind === 'smtp') target.config = smtpConfig(data); for (const [name] of alertFields[target.kind]) target[name] = String(data.get(name) || '').trim();
    const body = { tenant_id: String(data.get('tenant_id') || '').trim() || null, name: String(data.get('name')).trim(), enabled: data.get('enabled') === 'on', min_severity: data.get('min_severity'), target };
    await api(existing ? `/alerts/channels/${existing.id}` : '/alerts/channels', { method: existing ? 'PUT' : 'POST', body }); $('#dialog').close(); notify(existing ? translate('通知通道已保存。') : translate('通知通道已添加。建议点击“测试”确认可以收到。')); await renderAlerts();
  });
  modal(existing ? msg`编辑通知通道 · ${existing.name}` : translate('添加通知通道'), form);
}
async function renderCapabilities() { const c = await api('/capabilities'); const names = { 'two-factor-login': translate('两步验证登录'), 'scoped-api-tokens': translate('带权限范围的 API 令牌'), 'node-identity-revocation-replacement': translate('节点身份撤销与替换'), 'node-credential-rotation': translate('节点凭据轮换'), announcements: translate('公告'), ddns: 'DDNS', tcp: translate('TCP 转发'), udp: translate('UDP 转发'), ipv4: 'IPv4', ipv6: 'IPv6', 'dns-targets': translate('域名目标'), 'port-ranges': translate('端口段与偏移映射'), 'outbound-binding': translate('业务出口 IP / 网卡绑定'), 'dns-ttl-cache': translate('目标 DNS TTL 缓存'), 'node-local-loop-protection': translate('节点内监听环路检查'), 'proxy-protocol-tcp-v1-v2': 'TCP PROXY v1 / v2', 'proxy-protocol-udp-v2': 'UDP PROXY v2', 'udp-destination-tracking': translate('UDP 通配监听真实目标地址'), 'weighted-round-robin': translate('加权轮询'), 'source-hash': translate('来源 IP 哈希'), 'least-connections': translate('最少连接'), 'source-cidr-acl': translate('来源网段 ACL'), 'per-rule-quota': translate('规则共享配额'), 'per-rule-bandwidth': translate('规则共享速率'), 'durable-usage': translate('持久化流量账本'), 'config-revisions': translate('版本与回滚'), 'tenant-isolation': translate('租户隔离'), 'session-revocation': translate('会话撤销'), 'tls-data-transport': translate('TLS 数据传输'), 'mutual-tls': translate('TLS 双向证书认证'), 'backup-reconciliation': translate('旧备份用量对账'), websocket: translate('WebSocket 流隧道（v1）'), 'secure-websocket': translate('WSS 与双向证书验证'), 'declared-multi-node-topology': translate('跨节点多跳引用与环路检查'), 'atomic-config-batch': translate('多节点配置预览与事务发布'), 'target-health-checks': translate('目标探测与故障恢复'), 'priority-capacity-selection': translate('优先级与目标容量选路'), 'lowest-latency-selection': translate('按探测耗时自动选择最快目标'), 'node-telemetry': translate('节点资源、吞吐与事件历史'), 'connection-prewarm': translate('中转间预热连接'), 'alert-notifications': translate('告警通知（Webhook / Telegram / 企业微信 / 飞书 / 钉钉）'), 'smtp-alerts': translate('Email / SMTP 告警（TLS / STARTTLS）'), 'tenant-alerts': translate('按租户隔离通知与事件'), mptcp: 'MPTCP', 'node-execution-leases': translate('节点执行租约'), 'node-inventory-lifecycle': translate('节点资料、批量编辑与暂停到期'), 'durable-budget-run-recovery': translate('原状态额度恢复与预留诊断'), 'multipath-aggregation': translate('单连接多路径聚合（自有 v1）'), 'global-user-budgets': translate('跨节点用户总额度'), 'hierarchical-budgets': translate('租户 / 节点分层额度'), 'budget-reservation-return': translate('空闲预留归还'), 'controller-recovery-log': translate('控制器恢复日志'), 'budget-disaster-recovery': translate('预算完整灾难恢复'), 'global-rate-limits': translate('跨节点总限速'), wireguard: translate('WireGuard 组网'), 'nat-traversal': translate('NAT 穿透'), commerce: translate('套餐与交易'), tickets: translate('支持工单'), 'commerce-wallet': translate('钱包与资金流水'), 'commerce-orders': translate('订单与退款'), 'commerce-payments': translate('支付网关与回调验签'), 'commerce-coupons': translate('优惠码'), 'commerce-gifts': translate('礼品码'), 'http-connect': translate('HTTP CONNECT 入站'), 'http2-connect-managed': translate('HTTP/2 CONNECT · 计量 / ACL / 限速 / Bearer'), 'protocol-gateways': translate('受管 VLESS / Reality / Hysteria2 / TUIC / AnyTLS / Trojan / VMess'), 'protocol-client-exports': translate('sing-box / mihomo 协议订阅'), 'destination-acl': translate('目的地 ACL'), 'config-templates': translate('规则模板'), 'mptcp-diagnostics': translate('MPTCP 能力观测'), 'mptcp-rule-transport': translate('MPTCP 规则传输与连接观测'), 'nat-pmp': translate('NAT-PMP 端口映射'), 'pcp': translate('PCP 端口映射'), 'upnp': translate('UPnP 端口映射'), 'commerce-entitlements': translate('套餐权益执行'), 'client-subscriptions': translate('客户端订阅'), announcements: translate('公告'), 'dns-records': translate('DNS 托管记录与 DDNS'), 'dns-health-removal': translate('DNS 健康摘除'), 'dns-authoritative-pool': translate('独立权威 DNS 池'), 'dns-management': translate('DNS 管理'), federation: translate('跨面板共享'), 'postgresql-ha': translate('PostgreSQL 与控制面高可用') }; const deliveryNotes = localize({ 'nat-pmp': 'CLI 工具 · 需要网关支持', pcp: 'CLI 工具 · 需要网关支持', upnp: 'CLI 工具 · 需要网关支持', 'protocol-gateways': '需在节点预装协议引擎', 'tls-data-transport': '需在节点配置证书', 'mutual-tls': '需在两端配置证书', 'smtp-alerts': '需配置并验证 SMTP', 'commerce-payments': '支付不在本轮交付范围' }); const grid = el('div', undefined, 'capabilities'); for (const [title, list, status, color] of [[translate('已接入开发版本'), c.available, translate('已实现'), 'green'], [translate('后续完整范围'), c.pending, translate('待完成或验收'), '']]) { const p = panel(title, translate('最终验收以源码中的完整清单和测试证据为准。')), body = el('div', undefined, 'panel-body'); for (const key of list) { const row = el('div', undefined, 'capability'); row.append(el('span', names[key] || key), badge(key === 'commerce-payments' ? translate('本轮不含') : status, key === 'commerce-payments' ? '' : color)); if (deliveryNotes[key]) row.append(el('span', deliveryNotes[key], 'fine')); body.append(row); } p.append(body); grid.append(p); } if (state.view === 'capabilities') $('#content').replaceChildren(grid); }

// Skip while typing in the page so a re-render does not take the input away.
setInterval(() => { const typing = $('#content').contains(document.activeElement) && document.activeElement.matches('input, select, textarea'); if (state.actor && !document.hidden && !typing && !document.querySelector('dialog[open]') && !document.body.classList.contains('nav-open') && ['overview', 'nodes', 'rules', 'usage', 'budgets', 'alerts', 'recovery', 'topology', 'health'].includes(state.view)) refresh().catch(e => notify(e.message, true)); }, 5000);
if (state.token) { api('/session').then(user => { state.actor = user; return enter(); }).catch(e => { loggedOut(); $('#login-error').textContent = e.message; }); }

const budgetScopeNames = localize({ user: '用户', tenant: '租户', node: '节点' });
async function renderBudgets() {
  const [overview, users, nodes] = await Promise.all([api('/budgets'), api('/users'), api('/nodes')]);
  const p = panel(translate('跨节点共享额度'), translate('已用 + 尚未归还的预留不能超过总额度。同一笔流量受适用的用户、租户和节点额度共同约束。'), canWrite() && !overview.allocation_paused ? button(translate('＋ 创建额度'), () => editBudget(null, users, nodes), 'primary') : null);
  if (overview.allocation_paused) p.append(el('p', translate('控制器已从备份恢复，新增额度分配暂停。恢复完整的预留记录前，系统不会重复发放旧备份中遗漏的额度。'), 'error'));
  function scopeLabel(b) { return b.scope === 'user' ? users.find(u => u.id === b.scope_id)?.username || b.scope_id : b.scope === 'node' ? nodes.find(n => n.id === b.scope_id)?.name || b.scope_id : b.scope_id; }
  if (!overview.budgets.length) p.append(empty(translate('为多个入口设置一个总额度'), translate('创建前先暂停该范围内的规则，并确认所有相关节点已应用；之后重新启用规则，系统会自动绑定额度。')));
  else p.append(table([translate('名称 / 范围'), translate('总额度'), translate('已上报用量'), translate('尚未归还预留'), translate('可分配'), translate('操作')], overview.budgets.map(b => [namedCell(b.name, `${budgetScopeNames[b.scope]} · ${scopeLabel(b)}`), bytes(b.limit_bytes), bytes(b.consumed_bytes), bytes(b.committed_bytes - b.consumed_bytes), bytes(b.limit_bytes - b.committed_bytes), budgetActions(b, users, nodes, overview.allocation_paused)])));
  p.append(el('p', translate('节点按需领取预留。全节点会话空闲或正常停机后可归还未用部分；严格节点保留原状态且交接历史连续时，重启会先核对并恢复预留；旧备份或无法确认的部分继续占额。预留明细显示当前记录，增加总额度不会清零已有账。'), 'fine'));
  if (state.view === 'budgets') $('#content').replaceChildren(p);
}
function budgetActions(budget, users, nodes, paused) {
  const actions = el('div');
  actions.append(button(translate('预留明细'), () => showBudgetReservations(budget), 'table-action'));
  if (canWrite() && !paused) actions.append(button(translate('调整额度'), () => editBudget(budget, users, nodes), 'table-action'));
  return actions;
}
async function showBudgetReservations(budget) {
  const body = el('div'), rows = [], content = el('div'), controls = el('div');
  body.append(el('p', translate('未归还部分可能包含尚未上报的消费，不能直接当作可退款余额。此列表按页读取当前记录；有变化时重新打开刷新。'), 'fine'), content, controls);
  modal(translate('预留明细 · ') + budget.name, body);
  async function load(after) {
    controls.replaceChildren(el('p', translate('加载中…'), 'fine'));
    const page = await api(`/budgets/${budget.id}/reservations${after ? '?after=' + encodeURIComponent(after) : ''}`);
    rows.push(...page.reservations);
    content.replaceChildren(rows.length ? table([translate('节点 / 运行'), translate('预留编号'), translate('已分配'), translate('已确认消费'), translate('未归还'), translate('运行保护')], rows.map(row => [
      namedCell(row.node_name, row.run_id), row.grant_id, bytes(row.allocated_bytes), bytes(row.confirmed_consumed_bytes), bytes(row.outstanding_bytes),
      !row.node_lease.policy ? translate('离线模式') : row.node_lease.active && row.node_lease.holder_run_id === row.run_id ? translate('当前运行持有租约') : translate('当前无此运行租约')
    ])) : empty(translate('没有尚未关闭的预留'), translate('已正常结算的预留不在此列表中。')));
    controls.replaceChildren();
    if (page.next) controls.append(button(translate('加载下一页'), () => load(page.next), 'table-action'));
  }
  await load(null);
}
function editBudget(existing, users, nodes) {
  const form = el('form');
  if (!existing) {
    field(form, 'name', translate('额度名称')).maxLength = 120;
    const scope = select(form, 'scope', translate('适用范围'), [['user', translate('用户：跨节点共享')], ['tenant', translate('租户：包含租户内所有用户')], ['node', translate('节点：包含节点所有规则')]], 'user');
    const target = select(form, 'scope_id', translate('选择对象'), [], '');
    function showTargets() {
      const options = scope.value === 'user' ? users.map(u => [u.id, `${u.username} · ${u.tenant_id}`]) : scope.value === 'node' ? nodes.map(n => [n.id, n.name]) : [...new Set([state.actor.tenant_id, ...users.map(u => u.tenant_id)])].map(id => [id, id]);
      target.replaceChildren(); options.forEach(([id, label]) => { const option = el('option', label); option.value = id; target.append(option); }); target.required = true;
    }
    scope.onchange = showTargets; showTargets();
  } else form.append(el('p', msg`${existing.name} · 修订 ${existing.revision}。调整下限为已用与尚未归还预留的合计。`, 'fine'));
  const limit = field(form, 'limit_bytes', translate('总额度 / bytes（0 禁止新增分配）'), existing?.limit_bytes ?? 1073741824, 'number'); limit.min = existing?.committed_bytes ?? 0;
  const quantum = field(form, 'quantum_bytes', translate('目标预留大小 / bytes'), existing?.quantum_bytes ?? 4194304, 'number'); quantum.min = 1; quantum.max = 67108864;
  form.append(el('p', translate('较大的预留减少补额频率，但失联后会占用更多未确认额度。为容纳一个 UDP 报文，单次预留可能提高到报文所需大小，最大 64 KiB。'), 'fine'));
  submit(form, existing ? translate('保存额度') : translate('创建额度'), async data => {
    const body = { limit_bytes: number(data, 'limit_bytes'), quantum_bytes: number(data, 'quantum_bytes') };
    if (existing) { body.expected_revision = existing.revision; await api(`/budgets/${existing.id}`, { method: 'PUT', body }); }
    else { Object.assign(body, { name: data.get('name'), scope: data.get('scope'), scope_id: data.get('scope_id') }); await api('/budgets', { method: 'POST', body }); }
    $('#dialog').close(); await renderBudgets();
  });
  modal(existing ? translate('调整共享额度') : translate('创建共享额度'), form);
}

async function renderRecovery() {
  const [status, metrics] = await Promise.all([api('/recovery'), api('/control/metrics')]);
  const p = panel(translate('控制器恢复保护'), translate('将数据库备份与最新恢复日志、进度清单一起保管。恢复会重放备份之后已经确认的变更。'));
  const body = el('div', undefined, 'panel-body');
  body.append(badge(status.enabled && status.healthy ? translate('已启用 · 写入正常') : status.enabled ? translate('写入停止 · 需要检查') : translate('未启用'), status.enabled && status.healthy ? 'green' : ''));
  if (status.head) body.append(table([translate('项目'), translate('当前已确认记录')], [
    [translate('日志身份'), status.head.journal_id], [translate('事务序号'), String(status.head.sequence)],
    [translate('已提交日志大小'), bytes(status.head.committed_bytes)], [translate('当前校验值'), status.head.sha256]
  ]));
  body.append(el('p', translate('恢复前停止原控制器，使用完整日志及其最新进度清单，将恢复结果写入一个新的状态目录。原备份和日志保持原样。只有备份而缺少后续日志时，无法推断遗漏的额度分配。'), 'fine'));
  const command = el('pre', 'relay restore --backup backups/controller.sqlite --recovery-log state/controller/recovery.log --output state/restored-controller', 'mono');
  body.append(command, el('p', translate('恢复日志包含身份和配置数据，须按数据库的私有权限保护。当前保护覆盖控制器记录；节点异常退出后的未知消费、密钥目录迁移、自动归档和异地日志复制仍需后续完善。'), 'fine'));
  body.append(el('h3', translate('节点同步')), el('p', translate('本次控制器运行期间的同步统计。队列拥塞时节点会稍后重试；提交完成后才确认额度和用量。'), 'fine'), table([translate('项目'), translate('次数')], [
    [translate('已处理请求'), metrics.processed_requests], [translate('完成提交批次'), metrics.committed_batches],
    [translate('最大合并请求数'), metrics.largest_batch], [translate('拥塞退回'), metrics.queue_full_rejections], [translate('提交失败'), metrics.failed_batches]
  ]));
  body.append(table([translate('同步阶段'), translate('采样数'), translate('平均 / ms'), translate('最大 / ms')], [timingRow(translate('排队与合并'), metrics.queue_time), timingRow(translate('数据库处理批次'), metrics.storage_batch_time), timingRow(translate('请求处理总时间'), metrics.request_time)]), el('p', translate('数据库阶段包含线程池、数据库锁、SQL 和恢复日志提交；总时间到持久化结果返回，不包含响应传输与 Agent 本地写入。失败的已处理请求也计入耗时，429 拥塞退回不计入。'), 'fine'));
  p.append(body); if (state.view === 'recovery') $('#content').replaceChildren(p);
}

const topologyKey = ref => `${ref.node_id}/${ref.rule_id}`;
const diagramIssues = localize({
  cycle: '存在循环引用；请修正下一跳。', missing: '引用的节点或规则不可见；无法继续展开。', truncated: '路径过大；仅显示前 16 跳、64 个节点和每组 32 个目标。',
  listen: '请填写有效的本机监听地址和端口。', address: '请填写客户端或上一跳可达的地址；通配监听地址不能作为连接地址。',
  loopback: '回环地址只适用于同机测试；跨 VPS 请使用可达网卡及地址。', disabled: '此规则期望停用，不会接收新连接。',
  agent: '尚未注册 Agent；发布配置不会自动 SSH 安装。', engine: '此 VPS 需要预先安装协议引擎并准备对应证书或 Reality 配置。',
  range: '图中显示起始端口；端口范围和偏移仍按规则设置执行。', uot_tcp: 'UDP over TCP 需要整条路径支持 TCP；纯 UDP 无法使用此模式。',
  targets: '请添加至少一个最终目标或下一跳。', target: '目标需要有效的主机与端口，不能使用通配地址。',
  protocol: '下一跳未覆盖本跳的 TCP / UDP 协议，请逐跳匹配。', tenant: '所有节点与规则所有者必须属于同一租户。',
  mismatch: '目标地址与下一跳公布的地址不一致，请重新选择下一跳。', duplicate: '每一跳请选择不同的 VPS。',
});
function forwardingPathView() {
  const box = el('section', undefined, 'forwarding-diagram'); box.setAttribute('aria-label', translate('转发路径预览'));
  const protocols = { tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' };
  const services = localize({ forward: '端口转发', ss: 'Shadowsocks 服务', socks5: 'SOCKS5 服务', http: 'HTTP CONNECT 服务', h2: 'HTTP/2 CONNECT 服务', gateway: '受管协议服务' });
  const roles = localize({ entry: '入口 VPS', relay: '中转 VPS', exit: '出口 VPS', single: '运行 VPS · 入口与出口' });
  function update(model, stage = 'draft') {
    box.replaceChildren();
    const heading = el('div', undefined, 'flow-heading');
    heading.append(el('h3', translate('转发路径预览')), badge(stage === 'validated' ? translate('服务器配置校验通过') : stage === 'saved' ? translate('已保存的期望路径') : translate('草稿 · 随编辑更新'), stage === 'validated' ? 'green' : ''));
    const figure = el('figure', undefined, 'flow-figure'), track = el('div', undefined, 'flow-track'); track.tabIndex = 0; track.setAttribute('aria-label', translate('路径图（可滚动）'));
    const client = el('div', undefined, 'flow-card flow-terminal'); client.append(el('span', translate('连接起点'), 'flow-role'), el('strong', translate('客户端 / 上游')), el('p', translate('连接入口地址'), 'fine'));
    function edge(text) { const arrow = el('div', undefined, 'flow-edge'); arrow.append(el('span', text), el('span', '→', 'flow-arrow')); arrow.lastChild.setAttribute('aria-hidden', 'true'); return arrow; }
    function tree(item) {
      const wrap = el('div', undefined, 'flow-route'), card = el('div', undefined, 'flow-card');
      if (item.kind === 'target') { card.classList.add('flow-terminal'); card.append(el('span', translate('最终目标 / 外部服务'), 'flow-role'), el('strong', item.address || translate('待填写'), 'mono'), el('p', translate('手动地址；不推断后续 VPS 或代理服务。'), 'fine')); wrap.append(card); return wrap; }
      if (item.kind === 'unresolved') { card.append(el('strong', item.name || translate('待选择')), el('p', diagramIssues[item.reason], 'fine')); wrap.append(card); return wrap; }
      card.classList.toggle('flow-service', item.service !== 'forward');
      card.append(el('span', roles[item.role], 'flow-role'), el('strong', item.name), el('span', services[item.service], 'flow-service-label'));
      const addresses = el('dl', undefined, 'flow-addresses');
      addresses.append(el('dt', translate('连接地址')), el('dd', item.endpoint || translate('待填写'), 'mono'), el('dt', translate('本机监听')), el('dd', item.listen || translate('待填写'), 'mono'));
      card.append(addresses, el('p', item.service === 'forward' ? translate('本规则由 Agent 转发流量，不启用 SS 服务。') : item.service === 'gateway' ? translate('协议引擎在此 VPS 终止代理连接。') : translate('Agent 内置服务在此 VPS 处理代理连接。'), 'fine'));
      if (item.uot) card.append(badge('UDP over TCP'));
      wrap.append(card);
      if (item.service !== 'forward') {
        const destination = el('div', undefined, 'flow-card flow-terminal'); destination.append(el('span', translate('最终目的地'), 'flow-role'), el('strong', translate('客户端请求的网站 / 服务')), el('p', translate('出口 VPS 发起连接；受目的地 ACL 限制。'), 'fine'));
        wrap.append(edge(translate('出口连接')), destination);
      } else if (item.children.length) {
        const branches = el('div', undefined, 'flow-branches');
        if (item.children.length > 1) branches.append(el('p', item.aggregate ? translate('并行子流 · 汇聚到同一规则') : translate('候选目标 · 按策略选择，不是顺序中转'), 'flow-branch-label'));
        for (const child of item.children) {
          const branch = el('div', undefined, 'flow-branch');
          let label = [protocols[child.protocol] || '—', child.transport].filter(Boolean).join(' · ');
          if (item.children.length > 1 && !item.aggregate) label += ` · ${translate('权重')} ${child.weight} · ${translate('优先级')} ${child.priority}`;
          if (child.draining) label += ' · ' + translate('维护排空');
          branch.append(edge(label), tree(child.next)); branches.append(branch);
        }
        wrap.append(branches);
      }
      return wrap;
    }
    // Gateway `protocol` describes proxied payloads, not its client wire transport.
    track.append(client, edge(model.root.service === 'gateway' ? translate('受管协议接入') : [protocols[model.root.protocol] || '—', model.root.inboundTransport].filter(Boolean).join(' · ')), tree(model.root));
    figure.append(track, el('figcaption', translate('箭头表示期望转发方向，响应沿连接返回。图示不证明防火墙、网络或业务已经连通。')));
    const checks = el('ol', undefined, 'flow-checks');
    for (const [title, text] of [[translate('配置检查'), stage === 'validated' ? translate('服务器校验通过；尚未发布此草稿。') : stage === 'saved' ? translate('显示控制器中的期望配置。') : translate('填写后校验；尚未验证完整配置。')], [translate('Agent 应用'), translate('发布后逐跳确认实际修订与期望修订一致。')], [translate('真实流量'), translate('尚未测试；用真实客户端从入口验证 TCP、UDP 和出口地址。')]]) { const item = el('li'); item.append(el('strong', title), el('span', text)); checks.append(item); }
    box.append(heading, figure, checks);
    if (model.issues.length) {
      const warnings = el('details', undefined, 'flow-warnings');
      warnings.append(el('summary', msg`需要检查 ${model.issues.length} 项`));
      const list = el('ul'); for (const issue of model.issues) list.append(el('li', (issue.name ? issue.name + ': ' : '') + diagramIssues[issue.code])); warnings.append(list); box.append(warnings);
    }
    const help = el('details'); help.append(el('summary', translate('如何理解与验证这条路径')));
    help.append(el('p', translate('入口协议、节点间传输和出口服务是不同层。SS 路径的客户端使用入口地址及出口密钥；只有标为 Shadowsocks 服务的 VPS 处理 SS，其余节点转发流量。')),
      el('p', translate('每个 VPS 都需要 Agent。监听地址属于该 VPS；连接地址必须能被客户端或上一跳访问。检查每跳端口、防火墙和来源 ACL；发布不会自动开放端口。')),
      el('p', translate('配置校验检查规则结构、引用和修订，不会发送网络探测。发布后到转发路径页检查 Agent 回执，再从入口运行真实客户端；目标健康探测只能证明所配置的探测条件。')));
    box.append(help);
  }
  return { box, update };
}
async function renderTopology() {
  const snapshot = await api('/topology');
  const names = new Map(snapshot.nodes.map(node => [node.id, node.name]));
  const rules = new Map(snapshot.configs.flatMap(config => config.rules.map(rule => [`${config.node_id}/${rule.id}`, rule])));
  const roots = forwardingPathRoots(snapshot), ids = new Set();
  const actions = el('div');
  if (canWrite()) actions.append(button(translate('批量编辑'), () => editTopologyBatch(snapshot)), button(translate('创建转发路径'), () => chooseSetup(true), 'primary'));
  const p = panel(translate('从入口到目的地'), translate('每张卡片是一条完整路径，入口、中转与出口在同一张图中。修改某台 VPS 的端口或服务，请进入对应节点规则。'), actions);
  if (!roots.length) p.append(empty(translate('还没有转发路径'), translate('从模板创建单 VPS 服务或多跳路径。发布后，这里会自动按规则引用组成路径图。'), canWrite() ? button(translate('从模板开始'), () => chooseSetup(), 'primary') : null));
  const pageSize = 10;
  state.pathPage = Math.min(state.pathPage || 0, Math.max(0, Math.ceil(roots.length / pageSize) - 1));
  for (const root of roots.slice(state.pathPage * pageSize, (state.pathPage + 1) * pageSize)) {
    const model = forwardingDiagram(snapshot, root), members = new Map();
    function collect(item) {
      if (item.kind !== 'node') return;
      members.set(`${item.node_id}/${item.rule_id}`, item); ids.add(item.node_id);
      item.children.forEach(child => collect(child.next));
    }
    collect(model.root);
    const nodeIds = [...new Set([...members.values()].map(item => item.node_id))];
    const card = el('article', undefined, 'path-summary'), head = el('div', undefined, 'path-summary-head');
    const title = el('div'); title.append(el('h3', rules.get(topologyKey(root))?.name || translate('转发路径')), el('p', msg`${nodeIds.length} 台 VPS · ${members.size} 条节点规则`, 'fine'));
    head.append(title, badge(nodeIds.length > 1 ? translate('多跳路径') : translate('单 VPS 路径'))); card.append(head);
    const view = forwardingPathView(); view.update(model, 'saved'); card.append(view.box);
    const nodeActions = el('div', undefined, 'path-node-actions');
    nodeActions.append(el('span', translate('管理各跳规则：'), 'fine'));
    for (const id of nodeIds) nodeActions.append(button(names.get(id) || id, async () => { state.selectedNode = id; await navigate('rules'); }, 'subtle'));
    const path = shadowsocksPath(snapshot, root);
    if (path) nodeActions.append(button(translate('入口客户端链接'), () => shareShadowsocks(path.exit, path.entry, path.hops.map(hop => names.get(hop.node_id)).join(' → ')), 'primary'));
    if (canWrite()) {
      const enabled = rules.get(topologyKey(root))?.enabled;
      nodeActions.append(button(enabled ? translate('停用关联链路') : translate('启用关联链路'), () => changeTopologyComponent(snapshot, topologyKey(root), !enabled)));
    }
    card.append(nodeActions); p.append(card);
  }
  if (roots.length > pageSize) {
    const pager = el('div', undefined, 'toolbar');
    const previous = button(translate('上一页'), () => { state.pathPage--; return renderTopology(); }); previous.disabled = state.pathPage === 0;
    const next = button(translate('下一页'), () => { state.pathPage++; return renderTopology(); }); next.disabled = (state.pathPage + 1) * pageSize >= roots.length;
    pager.append(previous, el('span', msg`第 ${state.pathPage + 1} 页 · 共 ${roots.length} 条路径`), next); p.append(pager);
  }
  const status = panel(translate('节点应用状态'), translate('配置在控制器一次提交，各节点异步应用。修订一致不代表业务探测成功；改向前需停用相关链路，并确认涉及节点的全部活跃会话归零。'));
  status.append(table([translate('节点'), translate('实际 / 期望修订'), translate('活跃 TCP / UDP'), translate('回报'), translate('应用结果')], snapshot.nodes.filter(node => ids.has(node.id)).map(node => [node.name, `${node.applied_revision} / ${node.desired_revision}`, `${node.stats.active_tcp} / ${node.stats.active_udp}`, timestamp(node.last_seen_ms), node.apply_error || applicationBadge(node).textContent])));
  if (state.view === 'topology') $('#content').replaceChildren(p, ...(roots.length ? [status] : []));
}
async function previewTopology(snapshot, input, summary = '', back = null, diagramRoots = []) {
  const preview = await api('/configurations/preview', { method: 'POST', body: input });
  const body = el('div');
  const combined = { ...snapshot, configs: snapshot.configs.map(config => preview.configs.find(updated => updated.node_id === config.node_id) || config) };
  for (const root of diagramRoots) { const view = forwardingPathView(); view.update(forwardingDiagram(combined, root), 'validated'); body.append(view.box); }
  if (summary) body.append(el('p', summary, 'workflow-callout'));
  body.append(el('p', translate('下面是服务器校验后的变更。发布会同时提交期望配置；节点应用结果请在转发路径页逐项确认。')), table([translate('节点'), translate('修订'), translate('新增 / 修改 / 删除规则')], preview.changes.map(change => [snapshot.nodes.find(node => node.id === change.node_id)?.name || change.node_id, `${change.from_revision} → ${change.to_revision}`, `${change.added.length} / ${change.modified.length} / ${change.removed.length}`])));
  for (const change of preview.changes) for (const diff of change.rule_changes) { const details = el('details'); details.append(el('summary', msg`${diff.after?.name || diff.before?.name} · 查看发布前后配置`), el('pre', JSON.stringify({ before: diff.before, after: diff.after }, null, 2))); body.append(details); }
  if (back) body.append(button(translate('返回编辑'), back));
  body.append(button(translate('发布这些变更'), async () => { await api('/configurations/publish', { method: 'POST', body: input }); $('#dialog').close(); notify(translate('期望配置已同时提交，正在等待各节点应用。')); await navigate('topology'); }, 'primary'));
  modal(translate('发布前检查'), body);
}
async function changeTopologyComponent(snapshot, seed, enabled) {
  const selected = new Set([seed]); let changed = true;
  while (changed) { changed = false; for (const edge of snapshot.graph.edges) { const a = topologyKey(edge.from), b = topologyKey(edge.to); if (selected.has(a) || selected.has(b)) { if (!selected.has(a) || !selected.has(b)) changed = true; selected.add(a); selected.add(b); } } }
  const updates = snapshot.configs.filter(config => config.rules.some(rule => selected.has(`${config.node_id}/${rule.id}`))).map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: config.rules.map(rule => selected.has(`${config.node_id}/${rule.id}`) ? { ...rule, enabled } : rule) }));
  await previewTopology(snapshot, { updates });
}
async function newTopologyChain(snapshot, preset = {}) {
  if (snapshot.nodes.length < 2) { notify(translate('创建路径需要至少两个节点。请先注册并在对应 VPS 安装 Agent。'), true); return; }
  const users = await api('/users');
  const form = el('form'), rows = [], holder = el('div'), header = el('div', undefined, 'form-grid path-config-header');
  form.append(el('h3', translate('1. 选择路径类型'), 'setup-step'));
  field(header, 'name', translate('链路名称'), preset.name || '').maxLength = 80;
  const ownerField = select(header, 'owner', translate('规则所有者（须与所有节点同一租户）'), users.map(user => [user.id, `${user.username} · ${user.tenant_id}`]), state.actor.id);
  const mode = select(header, 'exit_service', translate('出口服务'), localize([['forward', '转发到固定目标'], ['ss', '在出口 VPS 创建 Shadowsocks']]), preset.mode || 'forward');
  const protocol = select(header, 'protocol', translate('传输协议（TCP / UDP）'), [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], preset.protocol || 'tcp');
  const transport = select(header, 'transport', translate('节点间传输'), [['plain', translate('原生 TCP / UDP')], ['ws', translate('WS 流隧道 · 仅 TCP')], ['wss', translate('WSS 双向证书 · 仅 TCP')]], 'plain');
  form.append(header);
  const pathView = forwardingPathView();
  const placement = el('p', '', 'workflow-callout'); form.append(placement);
  const secure = el('div', undefined, 'form-grid');
  const identity = field(secure, 'server_identity', translate('中转 / 出口的服务器证书编号'), 'server');
  const authority = field(secure, 'ca_identity', translate('各节点的信任 CA 编号'), 'root');
  const clientIdentity = field(secure, 'client_identity', translate('入口 / 中转的客户端证书编号'), 'client');
  const wsFields = el('div'); const wsPath = field(wsFields, 'ws_path', translate('WebSocket 路径'), '/relay'); wsPath.maxLength = 1024;
  form.append(secure, wsFields, el('h3', translate('2. 按顺序选择 VPS 和端口'), 'setup-step'), holder);
  let serial = 0;
  function draw() {
    holder.replaceChildren();
    rows.forEach((row, index) => {
      row.legend.textContent = index === 0 ? translate('入口 VPS · 客户端连接这里') : index === rows.length - 1 ? translate('出口 VPS · 最后一跳') : msg`中转 VPS · 第 ${index + 1} 跳`;
      row.up.disabled = index === 0; row.down.disabled = index === rows.length - 1; row.remove.disabled = rows.length <= 2;
      holder.append(row.card);
    });
    show();
  }
  function add() {
    if (rows.length >= 16) return;
    const index = serial++, card = el('fieldset', undefined, 'path-hop'), legend = el('legend'); card.append(legend);
    const fields = el('div', undefined, 'form-grid'); card.append(fields);
    const node = select(fields, `node-${index}`, translate('运行节点 / VPS'), snapshot.nodes.map(n => [n.id, n.name]), snapshot.nodes.find(n => !rows.some(r => r.node.value === n.id))?.id || snapshot.nodes[0].id);
    const listen = field(fields, `listen-${index}`, translate('本机监听地址'), `0.0.0.0:${19001 + index}`);
    const advertise = field(fields, `advertise-${index}`, translate('客户端或上一跳连接的地址')); advertise.placeholder = `vps.example.com:${19001 + index}`;
    const tlsName = field(fields, `tls_name-${index}`, translate('此节点证书中的服务名'), '', 'text', false);
    const sources = textarea(card, `sources-${index}`, translate('此跳允许来源 CIDR（留空不限）'));
    const note = el('p', '', 'fine'); card.append(note);
    const row = { card, legend, node, listen, advertise, tlsName, sources, note };
    const controls = el('div', undefined, 'toolbar');
    row.up = button(translate('上移'), () => { const i = rows.indexOf(row); if (i > 0) [rows[i - 1], rows[i]] = [rows[i], rows[i - 1]]; draw(); });
    row.down = button(translate('下移'), () => { const i = rows.indexOf(row); if (i < rows.length - 1) [rows[i], rows[i + 1]] = [rows[i + 1], rows[i]]; draw(); });
    row.remove = button(translate('移除此跳'), () => { if (rows.length > 2) rows.splice(rows.indexOf(row), 1); draw(); });
    controls.append(row.up, row.down, row.remove); card.append(controls);
    node.addEventListener('change', show); listen.addEventListener('input', show); advertise.addEventListener('input', show);
    rows.push(row);
  }
  const appendHop = button(translate('＋ 添加一跳'), () => { add(); draw(); }); form.append(appendHop);
  const targetBox = el('div'); const targets = textarea(targetBox, 'targets', translate('出口最终目标（每行一个；多个目标为加权相同的候选）'), '', true); form.append(targetBox);
  const ss = shadowsocksEditor(null); form.append(ss.box);
  ss.setEnabled(mode.value === 'ss');
  function show() {
    const proxy = mode.value === 'ss';
    if (proxy) transport.value = 'plain'; transport.disabled = proxy;
    const ws = transport.value !== 'plain', tls = transport.value === 'wss';
    if (ws) protocol.value = 'tcp'; protocol.disabled = ws;
    sectionVisible(secure, tls); sectionVisible(wsFields, ws); sectionVisible(targetBox, !proxy); targets.required = !proxy;
    sectionVisible(ss.box, proxy); ss.box.open = proxy;
    appendHop.disabled = rows.length >= 16;
    const names = rows.map(row => snapshot.nodes.find(n => n.id === row.node.value)?.name || '—');
    placement.textContent = proxy ? msg`路径：${names.join(' → ')}。SS 仅运行于最后的 ${names.at(-1)}；前面的 VPS 转发加密流量。所有 VPS 都需要 Agent，SS 已内置。` : msg`路径：${names.join(' → ')} → 固定目标。每个 VPS 创建一条转发规则；不会安装额外代理服务。`;
    rows.forEach((row, index) => {
      row.tlsName.disabled = !tls || index === 0; row.tlsName.required = tls && index > 0; row.tlsName.parentElement.classList.toggle('hidden', !tls || index === 0);
      const node = snapshot.nodes.find(n => n.id === row.node.value);
      row.note.textContent = (index === 0 ? translate('入口来源为客户端地址。') : translate('中转或出口通常看到上一跳地址；请勿直接复制客户端来源白名单。')) + ' ' + (node.enrolled ? translate('已注册 Agent；发布后检查应用回执。') : translate('尚未连接 Agent；发布只保存配置，不会自动 SSH 安装。')) + (splitEndpoint(row.listen.value)?.loopback ? ' ' + translate('回环监听仅用于同机测试，跨 VPS 需要可达监听地址。') : '');
    });
    pathView.update(forwardingPathDiagram(snapshot, { hops: rows.map(row => ({ node_id: row.node.value, listen: row.listen.value, advertise: row.advertise.value })),
      mode: mode.value, protocol: protocol.value, transport: transport.value, owner: users.find(u => u.id === ownerField.value),
      uot: proxy && ss.read()?.udp_over_tcp, targets: targets.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean).map(address => ({ address, weight: 1 })),
    }));
  }
  mode.addEventListener('change', () => { sectionVisible(ss.box, true); ss.setEnabled(mode.value === 'ss'); if (mode.value === 'ss') protocol.value = 'both'; show(); });
  transport.addEventListener('change', show);
  protocol.addEventListener('change', show); ownerField.addEventListener('change', show); targets.addEventListener('input', show); ss.box.addEventListener('change', show);
  add(); add(); draw();
  form.append(el('h3', translate('3. 检查整条路径'), 'setup-step'), pathView.box);
  form.append(el('p', translate('先校验并预览，再发布到各节点。发布不会开放防火墙；每跳独立计量。SS 路径分享链接使用入口地址和出口密钥。其他受管协议仍需先在出口节点配置服务及引擎。'), 'fine'));
  submit(form, translate('校验并预览链路'), async data => {
    const messages = localize({ path_hops: '路径需要 2–16 跳。', path_duplicate: '每一跳请选择不同的 VPS。', path_name: '请填写路径名称。', path_mode: '请选择有效的路径类型和传输协议。', path_transport: 'WS / WSS 仅支持 TCP；SS 向导使用原生转发。', path_ss: '请为出口选择 Shadowsocks 加密方式。', path_targets: '请填写至少一个最终目标。', path_tenant: '所有节点与规则所有者必须属于同一租户。', path_listen: '请为每一跳填写有效的监听地址和端口。', path_advertise: '请填写每一跳实际可达的 IP 或域名和端口，不能使用通配地址。', path_config: '节点配置缺失，请刷新后重试。' });
    let input;
    try {
      input = buildForwardingPath(snapshot, {
        name: String(data.get('name')), owner: users.find(u => u.id === ownerField.value), mode: mode.value,
        protocol: protocol.value, transport: transport.value, ws_path: wsPath.value.trim(), server_identity: identity.value.trim(), ca_identity: authority.value.trim(), client_identity: clientIdentity.value.trim(),
        shadowsocks: mode.value === 'ss' ? ss.read() : null,
        targets: targets.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean).map(address => ({ address, weight: 1 })),
        hops: rows.map(row => ({ node_id: row.node.value, listen: row.listen.value, advertise: row.advertise.value, tls_name: row.tlsName.value.trim(), allow_sources: row.sources.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean) })),
      }, () => crypto.randomUUID());
    } catch (error) { throw new Error(messages[error.message] || error.message); }
    await previewTopology(snapshot, input, placement.textContent, () => modal(translate('创建转发路径 · 入口 → 中转 → 出口'), form), [{ node_id: input.updates[0].node_id, rule_id: input.updates[0].rules.at(-1).id }]);
  });
  modal(translate('创建转发路径 · 入口 → 中转 → 出口'), form);
}

function editTopologyBatch(snapshot) {
  const form = el('form'); const input = textarea(form, 'batch', translate('节点配置批次（删除不需要发布的节点）'), JSON.stringify({ updates: snapshot.configs.map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: config.rules })) }, null, 2), true); input.rows = 20;
  form.append(el('p', translate('保留每个节点的其他规则；省略的规则表示删除。服务器会校验所有引用、修订和停止确认条件。'), 'fine'));
  submit(form, translate('校验并预览'), async data => previewTopology(snapshot, JSON.parse(data.get('batch')))); modal(translate('批量编辑配置'), form);
}

function healthEditor(form, spec, protocol) {
  const box = el('details'); box.open = !!spec; box.append(el('summary', translate('目标健康、故障摘除与恢复')));
  const enabled = select(box, 'health_enabled', translate('主动探测'), [['off', translate('关闭')], ['on', translate('启用 · 仅选择已通过探测的目标')]], spec ? 'on' : 'off');
  const grid = el('div', undefined, 'form-grid'), numbers = {};
  for (const [key, label, fallback, min, max] of [['interval_ms', translate('探测间隔 / 毫秒'), 1000, 100, 300000], ['timeout_ms', translate('单次超时 / 毫秒（不超过间隔）'), 1000, 25, 60000], ['unhealthy_threshold', translate('连续失败几次摘除'), 2, 1, 20], ['healthy_threshold', translate('连续成功几次接纳 / 恢复'), 2, 1, 20], ['recovery_delay_ms', translate('恢复后的持续观察 / 毫秒'), 5000, 0, 600000], ['max_age_ms', translate('结果有效期 / 毫秒（至少间隔 + 超时）'), 10000, 125, 3600000]]) { const input = field(grid, `health_${key}`, label, spec?.[key] ?? fallback, 'number'); input.min = min; input.max = max; numbers[key] = input; }
  const tcp = el('fieldset'); tcp.append(el('legend', translate('TCP 目标')));
  const tcpMode = select(tcp, 'health_tcp_kind', translate('成功条件'), [['connect', translate('建立传输 · 含 TLS / WS 握手，不验证业务回复')], ['exchange', translate('发送探测请求，并校验响应前缀')]], spec?.tcp?.kind || 'connect');
  const tcpFields = el('div');
  const tcpRequest = textarea(tcpFields, 'health_tcp_request', translate('请求内容 / Base64（最多 1024 字节，可留空等待欢迎消息）'), spec?.tcp?.request_base64 || '');
  const tcpExpected = textarea(tcpFields, 'health_tcp_expected', translate('预期响应前缀 / Base64（1～1024 字节）'), spec?.tcp?.expected_base64 || '', true);
  const halfClose = select(tcpFields, 'health_tcp_fin', translate('发送请求后关闭写方向'), [['no', translate('保持写方向')], ['yes', translate('发送 FIN，继续等待回复')]], spec?.tcp?.half_close ? 'yes' : 'no');
  tcp.append(tcpFields);
  const udp = el('fieldset'); udp.append(el('legend', translate('UDP 目标 · 必须收到完整且匹配的响应包')));
  const udpRequest = textarea(udp, 'health_udp_request', translate('请求包 / Base64（1～1024 字节）'), spec?.udp?.request_base64 || '', true);
  const udpExpected = textarea(udp, 'health_udp_expected', translate('完整预期回复 / Base64（1～1024 字节）'), spec?.udp?.expected_base64 || '', true);
  for (const input of [tcpRequest, tcpExpected, udpRequest, udpExpected]) input.maxLength = 1368;
  function show() {
    const on = enabled.value === 'on', hasTcp = protocol.value !== 'udp', hasUdp = protocol.value !== 'tcp';
    grid.classList.toggle('hidden', !on); Object.values(numbers).forEach(input => { input.disabled = !on; });
    tcp.classList.toggle('hidden', !on || !hasTcp); tcpMode.disabled = !on || !hasTcp;
    const exchange = on && hasTcp && tcpMode.value === 'exchange'; tcpFields.classList.toggle('hidden', !exchange); [tcpRequest, tcpExpected, halfClose].forEach(input => { input.disabled = !exchange; });
    udp.classList.toggle('hidden', !on || !hasUdp); [udpRequest, udpExpected].forEach(input => { input.disabled = !on || !hasUdp; });
  }
  for (const input of [enabled, tcpMode, protocol]) input.addEventListener('change', show);
  box.append(grid, tcp, udp, el('p', translate('首次通过探测前、结果过期或全部目标不可用时，新业务会被拒绝。探测使用节点实际出口与传输参数，报文应能重复执行。源节点探测统计单列；经过中转时，下游规则仍按收到的应用负载计量。'), 'fine')); form.append(box); show();
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
  if (!nodes.length) { if (state.view === 'health') $('#content').replaceChildren(empty(translate('还没有节点'), translate('先接入节点，再在规则中设置目标健康探测。'))); return; }
  if (!nodes.some(n => n.id === state.selectedNode)) state.selectedNode = nodes[0].id;
  const selected = state.selectedNode, toolbar = el('div', undefined, 'toolbar'), selector = el('select'); selector.setAttribute('aria-label', translate('选择节点'));
  nodes.forEach(node => { const option = el('option', node.name); option.value = node.id; selector.append(option); }); selector.value = selected; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; toolbar.append(selector);
  const snapshot = await api(`/nodes/${selected}/health`);
  if (state.view !== 'health' || state.selectedNode !== selected) return;
  const node = nodes.find(n => n.id === selected);
  toolbar.append(badge(msg`生效 v${snapshot.applied_revision} / 期望 v${snapshot.desired_revision}`), badge(online(node) ? translate('控制在线') : translate('无近期控制回报'), online(node) ? 'green' : 'orange'), button(translate('配置规则'), () => navigate('rules')));
  const panelHealth = panel(translate('目标观测与选路'), translate('TCP 与 UDP 独立判断；同优先级按规则的均衡策略分配，低优先级目标作为候选后备。已有 TCP 不会因单次健康状态变化被强制迁移。丢包与抖动按每个端点最近 20 次探测计算；“最低延迟”选路把丢包计入耗时。'));
  const kinds = { tcp_connect: translate('传输建立'), tcp_exchange: translate('TCP 响应前缀'), udp_exchange: translate('UDP 完整回复') };
  const statuses = { unknown: translate('尚未确认'), healthy: translate('探测通过'), unhealthy: translate('已摘除'), recovering: translate('恢复观察'), stale: translate('结果过期') };
  const reasons = { eligible: translate('参与优先池'), standby: translate('后备候选'), unknown: translate('等待探测确认'), unhealthy: translate('故障排除'), recovering: translate('等待持续成功'), stale: translate('等待新结果'), at_capacity: translate('会话已满'), expired: translate('规则已到期') };
  const errors = { dns: translate('域名解析失败'), transport: translate('连接、握手或路径检查失败'), timeout: translate('探测超时'), io: translate('收发失败'), unexpected_response: translate('回复不符或提前关闭'), expired: translate('规则已到期') };
  const info = el('div', undefined, 'panel-body'); info.append(el('p', msg`最近节点回报：${timestamp(snapshot.last_seen_ms)} · ${snapshot.reports.length} / ${snapshot.expected_endpoints} 个配置端点有记录 · 当前探测 ${snapshot.active_probes} 个`)); if (snapshot.apply_error) info.append(el('p', msg`配置应用失败：${snapshot.apply_error}`, 'error')); panelHealth.append(info);
  if (!snapshot.reports.length) panelHealth.append(empty(translate('暂无目标探测结果'), snapshot.expected_endpoints ? translate('节点尚未上报这些端点的结果，不能视为健康。') : translate('在规则编辑器启用健康探测，填写对应业务的成功条件。')));
  else panelHealth.append(table([translate('规则 / 目标'), translate('端口 / 成功条件'), translate('观测状态'), translate('选路原因'), translate('优先级 / 会话'), translate('耗时 / 丢包 · 抖动'), translate('连续成功 / 失败'), translate('诊断')], snapshot.reports.map(r => {
    const diagnostic = el('details'); diagnostic.append(el('summary', r.last_error ? errors[r.last_error] : translate('查看探测统计')), el('p', msg`完成 ${r.completed_checks} 次，成功 ${r.successful_checks} 次`), el('p', msg`结果年龄 ${r.sample_age_ms === null ? '—' : msg`${(r.sample_age_ms / 1000).toFixed(1)} 秒`}，有效期 ${(r.max_age_ms / 1000).toFixed(1)} 秒`), el('p', msg`源节点探测应用量：发送 ${bytes(r.probe_sent_bytes)} / 接收 ${bytes(r.probe_received_bytes)}`), el('p', msg`节点记录时间：${timestamp(r.checked_at_ms)}`));
    return [namedCell(snapshot.rule_names?.[r.rule_id] || r.rule_id, r.target_address), `${r.listen_port} / ${kinds[r.probe_kind]}`, badge(statuses[r.status], r.eligible ? 'green' : 'orange'), r.selection_reason === 'degraded' ? namedCell(translate('丢包降级'), translate('同级暂作后备')) : r.selection_reason === 'draining' ? namedCell(translate('维护排空'), translate('仅作最后备用')) : reasons[r.selection_reason] || r.selection_reason, `${r.priority} / ${r.active_sessions} / ${r.max_sessions ?? translate('不限')}`, namedCell(r.latency_ewma_us === null ? '—' : `${(r.latency_ewma_us / 1000).toFixed(2)} ms`, r.window_checks ? msg`丢包 ${Math.round(100 * r.window_failures / r.window_checks)}% · 抖动 ${r.jitter_us == null ? '—' : `${(r.jitter_us / 1000).toFixed(2)} ms`}` : translate('尚无探测')), `${r.consecutive_successes} / ${r.consecutive_failures}`, diagnostic];
  })));
  $('#content').replaceChildren(toolbar, panelHealth);
}
