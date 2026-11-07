import { t as translate, msg, localize, getLanguage, setupLanguageSwitcher, eventMessage, incidentMessage } from '/assets/i18n.js';
import { createConsoleUI, canVisit, parseRoute, navView } from '/assets/console-ui.js';
import { createGlobe, cities, cityFor } from '/assets/globe.js';
import { serviceKind, splitEndpoint, clientEndpoint, applicationState, buildForwardingPath, shadowsocksPath, shadowsocksClientProfile, forwardingDiagram, forwardingPathDiagram, forwardingPathRoots } from '/assets/workflows.js';
const $ = (s, root = document) => root.querySelector(s);
const state = { token: sessionStorage.getItem('relay-session'), actor: null, view: 'overview', overviewFilter: '', nodes: [], usage: [], nodeFilter: {}, selectedNodes: new Set(), selectedNode: null, dnsZone: null, config: null, features: {}, busy: false };
const titles = localize({ overview: '运行总览', nodes: '节点管理', rules: '转发规则 · 按服务器', topology: '转发规则', health: '目标健康', usage: '流量账本', subscriptions: '客户端订阅', dns: 'DNS 管理', wireguard: 'WireGuard 组网', federation: '跨面板共享', announcements: '公告', commerce: '钱包与订单', tickets: '工单', templates: '规则模板', budgets: '共享额度', users: '用户与权限', account: '账户安全', logs: '实时日志', diagnostics: '诊断报告', audit: '操作审计', alerts: '告警通知', recovery: '恢复保护', features: '可选功能', capabilities: '功能进度', guide: '使用指南' });
const roleNames = localize({ system_admin: '系统管理员', tenant_admin: '租户管理员', viewer: '只读用户' });
const canWrite = () => state.actor?.role !== 'viewer';
const scopeNames = localize({ read: '读取全部可见数据', 'nodes:write': '节点与配置写入', 'budgets:write': '共享额度写入', 'users:write': '用户与租户写入' });
// Appearance affects this browser only. Dark with the coral ("ember") accent is the
// default; status colors stay fixed whichever brand accent is chosen.
function readPreference(key, choices, fallback) {
  try { const value = localStorage.getItem(key); return choices.includes(value) ? value : fallback; }
  catch { return fallback; }
}
const themeMedia = matchMedia('(prefers-color-scheme: dark)');
const accents = ['ember', 'indigo', 'violet', 'rose', 'emerald', 'cyan', 'sky', 'graphite'];
let themePreference = readPreference('relay-theme', ['light', 'dark', 'system'], 'dark');
// Accents saved by earlier versions map to their closest current color.
const legacyAccents = { terracotta: 'ember', blue: 'indigo', cobalt: 'indigo', green: 'emerald' };
let accentPreference = readPreference('relay-accent', [...accents, ...Object.keys(legacyAccents)], 'ember');
accentPreference = legacyAccents[accentPreference] || accentPreference;
function applyTheme(theme, persist = true) {
  themePreference = ['light', 'dark', 'system'].includes(theme) ? theme : 'dark';
  const root = document.documentElement; root.classList.add('theme-switching');
  root.dataset.theme = themePreference === 'system' ? (themeMedia.matches ? 'dark' : 'light') : themePreference;
  if (persist) { try { localStorage.setItem('relay-theme', themePreference); } catch { /* Usable without storage. */ } }
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('theme-switching')));
}
function applyAccent(accent, persist = true) {
  accentPreference = accents.includes(accent) ? accent : 'ember';
  document.documentElement.dataset.accent = accentPreference;
  if (persist) { try { localStorage.setItem('relay-accent', accentPreference); } catch { /* Usable without storage. */ } }
}
// Card color wash strength, 0-100: 0 turns the washes off, 100 is the strongest wash that keeps every text color at 4.5:1.
let washPreference = (() => { try { const saved = localStorage.getItem('relay-wash'), value = Number(saved); return saved && value >= 0 && value <= 100 ? value : 90; } catch { return 90; } })();
function applyWash(level, persist = true) {
  washPreference = Math.min(100, Math.max(0, Math.round(Number(level)) || 0));
  document.documentElement.style.setProperty('--wash-level', String(washPreference / 100));
  if (persist) { try { localStorage.setItem('relay-wash', String(washPreference)); } catch { /* Usable without storage. */ } }
}
applyTheme(themePreference, false); applyAccent(accentPreference, false); applyWash(washPreference, false);
themeMedia.addEventListener('change', () => { if (themePreference === 'system') applyTheme('system', false); });
$('#theme').onclick = () => showAppearance();
// The monitoring layout and color theme are independent browser preferences.
function readOverviewLayout() {
  try { return localStorage.getItem('relay-overview-layout') === 'workspace' ? 'workspace' : 'monitoring'; }
  catch { return 'monitoring'; }
}
let overviewLayout = readOverviewLayout();
function applyOverviewLayout(layout = overviewLayout, persist = false) {
  overviewLayout = layout === 'workspace' ? 'workspace' : 'monitoring';
  const visible = !!state.actor && state.view === 'overview';
  if (visible) document.body.dataset.overviewLayout = overviewLayout;
  else delete document.body.dataset.overviewLayout;
  if (persist) { try { localStorage.setItem('relay-overview-layout', overviewLayout); } catch { /* Switching still works without storage. */ } }
}
applyOverviewLayout();
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notify(message, failure = false) { const n = $('#notification'); n.textContent = message; n.classList.remove('hidden'); n.classList.toggle('failure', failure); }
function button(text, handler, cls = 'subtle') { const n = el('button', text, cls); n.type = 'button'; n.addEventListener('click', () => Promise.resolve().then(handler).catch(e => notify(e.message, true))); return n; }
function bytes(n) { n = Number(n); if (!n) return '0 B'; const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1); return `${(n / 1024 ** i).toFixed(i ? 2 : 0)} ${u[i]}`; }
function timestamp(n) { return n ? new Date(n).toLocaleString(getLanguage(), { hour12: false }) : translate('尚未回报'); }
function badge(text, color = '') { return el('span', text, `badge ${color}`); }
function online(node) { return node.last_seen_ms && Date.now() - node.last_seen_ms < 30_000; }
async function api(path, options = {}) {
  const requestToken = state.token;
  const response = await fetch(`/api/v1${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(requestToken ? { Authorization: `Bearer ${requestToken}` } : {}), ...options.headers }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  const text = await response.text(); let result; try { result = JSON.parse(text); } catch { result = { error: text || `HTTP ${response.status}` }; }
  if (!response.ok) { if (response.status === 401 && path !== '/auth/login' && state.token === requestToken) loggedOut(); throw Object.assign(new Error(rateLimitReason(result.error) || result.error || msg`请求失败 HTTP ${response.status}`), { detail: result }); } return result;
}
setupLanguageSwitcher(() => {
  if (!state.actor) { document.title = translate('Relay · 独立转发平台'); return; }
  showIdentity();
  $('#view-title').textContent = titles[state.view];
  $('#notification').classList.add('hidden');
  consoleUI.sync(state.view);
  refresh().catch(error => notify(error.message, true));
});
const consoleUI = createConsoleUI({ navigate, getActor: () => state.actor, getView: () => state.view, el, button, modal, titles });
function loggedOut() { consoleUI.reset(); state.view = 'overview'; state.token = null; state.actor = null; applyOverviewLayout(); state.nodes = []; state.nodeFilter = {}; state.selectedNodes.clear(); sessionStorage.removeItem('relay-session'); resetSecondFactor(); $('#application').classList.add('hidden'); $('#login-screen').classList.remove('hidden'); $('#dialog').close(); state.config = null; state.selectedNode = null; $('#content').replaceChildren(); $('#identity').textContent = ''; $('#status-pill').textContent = ''; document.title = translate('Relay · 独立转发平台'); window.scrollTo({ top: 0 }); $('#login-form [name=username]').focus(); }
// Editing and details open as a sheet on the right; short confirmations stay centered.
function modal(title, content, variant = 'sheet') { const dialog = $('#dialog'); $('#dialog-title').textContent = title; $('#dialog-body').replaceChildren(content); dialog.className = variant; if (!dialog.open) dialog.showModal(); dialog.scrollTop = 0; }
function showIdentity() { const { username, role } = state.actor; $('#identity-name').textContent = username; $('#identity-role').textContent = roleNames[role]; $('#identity-avatar').textContent = username.slice(0, 1).toUpperCase(); $('.identity').title = `${username} · ${roleNames[role]}`; }
function showAppearance() {
  const body = el('div', undefined, 'appearance-settings');
  body.append(el('p', translate('深色优先的工作空间，可自选主题、强调色与显示方式。设置自动保存在当前浏览器。'), 'muted'));
  function choices(name, title, options, current, change) {
    const group = el('fieldset'); group.dataset.preference = name; group.append(el('legend', title));
    const grid = el('div', undefined, 'appearance-options');
    for (const [value, title, detail] of options) {
      const label = el('label', undefined, 'appearance-choice'), input = el('input');
      input.type = 'radio'; input.name = name; input.value = value; input.checked = value === current;
      input.onchange = () => { if (input.checked) change(value); };
      const copy = el('span'); copy.append(el('strong', title)); if (detail) copy.append(el('small', detail));
      label.append(input);
      if (name === 'accent') { const swatch = el('i', undefined, 'accent-swatch'); swatch.dataset.accent = value; swatch.setAttribute('aria-hidden', 'true'); label.append(swatch); }
      label.append(copy); grid.append(label);
    }
    group.append(grid); body.append(group);
  }
  choices('theme', translate('界面主题'), [['dark', translate('深色（默认）')], ['light', translate('浅色')], ['system', translate('跟随系统')]], themePreference, applyTheme);
  choices('accent', translate('强调色'), [['ember', translate('珊瑚（默认）')], ['indigo', translate('靛蓝')], ['violet', translate('紫罗兰')], ['rose', translate('玫瑰')], ['emerald', translate('翡翠绿')], ['cyan', translate('湖青')], ['sky', translate('天蓝')], ['graphite', translate('石墨')]], accentPreference, applyAccent);
  body.append(el('p', translate('强调色用于导航和主要操作；卡片与图表使用固定的配色，正常、警告与错误保留固定的状态色和文字。'), 'fine'));
  const wash = el('fieldset'), slider = el('input'), level = el('output', `${washPreference}%`), row = el('div', undefined, 'wash-control');
  wash.dataset.preference = 'wash'; wash.append(el('legend', translate('卡片配色')));
  Object.assign(slider, { type: 'range', min: '0', max: '100', step: '5', value: String(washPreference) }); slider.setAttribute('aria-label', translate('卡片配色强度'));
  const setWash = value => { applyWash(value); slider.value = String(washPreference); level.textContent = `${washPreference}%`; };
  slider.oninput = () => setWash(slider.value);
  row.append(slider, level, button(translate('恢复默认'), () => setWash(90), 'subtle'));
  wash.append(row, el('small', translate('每张卡片顶部的淡彩渐变。拖到 0 关闭；最右侧是仍能保证文字清晰的最强一档。')));
  body.append(wash);
  choices('layout', translate('总览显示模式'), [['monitoring', translate('展开总览'), translate('大图表、完整宽度的路径图和事件列表。')], ['workspace', translate('紧凑总览'), translate('较小的图表与摘要，适合日常管理。')]], overviewLayout, mode => {
    applyOverviewLayout(mode, true); if (state.view === 'overview') refresh().catch(e => notify(e.message, true));
  });
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('完成'), () => $('#dialog').close(), 'primary')); body.append(actions);
  modal(translate('外观与布局'), body);
}
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
    modal(promptMode ? translate('输入信息') : translate('确认操作'), form, 'confirm');
    if (input) input.focus();
  });
}
const confirmAction = message => panelQuestion(message, '', false);
const promptValue = (message, initial = '') => panelQuestion(message, initial, true);
$('#dialog-close').onclick = () => { $('#dialog').close(); $('#dialog-body').replaceChildren(); };
// The close event is queued; a follow-up modal may already have reopened the dialog with new content.
$('#dialog').addEventListener('close', () => { if (!$('#dialog').open) $('#dialog-body').replaceChildren(); });
function panel(title, description, action) { const n = el('section', undefined, 'panel'); const head = el('div', undefined, 'panel-head'); const info = el('div'); info.append(el('h2', title)); if (description) info.append(el('p', description)); head.append(info); if (action) head.append(action); n.append(head); return n; }
// Two related panels side by side on wide screens, stacked on narrow ones.
function pair(...items) { const n = el('div', undefined, 'panel-pair'); n.append(...items); return n; }
function empty(title, description, action) { const n = el('div', undefined, 'empty'); n.append(el('div', '◇', 'empty-symbol'), el('h2', title), el('p', description)); if (action) n.append(action); return n; }
function table(headers, rows) { const wrap = el('div', undefined, 'table-wrap'), t = el('table'), head = el('thead'), tr = el('tr'), body = el('tbody'); wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', msg`数据表：${headers.filter(h => typeof h === 'string' && h).slice(0, 3).join(' / ')}；可横向滚动`); headers.forEach(h => { const cell = el('th', h); cell.scope = 'col'; tr.append(cell); }); head.append(tr); rows.forEach(values => { const row = el('tr'); values.forEach(value => { const cell = el('td'); value instanceof Node ? cell.append(value) : cell.textContent = value; row.append(cell); }); body.append(row); }); t.append(head, body); wrap.append(t); return wrap; }
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
// Speed limits: the combined (upload + download) limit, upload-only and download-only limits, or any mix,
// all applying at once. Upload is what a hop's client sends toward its target, download what comes back.
// Rule and server limits can also burst: above the limit up to the burst rate while burst credit lasts.
const rateModes = localize([['combined', '上下行合计'], ['separate', '分别限制上传和下载'], ['both', '合计并分别限制上传和下载']]);
const rateLanes = localize({ combined: '合计', upload: '上传', download: '下载' });
function rateParts(rate, limits) {
  return { combined: [rate ?? null, limits?.burst || null], upload: [limits?.upload_bytes_per_sec ?? null, limits?.upload_burst || null], download: [limits?.download_bytes_per_sec ?? null, limits?.download_burst || null] };
}
// Each limit that is set, in `unit` (mbit or bytes/s). A combined limit alone reads as before.
function rateLines(rate, limits, unit = mbit) {
  const parts = rateParts(rate, limits);
  if (parts.upload[0] == null && parts.download[0] == null && !parts.combined[1]) return rate ? [unit(rate)] : [];
  return Object.entries(parts).filter(([, [value]]) => value != null).map(([lane, [value, burst]]) => {
    const text = msg`${rateLanes[lane]} ${unit(value)}`;
    return burst ? msg`${text}（突发 ${unit(burst.bytes_per_sec)} · ${burst.secs} 秒）` : text;
  });
}
// The same on one line; empty when nothing is set.
function rateText(rate, limits, unit = mbit) { return rateLines(rate, limits, unit).join(' · '); }
// Burst credit the agent reported for a rule (`ruleId`) or the server itself (''), as text; empty when none.
function burstState(node, ruleId) {
  const bursts = (node?.stats?.rate_limits?.bursts || []).filter(b => (b.rule_id || '') === ruleId);
  return bursts.map(b => msg`${rateLanes[b.direction] || b.direction}突发额度 ${b.capacity_bytes ? Math.floor(b.credit_bytes * 100 / b.capacity_bytes) : 100}%`).join(' · ');
}
// Combined, upload and download inputs with a mode, and optionally a burst for each. `unit`: 'bytes'
// (bytes/s, as the rule editor) or 'mbit' (Mbit/s, as server and user limits); `min`/`max` bound each
// limit in bytes/s and `rangeError` explains them; `combined` names and labels the combined input.
function rateLimitEditor({ rate, limits, unit = 'bytes', burst = false, combined, min = 1, max = 1e12, rangeError }) {
  const box = el('div', undefined, 'rate-limit-editor'), grid = el('div', undefined, 'form-grid'), parts = rateParts(rate, limits);
  const mbits = unit === 'mbit', shown = value => value == null ? '' : mbits ? +(value * 8 / 1e6).toFixed(3) : value;
  const labels = mbits ? { upload: translate('上传 / Mbit/s（留空不限速）'), download: translate('下载 / Mbit/s（留空不限速）') } : { upload: translate('上传速率 / bytes/s（留空不限）'), download: translate('下载速率 / bytes/s（留空不限）') };
  const names = { combined: combined.name, upload: 'rate_upload', download: 'rate_download' };
  const initial = parts.upload[0] != null || parts.download[0] != null ? (parts.combined[0] != null ? 'both' : 'separate') : 'combined';
  const mode = select(grid, 'rate_mode', translate('限速方式'), rateModes, initial);
  const inputs = {};
  for (const lane of ['combined', 'upload', 'download']) {
    const input = field(grid, names[lane], lane === 'combined' ? combined.label : labels[lane], shown(parts[lane][0]), 'number', false);
    input.min = mbits ? +(min * 8 / 1e6).toFixed(3) : min; input.step = mbits ? 'any' : '1'; inputs[lane] = input;
  }
  box.append(grid, el('p', translate('上传指本跳客户端发往目标的流量，下载指目标返回客户端的流量。设置的各项限速同时生效。'), 'fine'));
  const bursts = {};
  if (burst) {
    const details = el('details', undefined, 'rate-burst'), burstGrid = el('div', undefined, 'form-grid');
    details.append(el('summary', translate('突发限速（可选）')));
    for (const lane of ['combined', 'upload', 'download']) {
      const speed = field(burstGrid, `burst_${lane}_rate`, msg`${rateLanes[lane]}突发速率 / ${mbits ? 'Mbit/s' : 'bytes/s'}`, shown(parts[lane][1]?.bytes_per_sec), 'number', false);
      speed.min = inputs[lane].min; speed.step = inputs[lane].step;
      const secs = field(burstGrid, `burst_${lane}_secs`, msg`${rateLanes[lane]}突发时长 / 秒`, parts[lane][1]?.secs ?? '', 'number', false); secs.min = 1; secs.max = 86400; secs.step = '1';
      bursts[lane] = [speed, secs];
    }
    details.append(burstGrid, el('p', translate('突发让速率在一段时间内高于限速：高于限速的部分消耗突发额度，低于限速时按差值恢复，额度为（突发速率 − 限速）× 突发时长，用完后回到限速。例如突发 100 Mbit/s、限速 30 Mbit/s、突发时长 300 秒：满额时以 100 Mbit/s 运行 5 分钟，之后为 30 Mbit/s；空闲约 11.7 分钟后恢复满额。'), 'fine'));
    details.open = Object.values(parts).some(([, value]) => value);
    box.append(details);
  }
  function show() {
    for (const lane of ['combined', 'upload', 'download']) {
      const visible = lane === 'combined' ? mode.value !== 'separate' : mode.value !== 'combined';
      for (const input of [inputs[lane], ...(bursts[lane] || [])]) { input.parentElement?.classList.toggle('hidden', !visible); input.disabled = !visible; }
    }
  }
  mode.addEventListener('change', show); show();
  // Bytes/second of one input, or null when it is hidden or empty.
  function value(data, name) {
    const raw = String(data.get(name) ?? '').trim();
    if (!raw) return null;
    const n = Number(raw);
    if (!mbits) { if (!(Number.isInteger(n) && n >= 1)) throw new Error(translate('速率必须是正整数 bytes/s，留空不限。')); return n; }
    const bytesPerSec = Math.round(n * 1e6 / 8);
    if (!(bytesPerSec >= min && bytesPerSec <= max)) throw new Error(rangeError);
    return bytesPerSec;
  }
  return {
    box, mode,
    // `{rate_bytes_per_sec, rate_limits}` as the controller takes them; `rate_limits` is null when empty.
    read(data) {
      const read = { combined: value(data, names.combined), upload: value(data, names.upload), download: value(data, names.download) }, burstOf = {};
      for (const lane of Object.keys(bursts)) {
        const speedText = String(data.get(`burst_${lane}_rate`) ?? '').trim(), secsText = String(data.get(`burst_${lane}_secs`) ?? '').trim();
        if (!speedText && !secsText) continue;
        if (!speedText || !secsText) throw new Error(translate('突发速率和突发时长要同时填写，或都留空'));
        if (read[lane] == null) throw new Error(translate('设置突发前，请先填写对应的限速'));
        const secs = Number(secsText), speed = value(data, `burst_${lane}_rate`);
        if (!(Number.isInteger(secs) && secs >= 1 && secs <= 86400)) throw new Error(translate('突发时长必须是 1 到 86400 之间的整数秒'));
        if (!(speed > read[lane])) throw new Error(translate('突发速率必须高于对应的限速'));
        burstOf[lane] = { bytes_per_sec: speed, secs };
      }
      const out = {};
      if (read.upload != null) out.upload_bytes_per_sec = read.upload;
      if (read.download != null) out.download_bytes_per_sec = read.download;
      if (burstOf.combined) out.burst = burstOf.combined;
      if (burstOf.upload) out.upload_burst = burstOf.upload;
      if (burstOf.download) out.download_burst = burstOf.download;
      return { rate_bytes_per_sec: read.combined, rate_limits: Object.keys(out).length ? out : null };
    },
  };
}
// The controller refuses limits a server's agent cannot enforce and names the server (and user) in
// English; known reasons are shown in the panel's language, others as they are.
function rateLimitReason(message) {
  const server = text => {
    let m = /^the agent on server (.+) is too old for separate upload\/download or burst speed limits; upgrade it first$/.exec(text);
    if (m) return msg`服务器 ${m[1]} 的 Agent 版本过旧，不支持分别限制上传/下载或突发限速；请先升级 Agent`;
    m = /^server (.+) has not connected to the panel yet; separate upload\/download or burst speed limits need its agent to report in first$/.exec(text);
    if (m) return msg`服务器 ${m[1]} 尚未连接面板；它的 Agent 回报后才能设置分别的上传/下载限速或突发限速`;
    return null;
  };
  const user = /^user (.+) has separate upload\/download speed limits: (.+)$/.exec(String(message ?? ''));
  if (user) { const reason = server(user[2]); return reason && msg`用户 ${user[1]} 设有分别的上传/下载总限速：${reason}`; }
  return server(String(message ?? ''));
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
    options.open = !!(target.tls || target.proxy_protocol || target.websocket || target.draining || target.paused || multipathPaths);
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
    // A timed pause that already ended loads as not paused, so saving drops it.
    const pausedNow = !!target.paused && (target.paused_until_ms == null || target.paused_until_ms > Date.now());
    const pause = select(tuning, `target-pause-${id}`, translate('暂停（不接任何新会话，已有会话保持）'), [['off', translate('不暂停')], ['on', translate('暂停，直到手动恢复')], ['until', translate('暂停到指定时间')]], !pausedNow ? 'off' : target.paused_until_ms ? 'until' : 'on');
    const pauseUntil = field(tuning, `target-pause-until-${id}`, msg`暂停结束时间（${Intl.DateTimeFormat().resolvedOptions().timeZone}）`, pausedNow && target.paused_until_ms ? localDateTime(target.paused_until_ms) : '', 'datetime-local', false); pauseUntil.step = '0.001';
    function showPause() { pauseUntil.disabled = pause.value !== 'until'; pauseUntil.required = pause.value === 'until'; warnPaused(); }
    pause.addEventListener('change', showPause);
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
    const row = { box, address, via, weight, priority, draining, pause, pauseUntil, maximum, prewarm, mode, name, ca, identity, proxyMode, proxyPlacement, proxyCrc, ws, up, down, bindIp, bindInterface }; rows.push(row); showPause();
    function showSecurity() { const enabled = mode.value === 'tls'; secure.classList.toggle('hidden', !enabled); name.required = enabled; [name, ca, identity].forEach(input => { input.disabled = !enabled; }); }
    mode.onchange = showSecurity; showSecurity(); options.append(secure, proxyFields, ws.box, mp); box.append(options, button(translate('移除此目标'), () => { multipathMode?.removeEventListener('change', showMultipath); rows.splice(rows.indexOf(row), 1); box.remove(); warnPaused(); changed(); }, 'table-action danger')); container.append(box); warnPaused(); changed();
  }
  // Unlike draining, a paused target is never used as a last resort.
  const allPaused = el('p', translate('全部目标都已暂停：新连接会被拒绝，直到有目标恢复或暂停到期。'), 'error');
  function warnPaused() { allPaused.classList.toggle('hidden', !rows.length || rows.some(row => row.pause.value === 'off')); }
  targets.forEach((target, index) => add(target, multipathPaths?.[index])); form.append(container, allPaused, button(translate('＋ 添加目标'), () => add()));
  const read = () => { if (!rows.length) throw new Error(translate('至少保留一个转发目标')); return rows.map(row => {
    const target = { address: row.address.value.trim(), weight: Number(row.weight.value), priority: Number(row.priority.value), max_sessions: row.maximum.value === '' ? null : Number(row.maximum.value), ...(row.draining.value === 'on' ? { draining: true } : {}), ...(row.pause.value === 'off' ? {} : { paused: true, ...(row.pause.value === 'until' ? { paused_until_ms: pauseEnd(row.pauseUntil.value) } : {}) }), ...(row.prewarm.value === '' ? {} : { prewarm: Number(row.prewarm.value) }), ...(row.mode.value === 'tls' ? { tls: { server_name: row.name.value.trim(), ca: row.ca.value.trim() || null, identity: row.identity.value.trim() || null } } : {}) };
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
    ...(row.pause.value === 'off' ? {} : { paused: true, ...(row.pause.value === 'until' && Number.isFinite(new Date(row.pauseUntil.value).getTime()) ? { paused_until_ms: new Date(row.pauseUntil.value).getTime() } : {}) }),
    ...(row.mode.value === 'tls' ? { tls: {} } : {}),
    ...(row.via.value ? { via: { node_id: row.via.value.split('/')[0], rule_id: row.via.value.split('/')[1] } } : {}),
    ...(row.ws.read() ? { websocket: {} } : {}),
  }));
  read.onchange = callback => { changed = callback; };
  return read;
}
function pauseEnd(value) { const ms = new Date(value).getTime(); if (!Number.isFinite(ms) || ms <= Date.now()) throw new Error(translate('暂停结束时间必须晚于现在')); return ms; }

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
  showIdentity();
  document.querySelectorAll('.admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role !== 'system_admin'));
  document.querySelectorAll('.tenant-admin-only').forEach(n => n.classList.toggle('hidden', state.actor.role === 'viewer'));
  await loadFeatures();
  const route = parseRoute(location.hash); await navigate(route.view, { topic: route.topic, history: false });
}
async function navigate(view, options = {}) {
  if (!state.actor) return;
  if (!canVisit(view, state.actor)) view = 'overview';
  const topic = parseRoute(`#guide/${options.topic || 'quickstart'}`).topic;
  const hash = `#${view}${view === 'guide' ? '/' + topic : ''}`;
  if (location.hash !== hash) window.history[options.history === false ? 'replaceState' : 'pushState'](null, '', hash);
  state.view = view; applyOverviewLayout(); $('#notification').classList.add('hidden');
  document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === navView(view)));
  $('#view-title').textContent = titles[view]; $('#status-pill').classList.toggle('hidden', view !== 'overview'); $('#page-tools').replaceChildren();
  consoleUI.sync(view); $('#content').replaceChildren(el('p', translate('正在加载…'), 'loading-state')); window.scrollTo({ top: 0 });
  $('#main-content').focus({ preventScroll: true });
  try { await refresh(); } catch (e) { notify(e.message, true); }
}
// Cards on a page take turns through the companion colors, starting with the color of the page's sidebar section.
const cardTones = ['teal', 'blue', 'violet', 'pink', 'gold'];
function toneCards() {
  const groups = [...document.querySelectorAll('.sidebar nav > .nav-group')], start = Math.max(0, groups.indexOf(document.querySelector('.sidebar nav .nav-button.active')?.closest('.nav-group')));
  document.querySelectorAll('#content .panel').forEach((card, i) => { const tone = cardTones[(start + i) % cardTones.length]; if (card.dataset.tone !== tone) card.dataset.tone = tone; });
}
new MutationObserver(toneCards).observe($('#content'), { childList: true, subtree: true });
async function renderGuide() { consoleUI.renderGuide($('#content')); }
async function refresh() {
  if (!state.actor || state.busy) return; const requestedActor = state.actor, requestedView = state.view, requestedNode = state.selectedNode, requestedHash = location.hash, requestedLanguage = getLanguage(), requestedOverviewLayout = overviewLayout; state.busy = true; $('#refresh').disabled = true;
  try { await ({ overview: renderOverview, nodes: renderNodes, rules: renderRules, usage: renderUsage, subscriptions: renderSubscriptions, dns: renderDns, wireguard: renderWireguard, federation: renderFederation, announcements: renderAnnouncements, commerce: renderCommerce, tickets: renderTickets, templates: renderTemplates, budgets: renderBudgets, users: renderUsers, account: renderAccount, audit: renderAudit, logs: renderLogs, diagnostics: renderDiagnostics, alerts: renderAlerts, recovery: renderRecovery, features: renderFeatures, topology: renderTopology, health: renderHealth, capabilities: renderCapabilities, guide: renderGuide })[state.view](); $('#refreshed').textContent = msg`更新于 ${new Date().toLocaleTimeString(getLanguage(), { hour12: false })}`; }
  catch (error) { if (state.actor === requestedActor && state.actor && state.view === requestedView && location.hash === requestedHash && $('#content .loading-state')) $('#content').replaceChildren(empty(translate('页面暂时无法加载'), error.message, button(translate('重新加载'), () => { $('#notification').classList.add('hidden'); return refresh(); }, 'primary'))); throw error; }
  finally { state.busy = false; $('#refresh').disabled = false; if (state.actor && (state.actor !== requestedActor || getLanguage() !== requestedLanguage || state.view !== requestedView || location.hash !== requestedHash || (state.view === 'overview' && requestedOverviewLayout !== overviewLayout) || (['rules', 'health'].includes(requestedView) && requestedNode !== state.selectedNode))) queueMicrotask(() => refresh().catch(e => notify(e.message, true))); }
}

// Overview: per-node samples from /telemetry over the last 15 minutes, drawn as
// sparklines; the chain graph comes from declared `via` targets in /topology.
const SPAN_MS = 15 * 60_000, BINS = 60, BIN_MS = SPAN_MS / BINS;
function svg(tag, attrs = {}, cls) { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); if (cls) n.setAttribute('class', cls); return n; }
function bits(bytesPerSecond) { let n = bytesPerSecond * 8, i = 0; const u = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s']; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return `${n.toFixed(i === 0 || n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${u[i]}`; }
function millis(us) { if (us == null) return '—'; const n = us / 1000; return `${n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)} ms`; }
function ago(at, now) { const s = Math.max(0, Math.round((now - at) / 1000)); return s < 60 ? msg`${s} 秒前` : s < 3600 ? msg`${Math.floor(s / 60)} 分钟前` : msg`${Math.floor(s / 3600)} 小时前`; }
const probeErrors = localize({ dns: '域名解析失败', transport: '连接、握手或路径检查失败', timeout: '探测超时', io: '收发失败', unexpected_response: '回复不符或提前关闭', expired: '规则已到期' });
const selectionReasons = localize({ eligible: '参与优先池', standby: '后备候选', unknown: '等待探测确认', unhealthy: '故障排除', recovering: '等待持续成功', stale: '等待新结果', at_capacity: '会话已满', expired: '规则已到期', degraded: '丢包降级', draining: '维护排空', paused: '已暂停 · 不接新连接' });
// Probe reports by `${node_id}/${rule_id}/${target_index}`; a TCP + UDP rule can report each protocol separately.
function targetHealth(topology) {
  const health = new Map();
  for (const n of topology.nodes) for (const h of n.stats?.target_health || []) { const key = `${n.id}/${h.rule_id}/${h.target_index}`; health.set(key, [...(health.get(key) || []), h]); }
  return health;
}
// Real TCP connection outcomes from /history, summed over each hop's bins. A hop is a
// rule's inbound side (`${node}/${rule}/in`) or one target (`${node}/${rule}/${index}/${address}`).
const COUNTS = ['attempts', 'connected', 'timeout', 'refused', 'dns', 'closed', 'other', 'connect_us'];
const failureNames = localize({ timeout: '超时', refused: '被拒绝', dns: '域名解析失败', closed: '对端断开', other: '其他错误' });
function hopKey(node, rule, index = null, address = '') { return index == null ? `${node}/${rule}/in` : `${node}/${rule}/${index}/${address}`; }
function addCounts(sum, c) { for (const k of COUNTS) sum[k] = (sum[k] || 0) + (c[k] || 0); return sum; }
function hopTotals(history) {
  const totals = new Map();
  for (const h of history?.hops || []) { const key = hopKey(h.node_id, h.rule_id, h.target_index, h.target_address); totals.set(key, h.bins.reduce(addCounts, totals.get(key) || {})); }
  return totals;
}
// Pages refresh every 5 seconds; a history answer is reused for 15 seconds (last hour) or a minute.
const historyCache = new Map();
async function monitoringHistory(range) {
  const hit = historyCache.get(range), now = Date.now();
  if (hit && hit.actor === state.actor && now - hit.at < (range === '1h' ? 15_000 : 60_000)) return hit.data;
  const data = await api(`/history?range=${range}`).catch(() => null);
  historyCache.set(range, { at: now, actor: state.actor, data }); return data;
}
function connState(c) { const r = c.connected / c.attempts; return r >= 0.99 ? 'up' : r >= 0.9 ? 'partial' : 'down'; }
// Rounded down, so any failure keeps the rate below 100%.
function successRate(c) { const p = 100 * c.connected / c.attempts; return p === 100 || p === 0 ? `${p}%` : `${(Math.floor(p * 10) / 10).toFixed(1)}%`; }
function connSummary(c) {
  const failed = COUNTS.slice(2, 7).filter(k => c[k]).map(k => `${failureNames[k]} ${c[k]}`).join(getLanguage() === 'en' ? ', ' : '、');
  const n = v => v.toLocaleString(getLanguage());
  return [msg`${n(c.attempts)} 次连接，成功 ${n(c.connected)} 次`, failed && msg`失败：${failed}`, c.connected && msg`平均建立 ${millis(c.connect_us / c.connected)}`].filter(Boolean).join(' · ');
}
// One probe report as a link colour: removed targets are down; passing targets that recently lost probes are partial.
function probeState(r) { return r.status === 'healthy' ? (r.selection_reason === 'degraded' ? 'partial' : 'up') : r.status === 'recovering' ? 'partial' : r.status === 'unhealthy' ? 'down' : 'unknown'; }
function median(values) { const v = values.filter(x => x != null).sort((a, b) => a - b); return v.length ? v[Math.floor(v.length / 2)] : null; }
// Each report's byte delta is spread over the bins its interval covers.
// Counters restart with the agent process, so a falling counter contributes nothing.
function nodeSeries(samples, now) {
  const start = now - SPAN_MS, bin = t => Math.min(BINS - 1, Math.floor((t - start) / BIN_MS));
  const rate = Array(BINS).fill(null), sessions = Array(BINS).fill(null), available = Array(BINS).fill(null), latency = Array.from({ length: BINS }, () => []);
  samples.forEach((s, i) => {
    const b = bin(s.at_ms); if (b < 0) return;
    sessions[b] = s.active_sessions; if (s.probe_latency_us != null) latency[b].push(s.probe_latency_us);
    if (s.probed_targets) available[b] = s.healthy_targets / s.probed_targets;
    const prev = samples[i - 1]; if (!prev || s.forwarded_bytes < prev.forwarded_bytes || s.at_ms <= prev.at_ms) return;
    const perMs = (s.forwarded_bytes - prev.forwarded_bytes) / (s.at_ms - prev.at_ms);
    for (let k = Math.max(0, bin(prev.at_ms)); k <= b; k++) {
      const overlap = Math.min(s.at_ms, start + (k + 1) * BIN_MS) - Math.max(prev.at_ms, start + k * BIN_MS);
      if (overlap > 0) rate[k] = (rate[k] ?? 0) + overlap * perMs / (BIN_MS / 1000);
    }
  });
  return { rate, sessions, latency, available };
}
function currentRate(samples) {
  const last = samples.at(-1), first = samples.find(s => s.at_ms >= last?.at_ms - 20_000);
  if (!last || first === last || last.at_ms <= first.at_ms || last.forwarded_bytes < first.forwarded_bytes) return null;
  return (last.forwarded_bytes - first.forwarded_bytes) / ((last.at_ms - first.at_ms) / 1000);
}
function sumBins(list) { return Array.from({ length: list[0]?.length ?? BINS }, (_, i) => { const v = list.map(s => s[i]).filter(x => x != null); return v.length ? v.reduce((a, b) => a + b, 0) : null; }); }
// `compare`, when given, is a second series over the same bins drawn as a dashed line on the same scale.
function spark(values, cls, width = 160, height = 44, ceiling = null, compare = null) {
  const box = svg('svg', { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' }, `spark ${cls}`);
  const top = ceiling ?? (Math.max(0, ...values.filter(v => v != null), ...(compare || []).filter(v => v != null)) || 1), x = i => i / (values.length - 1) * width, y = v => height - 2 - v / top * (height - 6);
  const runs = series => { const out = []; let run = []; series.forEach((v, i) => { if (v == null) { if (run.length) out.push(run); run = []; } else run.push([x(i), y(v)]); }); if (run.length) out.push(run); for (const r of out) if (r.length === 1) r.push([r[0][0] + 2, r[0][1]]); return out; };
  const path = r => r.map(([px, py], i) => `${i ? 'L' : 'M'}${px.toFixed(1)} ${py.toFixed(1)}`).join('');
  box.append(svg('line', { x1: 0, x2: width, y1: height - 2, y2: height - 2 }, 'spark-empty'));
  for (const r of runs(compare || [])) box.append(svg('path', { d: path(r) }, 'spark-compare'));
  for (const r of runs(values)) {
    const line = path(r);
    box.append(svg('path', { d: `${line}L${r.at(-1)[0].toFixed(1)} ${height}L${r[0][0].toFixed(1)} ${height}Z` }, 'spark-area'), svg('path', { d: line }, 'spark-line'));
  }
  return box;
}
// Summary-card sparklines as discrete bars, at most 48: neighbouring bins are averaged and older bars are fainter.
// A bin without reports stays a grey tick, so a measured zero still reads differently from no data.
function barSpark(values, cls, width = 160, height = 36) {
  const group = Math.max(1, Math.ceil(values.length / 48)), cols = [];
  for (let i = 0; i < values.length; i += group) { const v = values.slice(i, i + group).filter(x => x != null); cols.push(v.length ? v.reduce((a, b) => a + b, 0) / v.length : null); }
  const box = svg('svg', { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' }, `spark bars ${cls}`);
  const top = Math.max(0, ...cols.filter(v => v != null)) || 1, step = width / cols.length, w = step * .62;
  cols.forEach((v, i) => {
    const h = v == null ? 2 : Math.max(2, v / top * height), attrs = { x: (i * step + (step - w) / 2).toFixed(2), y: (height - h).toFixed(2), width: w.toFixed(2), height: h.toFixed(2) };
    if (v != null) attrs.opacity = (.4 + .6 * i / Math.max(1, cols.length - 1)).toFixed(2);
    box.append(svg('rect', attrs, v == null ? 'bar-gap' : 'bar'));
  });
  return box;
}
function meter(ratio, label) {
  const cell = el('div', undefined, 'meter'), bar = svg('svg', { viewBox: '0 0 100 6', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const level = ratio == null ? '' : ratio >= .85 ? 'high' : ratio >= .6 ? 'mid' : 'low';
  bar.append(svg('rect', { width: 100, height: 6, rx: 3 }, 'meter-track'), svg('rect', { width: Math.max(0, Math.min(1, ratio ?? 0)) * 100, height: 6, rx: 3 }, `meter-fill ${level}`));
  cell.append(el('span', label, 'meter-label'), bar); return cell;
}
// The monitoring pages open as charts; the table view is one click away and remembered per page.
function displayMode(view) { try { return localStorage.getItem(`relay-display-${view}`) === 'table' ? 'table' : 'chart'; } catch { return 'chart'; } }
function displayToggle(view, render) {
  const group = el('div', undefined, 'mode-picker'); group.setAttribute('role', 'group'); group.setAttribute('aria-label', translate('显示方式'));
  for (const [mode, label] of [['chart', translate('图表')], ['table', translate('表格')]]) {
    const choice = button(label, async () => { try { localStorage.setItem(`relay-display-${view}`, mode); } catch { /* The page still switches without storage. */ } await render(); });
    choice.setAttribute('aria-pressed', String(displayMode(view) === mode)); group.append(choice);
  }
  return group;
}
function chartKey(parts) { const key = el('div', undefined, 'legend chart-key'); for (const [name, cls] of parts) { const item = el('span'); item.append(el('i', undefined, cls), name); key.append(item); } return key; }
function clock(ms) { return new Date(ms).toLocaleTimeString(getLanguage(), { hour: '2-digit', minute: '2-digit', hour12: false }); }
// One labelled bar per row, split into `parts` ([legend name, colour class]).
// Rows share one scale unless a row brings its own `max`, as a budget does with its limit; `failed` hatches an empty track.
function barChart(rows, parts) {
  const box = el('div', undefined, 'bar-chart'), top = Math.max(1, ...rows.map(r => r.values.reduce((a, b) => a + b, 0)));
  if (parts.length > 1) box.append(chartKey(parts));
  for (const r of rows) {
    const label = el('div', undefined, 'bar-label'), track = el('div', undefined, r.failed ? 'bar-track failed' : 'bar-track'), value = el('span', r.text, 'bar-value');
    label.append(el('strong', r.label)); if (r.detail) label.append(el('span', r.detail, 'subline'));
    r.values.forEach((v, i) => { if (v > 0) { const part = el('i', undefined, `chart-part ${parts[i][1]}`); part.style.width = `${Math.max(0.8, v / (r.max || top) * 100)}%`; track.append(part); } });
    for (const cell of [label, track, value]) cell.title = r.title || '';
    const actions = el('div', undefined, 'bar-actions'); if (r.actions) actions.append(r.actions);
    box.append(label, track, value, actions);
  }
  return box;
}
// Stacked columns with a value axis; columns: { label, values, title }. Empty labels keep crowded axes readable.
function columnChart(columns, parts, format) {
  const box = el('div', undefined, 'column-chart'), top = Math.max(0, ...columns.map(c => c.values.reduce((a, b) => a + b, 0)));
  if (parts.length > 1) box.append(chartKey(parts));
  const frame = el('div', undefined, 'chart-frame'), axis = el('div', undefined, 'chart-axis'), plot = el('div', undefined, 'column-plot'), labels = el('div', undefined, 'chart-labels column-labels');
  axis.append(el('span', format(top)), el('span', format(top / 2)), el('span', format(0)));
  plot.style.setProperty('--columns', columns.length); labels.style.setProperty('--columns', columns.length);
  for (const c of columns) {
    const column = el('div', undefined, 'column'); column.title = c.title || '';
    c.values.forEach((v, i) => { if (v > 0) { const part = el('i', undefined, `chart-part ${parts[i][1]}`); part.style.height = `${v / (top || 1) * 100}%`; column.append(part); } });
    plot.append(column); labels.append(el('span', c.label || ''));
  }
  frame.append(axis, plot, el('span'), labels); box.append(frame); return box;
}
// A line over `span` ending at `now` (15 minutes unless given) with a value axis, built on the overview sparkline.
function trendChart(values, cls, format, now, ceiling = null, span = SPAN_MS, compare = null) {
  const frame = el('div', undefined, 'chart-frame trend-chart'), axis = el('div', undefined, 'chart-axis'), labels = el('div', undefined, 'chart-labels');
  const top = ceiling ?? Math.max(0, ...values.filter(v => v != null), ...(compare || []).filter(v => v != null));
  axis.append(el('span', top ? format(top) : '—'), el('span', top ? format(top / 2) : ''), el('span', format(0)));
  const at = ms => span > 86_400_000 ? shortTime(ms, true) : clock(ms);
  labels.append(el('span', at(now - span)), el('span', at(now - span / 2)), el('span', at(now)));
  frame.append(axis, spark(values, cls, 600, 150, ceiling, compare), el('span'), labels); return frame;
}
function chartPanel(title, description, chart) { const p = panel(title, description); const body = el('div', undefined, 'panel-body chart-body'); body.append(chart); p.append(body); return p; }
function tileIcon(name) { const n = el('span', undefined, 'tile-icon'); n.append(consoleUI.icon(name)); return n; }
// `foot` is text or an element; `note` explains what the number counts and shows on hover.
function kpi(label, value, foot, chart, symbol, note) { const n = el('div', undefined, 'kpi'), head = el('div', undefined, 'kpi-head'), text = el('div', undefined, 'kpi-text'), footer = el('div', undefined, 'metric-foot'); footer.append(foot); text.append(el('div', label, 'metric-label'), el('div', value, 'metric-value'), footer); head.append(tileIcon(symbol), text); n.append(head, chart); if (note) n.title = note; return n; }
function overviewStatus(node, latest) {
  if (!node.enrolled) return [translate('待注册'), '', 'idle'];
  if (!online(node)) return [translate('离线'), 'red', 'down'];
  if (node.lifecycle && node.lifecycle !== 'active') return [translate('已暂停'), 'orange', 'partial'];
  if (node.apply_error) return [translate('配置异常'), 'orange', 'partial'];
  if (latest && latest.healthy_targets < latest.probed_targets) return [translate('降级'), 'orange', 'partial'];
  if (node.applied_revision !== node.desired_revision) return [translate('等待节点应用'), 'orange', 'partial'];
  return [translate('控制在线'), 'green', 'up'];
}
// /history bins as overview series: per node like nodeSeries, plus the success of
// real connections to targets summed over every node. The last bin is still filling.
function historySeries(history) {
  const { start_ms: start, end_ms: end, step_ms: step } = history, count = Math.round((end - start) / step);
  const index = at => Math.round((at - start) / step), blank = () => Array(count).fill(null);
  const seconds = i => Math.max(1, Math.min(step, history.generated_at_ms - (start + i * step)) / 1000);
  const nodes = new Map(history.nodes.map(n => {
    const s = { rate: blank(), sessions: blank(), latency: Array.from({ length: count }, () => []), available: blank() };
    for (const b of n.bins) {
      const i = index(b.at_ms); if (i < 0 || i >= count) continue;
      s.rate[i] = b.forwarded_bytes / seconds(i); s.sessions[i] = b.sessions_sum / b.reports;
      if (b.latency_count) s.latency[i].push(b.latency_sum_us / b.latency_count); if (b.probed_sum) s.available[i] = b.healthy_sum / b.probed_sum;
    }
    return [n.id, s];
  }));
  const totals = Array.from({ length: count }, () => ({}));
  for (const h of history.hops) if (h.target_index != null) for (const b of h.bins) { const i = index(b.at_ms); if (i >= 0 && i < count) addCounts(totals[i], b); }
  return { nodes, count, span: end - start, end, connections: totals.reduce(addCounts, {}), success: totals.map(t => t.attempts ? t.connected / t.attempts : null) };
}
const overviewRanges = localize([['15m', '15 分钟'], ['24h', '24 小时'], ['7d', '7 天']]);
function readOverviewRange() { try { const r = localStorage.getItem('relay-overview-range'); return overviewRanges.some(([v]) => v === r) ? r : '15m'; } catch { return '15m'; } }
// The 7-day history (hourly bins) as a lookup of the fleet's forwarded rate at a time; null where no node reported.
function hourlyRate(week) {
  if (!week) return () => null;
  const totals = new Map(), slot = at => Math.floor((at - week.start_ms) / week.step_ms);
  for (const n of week.nodes) for (const b of n.bins) if (b.reports) totals.set(slot(b.at_ms), (totals.get(slot(b.at_ms)) || 0) + b.forwarded_bytes);
  return at => { const v = totals.get(slot(at)); return v == null ? null : v / (week.step_ms / 1000); };
}
// The same hour yesterday from the 7-day history, for the summary deltas; null when no node reported then.
function yesterday(week, now) {
  const at = now - 86_400_000, bins = (week?.nodes || []).map(n => n.bins.find(b => b.at_ms <= at && at < b.at_ms + week.step_ms)).filter(b => b?.reports);
  if (!bins.length) return null;
  return { rate: hourlyRate(week)(at), sessions: bins.reduce((s, b) => s + b.sessions_sum / b.reports, 0), latency: median(bins.map(b => b.latency_count ? b.latency_sum_us / b.latency_count : null)) };
}
// "+12% vs this time yesterday". Round trips compare in milliseconds, where lower is better.
function kpiDelta(current, before, format, { percent = true, lowerIsBetter = false } = {}) {
  const line = el('span', undefined, 'kpi-delta');
  if (current == null) return line;
  if (before == null) { line.textContent = translate('昨日同时段无数据'); return line; }
  const diff = current - before, ratio = percent && before > 0 ? Math.abs(diff) / before : null;
  const size = ratio == null ? format(Math.abs(diff)) : `${(ratio * 100).toFixed(ratio && ratio < .1 ? 1 : 0)}%`;
  const value = el('b', `${diff > 0 ? '+' : diff < 0 ? '−' : '±'}${size}`, lowerIsBetter && diff ? (diff < 0 ? 'better' : 'worse') : ''), label = translate('较昨日同时段');
  line.append(...(getLanguage() === 'en' ? [value, ' ', label] : [label, ' ', value]));
  return line;
}
// The last 24 hours as a clock face: one spoke per 15-minute bin at its local time of day and one dot per `unit`
// real TCP connections to targets, failed ones outermost in red. A bin without connections keeps one faint dot.
function connectionDial(day, now) {
  const C = 200, R0 = 94, GAP = 5.9, DOTS = 13, OUT = R0 + (DOTS - 1) * GAP, step = day.step_ms, count = Math.round((day.end_ms - day.start_ms) / step);
  const bins = new Map(); for (const h of day.hops) if (h.target_index != null) for (const b of h.bins) { const i = Math.round((b.at_ms - day.start_ms) / step); bins.set(i, addCounts(bins.get(i) || {}, b)); }
  const total = [...bins.values()].reduce(addCounts, { attempts: 0, connected: 0 }), peak = Math.max(0, ...[...bins.values()].map(c => c.attempts));
  const nice = x => { const p = 10 ** Math.floor(Math.log10(x)); return [1, 2, 5, 10].map(k => k * p).find(v => v >= x); }, unit = peak > DOTS ? nice(peak / DOTS) : 1;
  const angle = at => { const d = new Date(at); return (d.getHours() * 60 + d.getMinutes() + d.getSeconds() / 60) / 1440 * 2 * Math.PI - Math.PI / 2; };
  const point = (a, r) => [+(C + r * Math.cos(a)).toFixed(1), +(C + r * Math.sin(a)).toFixed(1)], label = (x, y, text, cls, anchor = 'middle') => { const n = svg('text', { x, y, 'text-anchor': anchor }, cls); n.textContent = text; return n; };
  const box = svg('svg', { viewBox: '0 0 400 400', role: 'img', 'aria-label': total.attempts ? msg`最近 24 小时：${connSummary(total)}` : translate('最近 24 小时没有到目标的 TCP 连接') }, 'dial');
  box.append(svg('circle', { cx: C, cy: C, r: R0 - 12 }, 'dial-face'));
  for (let h = 0; h < 24; h++) { const a = h / 24 * 2 * Math.PI - Math.PI / 2, [x1, y1] = point(a, R0 - 12), [x2, y2] = point(a, R0 - (h % 6 ? 16 : 21)); box.append(svg('line', { x1, y1, x2, y2 }, h % 6 ? 'dial-tick' : 'dial-tick major')); }
  for (const [h, anchor, dx, dy] of [[0, 'middle', 0, -2], [6, 'start', 4, 4], [12, 'middle', 0, 10], [18, 'end', -4, 4]]) { const [x, y] = point(h / 24 * 2 * Math.PI - Math.PI / 2, OUT + 12); box.append(label(x + dx, y + dy, String(h).padStart(2, '0'), 'dial-hour', anchor)); }
  let worst = null;
  for (let i = 0; i < count; i++) {
    const at = day.start_ms + i * step, c = bins.get(i), a = angle(at + step / 2), spoke = svg('g'), failed = c ? c.attempts - c.connected : 0;
    const n = c?.attempts ? Math.min(DOTS, Math.max(1, Math.round(c.attempts / unit))) : 0, bad = failed ? Math.min(n, Math.max(1, Math.round(failed / unit))) : 0;
    if (!n) { const [cx, cy] = point(a, R0); spoke.append(svg('circle', { cx, cy, r: 1.3 }, 'idle')); }
    for (let k = 0; k < n; k++) { const [cx, cy] = point(a, R0 + k * GAP), fail = k >= n - bad; spoke.append(svg('circle', { cx, cy, r: 1.8, opacity: fail ? 1 : (.45 + .55 * k / (DOTS - 1)).toFixed(2) }, fail ? 'fail' : 'ok')); }
    if (c?.attempts) { const tip = svg('title'); tip.textContent = `${clock(at)}–${clock(at + step)} · ${connSummary(c)}`; spoke.append(tip); }
    if (failed && (!worst || failed > worst.failed)) worst = { at, failed, a };
    box.append(spoke);
  }
  const hand = angle(now), [x1, y1] = point(hand, R0 - 24), [x2, y2] = point(hand, OUT + 5);
  box.append(svg('line', { x1, y1, x2, y2 }, 'dial-hand'), svg('circle', { cx: x2, cy: y2, r: 3 }, 'dial-hand-dot'));
  if (worst) { const [x, y] = point(worst.a, OUT + 14), side = Math.cos(worst.a); box.append(label(x, y + 4, clock(worst.at), 'dial-alert', side > .3 ? 'start' : side < -.3 ? 'end' : 'middle')); }
  box.append(label(C, C + 8, total.attempts ? successRate(total) : '—', 'dial-value'), label(C, C + 32, total.attempts ? translate('连接成功') : translate('暂无连接'), 'dial-label'));
  const key = el('div', undefined, 'dial-key');
  for (const [cls, name, value] of [['ok', translate('成功'), total.connected], ['fail', translate('失败'), total.attempts - total.connected], ['idle', translate('无连接'), null]]) { const item = el('span'); item.append(el('i', undefined, cls), name); if (value != null) item.append(el('b', value.toLocaleString(getLanguage()))); key.append(item); }
  return { chart: box, key, unit };
}
// The newest unrecovered problem, critical ones first, with the way to its node and to the event list.
function attentionCallout(open, events, byId, now) {
  const top = open.find(e => e.severity === 'critical') || open[0], box = el('div', undefined, `attention-callout ${top ? top.severity : 'clear'}`), text = el('div', undefined, 'attention-text'), head = el('div', undefined, 'attention-title'), actions = el('div', undefined, 'attention-actions');
  const all = () => modal(translate('全部事件'), eventTable(events, byId, now)), node = top && byId.get(top.node_id);
  if (top) {
    head.append(el('strong', node?.name || top.node_id), el('time', `${clock(top.at_ms)} · ${ago(top.at_ms, now)}`));
    text.append(head, Object.assign(el('p', eventMessage(top)), { title: top.message }));
    if (node) actions.append(button(translate('查看节点'), () => nodeInspector(node), 'primary'));
  } else {
    head.append(el('strong', translate('没有未恢复的问题')));
    text.append(head, el('p', translate('目标故障、配置被拒绝和节点离线会显示在这里，直到恢复。')));
  }
  if (events.length) actions.append(button(translate('查看事件'), all));
  if (open.length > 1) actions.append(el('span', msg`另有 ${open.length - 1} 个未恢复`, 'attention-more'));
  if (actions.childElementCount) text.append(actions);
  box.append(el('i'), text); return box;
}
// Each node's forwarded bytes over the range, largest first; a bar takes its node's status colour.
function trafficRank(rows, totals) {
  const list = el('ol', undefined, 'traffic-rank'), top = Math.max(1, ...totals.values());
  rows.slice().sort((a, b) => totals.get(b.node.id) - totals.get(a.node.id) || a.node.name.localeCompare(b.node.name)).slice(0, 5).forEach((r, i) => {
    const item = el('li'), bar = el('span', undefined, 'traffic-bar'), fill = el('i', undefined, r.status[2]), value = totals.get(r.node.id);
    fill.style.width = `${value ? Math.max(1.5, value / top * 100) : 0}%`; bar.append(fill); item.title = r.status[0];
    item.append(el('span', String(i + 1), 'traffic-index'), el('strong', r.node.name), el('span', locationName(r.node.profile?.settings.location), 'traffic-place'), bar, el('span', bytes(value), 'traffic-value'));
    list.append(item);
  });
  return list;
}
async function renderOverview() {
  const actor = state.actor;
  const range = readOverviewRange();
  // The connection dial always shows the last 24 hours; the 7-day history also gives "this time yesterday".
  const [telemetry, nodes, topology, recent, daily, week] = await Promise.all([api('/telemetry'), api('/nodes'), api('/topology'), monitoringHistory('1h'), monitoringHistory('24h'), monitoringHistory('7d')]);
  if (state.view !== 'overview' || !actor || state.actor !== actor) return;
  const history = range === '24h' ? daily : range === '7d' ? week : null;
  const now = telemetry.generated_at_ms, byId = new Map(nodes.map(n => [n.id, n])), past = history && historySeries(history), conns = hopTotals(recent);
  const noData = () => ({ rate: Array(past.count).fill(null), sessions: Array(past.count).fill(null), latency: Array.from({ length: past.count }, () => []), available: Array(past.count).fill(null) });
  const rows = telemetry.nodes.filter(t => byId.has(t.id)).map(t => { const node = byId.get(t.id), latest = online(node) ? t.samples.at(-1) : null; return { node, samples: t.samples, latest, series: past ? past.nodes.get(t.id) || noData() : nodeSeries(t.samples, now), rate: online(node) ? currentRate(t.samples) : null, status: overviewStatus(node, latest) }; });
  const live = rows.filter(r => r.latest), enrolled = rows.filter(r => r.node.enrolled);
  const rate = sumBins(rows.map(r => r.series.rate)), sessions = sumBins(rows.map(r => r.series.sessions));
  const latency = Array.from({ length: past ? past.count : BINS }, (_, i) => median(rows.flatMap(r => r.series.latency[i])));
  const healthy = live.reduce((s, r) => s + r.latest.healthy_targets, 0), probed = live.reduce((s, r) => s + r.latest.probed_targets, 0);
  const measuredRates = rate.filter(Number.isFinite), liveRates = live.map(r => r.rate).filter(Number.isFinite);
  const peak = measuredRates.length ? Math.max(...measuredRates) : null;
  const fleet = el('div', undefined, 'fleet-bar'); enrolled.forEach(r => fleet.append(el('i', undefined, r.status[2])));
  const rangeLabel = overviewRanges.find(([v]) => v === range)[1], picker = el('div', undefined, 'mode-picker');
  picker.setAttribute('role', 'group'); picker.setAttribute('aria-label', translate('趋势范围'));
  for (const [value, label] of overviewRanges) { const choice = button(label, async () => { try { localStorage.setItem('relay-overview-range', value); } catch { /* Still switches without storage. */ } await renderOverview(); }); choice.setAttribute('aria-pressed', String(range === value)); picker.append(choice); }
  const events = telemetry.events.slice().reverse(), attention = rows.filter(r => r.status[2] === 'down' || r.status[2] === 'partial').length;
  const before = yesterday(week, now), liveRate = liveRates.length ? liveRates.reduce((sum, value) => sum + value, 0) : null, liveSessions = live.length ? live.reduce((s, r) => s + r.latest.active_sessions, 0) : null, liveLatency = median(live.map(r => r.latest.probe_latency_us));
  const count = v => (Math.round(v * 10) / 10).toLocaleString(getLanguage()), fleetNote = el('span', undefined, 'kpi-delta');
  if (enrolled.length) fleetNote.append(el('b', attention ? msg`${attention} 个需要关注` : translate('全部正常'), attention ? 'worse' : 'better'), ' · ', probed ? msg`目标可用 ${healthy} / ${probed}` : translate('尚无目标探测'));
  const kpis = el('div', undefined, 'kpis');
  kpis.append(
    kpi(translate('实时吞吐'), liveRate == null ? '—' : bits(liveRate), kpiDelta(liveRate, before?.rate, bits), barSpark(rate, 'teal'), 'activity', msg`多跳流量逐跳计入 · 峰值 ${peak == null ? '—' : bits(peak)}`),
    kpi(translate('活跃会话'), liveSessions == null ? '—' : String(liveSessions), kpiDelta(liveSessions, before?.sessions, count), barSpark(sessions, 'blue'), 'arrows', translate('TCP 连接 + UDP 会话')),
    kpi(translate('探测往返中位数'), millis(liveLatency), kpiDelta(liveLatency, before?.latency, millis, { percent: false, lowerIsBetter: true }), barSpark(latency, 'violet'), 'gauge', translate('节点到目标的探测，不含客户端一段')),
    kpi(translate('节点在线'), `${live.length} / ${enrolled.length}`, fleetNote, fleet, 'server'));
  const pill = $('#status-pill'); pill.className = `status-pill ${rows.some(r => r.status[2] === 'down') ? 'red' : attention ? 'orange' : 'green'}`;
  pill.textContent = !enrolled.length ? translate('等待节点注册') : !live.length ? translate('等待节点回报') : attention ? msg`${attention} 个节点需要关注` : msg`控制在线 · ${live.length} 个节点`;
  if (!live.length) pill.className = 'status-pill neutral';
  const graphPanel = panel(translate('转发链路'), translate('按规则声明的下一跳绘制；连线颜色取该段最新探测结果与最近 1 小时真实连接中较差的一项，标注为探测往返与连接成功率。点击节点查看规则。'), legend());
  graphPanel.classList.add('graph-panel'); graphPanel.append(chainGraph(topology, byId, conns));
  let trends = null;
  if (past) {
    const c = past.connections, percent = v => `${+(v * 100).toFixed(1)}%`;
    trends = el('div', undefined, 'chart-grid overview-trends');
    trends.append(chartPanel(translate('真实连接成功率'), c.attempts ? msg`最近 ${rangeLabel} · ${connSummary(c)}。只计 TCP 到目标的连接。` : msg`最近 ${rangeLabel}没有到目标的 TCP 连接。`, trendChart(past.success, 'up', percent, past.end, 1, past.span)),
      chartPanel(translate('平均会话'), msg`最近 ${rangeLabel} · 全部节点合计。`, trendChart(sessions, 'blue', v => String(Math.round(v)), past.end, null, past.span)),
      chartPanel(translate('探测往返（中位数）'), msg`最近 ${rangeLabel} · 各节点平均值的中位数。`, trendChart(latency, 'violet', millis, past.end, null, past.span)));
  }
  const eventActions = el('div', undefined, 'panel-actions'); if (state.actor.role === 'system_admin') eventActions.append(button(translate('诊断报告'), () => navigate('diagnostics'), 'table-action')); if (events.length) eventActions.append(button(translate('全部事件'), () => modal(translate('全部事件'), eventTable(events, byId, now)), 'table-action'));
  const incidents = panel(translate('事件'), msg`最近 24 小时 · 共 ${events.length} 条`, eventActions.childElementCount ? eventActions : undefined);
  incidents.classList.add('incident-panel');
  // A problem stays open until a later event about the same node, subject and kind family
  // (target_*, config_*, node_*) recovers, removes or supersedes it.
  const latest = new Map(); for (const e of events) { const k = `${e.node_id}/${e.subject}/${e.kind.split('_')[0]}`; if (!latest.has(k)) latest.set(k, e); }
  const problem = e => e.severity === 'warning' || e.severity === 'critical', day = events.filter(e => e.at_ms >= now - 86_400_000);
  const open = [...latest.values()].filter(problem), problems = day.filter(problem).length;
  const board = el('div', undefined, 'alert-status event-board');
  for (const [label, value, color] of [[translate('仍未恢复'), open.length, open.length ? 'red' : 'green'], [translate('新问题'), problems, problems ? 'orange' : 'green'], [translate('已恢复'), day.filter(e => e.severity === 'recovered').length, 'green']]) { const item = el('div', undefined, `alert-stat ${color}`); item.append(el('div', String(value), 'metric-value'), el('div', label, 'metric-label')); board.append(item); }
  const list = el('ol', undefined, 'incidents');
  if (!events.length) list.append(el('li', translate('最近 24 小时没有目标故障、配置拒绝或节点离线。'), 'incident-empty'));
  [...open, ...events.filter(e => !open.includes(e))].slice(0, 6).forEach(e => { const item = el('li', undefined, `incident ${e.severity}`), text = el('div'); text.append(Object.assign(el('div', eventMessage(e), 'incident-message'), { title: e.message }), el('div', byId.get(e.node_id)?.name || e.node_id, 'subline')); item.append(el('i'), text, el('time', ago(e.at_ms, now))); list.append(item); });
  incidents.append(board, list);
  // Second row: the 24-hour connection dial beside what needs attention, each node's traffic and the throughput line.
  // Without history the cards fall back to the last 15 minutes of telemetry, and say so.
  const dial = daily && connectionDial(daily, now), dialPanel = panel(translate('连接 · 最近 24 小时'), dial ? msg`到目标的真实 TCP 连接，按本地时间每 15 分钟一列，每点约 ${dial.unit.toLocaleString(getLanguage())} 次。` : undefined), shownRange = past ? rangeLabel : overviewRanges[0][1];
  const dialBody = el('div', undefined, 'dial-body'); dialBody.append(...(dial ? [dial.chart, dial.key] : [empty(translate('暂无监控历史'), translate('控制器没有提供监控历史，暂时无法显示最近 24 小时。'))])); dialPanel.classList.add('dial-panel'); dialPanel.append(dialBody);
  const attentionPanel = panel(translate('需要关注'), undefined, el('span', open.length ? msg`${open.length} 个问题仍未恢复` : translate('全部已恢复'), `attention-count${open.length ? '' : ' clear'}`));
  // Bytes each node forwarded over the range: history bins, or for 15 minutes the measured deltas in its chart bins.
  const forwarded = new Map(rows.map(r => [r.node.id, history ? (history.nodes.find(n => n.id === r.node.id)?.bins.reduce((s, b) => s + b.forwarded_bytes, 0) ?? 0) : Math.round(r.series.rate.reduce((s, v) => s + (v ?? 0), 0) * BIN_MS / 1000)]));
  const trafficHead = el('div', undefined, 'traffic-head'), trafficTitle = el('h3', translate('各节点流量'));
  trafficTitle.append(el('span', ' · ' + msg`最近 ${shownRange}`)); trafficHead.append(trafficTitle);
  if (rows.length) trafficHead.append(button(translate('全部节点 ↓'), () => nodePanel.scrollIntoView({ behavior: 'smooth', block: 'start' }), 'text-link'));
  attentionPanel.classList.add('attention-panel'); attentionPanel.append(attentionCallout(open, events, byId, now), trafficHead, rows.length ? trafficRank(rows, forwarded) : el('p', translate('还没有节点'), 'fine'));
  // The dashed line is the same time yesterday, from the 7-day history; 7 days back from a week has no data to compare.
  const start = past ? history.start_ms : now - SPAN_MS, step = past ? history.step_ms : BIN_MS, rateAt = hourlyRate(range === '7d' ? null : week);
  const compare = rate.map((_, i) => rateAt(start + i * step + step / 2 - 86_400_000)), compared = compare.some(v => v != null), key = el('div', undefined, 'legend chart-key');
  for (const [name, cls] of [[translate('吞吐'), 'teal'], ...(compared ? [[translate('昨日同时段'), 'compare']] : [])]) { const item = el('span'); item.append(el('i', undefined, cls), name); key.append(item); }
  const throughputPanel = chartPanel(translate('吞吐'), msg`最近 ${shownRange} · 全部节点合计，多跳流量逐跳计入。`, trendChart(rate, 'teal', bits, past ? past.end : now, null, past ? past.span : SPAN_MS, compared ? compare : null));
  throughputPanel.querySelector('.panel-head').append(key); throughputPanel.classList.add('throughput-panel');
  const overviewGrid = el('div', undefined, 'overview-grid'); overviewGrid.append(dialPanel, attentionPanel, throughputPanel);
  // The map sits beside what needs attention; without nodes the path graph takes its place.
  const globe = rows.length ? globePanel(rows, topology, now) : null, bento = el('div', undefined, 'overview-bento'); bento.append(globe || graphPanel, incidents);
  const waiting = el('div', undefined, 'overview-waiting');
  if (!live.length) {
    const copy = el('div'); copy.append(el('strong', translate('等待实时数据')), el('p', translate('尚无近期 Agent 回报。注册并启动节点，或检查已有 Agent 的连接；发布启用的规则后显示期望转发路径。')));
    waiting.append(copy, button(translate('前往节点管理'), () => navigate('nodes')));
  }
  const search = el('input'); search.type = 'search'; search.placeholder = translate('按名称、ID 或分组筛选'); search.value = state.overviewFilter || ''; search.setAttribute('aria-label', translate('筛选节点'));
  const nodePanel = panel(translate('中转节点'), msg`${enrolled.length} 个已注册 · 采样来自每次节点回报`, search);
  // Related readings share a cell (status with its report age, CPU with memory) so the table fits a laptop screen.
  const t = table([translate('节点'), translate('状态 / 最近回报'), translate('探测往返'), msg`吞吐（${rangeLabel}）`, translate('CPU / 内存'), translate('会话'), translate('配置修订'), ''], rows.map(r => {
    const { node, latest } = r, memory = latest?.memory_total_bytes ? 1 - latest.memory_available_bytes / latest.memory_total_bytes : null;
    const throughput = el('div', undefined, 'throughput'); throughput.append(spark(r.series.rate, 'teal'), el('span', r.rate == null ? '—' : bits(r.rate)));
    const status = el('div'); status.append(badge(r.status[0], r.status[1]), el('div', node.last_seen_ms ? ago(node.last_seen_ms, now) : translate('尚未回报'), 'subline'));
    const resources = el('div', undefined, 'resource-meters');
    if (latest?.cpu_percent != null) resources.append(meter(latest.cpu_percent / 100, `CPU ${latest.cpu_percent.toFixed(0)}%`));
    if (memory != null) resources.append(meter(memory, `${bytes(latest.memory_total_bytes - latest.memory_available_bytes)} / ${bytes(latest.memory_total_bytes)}`));
    return [namedCell(node.name, node.profile?.settings.group || node.id.slice(0, 8)), status, latest ? millis(latest.probe_latency_us) : '—', throughput, resources.childElementCount ? resources : '—',
      latest ? (node.stats?.prewarmed_connections ? namedCell(String(latest.active_sessions), msg`预热接手 ${node.stats.prewarmed_connections}`) : String(latest.active_sessions)) : '—', node.apply_error ? namedCell(`${node.applied_revision} / ${node.desired_revision}`, translate('应用失败')) : `${node.applied_revision} / ${node.desired_revision}`,
      button(translate('规则 →'), async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action')];
  }));
  const trs = [...t.querySelectorAll('tbody tr')], keys = rows.map(r => [r.node.name, r.node.id, r.node.profile?.settings.group || ''].join(' ').toLowerCase());
  const filter = () => { state.overviewFilter = search.value; const q = search.value.trim().toLowerCase(); trs.forEach((tr, i) => tr.classList.toggle('hidden', !!q && !keys[i].includes(q))); };
  search.addEventListener('input', filter); filter();
  nodePanel.append(rows.length ? t : empty(translate('还没有节点'), translate('注册节点并启动 Agent 后，这里会显示实时吞吐、资源和事件。'), button(translate('前往节点管理'), () => navigate('nodes'))));
  if (state.view === 'overview') { $('#page-tools').replaceChildren(picker); $('#content').replaceChildren(...(!live.length ? [waiting] : []), kpis, overviewGrid, bento, ...(globe ? [graphPanel] : []), ...(trends ? [trends] : []), nodePanel); }
}
function locationName(location) { const city = cityFor(location); return city ? (getLanguage() === 'en' ? city[2] : city[1]) : location?.name || ''; }
// One globe per page load: it keeps its rotation and selection across the 5-second refreshes.
let overviewGlobe = null;
function globePanel(rows, topology, now) {
  overviewGlobe ||= createGlobe({ label: translate('节点位置与转发连线'), onSelect: id => { state.globeNode = id; document.querySelectorAll('[data-globe-node]').forEach(n => n.classList.toggle('selected', n.dataset.globeNode === id)); } });
  const located = rows.filter(r => r.node.profile?.settings.location), sessions = r => r.latest ? msg`${r.latest.active_sessions} 会话` : '';
  overviewGlobe.update(located.map(r => { const l = r.node.profile.settings.location; return { id: r.node.id, name: r.node.name, lat: l.latitude_micros / 1e6, lon: l.longitude_micros / 1e6, status: r.status[2], detail: [r.status[0], locationName(l), sessions(r)].filter(Boolean).join(' · ') }; }),
    [...chainEdges(topology).edges.values()].filter(e => e.from !== 'client' && e.to !== 'sink').map(e => ({ from: e.from, to: e.to, state: linkState(e.states) })));
  const setLocations = () => editLocations(rows.map(r => r.node)), actions = el('div');
  actions.append(legend()); if (canWrite()) actions.append(button(translate('设置位置'), setLocations, 'table-action'));
  const p = panel(translate('全球节点'), translate('位置来自节点资料；连线是规则声明的下一跳，颜色为该段最新探测结果。拖动地球可旋转，点击节点可定位。'), actions);
  p.classList.add('globe-panel');
  const body = el('div', undefined, 'globe-body'), side = el('div', undefined, 'globe-side'), list = el('ul', undefined, 'globe-list');
  side.append(el('p', msg`${located.length} / ${rows.length} 个节点已标注位置`, 'globe-count'));
  for (const r of [...located, ...rows.filter(r => !located.includes(r))]) {
    const location = r.node.profile?.settings.location, item = el('li'), entry = el('button', undefined, 'globe-node'), text = el('span', undefined, 'globe-node-text');
    entry.type = 'button'; entry.dataset.globeNode = r.node.id; entry.classList.toggle('selected', state.globeNode === r.node.id);
    text.append(el('strong', r.node.name), el('span', location ? [locationName(location), sessions(r)].filter(Boolean).join(' · ') : translate('未设置位置'), 'subline'));
    entry.append(el('i', undefined, `globe-dot ${r.status[2]}`), text, badge(r.status[0], r.status[1]));
    if (location) entry.onclick = () => { state.globeNode = r.node.id; list.querySelectorAll('.globe-node').forEach(n => n.classList.toggle('selected', n === entry)); overviewGlobe.select(r.node.id); };
    else if (canWrite()) { entry.onclick = () => editNode(r.node); entry.setAttribute('aria-label', msg`为 ${r.node.name} 设置位置`); }
    else entry.disabled = true;
    item.append(entry); list.append(item);
  }
  side.append(list);
  // An empty globe explains itself instead of looking broken.
  const stage = el('div', undefined, 'globe-stage'); stage.append(overviewGlobe.element);
  if (!located.length) {
    const note = el('div', undefined, 'globe-empty'); note.append(el('strong', translate('还没有节点设置位置')), el('p', canWrite() ? translate('为节点选择所在城市后，节点和转发连线会出现在地球上。') : translate('管理员为节点设置位置后，节点和连线会出现在地球上。')));
    if (canWrite()) note.append(button(translate('设置节点位置'), setLocations, 'primary'));
    stage.append(note);
  }
  body.append(stage, side); p.append(body);
  return p;
}
function cityLocation(city) { const english = getLanguage() === 'en'; return { name: english ? city[2] : city[1], latitude_micros: Math.round(city[3] * 1e6), longitude_micros: Math.round(city[4] * 1e6) }; }
function cityOptions() { const english = getLanguage() === 'en'; return cities.map(c => [c[0], `${english ? c[2] : c[1]} · ${c[0]}`]).sort((a, b) => a[1].localeCompare(b[1], getLanguage())); }
// Every node's city in one dialog; only changed nodes are saved, in one batch.
function editLocations(nodes) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  form.append(el('p', translate('选择每个节点所在的城市，保存后显示在总览地球上。列表中没有的城市，可在节点资料中手动填写坐标。'), 'fine'), grid);
  const choices = nodes.map(node => {
    const current = node.profile.settings.location, city = cityFor(current), initial = current ? city?.[0] || 'keep' : '';
    const options = [['', translate('不设置')], ...(initial === 'keep' ? [['keep', msg`保持：${current.name}`]] : []), ...cityOptions()];
    return { node, initial, choice: select(grid, `city_${node.id}`, node.name, options, initial) };
  });
  submit(form, translate('保存位置'), async () => {
    const updates = choices.filter(c => c.choice.value !== c.initial).map(({ node, choice }) => {
      const city = cities.find(c => c[0] === choice.value);
      return { node_id: node.id, update: { expected_revision: node.profile.revision, name: node.name, settings: { ...node.profile.settings, location: city ? cityLocation(city) : null } } };
    });
    if (updates.length) await api('/nodes/profiles', { method: 'POST', body: { updates } });
    $('#dialog').close(); await refresh(); notify(updates.length ? msg`已保存 ${updates.length} 个节点的位置。` : translate('位置没有变化。'));
  });
  modal(translate('设置节点位置'), form);
}
function legend() { const n = el('div', undefined, 'legend'); for (const [text, cls] of [[translate('正常'), 'up'], [translate('部分可用'), 'partial'], [translate('不可用'), 'down'], [translate('未探测'), 'unknown']]) { const item = el('span'); item.append(el('i', undefined, cls), text); n.append(item); } return n; }
function eventTable(events, byId, now) {
  const names = { info: translate('信息'), recovered: translate('恢复'), warning: translate('警告'), critical: translate('严重') }, colors = { recovered: 'green', warning: 'orange', critical: 'red' };
  return table([translate('时间'), translate('节点'), translate('级别'), translate('内容')], events.map(e => [`${timestamp(e.at_ms)} · ${ago(e.at_ms, now)}`, byId.get(e.node_id)?.name || e.node_id, badge(names[e.severity] || e.severity, colors[e.severity]), eventMessage(e)]));
}
// One edge per node pair from enabled rules: client → entry nodes, node → next
// hop (`via`), and node → 'sink' for external targets and proxy services.
// `conns` adds real connection outcomes (hopTotals) to each edge.
function chainEdges(topology, conns = new Map()) {
  const health = targetHealth(topology), edges = new Map(), referenced = new Set(), ruleCount = new Map();
  const addEdge = (from, to, reports, counts) => {
    const key = `${from}>${to}`, e = edges.get(key) || { from, to, states: [], latency: [], counts: {} }; edges.set(key, e);
    e.states.push(!reports.length ? 'unknown' : reports.every(h => h.eligible) ? 'up' : reports.some(h => h.eligible) ? 'partial' : 'down');
    e.latency.push(...reports.filter(h => h.eligible).map(h => h.latency_ewma_us));
    if (counts) addCounts(e.counts, counts);
  };
  for (const config of topology.configs || []) for (const rule of config.rules) {
    if (!rule.enabled) continue; ruleCount.set(config.node_id, (ruleCount.get(config.node_id) || 0) + 1);
    if (serviceKind(rule) !== 'forward') addEdge(config.node_id, 'sink', []);
    rule.targets.forEach((target, i) => { if (target.via) referenced.add(`${target.via.node_id}/${target.via.rule_id}`); addEdge(config.node_id, target.via ? target.via.node_id : 'sink', health.get(`${config.node_id}/${rule.id}/${i}`) || [], conns.get(hopKey(config.node_id, rule.id, i, target.address))); });
  }
  for (const config of topology.configs || []) for (const rule of config.rules) if (rule.enabled && !referenced.has(`${config.node_id}/${rule.id}`)) addEdge('client', config.node_id, [], conns.get(hopKey(config.node_id, rule.id)));
  return { edges, ruleCount };
}
// A link is up only if every probed target is, and down only if none is; unprobed targets do not count.
function linkState(states) { const known = states.filter(s => s !== 'unknown'); return !known.length ? 'unknown' : known.every(s => s === 'up') ? 'up' : known.every(s => s === 'down') ? 'down' : 'partial'; }
// Columns follow the longest declared path from an entry node; external
// targets share one sink so each node shows one summarized outgoing link.
function chainGraph(topology, byId, conns) {
  const { edges, ruleCount } = chainEdges(topology, conns), labels = [];
  const ids = topology.nodes.map(n => n.id), depth = new Map();
  const depthOf = (id, seen = new Set()) => { if (depth.has(id)) return depth.get(id); if (seen.has(id)) return 1; seen.add(id); const parents = [...edges.values()].filter(e => e.to === id && e.from !== 'client').map(e => depthOf(e.from, seen)); const d = parents.length ? Math.max(...parents) + 1 : 1; depth.set(id, d); return d; };
  ids.forEach(id => depthOf(id));
  const last = Math.max(1, ...depth.values()) + 1, columns = Array.from({ length: last + 1 }, () => []);
  ids.forEach(id => columns[depth.get(id)].push(id)); if ([...edges.values()].some(e => e.from === 'client')) columns[0].push('client'); if ([...edges.values()].some(e => e.to === 'sink')) columns[last].push('sink');
  // Lay out at the panel's current pixel size so text stays at its CSS size; the viewBox rescales between refreshes.
  const monitoring = overviewLayout === 'monitoring', beside = !monitoring && window.innerWidth > 1390, W = Math.max(640, ($('#content').clientWidth || 1100) - (beside ? 316 : 0) - 36);
  // Client and target terminals are narrow; node columns share the width between them.
  const tw = 80, left = 12 + (columns[0].length ? tw + 40 : 0), right = W - 12 - (columns[last].length ? tw + 40 : 0), step = (right - left) / (last - 1);
  const bw = Math.max(112, Math.min(monitoring ? 210 : 176, step - 44)), bh = monitoring ? 64 : 52, gap = monitoring ? 100 : 84, H = Math.max(monitoring ? 270 : 190, Math.max(...columns.map(c => c.length)) * gap + 60), pos = new Map();
  columns.forEach((column, c) => column.forEach((id, r) => pos.set(id, [c === 0 ? 12 : c === last ? W - 12 - tw : left + (c - 1) * step + (step - bw) / 2, (H - column.length * gap) / 2 + r * gap + (gap - bh) / 2, c === 0 || c === last ? tw : bw])));
  const box = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': translate('转发链路图') }, 'chain');
  for (const e of edges.values()) {
    const a = pos.get(e.from), b = pos.get(e.to); if (!a || !b) continue;
    const used = e.counts.attempts > 0, probed = linkState(e.states), worst = used ? ['down', 'partial', 'up', 'unknown'].find(s => s === probed || s === connState(e.counts)) : probed;
    const x1 = a[0] + a[2], y1 = a[1] + bh / 2, x2 = b[0], y2 = b[1] + bh / 2, dx = (x2 - x1) / 2, state = e.from === 'client' ? 'client' : worst;
    const fromColumn = e.from === 'client' ? 0 : depth.get(e.from), toColumn = e.to === 'sink' ? last : depth.get(e.to);
    const bypass = toColumn - fromColumn !== 1, laneY = e.from === 'client' ? 18 : H - 18;
    // Keep direct and bypass connections outside intervening VPS cards. A
    // straight line through another card incorrectly looks like an extra hop.
    const d = bypass ? `M${x1} ${y1}C${x1 + 24} ${y1} ${x1 + 24} ${laneY} ${x1 + 48} ${laneY}L${x2 - 48} ${laneY}C${x2 - 24} ${laneY} ${x2 - 24} ${y2} ${x2} ${y2}` : `M${x1} ${y1}C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;
    const edge = svg('path', { d }, `edge ${state}`), title = svg('title');
    const name = id => id === 'client' ? translate('客户端') : id === 'sink' ? translate('目标服务') : byId.get(id)?.name || id;
    title.textContent = [`${name(e.from)} → ${name(e.to)}`, used ? msg`最近 1 小时真实 TCP 连接：${connSummary(e.counts)}` : ''].filter(Boolean).join('\n'); edge.append(title); box.append(edge);
    // Client links carry the entry's inbound setup, shown in the tooltip only: their lanes run together.
    const lat = median(e.latency), text = [lat != null ? millis(lat) : '', used && e.from !== 'client' ? successRate(e.counts) : ''].filter(Boolean).join(' · ');
    if (text) { const label = svg('text', { x: (x1 + x2) / 2, y: (bypass ? laneY : (y1 + y2) / 2) - 7, 'text-anchor': 'middle' }, `edge-label${used ? ` ${connState(e.counts)}` : ''}`); label.textContent = text; labels.push(label); }
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
  const wrap = el('div', undefined, 'chain-wrap');
  if (ids.length && !edges.size) wrap.append(el('p', translate('尚无启用的转发规则；这里只显示节点，不代表已建立转发路径。'), 'chain-notice'));
  wrap.append(box);
  if (!ids.length) return empty(translate('还没有节点'), translate('注册节点并配置规则后显示转发链路。'));
  return wrap;
}

async function renderNodes() {
  const actor = state.actor;
  const query = new URLSearchParams(state.nodeFilter).toString();
  const [nodes, usage, topology] = await Promise.all([api('/nodes' + (query ? '?' + query : '')), api('/usage'), api('/topology').catch(() => null)]);
  if (state.view !== 'nodes' || !actor || state.actor !== actor) return;
  state.nodes = nodes; state.usage = usage;
  state.inbound = {}; for (const c of topology?.configs || []) for (const r of c.rules) for (const t of r.targets) if (t.via) { const n = state.inbound[t.via.node_id] ||= { total: 0, draining: 0 }; n.total++; if (t.draining) n.draining++; }
  state.selectedNodes = new Set([...state.selectedNodes].filter(id => nodes.some(n => n.id === id)));
  const metric = el('div', undefined, 'metrics');
  [[translate('节点数量'), nodes.length, query ? translate('当前筛选范围') : translate('当前账号可见的节点'), 'server'], [translate('控制在线'), nodes.filter(online).length, translate('最近 30 秒收到心跳'), 'activity'], [translate('活跃连接'), nodes.some(online) ? nodes.filter(online).reduce((s,n) => s+n.stats.active_tcp+n.stats.active_udp,0) : '—', translate('当前范围的 TCP + UDP 会话'), 'arrows'], [translate('近期上报负载'), bytes(usage.reduce((s,u) => s+u.upload_bytes+u.download_bytes,0)), translate('全部可见节点最近 2,000 个计量周期'), 'chart']].forEach(([title,value,foot,symbol]) => { const n=el('div',undefined,'metric'); n.append(tileIcon(symbol),el('div',title,'metric-label'),el('div',String(value),'metric-value'),el('div',foot,'metric-foot'));metric.append(n); });
  // Tabs split the list by what each node needs; selecting "this page" covers the nodes the tab shows.
  const counts = { all: nodes.length, online: 0, attention: 0, awaiting: 0 }; nodes.forEach(n => counts[nodeGroup(n)]++);
  const tab = Object.hasOwn(counts, state.nodeTab) ? state.nodeTab : 'all', shown = tab === 'all' ? nodes : nodes.filter(n => nodeGroup(n) === tab);
  const bar = el('div', undefined, 'page-tabs'), tabs = el('div', undefined, 'page-tab-list'); tabs.setAttribute('aria-label', translate('节点'));
  for (const [id, label] of [['all', translate('全部')], ['online', translate('在线')], ['attention', translate('需要关注')], ['awaiting', translate('待注册')]]) { const choice = button(label, async () => { state.nodeTab = id; await renderNodes(); }, 'page-tab'); choice.append(el('span', String(counts[id]), 'tab-count')); if (id === tab) choice.setAttribute('aria-current', 'page'); tabs.append(choice); }
  const controls = el('div', undefined, 'toolbar node-tools'); controls.append(button(translate('筛选节点'), filterNodes));
  if (query) controls.append(button(translate('清除筛选'), async () => { state.nodeFilter = {}; state.selectedNodes.clear(); await renderNodes(); }));
  if (canWrite()) controls.append(button(translate('选择 / 取消本页'), async () => { if (shown.every(n => state.selectedNodes.has(n.id))) shown.forEach(n => state.selectedNodes.delete(n.id)); else shown.forEach(n => state.selectedNodes.add(n.id)); await renderNodes(); }), button(translate('批量编辑已选节点'), batchNodeProfiles), button(translate('＋ 注册节点'), newNode, 'primary'));
  bar.append(tabs, controls);
  const p = el('section', undefined, 'panel node-panel');
  if (!shown.length) p.append(empty(query || tab !== 'all' ? translate('没有匹配的节点') : translate('接入你的第一个节点'), query || tab !== 'all' ? translate('调整筛选条件后重试。') : translate('注册后启动 Agent，再配置转发。')));
  else {
    p.append(table([translate('选择'), translate('节点 / 位置'), translate('状态'), translate('用途 / 分组 / 成本'), translate('活跃会话'), translate('配置修订'), ''], shown.map(node => {
      let choice = '—'; if (canWrite()) { choice = el('input'); choice.className = 'node-choice'; choice.type = 'checkbox'; choice.checked = state.selectedNodes.has(node.id); choice.setAttribute('aria-label', translate('选择 ') + node.name); choice.onchange = () => choice.checked ? state.selectedNodes.add(node.id) : state.selectedNodes.delete(node.id); }
      const id = el('div'); id.append(el('strong', node.name), el('div', locationName(node.profile.settings.location) || translate('未设置位置'), 'subline'), el('div', node.id.slice(0, 8) + '…', 'subline mono')); id.title = node.id;
      const [text, color] = nodeBadge(node), status = el('div'); status.append(badge(text, color), el('div', node.last_seen_ms ? ago(node.last_seen_ms, Date.now()) : translate('尚未回报'), 'subline'));
      if (node.lifecycle !== 'active') status.append(el('div', nodeLifecycleText(node), 'subline warning'));
      const revision = node.apply_error ? namedCell(`v${node.applied_revision} / v${node.desired_revision}`, translate('应用失败')) : `v${node.applied_revision} / v${node.desired_revision}`;
      if (node.apply_error) revision.querySelector('.subline').className = 'subline error';
      return [choice, id, status, nodeInventoryCell(node), nodeSessionsCell(node), revision, nodeActions(node)];
    })));
    // Clicking anywhere on a row except its own controls opens the node's details.
    p.querySelectorAll('tbody tr').forEach((tr, i) => { tr.classList.add('row-link'); tr.tabIndex = 0; tr.addEventListener('click', event => { if (!event.target.closest('button, input, a, label, summary')) nodeInspector(shown[i]); }); tr.addEventListener('keydown', event => { if (event.key === 'Enter' && event.target === tr) nodeInspector(shown[i]); }); });
  }
  if (state.view === 'nodes') $('#content').replaceChildren(metric, bar, p);
}
function nodeLeaseText(node) {
  const lease = node.lease;
  if (!lease) return translate('运行保护未提供');
  if (!lease.policy) return translate('可用优先');
  if (lease.recovery_wait_ms > 0) return translate('严格租约 · 恢复等待');
  return lease.active ? translate('严格租约 · 有效') : translate('严格租约 · 未持有');
}
// The control connection decides the badge; permission, protection and revision are listed in the details.
function nodeBadge(node) {
  return node.credential_phase === 'revoked' ? [translate('身份已撤销'), 'red'] : node.credential_phase === 'replacement_pending' ? [translate('等待替换注册'), 'orange'] : !node.enrolled ? [translate('待注册'), ''] : online(node) ? (node.apply_error ? [translate('配置错误'), 'orange'] : [translate('控制在线'), 'green']) : [translate('无近期回报'), 'orange'];
}
function nodeGroup(node) {
  if (['revoked', 'replacement_pending'].includes(node.credential_phase) || node.apply_error || node.lifecycle !== 'active' || (node.enrolled && !online(node))) return 'attention';
  return node.enrolled ? 'online' : 'awaiting';
}
function nodeLifecycleText(node) {
  const names = { active: translate('允许运行'), disabled: translate('已暂停'), expired: translate('已到期') };
  return [names[node.lifecycle], node.profile.settings.expires_at_ms ? msg`到期 ${timestamp(node.profile.settings.expires_at_ms)}` : ''].filter(Boolean).join(' · ');
}
// Everything about one node in a side sheet: live state, profile, then each less frequent task with what it does.
function nodeInspector(node) {
  const body = el('div', undefined, 'inspector'), head = el('div', undefined, 'inspector-head'), [text, color] = nodeBadge(node), s = node.profile.settings, inbound = state.inbound?.[node.id];
  head.append(badge(text, color), el('span', node.id, 'mono'));
  const actions = el('div', undefined, 'inspector-actions');
  actions.append(button(translate('管理规则 →'), async () => { $('#dialog').close(); state.selectedNode = node.id; await navigate('rules'); }, 'primary'), button(canWrite() ? translate('编辑资料') : translate('查看资料'), () => editNode(node)));
  body.append(head);
  const facts = (title, rows) => { const section = el('section', undefined, 'inspector-section'), list = el('dl', undefined, 'facts'); section.append(el('h3', title)); for (const [label, value, cls] of rows.filter(Boolean)) list.append(el('dt', label), el('dd', value, cls)); section.append(list); body.append(section); };
  facts(translate('运行状态'), [
    [translate('最近回报'), node.last_seen_ms ? `${ago(node.last_seen_ms, Date.now())} · ${timestamp(node.last_seen_ms)}` : translate('尚未回报')],
    [translate('运行许可'), nodeLifecycleText(node), node.lifecycle === 'active' ? '' : 'warning'],
    [translate('运行保护'), nodeLeaseText(node) + (node.lifecycle !== 'active' && node.lease?.active ? ` · ${translate('现有租约尚在收敛')}` : '')],
    [translate('配置修订'), `v${node.applied_revision} / v${node.desired_revision}`],
    node.apply_error && [translate('应用失败'), node.apply_error, 'error'],
    [translate('活跃会话'), online(node) ? `${node.stats.active_tcp} TCP / ${node.stats.active_udp} UDP` : '—'],
    inbound?.total && [translate('上游目标'), inbound.draining ? `${inbound.total} · ${translate('维护中 · 不接新连接')}` : String(inbound.total), inbound.draining ? 'warning' : ''],
  ]);
  facts(translate('资料'), [
    [translate('位置'), locationName(s.location) || translate('未设置位置')],
    [translate('用途'), s.kinds.map(k => nodeKindNames[k]).join(' / ') || translate('未标注')],
    [translate('分组'), [s.group || translate('未分组'), ...s.tags].join(' · ')],
    [translate('成本'), costLabel(s.cost)],
  ]);
  const more = el('section', undefined, 'inspector-section'); more.append(el('h3', translate('更多操作')), nodeMoreList(node)); body.append(more);
  if (canWrite()) {
    const removal = el('section', undefined, 'inspector-section inspector-danger');
    removal.append(el('h3', translate('删除节点')), el('p', node.enrolled ? translate('这个节点还绑定着 Agent 身份：先撤销身份，它的规则立即停止转发，然后删除节点及其规则、配置历史和用量记录。审计日志保留。') : translate('删除节点及其规则、配置历史和用量记录。审计日志保留。'), 'fine'),
      button(node.enrolled ? translate('撤销身份并删除…') : translate('删除节点…'), () => removeNode(node), 'subtle danger'));
    body.append(removal);
  }
  body.insertBefore(actions, head.nextSibling);
  modal(node.name, body);
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
  actions.append(button(translate('管理规则 →'), async () => { state.selectedNode = node.id; await navigate('rules'); }, 'table-action'), button(translate('详情'), () => nodeInspector(node), 'table-action'));
  return actions;
}
// Less frequent node tasks, each with what it does, so the table row stays short.
function nodeMoreList(node) {
  const body = el('div', undefined, 'action-list'), inbound = state.inbound?.[node.id];
  const add = (title, text, handler, cls = 'subtle') => { const row = el('div', undefined, 'action-row'), copy = el('div'); copy.append(el('strong', title), el('p', text, 'fine')); row.append(copy, button(title, () => { $('#dialog').close(); return handler(); }, cls)); body.append(row); };
  add(translate('运行诊断'), translate('查看连接、计时、队列与资源回报。'), () => nodeDiagnostics(node));
  if (canWrite() && inbound?.total) add(inbound.draining ? translate('结束维护') : translate('维护排空'), inbound.draining ? translate('恢复上游按原优先级和权重分配新连接。') : translate('新连接改走其他目标，已有连接继续到结束，便于安全重启或升级。'), () => drainNode(node, !inbound.draining));
  add(translate('节点身份'), translate('查看注册状态；轮换、撤销或替换节点凭据，或删除节点。'), () => nodeCredential(node));
  return body;
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
  const actions = el('div', undefined, 'dialog-actions');
  if (canWrite() && phase === 'active' && !status.pending) {
    const action = button(translate('发起凭据轮换'), async () => {
      action.disabled = true;
      try {
        await api(`/nodes/${node.id}/credential/rotate`, { method: 'POST', body: { expected_revision: status.revision } });
        await nodeCredential(node);
      } finally { action.disabled = false; }
    }, 'primary');
    actions.append(action);
  }
  if (canWrite()) {
    actions.append(button(phase === 'not_enrolled' ? translate('撤销遗失的注册令牌') : translate('紧急撤销身份'), () => revokeNodeIdentity(node,status), 'subtle danger'));
    if (phase === 'revoked' || phase === 'replacement_pending') actions.append(button(translate('签发替换票据'), () => replaceNodeIdentity(node,status), 'primary'));
    if (phase === 'revoked' || phase === 'not_enrolled') actions.append(button(translate('删除节点'), () => deleteNode(node), 'subtle danger'));
  }
  actions.append(button(translate('刷新状态'), () => nodeCredential(node)));
  body.append(actions);
  modal(translate('节点身份与凭据'), body);
}
// The details' delete button: a node still bound to an Agent identity is revoked first, then deleted.
async function removeNode(node) {
  const status = await api(`/nodes/${node.id}/credential`), phase = status.phase || (node.enrolled ? 'active' : 'not_enrolled');
  if (phase === 'revoked' || phase === 'not_enrolled') return deleteNode(node);
  revokeNodeIdentity(node, status, () => deleteNode(node));
}
async function deleteNode(node) {
  if (!await confirmAction(msg`永久删除节点「${node.name}」及其规则、配置历史和用量记录？审计日志保留。仍被其他节点、DNS 记录或预算引用的节点不能删除。`)) return;
  await api(`/nodes/${node.id}`, { method: 'DELETE' });
  if (state.selectedNode === node.id) state.selectedNode = null;
  notify(msg`节点「${node.name}」已删除。`); await refresh();
}
function revokeNodeIdentity(node,status,then = () => nodeCredential(node)) {
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
    notify(translate('撤销操作已确认，请以当前身份状态为准。严格节点按已授期限停止；离线实例需要外部停止。'));
    await then();
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
    ]), el('p', translate('租约保留不等于业务健康。严格租约失去续租后停止业务，可用优先不提供跨机器互斥。租约到期不会自动退还未知消费的额度。'), 'fine'));
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
function forwardingDefaultsEditor(parent, value = {}, prefix = 'forwarding') {
  const box = el('div', undefined, 'forwarding-defaults');
  const host = field(box, `${prefix}-host`, translate('VPS 可达地址（IP 或域名，不含端口）'), value?.host || '', 'text', false);
  host.placeholder = 'vps.example.com'; host.maxLength = 253;
  const advanced = el('details'); advanced.append(el('summary', translate('端口范围 / NAT / 监听 IP')));
  const grid = el('div', undefined, 'form-grid'); advanced.append(grid);
  const listen = field(grid, `${prefix}-listen`, translate('监听 IP（留空自动选择）'), value?.listen_ip || '', 'text', false);
  const start = field(grid, `${prefix}-start`, translate('自动分配起始端口'), value?.port_start ?? 20000, 'number');
  const end = field(grid, `${prefix}-end`, translate('自动分配结束端口'), value?.port_end ?? 29999, 'number');
  const publicStart = field(grid, `${prefix}-public`, translate('NAT 公网起始端口（留空与监听端口相同）'), value?.public_port_start ?? '', 'number', false);
  for (const input of [start, end, publicStart]) { input.min = input === publicStart ? 1 : 1024; input.max = 65535; }
  advanced.append(el('p', translate('NAT 仅适用于已由服务商映射的连续端口段；面板不会创建 NAT 或开放防火墙。'), 'fine'));
  box.append(advanced); parent.append(box);
  const optional = () => { start.required = end.required = !!host.value.trim(); }; host.addEventListener('input', optional); optional();
  return { box, host, read() {
    if (!host.value.trim()) return null;
    const low = Number(start.value), high = Number(end.value), mapped = publicStart.value.trim() ? Number(publicStart.value) : null;
    if (!Number.isInteger(low) || low < 1024 || !Number.isInteger(high) || high < low || high > 65535 || (mapped !== null && (!Number.isInteger(mapped) || mapped < 1 || mapped + high - low > 65535))) throw new Error(translate('请检查自动分配端口范围和 NAT 映射范围。'));
    return { host: host.value.trim(), listen_ip: listen.value.trim() || null, port_start: low, port_end: high, public_port_start: mapped };
  } };
}
const mptcpFlags = ['signal', 'subflow', 'backup'];
function mptcpPathsStatus(report) {
  if (!report.host_enabled) return translate('这台服务器尚未授权 Agent 管理 MPTCP 路径，设置暂不生效。');
  const text = msg`服务器已授权 · 已生效 ${report.applied.length} 条路径 · 子流上限 ${report.subflows ?? '—'} · 接受地址上限 ${report.add_addr_accepted ?? '—'}`;
  return report.error ? `${text} · ${report.error}` : text;
}
// Shown while the feature is on, or when the node already has paths so they stay editable.
function mptcpPathsEditor(form, value, report) {
  if (!featureOn('mptcp-paths') && !value) return { read: () => null };
  form.append(el('h3', translate('MPTCP 额外路径')));
  const text = (value?.endpoints || []).map(e => [e.address, e.interface, ...mptcpFlags.filter(flag => e[flag])].filter(Boolean).join(' ')).join('\n');
  textarea(form, 'mptcp_paths', translate('每行一条路径：IP 地址、可选网卡名，再加 signal（告知对端此地址）、subflow（从此地址建立子流）或 backup（仅作备用）'), text).placeholder = '203.0.113.5 eth1 signal\n2001:db8::5 eth0 subflow backup';
  const grid = el('div', undefined, 'form-grid');
  const subflows = field(grid, 'mptcp_subflows', translate('每条连接最多子流数（0–8，留空保持服务器原值）'), value?.subflows ?? '', 'number', false);
  const accepted = field(grid, 'mptcp_add_addr', translate('最多接受对端告知的地址数（0–8，留空保持服务器原值）'), value?.add_addr_accepted ?? '', 'number', false);
  for (const input of [subflows, accepted]) { input.min = 0; input.max = 8; }
  form.append(grid, el('p', translate('服务器需先安装授权文件 relay-agent-mptcp-paths.conf。Agent 只增删自己编号 200–207 的路径，不改动手动配置的路径；两个上限是整台服务器的设置，清空后保持当前值，不会自动还原。'), 'fine'));
  if (report) form.append(el('p', mptcpPathsStatus(report), report.error || !report.host_enabled ? 'workflow-callout' : 'fine'));
  return { read(data) {
    const endpoints = String(data.get('mptcp_paths') || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
      const [address, ...words] = line.split(/\s+/), endpoint = { address, signal: false, subflow: false, backup: false };
      for (const word of words) {
        if (mptcpFlags.includes(word.toLowerCase())) endpoint[word.toLowerCase()] = true;
        else if (!endpoint.interface) endpoint.interface = word;
        else throw new Error(msg`无法识别的 MPTCP 路径：${line}`);
      }
      if (!endpoint.signal && !endpoint.subflow) throw new Error(msg`每条 MPTCP 路径需要 signal 或 subflow：${line}`);
      return endpoint;
    });
    const limit = name => { const raw = String(data.get(name) ?? '').trim(); if (!raw) return null; const n = Number(raw); if (!Number.isInteger(n) || n < 0 || n > 8) throw new Error(translate('MPTCP 上限须为 0–8 的整数')); return n; };
    const paths = { endpoints, subflows: limit('mptcp_subflows'), add_addr_accepted: limit('mptcp_add_addr') };
    return endpoints.length || paths.subflows !== null || paths.add_addr_accepted !== null ? paths : null;
  } };
}
function nodeSettingsEditor(form, settings = {}, strict = () => true, report = null) {
  form.append(el('h3', translate('新规则的连接默认值')));
  const forwarding = forwardingDefaultsEditor(form, settings.forwarding);
  form.append(el('p', translate('地址填写一次，新规则自动复用并分配端口。修改默认值不会改动已发布规则。'), 'fine'));
  const paths = mptcpPathsEditor(form, settings.mptcp_paths, report);
  form.append(el('h3', translate('位置与资料')));
  const location = locationEditor(form, settings.location);
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
    return { forwarding: forwarding.read(), mptcp_paths: paths.read(data), location: location.read(), kinds: data.getAll('node_kind'), group: String(data.get('node_group') || '').trim() || null, tags: String(data.get('node_tags') || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean), notes: String(data.get('node_notes') || ''), cost, enabled: strict() ? enabled.value === 'true' : true, expires_at_ms: expires };
  } };
}
// A listed city, or a named point; the overview globe draws the node there.
function locationEditor(parent, value) {
  const city = cityFor(value);
  const choice = select(parent, 'location_city', translate('所在城市（显示在总览地球上）'), [['', translate('不设置')], ...cityOptions(), ['custom', translate('其他位置 · 手动填写坐标')]], value ? city?.[0] || 'custom' : '');
  const custom = el('div', undefined, 'form-grid');
  const name = field(custom, 'location_name', translate('位置名称'), city ? '' : value?.name || ''); name.maxLength = 64;
  const lat = field(custom, 'location_lat', translate('纬度（-90 到 90，北纬为正）'), value && !city ? value.latitude_micros / 1e6 : '', 'number');
  const lon = field(custom, 'location_lon', translate('经度（-180 到 180，东经为正）'), value && !city ? value.longitude_micros / 1e6 : '', 'number');
  lat.min = -90; lat.max = 90; lon.min = -180; lon.max = 180; lat.step = lon.step = 'any';
  parent.append(custom);
  const show = () => sectionVisible(custom, choice.value === 'custom'); choice.addEventListener('change', show); show();
  return { read() {
    if (!choice.value) return null;
    if (choice.value !== 'custom') return cityLocation(cities.find(c => c[0] === choice.value));
    const latitude = Number(lat.value), longitude = Number(lon.value);
    if (!name.value.trim() || !(Math.abs(latitude) <= 90) || !(Math.abs(longitude) <= 180)) throw new Error(translate('请填写位置名称，以及有效的纬度和经度'));
    return { name: name.value.trim(), latitude_micros: Math.round(latitude * 1e6), longitude_micros: Math.round(longitude * 1e6) };
  } };
}
function editNode(node) {
  const settings = node.profile.settings;
  if (!canWrite()) { const body = el('div'); body.append(table([translate('资料'), translate('当前记录')], [[translate('名称'), node.name], [translate('类型'), settings.kinds.map(k => nodeKindNames[k]).join('、') || translate('未标注')], [translate('分组'), settings.group || translate('未分组')], [translate('位置'), locationName(settings.location) || translate('未设置')], [translate('标签'), settings.tags.join('、') || translate('无')], [translate('成本'), costLabel(settings.cost)], [translate('到期时间'), settings.expires_at_ms ? timestamp(settings.expires_at_ms) : translate('未设置')]])); body.append(el('pre', settings.notes || translate('无备注'))); modal(translate('节点资料'), body); return; }
  const form = el('form'); field(form, 'node_name', translate('节点名称'), node.name).maxLength = 120;
  const editor = nodeSettingsEditor(form, settings, () => !!node.lease.policy, node.stats?.mptcp_paths);
  submit(form, translate('保存资料'), async data => { await api(`/nodes/${node.id}/profile`, { method: 'PUT', body: { expected_revision: node.profile.revision, name: String(data.get('node_name')).trim(), settings: editor.read(data) } }); $('#dialog').close(); await refresh(); notify(translate('节点资料已保存；转发配置保持原修订。')); }); modal(translate('编辑节点 · ') + node.name, form);
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
// The one way to start a new forwarding: built-in wizards by number of servers,
// the full rule editor, or a saved template.
function chooseSetup() {
  const body = el('div', undefined, 'setup-chooser');
  body.append(el('p', translate('先选择这条转发经过几台服务器、提供什么服务。下一步选择服务器，地址和端口自动填写；发布前可以预览完整路径。'), 'workflow-callout'));
  for (const [title, path] of [[translate('只用一台服务器'), false], [translate('经过多台服务器（多跳）'), true]]) {
    const group = el('section', undefined, 'setup-group'), grid = el('div', undefined, 'setup-cards'); group.append(el('h3', title));
    for (const recipe of setupRecipes.filter(recipe => recipe.path === path)) {
      const card = button('', () => startSetup(recipe.id), 'setup-card'); card.dataset.recipe = recipe.id;
      card.append(el('span', recipe.scope, 'setup-scope'), el('strong', recipe.title, 'setup-title'), el('span', recipe.description, 'setup-text'), el('span', recipe.route, 'setup-route'));
      grid.append(card);
    }
    group.append(grid); body.append(group);
  }
  // Layers of candidate servers saved as a chain; planned by the controller.
  const chained = el('section', undefined, 'setup-group'), chainGrid = el('div', undefined, 'setup-cards'), chainCard = button('', () => useChain(), 'setup-card');
  chainCard.dataset.recipe = 'chain';
  chainCard.append(el('span', translate('端点组 · 按层'), 'setup-scope'), el('strong', translate('使用已保存的转发链'), 'setup-title'), el('span', translate('选择入口和一条已保存的转发链：每层的服务器互为候选，地址和端口自动分配。'), 'setup-text'), el('span', translate('客户端 → 入口 → 第 1 层候选 → … → 最后一层候选 → 固定目标'), 'setup-route'));
  chainGrid.append(chainCard); chained.append(el('h3', translate('按已保存的转发链')), chainGrid); body.append(chained);
  const more = el('div', undefined, 'setup-more'), copy = el('div');
  copy.append(el('strong', translate('需要其他协议或已有模板？')), el('p', translate('高级规则支持 SOCKS5、HTTP CONNECT、VLESS / Reality、Hysteria2 等全部选项。'), 'fine'));
  const links = el('div', undefined, 'toolbar'); links.append(button(translate('其他协议 / 高级规则'), () => startSetup('advanced')));
  if (state.actor.role !== 'viewer') links.append(button(translate('从已保存的模板创建'), pickTemplate));
  more.append(copy, links); body.append(more);
  modal(translate('新建转发'), body);
}
async function pickTemplate() {
  const [templates, nodes] = await Promise.all([api('/templates'), api('/nodes')]); state.nodes = nodes;
  const body = el('div');
  if (!templates.length) body.append(empty(translate('还没有模板'), translate('在「规则模板」页新建模板，或在规则列表中点击“存为模板”。'), button(translate('前往规则模板'), () => { $('#dialog').close(); return navigate('templates'); }, 'primary')));
  else body.append(table([translate('模板'), translate('类型'), ''], templates.map(template => [namedCell(template.name, template.description || '—'), templateKind(template.rule), button(translate('使用'), () => applyTemplate(template), 'table-action')])));
  body.append(button(translate('返回'), chooseSetup));
  modal(translate('从模板创建'), body);
}
async function startSetup(id) {
  const recipe = setupRecipes.find(recipe => recipe.id === id), snapshot = await api('/topology');
  state.nodes = snapshot.nodes;
  if (snapshot.nodes.length < (recipe?.path ? 2 : 1)) {
    const body = empty(translate('先连接所需的 VPS'), recipe?.path ? translate('多跳模板需要至少两个节点。注册 VPS 并启动 Agent 后，再选择入口和出口。') : translate('先注册一台 VPS 并启动 Agent，再用模板创建服务。'), button(translate('前往节点管理'), () => { $('#dialog').close(); return navigate('nodes'); }, 'primary'));
    modal(translate('准备节点'), body); return;
  }
  if (recipe) return newTopologyChain(snapshot, { mode: recipe.mode, protocol: 'both', name: recipe.title, single: !recipe.path, entryNode: state.selectedNode });
  const node = snapshot.nodes.find(n => n.id === state.selectedNode) || snapshot.nodes.find(n => n.tenant_id === state.actor.tenant_id) || snapshot.nodes[0];
  state.selectedNode = node.id; state.config = snapshot.configs.find(config => config.node_id === node.id);
  return editRule(null, {});
}

async function renderRules() {
  const actor = state.actor;
  const [nodes, sharedRules] = await Promise.all([api('/nodes'), api('/shared-rules')]);
  if (state.view !== 'rules' || !actor || state.actor !== actor) return;
  state.nodes = nodes; const content = $('#content');
  if (!state.nodes.length) { content.replaceChildren(empty(translate('还没有节点'), translate('先注册节点，再创建规则。'), button(translate('前往节点管理'), () => navigate('nodes'), 'primary'))); return; }
  if (!state.nodes.some(n => n.id === state.selectedNode)) state.selectedNode = (state.nodes.find(online) || state.nodes[0]).id;
  const toolbar = el('div', undefined, 'toolbar node-toolbar'), selector = el('select'); selector.setAttribute('aria-label', translate('选择节点')); state.nodes.forEach(n => { const option = el('option', n.name); option.value = n.id; selector.append(option); }); selector.value = state.selectedNode; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; const nodeLabel = el('label', translate('运行节点 / VPS')); nodeLabel.append(selector); toolbar.append(nodeLabel);
  const nodeId = state.selectedNode; const config = await api(`/nodes/${nodeId}/config`); if (state.view !== 'rules' || state.actor !== actor || state.selectedNode !== nodeId) return; state.config = config;
  const nodeStatus = el('div', undefined, 'node-toolbar-status'), nodeTools = el('div', undefined, 'node-toolbar-actions');
  const nodeLimit = rateText(config.rate_bytes_per_sec, config.rate_limits, mbit), nodeBurst = burstState(state.nodes.find(n => n.id === nodeId), '');
  nodeStatus.append(applicationBadge(state.nodes.find(n => n.id === nodeId)), badge(msg`期望修订 v${config.revision}`), badge(nodeLimit ? msg`节点总限速 ${nodeLimit}` : translate('节点不限速'), nodeLimit ? 'orange' : ''));
  if (nodeBurst) nodeStatus.append(badge(nodeBurst, 'orange'));
  nodeTools.append(button(translate('版本历史'), history)); if (canWrite()) nodeTools.append(button(translate('节点总限速'), () => editNodeRate(config)));
  toolbar.append(nodeTools, nodeStatus);
  const protocols = { tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' }, balances = { weighted_round_robin: translate('加权轮询'), source_hash: translate('来源 IP 哈希'), least_connections: translate('最少连接'), lowest_latency: translate('最低延迟'), random: translate('随机') };
  const p = panel(msg`${state.nodes.find(n => n.id === nodeId).name} 上运行的规则`, translate('一台服务器上的监听端口和服务。多跳转发会在经过的每台服务器上各有一条规则；完整路线见「全部转发」。'));
  const applyError = state.nodes.find(n => n.id === nodeId)?.apply_error;
  if (applyError) p.append(el('p', msg`节点应用错误：${applyError}`, 'error workflow-callout'));
  if (!config.rules.length) p.append(empty(translate('这台服务器还没有规则'), translate('新建一条转发：选择它只转发流量，还是在这里提供代理服务。'), canWrite() ? button(translate('＋ 新建转发'), chooseSetup, 'primary') : null));
  else p.append(table([translate('名称'), translate('监听 / 协议'), translate('目标'), translate('配额 / 限速'), translate('状态'), translate('操作')], config.rules.map(rule => { const actions = el('div'), membership = sharedRules.find(view => view.members.some(member => member.node_id === nodeId && member.rule_id === rule.id)); if (rule.inbound_shadowsocks) actions.append(button(translate('分享链接'), () => shareShadowsocks(rule), 'table-action')); if (rule.inbound_socks5) actions.append(button(translate('分享链接'), () => shareSocks5(rule), 'table-action')); if (rule.inbound_http_connect) actions.append(button(translate('分享链接'), () => shareHttpConnect(rule), 'table-action')); if (rule.protocol_gateway && rule.protocol_gateway.protocol.type !== 'any_tls') actions.append(button(translate('分享链接'), () => shareGateway(rule, config.node_id), 'table-action')); if (rule.id.startsWith('fed-')) actions.append(button(translate('在共享页管理'), () => navigate('federation'), 'table-action')); else if (rule.reverse_tunnel) actions.append(button(translate('在反向隧道中管理'), () => navigate('topology'), 'table-action')); else if (canWrite()) { actions.append(button(translate('编辑'), () => editRule(rule), 'table-action'), button(rule.enabled ? translate('停用') : translate('启用'), () => saveRules(config.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r), config), 'table-action')); if (state.actor.role !== 'viewer') actions.append(button(translate('存为模板'), () => saveTemplate(rule), 'table-action')); if (membership) actions.append(button(translate('编辑共同规则'), () => openSharedRule(membership), 'table-action')); else if (!rule.protocol_gateway && !rule.listen_end_port) actions.append(button(translate('扩展到多条线路…'), () => extendRule(config, rule), 'table-action')); actions.append(button(translate('删除'), async () => { if (rule.advertise || rule.targets.some(t => t.via)) return deleteChainedRule(config.node_id, rule); if (await confirmAction(msg`删除「${rule.name}」会终止其会话，历史账本保留。`)) await saveRules(config.rules.filter(r => r.id !== rule.id), config); }, 'table-action danger')); } return [ruleNameCell(rule, membership), namedCell((rule.protocol_gateway?.listen || rule.listen) + (rule.listen_end_port ? ` → ${rule.listen_end_port}` : ''), protocols[rule.protocol] || rule.protocol), rule.protocol_gateway ? namedCell(rule.protocol_gateway.protocol.type.toUpperCase(), rule.protocol_gateway.security.type === 'reality' ? 'Reality' : 'TLS') : rule.inbound_shadowsocks ? namedCell(translate('Shadowsocks 代理服务'), rule.inbound_shadowsocks.method) : rule.inbound_socks5 ? namedCell(translate('SOCKS5 代理服务'), rule.inbound_socks5.username ? translate('用户名密码认证') : translate('无认证')) : rule.inbound_http_connect ? namedCell(translate('HTTP CONNECT 代理服务'), rule.inbound_http_connect.username ? translate('Basic 认证') : translate('无认证')) : rule.inbound_http2_connect ? namedCell('HTTP/2 CONNECT', msg`并发隧道上限 ${rule.inbound_http2_connect.max_concurrent_streams || 128} · ${rule.inbound_tls ? 'TLS' : 'h2c'}`) : namedCell(rule.targets[0].address, [rule.targets.length > 1 ? msg`${rule.targets.length} 个目标 · ${balances[rule.balance] || rule.balance}` : translate('单一目标'), pausedTargets(rule)].filter(Boolean).join(' · ')), limitCell(rule, state.nodes.find(n => n.id === nodeId)), rule.enabled && rule.targets.length && rule.targets.every(t => targetPaused(t)) ? namedCell(translate('期望启用'), translate('全部目标已暂停 · 拒绝新连接')) : badge(rule.enabled ? translate('期望启用') : translate('期望停用'), rule.enabled ? '' : ''), actions]; })));
  content.replaceChildren(forwardingTabs('rules', config.rules.length), toolbar, p, sharedRulesPanel(sharedRules, state.nodes));
}
// Rules by server and complete paths are two views of the same configuration.
function forwardingTabs(view, count) {
  const bar = el('div', undefined, 'page-tabs'), tabs = el('nav', undefined, 'page-tab-list'); tabs.setAttribute('aria-label', translate('转发规则视图'));
  for (const [key, text] of [['topology', translate('全部转发')], ['rules', translate('按服务器')]]) {
    const tab = button(text, () => navigate(key), 'page-tab');
    if (key === view) { tab.setAttribute('aria-current', 'page'); if (count !== undefined) tab.append(el('span', String(count), 'tab-count')); }
    tabs.append(tab);
  }
  bar.append(tabs);
  if (canWrite()) bar.append(button(translate('＋ 新建转发'), chooseSetup, 'primary'));
  return bar;
}
function mbit(rate) { return `${+(rate * 8 / 1e6).toFixed(2)} Mbit/s`; }
// Quota and speed limits of a rule, with its burst credit when the agent reports it.
function limitCell(rule, node) {
  const lines = rateLines(rule.rate_bytes_per_sec, rule.rate_limits, rate => bytes(rate) + '/s'), credit = burstState(node, rule.id);
  const text = `${rule.quota_bytes === null ? translate('不限量') : bytes(rule.quota_bytes)} / ${lines[0] || translate('不限速')}`;
  if (lines.length < 2 && !credit) return text;
  // One limit per line, so several do not run under the actions column.
  const cell = el('div');
  cell.append(el('strong', text), ...lines.slice(1).map(line => el('div', line)));
  if (credit) cell.append(el('div', credit, 'subline mono'));
  return cell;
}
function editNodeRate(baseConfig) {
  const form = el('form'), node = state.nodes.find(n => n.id === baseConfig.node_id);
  const speed = rateLimitEditor({ rate: baseConfig.rate_bytes_per_sec, limits: baseConfig.rate_limits, unit: 'mbit', burst: true, combined: { name: 'mbit', label: translate('本节点所有规则上下行合计 / Mbit/s（留空不限速）') }, min: 1, max: 1e12, rangeError: translate('请输入 0.008 到 8,000,000 之间的 Mbit/s') });
  form.append(speed.box, el('p', translate('与规则自身的限速同时生效，取较严者。立即作用于已有连接，不会断开会话；健康探测不计入。'), 'muted'));
  if (node && !node.rate_limit_support) form.append(el('p', translate('这台服务器的 Agent 尚未报告支持分别限制上传/下载或突发限速；只有上下行合计可以发布，其他方式会被拒绝。请先升级 Agent。'), 'fine'));
  submit(form, translate('发布限速'), async data => { const { rate_bytes_per_sec: rate, rate_limits } = speed.read(data); await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision: baseConfig.revision, rules: baseConfig.rules, rate_bytes_per_sec: rate, rate_limits } }); $('#dialog').close(); const text = rateText(rate, rate_limits, mbit); notify(text ? msg`已发布节点总限速 ${text}。` : translate('已取消节点总限速。')); await renderRules(); });
  modal(translate('节点总限速'), form);
}
async function saveRules(rules, baseConfig) { const expected_revision = baseConfig.revision; await api(`/nodes/${baseConfig.node_id}/config`, { method: 'PUT', body: { expected_revision, rules } }); $('#dialog').close(); notify(translate('配置已发布。请在节点总览确认实际应用修订号。')); await renderRules(); }
function gatewayConfig(type, listen, uuid, password, vision, security, identity, serverName, handshake, privateKey, shortId, allowPrivate, payload, options = {}) {
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
  if (type === 'hysteria2') {
    if (options.obfs === 'salamander') {
      const key = options.obfsPassword || '';
      if (new TextEncoder().encode(key).length < 16 || new TextEncoder().encode(key).length > 256 || /[\x00-\x1f\x7f]/.test(key)) throw new Error(translate('混淆密码需要 16–256 字节，不能含控制字符'));
      protocol.obfs = { type: 'salamander', password: key };
    }
    if (options.masquerade === 'fixed') {
      const code = Number(options.masqueradeStatus), content = options.masqueradeContent || '';
      if (!Number.isInteger(code) || code < 200 || code > 599) throw new Error(translate('伪装响应状态码为 200–599'));
      if (new TextEncoder().encode(content).length > 4096) throw new Error(translate('伪装响应内容最多 4096 字节'));
      protocol.masquerade = { type: 'string', status_code: code, ...(content ? { content } : {}) };
    }
  }
  if (type === 'tuic') {
    if (!['bbr', 'cubic', 'new_reno'].includes(options.congestion || 'bbr')) throw new Error(translate('未知拥塞控制算法'));
    if ((options.congestion || 'bbr') !== 'bbr') protocol.congestion_control = options.congestion;
    if (options.zeroRtt === 'yes') protocol.zero_rtt_handshake = true;
  }
  let secure;
  if (security === 'certificate') {
    if (!identity.trim()) throw new Error(translate('请填写节点本地证书编号'));
    secure = { type: 'certificate', identity: identity.trim() };
    if (serverName.trim()) secure.server_name = serverName.trim();
  } else if (security === 'reality' && type === 'vless') {
    const ids = shortId.split(/[\s,]+/).filter(Boolean);
    if (!serverName.trim() || !handshake.trim() || !/^[A-Za-z0-9_-]{43}$/.test(privateKey) || !ids.length || ids.some(id => !/^(?:[0-9a-f]{2}){1,8}$/i.test(id))) throw new Error(translate('Reality 需要服务器名称、握手地址、32 字节 Base64URL 私钥和 2–16 位偶数长度十六进制 short ID'));
    if (ids.length > 16 || new Set(ids.map(id => id.toLowerCase())).size !== ids.length) throw new Error(translate('Reality short ID 最多 16 个且不能重复'));
    secure = { type: 'reality', server_name: serverName.trim(), handshake: handshake.trim(), private_key: privateKey, short_id: ids[0] };
    if (ids.length > 1) secure.extra_short_ids = ids.slice(1);
    const drift = String(options.maxTimeDiff ?? '').trim();
    if (drift) {
      const secs = Number(drift);
      if (!Number.isInteger(secs) || secs < 1 || secs > 3600) throw new Error(translate('Reality 最大时钟误差为 1–3600 秒，留空不检查'));
      secure.max_time_difference_secs = secs;
    }
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
  const shortId = field(fields, 'gateway_short_id', translate('Reality short ID（可填多个，用逗号分隔；客户端使用第一个）'), [spec?.security.short_id, ...(spec?.security.extra_short_ids || [])].filter(Boolean).join(', '), 'text', false);
  const maxTimeDiff = field(fields, 'gateway_max_time_diff', translate('Reality 最大时钟误差（秒，留空不检查）'), spec?.security.max_time_difference_secs ?? '', 'number', false); maxTimeDiff.min = 1; maxTimeDiff.max = 3600;
  const obfs = select(fields, 'gateway_obfs', translate('Hysteria2 混淆'), [['off', translate('关闭')], ['salamander', 'Salamander']], spec?.protocol.obfs ? 'salamander' : 'off');
  const obfsPassword = field(fields, 'gateway_obfs_password', translate('混淆密码（客户端须相同）'), spec?.protocol.obfs?.password || '', 'password', false);
  const masquerade = select(fields, 'gateway_masquerade', translate('认证失败时的伪装响应'), [['off', translate('引擎默认（404 Not Found）')], ['fixed', translate('固定响应')]], spec?.protocol.masquerade ? 'fixed' : 'off');
  const masqueradeStatus = field(fields, 'gateway_masquerade_status', translate('伪装响应状态码'), spec?.protocol.masquerade?.status_code ?? 404, 'number', false); masqueradeStatus.min = 200; masqueradeStatus.max = 599;
  const masqueradeContent = textarea(fields, 'gateway_masquerade_content', translate('伪装响应内容（可留空，最多 4096 字节）'), spec?.protocol.masquerade?.content || '');
  const congestion = select(fields, 'gateway_congestion', translate('TUIC 拥塞控制'), [['bbr', 'BBR'], ['cubic', 'CUBIC'], ['new_reno', 'NewReno']], spec?.protocol.congestion_control || 'bbr');
  const zeroRtt = select(fields, 'gateway_zero_rtt', translate('TUIC 0-RTT 握手'), [['no', translate('关闭')], ['yes', translate('启用 · 重连更快，早期数据可被重放')]], spec?.protocol.zero_rtt_handshake ? 'yes' : 'no');
  const allowPrivate = select(fields, 'gateway_private', translate('内网 / 回环目的地'), [['no', translate('拒绝（推荐）')], ['yes', translate('允许')]], spec?.allow_private_destinations ? 'yes' : 'no');
  const generate = button(translate('生成客户端凭据'), () => {
    uuid.value = crypto.randomUUID();
    password.value = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');
    if (obfs.value === 'salamander') obfsPassword.value = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');
  });
  const keys = button(translate('生成 Reality 密钥'), () => {
    privateKey.value = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    shortId.value = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
  });
  function show() {
    const on = type.value !== 'off', reality = security.value === 'reality', hysteria = type.value === 'hysteria2', tuic = type.value === 'tuic';
    for (const [control, visible] of [[uuid, ['vless', 'vmess', 'tuic'].includes(type.value)], [password, ['hysteria2', 'tuic', 'any_tls', 'trojan'].includes(type.value)], [vision, type.value === 'vless'], [identity, !reality], [handshake, reality], [privateKey, reality], [shortId, reality], [maxTimeDiff, reality], [obfs, hysteria], [obfsPassword, hysteria && obfs.value === 'salamander'], [masquerade, hysteria], [masqueradeStatus, hysteria && masquerade.value === 'fixed'], [masqueradeContent, hysteria && masquerade.value === 'fixed'], [congestion, tuic], [zeroRtt, tuic], [security, true], [serverName, true], [allowPrivate, true]]) {
      control.disabled = !on || !visible; control.parentElement.classList.toggle('hidden', !visible);
    }
    fields.classList.toggle('hidden', !on); generate.disabled = !on; keys.disabled = !on || !reality;
  }
  type.addEventListener('change', () => { if (type.value !== 'vless') security.value = 'certificate'; if (type.value !== 'off') payload.value = type.value === 'any_tls' ? 'tcp' : 'both'; show(); });
  security.addEventListener('change', show); obfs.addEventListener('change', show); masquerade.addEventListener('change', show);
  box.append(fields, generate, keys, el('p', translate('节点需要安装受支持的协议引擎。面板负责规则权限、流量账本、配额、限速和目的地 ACL。上方监听地址用于客户端连接；来源 ACL 使用实际客户端 IP。订阅请选择 sing-box JSON 或 mihomo YAML。证书模式须让客户端信任签发 CA。Reality 握手与伪装回落流量也计入配额并受目的地限制；请允许握手服务器地址与端口。来源 ACL 不替代握手前的主机防火墙。'), 'fine')); show();
  return { box, setEnabled(on) { type.value = on ? (type.value === 'off' ? 'vless' : type.value) : 'off'; if (on && !uuid.value) uuid.value = crypto.randomUUID(); show(); }, enabled: () => type.value !== 'off', onchange: f => type.addEventListener('change', f), read: () => gatewayConfig(type.value, publicListen.value, uuid.value, password.value, vision.value, security.value, identity.value, serverName.value, handshake.value, privateKey.value, shortId.value, allowPrivate.value, payload.value, { obfs: obfs.value, obfsPassword: obfsPassword.value, masquerade: masquerade.value, masqueradeStatus: masqueradeStatus.value, masqueradeContent: masqueradeContent.value, congestion: congestion.value, zeroRtt: zeroRtt.value, maxTimeDiff: maxTimeDiff.value }) };
}
function mptcpConfig(inbound, outbound, protocol) {
  const allowed = ['off', 'prefer', 'require'];
  if (!allowed.includes(inbound) || !allowed.includes(outbound)) throw new Error(translate('无效的 MPTCP 策略'));
  if (inbound === 'off' && outbound === 'off') return null;
  if (protocol === 'udp') throw new Error(translate('MPTCP 只适用于 TCP，不能用于纯 UDP 规则'));
  return { inbound, outbound };
}
function mptcpEditor(value) {
  const box = el('details', undefined, featureOn('mptcp') || (value && (value.inbound !== 'off' || value.outbound !== 'off')) ? '' : 'hidden'); box.append(el('summary', 'Linux MPTCP'));
  const options = [['off', translate('普通 TCP')], ['prefer', translate('优先 MPTCP · 允许 TCP 回退')], ['require', translate('必须协商 MPTCP · 否则拒绝')]];
  const inbound = select(box, 'mptcp_inbound', translate('入口传输'), options, value?.inbound || 'off');
  const outbound = select(box, 'mptcp_outbound', translate('出口传输'), options, value?.outbound || 'off');
  box.append(el('p', translate('MPTCP 需要 Linux 内核与对端支持。额外路径由节点网络配置决定；协商成功不代表已聚合多条线路。更改入口模式前请先停用并发布规则。'), 'fine'));
  return { box, gateway(on) { inbound.parentElement.classList.toggle('hidden', on); inbound.disabled = on; }, read: (protocol, gateway = false) => mptcpConfig(gateway ? 'off' : inbound.value, outbound.value, protocol) };
}
// Shared rules: one rule kept on several entry servers ("lines") with one listen port.
// The lines editor picks servers and the port; Auto pick and Check ask the controller for a
// per-line precheck, which reserves nothing.
function sharedLinesEditor(form, nodes, options) {
  const box = el('fieldset', undefined, 'shared-lines'), list = el('div', undefined, 'shared-line-list'), checks = [];
  box.append(el('legend', translate('线路（入口服务器）')));
  for (const node of nodes) {
    const label = el('label', undefined, 'inline-check'), input = el('input');
    input.type = 'checkbox'; input.value = node.id; input.checked = options.selected.includes(node.id);
    label.append(input, document.createTextNode(node.name || node.id)); list.append(label); checks.push(input);
  }
  box.append(list);
  const row = el('div', undefined, 'shared-port-row'), port = field(row, 'shared_port', translate('统一监听端口'), options.port ?? '', 'number', !options.fixedPort);
  port.min = 1; port.max = 65535; port.disabled = !!options.fixedPort;
  if (!options.fixedPort) row.append(button(translate('自动选号'), () => check(true)));
  row.append(button(translate('检查'), () => check(false)));
  const report = el('div', undefined, 'shared-precheck');
  box.append(row, el('p', options.fixedPort ? translate('新线路沿用原规则的端口；检查只核对所选的新线路。') : translate('自动选号从所选服务器转发端口范围的交集中，挑选在全部线路上都空闲的最小端口；也可以手动填写后点击“检查”。预检不会预占端口，保存时会重新检查。'), 'fine'), report);
  form.append(box);
  const names = new Map(nodes.map(node => [node.id, node.name || node.id]));
  const selected = () => checks.filter(input => input.checked).map(input => input.value);
  function readPort() {
    const value = Number(port.value);
    if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(translate('请输入 1 到 65535 之间的端口。'));
    return value;
  }
  async function check(auto) {
    const node_ids = selected();
    if (!node_ids.length) throw new Error(translate('请至少选择一台服务器。'));
    const body = { node_ids, listen_port: auto ? null : readPort(), rule: await options.readRule() };
    if (options.id) body.id = options.id;
    const result = await api('/shared-rules/precheck', { method: 'POST', body });
    if (auto && result.listen_port) port.value = String(result.listen_port);
    const summary = result.ok ? msg`端口 ${result.listen_port} 在全部 ${result.lines.length} 条线路上可用。` : result.error || translate('部分线路未通过预检，请查看下表。');
    report.replaceChildren(el('p', summary, result.ok ? 'workflow-callout' : 'workflow-callout warning'), table([translate('线路'), translate('在线'), translate('端口范围'), translate('端口空闲'), translate('配置校验')], result.lines.map(line => [
      line.node_name, badge(line.online ? translate('在线') : translate('离线'), line.online ? 'green' : 'orange'),
      line.in_range ? `${line.port_start}–${line.port_end}` : msg`${line.port_start}–${line.port_end} · 不在范围内（仅提示）`,
      badge(line.port_free ? translate('空闲') : translate('已占用'), line.port_free ? 'green' : 'red'),
      line.valid ? badge(translate('通过'), 'green') : namedCell(translate('未通过'), line.error || '—')])));
    return result;
  }
  return {
    box, selected, port: readPort, check,
    showErrors(lines) { report.replaceChildren(el('p', translate('以下线路未通过检查，没有发布任何修改：'), 'workflow-callout warning'), table([translate('线路'), translate('原因')], lines.map(line => [names.get(line.node_id) || line.node_id, line.error]))); },
  };
}
const listenPort = listen => Number(String(listen).split(':').pop());
function ruleNameCell(rule, membership) {
  const cell = namedCell(rule.name, rule.id);
  if (membership) cell.append(badge(msg`共同规则 · ${membership.members.length} 条线路`, 'blue'));
  if (rule.reverse_tunnel) cell.append(badge(translate('反向隧道公网端'), 'blue'));
  return cell;
}
function sharedTarget(rule) {
  if (!rule) return '—';
  if (rule.inbound_shadowsocks) return translate('Shadowsocks 代理服务');
  if (rule.inbound_socks5) return translate('SOCKS5 代理服务');
  if (rule.inbound_http_connect) return translate('HTTP CONNECT 代理服务');
  if (rule.inbound_http2_connect) return 'HTTP/2 CONNECT';
  return namedCell(rule.targets[0]?.address || '—', rule.targets.length > 1 ? msg`${rule.targets.length} 个目标` : translate('单一目标'));
}
// Listed on both forwarding pages; `nodes` supplies each line's application state.
function sharedRulesPanel(rules, nodes) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const p = panel(translate('共同规则'), translate('同一条规则运行在多台入口服务器（线路）上，使用同一个监听端口；创建、修改、暂停和删除一次作用于全部线路。每条线路上的成员仍是普通规则，客户端连接任意一个入口地址即可。'), canWrite() ? button(translate('＋ 新建共同规则'), () => openSharedRule(), 'primary') : null);
  if (!rules.length) { p.append(el('p', translate('还没有共同规则。点击“新建共同规则”，或在「按服务器」的规则操作中选择“扩展到多条线路…”。'), 'fine')); return p; }
  p.append(table([translate('名称'), translate('线路与状态'), translate('入口地址'), translate('目标'), translate('操作')], rules.map(view => {
    const present = view.members.filter(member => !member.missing), entries = present.map(member => member.entry).filter(Boolean);
    const name = el('div'); name.append(el('strong', view.name), el('div', msg`共同规则 · ${view.members.length} 条线路`, 'subline'));
    if (view.drift.length) name.append(badge(translate('线路配置不一致'), 'orange'), el('div', msg`不同的字段：${view.drift.join(', ')}`, 'subline mono'));
    const lines = el('div', undefined, 'shared-line-status');
    for (const member of view.members) {
      const row = el('div'), node = byId.get(member.node_id);
      row.append(el('span', `${member.node_name || member.node_id} · ${member.rule ? listenPort(member.rule.listen) : view.listen_port}`), member.missing ? badge(translate('规则或服务器已不存在'), 'red') : !member.rule.enabled ? badge(translate('已暂停'), 'orange') : node ? applicationBadge(node) : badge('—'));
      if (member.drift.length) row.append(badge(translate('与第一条线路不同'), 'orange'));
      lines.append(row);
    }
    const entryCell = el('div', undefined, 'shared-entries');
    for (const member of present) entryCell.append(el('div', member.entry || msg`${member.node_name || member.node_id}：未设置转发地址`, member.entry ? 'mono' : 'fine'));
    if (entries.length) entryCell.append(button(translate('复制全部'), async () => { await navigator.clipboard.writeText(entries.join('\n')); notify(msg`已复制 ${entries.length} 个入口地址。`); }, 'table-action'));
    const tools = el('div');
    if (canWrite()) {
      const paused = present.length > 0 && present.every(member => !member.rule.enabled);
      tools.append(button(translate('编辑'), () => openSharedRule(view), 'table-action'), button(paused ? translate('恢复运行') : translate('暂停'), () => pauseSharedRule(view, !paused), 'table-action'), button(translate('删除'), () => deleteSharedRule(view), 'table-action danger'));
    }
    return [name, lines, entryCell, sharedTarget(present[0]?.rule), tools];
  })));
  return p;
}
// The form is the rule editor in shared mode; the common fields start from the first present line.
async function openSharedRule(view = null) {
  const nodes = await api('/nodes'); state.nodes = nodes;
  const first = view?.members.find(member => !member.missing);
  const reference = first?.node_id || (nodes.find(node => node.id === state.selectedNode) || nodes[0])?.id;
  if (!reference) throw new Error(translate('先注册节点，再创建规则。'));
  const config = await api(`/nodes/${encodeURIComponent(reference)}/config`);
  await editRule(undefined, { ...(first?.rule || {}), name: view?.name || '', shared: { id: view?.id || null, name: view?.name || '', reference: config, selected: view ? view.members.filter(member => !member.missing).map(member => member.node_id) : [], port: view?.listen_port ?? null, drift: view?.drift || [], missing: view ? view.members.length - view.members.filter(member => !member.missing).length : 0 } });
}
async function pauseSharedRule(view, paused) {
  if (paused && !await confirmAction(msg`暂停「${view.name}」的全部 ${view.members.filter(member => !member.missing).length} 条线路？这些规则会停止接受新连接。`)) return;
  await api(`/shared-rules/${encodeURIComponent(view.id)}/pause`, { method: 'POST', body: { paused } });
  notify(paused ? translate('全部线路已暂停。') : translate('全部线路已恢复。')); await refresh();
}
function deleteSharedRule(view) {
  const form = el('form'), present = view.members.filter(member => !member.missing), list = el('ul');
  form.append(el('p', present.length ? msg`删除「${view.name}」会删除下列 ${present.length} 条线路上的规则并终止其会话，历史账本保留：` : translate('全部线路都已不存在，删除只移除共同规则本身。'), 'workflow-callout warning'));
  for (const member of present) list.append(el('li', msg`${member.node_name || member.node_id} · 端口 ${listenPort(member.rule.listen)}`));
  form.append(list);
  const keep = checkbox(form, 'keep_rules', translate('只删除共同规则，保留各线路上的规则，之后作为普通规则单独管理'));
  submit(form, translate('删除'), async () => {
    await api(`/shared-rules/${encodeURIComponent(view.id)}${keep.checked ? '?keep_rules=true' : ''}`, { method: 'DELETE' });
    $('#dialog').close(); notify(keep.checked ? translate('共同规则已删除，各线路上的规则保留。') : translate('共同规则及其全部线路上的规则已删除。')); await refresh();
  });
  modal(msg`删除共同规则 · ${view.name}`, form, 'confirm');
}
// An ordinary rule becomes the first line and keeps its id, port and counters.
function extendRule(config, rule) {
  const tenant = state.nodes.find(node => node.id === config.node_id)?.tenant_id, nodes = state.nodes.filter(node => node.tenant_id === tenant && node.id !== config.node_id);
  if (!nodes.length) throw new Error(translate('同一租户中没有其他服务器可以添加。'));
  const form = el('form'), port = listenPort(rule.listen);
  form.append(el('p', msg`「${rule.name}」会成为共同规则的第一条线路，保留规则编号、端口 ${port} 和流量统计；所选服务器上会新建配置相同、端口相同的规则。`, 'workflow-callout'));
  const lines = sharedLinesEditor(form, nodes, { selected: [], port, fixedPort: true, readRule: async () => rule });
  submit(form, translate('扩展到所选线路'), async () => {
    const add_node_ids = lines.selected();
    if (!add_node_ids.length) throw new Error(translate('请至少选择一台服务器。'));
    try { await api('/shared-rules/from-rule', { method: 'POST', body: { node_id: config.node_id, rule_id: rule.id, add_node_ids } }); }
    catch (error) { if (error.detail?.lines) lines.showErrors(error.detail.lines); throw error; }
    $('#dialog').close(); notify(msg`「${rule.name}」已扩展为共同规则，全部线路已同时提交。`); await refresh();
  });
  modal(msg`扩展到多条线路 · ${rule.name}`, form);
}
async function editRule(existing, seed = {}) {
  const shared = seed.shared; let baseConfig = shared?.reference || state.config, nodeLoad = null;
  const topology = await api('/topology'); const form = el('form'), grid = el('div', undefined, 'form-grid'), r = existing || seed, asTemplate = seed.template;
  if (asTemplate) {
    form.append(el('h3', translate('1. 模板名称与用途'), 'setup-step'));
    const about = el('div', undefined, 'form-grid'); field(about, 'template_name', translate('模板名称'), asTemplate.name || '').maxLength = 120;
    field(about, 'template_description', translate('模板说明（可留空）'), asTemplate.description || '', 'text', false).maxLength = 2000;
    form.append(about, el('p', translate('模板保存下方的规则内容。使用模板时再选择服务器、填写名称和监听地址；这里不会发布任何配置。'), 'workflow-callout'));
  } else form.append(el('h3', shared ? translate('1. 名称、线路与端口') : translate('1. 选择运行 VPS 与服务'), 'setup-step'));
  const extraGrid = el('div', undefined, 'form-grid');
  if ([r.inbound_shadowsocks, r.inbound_socks5, r.inbound_http_connect, r.inbound_http2_connect, r.protocol_gateway].filter(Boolean).length > 1) throw new Error(translate('每条规则只能启用一种代理入口'));
  const tenant = state.nodes.find(n => n.id === baseConfig.node_id).tenant_id;
  const runOn = select(grid, 'run_on', asTemplate ? translate('参考服务器（只用于选择下一跳，不会发布）') : translate('运行节点 / VPS'), state.nodes.filter(n => n.tenant_id === tenant).map(n => [n.id, n.name || n.id]), baseConfig.node_id);
  runOn.disabled = !!existing;
  if (shared) sectionVisible(runOn.parentElement, false);
  const purpose = select(grid, 'rule_purpose', translate('规则用途'), localize([['forward', '端口转发 · 入口或中转'], ['ss', 'Shadowsocks · 出口代理服务'], ['socks5', 'SOCKS5 · 代理服务'], ['http', 'HTTP CONNECT · 代理服务'], ['h2', 'HTTP/2 CONNECT · 代理服务'], ['gateway', '受管协议 · VLESS / Reality / Hysteria2 / TUIC / AnyTLS / Trojan / VMess']]).filter(([kind]) => !shared || kind !== 'gateway'), serviceKind(r));
  const ruleName = field(grid, 'name', translate('规则名称'), r.name || ''); ruleName.maxLength = 120;
  if (asTemplate) sectionVisible(ruleName.parentElement, false);
  const protocolControl = select(grid, 'protocol', translate('传输协议（TCP / UDP）'), [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], r.protocol || 'tcp');
  const listenControl = field(grid, 'listen', translate('监听地址'), r.protocol_gateway?.listen || r.listen || '127.0.0.1:9000');
  const advertise = field(grid, 'advertise', translate('客户端 / 上一跳连接地址（VPS 公网 IP 或域名:端口）'), r.advertise || '', 'text', !!seed.name && !asTemplate && !shared); advertise.placeholder = 'vps.example.com:9000';
  const endPort = field(extraGrid, 'listen_end_port', translate('结束端口（留空只监听一个端口，最多 256 个）'), r.listen_end_port, 'number', false); endPort.min = 1; endPort.max = 65535;
  const mapping = select(extraGrid, 'port_mapping', translate('端口段的目标映射'), [['fixed', translate('全部入口连接同一目标端口')], ['offset', translate('按入口端口偏移目标端口')]], r.port_mapping || 'fixed');
  const balance = select(extraGrid, 'balance', translate('目标分配'), [['weighted_round_robin', translate('加权轮询')], ['source_hash', translate('来源 IP 哈希')], ['least_connections', translate('最少连接')], ['lowest_latency', translate('最低延迟（须启用健康探测）')], ['random', translate('随机（同优先级内均匀选择，忽略权重）')]], r.balance || 'weighted_round_robin'); form.append(grid);
  // A template runs nowhere until it is used, so it does not name a server here.
  const placement = el('p', '', asTemplate ? 'workflow-callout hidden' : 'workflow-callout'), reachability = el('p', '', 'fine'); form.append(placement, reachability);
  // A shared rule runs on every chosen line; each line keeps its own listen host.
  const lines = shared ? sharedLinesEditor(form, state.nodes.filter(n => n.tenant_id === tenant), { id: shared.id, selected: shared.selected, port: shared.port, readRule: () => readRule(new FormData(form)) }) : null;
  if (shared) {
    sectionVisible(listenControl.parentElement, false);
    if (shared.id) form.append(el('p', translate('修改统一监听端口时，全部线路一起换号，各线路的流量统计重新开始；请先安排客户端改用新端口。'), 'fine'));
    if (shared.drift.length) form.append(el('p', msg`线路配置不一致：${shared.drift.join(', ')}。保存会把这些字段统一为当前表单的值（表单取自第一条线路）。`, 'workflow-callout warning'));
    if (shared.missing) form.append(el('p', msg`${shared.missing} 条线路的规则或服务器已不存在，保存时会从共同规则中移除。`, 'fine'));
  }
  function describePlacement() {
    if (shared) { placement.textContent = translate('共同规则在每条所选线路上各运行一条相同的规则：监听地址取服务器转发设置中的监听 IP，未设置时监听全部地址。'); reachability.textContent = translate('发布配置不会自动修改防火墙；请在每台服务器上放行这个端口。'); return; }
    const node = state.nodes.find(n => n.id === runOn.value);
    placement.textContent = purpose.value === 'forward' ? msg`运行于 ${node.name}：将流量转发到下方目标。多跳转发请在“新建转发”中选择多跳方式。` : purpose.value === 'gateway' ? msg`服务运行于 ${node.name}。此节点须先安装受支持的协议引擎并准备证书或 Reality 配置；保存规则不会自动下载安装引擎。` : msg`代理服务运行于 ${node.name}，由此节点连接客户端请求的目的地。Agent 已内置该服务，无需另装服务端。`;
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
    sectionVisible(advertise.parentElement, !gateway.enabled() && !shared);
    sectionVisible(endPort.parentElement, !gateway.enabled() && !shared);
    sectionVisible(mapping.parentElement, !server && !shared);
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
  const limits = el('div', undefined, 'form-grid'); field(limits, 'quota_bytes', translate('合并配额 / bytes（留空不限，0 禁止流量）'), r.quota_bytes, 'number', false).min = 0; form.append(limits);
  const speed = rateLimitEditor({ rate: r.rate_bytes_per_sec, limits: r.rate_limits, unit: 'bytes', burst: true, combined: { name: 'rate_bytes_per_sec', label: translate('合并速率 / bytes/s（留空不限）') } }); form.append(speed.box);
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
    const { rate_limits } = speed.read(data); if (rate_limits) rule.rate_limits = rate_limits;
    return rule;
  }
  const options = el('details'); options.append(el('summary', translate('配额、端口范围与高级选项')), extraGrid, mptcp.box, routing, transport, inboundWs.box, proxyInput, limits, speed.box, details);
  form.append(options);
  const pathView = forwardingPathView(); if (!asTemplate && !shared) form.append(el('h3', translate('3. 检查并预览发布'), 'setup-step'), pathView.box);
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
  if (shared) {
    submit(form, shared.id ? translate('保存到全部线路') : translate('创建并发布到全部线路'), async data => {
      const rule = await readRule(data), body = { name: rule.name, node_ids: lines.selected(), listen_port: lines.port(), rule };
      if (!body.node_ids.length) throw new Error(translate('请至少选择一台服务器。'));
      try { await api(shared.id ? `/shared-rules/${encodeURIComponent(shared.id)}` : '/shared-rules', { method: shared.id ? 'PUT' : 'POST', body }); }
      catch (error) { if (error.detail?.lines) lines.showErrors(error.detail.lines); throw error; }
      $('#dialog').close(); notify(translate('共同规则已保存，全部线路的期望配置已同时提交。')); await refresh();
    }); modal(shared.id ? msg`编辑共同规则 · ${shared.name}` : translate('新建共同规则'), form); return;
  }
  if (asTemplate) {
    submit(form, translate('保存模板'), async data => {
      const rule = { ...await readRule(data), name: String(data.get('template_name')).trim() }, body = { tenant_id: asTemplate.id ? asTemplate.tenant_id : state.actor.role === 'system_admin' ? null : state.actor.tenant_id, name: String(data.get('template_name')).trim(), description: String(data.get('template_description')).trim(), rule, variables: asTemplate.variables || {} };
      await api(asTemplate.id ? `/templates/${asTemplate.id}` : '/templates', { method: asTemplate.id ? 'PUT' : 'POST', body });
      $('#dialog').close(); notify(asTemplate.id ? translate('模板已保存为新版本；已创建的规则不受影响。') : translate('模板已创建。')); await navigate('templates');
    }); modal(asTemplate.id ? msg`编辑模板 · ${asTemplate.name}` : translate('新建模板'), form); return;
  }
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
// The controller builds gateway links (it derives the Reality public key and
// never includes the private key) and renders their QR codes.
function shareGateway(rule, nodeId) {
  const endpoint = clientEndpoint(rule);
  const body = el('div'), grid = el('div', undefined, 'form-grid');
  const host = field(grid, 'host', translate('客户端连接的地址（公网 IP 或域名）'), endpoint.host);
  const port = field(grid, 'port', translate('端口'), endpoint.port, 'number'); port.min = 1; port.max = 65535;
  const tag = field(grid, 'tag', translate('客户端里显示的名称'), rule.name); tag.maxLength = 120;
  const link = el('pre', '', 'secret-box mono'), problem = el('p', '', 'error'), qr = el('img', undefined, 'qr-code');
  qr.alt = translate('分享链接二维码'); qr.hidden = true;
  let serial = 0, timer;
  const update = async () => {
    const request = ++serial, address = host.value.trim().replace(/^\[|\]$/g, '');
    link.textContent = ''; problem.textContent = ''; qr.hidden = true;
    if (!address || !splitEndpoint(`${address.includes(':') ? `[${address}]` : address}:${port.value.trim()}`)) return;
    const query = new URLSearchParams({ host: address, port: port.value.trim(), name: tag.value.trim() });
    try {
      const result = await api(`/nodes/${encodeURIComponent(nodeId)}/rules/${encodeURIComponent(rule.id)}/share?${query}`);
      if (request !== serial) return;
      link.textContent = result.uri; qr.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(result.qr_svg)}`; qr.hidden = false;
    } catch (error) { if (request === serial) problem.textContent = error.message; }
  };
  [host, port, tag].forEach(input => input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 400); })); update();
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('关闭对话框'), () => $('#dialog').close()), button(translate('复制链接'), async () => { if (!link.textContent) throw new Error(translate('请填写入口的有效 IP 或域名和端口。')); await navigator.clipboard.writeText(link.textContent); notify(translate('分享链接已复制。')); }, 'primary'));
  body.append(grid, link, problem, qr, el('p', translate('用客户端扫描二维码或粘贴链接导入。链接包含客户端 UUID / 密码，不含 Reality 私钥；持有者即可使用本节点，请只发给使用者本人。证书模式须让客户端信任签发 CA。AnyTLS 没有通用链接格式，请使用订阅。'), 'fine'), actions);
  modal(msg`分享 ${rule.name}`, body);
}
const subscriptionFormats = localize({ sing_box: 'sing-box JSON（SS 与受管协议）', v2ray: 'V2Ray / Base64（ss:// 列表）', clash: 'mihomo / Clash Meta（YAML）', surge: 'Surge（完整配置 · 自动更新）', shadowrocket: 'Shadowrocket（ss:// 列表）' });
const dnsModes = localize({ observe: '观察（只读，不写服务商）', apply: '应用（创建/更新/删除托管记录）' });
const dnsRecordTypes = ['A', 'AAAA', 'CNAME'];
const announcementSeverities = localize({ info: '信息', warning: '警告', critical: '严重' });
function announcementTime(ms) { return timestamp(ms); }
function announcementDateTime(ms) { const d = new Date(ms || Date.now()); const pad = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
const ticketStatuses = localize({ open: '待处理', pending: '处理中', closed: '已关闭' });
const ticketPriorities = localize({ low: '低', normal: '普通', high: '高' });
async function renderTemplates() {
  const actor = state.actor;
  const [templates, nodes] = await Promise.all([api('/templates'), api('/nodes')]);
  if (state.view !== 'templates' || !actor || state.actor !== actor) return;
  state.nodes = nodes;
  const actions = el('div'); actions.append(button(translate('＋ 新建模板'), () => editTemplate(), 'primary'));
  const p = panel(translate('我的规则模板'), translate('模板保存一条规则的协议、目标与限制。使用时选择服务器并填写监听地址，生成一条新规则；之后修改模板不会改动已创建的规则。'), actions);
  if (!templates.length) p.append(empty(translate('还没有模板'), translate('点击“新建模板”从空白开始，或在「转发规则 · 按服务器」的规则列表中点击“存为模板”。'), button(translate('＋ 新建模板'), () => editTemplate(), 'primary')));
  else p.append(table([translate('名称 / 说明'), translate('类型'), translate('监听 / 协议'), translate('版本'), translate('范围'), translate('操作')], templates.map(template => {
    const actions = el('div', undefined, 'row-actions'), owner = state.actor.role === 'system_admin' || template.tenant_id === state.actor.tenant_id;
    actions.append(button(translate('使用'), () => applyTemplate(template), 'table-action'), button(translate('批量应用'), () => rolloutTemplate(template), 'table-action'));
    if (owner) actions.append(button(translate('编辑'), () => editTemplate(template), 'table-action'));
    actions.append(button(translate('版本历史'), () => templateVersions(template), 'table-action'));
    if (owner) actions.append(button(translate('删除'), () => deleteTemplate(template), 'table-action danger'));
    return [namedCell(template.name, template.description || '—'), templateKind(template.rule), namedCell(template.rule.protocol_gateway?.listen || template.rule.listen, { tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' }[template.rule.protocol] || template.rule.protocol), `v${template.version}`, template.tenant_id ? translate('本租户') : translate('全局'), actions];
  })));
  const wizards = el('div', undefined, 'template-wizards'), copy = el('div');
  copy.append(el('strong', translate('想一步步引导？')), el('p', translate('内置向导（单台或多跳的端口转发、Shadowsocks）在「转发规则」的“新建转发”里，会自动分配地址和端口。'), 'fine'));
  wizards.append(copy, button(translate('打开新建转发'), chooseSetup));
  p.append(wizards);
  if (state.view === 'templates') $('#content').replaceChildren(p);
}
function templateKind(rule) {
  const names = localize({ forward: '端口转发', ss: 'Shadowsocks 服务', socks5: 'SOCKS5 服务', http: 'HTTP CONNECT 服务', h2: 'HTTP/2 CONNECT 服务', gateway: '受管协议服务' }), kind = serviceKind(rule);
  return namedCell(names[kind], kind === 'forward' ? (rule.targets.length > 1 ? msg`${rule.targets.length} 个目标` : rule.targets[0]?.address || '—') : kind === 'gateway' ? rule.protocol_gateway.protocol.type.toUpperCase() : kind === 'ss' ? rule.inbound_shadowsocks.method : '');
}
// New or changed templates use the full rule editor; a reference server supplies next-hop choices only.
async function editTemplate(template = null) {
  const nodes = await api('/nodes'); if (!nodes.length) throw new Error(translate('先注册节点，再创建规则。'));
  state.nodes = nodes;
  const tenant = template?.tenant_id || state.actor.tenant_id, node = nodes.find(n => n.id === state.selectedNode && n.tenant_id === tenant) || nodes.find(n => n.tenant_id === tenant) || nodes[0];
  state.config = await api(`/nodes/${node.id}/config`);
  return editRule(null, { ...(template?.rule || {}), template: template || {} });
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
async function templateDiff(template, from) {
  const diff = await api(`/templates/${template.id}/diff?from=${from}&to=${template.version}`), body = el('div');
  body.append(el('p', msg`v${from} → 当前 v${template.version}`, 'fine'));
  if (!diff.changes.length) body.append(el('p', translate('两个版本内容相同。'), 'fine'));
  else body.append(table([translate('字段'), translate('旧值'), translate('新值')], diff.changes.map(change => [el('code', change.path), el('code', JSON.stringify(change.from)), el('code', JSON.stringify(change.to))])));
  body.append(button(translate('返回版本历史'), () => templateVersions(template)));
  modal(msg`差异 · ${template.name}`, body);
}
async function templateVersions(template) {
  const versions = await api(`/templates/${template.id}/versions`), owner = state.actor.role === 'system_admin' || template.tenant_id === state.actor.tenant_id;
  const content = el('div'); content.append(el('p', msg`当前版本 ${template.version}；保留 ${versions.length} 个版本。每次保存模板都会生成新版本。`, 'fine'));
  if (!versions.length) content.append(el('p', translate('这个模板还没有被修改过。'), 'fine'));
  else content.append(table([translate('版本'), translate('名称'), translate('操作')], versions.map(version => {
    const actions = el('div', undefined, 'row-actions');
    if (version.version < template.version) actions.append(button(translate('与当前比较'), () => templateDiff(template, version.version), 'table-action'));
    if (version.version < template.version && owner) actions.append(button(translate('回滚到此版本'), async () => {
      if (!await confirmAction(msg`把「${template.name}」恢复为 v${version.version} 的内容？会生成一个新版本，已创建的规则不受影响。`)) return;
      await api(`/templates/${template.id}/versions/${version.version}/rollback`, { method: 'POST' });
      $('#dialog').close(); notify(translate('模板已回滚。')); await renderTemplates();
    }, 'table-action'));
    return [`v${version.version}`, version.name, actions];
  })));
  modal(msg`版本 · ${template.name}`, content);
}

// Pick servers and listeners; the server checks each target and applies them in batches.
async function rolloutTemplate(template) {
  const snapshot = await api('/topology'), nodes = snapshot.nodes;
  if (!nodes.length) throw new Error(translate('先注册节点，再创建规则。'));
  const form = el('form'), listen = template.rule.protocol_gateway?.listen || template.rule.listen;
  field(form, 'name', translate('新规则名称'), template.name).maxLength = 120;
  const picker = el('fieldset', undefined, 'rollout-targets'); picker.append(el('legend', translate('选择服务器，并确认各自的监听地址')));
  const rows = nodes.map(node => {
    const row = el('div', undefined, 'rollout-row'), label = el('label', undefined, 'inline-check'), pick = el('input'), address = el('input');
    pick.type = 'checkbox'; pick.setAttribute('aria-label', node.name); address.value = listen; address.disabled = true; address.setAttribute('aria-label', msg`${node.name} 的监听地址`);
    pick.onchange = () => { address.disabled = !pick.checked; };
    label.append(pick, el('span', node.name), el('span', online(node) ? translate('控制在线') : translate('无近期回报'), online(node) ? 'subline' : 'subline warning'));
    row.append(label, address); picker.append(row);
    return { node, pick, address };
  });
  form.append(picker);
  const options = el('details'); options.append(el('summary', translate('分批与安全检查')));
  const grid = el('div', undefined, 'form-grid');
  const batch = field(grid, 'batch_size', translate('每批服务器数（1–50）'), '1', 'number'); batch.min = 1; batch.max = 50;
  field(grid, 'canary_percent', translate('首批百分比（留空使用批大小）'), '', 'number', false);
  field(grid, 'wait_for_apply_ms', translate('应用回执等待 / ms（留空不等待）'), '', 'number', false);
  options.append(grid);
  checkbox(options, 'rollback_on_failure', translate('失败时移除本次已发布规则'));
  checkbox(options, 'require_healthy', translate('仅健康节点（90 秒内有同步且无应用错误）'));
  checkbox(options, 'require_target_health', translate('目标健康门控（本次修订与规则的有效健康报告）'));
  form.append(options, el('p', translate('按顺序分批应用；某批失败后停止后续批次，成功节点仍保留，并返回每个节点的结果。'), 'fine'));
  submit(form, translate('开始批量应用'), async data => {
    const chosen = rows.filter(row => row.pick.checked);
    if (!chosen.length) throw new Error(translate('请至少选择一台服务器'));
    const targets = chosen.map(({ node, address }) => ({ node_id: node.id, expected_revision: snapshot.configs.find(c => c.node_id === node.id).revision, name: String(data.get('name')).trim(), listen: address.value.trim() }));
    const report = await api(`/templates/${template.id}/rollout`, { method: 'POST', body: { batch_size: Number(data.get('batch_size')), canary_percent: data.get('canary_percent') ? Number(data.get('canary_percent')) : null, require_healthy: data.get('require_healthy') === 'on', require_target_health: data.get('require_target_health') === 'on', wait_for_apply_ms: data.get('wait_for_apply_ms') ? Number(data.get('wait_for_apply_ms')) : null, rollback_on_failure: data.get('rollback_on_failure') === 'on', targets } });
    $('#dialog').close();
    const content = el('div'), names = new Map(nodes.map(node => [node.id, node.name])), yes = value => value ? '✓' : '—';
    const renderReport = current => {
      const summary = el('p', msg`已发布 ${current.applied} / ${current.results.length} 台 · 共 ${current.batches} 批 · 已回滚 ${current.rolled_back}`, current.aborted ? 'workflow-callout warning' : 'workflow-callout');
      content.replaceChildren(summary);
      if (current.aborted) content.append(el('p', current.gate_error ? msg`已停止：${current.gate_error}` : translate('已停止：有一批未通过，后续批次未执行。'), 'error'));
      content.append(table([translate('服务器'), translate('批次'), translate('已发布'), translate('已回执'), translate('健康'), translate('完成'), translate('错误')], current.results.map(r => [names.get(r.node_id) || r.node_id, String(r.batch), yes(r.applied), yes(r.acknowledged), yes(r.healthy), yes(r.completed), r.error || r.rollback_error || (r.rolled_back ? translate('已回滚') : '—')])));
      const raw = el('details'); raw.append(el('summary', translate('原始结果')), el('pre', JSON.stringify(current, null, 2), 'json-preview')); content.append(raw);
      if (current.aborted) content.append(button(translate('重新检查并继续批量'), async () => renderReport(await api(`/templates/${template.id}/rollouts/${current.id}/retry`, { method: 'POST' }))));
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
  field(grid, 'listen', translate('监听地址'), template.rule.protocol_gateway?.listen || template.rule.listen);
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
  const actor = state.actor;
  const tickets = await api('/tickets');
  if (state.view !== 'tickets' || !actor || state.actor !== actor) return;
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
const orderKinds = localize({ plan: '套餐购买', top_up: '补流量' });
// The controller's reasons for not topping up; the alert texts use the same words.
const topUpFailures = localize({ not_configured: '套餐未配置自动补流量', switched_off: '用户未开启自动补流量', cap_reached: '本周期补流量次数已达上限', insufficient_balance: '钱包余额不足' });
function money(cents) { return `¥${(cents / 100).toFixed(2)}`; }
function trafficResetLabel(reset) {
  if (reset === 'billing') return translate('跟随计费周期');
  if (reset?.every_days) return msg`每 ${reset.every_days} 天重置`;
  return translate('不重置');
}
function topUpLabel(topUp) { return topUp ? msg`每次 ${bytes(topUp.bytes)} · ${money(topUp.price_cents)} · 每周期最多 ${topUp.max_per_cycle} 次` : translate('未配置'); }
function planCycleCell(plan) {
  const n = el('div'); n.append(el('div', trafficResetLabel(plan.traffic_reset)));
  if (plan.top_up) n.append(el('div', msg`补流量 ${bytes(plan.top_up.bytes)} · ${money(plan.top_up.price_cents)}`, 'subline'), el('div', msg`每周期最多 ${plan.top_up.max_per_cycle} 次`, 'subline'));
  return n;
}
function day(ms) { return new Date(ms).toLocaleDateString(getLanguage()); }
function topUpCount(cycle) { return cycle.top_up ? `${cycle.top_ups} / ${cycle.top_up.max_per_cycle}` : translate('未配置'); }
async function switchAutoTopUp(item, enabled) {
  await api(`/commerce/entitlements/${item.user_id}/auto-top-up`, { method: 'PUT', body: { enabled } });
  notify(enabled ? translate('已开启自动补流量。') : translate('已关闭自动补流量。')); await renderCommerce();
}
async function resetTraffic(item) {
  if (!await confirmAction(msg`立即重置 ${item.username || item.user_id} 的本周期流量？已用流量清零并从现在开始新周期，本周期的补流量一并清零，到期时间不变。`)) return;
  await api(`/commerce/entitlements/${item.user_id}/reset`, { method: 'POST' });
  notify(translate('流量已重置，新周期从现在开始。')); await renderCommerce();
}
const entitlementStates = localize({ active: ['生效中', 'green'], awaiting_budget: ['等待额度', 'orange'], lapsed: ['已到期', ''] });
function entitlementBadge(value) { const [label, color] = entitlementStates[value] || [value, '']; return badge(label, color); }
function planUsage(budget) {
  if (!budget) return '—';
  const unlimited = budget.limit_bytes >= 9223372036854775807;
  return meter(unlimited ? 0 : budget.consumed_bytes / Math.max(1, budget.limit_bytes), `${bytes(budget.consumed_bytes)} / ${unlimited ? translate('不限') : bytes(budget.limit_bytes)}`);
}
async function activatePlan(user) { await api(`/commerce/entitlements/${user}/activate`, { method: 'POST' }); notify(translate('套餐已生效。')); await renderCommerce(); }
function myPlanPanel(item) {
  const cycle = item?.current_cycle;
  const p = panel(translate('我的套餐'), cycle ? translate('此套餐按周期重置流量：每个周期从套餐流量重新开始，未用完的流量不结转；续费只顺延到期时间。') : translate('购买的套餐会把流量和天数加到你的流量额度。续费会叠加流量并顺延到期时间；到期后不再发放新流量。'));
  if (!item) { p.append(empty(translate('还没有生效的套餐'), translate('从下方选择套餐购买，付款后自动生效。'))); return p; }
  const board = el('div', undefined, 'alert-status diagnostics-board'), budget = item.budget, unlimited = budget && budget.limit_bytes >= 9223372036854775807;
  const [label, color] = entitlementStates[item.state] || [item.state, ''];
  const tiles = cycle
    ? [[translate('状态'), label, color], [translate('到期'), day(item.expires_at_ms), ''], [translate('本周期已用'), bytes(cycle.used_bytes), ''], [translate('本周期额度'), cycle.allowance_bytes === null ? translate('不限') : bytes(cycle.allowance_bytes), ''], [translate('剩余'), cycle.remaining_bytes === null ? translate('不限') : bytes(cycle.remaining_bytes), cycle.remaining_bytes === 0 ? 'red' : ''], [translate('下次重置'), cycle.next_reset_at_ms ? day(cycle.next_reset_at_ms) : translate('到期前不再重置'), ''], [translate('本周期补流量'), topUpCount(cycle), '']]
    : [[translate('状态'), label, color], [translate('到期'), day(item.expires_at_ms), ''], [translate('已用'), budget ? bytes(budget.consumed_bytes) : '—', ''], [translate('额度'), !budget ? '—' : unlimited ? translate('不限') : bytes(budget.limit_bytes), '']];
  for (const [name, value, tone] of tiles) { const tile = el('div', undefined, `alert-stat ${tone}`); tile.append(el('div', value, 'metric-value'), el('div', name, 'metric-label')); board.append(tile); }
  p.append(board);
  if (cycle) {
    const body = el('div', undefined, 'panel-body'), actions = el('div', undefined, 'panel-actions');
    body.append(el('p', msg`本周期 ${day(cycle.started_at_ms)} – ${day(cycle.ends_at_ms)} · ${trafficResetLabel(cycle.policy)}。`, 'fine'));
    if (cycle.reserved_bytes) body.append(el('p', msg`服务器已领取、尚未上报的 ${bytes(cycle.reserved_bytes)} 也占用本周期流量。`, 'fine'));
    body.append(el('p', cycle.top_up ? msg`自动补流量：${topUpLabel(cycle.top_up)}。本周期流量用完时从钱包扣款，补充的流量只属于本周期，重置时清零，不延长到期时间。` : translate('此套餐没有自动补流量。'), 'fine'));
    if (cycle.last_failure) body.append(el('p', msg`上次未能自动补流量：${topUpFailures[cycle.last_failure.reason] || cycle.last_failure.reason}（${timestamp(cycle.last_failure.at_ms)}）`, 'workflow-callout'));
    actions.append(item.auto_top_up ? button(translate('关闭自动补流量'), () => switchAutoTopUp(item, false), 'table-action') : button(translate('开启“用完自动补流量”'), () => switchAutoTopUp(item, true), 'primary'));
    actions.append(badge(item.auto_top_up ? translate('自动补流量已开启') : translate('自动补流量未开启'), item.auto_top_up ? 'green' : ''));
    body.append(actions); p.append(body);
  }
  if (item.state === 'awaiting_budget') {
    const note = el('div', undefined, 'panel-body'), actions = el('div', undefined, 'panel-actions');
    actions.append(button(translate('立即生效'), () => activatePlan(item.user_id), 'primary'));
    note.append(el('p', translate('已付款，但你还有运行中的转发规则，流量额度暂时不能创建。请先停用自己的规则，等服务器确认后点击“立即生效”（也会在一分钟内自动重试），然后再启用规则。'), 'workflow-callout'), actions);
    p.append(note);
  }
  return p;
}
async function renderCommerce() {
  const actor = state.actor; if (state.view !== 'commerce' || !actor) return;
  const admin = actor.role === 'system_admin';
  const entitled = featureOn('plan-entitlements');
  const [wallet, plans, orders, webhook, coupons, gifts, mine, entitlements] = await Promise.all([api('/commerce/wallet'), api('/commerce/plans'), api('/commerce/orders'), admin ? api('/commerce/webhook') : null, admin ? api('/commerce/coupons') : [], admin ? api('/commerce/gift-codes') : [], entitled ? api('/commerce/entitlement') : null, entitled && admin ? api('/commerce/entitlements') : []]);
  if (state.view !== 'commerce' || state.actor !== actor) return;
  const walletActions = el('div'); walletActions.append(button(translate('兑换礼品码'), redeemGift, 'primary'));
  if (state.actor.role === 'system_admin') walletActions.append(button(translate('调整用户钱包'), adjustWallet, 'table-action'));
  const p = panel(translate('钱包'), msg`余额 ${money(wallet.wallet.balance_cents)} · ${wallet.wallet.currency}。余额可通过管理员调整、退款或礼品码入账；购买会即时扣款。`, walletActions);
  p.append(table([translate('金额'), translate('类型'), translate('说明'), translate('引用'), translate('时间')], wallet.entries.map(entry => [money(entry.delta_cents), ledgerKinds[entry.kind] || entry.kind, entry.description, entry.reference, timestamp(entry.created_at_ms)])));
  if (!wallet.entries.length) p.append(el('p', translate('还没有资金流水。'), 'muted'));
  const plansPanel = panel(translate('套餐'), translate('价格以人民币分保存；购买订单保存套餐快照，后续改价不影响已创建订单。'), state.actor.role === 'system_admin' ? button(translate('＋ 新建套餐'), () => planForm(null), 'primary') : null);
  if (!plans.length) plansPanel.append(empty(translate('暂无可用套餐'), translate('管理员创建并启用套餐后，用户可以创建订单。')));
  else plansPanel.append(table([translate('套餐'), translate('说明'), translate('价格'), translate('时长'), translate('流量'), translate('流量重置'), translate('操作')], plans.map(plan => {
    const actions = el('div'); actions.append(button(translate('钱包购买'), () => buyPlan(plan), 'table-action'), button(translate('创建待支付订单'), () => createPendingOrder(plan), 'table-action'));
    if (state.actor.role === 'system_admin') actions.append(button(translate('编辑'), () => planForm(plan), 'table-action'), button(translate('删除'), () => deletePlan(plan), 'table-action danger'));
    return [namedCell(plan.name, plan.id), plan.description || '—', money(plan.price_cents), msg`${plan.duration_days} 天`, plan.traffic_bytes ? bytes(plan.traffic_bytes) : translate('不限'), planCycleCell(plan), actions];
  })));
  const ordersPanel = panel(translate('订单'), entitled ? translate('支付成功的订单会自动把套餐的流量和天数加到购买者的流量额度；退款会扣回该订单的流量和天数，已用的流量不退回。') : translate('订单只记录计费结果。系统管理员在「可选功能」中开启“套餐权益”后，支付成功的订单会自动发放套餐的流量和天数。'), null);
  if (!orders.length) ordersPanel.append(empty(translate('还没有订单'), translate('选择套餐购买后会生成订单。')));
  else ordersPanel.append(table([translate('套餐'), translate('类型'), translate('金额'), translate('状态'), translate('通道'), translate('创建'), translate('支付/退款'), translate('操作')], orders.map(order => {
    const actions = el('div');
    if (order.status === 'pending') actions.append(button(translate('钱包支付'), async () => { await api(`/commerce/orders/${order.id}/pay`, { method: 'POST' }); notify(translate('订单已支付。')); await renderCommerce(); }, 'table-action'), button(translate('外部支付'), () => externalPayment(order), 'table-action'));
    if (order.status === 'paid' && order.channel === 'wallet' && order.kind !== 'top_up' && state.actor.role === 'system_admin') actions.append(button(translate('退款'), async () => { if (!await confirmAction(msg`退款 ${money(order.amount_cents)} 到用户钱包？`)) return; await api(`/commerce/orders/${order.id}/refund`, { method: 'POST' }); notify(translate('订单已退款。')); await renderCommerce(); }, 'table-action danger'));
    const kind = order.kind === 'top_up' ? msg`补流量 ${bytes(order.traffic_bytes)}` : orderKinds[order.kind] || orderKinds.plan;
    return [order.plan_name, kind, money(order.amount_cents), badge(orderStatuses[order.status] || order.status, order.status === 'paid' ? 'green' : order.status === 'refunded' ? 'orange' : ''), orderChannels[order.channel] || order.channel || translate('钱包'), timestamp(order.created_at_ms), order.paid_at_ms ? timestamp(order.paid_at_ms) : order.refunded_at_ms ? timestamp(order.refunded_at_ms) : '—', actions];
  })));
  const panels = [p, ...(entitled ? [myPlanPanel(mine)] : []), plansPanel, ordersPanel];
  if (entitled && admin) {
    const e = panel(translate('套餐权益'), translate('每位购买者一行。等待额度表示已付款，但购买者仍有运行中的规则，暂停规则后会在一分钟内自动生效。'));
    if (!entitlements.length) e.append(empty(translate('还没有套餐权益'), translate('开启后支付成功的订单会出现在这里。')));
    else e.append(table([translate('用户'), translate('状态'), translate('到期'), translate('已用 / 额度'), translate('本周期'), translate('订单'), translate('操作')], entitlements.map(item => {
      const actions = el('div'), cycle = item.current_cycle; if (item.state === 'awaiting_budget') actions.append(button(translate('立即生效'), () => activatePlan(item.user_id), 'table-action'));
      if (cycle) actions.append(button(translate('立即重置流量'), () => resetTraffic(item), 'table-action danger'), button(item.auto_top_up ? translate('关闭补流量') : translate('开启补流量'), () => switchAutoTopUp(item, !item.auto_top_up), 'table-action'));
      const usage = cycle ? meter(cycle.allowance_bytes ? (cycle.used_bytes + cycle.reserved_bytes) / Math.max(1, cycle.allowance_bytes) : 0, `${bytes(cycle.used_bytes)} / ${cycle.allowance_bytes === null ? translate('不限') : bytes(cycle.allowance_bytes)}`) : planUsage(item.budget);
      const period = cycle ? namedCell(`${day(cycle.started_at_ms)} – ${day(cycle.ends_at_ms)}`, cycle.next_reset_at_ms ? msg`下次重置 ${day(cycle.next_reset_at_ms)}` : translate('到期前不再重置')) : '—';
      if (cycle) period.append(el('div', item.auto_top_up ? translate('自动补流量已开启') : translate('自动补流量未开启'), 'subline'), el('div', msg`本周期补流量 ${topUpCount(cycle)}`, 'subline'));
      if (cycle?.last_failure) period.append(el('div', topUpFailures[cycle.last_failure.reason] || cycle.last_failure.reason, 'subline'));
      return [namedCell(item.username || item.user_id, item.user_id), entitlementBadge(item.state), timestamp(item.expires_at_ms), usage, period, String(item.grants.filter(g => !g.revoked_at_ms).length), actions];
    })));
    panels.push(e);
  }
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
  const reset = plan?.traffic_reset, every = reset?.every_days;
  select(grid, 'reset', translate('流量重置'), [['none', translate('不重置（流量用到到期）')], ['billing', translate('跟随计费周期')], ['every_days', translate('每 N 天重置')]], every ? 'every_days' : reset === 'billing' ? 'billing' : 'none');
  const interval = field(grid, 'reset_days', translate('重置间隔 / 天（1..366）'), every ?? '', 'number', false); interval.min = 1; interval.max = 366;
  field(grid, 'top_up_bytes', translate('自动补流量：每次 / bytes（留空不提供）'), plan?.top_up?.bytes ?? '', 'number', false).min = 1;
  const topUpPrice = field(grid, 'top_up_price', translate('每次补流量价格（元）'), plan?.top_up ? (plan.top_up.price_cents / 100).toFixed(2) : '', 'number', false); topUpPrice.min = 0; topUpPrice.step = '0.01';
  const topUpMax = field(grid, 'top_up_max', translate('每周期最多补流量次数（1..1000）'), plan?.top_up?.max_per_cycle ?? '', 'number', false); topUpMax.min = 1; topUpMax.max = 1000;
  form.append(grid, el('p', translate('价格转换为人民币分保存；已有订单使用创建时快照。'), 'fine'), el('p', translate('需要开启“套餐权益”。重置时本周期流量重新从套餐流量开始，未用完的不结转；跟随计费周期在每个已付费周期结束时重置。自动补流量需要设置流量和重置方式，用户开启后，本周期流量用完时从钱包扣款补充；补充的流量在下次重置时清零，不延长到期时间。'), 'fine'));
  submit(form, plan ? translate('保存套餐') : translate('创建套餐'), async data => {
    const body = { name: String(data.get('name')).trim(), description: String(data.get('description')), price_cents: Math.round(Number(data.get('price')) * 100), duration_days: number(data, 'days'), traffic_bytes: number(data, 'traffic'), enabled: data.get('enabled') === 'yes', traffic_reset: 'none', top_up: null };
    if (!Number.isSafeInteger(body.price_cents) || body.price_cents < 0) throw new Error(translate('价格无效'));
    const policy = String(data.get('reset')), days = number(data, 'reset_days');
    if (policy === 'every_days') { if (!(days >= 1 && days <= 366)) throw new Error(translate('重置间隔须为 1..366 天')); body.traffic_reset = { every_days: days }; } else if (policy === 'billing') body.traffic_reset = 'billing';
    const topUpBytes = number(data, 'top_up_bytes');
    if (topUpBytes !== null) {
      if (body.traffic_reset === 'none' || body.traffic_bytes === null) throw new Error(translate('自动补流量需要设置流量和流量重置方式'));
      const price = Math.round(Number(data.get('top_up_price')) * 100), max = number(data, 'top_up_max');
      if (!(topUpBytes > 0) || String(data.get('top_up_price') ?? '').trim() === '' || !Number.isSafeInteger(price) || price < 0) throw new Error(translate('请填写有效的补流量大小和价格'));
      if (!(max >= 1 && max <= 1000)) throw new Error(translate('每周期最多补流量次数须为 1..1000'));
      body.top_up = { bytes: topUpBytes, price_cents: price, max_per_cycle: max };
    }
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
  const actor = state.actor; if (state.view !== 'announcements' || !actor) return;
  const canManage = actor.role !== 'viewer';
  const [active, managed] = await Promise.all([api('/announcements'), canManage ? api('/announcements/manage') : []]);
  if (state.view !== 'announcements' || state.actor !== actor) return;
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
  const actor = state.actor; if (state.view !== 'dns' || !actor) return;
  if (actor.role !== 'system_admin') { $('#content').replaceChildren(empty(translate('仅系统管理员可见'), translate('DNS 服务商令牌可修改外部 DNS，因此只向系统管理员开放。'))); return; }
  const [providers, zones, nodes] = await Promise.all([api('/dns/providers'), api('/dns/zones'), api('/nodes')]);
  if (state.view !== 'dns' || state.actor !== actor) return;
  const providerNames = Object.fromEntries(providers.map(p => [p.id, p.name]));
  const p = panel(translate('DNS 服务商'), translate('保存 Cloudflare 兼容 API 的地址和令牌。令牌可逆保存以调用服务商，接口只显示是否已设置；仅系统管理员可读写。'), button(translate('＋ 新增服务商'), () => dnsProviderForm(null), 'primary'));
  if (!providers.length) p.append(empty(translate('还没有 DNS 服务商'), translate('先添加服务商，再创建区域和托管记录。')));
  else p.append(table([translate('名称'), translate('类型'), translate('API 地址'), translate('令牌'), translate('最低 TTL'), translate('操作')], providers.map(provider => {
    const actions = el('div'); actions.append(button(translate('测试'), () => testDnsProvider(provider), 'table-action'), button(translate('编辑'), () => dnsProviderForm(provider), 'table-action'), button(translate('删除'), () => deleteDnsProvider(provider), 'table-action danger'));
    return [namedCell(provider.name, provider.id), provider.kind, provider.endpoint, provider.token_set ? badge(translate('已设置'), 'green') : badge(translate('未设置'), 'red'), provider.min_ttl ? msg`${provider.min_ttl} 秒` : '—', actions];
  })));
  const now = Date.now();
  const z = panel(translate('DNS 区域'), translate('区域名是服务商的 zone 名称或 ID。控制器每 30 秒自动检查每个区域：应用模式写入差异，观察模式只记录结果、不写服务商。应用模式只管理由本平台创建、带 relay 标记的记录。'), providers.length ? button(translate('＋ 新增区域'), () => dnsZoneForm(null, providers), 'primary') : null);
  if (!zones.length) z.append(empty(translate('还没有 DNS 区域'), translate('添加区域后可以创建 A/AAAA/CNAME 托管记录并执行一次同步。')));
  else z.append(table([translate('区域'), translate('服务商'), translate('模式'), translate('最少保留'), translate('确认窗口'), translate('自动检查'), translate('操作')], zones.map(zone => {
    const actions = el('div');
    actions.append(button(translate('记录'), async () => { state.dnsZone = zone.id; await renderDns(); }, 'table-action'));
    actions.append(button(translate('立即同步'), () => reconcileDns(zone), 'table-action'));
    actions.append(button(translate('编辑'), () => dnsZoneForm(zone, providers), 'table-action'), button(translate('删除'), () => deleteDnsZone(zone), 'table-action danger'));
    return [namedCell(zone.name, zone.id), providerNames[zone.provider_id] || zone.provider_id, dnsModes[zone.mode] || zone.mode, zone.min_keep, msg`${zone.failover_confirm_secs ?? 0} 秒`, dnsZoneStatus(zone, now), actions];
  })));
  const pool = featureOn('dns-authoritative') ? await authoritativePanels(nodes) : [];
  if (state.view !== 'dns' || state.actor !== actor) return;
  const selected = zones.find(zone => zone.id === state.dnsZone) || zones[0];
  if (selected) {
    state.dnsZone = selected.id;
    const records = await api(`/dns/zones/${selected.id}/records`);
    if (state.view !== 'dns' || state.actor !== actor || state.dnsZone !== selected.id) return;
    const r = panel(msg`托管记录 · ${selected.name}`, translate('每条记录带 relay 标记。删除记录时应用模式会同时删除服务商记录；观察模式只删除本地记录。健康摘除只在节点心跳新鲜且至少一个目标健康时保留记录。'), button(translate('＋ 新增记录'), () => dnsRecordForm(selected, null, nodes), 'primary'));
    if (!records.length) r.append(empty(translate('还没有托管记录'), translate('创建 A/AAAA/CNAME 记录，然后执行“立即同步”。')));
    else r.append(table([translate('名称'), translate('类型'), translate('内容'), 'TTL', translate('状态'), translate('健康摘除'), translate('服务商记录'), translate('操作')], records.map(record => {
      const actions = el('div');
      actions.append(button(translate('编辑'), () => dnsRecordForm(selected, record, nodes), 'table-action'));
      if (record.type === 'A' || record.type === 'AAAA') actions.append(button('DDNS', () => ddnsRecord(record), 'table-action'));
      actions.append(button(record.enabled ? translate('停用') : translate('启用'), async () => { await api(`/dns/records/${record.id}`, { method: 'PUT', body: { enabled: !record.enabled } }); await renderDns(); }, 'table-action'));
      actions.append(button(translate('删除'), () => deleteDnsRecord(record), 'table-action danger'));
      const published = record.status?.published_ttl, ttl = published && published !== record.ttl ? namedCell(String(record.ttl), msg`按服务商最低 ${published} 发布`) : record.ttl;
      return [namedCell(record.name, record.id), record.type, record.content, ttl, dnsRecordStatus(record, selected, now), record.health ? `${record.health.node_id} / ${record.health.rule_id}` : '—', record.provider_record_id || '—', actions];
    })));
    if (records.some(record => record.last_error)) r.append(el('p', records.filter(record => record.last_error).map(record => `${record.name}: ${record.last_error}`).join('；'), 'error-text'));
    $('#content').replaceChildren(p, z, r, ...pool);
  } else {
    $('#content').replaceChildren(p, z, ...pool);
  }
}
const dnsRecordStates = localize({ published: '已发布', pending_remove: '等待确认摘除', pending_restore: '等待确认重建', removed: '已摘除', disabled: '已停用', held_min_keep: '最少保留，暂不删除', held_guard: '过半同时失败，暂停摘除', would_create: '将创建', would_update: '将更新', would_remove: '将摘除', error: '错误' });
const dnsRecordStateColors = { published: 'green', pending_remove: 'orange', pending_restore: 'orange', removed: 'red', held_min_keep: 'orange', held_guard: 'orange', would_create: 'orange', would_update: 'orange', would_remove: 'orange', error: 'red' };
// Last evaluation of a zone by this controller process (not kept across restarts).
function dnsZoneStatus(zone, now) {
  const status = zone.status || {}, cell = el('div');
  const last = el('div', status.last_automatic_ms ? ago(status.last_automatic_ms, now) : translate('等待首次自动检查'));
  if (status.last_automatic_ms) last.title = timestamp(status.last_automatic_ms);
  cell.append(last);
  if (status.last_error) cell.append(el('div', status.last_error, 'subline error-text'));
  if (status.guarded?.length) cell.append(el('div', msg`过半同时失败，暂停摘除：${status.guarded.join(', ')}`, 'subline'));
  return cell;
}
// Why a record is (not) published, from the zone's last evaluation.
function dnsRecordStatus(record, zone, now) {
  const status = record.status, cell = el('div');
  if (!status) {
    cell.append(record.last_error ? badge(translate('错误'), 'red') : record.enabled ? badge(translate('启用'), 'green') : badge(translate('停用'), ''), el('div', translate('尚未检查'), 'subline'));
    return cell;
  }
  cell.append(badge(dnsRecordStates[status.state] || status.state, dnsRecordStateColors[status.state] || ''));
  const streak = status.since_ms ? Math.max(0, Math.round((now - status.since_ms) / 1000)) : 0, confirm = zone.failover_confirm_secs ?? 0;
  const reason = {
    pending_remove: msg`健康检查已连续失败 ${streak} 秒，满 ${confirm} 秒后摘除`,
    pending_restore: msg`健康检查已连续通过 ${streak} 秒，满 ${confirm} 秒后重建`,
    removed: translate('健康检查未通过，不在 DNS 中；持续健康满确认时间后自动重建'),
    held_min_keep: translate('剩余有效记录会少于“最少保留”，暂不删除'),
    held_guard: translate('同名记录过半同时失败，更可能是监控或控制链路问题，暂停摘除'),
  }[status.state];
  const checked = msg`检查于 ${ago(status.evaluated_at_ms, now)}`;
  cell.append(el('div', reason ? `${reason} · ${checked}` : checked, reason ? 'subline wrap' : 'subline'));
  return cell;
}
async function testDnsProvider(provider) {
  const result = await api(`/dns/providers/${provider.id}/test`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', result.zones.length ? msg`连接正常，令牌可以看到 ${result.zones.length} 个区域。` : translate('连接正常，但令牌看不到任何区域；请检查令牌的区域权限。')));
  if (result.truncated) body.append(el('p', translate('区域较多，只列出前 1000 个。'), 'fine'));
  if (result.zones.length) body.append(table([translate('区域'), 'ID'], result.zones.map(zone => [zone.name, zone.id])));
  modal(msg`连接测试 · ${provider.name}`, body);
}
const poolStates = localize({ serving: '正在应答', updating: '更新中', waiting: '等待节点报告', error: '监听失败', offline: '节点离线' });
const poolStateColors = { serving: 'green', updating: 'orange', error: 'red', offline: 'red' };
// The authoritative DNS pool: zones answered by the panel's own nodes.
async function authoritativePanels(nodes) {
  const pool = await api('/dns/authoritative');
  const head = panel(translate('独立权威 DNS 池'), translate('由你自己的节点直接应答 DNS 查询。在域名注册商把子域名（或整个域名）委派给下面的名称服务器后，解析结果随节点健康实时变化，不依赖 DNS 服务商 API。'), button(translate('＋ 新增权威区域'), () => authoritativeZoneForm(null), 'primary'));
  if (!pool.zones.length) { head.append(empty(translate('还没有权威区域'), translate('添加区域，再指定由哪些节点应答、需要哪些记录。'))); return [head]; }
  return [head, ...pool.zones.map(zone => {
    const actions = el('div', undefined, 'panel-actions');
    actions.append(button(translate('＋ 名称服务器'), () => authoritativeMemberForm(zone, null, nodes), 'primary'), button(translate('＋ 记录'), () => authoritativeRecordForm(zone, null, nodes)), button(translate('编辑'), () => authoritativeZoneForm(zone)), button(translate('删除'), () => deleteAuthoritative(msg`删除权威区域「${zone.name}」及其全部名称服务器和记录？节点会停止应答这个区域。`, `/dns/authoritative/zones/${zone.id}`, translate('权威区域已删除。')), 'subtle danger'));
    const z = panel(msg`权威区域 · ${zone.name}`, msg`序列号 ${zone.serial} · TTL ${zone.ttl} 秒 · 否定缓存 ${zone.negative_ttl} 秒 · 每条记录最少保留 ${zone.min_keep} 个值`, actions), body = el('div', undefined, 'panel-body');
    body.append(el('h3', translate('本区域的名称服务器')));
    if (!zone.members.length) body.append(el('p', translate('至少添加两台位于不同服务器的名称服务器，再到注册商委派。'), 'muted'));
    else body.append(table([translate('名称服务器'), translate('节点'), translate('监听地址'), translate('对外地址'), translate('状态'), translate('查询'), translate('操作')], zone.members.map(member => {
      const buttons = el('div');
      buttons.append(button(translate('编辑'), () => authoritativeMemberForm(zone, member, nodes), 'table-action'), button(translate('移除'), () => deleteAuthoritative(msg`移除名称服务器「${member.nameserver}」？该节点会停止应答这个区域。`, `/dns/authoritative/members/${member.id}`, translate('名称服务器已移除。')), 'table-action danger'));
      return [namedCell(member.nameserver, member.label), member.node_name, member.listen.map(ip => member.port === 53 ? ip : `${ip} · ${member.port}`).join('\n'), member.advertise, badge(poolStates[member.state] || member.state, poolStateColors[member.state] || ''), member.report ? String(member.report.queries) : '—', buttons];
    })));
    const errors = zone.members.flatMap(member => (member.report?.errors || []).map(error => `${member.nameserver}: ${error}`));
    if (errors.length) body.append(el('p', errors.join('\n'), 'error-text'));
    body.append(el('h3', translate('本区域的记录')));
    if (!zone.records.length) body.append(el('p', translate('添加 A、AAAA、CNAME 或 TXT 记录。'), 'muted'));
    else body.append(table([translate('名称'), translate('类型'), 'TTL', translate('配置的值'), translate('当前应答'), translate('操作')], zone.records.map(record => {
      const buttons = el('div');
      buttons.append(button(translate('编辑'), () => authoritativeRecordForm(zone, record, nodes), 'table-action'), button(translate('删除'), () => deleteAuthoritative(msg`删除记录「${record.name}」？`, `/dns/authoritative/records/${record.id}`, translate('记录已删除。')), 'table-action danger'));
      const values = el('div');
      record.values.forEach((value, i) => { const line = el('div', value.content); if (record.healthy[i] !== null) line.append(' ', badge(record.healthy[i] ? translate('健康') : translate('不健康'), record.healthy[i] ? 'green' : 'red')); values.append(line); });
      return [record.name, record.type, record.ttl ?? zone.ttl, values, record.served.length ? record.served.join('\n') : translate('— 不应答'), buttons];
    })));
    if (zone.members.length) {
      const lines = zone.members.map(member => `${zone.name}.  NS  ${member.nameserver}.`).concat(zone.members.map(member => `${member.nameserver}.  ${member.advertise.includes(':') ? 'AAAA' : 'A'}  ${member.advertise}`));
      body.append(el('h3', translate('在注册商设置委派')), el('p', translate('子域名：在上级域名的 DNS 里添加下面的 NS 记录和地址（glue）记录。整个域名：在注册商创建同名的“子名称服务器”（host 记录），再把域名的名称服务器改成它们。该区域不支持 DNSSEC，上级不能有它的 DS 记录。'), 'fine'), el('pre', lines.join('\n'), 'secret-box mono'), el('p', msg`委派前先确认每台名称服务器都在应答：dig @${zone.members[0].advertise} ${zone.name} SOA +norec`, 'fine'));
    }
    z.append(body);
    return z;
  })];
}
async function deleteAuthoritative(question, path, done) {
  if (!await confirmAction(question)) return;
  await api(path, { method: 'DELETE' }); notify(done); await renderDns();
}
function authoritativeZoneForm(zone) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('区域名称（例如 edge.example.com）'), zone?.name || '').maxLength = 253;
  field(grid, 'hostmaster', translate('管理员邮箱（SOA，留空使用 hostmaster@区域）'), zone?.hostmaster || '', 'email', false).maxLength = 253;
  const ttl = field(grid, 'ttl', translate('TTL（秒）'), zone?.ttl ?? 60, 'number'); ttl.min = 30; ttl.max = 86400;
  const negative = field(grid, 'negative_ttl', translate('否定缓存 TTL（秒）'), zone?.negative_ttl ?? 60, 'number'); negative.min = 30; negative.max = 86400;
  const keep = field(grid, 'min_keep', translate('每条记录最少保留的值'), zone?.min_keep ?? 1, 'number'); keep.min = 0; keep.max = 16;
  form.append(grid, el('p', translate('健康检查失败的值会从应答中移除，但每条记录至少保留这里设置的数量（按填写顺序补回）。设为 0 时记录可以完全不应答。TTL 越短，切换越快。'), 'fine'));
  submit(form, zone ? translate('保存区域') : translate('添加区域'), async data => {
    const body = { name: String(data.get('name')).trim(), ttl: number(data, 'ttl'), negative_ttl: number(data, 'negative_ttl'), min_keep: number(data, 'min_keep') };
    if (String(data.get('hostmaster')).trim()) body.hostmaster = String(data.get('hostmaster')).trim();
    if (zone) await api(`/dns/authoritative/zones/${zone.id}`, { method: 'PUT', body });
    else await api('/dns/authoritative/zones', { method: 'POST', body });
    $('#dialog').close(); notify(translate('权威区域已保存。')); await renderDns();
  });
  modal(zone ? msg`编辑权威区域 · ${zone.name}` : translate('新增权威区域'), form);
}
function authoritativeMemberForm(zone, member, nodes) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  select(grid, 'node_id', translate('节点'), nodes.map(node => [node.id, node.name]), member?.node_id || nodes[0]?.id || '');
  field(grid, 'label', translate('名称服务器标签（留空自动 ns1、ns2…）'), member?.label || '', 'text', false).maxLength = 63;
  const port = field(grid, 'port', translate('端口'), member?.port ?? 53, 'number'); port.min = 1; port.max = 65535;
  field(grid, 'advertise', translate('对外公布的地址（留空使用第一个监听地址）'), member && member.advertise !== member.listen[0] ? member.advertise : '', 'text', false).maxLength = 45;
  form.append(grid);
  textarea(form, 'listen', translate('监听地址（每行一个，最多 4 个）'), (member?.listen || []).join('\n'), true).rows = 3;
  form.append(el('p', translate('监听地址必须是该节点上的具体 IP，不能是 0.0.0.0。节点在云服务商 NAT 后面时，监听内网地址，对外地址填公网 IP。端口 53 需要先在服务器安装授权文件 relay-agent-dns.conf，并在防火墙放行 UDP 和 TCP 53。'), 'fine'));
  submit(form, member ? translate('保存名称服务器') : translate('添加名称服务器'), async data => {
    const body = { node_id: data.get('node_id'), listen: String(data.get('listen')).split(/[\s,]+/).filter(Boolean), port: number(data, 'port') };
    if (String(data.get('label')).trim()) body.label = String(data.get('label')).trim();
    if (String(data.get('advertise')).trim()) body.advertise = String(data.get('advertise')).trim();
    if (member) await api(`/dns/authoritative/members/${member.id}`, { method: 'PUT', body });
    else await api(`/dns/authoritative/zones/${zone.id}/members`, { method: 'POST', body });
    $('#dialog').close(); notify(translate('名称服务器已保存。')); await renderDns();
  });
  modal(member ? msg`编辑名称服务器 · ${member.nameserver}` : msg`添加名称服务器 · ${zone.name}`, form);
}
function authoritativeRecordForm(zone, record, nodes) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('记录名称（@ 表示区域本身）'), record?.name || '').maxLength = 200;
  select(grid, 'type', translate('类型'), ['A', 'AAAA', 'CNAME', 'TXT'].map(type => [type, type]), record?.type || 'A');
  const ttl = field(grid, 'ttl', translate('TTL（秒，留空使用区域 TTL）'), record?.ttl ?? '', 'number', false); ttl.min = 30; ttl.max = 86400;
  const rows = el('div');
  const addRow = value => {
    const row = el('div', undefined, 'value-row');
    field(row, 'value', translate('值'), value?.content || '').maxLength = 255;
    select(row, 'health_node', translate('健康检查节点'), [['', translate('不检查')], ...nodes.map(node => [node.id, node.name])], value?.health?.node_id || '');
    field(row, 'health_rule', translate('规则 ID'), value?.health?.rule_id || '', 'text', false).maxLength = 128;
    row.append(button(translate('移除'), () => { if (rows.children.length > 1) row.remove(); }, 'table-action danger'));
    rows.append(row);
  };
  (record?.values?.length ? record.values : [null]).forEach(addRow);
  form.append(grid, rows, button(translate('＋ 添加值'), () => addRow(null)), el('p', translate('每个值可以跟随一条节点规则的健康状态：节点超过 90 秒没有报告，或该规则没有健康目标时，这个值暂时不出现在应答里。CNAME 只能有一个值，且不能与其他记录同名。'), 'fine'));
  submit(form, record ? translate('保存记录') : translate('添加记录'), async data => {
    const nodesSel = data.getAll('health_node'), rules = data.getAll('health_rule');
    const values = data.getAll('value').map((content, i) => { const value = { content: String(content).trim() }; if (nodesSel[i] && String(rules[i]).trim()) value.health = { node_id: nodesSel[i], rule_id: String(rules[i]).trim() }; return value; }).filter(value => value.content);
    const body = { name: String(data.get('name')).trim(), type: data.get('type'), ttl: number(data, 'ttl'), values };
    if (record) await api(`/dns/authoritative/records/${record.id}`, { method: 'PUT', body });
    else await api(`/dns/authoritative/zones/${zone.id}/records`, { method: 'POST', body });
    $('#dialog').close(); notify(translate('权威记录已保存。')); await renderDns();
  });
  modal(record ? msg`编辑权威记录 · ${record.name}` : msg`添加记录 · ${zone.name}`, form);
}
function dnsProviderForm(provider) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('名称'), provider?.name || '').maxLength = 120;
  select(grid, 'kind', translate('服务商类型'), [['cloudflare', translate('Cloudflare 兼容 API')]], provider?.kind || 'cloudflare');
  field(grid, 'endpoint', translate('API 基础地址'), provider?.endpoint || 'https://api.cloudflare.com/client/v4').maxLength = 500;
  const token = field(grid, 'token', provider ? translate('令牌（留空保留原值）') : translate('API 令牌'), '', 'password', false); token.maxLength = 4096;
  const minTtl = field(grid, 'min_ttl', translate('最低 TTL（秒，可选）'), provider?.min_ttl ?? '', 'number', false); minTtl.min = 0; minTtl.max = 86400;
  form.append(grid, el('p', translate('令牌只应授予 DNS 编辑权限；接口不会返回令牌原文。HTTP 只允许回环地址用于本机测试。'), 'fine'), el('p', translate('最低 TTL：TTL 低于它的记录按最低值发布（例如 Cloudflare 免费套餐为 60 秒）。TTL 1 表示由 Cloudflare 自动决定，不受影响；留空表示不限制。'), 'fine'));
  submit(form, provider ? translate('保存服务商') : translate('添加服务商'), async data => {
    const body = { name: String(data.get('name')).trim(), kind: data.get('kind'), endpoint: String(data.get('endpoint')).trim() };
    const min = number(data, 'min_ttl');
    if (min !== null) body.min_ttl = min; else if (provider?.min_ttl) body.min_ttl = 0;
    if (String(data.get('token') || '')) body.token = String(data.get('token'));
    if (provider) await api(`/dns/providers/${provider.id}`, { method: 'PUT', body });
    else await api('/dns/providers', { method: 'POST', body });
    $('#dialog').close(); notify(translate('DNS 服务商已保存。')); await renderDns();
  });
  modal(provider ? msg`编辑 DNS 服务商 · ${provider.name}` : translate('新增 DNS 服务商'), form);
}
function dnsZoneForm(zone, providers) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  const name = field(grid, 'name', translate('区域名称 / ID'), zone?.name || ''); name.maxLength = 253;
  const providerSelect = select(grid, 'provider_id', translate('服务商'), providers.map(provider => [provider.id, provider.name]), zone?.provider_id || providers[0]?.id || '');
  // Optional picker: list the zones the provider token can see; manual entry stays possible.
  const picker = el('div'), pickNote = el('p', translate('可以手动填写，也可以读取服务商的区域列表后选择；Cloudflare 的 API 需要区域 ID。'), 'fine');
  const resetPicker = () => picker.replaceChildren(button(translate('读取服务商区域'), async () => {
    const result = await api(`/dns/providers/${providerSelect.value}/test`, { method: 'POST' });
    if (!result.zones.length) { pickNote.textContent = translate('令牌看不到任何区域，请手动填写。'); return; }
    const label = el('label', translate('从服务商区域选择')), choice = el('select');
    for (const [value, text] of [['', translate('手动填写')], ...result.zones.map(item => [item.id, `${item.name} · ${item.id}`])]) { const option = el('option', text); option.value = value; choice.append(option); }
    choice.value = result.zones.find(item => item.id === name.value || item.name === name.value)?.id || '';
    choice.addEventListener('change', () => { if (choice.value) name.value = choice.value; });
    label.append(choice); picker.replaceChildren(label);
    pickNote.textContent = msg`令牌可以看到 ${result.zones.length} 个区域；选择后填入区域 ID。`;
  }));
  resetPicker(); providerSelect.addEventListener('change', resetPicker); grid.append(picker);
  select(grid, 'mode', translate('模式'), Object.entries(dnsModes), zone?.mode || 'observe');
  const keep = field(grid, 'min_keep', translate('最少保留记录数'), zone?.min_keep ?? 1, 'number'); keep.min = 0; keep.max = 1000;
  const confirm = field(grid, 'failover_confirm_secs', translate('健康摘除确认时间（秒）'), zone?.failover_confirm_secs ?? 60, 'number'); confirm.min = 0; confirm.max = 1800;
  form.append(grid, pickNote, el('p', translate('观察模式适合先核对现有记录。应用模式只创建/更新/删除本平台带 relay 标记的记录，不会接管同名的外部记录。'), 'fine'), el('p', translate('确认时间：带健康摘除的记录要连续失败这么久才摘除，连续健康这么久才重建（0 表示下一次检查就执行，最长 1800 秒）。同名记录过半同时失败时暂停摘除。'), 'fine'));
  submit(form, zone ? translate('保存区域') : translate('添加区域'), async data => {
    const body = { name: String(data.get('name')).trim(), provider_id: data.get('provider_id'), mode: data.get('mode'), min_keep: number(data, 'min_keep'), failover_confirm_secs: number(data, 'failover_confirm_secs') };
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
  const gating = featureOn('dns-health') || !!record?.health;
  if (gating) {
    select(grid, 'health_node', translate('入口健康摘除节点'), [['', translate('不启用')], ...nodes.map(node => [node.id, node.name])], record?.health?.node_id || '');
    field(grid, 'health_rule', translate('健康摘除规则 ID（可选）'), record?.health?.rule_id || '').maxLength = 128;
    if (record?.health) select(grid, 'health_clear', translate('健康摘除设置'), [['no', translate('保留现有设置')], ['yes', translate('清除健康摘除')]], 'no');
  }
  form.append(grid, el('p', gating ? translate('应用模式同步后会写入服务商；观察模式只显示“将创建/将更新”。CNAME 内容必须是主机名，A/AAAA 内容必须是 IP。填写节点和规则 ID 后，节点心跳超过 90 秒或没有健康目标、并且持续达到区域的确认时间时，应用模式会自动摘除该记录；持续健康达到确认时间后自动重建。控制器每 30 秒检查一次，同名记录过半同时失败或不足“最少保留”时暂不摘除。') : translate('应用模式同步后会写入服务商；观察模式只显示“将创建/将更新”。CNAME 内容必须是主机名，A/AAAA 内容必须是 IP。需要按入口健康自动摘除记录时，请系统管理员在「可选功能」中开启 DNS 健康摘除。'), 'fine'));
  submit(form, record ? translate('保存记录') : translate('添加记录'), async data => {
    const body = { name: String(data.get('name')).trim(), type: data.get('type'), content: String(data.get('content')).trim(), ttl: number(data, 'ttl'), proxied: data.get('proxied') === 'yes' };
    const healthNode = String(data.get('health_node') || ''), healthRule = String(data.get('health_rule') || '').trim();
    if (data.get('health_clear') === 'yes') body.clear_health = true;
    else if (healthNode && healthRule) body.health = { node_id: healthNode, rule_id: healthRule };
    if (record) await api(`/dns/records/${record.id}`, { method: 'PUT', body });
    else await api(`/dns/zones/${zone.id}/records`, { method: 'POST', body });
    $('#dialog').close(); notify(zone.mode === 'apply' ? translate('DNS 记录已保存；控制器每 30 秒自动同步应用模式区域，也可以点“立即同步”。') : translate('DNS 记录已保存；观察模式只报告差异，不写服务商。')); await renderDns();
  });
  modal(record ? msg`编辑 DNS 记录 · ${record.name}` : translate('新增 DNS 记录'), form);
}
async function reconcileDns(zone) {
  const result = await api(`/dns/zones/${zone.id}/reconcile`, { method: 'POST' });
  const body = el('div');
  body.append(el('p', msg`${dnsModes[zone.mode]}：观察 ${result.observed} 条，创建 ${result.created}，更新 ${result.updated}，删除 ${result.deleted}，未变 ${result.unchanged}，保留 ${result.kept}，错误 ${result.errors}。`));
  if (result.pending || result.guarded) body.append(el('p', msg`等待确认 ${result.pending} 条，过半同时失败暂停摘除 ${result.guarded} 条。`));
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
  const actor = state.actor;
  const subscriptions = await api('/subscriptions');
  if (state.view !== 'subscriptions' || !actor || state.actor !== actor) return;
  const p = panel(translate('客户端订阅'), translate('把支持的代理规则快照成可撤销的订阅链接。链接只包含客户端连接参数，不包含控制器会话或节点凭据；创建后可编辑，链接不变；轮换时可让旧链接在宽限期内继续有效。'), canWrite() ? button(translate('＋ 新建订阅'), () => subscriptionForm(), 'primary') : null);
  if (!subscriptions.length) p.append(empty(translate('还没有订阅链接'), translate('先创建至少一条启用中的 Shadowsocks 或受管协议规则，再按客户端格式生成订阅。')));
  else p.append(table([translate('名称'), translate('格式'), translate('所有者'), translate('到期'), translate('最近使用'), translate('操作')], subscriptions.map(item => {
    const actions = el('div');
    actions.append(button(translate('预览'), () => previewSubscription(item), 'table-action'));
    if (canWrite()) {
      actions.append(button(translate('编辑'), () => subscriptionForm(item), 'table-action'));
      actions.append(button(translate('轮换链接'), () => rotateSubscription(item), 'table-action'));
      actions.append(button(translate('删除'), () => deleteSubscription(item), 'table-action danger'));
    }
    const name = namedCell(item.name, item.id);
    if (item.allow_sources?.length) name.append(el('div', msg`仅限 ${item.allow_sources.length} 个来源网段拉取`, 'subline'));
    const expiry = el('div'); expiry.append(item.expires_at_ms ? timestamp(item.expires_at_ms) : translate('不过期'));
    if (item.previous_token_expires_at_ms > Date.now()) expiry.append(el('div', msg`轮换前的旧链接有效至 ${timestamp(item.previous_token_expires_at_ms)}`, 'subline'));
    return [name, subscriptionFormats[item.format] || item.format, item.owner_id, expiry, item.last_used_ms ? msg`${timestamp(item.last_used_ms)} · ${item.uses} 次` : translate('尚未使用'), actions];
  })));
  if (state.view === 'subscriptions') $('#content').replaceChildren(p);
}
function base64Text(value) {
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '='));
  return new TextDecoder().decode(Uint8Array.from(raw, c => c.charCodeAt(0)));
}
// socks5://user:pass@host:port#name, socks://base64(user:pass)@host:port, and
// ss:// in SIP002 (percent-encoded or base64 userinfo) or legacy all-base64 form.
function parseUpstreamLink(text) {
  const match = /^(socks5h?|socks|ss):\/\/([^#]*)(?:#(.*))?$/i.exec(text.trim());
  if (!match) throw new Error(translate('只支持 socks5:// 和 ss:// 链接'));
  const type = match[1].toLowerCase() === 'ss' ? 'shadowsocks' : 'socks5';
  let body = match[2];
  const query = body.indexOf('?');
  if (query >= 0) {
    if (/(^|&)plugin=/.test(body.slice(query + 1))) throw new Error(translate('不支持带插件的 ss:// 链接'));
    body = body.slice(0, query);
  }
  body = body.replace(/\/$/, '');
  if (type === 'shadowsocks' && !body.includes('@')) body = base64Text(body);
  const at = body.lastIndexOf('@');
  const userinfo = at < 0 ? '' : body.slice(0, at);
  const address = /^(\[[^\]]+\]|[^:@]+):(\d{1,5})$/.exec(body.slice(at + 1));
  if (!address || !Number(address[2]) || Number(address[2]) > 65535) throw new Error(translate('无法识别链接中的服务器地址和端口'));
  // Split before percent-decoding: an encoded ':' belongs to the username.
  const encoded = userinfo.includes(':'), plain = encoded || !userinfo ? userinfo : base64Text(decodeURIComponent(userinfo));
  const split = plain.indexOf(':');
  const [first, second] = (split < 0 ? [plain, ''] : [plain.slice(0, split), plain.slice(split + 1)]).map(part => encoded ? decodeURIComponent(part) : part);
  const server = address[1].replace(/^\[|\]$/g, ''), port = Number(address[2]);
  const name = (match[3] ? decodeURIComponent(match[3]).trim() : '') || `${type === 'socks5' ? 'SOCKS5' : 'SS'} ${server}`;
  if (type === 'socks5') return { name, type, server, port, username: first, password: second };
  if (!first || !second) throw new Error(translate('链接缺少 Shadowsocks 加密方式或密码'));
  if (!shadowsocksMethods.some(([id]) => id === first)) throw new Error(msg`不支持的加密方式：${first}`);
  return { name, type, server, port, method: first, password: second };
}
const MAX_UPSTREAMS = 8;
function upstreamEditor(initial = []) {
  const box = el('fieldset', undefined, 'upstream-editor');
  box.append(el('legend', translate('我的代理（可选 · 代理链）')), el('p', translate('填入你自己的 SOCKS5 或 Shadowsocks 代理。客户端会先连到中转节点，再经它连接你的代理：客户端 → 中转节点 → 你的代理 → 网站。只有 sing-box、mihomo / Clash Meta 和 Surge 格式能表达这条链；其他格式会在预览中跳过这些代理。'), 'fine'));
  const paste = el('div', undefined, 'upstream-paste');
  const link = field(paste, 'upstream_link', translate('粘贴 socks5:// 或 ss:// 链接（自动填入一行）'), '', 'text', false);
  link.autocomplete = 'off';
  const rows = [], list = el('div');
  let serial = 0;
  const addButton = button(translate('＋ 添加代理'), () => add());
  const add = (value = {}) => {
    if (rows.length >= MAX_UPSTREAMS) throw new Error(msg`最多添加 ${MAX_UPSTREAMS} 个代理`);
    const id = ++serial, row = el('div', undefined, 'upstream-row'), grid = el('div', undefined, 'form-grid');
    const name = field(grid, `upstream-name-${id}`, translate('显示名称'), value.name || ''); name.maxLength = 64;
    const type = select(grid, `upstream-type-${id}`, translate('代理类型'), [['socks5', 'SOCKS5'], ['shadowsocks', 'Shadowsocks']], value.type || 'socks5');
    const server = field(grid, `upstream-server-${id}`, translate('服务器地址（域名或 IP）'), value.server || ''); server.maxLength = 253;
    const port = field(grid, `upstream-port-${id}`, translate('端口'), value.port || '', 'number'); port.min = 1; port.max = 65535;
    const method = select(grid, `upstream-method-${id}`, translate('加密方式'), shadowsocksMethods, value.method || '2022-blake3-aes-128-gcm');
    const username = field(grid, `upstream-user-${id}`, translate('用户名（留空不认证）'), value.username || '', 'text', false); username.maxLength = 255; username.autocomplete = 'off';
    const password = field(grid, `upstream-password-${id}`, translate('密码'), value.password || '', 'password', false); password.maxLength = 255; password.autocomplete = 'new-password';
    const show = () => {
      const socks = type.value === 'socks5';
      username.closest('label').classList.toggle('hidden', !socks); username.disabled = !socks;
      method.closest('label').classList.toggle('hidden', socks); method.disabled = socks;
      password.closest('label').firstChild.nodeValue = socks ? translate('密码（与用户名同时填写）') : translate('密码');
      password.required = !socks;
    };
    type.addEventListener('change', show); show();
    const entry = { name, type, server, port, method, username, password };
    row.append(grid, button(translate('移除此代理'), () => { rows.splice(rows.indexOf(entry), 1); row.remove(); addButton.disabled = false; }, 'table-action danger'));
    rows.push(entry); list.append(row); addButton.disabled = rows.length >= MAX_UPSTREAMS;
  };
  paste.append(button(translate('导入链接'), () => { if (!link.value.trim()) return; add(parseUpstreamLink(link.value)); link.value = ''; }));
  box.append(paste, list, addButton, el('p', translate('你的代理必须能从中转节点访问；节点默认拒绝内网和回环地址。保存后可随时编辑，订阅链接不变。'), 'fine'));
  initial.forEach(value => add(value));
  const read = () => {
    const names = new Set();
    return rows.map(row => {
      const upstream = { name: row.name.value.trim(), type: row.type.value, server: row.server.value.trim().replace(/^\[|\]$/g, ''), port: Number(row.port.value) };
      if (names.has(upstream.name)) throw new Error(translate('代理名称不能重复'));
      names.add(upstream.name);
      if (upstream.type === 'shadowsocks') return { ...upstream, method: row.method.value, password: row.password.value };
      const user = row.username.value.trim(), pass = row.password.value;
      if (!!user !== !!pass) throw new Error(translate('SOCKS5 用户名和密码必须同时填写或同时留空'));
      return user ? { ...upstream, username: user, password: pass } : upstream;
    });
  };
  return { box, read };
}
// Bare addresses become single-host networks; the API takes CIDR notation.
function subscriptionSources(text) {
  return String(text || '').split(/[\s,]+/).filter(Boolean).map(value => value.includes('/') ? value : `${value}/${value.includes(':') ? 128 : 32}`);
}
// Creates a link, or edits `item` in place: the edit keeps its token.
async function subscriptionForm(item) {
  const editing = !!item, template = item?.template;
  const users = editing || state.actor.role === 'viewer' ? [] : await api('/users').catch(() => []);
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('名称（说明用途，如“手机订阅”）'), item?.name || '').maxLength = 120;
  select(grid, 'format', translate('客户端格式'), Object.entries(subscriptionFormats), item?.format || 'sing_box');
  form.append(el('p', translate('订阅按所有者和节点标签收集兼容规则，保存当前端点快照。多跳 SS 请使用「转发规则」中该路径的“客户端链接”；此处不会自动改写入口端口。'), 'workflow-callout'));
  field(grid, 'prefix', translate('客户端显示名称前缀（可选）'), template ? template.name_prefix : 'Relay ', 'text', false).maxLength = 64;
  const host = field(grid, 'host', translate('替换所有节点地址（可选，NAT / 域名场景）'), template?.host || '', 'text', false); host.maxLength = 253;
  field(grid, 'tags', translate('只包含这些节点标签（逗号分隔，留空全部）'), (template?.node_tags || []).join(', '), 'text', false);
  select(grid, 'udp', translate('在客户端启用 UDP'), [['yes', translate('启用')], ['no', translate('不启用')]], !template || template.udp ? 'yes' : 'no');
  const days = editing ? field(grid, 'days', translate('有效天数（从现在起 1–3650，留空保持当前到期时间）'), '', 'number', false) : field(grid, 'days', translate('有效天数（1–3650）'), 365, 'number'); days.min = 1; days.max = 3650;
  textarea(grid, 'allow_sources', translate('只允许这些来源拉取（IP 或 CIDR，每行一个，留空不限）'), (item?.allow_sources || []).join('\n'));
  if (!editing && state.actor.role !== 'viewer' && users.length > 1) {
    const owner = select(grid, 'user_id', translate('订阅所有者'), [['', translate('当前账号')], ...users.map(u => [u.id, `${u.username} · ${roleNames[u.role]}`])], '');
    owner.required = false;
  }
  const upstreams = upstreamEditor(template?.upstreams || []);
  form.append(grid, upstreams.box, el('p', translate('名称前缀和节点标签会作为快照保存在订阅记录中；节点后续改名不会改变已生成链接的显示名。只读账号不能创建或轮换链接。'), 'fine'), el('p', translate('来源限制按客户端实际地址判断（经本机反向代理时取 X-Forwarded-For 的最后一项）。其他来源拉取时得到与无效链接相同的响应。'), 'fine'));
  submit(form, editing ? translate('保存修改') : translate('创建订阅'), async data => {
    const chained = upstreams.read();
    const body = {
      name: String(data.get('name')).trim(),
      format: data.get('format'),
      template: {
        name_prefix: String(data.get('prefix') || ''),
        host: String(data.get('host') || '').trim() || null,
        node_tags: String(data.get('tags') || '').split(',').map(t => t.trim()).filter(Boolean),
        udp: data.get('udp') === 'yes',
        ...(chained.length ? { upstreams: chained } : {})
      },
      allow_sources: subscriptionSources(data.get('allow_sources'))
    };
    const expiresInDays = number(data, 'days');
    if (editing) {
      await api(`/subscriptions/${item.id}`, { method: 'PUT', body: { ...body, ...(expiresInDays === null ? {} : { expires_in_days: expiresInDays }) } });
      $('#dialog').close(); notify(translate('订阅已更新，链接不变。'));
      await renderSubscriptions();
      return;
    }
    const result = await api('/subscriptions', { method: 'POST', body: { ...body, expires_in_days: expiresInDays, ...(String(data.get('user_id') || '') ? { user_id: String(data.get('user_id')) } : {}) } });
    $('#dialog').close();
    showSubscriptionToken(result.subscription.name, result.token);
    await renderSubscriptions();
  });
  modal(editing ? msg`编辑订阅 · ${item.name}` : translate('新建客户端订阅'), form);
}
function showSubscriptionToken(name, token, graceUntil) {
  const body = el('div');
  const url = `${location.origin}/sub/${token}`;
  body.append(el('p', translate('订阅链接只显示这一次。任何持有链接的人都能读取节点连接参数；请像密码一样保存，泄露时立即轮换。'), 'fine'), el('div', url, 'secret-box'));
  if (graceUntil) body.append(el('p', msg`轮换前的旧链接有效至 ${timestamp(graceUntil)}，之后失效。`, 'fine'));
  const actions = el('div', undefined, 'dialog-actions');
  actions.append(button(translate('关闭对话框'), () => $('#dialog').close()), button(translate('复制链接'), async () => { await navigator.clipboard.writeText(url); notify(translate('订阅链接已复制。')); }, 'primary'));
  body.append(actions);
  modal(msg`订阅已创建 · ${name}`, body);
}
function chainedCell(name) { const n = el('div'); n.append(el('strong', name), ' ', badge(translate('代理链'), 'blue'), el('div', translate('经中转入口连接你的代理'), 'subline')); return n; }
async function previewSubscription(item) {
  const preview = await api(`/subscriptions/${item.id}/preview`);
  const body = el('div');
  if (preview.entries.length) body.append(table([translate('客户端名称'), translate('服务器'), translate('端口'), translate('加密方式')], preview.entries.map(entry => [entry.chained ? chainedCell(entry.name) : entry.name, entry.host, entry.port, entry.method])));
  else body.append(el('p', translate('没有可生成的条目，原因见下方跳过列表。'), 'muted'));
  if (preview.skipped.length) body.append(el('h3', translate('跳过规则')), table([translate('规则'), translate('原因')], preview.skipped.map(s => [namedCell(s.rule_name, s.rule_id), s.reason])));
  const details = el('details'); details.append(el('summary', translate('查看生成内容')), el('pre', preview.content, 'subscription-preview')); body.append(details);
  modal(msg`预览 · ${item.name}`, body);
}
async function rotateSubscription(item) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  form.append(el('p', msg`为「${item.name}」生成新的订阅链接。已导入的客户端需要改用新链接。`));
  const grace = field(grid, 'grace_minutes', translate('旧链接继续有效（分钟，0–1440；0 为立即失效）'), 0, 'number'); grace.min = 0; grace.max = 1440;
  form.append(grid, el('p', translate('宽限期内新旧链接都能拉取，便于逐台更换客户端。只保留本次轮换前的链接：再次轮换时，更早的链接立即失效。'), 'fine'));
  submit(form, translate('轮换链接'), async data => {
    const result = await api(`/subscriptions/${item.id}/rotate`, { method: 'POST', body: { grace_minutes: number(data, 'grace_minutes') ?? 0 } });
    $('#dialog').close();
    showSubscriptionToken(item.name, result.token, result.subscription.previous_token_expires_at_ms);
    await renderSubscriptions();
  });
  modal(translate('轮换订阅链接'), form);
}
async function deleteSubscription(item) {
  if (!await confirmAction(msg`删除订阅「${item.name}」？使用该链接的客户端将立即无法更新。`)) return;
  await api(`/subscriptions/${item.id}`, { method: 'DELETE' });
  notify(translate('订阅已删除。'));
  await renderSubscriptions();
}

async function renderUsage() {
  const actor = state.actor; const [records, nodes] = await Promise.all([api('/usage'), api('/nodes')]); const names = new Map(nodes.map(n => [n.id, n.name]));
  if (state.view !== 'usage' || !actor || state.actor !== actor) return;
  const toolbar = el('div', undefined, 'toolbar view-toolbar'); toolbar.append(displayToggle('usage', renderUsage));
  const p = panel(translate('已接纳应用负载'), translate('累计值按节点、规则与计量周期去重；发送失败也可能已经接纳计量。最多显示最近 2,000 条周期记录。'));
  if (!records.length) { p.append(empty(translate('还没有流量记录'), translate('让一条转发规则通过真实流量，Agent 会在同步后上报。'))); if (state.view === 'usage') $('#content').replaceChildren(p); return; }
  if (displayMode('usage') === 'chart') {
    const parts = [[translate('上行'), 'teal'], [translate('下行'), 'violet']];
    const totals = key => { const sums = new Map(); for (const r of records) { const k = key(r), v = sums.get(k) || [0, 0]; v[0] += r.upload_bytes; v[1] += r.download_bytes; sums.set(k, v); } return [...sums].sort((a, b) => b[1][0] + b[1][1] - a[1][0] - a[1][1]); };
    const row = (label, [up, down], detail) => ({ label, detail, values: [up, down], text: bytes(up + down), title: msg`上行 ${bytes(up)} · 下行 ${bytes(down)}` });
    const byRule = totals(r => r.rule_id), byNode = totals(r => r.node_id), byMonth = totals(r => r.meter_epoch).sort((a, b) => a[0].localeCompare(b[0]));
    const all = byNode.reduce((sum, [, [up, down]]) => sum + up + down, 0), grid = el('div', undefined, 'chart-grid');
    grid.append(chartPanel(translate('按规则'), byRule.length > 12 ? msg`流量最多的 12 条规则，共 ${byRule.length} 条。多跳转发在经过的每台服务器上各计一次。` : translate('各规则累计的上行与下行。多跳转发在经过的每台服务器上各计一次。'), barChart(byRule.slice(0, 12).map(([rule, v]) => row(rule, v)), parts)),
      chartPanel(translate('按节点'), msg`合计 ${bytes(all)}`, barChart(byNode.map(([id, v]) => row(names.get(id) || id, v, names.has(id) ? id.slice(0, 8) : '')), parts)));
    if (byMonth.length > 1) grid.append(chartPanel(translate('按计量月份'), translate('每个月的上行与下行合计。'), columnChart(byMonth.map(([month, [up, down]]) => ({ label: month, values: [up, down], title: msg`${month} · 上行 ${bytes(up)} · 下行 ${bytes(down)}` })), parts, bytes)));
    if (state.view === 'usage') { $('#page-tools').replaceChildren(...toolbar.childNodes); $('#content').replaceChildren(grid); }
    return;
  }
  p.append(table([translate('规则 / 周期'), translate('节点'), translate('上行'), translate('下行'), translate('序号'), translate('最近上报')], records.map(r => [namedCell(r.rule_id, r.meter_epoch), names.has(r.node_id) ? namedCell(names.get(r.node_id), r.node_id.slice(0, 8)) : r.node_id, bytes(r.upload_bytes), bytes(r.download_bytes), r.sequence, timestamp(r.reported_at_ms)])));
  if (state.view === 'usage') { $('#page-tools').replaceChildren(...toolbar.childNodes); $('#content').replaceChildren(p); }
}
async function renderUsers() { const actor = state.actor; const users = await api('/users'); if (state.view !== 'users' || !actor || state.actor !== actor) return; const p = panel(translate('用户与会话'), translate('权限由服务端校验；撤销、停用、改密或删除后，该用户已有的 Web 会话和 API 令牌立即失效。'), canWrite() ? button(translate('＋ 添加用户'), newUser, 'primary') : null); p.append(table([translate('账号'), translate('角色'), translate('租户'), translate('状态'), translate('两步验证'), translate('跨节点总限速'), translate('操作')], users.map(u => [namedCell(u.username, u.id), roleNames[u.role], u.tenant_id, u.disabled ? badge(translate('已停用'), 'red') : badge(translate('启用'), 'green'), u.mfa_enabled ? badge(translate('已启用'), 'green') : badge(translate('未启用')), userRateText(u) ? badge(userRateText(u), 'orange') : badge(translate('不限速')), userActions(u)]))); if (state.view === 'users') $('#content').replaceChildren(p); }
function userRateText(u) { return rateText(u.rate_bytes_per_sec, { upload_bytes_per_sec: u.upload_bytes_per_sec, download_bytes_per_sec: u.download_bytes_per_sec }, mbit); }
function userActions(u) {
  if (!canWrite() && u.id !== state.actor.id) return '—';
  const actions = el('div');
  actions.append(button(translate('撤销全部会话'), async () => { await api(`/users/${u.id}/revoke-sessions`, { method: 'POST' }); if (u.id === state.actor.id) loggedOut(); else notify(translate('该用户现有会话和 API 令牌已撤销。')); }, 'table-action'));
  if (state.actor.role === 'system_admin' || userRateText(u)) actions.append(button(translate('总限速'), () => editUserRate(u), 'table-action'));
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
  let speed = null;
  if (state.actor.role === 'system_admin') {
    speed = rateLimitEditor({ rate: view.rate_bytes_per_sec, limits: { upload_bytes_per_sec: view.upload_bytes_per_sec, download_bytes_per_sec: view.download_bytes_per_sec }, unit: 'mbit', combined: { name: 'mbit', label: translate('该用户所有节点入口规则的上下行合计 / Mbit/s（留空不限速）') }, min: 1024, max: 2 ** 40, rangeError: translate('请输入 0.009 到 8,796,093 之间的 Mbit/s') });
    form.append(speed.box, el('p', translate('控制器按各节点的实际用量动态分配份额，忙的节点多分；节点与控制器失联 15 秒后退回平均份额。与规则、节点限速同时生效，取较严者。只计入口规则；已停用或到期的节点不占份额，长期离线的节点请停用。'), 'muted'));
    form.append(el('p', translate('上传和下载总限速也各自按节点分配份额，各节点份额之和不超过总限速；需要这些节点的 Agent 支持分别限速。用户总限速不支持突发。'), 'fine'));
  }
  const shares = list => table([translate('节点'), translate('当前份额'), translate('实测'), translate('状态')], list.map(n => [namedCell(names[n.node_id] || n.node_id, n.node_id), mbit(n.share_bytes_per_sec), n.measured_bytes_per_sec == null ? '—' : mbit(n.measured_bytes_per_sec), n.seen_ms_ago == null ? badge(translate('未连接，预留平均份额'), 'red') : n.seen_ms_ago > 20000 ? badge(translate('失联，按平均份额'), 'red') : n.saturated ? badge(translate('已用满'), 'orange') : badge(translate('有余量'), 'green')]));
  const lanes = [[view.nodes || [], translate('上下行合计份额')], [view.upload_nodes || [], translate('上传份额')], [view.download_nodes || [], translate('下载份额')]].filter(([list]) => list.length);
  for (const [list, title] of lanes) { if (view.upload_nodes?.length || view.download_nodes?.length) form.append(el('h4', title)); form.append(shares(list)); }
  if (!lanes.length && userRateText(view)) form.append(el('p', translate('各节点下次同步后显示份额。'), 'muted'));
  if (speed) submit(form, translate('保存总限速'), async data => { const { rate_bytes_per_sec: rate, rate_limits } = speed.read(data); await api(`/users/${u.id}/rate`, { method: 'PUT', body: { rate_bytes_per_sec: rate, upload_bytes_per_sec: rate_limits?.upload_bytes_per_sec ?? null, download_bytes_per_sec: rate_limits?.download_bytes_per_sec ?? null } }); $('#dialog').close(); const text = rateText(rate, rate_limits, mbit); notify(text ? msg`${u.username} 的跨节点总限速为 ${text}。` : msg`已取消 ${u.username} 的跨节点总限速。`); await renderUsers(); });
  modal(msg`${u.username} 的跨节点总限速`, form);
}
async function renderAccount() {
  const actor = state.actor;
  const [factor, tokens] = await Promise.all([api('/account/mfa'), api('/api-tokens')]);
  if (state.view !== 'account' || !actor || state.actor !== actor) return;
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
  const page = el('div'); page.append(pair(password, security), keys);
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
// Live logs: the latest lines of the controller and every node, newest at the bottom. Agents send
// their lines with each report, so the page follows within one report interval.
const LOG_LEVELS = { all: ['error', 'warn', 'info', 'debug', 'trace'], warn: ['error', 'warn'], error: ['error'] };
const logSourceName = (sources, id) => id === 'controller' ? translate('控制器') : (sources || []).find(s => s.id === id)?.name || id;
async function renderLogs() {
  const actor = state.actor, view = state.logs ||= { source: '', level: 'all', query: '', paused: false, lines: [], after: 0, key: null };
  const key = view.source, fresh = view.key !== key || view.language !== getLanguage() || !view.box?.isConnected || !$('#content').contains(view.box);
  if (!fresh && view.paused) return;
  if (fresh) Object.assign(view, { lines: [], after: 0, key, language: getLanguage() });
  const data = await api(`/logs?after=${view.after}${key ? `&source=${encodeURIComponent(key)}` : ''}`);
  if (state.view !== 'logs' || state.actor !== actor || view.key !== key) return;
  // A restarted controller numbers lines from the start again.
  if (data.latest_id < view.after) { view.key = null; return renderLogs(); }
  if (data.truncated && !fresh && data.lines.length) view.lines.push({ gap: true, at_ms: data.lines[0].at_ms, id: data.lines[0].id - 0.5 });
  view.sources = data.sources; view.after = data.latest_id; view.lines.push(...data.lines); view.lines.splice(0, Math.max(0, view.lines.length - 2000));
  if (fresh) buildLogView(view); else drawLogLines(view);
}
function buildLogView(view) {
  const toolbar = el('div', undefined, 'toolbar log-toolbar'), source = el('select'), sourceLabel = el('label', translate('来源'));
  for (const [id, name] of [['', translate('全部来源')], ...view.sources.map(s => [s.id, logSourceName(view.sources, s.id)])]) { const option = el('option', name); option.value = id; source.append(option); }
  source.value = view.source; source.onchange = () => { view.source = source.value; refresh().catch(e => notify(e.message, true)); }; sourceLabel.append(source);
  const levels = el('div', undefined, 'mode-picker'); levels.setAttribute('aria-label', translate('级别'));
  for (const [value, label] of [['all', translate('全部级别')], ['warn', translate('警告和错误')], ['error', translate('仅错误')]]) {
    const choice = button(label, () => { view.level = value; [...levels.children].forEach(c => c.setAttribute('aria-pressed', String(c === choice))); drawLogLines(view, true); }); choice.setAttribute('aria-pressed', String(view.level === value)); levels.append(choice);
  }
  const search = el('input'); search.type = 'search'; search.value = view.query; search.placeholder = translate('筛选文字'); search.setAttribute('aria-label', translate('筛选文字')); search.oninput = () => { view.query = search.value; drawLogLines(view, true); };
  const pause = button('', () => { view.paused = !view.paused; showPause(); drawLogLines(view); if (!view.paused) refresh().catch(e => notify(e.message, true)); });
  const showPause = () => { pause.textContent = view.paused ? translate('继续') : translate('暂停'); pause.setAttribute('aria-pressed', String(view.paused)); }; showPause();
  const download = button(translate('下载'), () => {
    const shown = shownLogLines(view), stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const text = shown.filter(l => !l.gap).map(l => `${new Date(l.at_ms).toISOString()}  ${logSourceName(view.sources, l.source)}  ${l.level.toUpperCase()}  ${l.text}`).join('\n');
    const link = el('a'); link.href = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' })); link.download = `relay-logs-${(view.source ? logSourceName(view.sources, view.source) : 'all').replace(/[^\w.-]+/g, '_')}-${stamp}.txt`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }, 'table-action');
  toolbar.append(sourceLabel, levels, search, pause, download);
  const p = panel(translate('最近的日志'), translate('服务器的新日志随每次回报送来，约 5 秒一次；控制器的日志直接读取。每个来源保留最近 2000 行，完整记录仍在服务器的系统日志（journalctl）中。'));
  view.box = el('div', undefined, 'log-view'); view.box.setAttribute('role', 'log'); view.box.tabIndex = 0; view.foot = el('div', undefined, 'log-foot');
  p.append(view.box, view.foot);
  if (state.view === 'logs') $('#content').replaceChildren(toolbar, p);
  drawLogLines(view, true);
}
function shownLogLines(view) {
  const levels = LOG_LEVELS[view.level], query = view.query.trim().toLowerCase();
  // Servers send their lines a few seconds late, so lines are shown in the order they were logged.
  return view.lines.filter(l => l.gap || (levels.includes(l.level) && (!query || l.text.toLowerCase().includes(query) || logSourceName(view.sources, l.source).toLowerCase().includes(query)))).sort((a, b) => a.at_ms - b.at_ms || a.id - b.id);
}
function drawLogLines(view, jump) {
  const box = view.box; if (!box?.isConnected) return;
  const follow = jump || box.scrollHeight - box.scrollTop - box.clientHeight < 40, shown = shownLogLines(view), rows = [];
  for (const l of shown) {
    if (l.gap) { rows.push(el('div', translate('… 这段时间新日志太多，较早的一部分没有显示'), 'log-note')); continue; }
    if (l.restarted) rows.push(el('div', msg`${logSourceName(view.sources, l.source)} 重新启动`, 'log-note'));
    if (l.missing) rows.push(el('div', msg`… ${l.missing} 行没有送达`, 'log-note'));
    const at = new Date(l.at_ms), row = el('div', undefined, `log-line ${l.level}`), time = el('time', at.toLocaleTimeString(getLanguage(), { hour12: false }));
    time.dateTime = at.toISOString(); time.title = at.toLocaleString(getLanguage(), { hour12: false }); row.append(time);
    if (!view.source) row.append(el('span', logSourceName(view.sources, l.source), 'log-source'));
    row.append(el('span', l.level.toUpperCase(), 'log-level'), el('span', l.text, 'log-text')); rows.push(row);
  }
  if (!rows.length) rows.push(el('div', view.lines.length ? translate('没有符合筛选条件的日志。') : translate('还没有收到日志。服务器升级到 0.132.0 后，日志随每次回报送来；控制器重启后从新的日志开始显示。'), 'log-empty'));
  const top = box.scrollTop; box.replaceChildren(...rows); box.scrollTop = follow ? box.scrollHeight : top;
  const count = view.lines.filter(l => !l.gap).length;
  view.foot.textContent = msg`显示 ${shown.filter(l => !l.gap).length} / ${count} 行` + (view.paused ? ` · ${translate('已暂停，新日志不会加载')}` : ` · ${translate('自动更新')}`);
}
function openLogs(source) { state.logs = { ...(state.logs || { level: 'all', query: '', paused: false }), source, key: null }; return navigate('logs'); }

// Diagnostics: problems the controller finds in the current state, in plain words, with the full
// report available as a JSON download for support or an AI assistant.
const findingLevels = localize({ critical: ['严重', 'red'], warning: ['警告', 'orange'], info: ['提示', ''] });
function durationText(s) { return s < 120 ? msg`${s} 秒` : s < 7200 ? msg`${Math.round(s / 60)} 分钟` : s < 172_800 ? msg`${Math.round(s / 3600)} 小时` : msg`${Math.round(s / 86_400)} 天`; }
function findingText(f) {
  const x = f.facts || {}, node = f.node || '', rule = f.rule || '', source = x.source === 'controller' ? translate('控制器') : node;
  switch (f.kind) {
    case 'node_not_enrolled': return msg`节点 ${node} 尚未接入`;
    case 'node_never_reported': return msg`节点 ${node} 已接入但从未回报`;
    case 'node_offline': return msg`节点 ${node} 已 ${durationText(x.seconds)} 无回报`;
    case 'config_rejected': return msg`节点 ${node} 拒绝了修订 ${x.desired}，仍在运行修订 ${x.applied}`;
    case 'config_pending': return msg`节点 ${node} 尚未应用修订 ${x.desired}（当前 ${x.applied}）`;
    case 'hop_failing': return msg`${rule}：${x.from === '客户端' ? translate('客户端') : x.from} → ${x.to} 最近 1 小时 ${x.attempts} 次连接，成功 ${x.success_percent}%`;
    case 'target_unhealthy': return msg`${rule}：节点 ${node} 的目标 ${x.target_address} 探测失败`;
    case 'high_cpu': return msg`节点 ${node} CPU 使用率 ${x.cpu_percent}%`;
    case 'low_memory': return msg`节点 ${node} 可用内存仅剩 ${x.available_percent}%`;
    case 'log_errors': return msg`${source} 最近 1 小时记录了 ${x.count} 条错误`;
    case 'log_warnings': return msg`${source} 最近 1 小时记录了 ${x.count} 条警告`;
    default: return f.message;
  }
}
function findingDetail(f) {
  const x = f.facts || {};
  switch (f.kind) {
    case 'node_not_enrolled': return translate('在服务器上用注册令牌启动 Agent 后即可使用；不再需要时可以删除这个节点。');
    case 'node_never_reported': return translate('在服务器上启动 Agent，并确认注册令牌和控制器地址正确。');
    case 'node_offline': return translate('检查服务器是否开机、Agent 服务是否在运行，以及它能否连到控制器。');
    case 'config_rejected': return x.error;
    case 'config_pending': return translate('通常几秒内完成；一直不变时查看这个节点的日志。');
    case 'hop_failing': return ({
      refused: msg`主要原因：连接被拒绝（${x.cause_count} 次）。目标端口没有程序在监听，或防火墙拒绝了连接。`,
      timeout: msg`主要原因：连接超时（${x.cause_count} 次）。目标或线路不通，或防火墙丢弃了连接。`,
      dns: msg`主要原因：域名解析失败（${x.cause_count} 次）。检查目标域名和服务器的 DNS 设置。`,
      closed: msg`主要原因：连接被对方关闭（${x.cause_count} 次）。检查下一跳的协议和加密设置是否一致。`,
    })[x.cause] || msg`主要原因：其他错误（${x.cause_count} 次）。查看这台服务器的日志。`;
    case 'target_unhealthy': return msg`探测结果：${(x.probes || []).map(p => `${String(p.protocol).toUpperCase()} ${probeErrors[p.error] || p.error || translate('未知')}`).join(' · ')}`;
    case 'high_cpu': return translate('持续偏高会增加转发延迟；检查这台服务器上的其他程序，或提高配置。');
    case 'low_memory': return translate('内存不足可能导致连接失败，或程序被系统结束。');
    case 'log_errors': case 'log_warnings': return x.latest;
    default: return '';
  }
}
async function renderDiagnostics() {
  const actor = state.actor, report = await api('/diagnostics/report');
  if (state.view !== 'diagnostics' || state.actor !== actor) return;
  const { summary, findings } = report, time = timestamp(report.generated_at_ms);
  const download = button(translate('下载诊断报告'), () => {
    const stamp = new Date(report.generated_at_ms).toISOString().replace(/[:.]/g, '-');
    const link = el('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + '\n'], { type: 'application/json' })); link.download = `relay-diagnostics-${stamp}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }, 'primary');
  const copy = button(translate('复制摘要'), async () => {
    const lines = [msg`Relay 诊断 · ${time} · 控制器 ${report.controller_version}`, msg`严重 ${summary.critical} · 警告 ${summary.warning} · 提示 ${summary.info} · 在线节点 ${summary.online} / ${summary.enrolled}`, ''];
    for (const f of findings) { const detail = findingDetail(f); lines.push(`- [${findingLevels[f.severity]?.[0] || f.severity}] ${findingText(f)}${detail ? ` — ${detail}` : ''}`); }
    if (!findings.length) lines.push(translate('没有发现问题。'));
    await navigator.clipboard.writeText(lines.join('\n')); notify(translate('摘要已复制'));
  });
  const actions = el('div', undefined, 'panel-actions'); actions.append(button(translate('重新检查'), () => refresh()), copy, download);
  const head = panel(translate('诊断报告'), msg`检查于 ${time} · 控制器 ${report.controller_version}`, actions);
  const board = el('div', undefined, 'alert-status diagnostics-board');
  for (const [label, value, color] of [[translate('严重'), summary.critical, summary.critical ? 'red' : 'green'], [translate('警告'), summary.warning, summary.warning ? 'orange' : 'green'], [translate('提示'), summary.info, ''], [translate('在线节点'), `${summary.online} / ${summary.enrolled}`, summary.online < summary.enrolled ? 'orange' : 'green']]) { const item = el('div', undefined, `alert-stat ${color}`); item.append(el('div', String(value), 'metric-value'), el('div', label, 'metric-label')); board.append(item); }
  head.append(board);
  const list = el('ol', undefined, 'incidents findings');
  for (const f of findings) {
    const item = el('li', undefined, `incident ${f.severity}`), text = el('div'), detail = findingDetail(f), [level] = findingLevels[f.severity] || [f.severity];
    text.append(el('div', findingText(f), 'finding-title'));
    if (detail) text.append(el('div', detail, ['config_rejected', 'log_errors', 'log_warnings'].includes(f.kind) ? 'finding-detail code' : 'finding-detail'));
    const links = el('div', undefined, 'finding-links'), source = f.facts?.source || f.node_id;
    links.append(el('span', [level, f.facts?.source === 'controller' ? translate('控制器') : f.node, f.rule].filter(Boolean).join(' · '), 'subline'));
    if (source && f.kind !== 'node_not_enrolled') links.append(button(translate('查看日志'), () => openLogs(source), 'table-action'));
    if (['hop_failing', 'target_unhealthy'].includes(f.kind)) links.append(button(translate('查看转发规则'), () => navigate('topology'), 'table-action'));
    else if (f.node_id) links.append(button(translate('节点管理'), () => navigate('nodes'), 'table-action'));
    text.append(links); item.append(el('i'), text); list.append(item);
  }
  if (!findings.length) list.append(el('li', translate('没有发现问题：已接入的节点都在回报，配置都已应用，最近 1 小时各段连接成功率不低于 90%，没有资源告急，也没有新的错误日志。'), 'incident-empty'));
  head.append(list);
  const about = panel(translate('报告里有什么'), translate('下载的 JSON 文件可以交给技术支持或 AI 助手分析，不用来回截图描述问题。'));
  const items = el('ul', undefined, 'diagnostics-contents');
  for (const line of [translate('上面的问题列表，以及每个节点的回报时间、配置修订、CPU / 内存和目标探测结果'), translate('每条规则的监听地址、目标地址和启用的功能名称；不包含密码、密钥、令牌和证书'), translate('最近 1 小时各段真实连接的成功与失败次数，以及最近 24 小时的事件'), translate('控制器和每台服务器最近 300 行日志')]) items.append(el('li', line));
  about.append(items, el('p', translate('报告包含服务器地址和日志内容，只分享给你信任的人。'), 'diagnostics-note'));
  if (state.view === 'diagnostics') $('#content').replaceChildren(head, about);
}
async function renderAudit() { const actor = state.actor; const rows = await api('/audit'); if (state.view !== 'audit' || !actor || state.actor !== actor) return; const p = panel(translate('操作审计'), translate('记录配置发布、节点注册、身份及会话操作。最近 200 条。')); p.append(table([translate('时间'), translate('操作者'), translate('操作'), translate('对象'), translate('详情')], rows.map(r => [timestamp(r.at_ms), r.actor_id, r.action, r.resource, r.detail]))); if (state.view === 'audit') $('#content').replaceChildren(p); }
const alertKinds = localize({ smtp: 'Email / SMTP', webhook: 'Webhook', telegram: 'Telegram', wecom: '企业微信', feishu: '飞书', dingtalk: '钉钉' });
const alertFields = localize({ smtp: [], webhook: [['url', 'Webhook 地址'], ['secret', '签名密钥（可选，HMAC-SHA256）', true]], telegram: [['bot_token', 'Bot Token'], ['chat_id', 'Chat ID']], wecom: [['url', '群机器人 Webhook 地址']], feishu: [['url', '自定义机器人 Webhook 地址'], ['secret', '签名校验密钥（可选）', true]], dingtalk: [['url', '自定义机器人 Webhook 地址'], ['secret', '加签密钥（可选）', true]] });
const severityNames = localize({ warning: '警告及以上', critical: '仅严重' });
// Threshold rules, in the order the controller checks them. Ranges match the controller's validation.
const alertRuleNames = localize({ node_cpu: '节点 CPU 使用率', node_memory: '节点内存使用率', node_expiring: '节点即将到期', node_expired: '节点已到期', budget_near: '共享额度接近上限', budget_exhausted: '共享额度用尽', dns_sync_failed: 'DNS 记录同步失败' });
const alertRuleLabels = localize({ percent: '阈值（%）', days: '提前天数', reports: '连续回报次数', checks: '连续检查次数' });
const alertRuleRanges = { node_cpu: 100, node_memory: 100, node_expiring: 365, budget_near: 100 };
const perReport = key => key === 'node_cpu' || key === 'node_memory';
function alertRuleRows(rules) {
  return Object.entries(alertRuleNames).filter(([key]) => rules[key]).map(([key, name]) => {
    const rule = rules[key], critical = key === 'node_expired' || key === 'budget_exhausted';
    const threshold = rule.threshold == null ? '—' : key === 'node_expiring' ? msg`${rule.threshold} 天内` : `≥ ${rule.threshold}%`;
    return [name, badge(rule.enabled ? translate('已启用') : translate('已停用'), rule.enabled ? 'green' : ''), threshold, perReport(key) ? msg`连续 ${rule.checks} 次回报` : msg`连续 ${rule.checks} 次检查`, badge(critical ? translate('严重') : translate('警告'), critical ? 'red' : 'orange')];
  });
}
function editAlertRules(settings) {
  const form = el('form'), rules = settings.rules;
  for (const [key, name] of Object.entries(alertRuleNames)) {
    const rule = rules[key], group = el('fieldset', undefined, 'form-grid'), legend = el('legend');
    // The rule's own name is the switch's label, so each section reads "☐ Node CPU usage".
    checkbox(legend, `${key}.enabled`, name).checked = rule.enabled;
    legend.firstChild.className = 'inline-check'; group.append(legend);
    if (rule.threshold != null) { const input = field(group, `${key}.threshold`, key === 'node_expiring' ? alertRuleLabels.days : alertRuleLabels.percent, rule.threshold, 'number'); input.min = 1; input.max = alertRuleRanges[key]; }
    const checks = field(group, `${key}.checks`, perReport(key) ? alertRuleLabels.reports : alertRuleLabels.checks, rule.checks, 'number'); checks.min = 1; checks.max = 100;
    form.append(group);
  }
  form.append(el('p', translate('CPU 和内存在节点每次回报时检查一次，其他每 2 秒检查一次。连续达到次数才告警，一次检查正常就自动恢复。'), 'fine'));
  submit(form, translate('保存规则'), async data => {
    const next = {};
    for (const key of Object.keys(alertRuleNames)) {
      next[key] = { enabled: data.get(`${key}.enabled`) === 'on', checks: number(data, `${key}.checks`) };
      if (rules[key].threshold != null) next[key].threshold = number(data, `${key}.threshold`);
    }
    // The maintenance window is part of the same settings; keep it as it is.
    await api('/alerts/settings', { method: 'PUT', body: { maintenance_until_ms: settings.maintenance_until_ms ?? null, rules: next } });
    $('#dialog').close(); notify(translate('告警规则已保存。')); await renderAlerts();
  });
  modal(translate('告警规则'), form);
}
// Alerts of the last 24 hours, one lane per node; an alert that is still open runs to now.
function incidentTimeline(incidents, now) {
  const span = 86_400_000, start = now - span, lanes = new Map(), box = el('div', undefined, 'timeline');
  for (const i of incidents) if ((i.resolved_at_ms ?? now) >= start) { if (!lanes.has(i.node_name)) lanes.set(i.node_name, []); lanes.get(i.node_name).push(i); }
  if (!lanes.size) return empty(translate('最近 24 小时没有告警'), translate('目标不可用、配置拒绝或节点离线时，这里会按节点显示每次告警持续了多久。'));
  box.append(chartKey([[translate('警告'), 'partial'], [translate('严重'), 'down'], [translate('仍未恢复'), 'open']]));
  for (const [name, items] of [...lanes].sort((a, b) => a[0].localeCompare(b[0]))) {
    // Alerts that overlap on one node each get their own line in the lane.
    const track = el('div', undefined, 'timeline-track'), ends = [];
    for (const i of items.sort((a, b) => a.opened_at_ms - b.opened_at_ms)) {
      const from = Math.max(i.opened_at_ms, start), to = i.resolved_at_ms ?? now, bar = el('i', undefined, `timeline-bar ${i.severity === 'critical' ? 'down' : 'partial'}${i.resolved_at_ms ? '' : ' open'}`);
      let line = ends.findIndex(end => end < from); if (line < 0) line = ends.length; ends[line] = to;
      bar.style.left = `${(from - start) / span * 100}%`; bar.style.width = `${Math.max(0.4, (to - from) / span * 100)}%`; bar.style.top = `${4 + line * 14}px`;
      bar.title = `${incidentMessage(i)}\n${timestamp(i.opened_at_ms)} → ${i.resolved_at_ms ? timestamp(i.resolved_at_ms) : translate('仍未恢复')}`;
      track.append(bar);
    }
    track.style.height = `${8 + ends.length * 14}px`; box.append(el('strong', name, 'timeline-name'), track);
  }
  const ticks = el('div', undefined, 'chart-labels'); for (let h = 0; h <= 24; h += 6) ticks.append(el('span', clock(start + h * 3_600_000)));
  box.append(el('span'), ticks); return box;
}
async function renderAlerts() {
  const actor = state.actor;
  const data = await api('/alerts');
  if (state.view !== 'alerts' || !actor || state.actor !== actor) return;
  const now = Date.now(), { settings, channels, incidents, can_manage } = data;
  const until = settings.maintenance_until_ms, maintaining = until && until > now;
  const grid = el('div', undefined, 'alert-grid');
  const status = panel(translate('通知状态'), maintaining ? msg`维护模式至 ${timestamp(until)}。期间不发送新告警，结束时仍未恢复的问题会补发。` : translate('目标不可用、节点拒绝配置和节点离线会通知已启用的通道。同时出现的问题合并为一条消息；同一问题 5 分钟内反复出现只算一次。'));
  const strip = el('div', undefined, 'alert-status');
  for (const [label, value, color] of [[translate('当前告警'), incidents.open.length, incidents.open.length ? 'red' : 'green'], [translate('启用通道'), channels.filter(c => c.enabled).length, channels.some(c => c.enabled) ? 'green' : 'orange'], [translate('发送失败'), incidents.deliveries.filter(d => d.status === 'failed').length, incidents.deliveries.some(d => d.status === 'failed') ? 'red' : '']]) { const item = el('div', undefined, `alert-stat ${color}`); item.append(el('div', String(value), 'metric-value'), el('div', label, 'metric-label')); strip.append(item); }
  const actions = el('div', undefined, 'alert-actions');
  const maintain = ms => api('/alerts/settings', { method: 'PUT', body: { maintenance_until_ms: ms } }).then(renderAlerts);
  if (can_manage) actions.append(maintaining ? button(translate('结束维护'), () => maintain(null), 'primary') : badge(translate('正常通知'), 'green'), button(translate('维护 1 小时'), () => maintain(Date.now() + 3600_000)), button(translate('维护 4 小时'), () => maintain(Date.now() + 4 * 3600_000)));
  strip.append(actions); status.append(strip); grid.append(status);
  const charts = displayMode('alerts') === 'chart', toolbar = el('div', undefined, 'toolbar view-toolbar'); toolbar.append(displayToggle('alerts', renderAlerts));
  if (charts) grid.append(chartPanel(translate('最近 24 小时'), translate('每行一个节点，色条从告警出现画到恢复；仍未恢复的延续到现在。恢复记录保存在控制器内存中，控制器重启后重新记录。'), incidentTimeline([...incidents.open, ...incidents.resolved], now)));
  const list = panel(translate('通知通道'), can_manage ? translate('可向全局或指定租户发送通知。密钥保存后不再显示。最多 20 个通道。') : translate('仅显示本租户专用通道和事件。通道由系统管理员配置。'), can_manage ? button(translate('＋ 添加通道'), () => editAlertChannel(), 'primary') : null);
  if (!channels.length) list.append(empty(translate('还没有通知通道'), translate('系统管理员可添加 Email、Webhook 或聊天机器人通道。'), can_manage ? button(translate('＋ 添加通道'), () => editAlertChannel(), 'primary') : null));
  else list.append(table([translate('名称'), translate('租户范围'), translate('类型'), translate('发送到'), translate('级别'), translate('状态'), translate('操作')], channels.map(c => { const ops = el('div', undefined, 'row-actions'); if (can_manage) ops.append(button(translate('测试'), async () => { notify(msg`正在向 ${c.name} 发送测试消息…`); try { await api(`/alerts/channels/${c.id}/test`, { method: 'POST' }); notify(msg`测试消息已发送到 ${c.name}，请确认已收到。`); } finally { await renderAlerts(); } }, 'table-action'), button(translate('编辑'), () => editAlertChannel(c), 'table-action'), button(translate('删除'), async () => { if (!await confirmAction(msg`删除通知通道“${c.name}”？`)) return; await api(`/alerts/channels/${c.id}`, { method: 'DELETE' }); await renderAlerts(); }, 'table-action danger')); return [namedCell(c.name, c.secret_set ? translate('已设置密钥') : translate('未设置密钥')), c.tenant_id || translate('全部租户'), alertKinds[c.kind], el('span', c.destination, 'mono'), severityNames[c.min_severity], badge(c.enabled ? translate('已启用') : translate('已停用'), c.enabled ? 'green' : ''), ops]; })));
  grid.append(list);
  if (settings.rules) {
    const rules = panel(translate('告警规则'), translate('除目标不可用、配置拒绝和节点离线外，还可以按阈值通知节点资源、节点到期、共享额度和 DNS 同步问题。默认全部关闭；问题消失后自动恢复。'), can_manage ? button(translate('编辑规则'), () => editAlertRules(settings), 'primary') : null);
    rules.append(table([translate('告警类型'), translate('状态'), translate('阈值'), translate('连续次数'), translate('级别')], alertRuleRows(settings.rules)));
    grid.append(rules);
  }
  const levels = { warning: [translate('警告'), 'orange'], critical: [translate('严重'), 'red'] };
  const incidentRows = (items, resolved) => items.map(i => [resolved ? `${timestamp(i.resolved_at_ms)} · ${ago(i.resolved_at_ms, now)}` : `${timestamp(i.opened_at_ms)} · ${ago(i.opened_at_ms, now)}`, i.node_name, badge(...(levels[i.severity] || [i.severity])), el('span', incidentMessage(i), 'wrap'), i.repeats ? msg`${i.repeats} 次` : '—', resolved ? (i.last_notice_ms ? translate('已通知恢复') : translate('未通知')) : i.notified ? badge(translate('已通知'), 'green') : badge(maintaining ? translate('维护中暂缓') : translate('等待发送'), 'orange')]);
  const open = panel(translate('当前告警'), translate('仍未恢复的问题。控制器重启后会在 1 分钟内重新检测。'));
  open.append(incidents.open.length ? table([translate('开始'), translate('对象'), translate('级别'), translate('内容'), translate('反复'), translate('通知')], incidentRows(incidents.open, false)) : empty(translate('一切正常'), translate('没有未恢复的告警。')));
  grid.append(open);
  if (!charts && incidents.resolved.length) { const done = panel(translate('最近恢复'), translate('最近 200 条，保存在控制器内存中。')); done.append(table([translate('恢复'), translate('对象'), translate('级别'), translate('内容'), translate('反复'), translate('通知')], incidentRows(incidents.resolved.slice(0, 50), true))); grid.append(done); }
  const statusNames = { cancelled: [translate('已取消'), ''], sent: [translate('已送达'), 'green'], failed: [translate('失败'), 'red'], retrying: [translate('重试中'), 'orange'], pending: [translate('发送中'), ''] }, noticeNames = { opened: translate('告警'), resolved: translate('恢复'), test: translate('测试') };
  const log = panel(translate('发送记录'), translate('失败会在 10 秒、1 分钟、5 分钟后重试。最近 200 条。'));
  log.append(incidents.deliveries.length ? table([translate('时间'), translate('通道'), translate('类型'), translate('结果'), translate('尝试'), translate('错误')], incidents.deliveries.slice(0, 100).map(d => [timestamp(d.created_at_ms), d.channel_name, d.incidents > 1 ? msg`${noticeNames[d.notice]} · 合并 ${d.incidents} 条` : noticeNames[d.notice], badge(...statusNames[d.status]), String(d.attempts), d.error ? Object.assign(el('span', d.error, 'clip mono'), { title: d.error }) : '—'])) : empty(translate('还没有发送记录'), translate('发送测试消息或出现告警后会显示在这里。')));
  if (!charts) grid.append(log);
  else if (incidents.deliveries.length) {
    const results = new Map(); for (const d of incidents.deliveries) { const v = results.get(d.channel_name) || [0, 0, 0, 0]; v[{ sent: 0, failed: 2, cancelled: 3 }[d.status] ?? 1] += 1; results.set(d.channel_name, v); }
    grid.append(chartPanel(translate('发送结果'), translate('按通道统计最近 200 条发送记录。'), barChart([...results].map(([name, v]) => ({ label: name, values: v, text: msg`送达 ${v[0]} / 共 ${v.reduce((a, b) => a + b, 0)}` })),
      [[statusNames.sent[0], 'up'], [translate('发送中或重试'), 'partial'], [statusNames.failed[0], 'down'], [statusNames.cancelled[0], 'unknown']])));
  }
  if (state.view === 'alerts') { $('#page-tools').replaceChildren(...toolbar.childNodes); $('#content').replaceChildren(grid); }
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
  select(form, 'min_severity', translate('通知级别'), [['warning', translate('警告及以上（全部告警）')], ['critical', translate('仅严重（配置拒绝、节点离线或到期、共享额度用尽）')]], existing?.min_severity || 'warning');
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
// WireGuard networks: nodes join with the key their agent reports; devices get a configuration once.
const wgStates = localize({ up: '已连通', updating: '更新中', waiting: '等待节点报告', error: '出错', offline: '节点离线', connected: '已连接', idle: '未连接', disabled: '已停用' });
const wgList = value => String(value || '').split(/[\s,]+/).filter(Boolean);
const wgStateColors = { up: 'green', connected: 'green', updating: 'orange', error: 'red', offline: 'red' };
async function renderWireguard() {
  const actor = state.actor;
  if (!featureOn('wireguard')) { $('#content').replaceChildren(empty(translate('WireGuard 组网未开启'), translate('系统管理员可以在「可选功能」中开启。开启后，允许管理 WireGuard 的服务器会生成自己的密钥，之后才能加入网络。'), button(translate('前往可选功能'), () => navigate('features'), 'primary'))); return; }
  const view = await api('/wireguard');
  if (state.view !== 'wireguard' || state.actor !== actor) return;
  const head = panel(translate('WireGuard 组网'), translate('把节点和设备连进同一个私有网络。有公网端点的节点之间直连；两台都没有公网端点的节点经中继节点转发；设备连接到一台有公网端点的节点（入口节点）。'), button(translate('＋ 新建网络'), () => wireguardNetworkForm(null), 'primary'));
  const body = el('div', undefined, 'panel-body');
  body.append(el('h3', translate('节点是否可以加入')), table([translate('节点'), translate('状态'), translate('说明')], view.nodes.map(node => [node.name, badge(node.key_reported ? translate('可以加入') : translate('未就绪'), node.key_reported ? 'green' : ''), el('span', node.problem || (node.key_reported ? translate('Agent 已报告公钥') : translate('等待 Agent 报告公钥：服务器需安装授权文件 relay-agent-wireguard.conf 和 wireguard-tools')), 'wrap')])));
  head.append(body);
  if (!view.networks.length) { head.append(empty(translate('还没有 WireGuard 网络'), translate('新建网络，先加入一台有公网端点的节点作为中继和设备入口，再加入其他节点和设备。'))); $('#content').replaceChildren(head); return; }
  $('#content').replaceChildren(head, ...view.networks.map(network => wireguardNetworkPanel(network, view)));
}
function wireguardNetworkPanel(network, view) {
  const label = id => network.members.find(m => m.id === id)?.label || '—';
  const actions = el('div', undefined, 'panel-actions');
  actions.append(button(translate('＋ 节点'), () => wireguardNodeForm(network, null, view), 'primary'), button(translate('＋ 设备'), () => wireguardDeviceForm(network, null)), button(translate('编辑'), () => wireguardNetworkForm(network)), button(translate('删除'), () => deleteWireguard(msg`删除网络「${network.name}」及其全部成员？各节点会移除这个 WireGuard 接口，设备配置随之失效。`, `/wireguard/networks/${network.id}`, translate('网络已删除。')), 'subtle danger'));
  const p = panel(msg`网络 · ${network.name}`, msg`${network.cidr} · 接口 ${network.interface} · UDP 端口 ${network.listen_port} · MTU ${network.mtu} · 中继 ${network.relay_in_use ? label(network.relay_in_use) : translate('无')}${network.relay || !network.relay_in_use ? '' : translate('（自动）')}`, actions), body = el('div', undefined, 'panel-body');
  if (network.dns?.length) body.append(el('p', msg`设备配置中的 DNS：${network.dns.join(', ')}`, 'fine'));
  body.append(el('h3', translate('成员')));
  if (!network.members.length) body.append(el('p', translate('先加入一台有公网端点的节点。'), 'muted'));
  else body.append(table([translate('名称'), translate('类型'), translate('网内地址'), translate('公网端点'), translate('状态'), translate('操作')], network.members.map(member => {
    const buttons = el('div');
    if (member.kind === 'node') buttons.append(button(translate('编辑'), () => wireguardNodeForm(network, member, view), 'table-action'));
    else buttons.append(button(translate('编辑'), () => wireguardDeviceForm(network, member), 'table-action'), button(member.enabled === false ? translate('启用') : translate('停用'), async () => {
      // Name and entry node go along, or the controller would pick the relay as entry node.
      await api(`/wireguard/members/${member.id}`, { method: 'PUT', body: { kind: 'device', name: member.name, via: member.via, enabled: member.enabled === false } });
      notify(member.enabled === false ? translate('设备已启用，原有配置可以继续使用。') : translate('设备已停用：各节点移除它，密钥保留。')); await renderWireguard();
    }, 'table-action'), button(translate('新密钥'), () => rekeyWireguard(member), 'table-action'));
    buttons.append(button(translate('移除'), () => deleteWireguard(msg`从网络移除「${member.label}」？`, `/wireguard/members/${member.id}`, translate('成员已移除。')), 'table-action danger'));
    const status = el('div'); status.append(badge(wgStates[member.state] || member.state, wgStateColors[member.state] || ''));
    // The panel words the device error the controller reports; agent errors show as sent.
    if (member.error) status.append(el('span', member.kind === 'device' && member.error.includes('preshared keys') ? translate('入口节点的 Agent 版本过旧，不会写入预共享密钥，设备无法连接。请升级该 Agent。') : member.error, 'wrap error-text'));
    const kind = member.kind === 'node' ? translate('节点') : msg`设备 · 经 ${label(member.via)}`;
    const endpoint = member.endpoint || (member.kind === 'node' ? translate('无（在 NAT 后）') : '—');
    const detail = member.listen_port ? msg`UDP 端口 ${member.listen_port}` : member.preshared_key ? translate('已设预共享密钥') : '';
    return [namedCell(member.label, detail), kind, member.address, endpoint, status, buttons];
  })));
  if (network.pairs.length) {
    body.append(el('h3', translate('成员之间的连接')), table([translate('成员'), translate('路径'), translate('最近握手'), translate('接收 / 发送')], network.pairs.map(pair => {
      const path = el('div');
      path.append(pair.path === 'direct' ? badge(pair.punched ? translate('直连 · 已穿透 NAT') : translate('直连'), 'green') : pair.path === 'probing' ? badge(msg`正在尝试直连 · 暂经 ${pair.via}`) : pair.path === 'relayed' ? badge(msg`经中继 · ${pair.via}`, 'orange') : badge(translate('不可达'), 'red'));
      // The panel words the two reasons NAT traversal reports; others show as sent.
      if (pair.reason) path.append(el('span', pair.reason.startsWith('hole punching failed') ? translate('直连失败：45 秒内没有握手。对方的 NAT 可能为每个目标换端口（对称型 NAT）。') : pair.reason.includes('received nothing') ? translate('直连中断：75 秒没有收到数据。') : pair.reason, 'wrap fine'));
      if (pair.retry_in_s != null) path.append(el('span', msg`${Math.max(1, Math.ceil(pair.retry_in_s / 60))} 分钟后再试直连`, 'fine'));
      const age = pair.handshake_age_s == null ? translate('尚未握手') : pair.handshake_age_s < 60 ? msg`${pair.handshake_age_s} 秒前` : pair.handshake_age_s < 3600 ? msg`${Math.floor(pair.handshake_age_s / 60)} 分钟前` : msg`${Math.floor(pair.handshake_age_s / 3600)} 小时前`;
      return [`${pair.a} ⇄ ${pair.b}`, path, age, pair.rx_bytes == null ? '—' : `${bytes(pair.rx_bytes)} / ${bytes(pair.tx_bytes)}`];
    })));
    if (network.pairs.some(pair => pair.path === 'unreachable')) body.append(el('p', translate('两台都没有公网端点的节点需要一台有公网端点的节点做中继。给一台节点填写公网端点即可。'), 'fine'));
    if (!featureOn('nat-traversal') && network.pairs.some(pair => pair.path === 'relayed')) body.append(el('p', translate('开启可选功能「NAT 穿透」后，经中继的节点会先尝试直接连接。'), 'fine'));
    body.append(el('p', translate('握手每 2 分钟左右更新一次；没有流量时握手时间会变旧，这是正常的。经中继的连接显示两段中较旧的一次握手。'), 'fine'));
  }
  p.append(body);
  return p;
}
async function deleteWireguard(question, path, done) {
  if (!await confirmAction(question)) return;
  await api(path, { method: 'DELETE' }); notify(done); await renderWireguard();
}
function wireguardNetworkForm(network) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('网络名称'), network?.name || '').maxLength = 64;
  const cidr = field(grid, 'cidr', translate('网内地址段（私有地址，/16 到 /29）'), network?.cidr || '10.88.0.0/24');
  if (network?.members.length) { cidr.disabled = true; cidr.title = translate('网络有成员时不能修改地址段'); }
  const port = field(grid, 'listen_port', translate('UDP 端口'), network?.listen_port ?? 51820, 'number'); port.min = 1; port.max = 65535;
  const mtu = field(grid, 'mtu', 'MTU', network?.mtu ?? 1420, 'number'); mtu.min = 1280; mtu.max = 1420;
  if (network) select(grid, 'relay', translate('中继节点'), [['', translate('自动（网内地址最小的公网节点）')], ...network.members.filter(m => m.kind === 'node' && m.endpoint).map(m => [m.id, m.label])], network.relay || '');
  field(grid, 'dns', translate('设备使用的 DNS 服务器（可选，最多 4 个 IP，用逗号分隔）'), (network?.dns || []).join(', '), 'text', false);
  form.append(grid, el('p', translate('地址段不能与服务器已有的网段重叠，否则节点会拒绝创建接口并显示原因。有公网端点的节点需要在防火墙放行这里的 UDP 端口。'), 'fine'));
  submit(form, network ? translate('保存网络') : translate('新建网络'), async data => {
    const body = { name: String(data.get('name')).trim(), listen_port: number(data, 'listen_port'), mtu: number(data, 'mtu'), dns: wgList(data.get('dns')) };
    if (!cidr.disabled) body.cidr = String(data.get('cidr')).trim();
    if (network) body.relay = data.get('relay') || null;
    if (network) await api(`/wireguard/networks/${network.id}`, { method: 'PUT', body });
    else await api('/wireguard/networks', { method: 'POST', body });
    $('#dialog').close(); notify(translate('网络已保存。')); await renderWireguard();
  });
  modal(network ? msg`编辑网络 · ${network.name}` : translate('新建 WireGuard 网络'), form);
}
function wireguardNodeForm(network, member, view) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  const taken = new Set(network.members.map(m => m.node_id));
  const choices = member ? [[member.node_id, member.label]] : view.nodes.filter(n => n.key_reported && !taken.has(n.id)).map(n => [n.id, n.name]);
  if (!choices.length) { modal(translate('加入节点'), empty(translate('没有可以加入的节点'), translate('节点的 Agent 报告公钥后才能加入。请在服务器安装 wireguard-tools 和授权文件 relay-agent-wireguard.conf，重启 Agent 后稍等片刻。'))); return; }
  const node = select(grid, 'node_id', translate('节点'), choices, member?.node_id || choices[0][0]); node.disabled = !!member;
  field(grid, 'endpoint', translate('公网端点（IP 或域名，可带端口；在 NAT 后留空）'), member?.endpoint || '', 'text', false).maxLength = 260;
  const port = field(grid, 'listen_port', translate('本节点 UDP 端口（留空使用网络端口）'), member?.listen_port ?? '', 'number', false); port.min = 1; port.max = 65535;
  form.append(grid, el('p', translate('填写公网端点的节点可以被其他成员直接连接，也能做中继和设备入口；需要在防火墙放行它的 UDP 端口。没有公网地址的节点留空，它会主动连接公网节点。'), 'fine'));
  submit(form, member ? translate('保存节点') : translate('加入节点'), async data => {
    const body = { kind: 'node', endpoint: String(data.get('endpoint')).trim() || null, listen_port: number(data, 'listen_port') };
    if (member) await api(`/wireguard/members/${member.id}`, { method: 'PUT', body });
    else await api(`/wireguard/networks/${network.id}/members`, { method: 'POST', body: { ...body, node_id: node.value } });
    $('#dialog').close(); notify(translate('节点已保存。')); await renderWireguard();
  });
  modal(member ? msg`编辑节点 · ${member.label}` : msg`加入节点 · ${network.name}`, form);
}
function wireguardDeviceForm(network, member) {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  const hubs = network.members.filter(m => m.kind === 'node' && m.endpoint);
  if (!hubs.length) { modal(translate('添加设备'), empty(translate('还没有入口节点'), translate('设备需要连接一台有公网端点的节点。请先加入这样的节点。'))); return; }
  field(grid, 'name', translate('设备名称'), member?.name || '').maxLength = 64;
  select(grid, 'via', translate('入口节点'), member ? hubs.map(h => [h.id, h.label]) : [['', translate('自动（中继节点）')], ...hubs.map(h => [h.id, h.label])], member?.via || '');
  if (!member) field(grid, 'public_key', translate('设备自己的公钥（可选，留空由面板生成密钥）'), '', 'text', false).maxLength = 44;
  field(grid, 'allowed_ips', translate('经隧道访问的地址段（AllowedIPs，用逗号分隔；留空为本网络地址段）'), (member?.allowed_ips || []).join(', '), 'text', false);
  const keepalive = field(grid, 'keepalive', translate('保活间隔（秒，0 为关闭，留空为 25）'), member?.keepalive ?? '', 'number', false); keepalive.min = 0; keepalive.max = 65535;
  checkbox(grid, 'enabled', translate('启用')).checked = member?.enabled !== false;
  if (!member) checkbox(grid, 'preshared_key', translate('同时生成预共享密钥（PresharedKey；入口节点的 Agent 需支持）'));
  form.append(grid, el('p', translate('面板生成密钥时，配置和二维码只显示这一次，面板只保存公钥。用 WireGuard 应用扫描二维码或导入配置即可。'), 'fine'));
  submit(form, member ? translate('保存设备') : translate('添加设备'), async data => {
    const body = { kind: 'device', name: String(data.get('name')).trim(), via: data.get('via') || null, allowed_ips: wgList(data.get('allowed_ips')), keepalive: number(data, 'keepalive') ?? 25, enabled: data.get('enabled') === 'on' };
    if (body.keepalive > 65535) throw new Error(translate('保活间隔必须为 0–65535 秒'));
    if (member) { await api(`/wireguard/members/${member.id}`, { method: 'PUT', body }); $('#dialog').close(); notify(translate('设备已保存。入口节点、AllowedIPs 或保活间隔改变后，请给设备生成新密钥并重新导入配置。')); }
    else { const issued = await api(`/wireguard/networks/${network.id}/members`, { method: 'POST', body: { ...body, public_key: String(data.get('public_key')).trim() || null, preshared_key: data.get('preshared_key') === 'on' } }); $('#dialog').close(); showWireguardConfig(issued); }
    await renderWireguard();
  });
  modal(member ? msg`编辑设备 · ${member.name}` : msg`添加设备 · ${network.name}`, form);
}
function rekeyWireguard(member) {
  const form = el('form');
  form.append(el('p', msg`给「${member.label}」生成新密钥？旧配置会立即失效，需要在设备上重新导入。`));
  checkbox(form, 'preshared_key', translate('同时生成预共享密钥（PresharedKey；入口节点的 Agent 需支持）')).checked = !!member.preshared_key;
  submit(form, translate('生成新密钥'), async data => {
    const issued = await api(`/wireguard/members/${member.id}/rekey`, { method: 'POST', body: { preshared_key: data.get('preshared_key') === 'on' } });
    $('#dialog').close(); showWireguardConfig(issued); await renderWireguard();
  });
  modal(translate('新密钥'), form);
}
function showWireguardConfig(issued) {
  const body = el('div');
  if (issued.qr_svg) { const qr = el('img', undefined, 'qr-code'); qr.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(issued.qr_svg)}`; qr.alt = translate('WireGuard 配置二维码'); body.append(el('p', translate('用手机上的 WireGuard 应用扫描二维码，或复制下面的配置导入电脑。配置包含私钥，只显示这一次，关闭后无法再次查看。')), qr); }
  else body.append(el('p', translate('设备使用自己的密钥：把下面的配置填入设备，并把 PrivateKey 换成设备自己的私钥。')));
  const config = el('pre', issued.config || '', 'secret-box mono');
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('复制配置'), async () => { await navigator.clipboard.writeText(issued.config || ''); notify(translate('配置已复制。')); }), button(translate('我已保存配置'), () => $('#dialog').close(), 'primary'));
  body.append(config, actions);
  modal(msg`设备配置 · ${issued.name}`, body);
}
const fedStates = localize({ active: '使用中', paused: '已暂停', revoked: '已撤销' });
const fedStateColors = { active: 'green', paused: 'orange', revoked: '' };
const fedKinds = localize({ forward: '端口转发', shadowsocks: 'Shadowsocks' });
const fedProtocols = localize({ tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' });
function fedLimits(s) {
  const parts = [s.kinds.map(k => fedKinds[k] || k).join(' / '), msg`规则 ${s.rules.length}/${s.max_rules}`, userRateText(s) ? msg`带宽 ${userRateText(s)}` : translate('不限速'), s.quota_bytes ? msg`流量 ${bytes(s.quota_bytes)}` : translate('不限流量'), s.expires_at_ms ? msg`到期 ${timestamp(s.expires_at_ms)}` : translate('长期有效')];
  if (s.allow_sources?.length) parts.push(msg`来源 ${s.allow_sources.join(', ')}`);
  return parts.join(' · ');
}
function fedUsage(statement, quota) {
  const up = statement?.upload_bytes || 0, down = statement?.download_bytes || 0;
  return namedCell(quota ? `${bytes(up + down)} / ${bytes(quota)}` : bytes(up + down), `↑ ${bytes(up)} · ↓ ${bytes(down)}`);
}
async function renderFederation() {
  const actor = state.actor;
  if (!featureOn('federation')) { $('#content').replaceChildren(empty(translate('跨面板共享未开启'), translate('系统管理员可以在「可选功能」中开启。开启后，可以把节点上的一段端口共享给另一个面板，也可以接收其他面板共享的端口。'), button(translate('前往可选功能'), () => navigate('features'), 'primary'))); return; }
  const view = await api('/federation');
  if (state.view !== 'federation' || state.actor !== actor) return;
  const given = panel(translate('共享给其他面板'), translate('把一台节点上的一段端口交给另一个面板使用。对方只能在这段端口里建规则；带宽、流量、到期时间和允许的来源由你决定。规则由本面板生成，对方无法放宽。'), button(translate('＋ 新建共享'), () => federationGrantForm(null), 'primary'));
  if (!view.grants.length) given.append(empty(translate('还没有共享'), translate('新建共享，选择节点和端口范围，再把邀请码发给对方面板的管理员。')));
  else { const body = el('div', undefined, 'panel-body'); body.append(table([translate('共享'), translate('节点与端口'), translate('限制'), translate('对方'), translate('已用流量'), translate('操作')], view.grants.map(federationGrantRow))); given.append(body); }
  const received = panel(translate('其他面板共享给我'), translate('输入对方面板给的邀请码即可接入。你可以在共享的端口范围内建规则；规则运行在对方的节点上，流量由对方计量。'), button(translate('＋ 输入邀请码'), federationRemoteForm, 'primary'));
  if (!view.remotes.length) received.append(empty(translate('还没有收到共享'), translate('对方面板在「跨面板共享」中新建共享并生成邀请码后，把邀请码粘贴到这里。')));
  $('#content').replaceChildren(given, received, ...view.remotes.map(federationRemotePanel));
}
function federationGrantRow(view) {
  // The share's own fields sit beside the node name and statement.
  const g = view, actions = el('div');
  if (g.state !== 'revoked') {
    if (!g.link) actions.append(button(translate('邀请码'), () => inviteFederation(g), 'table-action'));
    actions.append(button(translate('编辑'), () => federationGrantForm(view), 'table-action'));
    actions.append(g.state === 'active'
      ? button(translate('暂停'), () => federationGrantAction(g, 'pause', msg`暂停「${g.name}」？对方的规则会停用，直到你恢复。`, translate('共享已暂停。')), 'table-action')
      : button(translate('恢复'), () => federationGrantAction(g, 'resume', null, translate('共享已恢复。')), 'table-action'));
    actions.append(button(translate('撤销'), () => federationGrantAction(g, 'revoke', msg`撤销「${g.name}」？节点会删除对方的全部规则，对方的密钥立即失效。撤销后不能恢复，只能新建共享。`, translate('共享已撤销。')), 'table-action danger'));
  } else actions.append(button(translate('删除'), () => federationGrantAction(g, null, msg`删除已撤销的共享「${g.name}」？流量记录会保留。`, translate('共享已删除。')), 'table-action danger'));
  const peer = g.link ? namedCell(msg`面板 ${g.link.panel_id.slice(0, 8)}`, g.link.last_seen_ms ? msg`最近访问 ${ago(g.link.last_seen_ms, Date.now())}` : '')
    : g.invite && g.invite.expires_at_ms > Date.now() ? namedCell(translate('等待对方接入'), msg`邀请码有效至 ${timestamp(g.invite.expires_at_ms)}`) : el('span', translate('尚未邀请'), 'muted');
  const ports = el('div'); ports.append(el('strong', view.node_name), el('div', `${g.listen_ip}:${g.port_start}–${g.port_end}`, 'subline mono'), ...(g.rules.length ? g.rules.map(r => el('div', `${r.name} :${r.port}`, 'fine')) : [el('div', translate('对方还没有建规则'), 'fine')]));
  const share = namedCell(g.name, g.public_host), status = el('div', undefined, 'badge-row');
  status.append(badge(fedStates[g.state] || g.state, fedStateColors[g.state] || ''));
  if (!view.applied) status.append(badge(translate('节点更新中'), 'orange'));
  share.append(status);
  if (view.ack_mismatch) share.append(el('span', translate('对方确认过的流量比这里记录的多：本面板的数据可能是从旧备份恢复的。'), 'wrap error-text'));
  return [share, ports, el('span', fedLimits(g), 'wrap fine'), peer, fedUsage(view.statement, g.quota_bytes), actions];
}
async function federationGrantAction(g, action, question, done) {
  if (question && !await confirmAction(question)) return;
  if (action) await api(`/federation/grants/${g.id}/${action}`, { method: 'POST' });
  else await api(`/federation/grants/${g.id}`, { method: 'DELETE' });
  notify(done); await renderFederation();
}
async function inviteFederation(g) {
  const issued = await api(`/federation/grants/${g.id}/invite`, { method: 'POST', body: { owner_url: `${location.origin}/` } });
  const body = el('div');
  body.append(el('p', msg`把邀请码发给对方面板的管理员，对方在「跨面板共享 → 输入邀请码」中粘贴即可接入。邀请码只能使用一次，有效至 ${timestamp(issued.expires_at_ms)}。关闭后无法再次查看，需要时可以重新生成。`), el('pre', issued.code, 'secret-box mono'), el('p', msg`对方面板会通过 ${location.origin} 访问本面板，这个地址需要能从对方的服务器用 HTTPS 访问。`, 'fine'));
  const actions = el('div', undefined, 'dialog-actions'); actions.append(button(translate('复制邀请码'), async () => { await navigator.clipboard.writeText(issued.code); notify(translate('邀请码已复制。')); }), button(translate('完成'), () => $('#dialog').close(), 'primary'));
  body.append(actions);
  modal(msg`邀请码 · ${g.name}`, body);
  await renderFederation();
}
async function federationGrantForm(view) {
  const g = view, nodes = g ? [] : await api('/nodes');
  if (!g && !nodes.length) { modal(translate('新建共享'), empty(translate('还没有节点'), translate('先在「节点管理」接入一台服务器。'))); return; }
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('共享名称（对方能看到）'), g?.name || '').maxLength = 64;
  const node = select(grid, 'node_id', translate('节点'), g ? [[g.node_id, view.node_name]] : nodes.map(n => [n.id, n.name]), g?.node_id || nodes[0].id); node.disabled = !!g;
  field(grid, 'public_host', translate('对方用户连接的地址（节点的公网 IP 或域名）'), g?.public_host || '').maxLength = 253;
  field(grid, 'listen_ip', translate('节点监听地址（留空为全部地址）'), g && g.listen_ip !== '0.0.0.0' ? g.listen_ip : '', 'text', false).maxLength = 45;
  const start = field(grid, 'port_start', translate('起始端口'), g?.port_start ?? 20000, 'number'); start.min = 1; start.max = 65535;
  const end = field(grid, 'port_end', translate('结束端口'), g?.port_end ?? 20009, 'number'); end.min = 1; end.max = 65535;
  const max = field(grid, 'max_rules', translate('对方最多可建的规则数'), g?.max_rules ?? 5, 'number'); max.min = 1; max.max = 32;
  const quota = field(grid, 'gib', translate('总流量 / GiB（留空不限；建好后只能修改，不能取消或新加）'), g?.quota_bytes ? +(g.quota_bytes / 2 ** 30).toFixed(3) : '', 'number', false); quota.min = 0.001; quota.step = 'any';
  if (g && !g.quota_bytes) { quota.disabled = true; quota.title = translate('这个共享建立时没有流量限制'); }
  field(grid, 'expires', translate('到期时间（本地，留空长期有效）'), g?.expires_at_ms ? announcementDateTime(g.expires_at_ms) : '', 'datetime-local', false);
  form.append(grid);
  const speed = rateLimitEditor({ rate: g?.rate_bytes_per_sec, limits: { upload_bytes_per_sec: g?.upload_bytes_per_sec, download_bytes_per_sec: g?.download_bytes_per_sec }, unit: 'mbit', combined: { name: 'mbit', label: translate('总带宽 / Mbit/s（留空不限速）') }, min: 1024, max: 2 ** 40, rangeError: translate('请输入 0.009 到 8,796,093 之间的 Mbit/s') });
  form.append(speed.box);
  const kinds = el('fieldset', undefined, 'target-editor'); kinds.append(el('legend', translate('允许对方建的规则类型')));
  for (const [value, label] of Object.entries(fedKinds)) { const item = el('label', label, 'inline-check'), input = el('input'); input.type = 'checkbox'; input.name = 'kinds'; input.value = value; input.checked = g ? g.kinds.includes(value) : value === 'shadowsocks'; item.prepend(input); kinds.append(item); }
  form.append(kinds);
  const lists = el('div', undefined, 'form-grid');
  textarea(lists, 'allow_sources', translate('允许连接的来源 IP 或网段（每行一个；端口转发必填，留空表示任何来源）'), (g?.allow_sources || []).join('\n'));
  textarea(lists, 'deny_destinations', translate('禁止访问的目的地（每行一个域名、IP 或网段，可选）'), (g?.deny_destinations || []).join('\n'));
  textarea(lists, 'allow_destinations', translate('只允许访问的目的地（每行一个，留空不限制）'), (g?.allow_destinations || []).join('\n'));
  form.append(lists);
  const privateTargets = checkbox(form, 'allow_private_destinations', translate('允许访问节点本机和内网地址（默认禁止）'));
  privateTargets.checked = !!g?.allow_private_destinations; privateTargets.parentElement.classList.add('inline-check');
  form.append(el('p', translate('对方的规则都由本面板按这些限制生成。端口范围不能和节点上已有的规则或其他共享重叠；修改后节点会自动更新。'), 'fine'));
  submit(form, g ? translate('保存共享') : translate('新建共享'), async data => {
    const lines = key => String(data.get(key) || '').split('\n').map(s => s.trim()).filter(Boolean);
    const gibText = String(data.get('gib') || '').trim(), expires = String(data.get('expires') || '').trim(), { rate_bytes_per_sec, rate_limits } = speed.read(data);
    const body = { name: String(data.get('name')).trim(), public_host: String(data.get('public_host')).trim(), listen_ip: String(data.get('listen_ip') || '').trim() || null, port_start: number(data, 'port_start'), port_end: number(data, 'port_end'), max_rules: number(data, 'max_rules'), kinds: data.getAll('kinds'), rate_bytes_per_sec, upload_bytes_per_sec: rate_limits?.upload_bytes_per_sec ?? null, download_bytes_per_sec: rate_limits?.download_bytes_per_sec ?? null, quota_bytes: gibText ? Math.round(Number(gibText) * 2 ** 30) : g?.quota_bytes ?? null, expires_at_ms: expires ? new Date(expires).getTime() : null, allow_sources: lines('allow_sources'), allow_destinations: lines('allow_destinations'), deny_destinations: lines('deny_destinations'), allow_private_destinations: data.get('allow_private_destinations') === 'on' };
    if (g) await api(`/federation/grants/${g.id}`, { method: 'PUT', body });
    else await api('/federation/grants', { method: 'POST', body: { ...body, node_id: node.value } });
    $('#dialog').close(); notify(translate('共享已保存。')); await renderFederation();
  });
  modal(g ? msg`编辑共享 · ${g.name}` : translate('新建共享'), form);
}
function federationRemoteForm() {
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  textarea(grid, 'invite', translate('邀请码（以 relay-invite:v1: 开头）'), '', true);
  field(grid, 'label', translate('名称（可选，默认用对方起的名字）'), '', 'text', false).maxLength = 64;
  form.append(grid, el('p', translate('本面板会用邀请码向对方面板换取自己的密钥。邀请码只能使用一次。'), 'fine'));
  submit(form, translate('接入'), async data => {
    await api('/federation/remotes', { method: 'POST', body: { invite: String(data.get('invite')).trim(), label: String(data.get('label')).trim() } });
    $('#dialog').close(); notify(translate('已接入共享。')); await renderFederation();
  });
  modal(translate('输入邀请码'), form);
}
function federationRemotePanel(remote) {
  const s = remote.shared, open = !remote.revoked && s?.state === 'active';
  const actions = el('div', undefined, 'panel-actions');
  if (open) actions.append(button(translate('＋ 规则'), () => federationRuleForm(remote), 'primary'));
  actions.append(button(translate('立即同步'), async () => { await api(`/federation/remotes/${remote.id}/sync`, { method: 'POST' }); notify(translate('已同步。')); await renderFederation(); }), button(translate('移除'), async () => {
    if (!await confirmAction(msg`移除「${remote.label}」？本面板会删除这个共享和它的密钥；对方节点上的规则不受影响，需要对方撤销。`)) return;
    await api(`/federation/remotes/${remote.id}`, { method: 'DELETE' }); notify(translate('已移除。')); await renderFederation();
  }, 'subtle danger'));
  const p = panel(msg`收到的共享 · ${remote.label}`, s ? msg`来自 ${remote.owner_url} · 连接 ${s.public_host} 端口 ${s.port_start}–${s.port_end}` : remote.owner_url, actions), body = el('div', undefined, 'panel-body');
  const status = el('div', undefined, 'badge-row');
  if (remote.revoked) status.append(badge(translate('对方已撤销'), 'red'));
  else if (s) status.append(badge(fedStates[s.state] || s.state, fedStateColors[s.state] || ''), badge(s.applied ? translate('对方节点已生效') : translate('对方节点更新中'), s.applied ? 'green' : 'orange'));
  if (remote.rollback) status.append(badge(translate('对方报告的流量变少了'), 'red'));
  body.append(status);
  if (remote.rollback) body.append(el('p', msg`对方报告的流量低于之前确认过的 ${bytes(remote.high.upload_bytes + remote.high.download_bytes)}，对方面板可能从旧备份恢复了数据。请和对方核对。`, 'error-text'));
  if (remote.last_error) body.append(el('p', remote.last_error, 'error-text'));
  if (s) {
    const host = s.public_host.includes(':') ? `[${s.public_host}]` : s.public_host;
    body.append(el('p', fedLimits(s), 'fine'));
    const usage = s.statement.upload_bytes + s.statement.download_bytes;
    body.append(el('p', s.quota_bytes ? msg`已用流量 ${bytes(usage)} · 额度已用 ${bytes(s.quota_used_bytes || 0)} / ${bytes(s.quota_bytes)}` : msg`已用流量 ${bytes(usage)}（上传 ${bytes(s.statement.upload_bytes)} · 下载 ${bytes(s.statement.download_bytes)}）`, 'fine'));
    if (!s.rules.length) body.append(el('p', open ? translate('还没有规则。点「＋ 规则」在共享的端口里建一条。') : translate('没有规则。'), 'muted'));
    else body.append(table([translate('名称'), translate('类型'), translate('连接地址'), translate('目标'), translate('操作')], s.rules.map(rule => {
      const ops = el('div');
      if (rule.kind === 'shadowsocks' && rule.password && !remote.revoked) ops.append(button(translate('复制链接'), async () => { await navigator.clipboard.writeText(shadowsocksLink({ method: '2022-blake3-aes-128-gcm', password: rule.password }, s.public_host, rule.port, rule.name)); notify(translate('链接已复制。')); }, 'table-action'));
      if (open) ops.append(button(translate('删除'), () => federationRules(remote, s.rules.filter(r => r.id !== rule.id), msg`删除规则「${rule.name}」？`), 'table-action danger'));
      return [rule.name, `${fedKinds[rule.kind] || rule.kind} · ${fedProtocols[rule.protocol] || rule.protocol}`, `${host}:${rule.port}`, (rule.targets || []).join(', ') || translate('由客户端决定'), ops];
    })));
  }
  body.append(el('p', remote.last_synced_ms ? msg`最近同步 ${timestamp(remote.last_synced_ms)}，每分钟自动同步。` : translate('每分钟自动同步。'), 'fine'));
  p.append(body);
  return p;
}
async function federationRules(remote, rules, question) {
  if (question && !await confirmAction(question)) return;
  await api(`/federation/remotes/${remote.id}/rules`, { method: 'PUT', body: { expected_revision: remote.shared.revision, rules: rules.map(r => ({ id: r.id, name: r.name, kind: r.kind, protocol: r.protocol, port: r.port, targets: r.targets || [] })) } });
  notify(translate('规则已提交，对方节点会自动更新。')); await renderFederation();
}
function federationRuleForm(remote) {
  const s = remote.shared, used = new Set(s.rules.map(r => r.port));
  if (s.rules.length >= s.max_rules) { modal(translate('添加规则'), empty(translate('规则数已达上限'), msg`这个共享最多 ${s.max_rules} 条规则。删除一条，或请对方提高上限。`)); return; }
  let free = s.port_start; while (used.has(free) && free < s.port_end) free++;
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'name', translate('规则名称'), '').maxLength = 64;
  const kind = select(grid, 'kind', translate('类型'), s.kinds.map(k => [k, fedKinds[k] || k]), s.kinds[0]);
  select(grid, 'protocol', translate('协议'), Object.entries(fedProtocols), 'tcp');
  const port = field(grid, 'port', msg`端口（${s.port_start}–${s.port_end}）`, free, 'number'); port.min = s.port_start; port.max = s.port_end;
  const targets = textarea(grid, 'targets', translate('目标地址（每行一个，主机:端口）'), '');
  const show = () => { targets.required = kind.value === 'forward'; targets.closest('label').hidden = kind.value !== 'forward'; }; kind.addEventListener('change', show); show();
  form.append(grid, el('p', translate('Shadowsocks 规则的密钥由对方面板生成；保存后可以复制 ss:// 链接给客户端。'), 'fine'));
  submit(form, translate('提交规则'), async data => {
    const rule = { name: String(data.get('name')).trim(), kind: kind.value, protocol: data.get('protocol'), port: number(data, 'port'), targets: kind.value === 'forward' ? String(data.get('targets') || '').split('\n').map(t => t.trim()).filter(Boolean) : [] };
    await api(`/federation/remotes/${remote.id}/rules`, { method: 'PUT', body: { expected_revision: s.revision, rules: [...s.rules.map(r => ({ id: r.id, name: r.name, kind: r.kind, protocol: r.protocol, port: r.port, targets: r.targets || [] })), rule] } });
    $('#dialog').close(); notify(translate('规则已提交，对方节点会自动更新。')); await renderFederation();
  });
  modal(msg`添加规则 · ${remote.label}`, form);
}
// Optional features start switched off; their settings stay out of forms until a system administrator switches them on.
const featureInfo = localize({
  mptcp: ['Linux MPTCP', '转发规则的入口或出口可以使用多路径 TCP（MPTCP）。两端都支持时，一条连接可以同时使用多条网络路径。', '开启后，规则编辑器显示“Linux MPTCP”设置。需要两端的 Linux 内核支持；要真正走多条路径，服务器还需要多个网卡或地址。'],
  'dns-health': ['DNS 健康摘除', '入口服务器失联或目标全部不可用时，自动从 DNS 移除它的解析记录，恢复后自动加回。', '开启后，DNS 记录表单显示健康摘除设置。只在“应用”模式的区域生效；剩余有效记录少于“最少保留”数量时，记录不会被移除。'],
  'budget-recovery': ['额度灾难恢复', '节点状态丢失或控制器从旧备份恢复后，核销无法再上报的预留，或结束旧备份留下的额度锁定。未知用量一律按已消耗计算。', '开启后，「恢复保护」页显示未结束的预留和恢复锁定。只有系统管理员可以操作，每次操作都写入审计日志。'],
  'mptcp-paths': ['MPTCP 额外路径', '为节点指定额外的本机地址，让 MPTCP 连接可以同时经过多块网卡或多个地址传输。', '开启后，节点资料显示“MPTCP 额外路径”。只有安装了授权文件的服务器才会真正修改 MPTCP 设置；服务器只有一个网卡和地址时没有效果。'],
  wireguard: ['WireGuard 组网', '把节点和用户设备连进同一个私有网络：节点之间自动配置 WireGuard 隧道，两台都在 NAT 后面的节点经一台公网节点中继，设备扫码即可加入。', '开启后，左侧出现「WireGuard 组网」页。只有安装了授权文件 relay-agent-wireguard.conf 和 wireguard-tools 的服务器才会创建接口；它只管理名为 rwg-* 的接口，不改默认路由、防火墙或系统全局设置。'],
  federation: ['跨面板共享', '把一台节点上的一段端口共享给另一个 Relay 面板，或接收其他面板共享的端口。对方用一次性邀请码接入，得到自己的密钥；带宽、流量、到期时间和允许的来源由共享方决定，对方无法放宽。', '开启后，左侧出现「跨面板共享」页。共享方的节点会多出由共享生成的规则，这些规则只能在共享页修改；撤销后节点立即删除它们，对方的密钥失效。接收方每分钟向共享方同步一次。'],
  'nat-traversal': ['NAT 穿透', '两台都在 NAT 后面的 WireGuard 节点先尝试直接连接（打洞）。成功后它们之间的流量不再经过中继；尝试失败或直连中断时自动回到中继，并显示原因。', '需要先开启「WireGuard 组网」。开启后，「WireGuard 组网」页的连接表显示每对节点是直连、正在尝试还是经中继。只对两端都没有公网端点的节点生效，不修改服务器的防火墙或系统设置。对方的 NAT 为每个目标换端口（对称型 NAT）时无法直连，会继续经中继。'],
  'dns-authoritative': ['独立权威 DNS 池', '让你自己的节点直接应答一个域名的 DNS 查询，解析结果随入口健康实时变化，不需要 DNS 服务商 API。', '开启后，「DNS 管理」页显示权威 DNS 池。节点要监听 53 端口，需先在服务器安装授权文件 relay-agent-dns.conf 并放行防火墙；还要在域名注册商把域名委派给这些节点。'],
  'plan-entitlements': ['套餐权益', '支付成功的套餐订单自动变成购买者的流量额度：套餐流量加到额度上，到期后停止发放新流量，退款扣回该订单的流量和天数。', '开启后，「钱包与订单」显示“我的套餐”。开启前已经付款的订单不会补发。购买者还有运行中的规则时，需要先停用规则，额度才能创建。'],
});
const featureUsage = { mptcp: n => msg`${n} 条转发规则正在使用 MPTCP`, 'dns-health': n => msg`${n} 条 DNS 记录正在使用健康摘除`, 'plan-entitlements': n => msg`${n} 个套餐生效中或等待额度`, 'mptcp-paths': n => msg`${n} 个节点设置了 MPTCP 额外路径`, 'dns-authoritative': n => msg`${n} 个区域在权威 DNS 池中`, wireguard: n => msg`${n} 个 WireGuard 网络`, federation: n => msg`${n} 个共享（给出未撤销的和收到的）` };
const featureOn = id => !!state.features[id];
async function loadFeatures() { const list = await api('/features'); state.features = Object.fromEntries(list.map(f => [f.id, f.enabled])); document.querySelectorAll('[data-feature]').forEach(n => n.classList.toggle('feature-off', !featureOn(n.dataset.feature))); return list; }
async function renderFeatures() {
  const actor = state.actor, list = await loadFeatures();
  if (state.view !== 'features' || state.actor !== actor) return;
  const p = panel(translate('可选功能'), translate('这些功能默认关闭。开启后，相关设置才会出现在面板里；关闭前需要先移除正在使用它的设置。这里的开关只改变面板，不会修改服务器的系统设置。'));
  const body = el('div', undefined, 'feature-list');
  for (const f of list) {
    const [name, about, effect] = featureInfo[f.id] || [f.id, '', ''], row = el('article', undefined, `feature-row${f.enabled ? ' on' : ''}`), text = el('div', undefined, 'feature-text'), title = el('h3', name);
    title.append(badge(f.enabled ? translate('已开启') : translate('未开启'), f.enabled ? 'green' : ''));
    text.append(title, el('p', about), el('p', effect, 'fine'));
    if (f.in_use) text.append(el('p', featureUsage[f.id]?.(f.in_use) ?? String(f.in_use), 'feature-usage'));
    const toggle = button(f.enabled ? translate('关闭此功能') : translate('开启此功能'), async () => {
      await api(`/features/${f.id}`, { method: 'PUT', body: { enabled: !f.enabled } });
      notify(f.enabled ? msg`已关闭「${name}」` : msg`已开启「${name}」`); await renderFeatures();
    }, f.enabled ? 'subtle' : 'primary');
    toggle.setAttribute('aria-label', `${f.enabled ? translate('关闭此功能') : translate('开启此功能')} ${name}`);
    row.append(text, toggle); body.append(row);
  }
  p.append(body);
  $('#content').replaceChildren(p);
}
async function renderCapabilities() { const actor = state.actor; const c = await api('/capabilities'); if (state.view !== 'capabilities' || !actor || state.actor !== actor) return; const names = { 'two-factor-login': translate('两步验证登录'), 'scoped-api-tokens': translate('带权限范围的 API 令牌'), 'node-identity-revocation-replacement': translate('节点身份撤销与替换'), 'node-credential-rotation': translate('节点凭据轮换'), announcements: translate('公告'), ddns: 'DDNS', tcp: translate('TCP 转发'), udp: translate('UDP 转发'), ipv4: 'IPv4', ipv6: 'IPv6', 'dns-targets': translate('域名目标'), 'port-ranges': translate('端口段与偏移映射'), 'outbound-binding': translate('业务出口 IP / 网卡绑定'), 'dns-ttl-cache': translate('目标 DNS TTL 缓存'), 'node-local-loop-protection': translate('节点内监听环路检查'), 'proxy-protocol-tcp-v1-v2': 'TCP PROXY v1 / v2', 'proxy-protocol-udp-v2': 'UDP PROXY v2', 'udp-destination-tracking': translate('UDP 通配监听真实目标地址'), 'weighted-round-robin': translate('加权轮询'), 'source-hash': translate('来源 IP 哈希'), 'least-connections': translate('最少连接'), 'source-cidr-acl': translate('来源网段 ACL'), 'per-rule-quota': translate('规则共享配额'), 'per-rule-bandwidth': translate('规则共享速率'), 'durable-usage': translate('持久化流量账本'), 'config-revisions': translate('版本与回滚'), 'tenant-isolation': translate('租户隔离'), 'session-revocation': translate('会话撤销'), 'tls-data-transport': translate('TLS 数据传输'), 'mutual-tls': translate('TLS 双向证书认证'), 'backup-reconciliation': translate('旧备份用量对账'), websocket: translate('WebSocket 流隧道（v1）'), 'secure-websocket': translate('WSS 与双向证书验证'), 'declared-multi-node-topology': translate('跨节点多跳引用与环路检查'), 'atomic-config-batch': translate('多节点配置预览与事务发布'), 'target-health-checks': translate('目标探测与故障恢复'), 'priority-capacity-selection': translate('优先级与目标容量选路'), 'lowest-latency-selection': translate('按探测耗时自动选择最快目标'), 'node-telemetry': translate('节点资源、吞吐与事件历史'), 'connection-history': translate('逐段真实连接与 7 天历史'), 'live-logs': translate('实时日志'), 'diagnostic-report': translate('诊断报告与问题检查'), 'connection-prewarm': translate('中转间预热连接'), 'alert-notifications': translate('告警通知（Webhook / Telegram / 企业微信 / 飞书 / 钉钉）'), 'smtp-alerts': translate('Email / SMTP 告警（TLS / STARTTLS）'), 'tenant-alerts': translate('按租户隔离通知与事件'), mptcp: 'MPTCP', 'node-execution-leases': translate('节点执行租约'), 'node-inventory-lifecycle': translate('节点资料、批量编辑与暂停到期'), 'durable-budget-run-recovery': translate('原状态额度恢复与预留诊断'), 'multipath-aggregation': translate('单连接多路径聚合（自有 v1）'), 'global-user-budgets': translate('跨节点用户总额度'), 'hierarchical-budgets': translate('租户 / 节点分层额度'), 'budget-reservation-return': translate('空闲预留归还'), 'controller-recovery-log': translate('控制器恢复日志'), 'budget-disaster-recovery': translate('预算完整灾难恢复'), 'global-rate-limits': translate('跨节点总限速'), wireguard: translate('WireGuard 组网'), 'nat-traversal': translate('NAT 穿透'), commerce: translate('套餐与交易'), tickets: translate('支持工单'), 'commerce-wallet': translate('钱包与资金流水'), 'commerce-orders': translate('订单与退款'), 'commerce-payments': translate('支付网关与回调验签'), 'commerce-coupons': translate('优惠码'), 'commerce-gifts': translate('礼品码'), 'http-connect': translate('HTTP CONNECT 入站'), 'http2-connect-managed': translate('HTTP/2 CONNECT · 计量 / ACL / 限速 / Bearer'), 'protocol-gateways': translate('受管 VLESS / Reality / Hysteria2 / TUIC / AnyTLS / Trojan / VMess'), 'protocol-client-exports': translate('sing-box / mihomo 协议订阅'), 'destination-acl': translate('目的地 ACL'), 'config-templates': translate('规则模板'), 'mptcp-diagnostics': translate('MPTCP 能力观测'), 'mptcp-rule-transport': translate('MPTCP 规则传输与连接观测'), 'nat-pmp': translate('NAT-PMP 端口映射'), 'pcp': translate('PCP 端口映射'), 'upnp': translate('UPnP 端口映射'), 'commerce-entitlements': translate('套餐权益执行'), 'client-subscriptions': translate('客户端订阅'), announcements: translate('公告'), 'dns-records': translate('DNS 托管记录与 DDNS'), 'dns-health-removal': translate('DNS 健康摘除'), 'dns-authoritative-pool': translate('独立权威 DNS 池'), 'dns-management': translate('DNS 管理'), federation: translate('跨面板共享'), 'postgresql-ha': translate('PostgreSQL 与控制面高可用') }; const deliveryNotes = localize({ 'nat-pmp': 'CLI 工具 · 需要网关支持', pcp: 'CLI 工具 · 需要网关支持', upnp: 'CLI 工具 · 需要网关支持', 'protocol-gateways': '需在节点预装协议引擎', 'tls-data-transport': '需在节点配置证书', 'mutual-tls': '需在两端配置证书', 'smtp-alerts': '需配置并验证 SMTP', 'commerce-payments': '支付不在本轮交付范围', mptcp: '额外路径需服务器授权 · 公网多线路未验收', 'dns-authoritative-pool': '53 端口需服务器授权 · 需在注册商委派 · 公网委派未验收', wireguard: '需安装 wireguard-tools 并授予服务器权限 · 真实 NAT 与公网未验收', 'nat-traversal': '需先开启 WireGuard 组网 · 对称型 NAT 无法直连 · 真实 NAT 未验收', federation: '共享方面板需能被对方用 HTTPS 访问 · 两个真实面板之间未验收' }); const grid = el('div', undefined, 'capabilities'); for (const [title, list, status, color] of [[translate('已接入开发版本'), c.available, translate('已实现'), 'green'], [translate('后续完整范围'), c.pending, translate('待完成或验收'), '']]) { const p = panel(title, translate('最终验收以源码中的完整清单和测试证据为准。')), body = el('div', undefined, 'panel-body'); for (const key of list) { const row = el('div', undefined, 'capability'); row.append(el('span', names[key] || key), badge(key === 'commerce-payments' ? translate('本轮不含') : status, key === 'commerce-payments' ? '' : color)); const switchable = { 'mptcp-rule-transport': 'mptcp', 'dns-health-removal': 'dns-health', 'commerce-entitlements': 'plan-entitlements', 'budget-disaster-recovery': 'budget-recovery', mptcp: 'mptcp-paths', 'dns-authoritative-pool': 'dns-authoritative', wireguard: 'wireguard', 'nat-traversal': 'nat-traversal', federation: 'federation' }[key]; if (switchable) row.append(badge(featureOn(switchable) ? translate('已开启') : translate('未开启'), featureOn(switchable) ? 'green' : '')); if (deliveryNotes[key]) row.append(el('span', deliveryNotes[key], 'fine')); body.append(row); } p.append(body); grid.append(p); } if (state.view === 'capabilities') $('#content').replaceChildren(grid); }

// Skip while typing in the page so a re-render does not take the input away.
setInterval(() => { const typing = $('#content').contains(document.activeElement) && document.activeElement.matches('input, select, textarea'); if (state.actor && !document.hidden && !typing && !document.querySelector('dialog[open]') && !document.body.classList.contains('nav-open') && ['overview', 'nodes', 'rules', 'usage', 'budgets', 'alerts', 'recovery', 'topology', 'health', 'logs'].includes(state.view)) refresh().catch(e => notify(e.message, true)); }, 5000);
if (state.token) { api('/session').then(user => { state.actor = user; return enter(); }).catch(e => { loggedOut(); $('#login-error').textContent = e.message; }); }

const budgetScopeNames = localize({ user: '用户', tenant: '租户', node: '节点' });
async function renderBudgets() {
  const actor = state.actor;
  const [overview, users, nodes] = await Promise.all([api('/budgets'), api('/users'), api('/nodes')]);
  if (state.view !== 'budgets' || !actor || state.actor !== actor) return;
  const p = panel(translate('跨节点共享额度'), translate('已用 + 尚未归还的预留不能超过总额度。同一笔流量受适用的用户、租户和节点额度共同约束。'), canWrite() && !overview.allocation_paused ? button(translate('＋ 创建额度'), () => editBudget(null, users, nodes), 'primary') : null);
  if (overview.allocation_paused) p.append(el('p', translate('控制器已从备份恢复，新增额度分配暂停。恢复完整的预留记录前，系统不会重复发放旧备份中遗漏的额度。'), 'error'));
  function scopeLabel(b) { return b.scope === 'user' ? users.find(u => u.id === b.scope_id)?.username || b.scope_id : b.scope === 'node' ? nodes.find(n => n.id === b.scope_id)?.name || b.scope_id : b.scope_id; }
  if (!overview.budgets.length) p.append(empty(translate('为多个入口设置一个总额度'), translate('创建前先暂停该范围内的规则，并确认所有相关节点已应用；之后重新启用规则，系统会自动绑定额度。')));
  else if (displayMode('budgets') === 'chart') {
    // Each bar is the budget's own limit: used, then reserved but not yet returned, then still available.
    const body = el('div', undefined, 'panel-body chart-body'), parts = [[translate('已上报用量'), 'teal'], [translate('尚未归还预留'), 'partial'], [translate('可分配'), 'free']];
    body.append(barChart(overview.budgets.map(b => {
      const reserved = b.committed_bytes - b.consumed_bytes, available = b.limit_bytes - b.committed_bytes;
      return { label: b.name, detail: `${budgetScopeNames[b.scope]} · ${scopeLabel(b)}`, values: [b.consumed_bytes, reserved, available], max: b.limit_bytes || 1,
        text: msg`已占用 ${b.limit_bytes ? Math.round(100 * b.committed_bytes / b.limit_bytes) : 100}% · 共 ${bytes(b.limit_bytes)}`, title: msg`已上报用量 ${bytes(b.consumed_bytes)} · 尚未归还预留 ${bytes(reserved)} · 可分配 ${bytes(available)}`,
        actions: budgetActions(b, users, nodes, overview.allocation_paused) };
    }), parts));
    p.append(body);
  } else p.append(table([translate('名称 / 范围'), translate('总额度'), translate('已上报用量'), translate('尚未归还预留'), translate('可分配'), translate('操作')], overview.budgets.map(b => [namedCell(b.name, `${budgetScopeNames[b.scope]} · ${scopeLabel(b)}`), bytes(b.limit_bytes), bytes(b.consumed_bytes), bytes(b.committed_bytes - b.consumed_bytes), bytes(b.limit_bytes - b.committed_bytes), budgetActions(b, users, nodes, overview.allocation_paused)])));
  p.append(el('p', translate('节点按需领取预留。全节点会话空闲或正常停机后可归还未用部分；严格节点保留原状态且交接历史连续时，重启会先核对并恢复预留；旧备份或无法确认的部分继续占额。预留明细显示当前记录，增加总额度不会清零已有账。'), 'fine'));
  const toolbar = el('div', undefined, 'toolbar view-toolbar'); toolbar.append(displayToggle('budgets', renderBudgets));
  if (state.view === 'budgets') { $('#page-tools').replaceChildren(...(overview.budgets.length ? toolbar.childNodes : [])); $('#content').replaceChildren(p); }
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
      !row.node_lease.policy ? translate('可用优先') : row.node_lease.active && row.node_lease.holder_run_id === row.run_id ? translate('当前运行持有租约') : translate('当前无此运行租约')
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

const runFences = localize({ current: ['使用中', 'green'], waiting: ['等待交接窗口', 'orange'], fenced: ['已停止', ''], unconfirmed: ['需要确认已停止', 'orange'] });
const recoveryKinds = localize({ write_off: '核销运行', quarantine_exit: '结束恢复锁定' });
function writeOffRun(run) {
  const form = el('form'), grid = el('div', undefined, 'form-grid'), operation = crypto.randomUUID();
  form.append(el('p', msg`「${run.node_name}」的这次运行还有 ${run.reservations} 个未结束的预留，共 ${bytes(run.outstanding_bytes)} 未确认用量。核销后这些字节全部按已消耗计算，不会退回；之后由这台节点的新运行重新申请额度。`, 'workflow-callout'));
  field(grid, 'reason', translate('原因（写入审计日志）'), '').maxLength = 500;
  if (run.fence === 'unconfirmed') select(grid, 'stopped', translate('这台节点没有执行租约，面板无法确认旧进程已停止'), [['no', translate('请选择')], ['yes', translate('我确认这次运行的 Agent 进程已经停止')]], 'no');
  form.append(grid);
  submit(form, translate('核销并按已消耗计算'), async data => {
    if (run.fence === 'unconfirmed' && data.get('stopped') !== 'yes') throw new Error(translate('请先确认这次运行的 Agent 进程已经停止'));
    const receipt = await api(`/recovery/budgets/runs/${run.node_id}/write-off`, { method: 'POST', body: { operation_id: operation, run_id: run.run_id, reason: String(data.get('reason')).trim(), stopped_confirmed: data.get('stopped') === 'yes' } });
    $('#dialog').close(); notify(msg`已核销 ${receipt.reservations} 个预留，共 ${bytes(receipt.bytes)}。`); await renderRecovery();
  });
  modal(msg`核销运行 · ${run.node_name}`, form);
}
function exitQuarantine(view) {
  const form = el('form'), grid = el('div', undefined, 'form-grid'), operation = crypto.randomUUID(), total = view.budgets.reduce((sum, b) => sum + b.assumed_bytes, 0);
  form.append(el('p', msg`备份之后发放的预留无法得知。结束锁定会把每个额度剩余的空间按已用计算，合计 ${bytes(total)}；之后需要更多额度时，在「共享额度」调高上限。`, 'workflow-callout'));
  form.append(table([translate('额度'), translate('上限'), translate('已承诺'), translate('按已用计算')], view.budgets.map(b => [b.name, bytes(b.limit_bytes), bytes(b.committed_bytes), bytes(b.assumed_bytes)])));
  field(grid, 'reason', translate('原因（写入审计日志）'), '').maxLength = 500;
  form.append(grid);
  submit(form, translate('结束锁定并按已用计算'), async data => {
    const receipt = await api('/recovery/budgets/quarantine/exit', { method: 'POST', body: { operation_id: operation, reason: String(data.get('reason')).trim(), budgets: view.budgets.map(b => ({ id: b.id, expected_revision: b.revision })) } });
    $('#dialog').close(); notify(msg`恢复锁定已结束，${bytes(receipt.bytes)} 按已用计算。`); await renderRecovery();
  });
  modal(translate('结束恢复锁定'), form);
}
function budgetRecoveryPanel(view) {
  const p = panel(translate('额度灾难恢复'), translate('节点状态丢失或控制器从旧备份恢复后，在这里处理无法再上报的预留。未知用量一律按已消耗计算，不会退回；需要更多额度时由管理员调高上限。'));
  const body = el('div', undefined, 'panel-body');
  if (view.allocation_paused) {
    const total = view.budgets.reduce((sum, b) => sum + b.assumed_bytes, 0), actions = el('div', undefined, 'panel-actions');
    actions.append(button(translate('结束恢复锁定'), () => exitQuarantine(view), 'primary'));
    body.append(el('p', msg`控制器从旧备份恢复，已暂停发放新额度。结束锁定会把剩余空间按已用计算（合计 ${bytes(total)}）。`, 'workflow-callout'), actions);
  } else body.append(badge(translate('额度分配正常'), 'green'));
  body.append(el('h3', translate('未结束的预留')), el('p', translate('每台节点的每次运行一行。“使用中”是正在工作的运行；节点换盘、重装或身份替换后留下的旧运行，可以在这里核销。'), 'fine'));
  if (!view.runs.length) body.append(el('p', translate('没有未结束的预留。'), 'muted'));
  else body.append(table([translate('节点'), translate('运行'), translate('预留'), translate('未确认用量'), translate('状态'), translate('操作')], view.runs.map(run => {
    const [label, color] = runFences[run.fence] || [run.fence, ''], actions = el('div');
    if (['fenced', 'unconfirmed'].includes(run.fence)) actions.append(button(translate('核销'), () => writeOffRun(run), 'table-action danger'));
    return [run.node_name, el('span', run.run_id, 'mono'), String(run.reservations), bytes(run.outstanding_bytes), badge(run.fence === 'waiting' ? msg`${label} · ${Math.ceil(run.wait_ms / 1000)} 秒` : label, color), actions];
  })));
  if (view.receipts.length) body.append(el('h3', translate('恢复记录')), table([translate('时间'), translate('操作'), translate('对象'), translate('字节'), translate('原因')], view.receipts.map(r => [timestamp(r.at_ms), recoveryKinds[r.kind] || r.kind, r.node_id ? `${state.nodes.find(n => n.id === r.node_id)?.name || r.node_id} · ${r.run_id}` : msg`${r.reservations} 个额度`, bytes(r.bytes), r.reason])));
  p.append(body);
  return p;
}
async function renderRecovery() {
  const actor = state.actor, recovering = featureOn('budget-recovery');
  const [status, metrics, budgetView] = await Promise.all([api('/recovery'), api('/control/metrics'), recovering ? api('/recovery/budgets') : null]);
  if (state.view !== 'recovery' || !actor || state.actor !== actor) return;
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
  p.append(body); if (state.view === 'recovery') $('#content').replaceChildren(...(budgetView ? [budgetRecoveryPanel(budgetView), p] : [p]));
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
  paused: '全部目标都已暂停，新连接会被拒绝。',
});
// A paused target takes no new sessions; a timed pause ends on the agent's clock.
function targetPaused(target, now = Date.now()) { return !!target.paused && (target.paused_until_ms == null || now < target.paused_until_ms); }
function pauseLabel(until) { return until ? msg`暂停至 ${new Date(until).toLocaleString(getLanguage(), { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}` : translate('已暂停'); }
// The rule table's note on paused targets, or '' when none is paused.
function pausedTargets(rule) {
  const paused = rule.targets.filter(t => targetPaused(t));
  if (!paused.length) return '';
  if (rule.targets.length === 1) return pauseLabel(paused[0].paused_until_ms);
  return paused.length === rule.targets.length ? translate('全部目标已暂停') : msg`${paused.length} 个目标已暂停`;
}
function forwardingPathView(options = {}) {
  const box = el('section', undefined, 'forwarding-diagram'); box.setAttribute('aria-label', translate('转发路径预览'));
  let cards = [];
  const focusNode = ref => {
    const card = cards.find(card => card.dataset.flowKey === topologyKey(ref));
    card?.scrollIntoView({ block: 'nearest', inline: 'nearest' }); card?.focus({ preventScroll: true });
  };
  const protocols = { tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' };
  const services = localize({ forward: '端口转发', ss: 'Shadowsocks 服务', socks5: 'SOCKS5 服务', http: 'HTTP CONNECT 服务', h2: 'HTTP/2 CONNECT 服务', gateway: '受管协议服务' });
  const roles = localize({ entry: '入口 VPS', relay: '中转 VPS', exit: '出口 VPS', single: '运行 VPS · 入口与出口' });
  function update(model, stage = 'draft') {
    const active = document.activeElement, focusedKey = cards.includes(active) ? active.dataset.flowKey : null;
    const oldTrack = box.querySelector('.flow-track'), scrollLeft = oldTrack?.scrollLeft || 0;
    cards = [];
    box.replaceChildren();
    const heading = el('div', undefined, 'flow-heading');
    heading.append(el('h3', translate('转发路径预览')), badge(stage === 'validated' ? translate('服务器配置校验通过') : stage === 'saved' ? translate('已保存的期望路径') : translate('草稿 · 随编辑更新'), stage === 'validated' ? 'green' : ''));
    const figure = el('figure', undefined, 'flow-figure'), track = el('div', undefined, 'flow-track'); track.tabIndex = 0; track.setAttribute('aria-label', translate('路径图（可滚动）'));
    const client = el('div', undefined, 'flow-card flow-terminal'); client.append(el('span', translate('连接起点'), 'flow-role'), el('strong', translate('客户端 / 上游')), el('p', translate('连接入口地址'), 'fine'));
    // Each label part gets its own line so narrow arrows never split a phrase such as "TCP + UDP".
    function edge(parts) { const arrow = el('div', undefined, 'flow-edge'); for (const part of [parts].flat()) arrow.append(el('span', part)); arrow.append(el('span', '→', 'flow-arrow')); arrow.lastChild.setAttribute('aria-hidden', 'true'); return arrow; }
    function tree(item) {
      const editable = item.kind === 'node' && options.onSelect && (!options.canSelect || options.canSelect(item));
      const wrap = el('div', undefined, 'flow-route'), card = editable ? button('', () => options.onSelect(item), 'flow-card flow-selectable') : el('div', undefined, 'flow-card');
      if (item.kind === 'target') { card.classList.add('flow-terminal'); card.append(el('span', translate('最终目标 / 外部服务'), 'flow-role'), el('strong', item.address || translate('待填写'), 'mono'), el('p', translate('手动地址；不推断后续 VPS 或代理服务。'), 'fine')); wrap.append(card); return wrap; }
      if (item.kind === 'unresolved') { card.append(el('strong', item.name || translate('待选择')), el('p', diagramIssues[item.reason], 'fine')); wrap.append(card); return wrap; }
      card.classList.toggle('flow-service', item.service !== 'forward');
      card.append(el('span', roles[item.role], 'flow-role'), el('strong', item.name), el('span', services[item.service], 'flow-service-label'));
      const addresses = el('dl', undefined, 'flow-addresses');
      addresses.append(el('dt', translate('连接地址')), el('dd', item.endpoint || translate('待填写'), 'mono'), el('dt', translate('本机监听')), el('dd', item.listen || translate('待填写'), 'mono'));
      card.append(addresses, el('p', item.service === 'forward' ? translate('本规则由 Agent 转发流量，不启用 SS 服务。') : item.service === 'gateway' ? translate('协议引擎在此 VPS 终止代理连接。') : translate('Agent 内置服务在此 VPS 处理代理连接。'), 'fine'));
      if (item.uot) card.append(badge('UDP over TCP'));
      if (editable) {
        card.dataset.flowKey = topologyKey(item); cards.push(card);
        const selected = options.selected?.(), current = selected && topologyKey(selected) === topologyKey(item);
        card.classList.toggle('flow-selected', !!current); card.setAttribute('aria-pressed', String(!!current));
        card.setAttribute('aria-label', msg`编辑 ${roles[item.role]} · ${item.name}`);
        card.append(el('span', current ? translate('已选择 · 正在编辑') : translate('点击编辑此跳'), 'flow-edit-hint'));
      }
      wrap.append(card);
      if (item.service !== 'forward') {
        const destination = el('div', undefined, 'flow-card flow-terminal'); destination.append(el('span', translate('最终目的地'), 'flow-role'), el('strong', translate('客户端请求的网站 / 服务')), el('p', translate('出口 VPS 发起连接；受目的地 ACL 限制。'), 'fine'));
        wrap.append(edge(translate('出口连接')), destination);
      } else if (item.children.length) {
        const branches = el('div', undefined, 'flow-branches');
        if (item.children.length > 1) branches.append(el('p', item.aggregate ? translate('并行子流 · 汇聚到同一规则') : translate('候选目标 · 按策略选择，不是顺序中转'), 'flow-branch-label'));
        for (const child of item.children) {
          const branch = el('div', undefined, 'flow-branch');
          const label = [protocols[child.protocol] || '—', child.transport].filter(Boolean);
          if (item.children.length > 1 && !item.aggregate) label.push(`${translate('权重')} ${child.weight}`, `${translate('优先级')} ${child.priority}`);
          if (child.draining) label.push(translate('维护排空'));
          if (child.paused) label.push(pauseLabel(child.pausedUntil));
          branch.append(edge(label), tree(child.next)); branches.append(branch);
        }
        wrap.append(branches);
      }
      return wrap;
    }
    // Gateway `protocol` describes proxied payloads, not its client wire transport.
    track.append(client, edge(model.root.service === 'gateway' ? translate('受管协议接入') : [protocols[model.root.protocol] || '—', model.root.inboundTransport].filter(Boolean)), tree(model.root));
    figure.append(track, el('figcaption', translate('箭头表示期望转发方向，响应沿连接返回。图示不证明防火墙、网络或业务已经连通。')));
    const checks = el('ol', undefined, 'flow-checks');
    for (const [title, text] of [[translate('配置检查'), stage === 'validated' ? translate('服务器校验通过；尚未发布此草稿。') : stage === 'saved' ? translate('显示控制器中的期望配置。') : translate('填写后校验；尚未验证完整配置。')], [translate('Agent 应用'), translate('发布后逐跳确认实际修订与期望修订一致。')], [translate('真实流量'), translate('尚未测试；用真实客户端从入口验证 TCP、UDP 和出口地址。')]]) { const item = el('li'); item.append(el('strong', title), el('span', text)); checks.append(item); }
    box.append(heading, figure, checks);
    if (cards.length) {
      heading.append(el('span', stage === 'validated' ? translate('点击 VPS 卡片返回编辑，修改后重新预览。') : translate('点击 VPS 卡片编辑此跳；也支持 Tab 与 Enter。'), 'fine'));
      track.scrollLeft = scrollLeft;
      if (focusedKey) cards.find(card => card.dataset.flowKey === focusedKey)?.focus({ preventScroll: true });
    }
    if (model.issues.length) {
      const warnings = el('details', undefined, 'flow-warnings');
      warnings.append(el('summary', msg`需要检查 ${model.issues.length} 项`));
      const list = el('ul'); for (const issue of model.issues) list.append(el('li', (issue.name ? issue.name + ': ' : '') + diagramIssues[issue.code])); warnings.append(list); box.append(warnings);
    }
    const help = el('details'); help.append(el('summary', translate('如何理解与验证这条路径')));
    help.append(el('p', translate('入口协议、节点间传输和出口服务是不同层。SS 路径的客户端使用入口地址及出口密钥；只有标为 Shadowsocks 服务的 VPS 处理 SS，其余节点转发流量。')),
      el('p', translate('每个 VPS 都需要 Agent。监听地址属于该 VPS；连接地址必须能被客户端或上一跳访问。检查每跳端口、防火墙和来源 ACL；发布不会自动开放端口。')),
      el('p', translate('配置校验检查规则结构、引用和修订，不会发送网络探测。发布后在「转发规则」检查 Agent 回执，再从入口运行真实客户端；目标健康探测只能证明所配置的探测条件。')));
    box.append(help);
  }
  return { box, update, focusNode };
}
async function editDiagramRule(ref) {
  if (!canWrite()) return;
  const [nodes, config] = await Promise.all([api('/nodes'), api(`/nodes/${ref.node_id}/config`)]);
  const rule = config.rules.find(rule => rule.id === ref.rule_id);
  if (!rule || !nodes.some(node => node.id === ref.node_id)) throw new Error(translate('此规则已变化，请刷新路径后重试。'));
  if (rule.id.startsWith('fed-')) throw new Error(translate('这条规则由跨面板共享生成，请在「跨面板共享」页管理。'));
  state.nodes = nodes; state.selectedNode = ref.node_id; state.config = config;
  await editRule(rule);
}
async function renderTopology() {
  const actor = state.actor;
  const [snapshot, recent, sharedRules, groups, chains, tunnels] = await Promise.all([api('/topology'), monitoringHistory('1h'), api('/shared-rules'), api('/endpoint-groups'), api('/chains'), api('/reverse-tunnels')]);
  if (state.view !== 'topology' || !actor || state.actor !== actor) return;
  const chainUses = new Map(chains.flatMap(chain => chain.uses.map(use => [`${use.entry_node_id}/${use.entry_rule_id}`, { chain, use }])));
  const names = new Map(snapshot.nodes.map(node => [node.id, node.name])), byId = new Map(snapshot.nodes.map(node => [node.id, node])), health = targetHealth(snapshot), conns = hopTotals(recent);
  const rules = new Map(snapshot.configs.flatMap(config => config.rules.map(rule => [`${config.node_id}/${rule.id}`, rule])));
  const roots = forwardingRootsWithoutTunnels(snapshot), ids = new Set();
  const actions = el('div');
  if (canWrite() && roots.length) actions.append(button(translate('批量编辑'), () => editTopologyBatch(snapshot)));
  const p = panel(translate('从客户端到目标'), translate('每一行是一条完整转发：客户端连接入口，经过一台或多台服务器到达目标。展开可查看路径图，点击图中的服务器即可编辑那一段。'), actions);
  if (!roots.length) p.append(empty(translate('还没有转发'), translate('新建一条转发：可以只用一台服务器，也可以经过多台服务器。发布后，这里按规则引用自动组成完整路线。'), canWrite() ? button(translate('＋ 新建转发'), chooseSetup, 'primary') : null));
  const pageSize = 20, open = state.openPaths ||= new Set(), list = el('div', undefined, 'path-list');
  state.pathPage = Math.min(state.pathPage || 0, Math.max(0, Math.ceil(roots.length / pageSize) - 1));
  for (const root of roots.slice(state.pathPage * pageSize, (state.pathPage + 1) * pageSize)) {
    const model = forwardingDiagram(snapshot, root), members = new Map(), key = topologyKey(root), rule = rules.get(key);
    function collect(item) {
      if (item.kind !== 'node') return;
      members.set(`${item.node_id}/${item.rule_id}`, item); ids.add(item.node_id);
      item.children.forEach(child => collect(child.next));
    }
    collect(model.root);
    const nodeIds = [...new Set([...members.values()].map(item => item.node_id))];
    const card = el('article', undefined, 'path-summary'), head = el('div', undefined, 'path-summary-head'), title = el('div', undefined, 'path-title');
    const tags = el('div', undefined, 'path-tags');
    tags.append(badge(nodeIds.length > 1 ? msg`多跳 · ${nodeIds.length} 台服务器` : translate('单台服务器')), badge({ tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' }[model.root.protocol] || '—'));
    if (rule && !rule.enabled) tags.append(badge(translate('已停用'), 'orange'));
    if (model.issues.length) tags.append(badge(msg`需要检查 ${model.issues.length} 项`, 'orange'));
    const origin = chainUses.get(key);
    if (origin) tags.append(badge(msg`转发链 · ${origin.chain.name}`, 'blue'), ...(origin.use.out_of_date ? [badge(translate('组成员已变化'), 'orange')] : []));
    title.append(el('h3', rule?.name || translate('转发路径')), tags);
    const tools = el('div', undefined, 'path-actions');
    if (canWrite()) tools.append(button(nodeIds.length > 1 ? translate('编辑入口') : translate('编辑'), () => editDiagramRule(root), 'table-action'));
    const path = shadowsocksPath(snapshot, root);
    if (path) tools.append(button(translate('客户端链接'), () => shareShadowsocks(path.exit, path.entry, path.hops.map(hop => names.get(hop.node_id)).join(' → ')), 'table-action'));
    if (canWrite()) tools.append(button(rule?.enabled ? translate('停用') : translate('启用'), () => changeTopologyComponent(snapshot, key, !rule?.enabled), 'table-action'));
    if (canWrite() && !root.rule_id.startsWith('fed-')) tools.append(button(translate('删除'), () => deleteForwarding(snapshot, root), 'table-action danger'));
    head.append(title, tools); card.append(head, routeChips(model, health, byId, conns));
    const details = el('details', undefined, 'path-details'); details.open = open.has(key);
    details.addEventListener('toggle', () => details.open ? open.add(key) : open.delete(key));
    details.append(el('summary', translate('路径图、检查项与各段规则')));
    const view = forwardingPathView({ onSelect: canWrite() ? editDiagramRule : null }); view.update(model, 'saved'); details.append(view.box);
    // Loaded when the row is first opened, then on each refresh while it stays open.
    const historyBox = el('div', undefined, 'hop-history-box'), loadHistory = () => { if (details.open) hopHistory(historyBox, model, rule?.name).catch(error => historyBox.replaceChildren(el('p', error.message, 'fine'))); };
    details.addEventListener('toggle', loadHistory); loadHistory(); details.append(historyBox);
    const nodeActions = el('div', undefined, 'path-node-actions');
    nodeActions.append(el('span', translate('按服务器查看各段规则：'), 'fine'));
    for (const id of nodeIds) nodeActions.append(button(names.get(id) || id, async () => { state.selectedNode = id; await navigate('rules'); }, 'subtle'));
    details.append(nodeActions); card.append(details); list.append(card);
  }
  p.append(list);
  if (roots.length > pageSize) {
    const pager = el('div', undefined, 'toolbar pager');
    const previous = button(translate('上一页'), () => { state.pathPage--; return renderTopology(); }); previous.disabled = state.pathPage === 0;
    const next = button(translate('下一页'), () => { state.pathPage++; return renderTopology(); }); next.disabled = (state.pathPage + 1) * pageSize >= roots.length;
    pager.append(previous, el('span', msg`第 ${state.pathPage + 1} 页 · 共 ${roots.length} 条路径`), next); p.append(pager);
  }
  const status = panel(translate('节点应用状态'), translate('配置在控制器一次提交，各节点异步应用。修订一致不代表业务探测成功；改向前需停用相关链路，并确认涉及节点的全部活跃会话归零。'));
  status.append(table([translate('节点'), translate('实际 / 期望修订'), translate('活跃 TCP / UDP'), translate('回报'), translate('应用结果')], snapshot.nodes.filter(node => ids.has(node.id)).map(node => [node.name, `${node.applied_revision} / ${node.desired_revision}`, online(node) ? `${node.stats.active_tcp} / ${node.stats.active_udp}` : '—', timestamp(node.last_seen_ms), node.apply_error || applicationBadge(node).textContent])));
  if (state.view === 'topology') $('#content').replaceChildren(forwardingTabs('topology', roots.length), p, sharedRulesPanel(sharedRules, snapshot.nodes), chainsPanel(groups, chains, snapshot.nodes), reverseTunnelsPanel(tunnels), ...(roots.length ? [status] : []));
}
// One line per path: client, each server with its connect address, then the target.
// The arrow after a server shows that server's latest probe of the next hop and the
// success of its real connections there in the last hour; the client arrow shows the
// entry's inbound setup. Several targets are listed by priority (lower first).
function routeChips(model, health = new Map(), nodes = new Map(), conns = new Map()) {
  const line = el('div', undefined, 'route-chips'), arrow = () => el('span', '→', 'route-arrow');
  const services = { ss: 'Shadowsocks', socks5: 'SOCKS5', http: 'HTTP CONNECT', h2: 'HTTP/2 CONNECT', gateway: translate('受管协议') };
  const worse = (a, b) => ['down', 'partial', 'up', 'unknown'].find(s => s === a || s === b);
  const probe = (reports, counts, inbound = false) => {
    const used = counts?.attempts > 0, probed = linkState(reports.map(probeState));
    const state = used ? worse(probed, connState(counts)) : probed, label = el('span', undefined, `route-probe ${state}`);
    const checks = reports.reduce((n, r) => n + r.window_checks, 0), failures = reports.reduce((n, r) => n + r.window_failures, 0);
    const failed = reports.find(r => r.status === 'unhealthy' && r.last_error), time = millis(median(reports.map(r => r.latency_ewma_us)));
    const text = !reports.length ? (used ? '' : translate('未探测')) : probed === 'unknown' ? translate('等待探测确认') : probed === 'down' ? (failed ? probeErrors[failed.last_error] : translate('不可用'))
      : checks ? msg`${time} · 丢包 ${Math.round(100 * failures / checks)}%` : time;
    if (text) label.append(text);
    if (used) label.append(el('span', inbound ? msg`入站 ${successRate(counts)}` : msg`成功 ${successRate(counts)}`, `route-conn ${connState(counts)}`));
    label.title = [...reports.map(r => [r.protocol.toUpperCase(), selectionReasons[r.selection_reason] || r.selection_reason, millis(r.latency_ewma_us), r.last_error ? probeErrors[r.last_error] : ''].filter(Boolean).join(' · ')),
      used ? (inbound ? msg`最近 1 小时入站 TCP 连接建立（TLS、PROXY、WebSocket）：${connSummary(counts)}` : msg`最近 1 小时真实 TCP 连接：${connSummary(counts)}`) : ''].filter(Boolean).join('\n');
    return label;
  };
  const link = (reports, counts, inbound, note) => { const box = el('span', undefined, 'route-link'); box.append(probe(reports, counts, inbound)); if (note) box.append(el('span', note, 'route-note')); box.append(arrow()); return box; };
  line.append(el('span', translate('客户端'), 'route-chip route-end'));
  const entry = model.root.kind === 'node' && conns.get(hopKey(model.root.node_id, model.root.rule_id));
  let next = entry?.attempts ? [[], entry, true] : null;
  for (let item = model.root; item;) {
    line.append(next ? link(...next) : arrow());
    if (item.kind === 'target') { line.append(el('span', item.address || translate('待填写'), 'route-chip route-end mono')); break; }
    if (item.kind !== 'node') { line.append(el('span', item.name || translate('待选择'), 'route-chip route-warning')); break; }
    const chip = el('span', undefined, 'route-chip'), node = nodes.get(item.node_id); chip.append(el('strong', item.name), el('span', item.endpoint || item.listen || translate('待填写'), 'mono'));
    if (item.service !== 'forward') chip.append(el('span', services[item.service], 'route-service'));
    if (node?.apply_error) { const note = el('span', translate('应用失败'), 'route-note down'); note.title = node.apply_error; chip.classList.add('route-failed'); chip.append(note); }
    else if (node && !online(node)) chip.append(el('span', translate(node.enrolled ? '离线' : '待注册'), 'route-note'));
    line.append(chip);
    if (item.service !== 'forward') { line.append(arrow(), el('span', translate('客户端请求的网站 / 服务'), 'route-chip route-end')); break; }
    const key = i => `${item.node_id}/${item.rule_id}/${i}`, counts = (child, i) => conns.get(hopKey(item.node_id, item.rule_id, i, child.address));
    if (item.children.length > 1) {
      const list = el('span', undefined, 'route-chip route-candidates');
      // Array sort is stable, so targets of one priority keep their configured order.
      item.children.map((child, i) => ({ child, reports: health.get(key(i)) || [], counts: counts(child, i) })).sort((a, b) => a.child.priority - b.child.priority).forEach(({ child, reports, counts }) => {
        // TCP and UDP are selected separately; name the protocol only when their roles differ.
        const reason = r => selectionReasons[r.selection_reason] || r.selection_reason, same = new Set(reports.map(reason)).size === 1;
        const row = el('span', undefined, 'route-candidate'), roles = child.paused ? [pauseLabel(child.pausedUntil)] : same ? [reason(reports[0])] : reports.map(r => `${r.protocol.toUpperCase()} ${reason(r)}`);
        row.append(el('span', child.next.kind === 'node' ? child.next.name : child.address || translate('待填写'), child.next.kind === 'node' ? 'route-candidate-name' : 'route-candidate-name mono'));
        if (roles.length) row.append(el('span', roles.join(' / '), 'route-role'));
        row.append(probe(reports, counts)); list.append(row);
      });
      line.append(arrow(), list); break;
    }
    next = item.children.length ? [health.get(key(0)) || [], counts(item.children[0], 0), false, item.children[0].paused ? pauseLabel(item.children[0].pausedUntil) : null] : null; item = item.children[0]?.next;
  }
  return line;
}
// Every hop of a path in order: the entry's inbound side, then each server's targets.
function pathHops(model) {
  const hops = [];
  if (model.root.kind === 'node') hops.push({ label: msg`客户端 → ${model.root.name}`, key: hopKey(model.root.node_id, model.root.rule_id), node: model.root.node_id, rule: model.root.rule_id, target: translate('入口') });
  (function walk(item) {
    if (item?.kind !== 'node' || item.service !== 'forward') return;
    item.children.forEach((child, i) => {
      hops.push({ label: `${item.name} → ${child.next.kind === 'node' ? child.next.name : child.address}`, key: hopKey(item.node_id, item.rule_id, i, child.address), node: item.node_id, rule: item.rule_id, target: child.address });
      walk(child.next);
    });
  })(model.root);
  return hops;
}
function shortTime(ms, days) { return new Date(ms).toLocaleString(getLanguage(), days ? { month: 'numeric', day: 'numeric' } : { hour: '2-digit', minute: '2-digit', hour12: false }); }
// One strip per hop, one cell per bin, coloured by the share of real connections that succeeded.
async function hopHistory(box, model, name) {
  const range = state.hopRange || '24h', history = await monitoringHistory(range);
  if (!history) { box.replaceChildren(el('p', translate('控制器没有返回连接记录。'), 'fine')); return; }
  const { start_ms: start, end_ms: end, step_ms: step } = history, count = Math.round((end - start) / step), days = range === '7d';
  const byKey = new Map(history.hops.map(h => [hopKey(h.node_id, h.rule_id, h.target_index, h.target_address), h])), hops = pathHops(model);
  const head = el('div', undefined, 'hop-history-head'), title = el('div'), picker = el('div', undefined, 'mode-picker');
  title.append(el('strong', translate('真实连接记录')), el('span', days ? translate('最近 7 天 · 每格 1 小时 · 仅 TCP') : translate('最近 24 小时 · 每格 15 分钟 · 仅 TCP'), 'fine'));
  for (const [value, label] of [['24h', translate('24 小时')], ['7d', translate('7 天')]]) {
    const choice = button(label, async () => { state.hopRange = value; await hopHistory(box, model, name); }); choice.setAttribute('aria-pressed', String(range === value)); picker.append(choice);
  }
  const csv = button(translate('导出 CSV'), () => {
    const quote = v => /[",\n]/.test(String(v)) ? `"${String(v).replaceAll('"', '""')}"` : String(v);
    const lines = [['start', 'hop', 'node_id', 'rule_id', 'target', ...COUNTS.slice(0, 7), 'avg_connect_ms'].join(',')];
    for (const hop of hops) for (const b of byKey.get(hop.key)?.bins || []) lines.push([new Date(b.at_ms).toISOString(), hop.label, hop.node, hop.rule, hop.target, ...COUNTS.slice(0, 7).map(k => b[k]), b.connected ? (b.connect_us / b.connected / 1000).toFixed(2) : ''].map(quote).join(','));
    const link = el('a'); link.href = URL.createObjectURL(new Blob(['\ufeff' + lines.join('\n')], { type: 'text/csv' })); link.download = `relay-connections-${(name || 'path').replace(/[^\w.-]+/g, '_')}-${range}.csv`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }, 'table-action');
  head.append(title, picker, csv);
  const grid = el('div', undefined, 'hop-history');
  for (const hop of hops) {
    const bins = new Map((byKey.get(hop.key)?.bins || []).map(b => [Math.round((b.at_ms - start) / step), b])), total = [...bins.values()].reduce(addCounts, {});
    const strip = el('div', undefined, 'uptime'); strip.style.setProperty('--bins', count);
    for (let i = 0; i < count; i++) { const b = bins.get(i), cell = el('i', undefined, b?.attempts ? connState(b) : 'none'); cell.title = `${shortTime(start + i * step, days)} – ${shortTime(start + (i + 1) * step, days)}\n${b?.attempts ? connSummary(b) : translate('没有连接')}`; strip.append(cell); }
    const sum = el('span', total.attempts ? `${successRate(total)} · ${total.attempts.toLocaleString(getLanguage())}` : translate('没有连接'), `hop-history-total ${total.attempts ? connState(total) : ''}`); sum.title = total.attempts ? connSummary(total) : '';
    grid.append(el('span', hop.label, 'hop-history-label'), strip, sum);
  }
  const axis = el('div', undefined, 'hop-history-axis'); axis.append(el('span', shortTime(start, days)), el('span', translate('现在')));
  grid.append(el('span'), axis, el('span'));
  box.replaceChildren(head, grid);
}
// `source` lets a caller supply its own checked preview and publish step (saved chains).
async function previewTopology(snapshot, input, summary = '', back = null, diagramRoots = [], editHop = null, source = {}) {
  const preview = source.preview || await api('/configurations/preview', { method: 'POST', body: input });
  const body = el('div');
  const combined = { ...snapshot, configs: snapshot.configs.map(config => preview.configs.find(updated => updated.node_id === config.node_id) || config) };
  for (const root of diagramRoots) {
    const view = forwardingPathView({ onSelect: editHop || (back ? () => back() : null), canSelect: editHop ? null : item => topologyKey(item) === topologyKey(root) });
    view.update(forwardingDiagram(combined, root), 'validated'); body.append(view.box);
  }
  if (summary) body.append(el('p', summary, 'workflow-callout'));
  body.append(el('p', translate('下面是服务器校验后的变更。发布会同时提交期望配置；节点应用结果请在「转发规则」页逐项确认。')), table([translate('节点'), translate('修订'), translate('新增 / 修改 / 删除规则')], preview.changes.map(change => [snapshot.nodes.find(node => node.id === change.node_id)?.name || change.node_id, `${change.from_revision} → ${change.to_revision}`, `${change.added.length} / ${change.modified.length} / ${change.removed.length}`])));
  for (const change of preview.changes) for (const diff of change.rule_changes) { const details = el('details'); details.append(el('summary', msg`${diff.after?.name || diff.before?.name} · 查看发布前后配置`), el('pre', JSON.stringify({ before: diff.before, after: diff.after }, null, 2))); body.append(details); }
  if (back) body.append(button(translate('返回编辑'), back));
  body.append(button(translate('发布这些变更'), async () => { await (source.publish ? source.publish() : api('/configurations/publish', { method: 'POST', body: input })); $('#dialog').close(); notify(translate('期望配置已同时提交，正在等待各节点应用。')); await navigate('topology'); }, 'primary'));
  modal(translate('发布前检查'), body);
}
async function changeTopologyComponent(snapshot, seed, enabled) {
  const selected = new Set([seed]); let changed = true;
  while (changed) { changed = false; for (const edge of snapshot.graph.edges) { const a = topologyKey(edge.from), b = topologyKey(edge.to); if (selected.has(a) || selected.has(b)) { if (!selected.has(a) || !selected.has(b)) changed = true; selected.add(a); selected.add(b); } } }
  const updates = snapshot.configs.filter(config => config.rules.some(rule => selected.has(`${config.node_id}/${rule.id}`))).map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: config.rules.map(rule => selected.has(`${config.node_id}/${rule.id}`) ? { ...rule, enabled } : rule) }));
  await previewTopology(snapshot, { updates });
}
// The rules a forwarding owns: every hop from its entry, except a hop another forwarding also passes through, and what follows it.
function forwardingRules(snapshot, root) {
  const next = new Map(snapshot.configs.flatMap(config => config.rules.map(rule => [`${config.node_id}/${rule.id}`, (rule.targets || []).filter(t => t.via).map(t => topologyKey(t.via))])));
  const members = new Set(), shared = new Set();
  const walk = (key, into) => { if (into.has(key) || !next.has(key)) return; into.add(key); next.get(key).forEach(k => walk(k, into)); };
  walk(topologyKey(root), members);
  for (const [key, hops] of next) if (!members.has(key)) hops.filter(k => members.has(k)).forEach(k => walk(k, shared));
  return { own: [...members].filter(k => !shared.has(k)), shared: [...members].filter(k => shared.has(k)) };
}
// Deleting a forwarding takes two publishes when it chains servers: its rules stop first with their routes unchanged,
// and only after every server has applied the stop and ended its sessions does the panel accept their removal.
async function deleteForwarding(snapshot, root) {
  const { own, shared } = forwardingRules(snapshot, root), keys = new Set(own), names = new Map(snapshot.nodes.map(n => [n.id, n.name]));
  const owned = snapshot.configs.flatMap(config => config.rules.filter(rule => keys.has(`${config.node_id}/${rule.id}`)).map(rule => ({ node_id: config.node_id, rule })));
  const name = owned.find(item => `${item.node_id}/${item.rule.id}` === topologyKey(root))?.rule.name || root.rule_id;
  const servers = [...new Set(owned.map(item => names.get(item.node_id) || item.node_id))].join(getLanguage() === 'en' ? ', ' : '、');
  const updates = change => snapshot.configs.filter(config => config.rules.some(rule => keys.has(`${config.node_id}/${rule.id}`))).map(config => ({ node_id: config.node_id, expected_revision: config.revision, rules: change(config) }));
  const label = key => { const config = snapshot.configs.find(c => key.startsWith(`${c.node_id}/`)), rule = config?.rules.find(r => `${config.node_id}/${r.id}` === key); return `${names.get(config?.node_id) || key} · ${rule?.name || key}`; };
  const keep = shared.length ? ' ' + msg`${shared.map(label).join(getLanguage() === 'en' ? ', ' : '、')} 也属于其他转发，保留不删。` : '';
  if (!owned.length) { notify(translate('这条转发的每一跳都被其他转发使用，请删除那些转发。'), true); return; }
  if (owned.some(item => item.rule.enabled && (item.rule.advertise || item.rule.targets.some(t => t.via))))
    return previewTopology(snapshot, { updates: updates(config => config.rules.map(rule => keys.has(`${config.node_id}/${rule.id}`) ? { ...rule, enabled: false } : rule)) },
      msg`删除「${name}」分两步：先停止，等 ${servers} 应用停止并结束现有连接后，再点一次「删除」完成删除。现在发布第 1 步：停止 ${owned.length} 条规则，路线保持不变。` + keep);
  try {
    await previewTopology(snapshot, { updates: updates(config => config.rules.filter(rule => !keys.has(`${config.node_id}/${rule.id}`))) }, msg`删除「${name}」：从 ${servers} 移除 ${owned.length} 条规则并结束其会话，历史账本保留。` + keep);
  } catch (error) {
    if (!/topology stop is not confirmed/.test(error.message)) throw error;
    modal(translate('还不能删除'), el('p', msg`「${name}」已停止，但还有服务器没有确认：它需要应用停止后的配置，并报告没有活动连接。稍等片刻再点「删除」。离线的服务器无法确认；不再使用它的话，请在「节点」页打开它的详情并删除该节点。`, 'workflow-callout'));
  }
}
// From the per-server page: a chained rule goes through its whole forwarding, or explains which forwarding owns it.
async function deleteChainedRule(nodeId, rule) {
  const snapshot = await api('/topology'), key = `${nodeId}/${rule.id}`, root = forwardingPathRoots(snapshot).find(r => topologyKey(r) === key);
  if (root) return deleteForwarding(snapshot, root);
  const body = el('div');
  body.append(el('p', msg`「${rule.name}」是一条多服务器转发中的一跳，前面的服务器仍指向它，所以不能单独删除。请在「全部转发」里删除整条转发：它会先停止整条路线，再移除各跳规则。`, 'workflow-callout'), button(translate('打开全部转发'), async () => { $('#dialog').close(); await navigate('topology'); }, 'primary'));
  modal(msg`删除「${rule.name}」`, body);
}
// Reverse tunnels (NAT traversal). A public server accepts users on a public port; a private server
// behind NAT that cannot accept inbound connections keeps an outbound, encrypted tunnel to it and
// hands each user to a target it can reach. The public end is an ordinary rule on the public server,
// metered and limited like any rule; the tunnel decides its port, protocol, target and switch.
const tunnelProtocols = { tcp: 'TCP', udp: 'UDP', tcp_udp: 'TCP + UDP' };
// The controller and the agents explain a waiting or failed tunnel in English; known reasons are
// shown in the panel's language, others as they are.
const tunnelReasons = {
  'the public server was deleted': '公网服务器已删除',
  'the private server was deleted': '内网服务器已删除',
  "the public server's agent is too old for reverse tunnels; upgrade it": 'Agent 版本过旧：公网服务器的 Agent 不支持反向隧道，请升级',
  "the private server's agent is too old for reverse tunnels; upgrade it": 'Agent 版本过旧：内网服务器的 Agent 不支持反向隧道，请升级',
  'the public server has not connected to the panel yet': '公网服务器尚未连接面板',
  'the private server has not connected to the panel yet': '内网服务器尚未连接面板',
  "waiting for the public server's key": '等待公网服务器的密钥',
  "the public server has no forwarding host, so the private server cannot reach the tunnel port; set it in the public server's forwarding settings": '公网服务器没有设置转发地址，内网服务器无法连接隧道端口；请在公网服务器的转发设置中填写',
  'the public server is offline': '公网服务器离线',
  'the private server is offline': '内网服务器离线',
  "waiting for the public server's configuration": '等待公网服务器应用配置',
  'waiting for the private server to connect': '等待内网服务器连入',
  'the public server does not have this tunnel yet': '公网服务器尚未收到这条隧道',
  'the public server rejected the tunnel token': '公网服务器拒绝了隧道令牌',
  "the public server's key does not match its reported fingerprint": '公网服务器的密钥与其回报的指纹不符',
};
// A reverse tunnel's public end is listed with its tunnel, not as a forwarding path of its own.
function forwardingRootsWithoutTunnels(snapshot) {
  const ends = new Set((snapshot.configs || []).flatMap(config => config.rules.filter(rule => rule.reverse_tunnel).map(rule => `${config.node_id}/${rule.id}`)));
  return forwardingPathRoots(snapshot).filter(root => !ends.has(`${root.node_id}/${root.rule_id}`));
}
function tunnelReason(reason) { return reason ? translate(tunnelReasons[reason] || reason) : ''; }
function tunnelDuration(secs) { return secs < 60 ? msg`${secs} 秒` : secs < 3600 ? msg`${Math.floor(secs / 60)} 分钟` : secs < 86400 ? msg`${Math.floor(secs / 3600)} 小时` : msg`${Math.floor(secs / 86400)} 天`; }
function reverseTunnelsPanel(tunnels) {
  const p = panel(translate('反向隧道（NAT 穿透）'), translate('内网服务器在 NAT 或家庭路由器之后、无法接受入站连接时使用：它主动连出，与公网服务器保持一条加密隧道；用户连接公网服务器的公网端口，每个连接经隧道送到内网服务器能访问的目标。'), canWrite() ? button(translate('＋ 新建反向隧道'), () => openReverseTunnel(), 'primary') : null);
  if (!tunnels.length) { p.append(el('p', translate('还没有反向隧道。两台服务器都需要运行支持反向隧道的 Agent。'), 'fine')); return p; }
  const states = { connected: [translate('已连接'), 'green'], waiting: [translate('等待中'), 'orange'], error: [translate('异常'), 'red'], disabled: [translate('已停用'), ''] };
  const server = (missing, name, id, ...details) => { const cell = el('div'); cell.append(el('strong', missing ? id : name || id), ...details.map(detail => el('div', detail, 'subline mono'))); if (missing) cell.append(badge(translate('服务器已删除'), 'red')); return cell; };
  p.append(table([translate('名称 · 协议'), translate('公网服务器 · 端口'), translate('内网服务器 · 目标'), translate('状态'), translate('用户入口地址'), translate('流量'), translate('操作')], tunnels.map(view => {
    const name = el('div'); name.append(el('strong', view.name), el('div', tunnelProtocols[view.protocol] || view.protocol, 'subline'));
    const [label, color] = states[view.state] || [view.state, ''], stateCell = el('div');
    stateCell.append(badge(label, color));
    if (view.state === 'connected' && view.connected_for_secs != null) stateCell.append(el('div', msg`已建立 ${tunnelDuration(view.connected_for_secs)}`, 'subline'));
    if (view.reason) stateCell.append(el('div', tunnelReason(view.reason), 'subline wrap'));
    const entry = el('div');
    // The button sits in its own box so the address itself never wraps.
    if (view.entry) { const copy = el('div'); copy.append(button(translate('复制'), async () => { await navigator.clipboard.writeText(view.entry); notify(msg`已复制 ${view.entry}。`); }, 'table-action')); entry.append(el('div', view.entry, 'mono'), copy); }
    else entry.append(el('div', translate('未设置转发地址'), 'fine'));
    const tools = el('div');
    if (canWrite()) {
      if (!view.public_missing && !view.private_missing) {
        tools.append(button(translate('编辑'), () => openReverseTunnel(view), 'table-action'));
        if (view.rule_id) tools.append(button(translate('访问与限速'), () => limitReverseTunnel(view), 'table-action'));
        tools.append(button(view.enabled ? translate('停用') : translate('启用'), () => switchReverseTunnel(view), 'table-action'));
      }
      tools.append(button(translate('删除'), () => deleteReverseTunnel(view), 'table-action danger'));
    }
    const traffic = el('div'); traffic.append(el('div', `↑ ${bytes(view.upload_bytes)}`), el('div', `↓ ${bytes(view.download_bytes)}`));
    return [name, server(view.public_missing, view.public_node_name, view.public_node_id, msg`公网端口 ${view.public_port}`, msg`隧道端口 ${view.tunnel_port}`), server(view.private_missing, view.private_node_name, view.private_node_id, view.target), stateCell, entry, traffic, tools];
  })));
  return p;
}
// The request body of a tunnel; `enabled` stays as it was when editing.
function readReverseTunnel(data, view) {
  const port = key => { const text = String(data.get(key) ?? '').trim(), value = Number(text); if (!/^\d+$/.test(text) || value < 1 || value > 65535) throw new Error(translate('端口必须是 1 到 65535 之间的整数。')); return value; };
  const name = String(data.get('tunnel_name') || '').trim(), target = String(data.get('target') || '').trim(), listen = String(data.get('listen_ip') || '').trim();
  if (!name) throw new Error(translate('请填写名称。'));
  if (!data.get('private_node_id')) throw new Error(translate('请选择内网服务器：它必须与公网服务器属于同一租户，且不是同一台服务器。'));
  if (!/^(\[[0-9a-fA-F:.]+\]|[^\s:[\]/]+):\d{1,5}$/.test(target)) throw new Error(translate('目标必须是 host:端口，例如 127.0.0.1:8080 或 192.168.10.20:8080。'));
  const body = { name, public_node_id: data.get('public_node_id'), private_node_id: data.get('private_node_id'), public_port: port('public_port'), listen_ip: listen || null, protocol: data.get('protocol'), target, tunnel_port: port('tunnel_port'), enabled: view ? view.enabled : true };
  if (body.public_port === body.tunnel_port) throw new Error(translate('公网端口和隧道端口不能相同。'));
  return body;
}
async function openReverseTunnel(view = null) {
  const [nodes, tunnels] = await Promise.all([api('/nodes'), api('/reverse-tunnels')]); state.nodes = nodes;
  if (nodes.length < 2) throw new Error(translate('反向隧道需要两台服务器：一台公网服务器和一台内网服务器。'));
  const form = el('form'), grid = el('div', undefined, 'form-grid'), named = list => list.map(node => [node.id, node.name || node.id]);
  field(grid, 'tunnel_name', translate('名称'), view?.name || '').maxLength = 120;
  const publicNode = select(grid, 'public_node_id', translate('公网服务器（接受用户连接）'), named(nodes), view?.public_node_id || (nodes.find(node => node.id === state.selectedNode) || nodes[0]).id);
  const privateNode = select(grid, 'private_node_id', translate('内网服务器（在 NAT 后，主动连出）'), [], '');
  const portRow = el('div', undefined, 'shared-port-row');
  const port = field(portRow, 'public_port', translate('公网端口（用户连接）'), view?.public_port ?? '', 'number'); port.min = 1; port.max = 65535;
  portRow.append(button(translate('自动选择'), autoPort)); grid.append(portRow);
  const target = field(grid, 'target', translate('目标（内网服务器看到的 host:端口）'), view?.target || ''); target.placeholder = '127.0.0.1:8080';
  select(grid, 'protocol', translate('协议'), [['tcp', 'TCP'], ['udp', 'UDP'], ['tcp_udp', 'TCP + UDP']], view?.protocol || 'tcp');
  form.append(grid);
  const advanced = el('details', undefined, 'advanced-options'), more = el('div', undefined, 'form-grid');
  advanced.append(el('summary', translate('高级选项')), more);
  const tunnelPort = field(more, 'tunnel_port', translate('隧道端口（内网服务器连出到公网服务器的端口，同一台公网服务器上的隧道共用）'), view?.tunnel_port ?? 29123, 'number'); tunnelPort.min = 1; tunnelPort.max = 65535;
  field(more, 'listen_ip', translate('公网端口的监听 IP（留空使用公网服务器转发设置中的监听 IP）'), view?.listen_ip || '', 'text', false).placeholder = '0.0.0.0';
  if (view?.listen_ip || (view && view.tunnel_port !== 29123)) advanced.open = true;
  form.append(advanced);
  const help = el('ul', undefined, 'fine tunnel-help');
  for (const text of [translate('公网端口给用户连接；隧道端口给内网服务器主动连出。'), translate('目标里的 127.0.0.1 指内网服务器自己；也可以填写内网服务器能访问的局域网地址，例如 192.168.10.20:8080。'), translate('请在公网服务器的云防火墙 / 安全组中放行公网端口和隧道端口（隧道端口只需 TCP；协议含 UDP 时公网端口还需放行 UDP）。'), translate('隧道使用 TLS 加密：内网服务器校验公网服务器回报的密钥指纹，再用这条隧道独有的令牌认证。令牌只发给这两台服务器，不会显示。')]) help.append(el('li', text));
  form.append(help);
  if (view) form.append(el('p', translate('更换公网或内网服务器会生成新的隧道令牌；更换公网端口后，流量统计从新的周期开始。'), 'fine'));
  function drawPrivate() {
    const tenant = nodes.find(node => node.id === publicNode.value)?.tenant_id, keep = privateNode.value || view?.private_node_id;
    const choices = nodes.filter(node => node.tenant_id === tenant && node.id !== publicNode.value);
    privateNode.replaceChildren(...named(choices).map(([id, text]) => { const option = el('option', text); option.value = id; return option; }));
    privateNode.value = choices.some(node => node.id === keep) ? keep : choices[0]?.id || '';
  }
  publicNode.addEventListener('change', drawPrivate); drawPrivate();
  // The lowest port of the public server's forwarding range that no rule and no other tunnel holds there.
  async function autoPort() {
    const node = nodes.find(n => n.id === publicNode.value), range = node?.profile?.settings?.forwarding;
    if (!range) throw new Error(translate('公网服务器没有设置转发端口范围；请手动填写公网端口，或先在服务器的转发设置中设置端口范围。'));
    const config = await api(`/nodes/${encodeURIComponent(node.id)}/config`), taken = new Set([Number(tunnelPort.value)]);
    for (const rule of config.rules) {
      if (view && rule.reverse_tunnel === view.id) continue;
      const start = listenPort(rule.listen), end = rule.listen_end_port || start;
      for (let p = start; p <= end; p++) taken.add(p);
      if (rule.protocol_gateway) taken.add(listenPort(rule.protocol_gateway.listen));
    }
    for (const other of tunnels) if (other.id !== view?.id && other.public_node_id === node.id) taken.add(other.public_port).add(other.tunnel_port);
    for (let p = range.port_start; p <= range.port_end; p++) if (!taken.has(p)) { port.value = String(p); return; }
    throw new Error(translate('公网服务器的转发端口范围内没有空闲端口。'));
  }
  submit(form, view ? translate('保存反向隧道') : translate('创建反向隧道'), async data => {
    const body = readReverseTunnel(data, view);
    await api(view ? `/reverse-tunnels/${encodeURIComponent(view.id)}` : '/reverse-tunnels', { method: view ? 'PUT' : 'POST', body });
    $('#dialog').close(); notify(view ? translate('反向隧道已保存，两台服务器在下次同步时生效。') : translate('反向隧道已创建。两台服务器的 Agent 就绪后自动建立隧道。')); await refresh();
  });
  modal(view ? msg`编辑反向隧道 · ${view.name}` : translate('新建反向隧道'), form);
}
async function switchReverseTunnel(view) {
  if (view.enabled && !await confirmAction(msg`停用「${view.name}」？公网端口会关闭，进行中的连接会断开，内网服务器停止连出。`)) return;
  const { name, public_node_id, private_node_id, public_port, protocol, target, tunnel_port } = view;
  await api(`/reverse-tunnels/${encodeURIComponent(view.id)}`, { method: 'PUT', body: { name, public_node_id, private_node_id, public_port, listen_ip: view.listen_ip ?? null, protocol, target, tunnel_port, enabled: !view.enabled } });
  notify(view.enabled ? translate('反向隧道已停用。') : translate('反向隧道已启用。')); await refresh();
}
async function deleteReverseTunnel(view) {
  if (!await confirmAction(msg`删除反向隧道「${view.name}」？公网端口会关闭，内网服务器停止连出；历史账本保留。`)) return;
  await api(`/reverse-tunnels/${encodeURIComponent(view.id)}`, { method: 'DELETE' });
  notify(translate('反向隧道已删除。')); await refresh();
}
// Source rules and limits of the public end, the rule fields a tunnel leaves to the operator.
async function limitReverseTunnel(view) {
  const path = `/nodes/${encodeURIComponent(view.public_node_id)}/config`, config = await api(path), rule = config.rules.find(r => r.id === view.rule_id);
  if (!rule) throw new Error(translate('公网端还没有运行；两台服务器就绪后再设置。'));
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  textarea(grid, 'allow_sources', translate('允许来源 CIDR（留空允许所有未拒绝来源，每行一个）'), (rule.allow_sources || []).join('\n'));
  textarea(grid, 'deny_sources', translate('拒绝来源 CIDR（优先于允许列表，每行一个）'), (rule.deny_sources || []).join('\n'));
  const most = field(grid, 'max_connections', translate('TCP 最大连接'), rule.max_connections ?? 4096, 'number'); most.min = 1; most.max = 1000000;
  const speed = rateLimitEditor({ rate: rule.rate_bytes_per_sec, limits: rule.rate_limits, unit: 'bytes', burst: true, combined: { name: 'rate_bytes_per_sec', label: translate('合并速率 / bytes/s（留空不限）') } });
  form.append(grid, speed.box, el('p', translate('这些限制作用于公网端口上的用户连接，与普通规则相同；流量计入公网服务器的流量账本。'), 'fine'));
  submit(form, translate('保存'), async data => {
    const lines = key => String(data.get(key) || '').split('\n').map(s => s.trim()).filter(Boolean), { rate_bytes_per_sec, rate_limits } = speed.read(data), most = Number(data.get('max_connections'));
    if (!(Number.isInteger(most) && most >= 1 && most <= 1000000)) throw new Error(translate('TCP 最大连接必须在 1 到 1000000 之间。'));
    const changed = { ...rule, allow_sources: lines('allow_sources'), deny_sources: lines('deny_sources'), rate_bytes_per_sec, max_connections: most };
    if (rate_limits) changed.rate_limits = rate_limits; else delete changed.rate_limits;
    await api(path, { method: 'PUT', body: { expected_revision: config.revision, rules: config.rules.map(r => r.id === rule.id ? changed : r) } });
    $('#dialog').close(); notify(translate('访问与限速已发布到公网服务器。')); await refresh();
  });
  modal(msg`访问与限速 · ${view.name}`, form);
}
// Endpoint groups and saved chains. A group is one layer of candidate servers: its members are
// alternatives the previous hop chooses between, not consecutive hops. A chain orders groups into
// layers. Building a forwarding from a chain is the controller's plan; the panel reviews it in the
// usual publish preview and applies it in one batch.
const chainBalances = localize([['weighted_round_robin', '加权轮询（默认）'], ['source_hash', '来源 IP 哈希'], ['least_connections', '最少连接'], ['lowest_latency', '最低延迟（仅 TCP，自动加连接探测）'], ['random', '随机']]);
const balanceNames = localize({ weighted_round_robin: '加权轮询', source_hash: '来源 IP 哈希', least_connections: '最少连接', lowest_latency: '最低延迟', random: '随机' });
function memberNames(members) { return members.map(member => member.node_name || member.node_id).join(' · ') || '—'; }
// Listed on "All forwarding"; `nodes` names the servers of out-of-date changes.
function chainsPanel(groups, chains, nodes) {
  const names = new Map(nodes.map(node => [node.id, node.name])), named = ids => ids.map(id => names.get(id) || id).join(' · ');
  const actions = el('div', undefined, 'toolbar');
  if (canWrite()) actions.append(button(translate('＋ 新建端点组'), () => openEndpointGroup()), button(translate('＋ 新建转发链'), () => openChain(), groups.length ? 'primary' : 'subtle'));
  const p = panel(translate('端点组与转发链'), translate('端点组是一层候选服务器：组内服务器互为备选，由上一跳按这一层的均衡方式选择其中一台，不是依次经过。转发链把端点组按顺序排成多层。在“新建转发”中选择“使用已保存的转发链”：入口和每层的每台服务器各得一条普通规则，指向下一层的全部服务器。'), canWrite() ? actions : null);
  const body = el('div', undefined, 'panel-body');
  body.append(el('h3', translate('已保存的端点组')));
  if (!groups.length) body.append(el('p', translate('还没有端点组。为每一层（例如中转层、落地层）分别新建一个组。'), 'fine'));
  else body.append(table([translate('名称'), translate('成员服务器（按顺序）'), translate('使用此组的转发链'), translate('操作')], groups.map(group => {
    const name = el('div'); name.append(el('strong', group.name), el('div', group.description || msg`${group.members.length} 台服务器`, 'subline'));
    const members = el('ol', undefined, 'chain-members');
    for (const member of group.members) { const row = el('li', member.node_name || member.node_id); if (member.missing) row.append(badge(translate('服务器已删除'), 'red')); members.append(row); }
    const tools = el('div');
    if (canWrite()) tools.append(button(translate('编辑'), () => openEndpointGroup(group), 'table-action'), button(translate('删除'), () => deleteEndpointGroup(group), 'table-action danger'));
    return [name, members, group.used_by.map(chain => chain.name).join(' · ') || '—', tools];
  })));
  body.append(el('h3', translate('已保存的转发链')));
  if (!chains.length) body.append(el('p', groups.length ? translate('还没有转发链。点击“新建转发链”，按顺序选择每一层的端点组。') : translate('先新建端点组，再把它们按顺序组成转发链。'), 'fine'));
  else body.append(table([translate('名称'), translate('层（按顺序）'), translate('用此链创建的转发'), translate('操作')], chains.map(chain => {
    const name = el('div'); name.append(el('strong', chain.name), badge(chain.enabled ? translate('已启用') : translate('已停用'), chain.enabled ? 'green' : 'orange'));
    const layers = el('ol', undefined, 'chain-layers');
    chain.layers.forEach(layer => { const row = el('li'); row.append(el('strong', layer.group_name || layer.group_id), el('span', ` · ${balanceNames[layer.balance] || layer.balance}`), el('div', memberNames(layer.members), 'subline')); layers.append(row); });
    const uses = el('div', undefined, 'shared-line-status');
    for (const use of chain.uses) {
      const row = el('div');
      row.append(el('span', msg`${use.name || translate('已删除的转发')} · 入口 ${use.entry_node_name || use.entry_node_id}`));
      if (use.missing) row.append(badge(translate('转发已删除'), 'red'));
      else if (use.out_of_date) row.append(badge(translate('组成员已变化'), 'orange'));
      uses.append(row);
      for (const change of use.changes) uses.append(el('div', [msg`第 ${change.layer} 层`, change.added.length ? msg`新增 ${named(change.added)}` : '', change.removed.length ? msg`移除 ${named(change.removed)}` : ''].filter(Boolean).join(' · '), 'subline warning'));
    }
    if (!chain.uses.length) uses.append(el('span', '—'));
    const tools = el('div');
    if (canWrite()) {
      if (chain.enabled) tools.append(button(translate('用此链新建转发'), () => useChain(chain.id), 'table-action'));
      tools.append(button(translate('编辑'), () => openChain(chain), 'table-action'), button(translate('删除'), () => deleteChain(chain), 'table-action danger'));
    }
    return [name, layers, uses, tools];
  })));
  if (chains.some(chain => chain.uses.some(use => use.out_of_date))) body.append(el('p', translate('已创建的转发不会随端点组自动更新。“组成员已变化”表示创建之后组里增加或移除了服务器；要使用新的成员，请用此链重新创建转发，再删除旧转发。'), 'workflow-callout warning'));
  p.append(body);
  return p;
}
// An ordered member list: Up and Down set the order, Add offers servers of the group's tenant.
async function openEndpointGroup(view = null) {
  const nodes = await api('/nodes'); state.nodes = nodes;
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'group_name', translate('组名称'), view?.name || '').maxLength = 120;
  field(grid, 'group_description', translate('说明（可留空）'), view?.description || '', 'text', false).maxLength = 2000;
  form.append(grid, el('p', translate('一个端点组是转发链中的一层。组内服务器互为备选：上一跳按这一层的均衡方式选择其中一台，不会依次经过它们。请为每一层分别建组，不要把不同层的服务器放进同一个组。'), 'workflow-callout'));
  const members = view ? view.members.filter(member => !member.missing).map(member => member.node_id) : [];
  const missing = view ? view.members.length - members.length : 0;
  if (missing) form.append(el('p', msg`${missing} 台服务器已删除，保存时从组中移除。`, 'fine'));
  const box = el('fieldset', undefined, 'shared-lines'), list = el('ol', undefined, 'chain-members chain-editor-list'), adder = el('div', undefined, 'shared-port-row');
  box.append(el('legend', translate('成员服务器（按顺序）')), list, adder);
  const choice = select(adder, 'group_add', translate('添加服务器'), [], '');
  const add = button(translate('添加'), () => { if (choice.value && !members.includes(choice.value)) members.push(choice.value); draw(); });
  adder.append(add); form.append(box);
  const name = id => nodes.find(node => node.id === id)?.name || id;
  function draw() {
    list.replaceChildren();
    members.forEach((id, index) => {
      const row = el('li'), tools = el('span', undefined, 'chain-row-tools');
      const up = button(translate('上移'), () => { [members[index - 1], members[index]] = [members[index], members[index - 1]]; draw(); }, 'table-action'); up.disabled = index === 0;
      const down = button(translate('下移'), () => { [members[index], members[index + 1]] = [members[index + 1], members[index]]; draw(); }, 'table-action'); down.disabled = index === members.length - 1;
      tools.append(up, down, button(translate('移除'), () => { members.splice(index, 1); draw(); }, 'table-action'));
      row.append(el('span', `${index + 1}. ${name(id)}`), tools); list.append(row);
    });
    if (!members.length) list.append(el('li', translate('还没有成员服务器。'), 'fine'));
    const tenant = nodes.find(node => node.id === members[0])?.tenant_id;
    const available = nodes.filter(node => !members.includes(node.id) && (!tenant || node.tenant_id === tenant));
    choice.replaceChildren(...available.map(node => { const option = el('option', node.name || node.id); option.value = node.id; return option; }));
    choice.value = available[0]?.id || '';
    add.disabled = !available.length || members.length >= 32;
  }
  draw();
  submit(form, view ? translate('保存端点组') : translate('创建端点组'), async data => {
    if (!members.length) throw new Error(translate('请至少添加一台服务器。'));
    const body = { name: String(data.get('group_name')).trim(), description: String(data.get('group_description') || '').trim(), members: [...members] };
    await api(view ? `/endpoint-groups/${encodeURIComponent(view.id)}` : '/endpoint-groups', { method: view ? 'PUT' : 'POST', body });
    $('#dialog').close(); notify(view ? translate('端点组已保存。已用转发链创建的转发保持不变，若成员变化会标为“组成员已变化”。') : translate('端点组已创建。')); await refresh();
  });
  modal(view ? msg`编辑端点组 · ${view.name}` : translate('新建端点组'), form);
}
async function deleteEndpointGroup(view) {
  if (view.used_by.length) throw new Error(msg`转发链 ${view.used_by.map(chain => chain.name).join(' · ')} 使用此组，请先从转发链中移除它。`);
  if (!await confirmAction(msg`删除端点组「${view.name}」？服务器和规则不受影响。`)) return;
  await api(`/endpoint-groups/${encodeURIComponent(view.id)}`, { method: 'DELETE' });
  notify(translate('端点组已删除。')); await refresh();
}
// Layers in order; each picks a group and the balance its candidates are chosen with.
async function openChain(view = null) {
  const groups = await api('/endpoint-groups');
  if (!groups.length) throw new Error(translate('先新建端点组，再把它们按顺序组成转发链。'));
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  field(grid, 'chain_name', translate('转发链名称'), view?.name || '').maxLength = 120;
  form.append(grid);
  const enabled = checkbox(form, 'chain_enabled', translate('启用：可以用此链创建新的转发'));
  enabled.checked = view ? view.enabled : true; enabled.parentElement.classList.add('inline-check');
  form.append(el('p', translate('入口从第 1 层的服务器中选择一台，第 1 层再从第 2 层中选择一台，依此类推，最后一层连接目标。每层的均衡方式决定上一跳如何在这一层的服务器中选择。一个端点组只能作为一层，同一台服务器不能出现在两层中；最多 6 层。修改转发链不会改变已经创建的转发。'), 'workflow-callout'));
  const layers = view ? view.layers.map(layer => ({ group_id: layer.group_id, balance: layer.balance })) : [{ group_id: groups[0].id, balance: 'weighted_round_robin' }];
  const list = el('ol', undefined, 'chain-layers chain-editor-list');
  const addLayer = button(translate('＋ 添加层'), () => { layers.push({ group_id: (groups.find(group => !layers.some(layer => layer.group_id === group.id)) || groups[0]).id, balance: 'weighted_round_robin' }); draw(); });
  form.append(list, addLayer);
  function draw() {
    list.replaceChildren();
    layers.forEach((layer, index) => {
      const row = el('li'), fields = el('div', undefined, 'form-grid'), tools = el('div', undefined, 'toolbar');
      const group = select(fields, `layer_group_${index}`, msg`第 ${index + 1} 层 · 端点组`, groups.map(item => [item.id, msg`${item.name}（${item.members.length} 台）`]), layer.group_id);
      group.addEventListener('change', () => { layer.group_id = group.value; draw(); });
      const balance = select(fields, `layer_balance_${index}`, translate('上一跳在这一层中的选择方式'), chainBalances, layer.balance);
      balance.addEventListener('change', () => { layer.balance = balance.value; });
      const up = button(translate('上移'), () => { [layers[index - 1], layers[index]] = [layers[index], layers[index - 1]]; draw(); }); up.disabled = index === 0;
      const down = button(translate('下移'), () => { [layers[index], layers[index + 1]] = [layers[index + 1], layers[index]]; draw(); }); down.disabled = index === layers.length - 1;
      const remove = button(translate('移除此层'), () => { layers.splice(index, 1); draw(); }); remove.disabled = layers.length === 1;
      tools.append(up, down, remove);
      row.append(fields, el('p', memberNames(groups.find(item => item.id === layer.group_id)?.members || []), 'fine'), tools); list.append(row);
    });
    addLayer.disabled = layers.length >= 6;
  }
  draw();
  submit(form, view ? translate('保存转发链') : translate('创建转发链'), async data => {
    const body = { name: String(data.get('chain_name')).trim(), enabled: enabled.checked, layers: layers.map(layer => ({ group_id: layer.group_id, balance: layer.balance })) };
    await api(view ? `/chains/${encodeURIComponent(view.id)}` : '/chains', { method: view ? 'PUT' : 'POST', body });
    $('#dialog').close(); notify(view ? translate('转发链已保存；已经创建的转发保持不变。') : translate('转发链已创建。')); await refresh();
  });
  modal(view ? msg`编辑转发链 · ${view.name}` : translate('新建转发链'), form);
}
async function deleteChain(view) {
  if (!await confirmAction(msg`删除转发链「${view.name}」？用它创建的 ${view.uses.length} 条转发及其规则保持不变，只是不再显示来自此链。`)) return;
  await api(`/chains/${encodeURIComponent(view.id)}`, { method: 'DELETE' });
  notify(translate('转发链已删除；用它创建的转发保持不变。')); await refresh();
}
// New forwarding from a saved chain: the controller plans every rule and endpoint, the usual
// publish preview shows the path, and publishing applies the plan's revisions in one batch.
async function useChain(chainId = null) {
  const [snapshot, chains, users] = await Promise.all([api('/topology'), api('/chains'), api('/users')]);
  state.nodes = snapshot.nodes;
  const usable = chains.filter(chain => chain.enabled), title = translate('使用已保存的转发链');
  if (!usable.length) { modal(title, empty(translate('还没有可用的转发链'), translate('先在「全部转发」页下方的“端点组与转发链”中新建端点组和转发链，并确认转发链已启用。'), button(translate('前往全部转发'), async () => { $('#dialog').close(); await navigate('topology'); }, 'primary'))); return; }
  const form = el('form'), grid = el('div', undefined, 'form-grid');
  form.append(el('p', translate('选择转发链和入口服务器。控制器按链为每台服务器生成规则并自动分配端口；先预览整条路径，再确认发布。所有服务器一次提交，任何一台失败都不会修改。'), 'workflow-callout'));
  const chainField = select(grid, 'chain', translate('转发链'), usable.map(chain => [chain.id, chain.name]), usable.some(chain => chain.id === chainId) ? chainId : usable[0].id);
  const entry = select(grid, 'entry_node_id', translate('入口服务器（客户端连接这里）'), [], '');
  field(grid, 'name', translate('转发名称'), '').maxLength = 100;
  const protocol = select(grid, 'protocol', translate('传输协议（TCP / UDP）'), [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], 'both');
  field(grid, 'target', translate('最终目标（IP 或域名:端口）'), '').placeholder = 'destination.example.com:443';
  const port = field(grid, 'entry_port', translate('入口端口（留空自动分配）'), '', 'number', false); port.min = 1; port.max = 65535;
  const advanced = el('details'); advanced.append(el('summary', translate('高级选项：规则所有者')));
  const owner = select(advanced, 'owner', translate('规则所有者（须与所有节点同一租户）'), users.map(user => [user.id, `${user.username} · ${user.tenant_id}`]), state.actor.id);
  const route = el('p', '', 'workflow-callout'), layers = el('div');
  form.append(grid, advanced, el('h3', translate('转发链的各层'), 'setup-step'), route, layers);
  form.append(el('p', translate('只创建普通 TCP / UDP 转发，节点之间不加 WS / WSS 隧道或多路径。端口按已保存的配置避让，预览不会占用端口；防火墙需允许所示端口。'), 'fine'));
  function show() {
    const chain = usable.find(item => item.id === chainField.value), inside = new Set(chain.layers.flatMap(layer => layer.members.map(member => member.node_id)));
    const candidates = snapshot.nodes.filter(node => node.tenant_id === chain.tenant_id && !inside.has(node.id)), previous = entry.value;
    entry.replaceChildren(...candidates.map(node => { const option = el('option', node.name); option.value = node.id; return option; }));
    entry.value = (candidates.find(node => node.id === previous) || candidates.find(node => node.id === state.selectedNode) || candidates[0])?.id || '';
    const latency = chain.layers.some(layer => layer.balance === 'lowest_latency');
    if (latency) protocol.value = 'tcp'; protocol.disabled = latency;
    route.textContent = [translate('客户端'), translate('入口'), ...chain.layers.map((layer, index) => msg`第 ${index + 1} 层（${layer.members.length} 台候选 · ${balanceNames[layer.balance] || layer.balance}）`), translate('目标')].join(' → ');
    layers.replaceChildren(table([translate('层'), translate('端点组'), translate('候选服务器'), translate('选择方式')], chain.layers.map((layer, index) => [String(index + 1), layer.group_name || layer.group_id, memberNames(layer.members), balanceNames[layer.balance] || layer.balance])));
    if (!candidates.length) layers.append(el('p', translate('这个租户中没有链外的服务器可以作为入口。'), 'error'));
  }
  chainField.addEventListener('change', show); show();
  submit(form, translate('预览发布内容'), async data => {
    const chain = usable.find(item => item.id === chainField.value), rawPort = String(data.get('entry_port') ?? '').trim();
    if (!entry.value) throw new Error(translate('这个租户中没有链外的服务器可以作为入口。'));
    const body = { entry_node_id: entry.value, name: String(data.get('name')).trim(), protocol: protocol.value, target: String(data.get('target')).trim(), entry_port: rawPort ? Number(rawPort) : null };
    if (owner.value && owner.value !== state.actor.id) body.owner_id = owner.value;
    const path = `/chains/${encodeURIComponent(chain.id)}`, plan = await api(`${path}/plan`, { method: 'POST', body });
    const expected_revisions = Object.fromEntries(plan.batch.updates.map(update => [update.node_id, update.expected_revision]));
    const summary = msg`「${body.name}」经过 ${chain.layers.length} 层，在 ${plan.hops.length} 台服务器上各新建一条规则；客户端连接 ${plan.hops[0].advertise}。发布时如果任何一台服务器的配置已变化，全部不修改，请重新预览。`;
    await previewTopology(snapshot, plan.batch, summary, () => modal(title, form), [{ node_id: body.entry_node_id, rule_id: plan.entry_rule_id }], null,
      { preview: plan.preview, publish: () => api(`${path}/apply`, { method: 'POST', body: { ...body, expected_revisions } }) });
  });
  modal(title, form);
}
async function newTopologyChain(snapshot, preset = {}) {
  const minimum = preset.single ? 1 : 2;
  const title = preset.single ? translate('新建转发 · 单台服务器') : translate('新建转发 · 入口 → 中转 → 出口');
  if (snapshot.nodes.length < minimum) { notify(translate('请先注册路径所需的 VPS 并安装 Agent。'), true); return; }
  const users = await api('/users');
  const form = el('form'), rows = [], holder = el('div', undefined, 'path-picker'), header = el('div', undefined, 'form-grid');
  form.append(el('p', translate('选择 VPS，面板自动填写地址并分配端口。先预览整条路径，再确认发布。'), 'workflow-callout'));
  field(header, 'name', translate('链路名称'), preset.name || '').maxLength = 80;
  const mode = select(header, 'exit_service', translate('出口服务'), localize([['forward', '转发到固定目标'], ['ss', '在出口 VPS 创建 Shadowsocks']]), preset.mode || 'forward');
  form.append(header, el('h3', preset.single ? translate('1. 选择服务 VPS') : translate('1. 选择入口、中转和出口'), 'setup-step'), holder);
  const status = el('p', '', 'fine'); status.setAttribute('role', 'status');
  const addRelay = button(translate('＋ 添加中转 VPS（可选）'), () => { add(rows.length - 1); draw(); schedule(); });
  form.append(addRelay, status);
  const targetBox = el('div');
  const targets = textarea(targetBox, 'targets', translate('最终目标（IP 或域名:端口，每行一个）'), '', true); targets.placeholder = 'destination.example.com:443';
  const serviceHome = el('div'), serviceFields = el('div'), serviceHint = el('p', translate('出口服务正在下方的图示编辑器中编辑。'), 'fine hidden');
  serviceHome.append(serviceHint, serviceFields);
  form.append(el('h3', translate('2. 设置出口服务'), 'setup-step'), serviceHome);
  const ss = shadowsocksEditor(null); ss.setEnabled(mode.value === 'ss'); ss.box.open = false;
  const ssNote = el('p', preset.single ? translate('已自动生成 SS 密钥。客户端直接连接所选 VPS 上的 SS 服务。') : translate('已自动生成 SS 密钥。只有出口 VPS 运行 SS；客户端连接入口，前面的 VPS 仅转发加密流量。'), 'fine');
  serviceFields.append(targetBox, ssNote, ss.box);
  const advanced = el('details'); advanced.append(el('summary', translate('高级选项：协议、所有者与隧道')));
  const tuning = el('div', undefined, 'form-grid'); advanced.append(tuning);
  const ownerField = select(tuning, 'owner', translate('规则所有者（须与所有节点同一租户）'), users.map(user => [user.id, `${user.username} · ${user.tenant_id}`]), state.actor.id);
  const protocol = select(tuning, 'protocol', translate('传输协议（TCP / UDP）'), [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP + UDP']], preset.protocol || 'both');
  const transport = select(tuning, 'transport', translate('节点间传输'), [['plain', translate('原生 TCP / UDP')], ['ws', translate('WS 流隧道 · 仅 TCP')], ['wss', translate('WSS 双向证书 · 仅 TCP')]], 'plain');
  const secure = el('div', undefined, 'form-grid');
  const identity = field(secure, 'server_identity', translate('中转 / 出口的服务器证书编号'), 'server');
  const authority = field(secure, 'ca_identity', translate('各节点的信任 CA 编号'), 'root');
  const clientIdentity = field(secure, 'client_identity', translate('入口 / 中转的客户端证书编号'), 'client');
  const wsFields = el('div'), wsPath = field(wsFields, 'ws_path', translate('WebSocket 路径'), '/relay'); wsPath.maxLength = 1024;
  advanced.append(secure, wsFields); form.append(advanced);
  let selectedRow = null;
  const inspector = el('section', undefined, 'path-inspector hidden'), inspectorHead = el('div', undefined, 'path-inspector-head');
  inspector.setAttribute('aria-label', translate('编辑选中的路径节点'));
  const inspectorTitle = el('h3'), inspectorBody = el('div', undefined, 'path-inspector-body'), inspectorHop = el('div'), inspectorService = el('div');
  inspectorHead.append(inspectorTitle, button(translate('完成此跳编辑'), () => {
    const ref = selectedRef(); selectedRow = null; draw(); if (ref) pathView.focusNode(ref);
  }));
  inspectorBody.append(inspectorHop, inspectorService); inspector.append(inspectorHead, inspectorBody);
  const pathView = forwardingPathView({ onSelect: item => editHop(rows.find(row => row.node.value === item.node_id)), selected: selectedRef }), placement = el('p', '', 'fine');
  function selectedRef() { return selectedRow ? { node_id: selectedRow.node.value, rule_id: `diagram-${rows.indexOf(selectedRow)}` } : null; }
  function editHop(row) {
    if (!row || !rows.includes(row)) return;
    selectedRow = row; row.options.open = true; draw();
    inspector.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); row.node.focus({ preventScroll: true });
  }
  let serial = 0, requestSerial = 0, timer;
  const errorNames = localize({ address_required: '请先保存此 VPS 的可达地址。', ports_exhausted: '自动分配范围内没有可用端口；请调整节点端口范围。', port_in_use: '手动指定的端口已被配置占用，请更换。' });
  const selectedNode = row => snapshot.nodes.find(node => node.id === row.node.value);
  const hopInputs = () => rows.map(row => ({ node_id: row.node.value, listen: row.listen.value.trim(), advertise: row.advertise.value.trim(), tls_name: row.tlsName.value.trim(), allow_sources: row.sources.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean) }));
  function resetSetup(row, defaults) {
    row.setup.replaceChildren(el('p', translate('此 VPS 的地址填写一次，以后自动复用。请使用客户端或上一跳可以访问的 IP 或域名。'), 'fine'));
    row.defaults = forwardingDefaultsEditor(row.setup, defaults || selectedNode(row).profile?.settings?.forwarding, `defaults-${row.index}`);
    const save = button(translate('保存 VPS 地址并自动分配'), async () => {
      save.disabled = true;
      try {
        const node = selectedNode(row), value = row.defaults.read();
        if (!value) throw new Error(errorNames.address_required);
        const profile = await api(`/nodes/${node.id}/profile`, { method: 'PUT', body: { expected_revision: node.profile.revision, name: node.name, settings: { ...node.profile.settings, forwarding: value } } });
        // Profile responses are versioned separately from forwarding rules.
        node.profile = profile.profile;
        row.editAddress = false; await allocate();
      } catch (error) {
        row.issue.textContent = error.message;
      } finally { save.disabled = false; }
    });
    row.setup.append(save);
  }
  function draw() {
    if (!rows.includes(selectedRow)) selectedRow = null;
    holder.replaceChildren();
    rows.forEach((row, index) => {
      const middle = index > 0 && index < rows.length - 1;
      row.legend.textContent = rows.length === 1 ? translate('服务 VPS · 入口与出口') : index === 0 ? translate('入口 VPS · 客户端连接这里') : index === rows.length - 1 ? translate('出口 VPS · 最后一跳') : msg`中转 VPS · 第 ${index + 1} 跳`;
      row.controls.classList.toggle('hidden', !middle);
      row.up.disabled = index <= 1; row.down.disabled = index >= rows.length - 2;
      if (row === selectedRow) {
        const placeholder = el('div', undefined, 'path-hop path-hop-placeholder');
        placeholder.append(el('strong', row.legend.textContent), el('p', selectedNode(row).name), button(translate('正在图中编辑 · 查看设置'), () => editHop(row)));
        holder.append(placeholder);
        if (row.card.parentElement !== inspectorHop) inspectorHop.replaceChildren(row.card);
        inspectorTitle.textContent = msg`编辑 ${row.legend.textContent}`;
      } else holder.append(row.card);
    });
    inspector.classList.toggle('hidden', !selectedRow);
    if (!selectedRow) inspectorHop.replaceChildren();
    const exitSelected = selectedRow && selectedRow === rows.at(-1);
    const destination = exitSelected ? inspectorService : serviceHome;
    if (serviceFields.parentElement !== destination) destination.append(serviceFields);
    inspectorService.classList.toggle('hidden', !exitSelected); serviceHint.classList.toggle('hidden', !exitSelected);
    inspectorBody.classList.toggle('with-service', !!exitSelected);
    show();
  }
  function add(position = rows.length) {
    if (rows.length >= Math.min(16, snapshot.nodes.length)) return;
    const index = serial++, card = el('fieldset', undefined, 'path-hop'), legend = el('legend'); card.append(legend);
    const preferred = rows.length === 0 ? snapshot.nodes.find(n => n.id === preset.entryNode) : null;
    const node = select(card, `node-${index}`, translate('运行节点 / VPS'), snapshot.nodes.map(n => [n.id, n.name]), preferred?.id || snapshot.nodes.find(n => !rows.some(r => r.node.value === n.id))?.id);
    const endpoint = el('p', '', 'endpoint-summary mono'), issue = el('p', '', 'error'), setup = el('div', undefined, 'address-setup');
    const options = el('details'); options.append(el('summary', translate('高级：手动端口、来源限制与节点地址')));
    const manual = checkbox(options, `manual-${index}`, translate('为这条路径手动指定地址和端口'));
    manual.parentElement.classList.add('inline-check');
    const fields = el('div', undefined, 'form-grid');
    const listen = field(fields, `listen-${index}`, translate('本机监听地址'), '', 'text', false);
    const advertise = field(fields, `advertise-${index}`, translate('客户端或上一跳连接的地址'), '', 'text', false);
    options.append(fields);
    const tlsName = field(options, `tls_name-${index}`, translate('此节点证书中的服务名'), '', 'text', false);
    const sources = textarea(options, `sources-${index}`, translate('此跳允许来源 CIDR（留空不限）'));
    const note = el('p', '', 'fine'); options.append(note);
    const row = { index, card, legend, node, endpoint, issue, setup, options, manual, fields, listen, advertise, tlsName, sources, note, result: null, editAddress: false, previousNode: node.value };
    options.append(button(translate('修改此 VPS 的连接默认值'), () => { row.editAddress = !row.editAddress; show(); }));
    const controls = el('div', undefined, 'toolbar'); row.controls = controls;
    row.up = button(translate('上移'), () => { const i = rows.indexOf(row); if (i > 1) [rows[i - 1], rows[i]] = [rows[i], rows[i - 1]]; draw(); schedule(); });
    row.down = button(translate('下移'), () => { const i = rows.indexOf(row); if (i > 0 && i < rows.length - 2) [rows[i], rows[i + 1]] = [rows[i + 1], rows[i]]; draw(); schedule(); });
    row.remove = button(translate('移除此跳'), () => { const i = rows.indexOf(row); if (i > 0 && i < rows.length - 1) rows.splice(i, 1); draw(); schedule(); });
    controls.append(row.up, row.down, row.remove); card.append(endpoint, issue, setup, options, controls);
    node.addEventListener('change', () => {
      // Swapping lets a two-node path change its entry without a third VPS.
      const other = rows.find(item => item !== row && item.node.value === row.node.value);
      if (other) other.node.value = row.previousNode;
      for (const changed of other ? [row, other] : [row]) {
        changed.previousNode = changed.node.value; changed.manual.checked = false;
        changed.listen.value = changed.advertise.value = ''; changed.result = null; changed.editAddress = false; resetSetup(changed);
      }
      draw(); schedule();
    });
    manual.addEventListener('change', () => { show(); schedule(); });
    for (const input of [listen, advertise]) input.addEventListener('input', () => { show(); schedule(); });
    rows.splice(position, 0, row); resetSetup(row);
  }
  function schedule() {
    ++requestSerial; clearTimeout(timer); status.textContent = translate('正在自动填写地址并分配端口…');
    timer = setTimeout(() => allocate().catch(error => { status.textContent = error.message; }), 200);
  }
  async function allocate(strict = false) {
    clearTimeout(timer); const sequence = ++requestSerial;
    const hops = rows.map(row => ({ node_id: row.node.value, ...(row.manual.checked ? { listen: row.listen.value.trim(), advertise: row.advertise.value.trim() } : {}) }));
    if (new Set(hops.map(h => h.node_id)).size !== hops.length) throw new Error(translate('每一跳请选择不同的 VPS。'));
    let allocation;
    try { allocation = await api('/configurations/allocate-endpoints', { method: 'POST', body: { hops } }); }
    catch (error) { if (sequence !== requestSerial && !strict) return null; throw error; }
    if (sequence !== requestSerial) { if (strict) throw new Error(translate('选择已变化，请重新预览。')); return null; }
    rows.forEach((row, index) => {
      row.result = allocation.endpoints[index];
      if (!row.manual.checked) { row.listen.value = row.result.listen || ''; row.advertise.value = row.result.advertise || ''; }
      if (row.result.defaults && !row.defaults.host.value) resetSetup(row, row.result.defaults);
    });
    const failed = allocation.endpoints.find(endpoint => endpoint.error);
    status.textContent = failed ? translate('请补全标出的 VPS 设置后继续。') : translate('地址和端口已自动填好。下一步预览并检查发布内容。');
    show();
    if (failed && strict) throw new Error(errorNames[failed.error] || failed.error);
    return allocation;
  }
  function show() {
    const proxy = mode.value === 'ss';
    if (proxy || rows.length === 1) transport.value = 'plain'; transport.disabled = proxy || rows.length === 1;
    const ws = transport.value !== 'plain', tls = transport.value === 'wss';
    if (ws) protocol.value = 'tcp'; protocol.disabled = ws;
    sectionVisible(secure, tls); sectionVisible(wsFields, ws); sectionVisible(targetBox, !proxy); targets.required = !proxy;
    sectionVisible(ss.box, proxy); ssNote.classList.toggle('hidden', !proxy);
    addRelay.classList.toggle('hidden', !!preset.single); addRelay.disabled = rows.length >= Math.min(16, snapshot.nodes.length);
    const names = rows.map(row => selectedNode(row)?.name || '—');
    placement.textContent = proxy && preset.single ? msg`路径：客户端 → ${names[0]}（SS）→ 客户端请求的目的地。` : proxy ? msg`路径：${names.join(' → ')}。SS 仅运行于最后的 ${names.at(-1)}；前面的 VPS 转发加密流量。所有 VPS 都需要 Agent，SS 已内置。` : msg`路径：${names.join(' → ')} → 固定目标。每个 VPS 创建一条转发规则；不会安装额外代理服务。`;
    rows.forEach((row, index) => {
      row.listen.readOnly = row.advertise.readOnly = !row.manual.checked;
      row.listen.required = row.advertise.required = row.manual.checked;
      row.fields.classList.toggle('hidden', !row.manual.checked);
      row.tlsName.disabled = !tls || index === 0; row.tlsName.required = tls && index > 0; row.tlsName.parentElement.classList.toggle('hidden', !tls || index === 0);
      if (tls && index > 0) row.options.open = true;
      row.endpoint.textContent = row.advertise.value ? msg`连接 ${row.advertise.value} · 监听 ${row.listen.value}` : translate('等待自动分配地址和端口');
      row.issue.textContent = errorNames[row.result?.error] || '';
      sectionVisible(row.setup, row.editAddress || (!row.manual.checked && row.result?.error === 'address_required'));
      const node = selectedNode(row);
      row.note.textContent = (index === 0 ? translate('入口来源为客户端地址。') : translate('中转或出口通常看到上一跳地址；请勿直接复制客户端来源白名单。')) + ' ' + (node.enrolled ? translate('已注册 Agent；发布后检查应用回执。') : translate('尚未连接 Agent；发布只保存配置，不会自动 SSH 安装。'));
    });
    pathView.update(forwardingPathDiagram(snapshot, { hops: hopInputs(), mode: mode.value, protocol: protocol.value, transport: transport.value, owner: users.find(u => u.id === ownerField.value), uot: proxy && ss.read()?.udp_over_tcp, targets: targets.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean).map(address => ({ address, weight: 1 })) }));
  }
  mode.addEventListener('change', () => { sectionVisible(ss.box, true); ss.setEnabled(mode.value === 'ss'); if (mode.value === 'ss') protocol.value = 'both'; show(); });
  for (const input of [transport, protocol, ownerField, ss.box]) input.addEventListener('change', show);
  targets.addEventListener('input', show);
  add(); if (!preset.single) add(); draw();
  form.append(el('h3', translate('3. 预览路径'), 'setup-step'), placement, pathView.box, inspector);
  form.append(el('p', translate('端口按已保存配置避让，预览不会占用端口。发布时再次检查修订和冲突；实际监听由 Agent 应用后确认，防火墙需允许所示端口。'), 'fine'));
  submit(form, translate('预览发布内容'), async data => {
    form.inert = true;
    try {
      const allocation = await allocate(true);
      const current = { ...snapshot, configs: snapshot.configs.map(config => allocation.configs.find(fresh => fresh.node_id === config.node_id) || config) };
      const messages = localize({ path_hops: '路径需要 1–16 跳。', path_duplicate: '每一跳请选择不同的 VPS。', path_name: '请填写路径名称。', path_mode: '请选择有效的路径类型和传输协议。', path_transport: 'WS / WSS 仅支持 TCP；SS 向导使用原生转发。', path_ss: '请为出口选择 Shadowsocks 加密方式。', path_targets: '请填写至少一个最终目标。', path_tenant: '所有节点与规则所有者必须属于同一租户。', path_listen: '请为每一跳填写有效的监听地址和端口。', path_advertise: '请填写每一跳实际可达的 IP 或域名和端口，不能使用通配地址。', path_config: '节点配置缺失，请刷新后重试。' });
      let input;
      try {
        input = buildForwardingPath(current, { name: String(data.get('name')), owner: users.find(u => u.id === ownerField.value), mode: mode.value, protocol: protocol.value, transport: transport.value, ws_path: wsPath.value.trim(), server_identity: identity.value.trim(), ca_identity: authority.value.trim(), client_identity: clientIdentity.value.trim(), shadowsocks: mode.value === 'ss' ? ss.read() : null, targets: targets.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean).map(address => ({ address, weight: 1 })), hops: hopInputs() }, () => crypto.randomUUID());
      } catch (error) { throw new Error(messages[error.message] || error.message); }
      const returnToEdit = ref => {
        modal(title, form);
        if (ref) editHop(rows[input.updates.findIndex(update => update.node_id === ref.node_id && update.rules.at(-1).id === ref.rule_id)]);
        schedule();
      };
      await previewTopology(current, input, placement.textContent, () => returnToEdit(), [{ node_id: input.updates[0].node_id, rule_id: input.updates[0].rules.at(-1).id }], returnToEdit);
    } finally { form.inert = false; }
  });
  modal(title, form);
  await allocate().catch(error => { status.textContent = error.message; });
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
  const actor = state.actor;
  const nodes = await api('/nodes');
  if (state.view !== 'health' || !actor || state.actor !== actor) return;
  if (!nodes.length) { if (state.view === 'health') $('#content').replaceChildren(empty(translate('还没有节点'), translate('先接入节点，再在规则中设置目标健康探测。'))); return; }
  if (!nodes.some(n => n.id === state.selectedNode)) state.selectedNode = (nodes.find(online) || nodes[0]).id;
  const selected = state.selectedNode, toolbar = el('div', undefined, 'toolbar node-toolbar'), selector = el('select'); selector.setAttribute('aria-label', translate('选择节点'));
  nodes.forEach(node => { const option = el('option', node.name); option.value = node.id; selector.append(option); }); selector.value = selected; selector.onchange = async () => { state.selectedNode = selector.value; await refresh(); }; const nodeLabel = el('label', translate('节点')); nodeLabel.append(selector); toolbar.append(nodeLabel);
  const charts = displayMode('health') === 'chart', [snapshot, telemetry] = await Promise.all([api(`/nodes/${selected}/health`), charts ? api('/telemetry') : null]);
  if (state.view !== 'health' || state.actor !== actor || state.selectedNode !== selected) return;
  const node = nodes.find(n => n.id === selected);
  const nodeStatus = el('div', undefined, 'node-toolbar-status'), nodeTools = el('div', undefined, 'node-toolbar-actions');
  nodeStatus.append(badge(online(node) ? translate('控制在线') : translate('无近期控制回报'), online(node) ? 'green' : 'orange'), badge(msg`生效 v${snapshot.applied_revision} / 期望 v${snapshot.desired_revision}`)); nodeTools.append(displayToggle('health', renderHealth), button(translate('配置规则'), () => navigate('rules')));
  toolbar.append(nodeTools, nodeStatus);
  const panelHealth = panel(translate('目标观测与选路'), translate('TCP 与 UDP 独立判断；同优先级按规则的均衡策略分配，低优先级目标作为候选后备。已有 TCP 不会因单次健康状态变化被强制迁移。丢包与抖动按每个端点最近 20 次探测计算；“最低延迟”选路把丢包计入耗时。'));
  const kinds = { tcp_connect: translate('传输建立'), tcp_exchange: translate('TCP 响应前缀'), udp_exchange: translate('UDP 完整回复') };
  const statuses = { unknown: translate('尚未确认'), healthy: translate('探测通过'), unhealthy: translate('已摘除'), recovering: translate('恢复观察'), stale: translate('结果过期') };
  const reasons = selectionReasons, errors = probeErrors;
  const info = el('div', undefined, 'panel-body health-summary'); info.append(el('p', msg`最近节点回报：${timestamp(snapshot.last_seen_ms)} · ${snapshot.reports.length} / ${snapshot.expected_endpoints} 个配置端点有记录 · 当前探测 ${snapshot.active_probes} 个`)); if (snapshot.apply_error) info.append(el('p', msg`配置应用失败：${snapshot.apply_error}`, 'error')); panelHealth.append(info);
  if (!snapshot.reports.length) panelHealth.append(empty(translate('暂无目标探测结果'), snapshot.expected_endpoints ? translate('节点尚未上报这些端点的结果，不能视为健康。') : translate('在规则编辑器启用健康探测，填写对应业务的成功条件。')));
  else if (charts) {
    // Bar length is the smoothed probe time; the colour is the observed state.
    const slot = { healthy: 0, recovering: 1, unhealthy: 2 }, body = el('div', undefined, 'panel-body chart-body');
    body.append(barChart(snapshot.reports.map(r => {
      const values = [0, 0, 0, 0], loss = r.window_checks ? Math.round(100 * r.window_failures / r.window_checks) : null; values[slot[r.status] ?? 3] = r.latency_ewma_us ?? 0;
      const silent = r.status === 'unhealthy' && r.latency_ewma_us == null, time = silent ? translate('无响应') : millis(r.latency_ewma_us);
      return { label: snapshot.rule_names?.[r.rule_id] || r.rule_id, detail: `${r.target_address} · ${kinds[r.probe_kind]}`, values, failed: silent, text: loss == null ? time : msg`${time} · 丢包 ${loss}%`,
        title: [statuses[r.status], reasons[r.selection_reason] || r.selection_reason, r.last_error ? errors[r.last_error] : ''].filter(Boolean).join(' · ') };
    }), [[statuses.healthy, 'up'], [statuses.recovering, 'partial'], [statuses.unhealthy, 'down'], [translate('尚未确认或结果过期'), 'unknown']]));
    panelHealth.append(body);
  } else panelHealth.append(table([translate('规则 / 目标'), translate('端口 / 成功条件'), translate('观测状态'), translate('选路原因'), translate('优先级 / 会话'), translate('耗时 / 丢包 · 抖动'), translate('连续成功 / 失败'), translate('诊断')], snapshot.reports.map(r => {
    const diagnostic = el('details'); diagnostic.append(el('summary', r.last_error ? errors[r.last_error] : translate('查看探测统计')), el('p', msg`完成 ${r.completed_checks} 次，成功 ${r.successful_checks} 次`), el('p', msg`结果年龄 ${r.sample_age_ms === null ? '—' : msg`${(r.sample_age_ms / 1000).toFixed(1)} 秒`}，有效期 ${(r.max_age_ms / 1000).toFixed(1)} 秒`), el('p', msg`源节点探测应用量：发送 ${bytes(r.probe_sent_bytes)} / 接收 ${bytes(r.probe_received_bytes)}`), el('p', msg`节点记录时间：${timestamp(r.checked_at_ms)}`));
    return [namedCell(snapshot.rule_names?.[r.rule_id] || r.rule_id, r.target_address), namedCell(String(r.listen_port), kinds[r.probe_kind]), badge(statuses[r.status], r.eligible ? 'green' : 'orange'), r.selection_reason === 'degraded' ? namedCell(translate('丢包降级'), translate('同级暂作后备')) : r.selection_reason === 'draining' ? namedCell(translate('维护排空'), translate('仅作最后备用')) : r.selection_reason === 'paused' ? namedCell(translate('已暂停'), translate('不接新连接 · 探测继续')) : reasons[r.selection_reason] || r.selection_reason, `${r.priority} / ${r.active_sessions} / ${r.max_sessions ?? translate('不限')}`, namedCell(r.latency_ewma_us === null ? '—' : `${(r.latency_ewma_us / 1000).toFixed(2)} ms`, r.window_checks ? msg`丢包 ${Math.round(100 * r.window_failures / r.window_checks)}% · 抖动 ${r.jitter_us == null ? '—' : `${(r.jitter_us / 1000).toFixed(2)} ms`}` : translate('尚无探测')), `${r.consecutive_successes} / ${r.consecutive_failures}`, diagnostic];
  })));
  if (!charts) { $('#content').replaceChildren(toolbar, panelHealth); return; }
  const series = nodeSeries(telemetry.nodes.find(t => t.id === selected)?.samples || [], telemetry.generated_at_ms), trends = el('div', undefined, 'chart-grid');
  trends.append(chartPanel(translate('探测往返（中位数）'), msg`${node.name} 最近 15 分钟，来自每次节点回报。`, trendChart(series.latency.map(median), 'violet', millis, telemetry.generated_at_ms)),
    chartPanel(translate('目标可用比例'), translate('探测通过的目标占已探测目标的比例。'), trendChart(series.available, 'up', v => `${Math.round(v * 100)}%`, telemetry.generated_at_ms, 1)));
  $('#content').replaceChildren(toolbar, panelHealth, trends);
}
