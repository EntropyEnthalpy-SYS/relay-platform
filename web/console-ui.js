import { t as translate, msg, localize, searchAliases } from '/assets/i18n.js';
// The console shell is dependency-free and searches only its local page/guide index.
export const pageInfo = localize({
  overview: ['总览', 'NETWORK OVERVIEW', '节点在哪里、是否在线、流量走向哪里，一页看清。', 'observability', 'dashboard monitor globe map 总览 监控 地球 地图'],
  nodes: ['转发配置', 'STEP 1 · SERVERS', '第一步：接入服务器。管理每台服务器的位置、身份、默认地址与运行许可。', 'quickstart', 'server agent location 服务器 注册 位置'],
  topology: ['转发配置', 'STEP 2 · FORWARDING', '第二步：建立转发。每条转发从客户端出发，经过一台或多台服务器到达目标。', 'rules', 'chain route path forward 链路 路径 转发 多跳'],
  rules: ['转发配置', 'STEP 2 · FORWARDING', '同一份转发配置，按服务器列出它上面运行的监听端口和服务。', 'rules', 'proxy gateway vless reality tuic hysteria2 socks http2 代理 网关 节点规则'],
  templates: ['转发配置', 'REUSABLE TEMPLATES', '把常用的协议、目标和限制保存为模板，之后在任意服务器上一键创建规则。', 'rules', 'template 模板 模板库 端口'],
  health: ['监控与用量', 'TARGET HEALTH', '跟踪真实目标的探测结果，定位不可用的线路。', 'observability', 'latency failover 健康 延迟'],
  usage: ['监控与用量', 'TRAFFIC LEDGER', '按规则与周期查看已上报的流量，核对用量记录。', 'resources', 'traffic bandwidth 计量 流量'],
  budgets: ['监控与用量', 'SHARED BUDGETS', '在多个节点之间分配额度，追踪消费与尚未归还的预留。', 'resources', 'quota limit 配额 预算 限速'],
  alerts: ['监控与用量', 'ALERTS & NOTIFICATIONS', '为需要关注的运行事件设置通知通道。', 'observability', 'smtp email telegram 邮件 告警'],
  subscriptions: ['客户与服务', 'CLIENT SUBSCRIPTIONS', '将兼容规则交付给客户端，管理订阅的预览、有效期与撤销。', 'clients', 'clash mihomo sing-box subscription 客户端'],
  dns: ['客户与服务', 'MANAGED DNS', '管理服务商与解析记录，先观察变更，再按需要应用。', 'operations', 'cloudflare 域名 解析'],
  announcements: ['客户与服务', 'ANNOUNCEMENTS', '向工作空间与租户发布有明确生效时间的消息。', 'operations', '公告 消息'],
  tickets: ['客户与服务', 'SUPPORT DESK', '将问题、回复与处理状态放在同一条记录中。', 'operations', 'support 工单 支持'],
  commerce: ['客户与服务', 'WALLET & ORDERS', '查看现有钱包、套餐与订单记录；支付集成不在本轮交付范围。', 'operations', 'wallet order 钱包 订单'],
  users: ['系统与帮助', 'PEOPLE & PERMISSIONS', '管理账号与租户，按角色分配工作空间访问权限。', 'security', 'tenant role user 租户 用户 权限'],
  account: ['系统与帮助', 'ACCOUNT SECURITY', '管理登录保护、两步验证与自己的 API 令牌。', 'security', 'totp token password 安全 密码 令牌'],
  audit: ['系统与帮助', 'AUDIT LOG', '追踪操作发生的时间、执行者与对象。', 'security', 'audit history 审计 日志'],
  recovery: ['系统与帮助', 'RECOVERY & CONTINUITY', '检查恢复日志、备份与额度对账，保留系统的连续记录。', 'operations', 'backup restore 备份 恢复'],
  capabilities: ['系统与帮助', 'DELIVERY STATUS', '区分已实现的能力与仍在开发、等待验收的部分。', 'operations', 'features roadmap 功能 进度'],
  guide: ['系统与帮助', 'THE RELAY HANDBOOK', '从第一次连接到日常运维，在操作旁边找到答案。', 'quickstart', 'docs documentation help 文档 指南 帮助'],
});
// "By server" is a tab of Forwarding rules, so the sidebar highlights that entry.
export const navView = view => view === 'rules' ? 'topology' : view;
const adminViews = new Set(['dns', 'audit', 'recovery']);
export function canVisit(view, actor) {
  return !!actor && Object.hasOwn(pageInfo, view) && (!adminViews.has(view) || actor.role === 'system_admin') && (!['alerts', 'templates'].includes(view) || actor.role !== 'viewer');
}
export const guideArticles = localize([
  { id: 'quickstart', title: '连接你的第一个节点', subtitle: '从一台服务器开始，建立可观测的转发路径。', icon: 'server', read: '3 分钟', target: 'nodes', steps: [
    ['注册节点', '在「节点管理」创建节点，确认所属租户与用途，获取一次性注册令牌。令牌仅用于注册，请保存在受限权限的文件中。'],
    ['启动 Agent', '按照节点注册对话框中的部署信息，在服务器启动 Agent。控制服务地址、令牌文件与状态目录须对应同一个节点；等待控制在线。'],
    ['创建并检查转发', '进入「转发规则」点击“＋ 新建转发”，选择单台服务器或多跳的端口转发 / SS。选择服务器后地址和端口自动填好；缺少地址时仅需保存一次，再预览发布。'],
    ['验证完整链路', '使用真实客户端连接入口，核对目标响应和流量账本。控制在线只表示 Agent 可联系面板，不能代替业务连接测试。'],
  ], note: '小规格机器先从少量规则与连接开始。最低配置取决于协议、并发与流量，不能用空载内存推算满载容量。' },
  { id: 'rules', title: '规则、协议与多跳链路', subtitle: '先定义入口与目标，再按需要添加协议和策略。', icon: 'arrows', read: '4 分钟', target: 'topology', steps: [
    ['选择规则类型', '「转发规则」的“全部转发”从客户端展示整条连接，“按服务器”列出一台服务器上运行的规则；两者是同一份配置。「规则模板」保存可复用的规则，可直接新建或从现有规则另存。'],
    ['配置受管协议', 'VLESS、Reality、Hysteria2、TUIC、AnyTLS、Trojan 与 VMess 按对应表单配置。节点需要已部署支持的协议引擎；公网监听与本机桥接监听是不同端点。'],
    ['保护与限制', '按需要配置来源 / 目的地 ACL、配额、有效期、会话上限与限速。TLS 证书编号对应节点本地证书；Reality 私钥应保留在可信配置中。'],
    ['组织多跳与发布', '点击“＋ 新建转发”并选择多跳方式，选择入口与出口，按需添加中转；地址和端口自动分配。SS 仅在出口运行。点击“预览发布内容”检查图示后确认发布。等所有节点应用后，用“客户端链接”导入客户端并验证流量。'],
  ], note: 'MPTCP 的 Require 模式需要两端内核和网络支持。自有多路径聚合与 Linux MPTCP 是不同机制，不能用其中一种的结果替代另一种验收。' },
  { id: 'observability', title: '读懂监控与告警', subtitle: '把控制连通、目标探测和业务验证分开判断。', icon: 'activity', read: '3 分钟', target: 'health', steps: [
    ['查看总览', '吞吐曲线取自节点上报的采样；多跳流量逐跳计入。活跃会话合并 TCP 连接与 UDP 会话，没有近期回报时显示为空缺。'],
    ['检查目标健康', '选择节点查看 TCP / UDP 目标探测、可选状态和失败原因。探测往返不包含客户端到入口的网络，不能直接解释为用户端延迟。'],
    ['定位配置问题', '检查节点的期望 / 已应用修订与应用错误，再查看运行诊断。控制在线、配置应用成功、目标可用是三个不同信号。'],
    ['设置通知', '有管理权限的账号可配置通知通道与严重级别。SMTP 支持 TLS / STARTTLS；保存后使用测试通知验证目标收件端。'],
  ], note: '面板在部分运行页面每 5 秒刷新。输入筛选条件、打开对话框或切到后台时会暂停自动刷新，避免打断操作。' },
  { id: 'resources', title: '流量、额度与限速', subtitle: '理解消费、预留与可分配额度之间的关系。', icon: 'gauge', read: '3 分钟', target: 'budgets', steps: [
    ['确定额度范围', '规则额度与用户、租户、节点共享额度可共同生效。创建共享额度前，按页面指引暂停相关规则并等待节点确认。'],
    ['理解预留', '尚未归还的预留包含节点已获授权、尚未全部上报的额度。可分配额度以已承诺额度为依据，不能只用已上报消费计算。'],
    ['核对账本', '在「流量账本」按节点、规则与周期查看用量。重传、聚合额外负载与应用逻辑字节可能采用不同计数口径，结合运行诊断理解。'],
    ['验证限速', '用多条并发连接验证适用范围的总限速，并同时观察 CPU、内存与队列。最低硬件配置必须在预期并发和协议组合下验证。'],
  ], note: '控制器从旧备份恢复后可能暂停新增额度分配。应完成恢复与对账，不能通过清除记录来回收未知消费。' },
  { id: 'clients', title: '交付客户端订阅', subtitle: '将兼容规则转换为可预览、可撤销的订阅。', icon: 'link', read: '2 分钟', target: 'subscriptions', steps: [
    ['检查公开端点', '确认规则的公开访问地址、端口、协议和证书服务名正确。本机桥接地址不能作为客户端访问入口。'],
    ['选择客户端格式', '订阅按所有者收集兼容规则，可用节点标签筛选。当前订阅保存端点快照，不自动替换多跳入口端口；SS 多跳路径请在「转发规则」中使用该路径的“客户端链接”。不兼容的规则会列出原因。'],
    ['预览并导入', '先检查生成内容，再将订阅导入真实客户端，验证访问、DNS 和计量。Reality 私钥与内部桥接凭据不应出现在导出中。'],
    ['管理生命周期', '按需要设置有效期、轮换或撤销链接。订阅链接包含访问凭证，只分享给授权使用者。规则变化后按订阅页面的快照行为重新生成。'],
  ], note: '生成配置不等于客户端验收。每个要支持的客户端和协议组合都需要实际连接测试。' },
  { id: 'security', title: '账号与访问保护', subtitle: '把账号登录、节点身份和 API 凭据分别管理。', icon: 'shield', read: '3 分钟', target: 'account', steps: [
    ['配置两步验证', '在「账户安全」启用身份验证器并离线保存恢复码。恢复码是敏感凭据，不应发送到工单或写入共享文档。'],
    ['最小化 API 权限', '为 API 令牌设置实际需要的权限范围和有效期。定期撤销不用的令牌，避免把管理员会话当作长期集成凭据。'],
    ['明确角色边界', '系统管理员、租户管理员与只读用户的访问由服务端检查。导航和搜索只显示该角色允许访问的管理页面。'],
    ['管理节点身份', '节点资料中的身份管理支持轮换、紧急撤销与替换。撤销可能中断业务，操作前应阅读对应对话框中的影响说明。'],
  ], note: '远程控制服务应通过 HTTPS 反向代理访问。请勿把状态目录、管理员密码文件或订阅凭证放入公开目录。' },
  { id: 'operations', title: '运维与交付边界', subtitle: '让配置、恢复记录与验收结论保持一致。', icon: 'book', read: '3 分钟', target: 'capabilities', steps: [
    ['先观察后变更', 'DNS 托管先使用观察模式核对拟变更，再决定应用。公告和工单按租户作用域管理；对外通知需要明确接收者。'],
    ['保留恢复链', '备份应包含一致性数据库、恢复日志和需要的进度信息。恢复后先检查对账与执行状态，再开放业务流量。'],
    ['按真实场景验收', '依次验证单节点、跨节点、真实客户端、故障恢复与持续负载。记录系统、架构、内存、带宽和协议，避免不同条件下直接比较性能。'],
    ['查看功能进度', '「功能进度」列出当前实现状态。支付开发不在本轮范围；证书生命周期、部分组网能力和其他待验收目标仍需按交付清单推进。'],
  ], note: '本界面是持续开发版本。使用指南说明现有操作流程，不代表全部目标功能或所有部署环境已完成验收。' },
]);
export function parseRoute(hash) {
  const [view, topic] = String(hash).replace(/^#/, '').split('/');
  return { view: Object.hasOwn(pageInfo, view) ? view : 'overview', topic: guideArticles.some(a => a.id === topic) ? topic : 'quickstart' };
}
export function searchEntries(query, actor, titles) {
  const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  const entries = Object.entries(pageInfo).filter(([view]) => canVisit(view, actor)).map(([view, info]) => ({ view, title: titles[view], subtitle: info[0], keywords: [titles[view], info[1], info[2], info[4]].map(searchAliases).join(' '), icon: view === 'guide' ? 'book' : 'arrow' }));
  if (actor) entries.push(...guideArticles.map(a => ({ view: 'guide', topic: a.id, title: a.title, subtitle: translate('使用指南'), keywords: [a.title, a.subtitle, a.note, ...a.steps.flat()].map(searchAliases).join(' '), icon: 'book' })));
  return entries.filter(e => terms.every(t => `${e.title} ${e.keywords} ${e.subtitle}`.toLocaleLowerCase().includes(t))).sort((a, b) => Number(b.title.toLocaleLowerCase().includes(query.toLocaleLowerCase())) - Number(a.title.toLocaleLowerCase().includes(query.toLocaleLowerCase())));
}

const paths = {
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  server: 'M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6',
  arrows: 'M3 7h17l-4-4 M21 17H4l4 4', layers: 'm12 3 9 5-9 5-9-5z M3 12l9 5 9-5 M3 16l9 5 9-5',
  network: 'M9 3h6v6H9z M3 15h6v6H3z M15 15h6v6h-6z M12 9v3 M6 15v-3h12v3',
  activity: 'M2 12h4l3-8 6 16 3-8h4', chart: 'M4 3v17h17 M8 15V9 M13 15V5 M18 15v-4',
  gauge: 'M4 19a9 9 0 1 1 16 0 M7 17h10 M12 13l4-5 M12 4v2 M5 9l2 1 M19 9l-2 1',
  bell: 'M6 8a6 6 0 0 1 12 0c0 7 3 7 3 9H3c0-2 3-2 3-9 M10 21h4',
  link: 'm10 13 4-4 M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0 M16 8l1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0',
  globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3a18 18 0 0 1 0 18 18 18 0 0 1 0-18',
  flag: 'M5 21V3h14l-3 4 3 4H5', message: 'M3 3h18v14H8l-5 4z M7 7h10 M7 11h6',
  wallet: 'M21 7H4a2 2 0 0 1 0-4h14v4 M3 5v15h18V7 M21 11h-6v5h6 M18 13.5h.01',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M17 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-4-4',
  shield: 'm12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6z m-4 10 3 3 5-6',
  list: 'M8 5h13 M8 12h13 M8 19h13 M3 5h.01 M3 12h.01 M3 19h.01',
  restore: 'M3 11a9 9 0 1 1 3 8 M3 4v7h7 M12 7v5l3 2', check: 'm5 12 4 4L19 6 M21 12v8H3V3h13',
  book: 'M12 5C9 3 5 3 2 4v16c4-1 7-1 10 1 3-2 6-2 10-1V4c-3-1-7-1-10 1z M12 5v16',
  search: 'M16 10a6 6 0 1 1-12 0 6 6 0 0 1 12 0 m-1 5 6 6',
  menu: 'M4 6h16 M4 12h16 M4 18h16', sun: 'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1 1 M18 18l1 1 M5 19l1-1 M18 6l1-1',
  sliders: 'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
  home: 'm3 10 9-8 9 8 M5 9v12h14V9 M9 21v-8h6v8', refresh: 'M20 7a9 9 0 0 0-15-2L2 8 M2 2v6h6 M4 17a9 9 0 0 0 15 2l3-3 M16 16h6v6',
  logout: 'M9 4H3v16h6 M9 12h13l-5-5 M22 12l-5 5', arrow: 'M4 12h16l-6-6 M20 12l-6 6',
};
export function createConsoleUI({ navigate, getActor, getView, el, button, modal, titles }) {
  const $ = s => document.querySelector(s);
  function icon(name) { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); for (const [k, v] of Object.entries({viewBox:'0 0 24 24', fill:'none', stroke:'currentColor', 'stroke-width':'1.5', 'stroke-linecap':'round', 'stroke-linejoin':'round', 'aria-hidden':'true'})) s.setAttribute(k,v); const p = document.createElementNS(s.namespaceURI, 'path'); p.setAttribute('d', paths[name] || paths.book); s.append(p); return s; }
  document.querySelectorAll('[data-icon]').forEach(n => n.replaceChildren(icon(n.dataset.icon)));
  const media = matchMedia('(max-width: 920px)'), sidebar = $('#sidebar'), toggle = $('#menu-toggle');
  let drawerOpen = false, previousFocus = null, results = [], selected = 0;
  function drawer(open, restoreFocus = false) {
    drawerOpen = open && media.matches; document.body.classList.toggle('nav-open', drawerOpen);
    toggle.setAttribute('aria-expanded', String(drawerOpen)); toggle.setAttribute('aria-label', drawerOpen ? translate('关闭导航') : translate('打开导航'));
    sidebar.inert = media.matches && !drawerOpen; $('#nav-backdrop').hidden = !drawerOpen;
    $('#main-content').inert = drawerOpen;
    if (drawerOpen) sidebar.querySelector('.nav-button.active:not(.hidden)')?.focus();
    else if (restoreFocus) toggle.focus();
  }
  toggle.onclick = () => drawer(!drawerOpen, drawerOpen); $('#nav-backdrop').onclick = () => drawer(false, true);
  media.addEventListener('change', () => drawer(false)); drawer(false);
  $('#console-tab').onclick = () => navigate('overview'); $('#guide-tab').onclick = () => navigate('guide');
  $('.skip-link').onclick = event => { event.preventDefault(); $('#main-content').focus(); };
  window.addEventListener('hashchange', () => { if (getActor()) { const route = parseRoute(location.hash); navigate(route.view, { topic: route.topic, history: false }); } });
  const dialog = $('#command-dialog'), input = $('#command-input'), list = $('#command-results');
  function selectResult(index) {
    selected = results.length ? (index + results.length) % results.length : 0;
    [...list.children].forEach((n, i) => { n.classList.toggle('selected', i === selected); n.setAttribute('aria-selected', String(i === selected)); });
    if (results.length) { input.setAttribute('aria-activedescendant', `command-result-${selected}`); list.children[selected].scrollIntoView({ block: 'nearest' }); }
    else input.removeAttribute('aria-activedescendant');
  }
  function openResult(index) { const r = results[index]; if (!r) return; closeSearch(false); navigate(r.view, { topic: r.topic }); }
  function drawResults() {
    results = searchEntries(input.value, getActor(), titles); list.replaceChildren();
    results.forEach((r, i) => { const row = el('div', undefined, 'command-result'); row.id = `command-result-${i}`; row.setAttribute('role', 'option'); const text = el('div'); text.append(el('strong', r.title), el('span', r.subtitle)); row.append(icon(r.icon), text, el('span', '↵', 'result-enter')); row.addEventListener('click', () => openResult(i)); list.append(row); });
    if (!results.length) { const empty = el('div', undefined, 'search-empty'); empty.setAttribute('role', 'presentation'); empty.append(el('strong', translate('没有找到匹配内容')), el('p', translate('试试“节点”、Reality、限速或订阅。'))); list.append(empty); }
    $('#command-status').textContent = msg`${results.length} 个结果`; selectResult(0);
  }
  function closeSearch(restore = true) { dialog.close(); input.value = ''; results = []; list.replaceChildren(); input.removeAttribute('aria-activedescendant'); if (restore && previousFocus?.isConnected) previousFocus.focus(); }
  function openSearch() { if (!getActor() || $('#dialog').open || dialog.open) return; previousFocus = document.activeElement; drawer(false); dialog.showModal(); input.value = ''; drawResults(); input.focus(); }
  $('#command-open').onclick = openSearch; $('#command-close').onclick = () => closeSearch(); input.addEventListener('input', drawResults);
  dialog.addEventListener('cancel', event => { event.preventDefault(); closeSearch(); });
  dialog.addEventListener('click', event => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) closeSearch(); } });
  input.addEventListener('keydown', event => { if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); selectResult(selected + (event.key === 'ArrowDown' ? 1 : -1)); } else if (event.key === 'Enter' && !event.isComposing) { event.preventDefault(); openResult(selected); } });
  document.addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k' && getActor()) { event.preventDefault(); dialog.open ? closeSearch() : openSearch(); }
    if (event.key === 'Escape' && drawerOpen) { event.preventDefault(); drawer(false, true); }
    if (event.key === 'Tab' && drawerOpen) {
      const controls = [...sidebar.querySelectorAll('button:not(.hidden)')].filter(n => !n.disabled && n.getClientRects().length);
      const first = controls[0], last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  function articleBody(article, compact = false) {
    const body = el('div', undefined, 'guide-prose');
    if (compact) body.append(el('p', article.subtitle, 'guide-lead'));
    const steps = el('div', undefined, 'guide-steps');
    article.steps.forEach(([title, text], i) => { const section = el('section'); section.id = `${compact ? "help" : "guide"}-step-${i}`; section.tabIndex = -1; section.append(el('span', String(i + 1).padStart(2, '0'), 'step-number')); const content = el('div'); content.append(el('h2', title), el('p', text)); section.append(content); steps.append(section); });
    const note = el('aside', undefined, 'guide-callout'); note.append(icon('book'), el('p', article.note));
    body.append(steps, note);
    if (canVisit(article.target, getActor())) body.append(button(msg`前往${titles[article.target]} →`, () => { $('#dialog').close(); return navigate(article.target); }, 'primary'));
    return body;
  }
  $('#context-help').onclick = () => { const article = guideArticles.find(a => a.id === (getView() === 'guide' ? parseRoute(location.hash).topic : pageInfo[getView()][3])); modal(article.title, articleBody(article, true)); };
  function sync(view) {
    const info = pageInfo[view]; $('#breadcrumb-group').textContent = info[0]; $('#breadcrumb-current').textContent = titles[view]; $('#page-kicker').textContent = info[1]; $('#view-description').textContent = info[2];
    document.title = `${titles[view]} · Relay`; $('#console-tab').classList.toggle('active', view !== 'guide'); $('#guide-tab').classList.toggle('active', view === 'guide');
    document.querySelectorAll('[data-view]').forEach(n => { if (n.dataset.view === navView(view)) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current'); });
    drawer(false); $('#main-content').dataset.view = view;
  }
  function renderGuide(container) {
    const topic = parseRoute(location.hash).topic, article = guideArticles.find(a => a.id === topic);
    const layout = el('div', undefined, 'guide-layout'), contents = el('nav', undefined, 'guide-contents'); contents.setAttribute('aria-label', translate('指南章节')); contents.append(el('p', 'EXPLORE THE HANDBOOK', 'nav-label'));
    guideArticles.forEach(a => { const b = button(a.title, () => navigate('guide', { topic: a.id }), 'guide-link'); b.prepend(icon(a.icon)); if (a.id === topic) { b.classList.add('active'); b.setAttribute('aria-current', 'page'); } contents.append(b); });
    const paper = el('article', undefined, 'guide-paper'), heading = el('div', undefined, 'guide-heading');
    heading.append(el('span', msg`操作指南 / ${article.read}`, 'guide-read'), el('h2', article.title), el('p', article.subtitle, 'guide-lead'));
    paper.append(heading, articleBody(article));
    const next = guideArticles[(guideArticles.indexOf(article) + 1) % guideArticles.length], onward = button(msg`继续阅读：${next.title} →`, () => navigate('guide', { topic: next.id }), 'guide-next'); paper.append(onward);
    const toc = el('nav', undefined, 'guide-toc'); toc.setAttribute('aria-label', translate('本文目录')); toc.append(el('p', translate('本文目录'), 'nav-label'));
    article.steps.forEach(([title], i) => toc.append(button(title, () => { const section = paper.querySelector(`#guide-step-${i}`); section.scrollIntoView({ block: 'start', behavior: 'instant' }); section.focus({ preventScroll: true }); }, 'toc-link')));
    toc.append(el('p', translate('指南随源码提供，离线可读。'), 'fine')); layout.append(contents, paper, toc); container.replaceChildren(layout);
  }
  return { sync, renderGuide, reset() { closeSearch(false); drawer(false); } };
}
