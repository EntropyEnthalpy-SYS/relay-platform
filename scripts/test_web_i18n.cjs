const assert = require('node:assert/strict');
const { loadI18n, loadConsole, loadTitles, english } = require('./web_i18n_helpers.cjs');
let stored = null;
const storage = { getItem: () => stored, setItem: (key, value) => { assert.equal(key, 'relay-language'); stored = value; } };
const i18n = loadI18n(storage), shell = loadConsole(i18n), titles = loadTitles(i18n);
const admin = { role: 'system_admin' }, viewer = { role: 'viewer' };
assert.equal(i18n.getLanguage(), 'zh-CN');
assert.equal(titles.nodes, '节点管理');
assert.equal(i18n.setLanguage('en', storage), true);
assert.equal(titles.nodes, 'Nodes', 'existing label objects must update without reloading');
assert.equal(shell.guideArticles[0].title, 'Connect your first node');
assert.equal(loadI18n(storage).getLanguage(), 'en', 'preference must survive module/page reload');
assert.equal(i18n.setLanguage('invalid', storage), false);
assert.equal(i18n.getLanguage(), 'en');
assert.equal(i18n.t('__proto__'), '__proto__');
assert.equal(i18n.t('untranslated diagnostic'), 'untranslated diagnostic');
assert.equal(i18n.eventMessage({ kind: 'config_applied', message: '已应用配置修订 12' }), 'Applied configuration revision 12');
assert.equal(i18n.eventMessage({ kind: 'config_rejected', message: '节点拒绝新配置，继续运行修订 12：原始诊断 {0}' }), 'Node rejected the new configuration; still running revision 12: 原始诊断 {0}');
assert.equal(i18n.eventMessage({ kind: 'target_down', message: '规则 测试 的目标 example.test:443（TCP 端口 9000）不可用，新连接改用其他目标；原因：探测超时' }), 'Rule 测试: target example.test:443 (TCP port 9000) unavailable; new connections use other targets; reason: Probe timed out');
assert.equal(i18n.eventMessage({ kind: 'unknown', message: '已应用配置修订 12' }), '已应用配置修订 12');
const opaque = '节点管理 <img onerror=alert(1)> {1} $&';
assert.equal(i18n.msg(['删除「', '」会终止其会话，历史账本保留。'], opaque), `Deleting “${opaque}” terminates its sessions. Ledger history is preserved.`);
assert.equal(i18n.msg(['为「', '」输入新的 ', ' 地址（DDNS）；当前 ', ''], '测试', 'AAAA', '::1'), 'Enter a new AAAA address for “测试” (DDNS); current address: ::1');
const options = i18n.localize([['off', '关闭'], ['prefer', '优先 MPTCP · 允许 TCP 回退']]);
assert.equal(options[1][0], 'prefer');
assert.equal(options[1][1], 'Prefer MPTCP · Allow TCP fallback');
for (const locale of ['en', 'zh-CN']) {
  i18n.setLanguage(locale, storage);
  for (const query of ['节点管理', 'nodes', '配额', 'quota', 'SMTP', 'Reality']) {
    assert.ok(shell.searchEntries(query, admin, titles).length, `${locale} search misses ${query}`);
  }
  for (const view of ['templates', 'dns', 'audit', 'recovery', 'alerts']) assert.ok(!shell.searchEntries('', viewer, titles).some(r => r.view === view));
  for (const article of shell.guideArticles) {
    assert.ok(shell.searchEntries(article.title, viewer, titles).some(r => r.topic === article.id));
    assert.ok(article.steps.every(([title, text]) => title && text));
  }
}
assert.equal(titles.nodes, '节点管理');
assert.equal(options[1][1], '优先 MPTCP · 允许 TCP 回退');
const blocked = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
const fallback = loadI18n(blocked);
assert.equal(fallback.getLanguage(), 'zh-CN');
assert.equal(fallback.setLanguage('en', blocked), true);
assert.equal(fallback.t('保存'), 'Save');
for (const [source, translated] of Object.entries(english)) {
  assert.ok(translated.trim(), `empty translation: ${source}`);
  assert.deepEqual((source.match(/\{\d+\}/g) || []).sort(), (translated.match(/\{\d+\}/g) || []).sort(), `placeholder mismatch: ${source}`);
  assert.ok(!/[\u3400-\u9fff]/.test(translated), `untranslated English message: ${source}`);
}
console.log(`I18n: ${Object.keys(english).length} messages; persistent preference, live labels, bilingual role-filtered search, opaque interpolation, unchanged option values and blocked storage passed`);
