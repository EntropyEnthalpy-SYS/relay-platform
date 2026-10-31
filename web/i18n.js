import english from './i18n-en.js';

// No remote translations, DOM observers or user-data rewriting. Only authored
// messages are translated. The existing Chinese interface remains the default.
export const languageStorageKey = 'relay-language';
export function readLanguage(storage) {
  try { return storage?.getItem(languageStorageKey) === 'en' ? 'en' : 'zh-CN'; }
  catch { return 'zh-CN'; }
}
let language = 'zh-CN';
try { language = readLanguage(globalThis.localStorage); } catch { /* Storage can be blocked. */ }
const listeners = new Set();
export const getLanguage = () => language;
export function setLanguage(next, storage) {
  if (!['zh-CN', 'en'].includes(next)) return false;
  try { (storage ?? globalThis.localStorage)?.setItem(languageStorageKey, next); } catch { /* Keep this session usable. */ }
  if (next === language) return false;
  language = next;
  for (const listener of listeners) listener(next);
  return true;
}
export function t(source, locale = language) {
  return locale === 'en' && Object.hasOwn(english, source) ? english[source] : source;
}
export function msg(parts, ...values) {
  const source = parts.map((part, index) => part + (index < values.length ? `{${index}}` : '')).join('');
  // Replace in one pass: a user's value can contain braces, markup or Chinese,
  // but must never become a second translation or interpolation instruction.
  return t(source).replace(/\{(\d+)\}/g, (placeholder, index) => Number(index) < values.length ? String(values[Number(index)]) : placeholder);
}
export function localize(value) {
  // Stable, read-only label trees resolve lazily so menus and handbook entries
  // change language without rebuilding application state or reloading the page.
  if (!value || typeof value !== 'object') return value;
  const result = Array.isArray(value) ? [] : {};
  for (const [key, item] of Object.entries(value)) {
    Object.defineProperty(result, key, typeof item === 'string'
      ? { enumerable: true, get: () => t(item) }
      : { enumerable: true, value: localize(item) });
  }
  return Object.freeze(result);
}
const aliases = new Map();
for (const [source, translated] of Object.entries(english)) {
  aliases.set(source, `${source} ${translated}`);
  aliases.set(translated, `${aliases.get(translated) || translated} ${source}`);
}
export const searchAliases = text => aliases.get(text) || text;

// Translate only recognized, typed telemetry envelopes. Error details, rule IDs
// and addresses remain opaque; unknown server messages keep their original text.
export function eventMessage(event) {
  if (language !== 'en') return event.message;
  const patterns = {
    config_applied: [/^已应用配置修订 (\d+)$/, match => msg`已应用配置修订 ${match[1]}`],
    config_recovered: [/^配置错误已解除，正在运行修订 (\d+)$/, match => msg`配置错误已解除，正在运行修订 ${match[1]}`],
    config_rejected: [/^节点拒绝新配置，继续运行修订 (\d+)：([\s\S]*)$/, match => msg`节点拒绝新配置，继续运行修订 ${match[1]}：${match[2]}`],
    node_reconnected: [/^节点在 (\d+) 秒无回报后恢复联系$/, match => msg`节点在 ${match[1]} 秒无回报后恢复联系`],
    target_down: [/^规则 (.+) 的目标 (.+)（(TCP|UDP) 端口 (\d+)）不可用，新连接改用其他目标(?:；原因：([\s\S]*))?$/, match => msg`规则 ${match[1]} 的目标 ${match[2]}（${match[3]} 端口 ${match[4]}）不可用，新连接改用其他目标${match[5] ? msg`；原因：${t(match[5])}` : ''}`],
    target_recovered: [/^规则 (.+) 的目标 (.+)（(TCP|UDP) 端口 (\d+)）恢复可用$/, match => msg`规则 ${match[1]} 的目标 ${match[2]}（${match[3]} 端口 ${match[4]}）恢复可用`],
    target_removed: [/^规则 (.+) 的目标 (\d+)（(TCP|UDP) 端口 (\d+)）已从配置移除$/, match => msg`规则 ${match[1]} 的目标 ${match[2]}（${match[3]} 端口 ${match[4]}）已从配置移除`],
    // Written by the controller's alert loop for node silence, not by telemetry.
    node_silent: [/^节点 (.+) 已 (\d+) 秒无回报$/, match => msg`节点 ${match[1]} 已 ${match[2]} 秒无回报`],
    node_reported: [/^节点 (.+) 恢复回报$/, match => msg`节点 ${match[1]} 恢复回报`],
  };
  const pattern = Object.hasOwn(patterns, event.kind) ? patterns[event.kind] : null;
  const match = pattern && String(event.message).match(pattern[0]);
  return match ? pattern[1](match) : event.message;
}
// An alert keeps the text of the event that opened or resolved it; its key prefix names the source.
const incidentKinds = { target: ['target_down', 'target_recovered', 'target_removed'], config: ['config_rejected', 'config_recovered'], node: ['node_silent', 'node_reported'] };
export function incidentMessage(incident) {
  const source = String(incident.key).split(':')[0];
  for (const kind of Object.hasOwn(incidentKinds, source) ? incidentKinds[source] : []) {
    const text = eventMessage({ kind, message: incident.summary });
    if (text !== incident.summary) return text;
  }
  return incident.summary;
}

export function setupLanguageSwitcher(onChange) {
  // Capture only the initial static shell, before any API content is rendered.
  // Retain text-node identities so inputs, icons and event handlers are untouched.
  const bindings = [], walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    if (node.parentElement?.closest('script, style, code, pre, [data-language-toggle]')) continue;
    const source = node.nodeValue, key = source.trim();
    if (Object.hasOwn(english, key)) {
      const textNode = node;
      bindings.push(() => {
        if (textNode.isConnected) textNode.nodeValue = source.replace(key, () => t(key));
      });
    }
  }
  for (const element of document.querySelectorAll('[placeholder], [title], [aria-label]')) {
    if (element.closest('[data-language-toggle]')) continue;
    for (const attribute of ['placeholder', 'title', 'aria-label']) {
      const source = element.getAttribute(attribute);
      if (source && Object.hasOwn(english, source)) bindings.push(() => {
        if (element.isConnected) element.setAttribute(attribute, t(source));
      });
    }
  }
  const buttons = [...document.querySelectorAll('[data-language-toggle]')];
  function apply() {
    document.documentElement.lang = language;
    for (const binding of bindings) binding();
    for (const button of buttons) {
      const next = language === 'en' ? 'zh-CN' : 'en';
      const label = button.querySelector('.language-name');
      label.textContent = next === 'en' ? 'English' : '中文';
      label.lang = next;
      const description = t(next === 'en' ? '切换到英文' : '切换到中文');
      button.setAttribute('aria-label', description);
      button.title = description;
    }
  }
  apply();
  document.title = t('Relay · 独立转发平台');
  listeners.add(() => { apply(); onChange(); });
  for (const button of buttons) button.addEventListener('click', () => setLanguage(language === 'en' ? 'zh-CN' : 'en'));
}
