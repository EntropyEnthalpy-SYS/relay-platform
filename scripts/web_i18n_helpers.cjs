// Execute the shipped dependency-free modules in the existing VM-based UI tests.
const fs = require('node:fs'), vm = require('node:vm');
const english = JSON.parse(fs.readFileSync('web/i18n-en.js', 'utf8').split('export default ')[1].replace(/;\s*$/, ''));
function loadI18n(storage = { getItem: () => process.env.RELAY_TEST_LANGUAGE || 'zh-CN', setItem() {} }) {
  const source = fs.readFileSync('web/i18n.js', 'utf8').replace(/^import .*;\n/m, '').replace(/^export /gm, '');
  const api = vm.runInNewContext(source + '\n;({ t, msg, localize, searchAliases, getLanguage, setLanguage, readLanguage, languageStorageKey, eventMessage, incidentMessage })', { english, localStorage: storage });
  return { ...api, translate: api.t };
}
function loadConsole(i18n = loadI18n()) {
  const source = fs.readFileSync('web/console-ui.js', 'utf8').replace(/^import .*;\n/m, '').replace(/^export /gm, '');
  return vm.runInNewContext(source + '\n;({ pageInfo, guideArticles, canVisit, parseRoute, searchEntries })', i18n);
}
function loadTitles(i18n = loadI18n()) {
  const source = fs.readFileSync('web/app.js', 'utf8').match(/^const titles = (.*);$/m)[1];
  return vm.runInNewContext(source, i18n);
}
function loadWorkflows() {
  const source = fs.readFileSync('web/workflows.js', 'utf8').replace(/^export /gm, '');
  return vm.runInNewContext(source + '\n;({ serviceKind, splitEndpoint, clientEndpoint, applicationState, buildForwardingPath, shadowsocksPath, shadowsocksClientProfile, forwardingDiagram, forwardingPathDiagram, forwardingPathRoots })');
}
module.exports = { loadI18n, loadConsole, loadTitles, loadWorkflows, english };
