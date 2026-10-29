const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2] || 'web/app.js', 'utf8');
const start = source.indexOf('function mptcpConfig('), end = source.indexOf('\nfunction mptcpEditor(', start);
const context = require('./web_i18n_helpers.cjs').loadI18n(); vm.createContext(context); vm.runInContext(source.slice(start, end) + '\nthis.read = mptcpConfig;', context);
assert.equal(context.read('off', 'off', 'tcp'), null);
assert.equal(JSON.stringify(context.read('require', 'prefer', 'both')), '{"inbound":"require","outbound":"prefer"}');
assert.throws(() => context.read('prefer', 'off', 'udp'));
assert.throws(() => context.read('typo', 'off', 'tcp'));
console.log('MPTCP editor preserves explicit fallback policies and rejects UDP-only rules');
