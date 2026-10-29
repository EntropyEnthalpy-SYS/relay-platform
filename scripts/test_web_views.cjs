// Structural check: every sidebar view has a title and a refresh renderer.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2] || 'web/index.html', 'utf8');
const source = fs.readFileSync(process.argv[3] || 'web/app.js', 'utf8');
const views = [...html.matchAll(/data-view="([^"]+)"/g)].map(match => match[1]);
assert.ok(views.length >= 10, 'sidebar views not found');
assert.equal(new Set(views).size, views.length, 'duplicate data-view entries');
const block = source.match(/const titles = localize\(\{([^}]*)\}\);/);
assert.ok(block, 'titles map not found');
const titles = block[1].split(',').map(entry => entry.split(':')[0].trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
for (const view of views) assert.ok(titles.includes(view), `missing title for view ${view}`);
const refresh = source.match(/await \(\{([\s\S]*?)\}\)\[state\.view\]\(\)/);
assert.ok(refresh, 'refresh view map not found');
for (const view of views) {
  const key = /^[a-zA-Z_$][\w$]*$/.test(view) ? view : `'${view}'`;
  assert.ok(refresh[1].includes(`${key}: render`), `missing renderer for view ${view}`);
}
console.log(JSON.stringify({ views }));
