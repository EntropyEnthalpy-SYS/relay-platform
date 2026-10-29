// Exercise navigation/search authorization and deep links without a browser dependency.
const fs = require('node:fs'), assert = require('node:assert/strict');
(async () => {
  const source = fs.readFileSync('web/console-ui.js', 'utf8');
  const { pageInfo, canVisit, parseRoute, searchEntries, guideArticles } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
  const app = fs.readFileSync('web/app.js', 'utf8'), titles = Object.fromEntries([...app.match(/const titles = \{([^}]*)\};/)[1].matchAll(/(\w+): '([^']+)'/g)].map(m => [m[1], m[2]]));
  assert.deepEqual(Object.keys(titles).sort(), Object.keys(pageInfo).sort());
  const admin = { role: 'system_admin' }, tenant = { role: 'tenant_admin' }, viewer = { role: 'viewer' };
  assert.equal(searchEntries('', null, titles).length, 0, 'signed-out search must contain no results');
  for (const [actor, forbidden] of [[tenant, ['templates', 'dns', 'audit', 'recovery']], [viewer, ['templates', 'dns', 'audit', 'recovery', 'alerts']]]) {
    const results = searchEntries('', actor, titles);
    for (const view of forbidden) { assert.equal(canVisit(view, actor), false); assert.ok(!results.some(r => r.view === view), `search exposed restricted page ${view}`); }
    assert.ok(results.some(r => r.view === 'account')); assert.ok(results.some(r => r.topic === 'security'));
  }
  for (const view of Object.keys(pageInfo)) { assert.equal(canVisit(view, admin), true); assert.equal(parseRoute('#' + view).view, view); }
  for (const hash of ['', '#unknown', '#constructor', '#__proto__', '#<script>']) assert.equal(parseRoute(hash).view, 'overview');
  for (const article of guideArticles) {
    assert.deepEqual(parseRoute('#guide/' + article.id), { view: 'guide', topic: article.id });
    assert.ok(Object.hasOwn(pageInfo, article.target));
    assert.ok(searchEntries(article.title, viewer, titles).some(r => r.topic === article.id));
  }
  assert.equal(parseRoute('#guide/invalid').topic, 'quickstart');
  assert.ok(searchEntries(' REALITY ', admin, titles).some(r => r.view === 'rules'));
  assert.ok(searchEntries('smtp email', tenant, titles).some(r => r.view === 'alerts'));
  assert.ok(!searchEntries('smtp email', viewer, titles).some(r => r.view === 'alerts'));
  assert.ok(searchEntries('配额', viewer, titles).some(r => r.view === 'budgets'));
  assert.equal(searchEntries('no-such-page-xyz', admin, titles).length, 0);
  assert.ok(searchEntries('节点管理', admin, titles)[0].view === 'nodes', 'title matches should rank first');
  console.log('Console: 20 page routes, 7 guides, three-role search boundaries, signed-out empty index, aliases, ranking and invalid deep links passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
