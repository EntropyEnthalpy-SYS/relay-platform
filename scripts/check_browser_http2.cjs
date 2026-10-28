// Linux Chromium UI acceptance using a fresh profile and the DevTools protocol.
// Input is a private lab-access JSON, never include it in a verification ZIP.
const fs = require('node:fs/promises'), path = require('node:path'), assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {X509Certificate, createHash} = require('node:crypto');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
  const access = JSON.parse(await fs.readFile(process.argv[2], 'utf8'));
  const output = path.resolve(process.argv[3]); await fs.mkdir(output, {recursive:true});
  const proxyMode = process.argv.includes('--proxy');
  const profile = path.join(path.dirname(process.argv[2]), (proxyMode ? 'proxy-browser-profile-' : 'browser-profile-') + Date.now());
  const proxyFlags = [];
  if (proxyMode) {
    const cert = new X509Certificate(await fs.readFile(path.join(path.dirname(access.ca_file), '../server/cert.pem')));
    const spki = createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
    proxyFlags.push(`--proxy-server=https://127.0.0.1:${access.h2_port}`, '--proxy-bypass-list=<-loopback>', `--ignore-certificate-errors-spki-list=${spki}`);
  }
  const chrome = spawn(process.env.CHROMIUM || '/usr/bin/chromium', ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', ...proxyFlags, `--user-data-dir=${profile}`, 'about:blank'], {stdio:'ignore'});
  let socket; const failures=[]; const checks=[]; let next=1; let challenges=0; const pending=new Map();
  try {
    let port;
    for(let n=0;n<100;n++){try{port=Number((await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);break;}catch{await delay(100);}}
    assert.ok(port,'Chromium did not start');
    const tabs=await(await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);
    await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
    socket.onmessage=event=>{const value=JSON.parse(event.data);if(value.id){const p=pending.get(value.id);if(p){pending.delete(value.id);value.error?p.reject(new Error(value.error.message)):p.resolve(value.result);}} else if(value.method==='Fetch.requestPaused') {cdp('Fetch.continueRequest',{requestId:value.params.requestId}).catch(()=>{});} else if(value.method==='Fetch.authRequired') {challenges++; cdp('Fetch.continueWithAuth',{requestId:value.params.requestId,authChallengeResponse:value.params.authChallenge.source==='Proxy'?{response:'ProvideCredentials',username:access.proxy_user,password:access.proxy_password}:{response:'CancelAuth'}}).catch(()=>{});} else if(value.method==='Runtime.exceptionThrown') failures.push(value.params.exceptionDetails.text);};
    function cdp(method,params={}){return new Promise((resolve,reject)=>{const id=next++;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});}
    async function evaluate(expression){const result=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(result.exceptionDetails.exception?.description||result.exceptionDetails.text);return result.result.value;}
    async function wait(expression){for(let n=0;n<150;n++){if(await evaluate(expression))return;await delay(100);}throw new Error(`UI wait timed out: ${expression}`);}
    await cdp('Runtime.enable');await cdp('Page.enable');
    if(proxyMode){
      await cdp('Fetch.enable',{handleAuthRequests:true});
      await cdp('Page.navigate',{url:`https://127.0.0.1:${access.https_origin_port}/browser-proxy`});
      await wait(`document.body?.textContent.trim() === 'relay-browser-proxy-accepted'`);
      assert.ok(challenges>0,'proxy authentication was not exercised');
      const version=await cdp('Browser.getVersion');
      await fs.writeFile(path.join(output,'browser-proxy.json'),JSON.stringify({passed:true,browser:version.product,payload:'relay-browser-proxy-accepted',authentication:'Basic via proxy challenge',proxy:'HTTPS with fixture SPKI pin; server requires h2 ALPN',proxy_challenges:challenges},null,2)+'\n');
      console.log(JSON.stringify({passed:true,mode:'browser through HTTP2 proxy',browser:version.product}));return;
    }

    await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
    await cdp('Page.navigate',{url:`http://127.0.0.1:${access.controller_port}`});
    await wait(`typeof document.querySelector('#login-form')?.onsubmit === 'function'`);
    await evaluate(`document.querySelector('#login-form [name=password]').value=${JSON.stringify(access.admin_password)};document.querySelector('#login-form').requestSubmit();`);
    await wait(`!document.querySelector('#application').classList.contains('hidden')`);checks.push('real form login');
    await evaluate(`document.querySelector('[data-view=rules]').click()`);
    await wait(`document.querySelector('#content').textContent.includes('Managed HTTP2 TLS')`);checks.push('managed HTTP2 rule list renders');
    const openEdit=`[...document.querySelectorAll('#content tr')].find(r=>r.textContent.includes('Managed HTTP2 TLS')).querySelectorAll('button')`;
    await evaluate(`[...${openEdit}].find(b=>b.textContent==='编辑').click()`);
    await wait(`!!document.querySelector('#dialog [name=h2_streams]')`);
    const initial=await evaluate(`({limit:document.querySelector('[name=h2_streams]').value, tls:document.querySelector('[name=tls_identity]').value, tlsEnabled:!document.querySelector('[name=tls_identity]').disabled, hashes:document.querySelector('[name=h2_hashes]').value.split(/\\s+/).filter(Boolean).length})`);
    assert.equal(initial.limit,'128');assert.equal(initial.tls,'server');assert.ok(initial.tlsEnabled);assert.ok(initial.hashes>=1 && initial.hashes<8);checks.push('editor preserves TLS and bearer digest');
    await evaluate(`document.querySelector('#dialog form').requestSubmit()`);
    await wait(`!document.querySelector('#dialog').open`);checks.push('no-change edit publishes successfully');
    await wait(`document.querySelector('#content').textContent.includes('Managed HTTP2 TLS')`);
    await evaluate(`[...${openEdit}].find(b=>b.textContent==='编辑').click()`);
    await wait(`!!document.querySelector('#dialog [name=h2_hashes]')`);
    await evaluate(`[...document.querySelectorAll('#dialog button')].find(b=>b.textContent==='生成 Bearer 令牌').click()`);
    await wait(`document.querySelector('[name=h2_hashes]').value.split(/\\s+/).filter(Boolean).length===${initial.hashes + 1}`);
    assert.ok(await evaluate(`document.querySelector('#dialog pre').textContent.length===64`));
    await evaluate(`document.querySelector('#dialog form').requestSubmit()`);await wait(`!document.querySelector('#dialog').open`);
    checks.push('generate second bearer token and publish rotation overlap');
    // Read persisted policy independently of the DOM, without saving credentials.
    const config=await(await fetch(`http://127.0.0.1:${access.controller_port}/api/v1/nodes/${access.node_id}/config`,{headers:{Authorization:`Bearer ${access.session}`}})).json();
    const rule=config.rules.find(r=>r.id==='h2-linux');assert.equal(rule.inbound_http2_connect.bearer_token_sha256.length,initial.hashes+1);assert.equal(rule.inbound_tls.identity,'server');assert.equal(rule.targets.length,0);
    assert.equal(rule.inbound_http2_connect.max_concurrent_streams,128);checks.push('API confirms persisted TLS, credentials and limits');
    await cdp('Page.captureScreenshot',{format:'png'}).then(r=>fs.writeFile(path.join(output,'browser-rules.png'),Buffer.from(r.data,'base64')));
    assert.deepEqual(failures,[],'uncaught browser JavaScript errors');
    const version=await cdp('Browser.getVersion');
    await fs.writeFile(path.join(output,'browser.json'),JSON.stringify({passed:true,browser:version.product,checks,uncaught_exceptions:failures,revision:config.revision},null,2)+'\n');
    console.log(JSON.stringify({passed:true,checks:checks.length,browser:version.product}));
  } catch(error) {
    await fs.writeFile(path.join(output,proxyMode?'browser-proxy.json':'browser.json'),JSON.stringify({passed:false,checks,error:String(error),uncaught_exceptions:failures},null,2)+'\n');throw error;
  } finally {socket?.close();chrome.kill('SIGTERM');}
})().catch(error=>{console.error(error);process.exitCode=1;});
