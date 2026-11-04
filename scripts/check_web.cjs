const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert');
const root=path.resolve(process.env.WEB_ROOT || path.join(__dirname,'../dist/web'));
const server=http.createServer((req,res)=>{const pathname=decodeURIComponent(req.url.split('?')[0]);const file=path.join(root,pathname==='/'?'index.html':pathname);if(!file.startsWith(root+path.sep)){res.writeHead(403).end();return;}fs.readFile(file,(e,data)=>{if(e){res.writeHead(404).end();return;}res.setHeader('Content-Type',({'.html':'text/html','.css':'text/css','.svg':'image/svg+xml','.js':'text/javascript','.py':'text/plain'})[path.extname(file)]||'application/octet-stream');res.end(data);});});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({headless:true});
 try {
 const context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
 if(process.env.AXE_PATH) await context.addInitScript({path:process.env.AXE_PATH});
 const page=await context.newPage();const errors=[],posts=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(r.method()!=='GET')posts.push({method:r.method(),url:r.url()});});
 await page.goto(`http://127.0.0.1:${server.address().port}`);
 await page.locator('#sample').click();await page.locator('#analyze').click();
 await page.waitForFunction(()=>!document.getElementById('results').hidden || !document.getElementById('error').hidden,{},{timeout:120000});
 if(await page.locator('#error').isVisible())throw Error(await page.locator('#error').innerText());
 assert(await page.locator('.finding').count()>0);
 console.log('SAMPLE:',await page.locator('#metrics').innerText());
 if(process.env.WEB_SCREENSHOTS) await page.screenshot({path:path.join(process.env.WEB_SCREENSHOTS,'storage-log-web-desktop.png'),fullPage:true});
 const download=page.waitForEvent('download');await page.locator('#download-json').click(); const dl=await download;await dl.saveAs(path.join(require('os').tmpdir(),'storage-log-web-result.json'));
 const result=JSON.parse(fs.readFileSync(path.join(require('os').tmpdir(),'storage-log-web-result.json')));assert(result.event_count>0);assert(result.findings.length>0);
 // Confirm log text remains data, and same-device controller/path escalation uses the real engine.
 await page.locator('#clear').click();
 const rows=[{timestamp:'2026-11-04T12:00:00Z',device:'array-a',vendor:'pure',message:'controller 1 failed <img src=x onerror=alert(1)>'},{timestamp:'2026-11-04T12:00:10Z',device:'array-a',vendor:'pure',message:'path 1 failed'}];
 await page.locator('#files').setInputFiles({name:'correlation.jsonl',mimeType:'application/json',buffer:Buffer.from(rows.map(r=>JSON.stringify(r)).join('\n'))});await page.locator('#analyze').click();
 await page.waitForFunction(()=>!document.getElementById('results').hidden || !document.getElementById('error').hidden,{},{timeout:120000});
 if(await page.locator('#error').isVisible())throw Error(await page.locator('#error').innerText());
 assert((await page.locator('#findings').innerText()).includes('controller path correlation'));
 assert.equal(await page.locator('#findings img').count(),0);
 await page.locator('#clear').click();
 await page.locator('#files').setInputFiles({name:'bad.jsonl',mimeType:'text/plain',buffer:Buffer.from('{broken')});await page.locator('#analyze').click();await page.locator('#error').waitFor({state:'visible',timeout:120000});assert(await page.locator('#results').isHidden());
 console.log('INVALID INPUT:',await page.locator('#error').innerText());
 await page.locator('#clear').click();
 await page.locator('#files').setInputFiles({name:'huge.log',mimeType:'text/plain',buffer:Buffer.alloc(21*1024*1024,65)});assert(await page.locator('#error').isVisible());assert(await page.locator('#analyze').isDisabled());
 await page.locator('#files').setInputFiles({name:'empty.log',mimeType:'text/plain',buffer:Buffer.alloc(0)});assert((await page.locator('#error').innerText()).includes('empty'));
 for(const width of [320,375,768]){await page.setViewportSize({width,height:900});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`overflow ${width}`);}
 await page.setViewportSize({width:375,height:900});if(process.env.WEB_SCREENSHOTS) await page.screenshot({path:path.join(process.env.WEB_SCREENSHOTS,'storage-log-web-mobile.png'),fullPage:true});
 if(process.env.AXE_PATH){const violations=await page.evaluate(async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)})));assert.deepEqual(violations,[]);console.log('Accessibility checks passed');}
 assert.deepEqual(posts,[],'No log content should be posted');assert.deepEqual(errors,[]);
 console.log('PASS: real browser analysis, correlation, safe evidence, downloads, malformed/empty/oversized inputs, responsive layouts, no outbound uploads.');
 }finally{await browser.close();server.close();}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
