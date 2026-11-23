// Certificate rollout uses the rendered settings page and authenticated API contract.
const {chromium}=require('playwright'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-navigation-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{const p=new URL(req.url,'http://localhost').pathname,file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,'admin-'+p.slice(1).replaceAll('/','_')+'.html');if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));});


(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});try{
 const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[],calls=[];let jobs=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/v1/certificates/rollouts',async route=>{const req=route.request();if(req.method()==='POST'){const body=req.postDataJSON();calls.push(body);assert.equal(req.headers()['x-csrf-token']?.length>0,true);
 if(body.action==='plan'){assert.equal(body.years,'10');assert.equal(body.renewCA,true);jobs=[{id:'a'.repeat(32),created:'2026-11-23T10:00:00Z',status:'planned',nodes:[{node:'dc1.example.org',phase:'prepared',expires:'2036-11-23T10:00:00Z'},{node:'rodc.example.org',phase:'prepared',expires:'2036-11-23T10:00:00Z'}]}];}
 if(body.action==='apply'){assert.equal(body.confirm,true);jobs[0].status='complete';jobs[0].nodes.forEach(n=>{n.phase='installed';n.state={phase:'installed'};});}
 await route.fulfill({json:jobs[0]});}else await route.fulfill({json:jobs});});
 await page.goto('http://127.0.0.1:'+server.address().port+'/settings/certificates');
 assert.equal(await page.locator('#certificate-years').inputValue(),'10');
 const section=page.locator('[data-certificate-rollout]');await section.getByRole('button',{name:'Подготовить план для всех DC',exact:true}).click();await section.getByText('План готов',{exact:false}).waitFor();assert.ok((await section.innerText()).includes('rodc.example.org'));
 const apply=section.getByRole('button',{name:'Применить план на всех DC',exact:true});assert.equal(await apply.isEnabled(),false);await section.getByRole('checkbox',{name:/Подтверждаю последовательные перезапуски/}).check();await apply.click();await section.getByText('Все DC проверены',{exact:false}).waitFor();assert.equal(calls.filter(c=>c.action==='apply').length,1);assert.equal(await section.getByRole('button',{name:'Откатить dc1.example.org',exact:true}).isEnabled(),false);
 await page.screenshot({path:path.join(dir,'certificate-rollout.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert.deepEqual(errors,[]);console.log('PASS: ten-year selection, all-DC plan including RODC, explicit apply/rollback confirmation, CSRF and responsive layout');console.log('Screenshot:',path.join(dir,'certificate-rollout.png'));
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
