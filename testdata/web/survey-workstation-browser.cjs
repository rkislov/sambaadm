// Real SSR shell and scripts, synthetic offline snapshots only. No domain access.
const {chromium}=require('playwright');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-survey-'));
execFileSync('go',['test','./internal/web','-run','^TestSurveyBrowserFixture$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_SURVEY_FIXTURE_DIR:dir}});
const oldID='a'.repeat(64),newID='b'.repeat(64),marker='<img src=x onerror=alert(1)>';
function material(time,server){return {node:'ws.example.test',site:'Branch',sha256:'test',imported:time,snapshot:{profile:'alt-workstation',node:'ws.example.test',site:'Branch',helper:'test',started:time,finished:time,checks:[{source:'rpm -q sssd',observed:time,status:'observed',detail:'sssd-test'}],workstation:{format:1,configs:[{path:'/etc/sssd/sssd.conf',status:'observed',mode:'0600',owner:'root:root',observed:time,omitted:1,issues:[marker],settings:[{section:'domain/example.test',key:'ad_server',value:server}]}],dns:[{resolver:'192.0.2.53',name:'app.example.test.',type:'A',transport:'tcp',observed:time,status:'observed',rcode:'NXDOMAIN',answers:[],durationMs:5}]}}};}
const records={[oldID]:material('2026-11-10T10:00:00Z','dc1.example.test'),[newID]:material('2026-11-10T11:00:00Z','dc2.example.test')};
const server=http.createServer((req,res)=>{
 const p=new URL(req.url,'http://localhost').pathname;
 if(p.startsWith('/api/v1/surveys')) {res.setHeader('Content-Type','application/json');const id=p.split('/').pop();res.end(JSON.stringify(records[id] || [{id:newID,imported:records[newID].imported},{id:oldID,imported:records[oldID].imported}]));return;}
 const file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,'surveys.html');
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',p.endsWith('.js')?'application/javascript':p.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
 try {
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  for(const width of [375,1366]) {
   await page.setViewportSize({width,height:1000});await page.goto(`http://127.0.0.1:${server.address().port}/surveys`);
   await page.getByRole('heading',{name:'Карточка рабочей станции'}).waitFor();
   assert.match(await page.locator('#survey-view').innerText(),/dc2.example.test/);
   assert.match(await page.locator('#survey-view').innerText(),/NXDOMAIN/);
   assert.match(await page.locator('#survey-view').innerText(),/<img src=x/);
   assert.equal(await page.locator('#survey-view img').count(),0,'untrusted import rendered as HTML');
   assert(await page.locator('main').evaluate(e=>e.scrollWidth<=e.clientWidth),'main overflows');
   await page.getByText('Сравнить два снимка станции',{exact:true}).click();
   await page.locator('#survey-before').selectOption(oldID);await page.locator('#survey-compare').click();
   await page.getByText('Изменение наблюдаемых данных',{exact:true}).waitFor();
   assert.match(await page.locator('#survey-diff').innerText(),/dc1.example.test/);
   assert.match(await page.locator('#survey-diff').innerText(),/dc2.example.test/);
   const download=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:'Скачать снимок станции'}).click()]);
   await download[0].saveAs(path.join(dir,`export-${width}.json`));
   assert.equal(JSON.parse(fs.readFileSync(path.join(dir,`export-${width}.json`),'utf8')).profile,'alt-workstation');
   if(process.env.SAMBAADM_SURVEY_SCREENSHOT)await page.screenshot({path:process.env.SAMBAADM_SURVEY_SCREENSHOT+`-${width}.png`,fullPage:true});
  }
  assert.deepEqual(errors,[]);console.log('Workstation browser checks passed at 375 and 1366px');
 } finally {await browser.close();server.close();fs.rmSync(dir,{recursive:true,force:true});}
})().catch(e=>{console.error(e);server.close();process.exitCode=1});
