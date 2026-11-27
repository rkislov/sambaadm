const {chromium}=require('playwright'),http=require('http'),fs=require('fs'),path=require('path'),assert=require('assert/strict');
const project=path.resolve(__dirname,'../..'),out=process.env.SAMBAADM_SYSVOL_SCREENSHOTS||'/tmp/sambaadm-sysvol-ui';fs.mkdirSync(out,{recursive:true});
const server=http.createServer((req,res)=>{
 if(req.url==='/'){res.setHeader('Content-Type','text/html');return res.end('<html lang="ru"><head><meta charset="utf-8"><meta name="csrf-token" content="test-csrf"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/domain-init-assets/wizard.css"><link rel="stylesheet" href="/domain-init-assets/theme.css"><link rel="stylesheet" href="/static/css/sysvol-sync.css"><script defer src="/static/js/sysvol-sync.js"></script></head><body><main class="di-shell ss-shell"><h1>Синхронизация SYSVOL</h1><div data-sysvol-sync></div></main></body></html>');}
 const file=['/domain-init-assets/wizard.css','/domain-init-assets/theme.css'].includes(req.url)?path.join(project,'internal/domaininit/assets',path.basename(req.url)):path.join(project,'internal/web',req.url);
 if(!file.startsWith(project)||!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':'text/css');res.end(fs.readFileSync(file));
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch();try{
 const page=await browser.newPage({viewport:{width:1280,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));let plans=0,applies=0,state='planned';
 const input={source:'win-dc1.corp.example',targets:['linux-dc1.corp.example'],policies:['{10000000-0000-0000-0000-000000000001}','{10000000-0000-0000-0000-000000000003}']};
 const job=()=>({id:'10000000-0000-0000-0000-000000000002',input,state,revision:'preview-token',created:new Date().toISOString(),items:[{gpo:input.policies[0],name:'Настройки рабочих станций',target:input.targets[0],state:state==='partial'?'applied':'ready',version:65538,versionKnown:true,changes:2,aclChanges:1,paths:['Содержимое: Machine/Registry.pol'],aclPaths:['Machine/Registry.pol'],message:state==='partial'?'Файлы и права проверены':'Готово к переносу'},{gpo:'{10000000-0000-0000-0000-000000000003}',name:'Ограничения входа',target:input.targets[0],state:'blocked',message:'LDAP получателя ещё не совпадает с источником'}]});
 await page.route('**/api/v1/gpo/sysvol-sync**',async route=>{const req=route.request(),url=new URL(req.url());let value;
  if(url.pathname.endsWith('/plan')){plans++;assert.equal(req.headers()['x-csrf-token'],'test-csrf');const body=req.postDataJSON();assert.equal(body.source,input.source);assert.deepEqual(body.targets,input.targets);assert.deepEqual(body.policies,input.policies);value=job();}
  else if(url.pathname.endsWith('/apply')){applies++;assert.deepEqual(req.postDataJSON(),{revision:'preview-token',confirm:true});assert.equal(req.headers()['x-csrf-token'],'test-csrf');state='partial';value=job();}
  else if(url.pathname.includes('/jobs/'))value=job();
  else value={controllers:[{dns:input.source,site:'Основной',rodc:false},{dns:input.targets[0],site:'Филиал',rodc:false}],targets:input.targets,policies:[{guid:input.policies[0],displayName:'Настройки рабочих станций'},{guid:input.policies[1],displayName:'Ограничения входа'}],history:[]};
  await route.fulfill({json:value});
 });
 await page.goto('http://127.0.0.1:'+server.address().port);
 await page.getByLabel('Источник SYSVOL').selectOption(input.source);await page.getByRole('checkbox',{name:input.targets[0],exact:true}).check();
 await page.locator('.di-shell').screenshot({path:path.join(out,'sysvol-selection.png')});await page.getByRole('button',{name:'Подготовить предпросмотр'}).click();
 await page.getByRole('button',{name:'Синхронизировать готовые пары GPO/DC'}).waitFor();assert.equal(applies,0);
 await page.getByRole('checkbox',{name:/Подтверждаю источник/}).check();await page.getByRole('button',{name:'Синхронизировать готовые пары GPO/DC'}).click();
 await page.getByText('Частично выполнено',{exact:false}).first().waitFor();assert.equal(applies,1);assert.equal(plans,1);
 await page.locator('.di-shell').screenshot({path:path.join(out,'sysvol-report.png')});await page.reload();await page.getByText('Синхронизировано',{exact:true}).waitFor();assert.equal(applies,1,'reload repeated writes');
 await page.setViewportSize({width:390,height:844});assert(!await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth));await page.locator('.di-shell').screenshot({path:path.join(out,'sysvol-mobile.png')});assert.deepEqual(errors,[]);
 console.log('PASS Russian SYSVOL selector, preview/confirmation/CSRF, partial delivery report, no replay on reload, mobile. Screenshots:',out);
 }finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
