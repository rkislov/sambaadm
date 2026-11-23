// Acceptance feedback: a large OU must not fill navigation with account objects.
const {chromium}=require('playwright'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-navigation-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{const p=new URL(req.url,'http://localhost').pathname,file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,'admin-'+p.slice(1)+'.html');if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));});

(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],writes=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/v1/**',async route=>{const req=route.request(),p=new URL(req.url()).pathname;let result=[];
 if(p.endsWith('/domain/fsmo'))result=[{role:'DomainNamingMaster',owner:'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=example,DC=com',source:'ldap'}];
 if(p.endsWith('/sites/controllers'))result=[{dns:'dc1.example.com',rodc:false},{dns:'dc2.example.com',rodc:false},{dns:'rodc.example.com',rodc:true}];
 if(req.method()==='POST'){writes.push({path:p,body:req.postDataJSON()});result={status:'ok'};}
 await route.fulfill({json:result});});
 await page.goto('http://127.0.0.1:'+server.address().port+'/domain');await page.getByRole('status').filter({hasText:'Данные обновлены'}).waitFor();
 for(const operation of ['Передать роль','Захватить роль']) {
  await page.getByRole('button',{name:operation,exact:true}).click();const dialog=page.getByRole('dialog');const target=dialog.getByLabel('Новый владелец (RWDC)',{exact:true});await target.waitFor();
  assert.equal(await target.inputValue(),'');assert.equal(await target.locator('option').count(),3);assert.equal(await target.locator('option[value="rodc.example.com"]').count(),0);
  assert.equal(await dialog.getByLabel('Роль',{exact:true}).getAttribute('readonly'),'');await dialog.getByText(/Текущий владелец: CN=NTDS Settings,CN=DC1/).waitFor();
  await target.selectOption('dc2.example.com');await dialog.getByRole('checkbox').check();await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();
  await dialog.getByText('Операция выполнена',{exact:true}).waitFor();await dialog.getByRole('button',{name:'Закрыть',exact:true}).last().click();
  const sent=writes.at(-1);assert.equal(sent.body.targetDC,'dc2.example.com');assert.equal(sent.body.role,'DomainNamingMaster');if(operation==='Захватить роль')assert.equal(sent.body.confirmDecommissioned,true);
 }
 assert.deepEqual(errors,[]);console.log('PASS: FSMO transfer/seizure explicit RWDC picker, immutable role, current owner, RODC excluded, confirmations and target payload');
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
