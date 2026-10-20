// Optional browser contract tests. Uses synthetic AD responses; never contacts a domain.
// NODE_PATH=<Playwright modules> PLAYWRIGHT_CHROMIUM_EXECUTABLE=<browser> node testdata/web/workspace.cjs
const {chromium} = require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict');
const {execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-web-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
let role='admin',failure=false;const calls=[];let altState='not-configured',altVersion=0,altDisabled=false,altUnavailable=false,altConflict=false;
const altOthers=[{id:'cups.service',label:'cups.service',state:'disabled'},{id:'custom.service',label:'Служба <img src=x onerror=alert(1)>',state:'unsupported'}];
const base='DC=example,DC=com',people='OU=People,'+base;
const user={samAccountName:'alice',displayName:'Alice <script>bad()</script>',enabled:true,dn:'CN=Alice,'+people};
const tree={dn:base,label:'example.com',kind:'domain',children:[{dn:people,label:'People',kind:'ou',children:[{dn:user.dn,objectDN:user.dn,parentDN:people,label:'alice',kind:'user',children:[]}]}]};
const listings={users:[user],groups:[{samAccountName:'Finance',dn:'CN=Finance,CN=Users,'+base,members:[user.dn]}],computers:[{samAccountName:'PC01$',dnsHostName:'pc01.example.com',dn:'CN=PC01,'+people}],ou:[{name:'People',dn:people}],gpo:[{displayName:'Workstation Baseline',guid:'{abc}',source:'ldap'}],sites:[{name:'Default',dn:'CN=Default,CN=Sites,CN=Configuration,'+base}],trusts:[{domain:'partner.test',direction:'both',type:'forest'}],shares:[{name:'Finance',path:'/srv/samba/Finance'}],printers:[{name:'Printer',printerName:'queue',path:'/srv/samba/spool'}]};
const server=http.createServer((req,res)=>{
 const pathname=new URL(req.url,'http://localhost').pathname;
 if(pathname.startsWith('/static/')){const file=path.join(repo,'internal/web',pathname);if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':'text/css');res.end(fs.readFileSync(file));return;}
 const file=path.join(dir,`${role}-${pathname.slice(1)}.html`);if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type','text/html');res.end(fs.readFileSync(file));
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const url=`http://127.0.0.1:${server.address().port}`;
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const req=route.request(),u=new URL(req.url()),endpoint=u.pathname.replace('/api/v1','');calls.push({method:req.method(),path:endpoint,query:u.searchParams,body:req.postDataJSON(),headers:req.headers()});
   let result={status:'ok'},status=200;
   if(req.method()!=='GET'){assert.ok(req.headers()['x-csrf-token'],'missing CSRF token');if(failure){status=502;result={error:'LDAP operation failed'};}else if(endpoint==='/users/alice/disable')user.enabled=false;else if(endpoint==='/users/alice/enable')user.enabled=true;else if(endpoint.endsWith('/distribute'))result={id:'job1',status:'running',progress:25,steps:[]};}
   else if(endpoint==='/directory/tree')result=u.searchParams.get('kind')==='ou'?{...tree,children:[{...tree.children[0],children:[]}]}:tree;
   else if(endpoint==='/dns/zones')result=[{name:'example.com',source:'ldap'}];
   else if(endpoint.endsWith('/nodes'))result=['@','files'];
   else if(endpoint.endsWith('/records'))result=[{name:u.searchParams.get('name'),type:'A',data:'192.0.2.20',raw:'A: 192.0.2.20'}];
   else if(endpoint==='/gpo/distribute/job1')result={id:'job1',status:'ok',progress:100,steps:[{title:'SYSVOL',status:'ok'}]};
   else if(endpoint==='/gpo/links')result='GPO: {abc}';
   else if(endpoint==='/repl/partners')result=[{name:'dc1',dn:'CN=NTDS Settings,'+base,status:'ok'}];
   else if(endpoint==='/domain/fsmo')result=[{role:'pdc',owner:'dc1',source:'ldap'}];
   else result=listings[endpoint.slice(1)]||user;
   if(endpoint.endsWith('/alt-settings')){
    if(altUnavailable){status=503;result={error:'unfinished policy save: inspect .sambaadm-editor.pending before further edits'};}
    else if(failure||(req.method()==='PUT'&&altConflict)){status=409;result={error:'policy changed; reload before saving'};}
    else {
     if(req.method()==='PUT'){const change=req.postDataJSON();assert.equal(change.revision,'revision-'+altVersion);assert.equal(change.id,'chronyd.service');altState=change.state;altVersion++;}
     result={version:altVersion,revision:'revision-'+altVersion,scope:'Machine',machineDisabled:altDisabled,settings:[{id:'chronyd.service',label:'chronyd.service',state:altState},...altOthers]};
    }
   }
   await route.fulfill({status,contentType:'application/json',body:JSON.stringify(result)});
  });
  const open=async module=>{await page.goto(url+'/'+module);await page.getByRole('status').filter({hasText:'Данные обновлены'}).waitFor();};
  const close=async()=>page.getByRole('dialog').getByRole('button',{name:'Закрыть',exact:true}).click();
  const screenshot=async name=>{if(process.env.SAMBAADM_WEB_SCREENSHOTS){fs.mkdirSync(process.env.SAMBAADM_WEB_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.SAMBAADM_WEB_SCREENSHOTS,name+'.png'),fullPage:true});await page.screenshot({path:path.join(process.env.SAMBAADM_WEB_SCREENSHOTS,name+'-guide.png'),clip:{x:0,y:0,width:1440,height:560}});}};
  await open('users');assert.equal(await page.locator('tbody tr').count(),1);assert.equal(await page.locator('tbody script').count(),0);
  await page.getByRole('button',{name:'People',exact:true}).click();assert.equal(await page.locator('tbody tr').count(),1);
  await page.getByRole('button',{name:'Сбросить пароль',exact:true}).click();let dialog=page.getByRole('dialog');await dialog.getByLabel('Новый пароль',{exact:true}).fill('TestPassword123!');await dialog.getByLabel('Повторите пароль').fill('different');assert.equal(await dialog.locator('input:invalid').count(),1);await dialog.getByLabel('Повторите пароль').fill('TestPassword123!');await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('Операция выполнена',{exact:true}).waitFor();assert.equal(await dialog.getByLabel('Новый пароль',{exact:true}).inputValue(),'');assert.equal(calls.find(c=>c.path.endsWith('/password')).body.password,'TestPassword123!');await close();
  await page.getByRole('button',{name:'Переместить',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('Подразделение или контейнер DN').fill('OU=Finance,'+base);await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('Операция выполнена',{exact:true}).waitFor();assert.equal(calls.find(c=>c.path.endsWith('/move')).body.toOU,'OU=Finance,'+base);await close();
  await page.getByRole('button',{name:'Отключить',exact:true}).click();dialog=page.getByRole('dialog');assert.equal(await dialog.locator('input:invalid').count(),1);await dialog.getByRole('checkbox').check();await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('Операция выполнена',{exact:true}).waitFor();await close();await page.getByRole('button',{name:'Включить',exact:true}).waitFor();
  failure=true;await page.getByRole('button',{name:'Включить',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByRole('alert').filter({hasText:'LDAP operation failed'}).waitFor();await close();failure=false;
  user.displayName='Алиса Иванова';await open('users');await page.locator('.directory-tree details').nth(1).locator('summary').click();await screenshot('users');
  await open('dns');await page.getByText('Имена записей',{exact:true}).click();await page.getByRole('button',{name:'files',exact:true}).waitFor();await page.getByRole('button',{name:'files',exact:true}).click();dialog=page.getByRole('dialog');assert.equal(await dialog.getByLabel('Имя записи',{exact:true}).inputValue(),'files');await dialog.getByRole('button',{name:'Показать',exact:true}).click();await dialog.getByText('A: 192.0.2.20',{exact:true}).waitFor();await close();
  await page.getByRole('button',{name:'Изменить запись',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('Имя записи',{exact:true}).fill('files');await dialog.getByLabel('Прежнее значение').fill('192.0.2.20');await dialog.getByLabel('Новое значение').fill('192.0.2.21');await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('Операция выполнена',{exact:true}).waitFor();assert.deepEqual(calls.find(c=>c.method==='PUT').body,{name:'files',type:'A',oldData:'192.0.2.20',newData:'192.0.2.21'});await close();await page.getByText('Имена записей',{exact:true}).click();await page.getByRole('button',{name:'files',exact:true}).waitFor();await screenshot('dns');
  await open('gpo');await page.getByRole('button',{name:'People',exact:true}).click();dialog=page.getByRole('dialog');assert.equal(await dialog.getByLabel('Полный DN').inputValue(),people);await dialog.getByRole('button',{name:'Показать',exact:true}).click();await dialog.getByText('GPO: {abc}',{exact:true}).waitFor();await close();
  await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('chronyd.service',{exact:true}).selectOption('enabled');await dialog.locator('form').filter({has:page.getByLabel('chronyd.service',{exact:true})}).getByRole('checkbox').check();await dialog.locator('form').filter({has:page.getByLabel('chronyd.service',{exact:true})}).getByRole('button',{name:'Сохранить',exact:true}).click();await dialog.getByText('Сохранено. Проверьте gpupdate и gpresult на ALT-клиенте.',{exact:true}).waitFor();assert.equal(altState,'enabled');assert.equal(await dialog.getByLabel('chronyd.service',{exact:true}).inputValue(),'enabled');if(process.env.SAMBAADM_WEB_SCREENSHOTS)await page.screenshot({path:path.join(process.env.SAMBAADM_WEB_SCREENSHOTS,'alt-editor.png'),fullPage:true});await close();
  await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');
  await dialog.getByLabel('cups.service',{exact:true}).waitFor();assert.equal(await dialog.getByLabel('cups.service',{exact:true}).inputValue(),'disabled');assert.equal(await dialog.locator('img').count(),0);assert.equal(await dialog.getByLabel('Служба <img src=x onerror=alert(1)>',{exact:true}).isDisabled(),true);
  let editForm=dialog.locator('form').filter({has:page.getByLabel('chronyd.service',{exact:true})});
  const writesBefore=calls.filter(c=>c.path.endsWith('/alt-settings')&&c.method==='PUT').length;
  await editForm.getByRole('button',{name:'Сохранить',exact:true}).click();assert.equal(calls.filter(c=>c.path.endsWith('/alt-settings')&&c.method==='PUT').length,writesBefore,'unconfirmed save sent request');
  altConflict=true;await editForm.getByRole('checkbox').check();await editForm.getByRole('button',{name:'Сохранить',exact:true}).click();await dialog.getByRole('alert').filter({hasText:'policy changed'}).waitFor();assert.equal(await dialog.getByRole('button',{name:'Сохранить',exact:true}).count(),0);
  altConflict=false;await dialog.getByRole('button',{name:'Перезагрузить параметры',exact:true}).click();await dialog.getByLabel('chronyd.service',{exact:true}).waitFor();assert.equal(await dialog.getByLabel('cups.service',{exact:true}).inputValue(),'disabled');await close();
  altDisabled=true;await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByText('Машинный раздел этой GPO отключён. Настройки не применятся, пока раздел не будет включён.',{exact:true}).waitFor();await close();altDisabled=false;
  altUnavailable=true;await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByRole('alert').filter({hasText:'.sambaadm-editor.pending'}).waitFor();assert.equal(await dialog.getByRole('button',{name:'Сохранить',exact:true}).count(),0);altUnavailable=false;await dialog.getByRole('button',{name:'Повторить',exact:true}).click();await dialog.getByLabel('chronyd.service',{exact:true}).waitFor();await close();
  failure=true;await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByText('policy changed; reload before saving',{exact:true}).waitFor();await close();failure=false;
  await page.getByRole('button',{name:'Восстановить в новую GPO',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('Имя новой политики',{exact:true}).fill('Restored Policy');await dialog.getByLabel('Каталог копии policy/{GUID} на сервере',{exact:true}).fill('/backup/policy/{abc}');await dialog.getByRole('checkbox').check();await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('Операция выполнена',{exact:true}).waitFor();assert.deepEqual(calls.find(c=>c.path==='/gpo/restore').body,{name:'Restored Policy',path:'/backup/policy/{abc}'});await close();
  await page.getByRole('button',{name:'Доставить на контроллеры',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByRole('checkbox').check();await dialog.getByRole('button',{name:'Выполнить',exact:true}).click();await dialog.getByText('100% · ok',{exact:true}).waitFor();await close();await screenshot('gpo');
  for(const module of ['groups','computers','ou','domain','sites','repl','trusts','shares','printers'])await open(module);
  role='readonly';await open('users');assert.equal(await page.getByRole('button',{name:'Создать пользователя',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Сбросить пароль',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Удалить',exact:true}).count(),0);await page.getByRole('button',{name:'Свойства',exact:true}).waitFor();
  await open('gpo');await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('chronyd.service',{exact:true}).waitFor();assert.equal(await dialog.getByRole('button',{name:'Сохранить',exact:true}).count(),0);assert.equal(await dialog.getByLabel('chronyd.service',{exact:true}).isDisabled(),true);await close();
  role='helpdesk';await open('users');await page.getByRole('button',{name:'Сбросить пароль',exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'Переместить',exact:true}).count(),0);
  await open('gpo');await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('chronyd.service',{exact:true}).waitFor();assert.equal(await dialog.getByRole('button',{name:'Сохранить',exact:true}).count(),0);await close();
  role='admin';await page.setViewportSize({width:390,height:844});await open('gpo');await page.getByRole('button',{name:'Параметры ALT',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByLabel('chronyd.service',{exact:true}).waitFor();assert.equal(await dialog.evaluate(e=>e.scrollWidth>e.clientWidth),false,'mobile ALT editor overflow');await close();await open('dns');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'mobile page overflow');
  assert.deepEqual(errors,[]);console.log('PASS: all 12 sections, user tree, password/move/status, DNS browsing/update, GPO links/jobs/ALT editor, RBAC, CSRF, errors, XSS text and mobile layout');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>{server.close();fs.rmSync(dir,{recursive:true,force:true});});
