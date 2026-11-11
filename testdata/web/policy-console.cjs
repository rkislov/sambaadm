// Production policy console against synthetic ADMX data, without a domain connection.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict');
const {execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-policy-console-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
let role='admin',language='ru',version=0;const writes=[],errors=[];
const settings=Array.from({length:4500},(_,i)=>({id:'setting-'+i,label:'Policy '+String(i).padStart(4,'0'),template:'Example.admx',category:i%2?'Network':'System',description:'Description '+i+' <img src=x onerror=alert(1)>',state:['not-configured','enabled','disabled'][i%3],fields:[{id:'text',label:'Value',kind:'text',default:'initial'}]}));
settings[0].template='BaseALTSystemd.admx';
const server=http.createServer((req,res)=>{
 const pathname=new URL(req.url,'http://localhost').pathname;
 const file=pathname.startsWith('/static/')?path.join(repo,'internal/web',pathname):path.join(dir,`${role}-${pathname==='/settings'?'settings':'gpo'}.html`);
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');
 let data=fs.readFileSync(file);if(!pathname.startsWith('/static/'))data=data.toString().replace('lang="ru"','lang="'+language+'"');res.end(data);
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const req=route.request(),u=new URL(req.url()),endpoint=u.pathname.replace('/api/v1','');let result=[];
   if(endpoint==='/directory/tree')result={dn:'DC=example,DC=com',label:'example.com',kind:'domain',children:[]};
   else if(endpoint==='/gpo')result=[{displayName:'Workstation baseline',guid:'{abc}'}];
   else if(endpoint.endsWith('/alt-settings')){
    const scope=u.searchParams.get('scope')||'Machine';
    if(req.method()==='PUT'){const data=req.postDataJSON();writes.push(data);assert.equal(data.revision,'revision-'+version);const setting=settings.find(s=>s.id===data.id);setting.state=data.state;setting.values=data.values;version++;}
    result={scope,revision:'revision-'+version,version,settings,controller:'dc0.example.com',templateSource:'SYSVOL'};
   }
   await route.fulfill({json:result});
  });
  async function open(){await page.goto(`http://127.0.0.1:${server.address().port}/gpo`);await page.getByRole('status').filter({hasText:language==='ru'?'Данные обновлены':'Data refreshed'}).waitFor();if(await page.locator('.workspace-menu summary').count())await page.locator('.workspace-menu summary').click();await page.getByRole('button',{name:language==='ru'?'Редактор политик':'Policy editor',exact:true}).click();await page.locator('.policy-settings-table tbody tr').first().waitFor();return page.getByRole('dialog');}
  let dialog=await open();const table=dialog.locator('.policy-settings-table');
  assert.equal(await table.locator('tbody tr').count(),100,'large catalog must render a bounded page');
  assert.equal(await table.locator('tbody tr').filter({hasText:'Policy 0000'}).locator('.policy-platform-badge').textContent(),'ALT');assert.equal(await table.locator('tbody tr').filter({hasText:'Policy 0001'}).locator('.policy-platform-badge').count(),0);
  await dialog.getByText('Найдено: 4500 / 4500',{exact:true}).waitFor();await table.getByRole('button',{name:'Policy 0000',exact:true}).waitFor();
  await dialog.locator('.policy-list-pager').getByRole('button',{name:'Далее',exact:true}).click();await table.getByRole('button',{name:'Policy 0100',exact:true}).waitFor();
  await dialog.getByRole('combobox',{name:'Состояние параметра',exact:true}).selectOption('enabled');await dialog.getByText('Найдено: 1500 / 4500',{exact:true}).waitFor();
  assert.ok(await table.locator('tbody tr td:nth-child(2)').evaluateAll(cells=>cells.every(c=>c.textContent==='Включено')));
  await dialog.getByRole('combobox',{name:'Состояние параметра',exact:true}).selectOption('');
  await table.getByRole('button',{name:'Параметр',exact:true}).click();await table.getByRole('button',{name:'Policy 4499',exact:true}).waitFor();
  await dialog.locator('.policy-console-tree summary').filter({hasText:'BaseALTSystemd.admx'}).click();await dialog.getByRole('button',{name:'System (1)',exact:true}).click();assert.equal(await table.locator('tbody tr').count(),1,'same category in another template must not leak into this folder');await dialog.getByRole('button',{name:'Все параметры (4500)',exact:true}).click();
  await dialog.getByLabel('Поиск политик',{exact:true}).fill('Policy 0321');assert.equal(await table.locator('tbody tr').count(),1);
  await table.locator('tbody tr td:nth-child(2)').click();await dialog.locator('.policy-list-preview').getByText('Description 321 <img src=x onerror=alert(1)>',{exact:true}).waitFor();assert.equal(await dialog.locator('img').count(),0);
  await dialog.locator('.policy-list-preview').getByRole('button',{name:'Открыть параметр',exact:true}).click();
  let group=dialog.getByRole('group',{name:'Policy 0321',exact:true});await group.getByRole('radio',{name:'Включено',exact:true}).check();await dialog.getByLabel('Value',{exact:true}).fill('changed');
  await dialog.getByRole('button',{name:'К списку параметров',exact:true}).click();assert.equal(writes.length,0,'cancel/back must not persist');
  await dialog.getByRole('button',{name:'Policy 0321',exact:true}).click();group=dialog.getByRole('group',{name:'Policy 0321',exact:true});await group.getByRole('radio',{name:'Включено',exact:true}).check();await dialog.getByLabel('Value',{exact:true}).fill('saved');
  await dialog.getByRole('button',{name:'Сохранить',exact:true}).click();assert.equal(writes.length,0,'confirmation remains required');
  await dialog.getByLabel('Подтверждаю изменение этой политики',{exact:true}).check();await dialog.getByRole('button',{name:'Сохранить',exact:true}).click();await dialog.getByText('Сохранено. Проверьте gpupdate и gpresult на ALT-клиенте.',{exact:true}).waitFor();
  assert.deepEqual(writes[0],{id:'setting-321',state:'enabled',revision:'revision-0',scope:'Machine',values:{text:'saved'}});
  await dialog.getByRole('button',{name:'К списку параметров',exact:true}).click();await dialog.getByLabel('Поиск политик',{exact:true}).fill('');
  await dialog.locator('.policy-console-tree').getByRole('button',{name:'Конфигурация пользователя',exact:true}).click();await dialog.getByText(/Версия .*User/).waitFor();
  await dialog.locator('.policy-console-tree summary').filter({hasText:'Example.admx'}).click();await dialog.getByRole('button',{name:'Network (2250)',exact:true}).click();
  await dialog.getByText('Найдено: 2250 / 4500',{exact:true}).waitFor();assert.ok(await table.locator('tbody tr td:nth-child(4)').evaluateAll(cells=>cells.every(c=>c.textContent==='Network')));
  await page.screenshot({path:path.join(dir,'rsat-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.ok(await dialog.evaluate(e=>e.scrollWidth<=e.clientWidth),'mobile dialog must not overflow');
  await dialog.getByLabel('Поиск политик',{exact:true}).fill('Policy 0001');await dialog.getByRole('button',{name:'Policy 0001',exact:true}).click();await group.getByRole('radio').count();assert.ok(await dialog.evaluate(e=>e.scrollWidth<=e.clientWidth));assert.ok(await dialog.getByRole('radio').evaluateAll(inputs=>inputs.every(i=>i.getBoundingClientRect().width<=20)),'radio controls must not consume the label width');await page.screenshot({path:path.join(dir,'rsat-mobile-properties.png'),fullPage:true});
  role='readonly';await page.setViewportSize({width:1440,height:1000});dialog=await open();await dialog.getByRole('button',{name:'Policy 0000',exact:true}).click();assert.equal(await dialog.getByRole('button',{name:'Сохранить',exact:true}).count(),0);assert.ok(await dialog.getByRole('radio').first().isDisabled());
  language='en';dialog=await open();await dialog.getByRole('button',{name:'Computer Configuration',exact:true}).waitFor();await dialog.getByRole('columnheader',{name:'State',exact:true}).waitFor();
  // Slow helper reads time out visibly and closing the modal aborts its GET.
  await dialog.locator('.workspace-dialog-close button').click();
  let held;await page.route('**/api/v1/gpo/*/alt-settings',route=>{held=route;});await page.clock.install();
  await page.getByRole('button',{name:'Policy editor',exact:true}).click();dialog=page.getByRole('dialog');await dialog.getByRole('status').filter({hasText:'Loading'}).waitFor();
  await page.clock.fastForward(126000);await dialog.getByRole('alert').filter({hasText:'Loading exceeded two minutes'}).waitFor();
  assert.equal(await dialog.getByLabel('Policy scope',{exact:true}).isDisabled(),false);await held.abort().catch(()=>{});
  await dialog.getByRole('button',{name:'Retry',exact:true}).click();await dialog.getByRole('status').filter({hasText:'Loading'}).waitFor();
  const cancelled=page.waitForEvent('requestfailed',{predicate:req=>req.url().includes('/alt-settings')});await dialog.locator('.workspace-dialog-close button').click();await cancelled;await held.abort().catch(()=>{});
  await page.clock.fastForward(126000);assert.equal(await page.getByRole('dialog').count(),0,'aborted read must not reopen dialog');
  await page.clock.resume();role='admin';language='ru';await page.goto(`http://127.0.0.1:${server.address().port}/settings`);
  const cacheLink=page.getByRole('navigation',{name:'В этом разделе'}).getByRole('link',{name:'Локальные шаблоны политик',exact:true});await cacheLink.click();assert.equal(await cacheLink.getAttribute('aria-current'),'location');
  let importResult={count:4500,saved:true,issues:[]};await page.route('**/api/v1/gpo/templates/import',route=>{assert.equal(route.request().method(),'POST');assert.ok(route.request().headers()['x-csrf-token']);return route.fulfill({json:importResult});});
  await page.getByRole('button',{name:'Импортировать / обновить шаблоны',exact:true}).click();await page.getByText(/Шаблоны сохранены локально. Определений: 4500/).waitFor();
  importResult={count:4490,saved:true,issues:[{file:'ru-RU/Broken.adml',template:'Broken.admx',error:'ADML: malformed XML <script>window.bad=true</script>'}]};
  await page.getByRole('button',{name:'Импортировать / обновить шаблоны',exact:true}).click();await page.getByText(/Определений: 4490/).waitFor();await page.getByText('Проблемные файлы: 1',{exact:true}).waitFor();assert.ok(await page.locator('.template-import-issues').isVisible());assert.equal(await page.locator('.template-import-issues script').count(),0);assert.equal(await page.evaluate(()=>window.bad),undefined);
  importResult={count:0,saved:false,issues:[{file:'Broken.admx',error:'invalid XML'}]};await page.getByRole('button',{name:'Импортировать / обновить шаблоны',exact:true}).click();await page.getByText('Нет пригодных определений. Прежний кэш не изменён.',{exact:true}).waitFor();
  importResult={count:4500,saved:true,issues:[]};await page.getByRole('button',{name:'Импортировать / обновить шаблоны',exact:true}).click();await page.getByText(/Определений: 4500/).waitFor();assert.ok(await page.locator('.template-import-issues').isHidden());
  assert.deepEqual(errors,[]);console.log('PASS: RSAT layout, 4500 settings/paging/search/sort/filter/description, cancel/no write, confirmation/revision/scope/value payload, scope tree/categories, mobile, readonly, English, delayed-load timeout/cancellation, template import');console.log('Screenshots:',dir);
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
