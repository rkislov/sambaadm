// NODE_PATH must contain the installed Playwright package.
const {chromium}=require('playwright'),fs=require('fs'),path=require('path'),os=require('os'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-printing-'));
execFileSync('go',['test','./internal/web','-run','^TestPrintingBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_PRINTING_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{const p=new URL(req.url,'http://localhost').pathname,file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,p==='/roles'?'roles.html':p==='/readonly'?'printing-readonly.html':'printing-admin.html');if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});try{
 const page=await browser.newPage({viewport:{width:1500,height:1000}}),errors=[],calls=[];page.on('pageerror',e=>errors.push(e.message));
 let queues=Array.from({length:61},(_,i)=>({name:'Printer_'+String(i).padStart(2,'0'),model:'Legacy PPD',uri:'ipp://device/ipp/print',state:3,accepting:true,shared:true,reason:''}));
 await page.route('**/api/v1/**',async route=>{const req=route.request(),u=new URL(req.url()),body=req.postDataJSON(),op=u.pathname.split('/').pop();calls.push({path:u.pathname,body,query:u.searchParams});if(body)assert.equal(req.headers()['x-csrf-token'],'test-csrf');let result={};
 if(u.pathname==='/api/v1/services/overview')result={servers:[{name:'print.example.test',helper:'online'}]};
 else if(u.pathname.startsWith('/api/v1/printing/')){
  if(op==='inspect')result={state:'active',enabled:'enabled',queues,kerberos:{http:{state:'ready'},smb:{state:'ready'}}};
  else if(op==='queue.plan')result={revision:'fresh',settings:body};
  else if(op==='queue.apply'){assert(body.confirm);assert.equal(body.revision,'fresh');queues.push({name:body.name,model:'IPP Everywhere',uri:body.uri,state:3,accepting:true});result={detail:'done'};}
  else if(op==='models')result={rows:[{id:'legacy',label:'<img src=x onerror=alert(1)>',source:'installed',available:true},{id:'uploaded:bad',label:'Katusha M133',source:'uploaded',available:false,missingFilters:['Katusha/Katusha_M133'],validationError:'invalid constraints'}],total:2};
  else if(op==='journal')result={rows:[{node:'print.example.test',id:1,created:100,state:9,printer:'Office',user:'user@REALM',title:'<img src=x onerror=alert(1)>',pages:1,reasons:['job-completed-successfully']}],total:1,errors:{},retention:'Fixture history'};
  else if(op==='install.plan')result={revision:'install',packages:['cups']};
  else if(op==='install.start'){assert.equal(body.revision,'install');assert(body.confirm);result={id:'0123456789abcdef0123456789abcdef'};}
  else if(op==='install.status')result={state:'complete',phase:'CUPS installed'};
  else if(op==='windows.catalog')result={rows:[],total:0};
  else if(op==='keytab.upload'){assert.equal(body.data,Buffer.from('fixture-keytab').toString('base64'));result={state:'ready'};}
  else throw Error('unexpected '+op);
 } else if(u.pathname==='/api/v1/dhcp/install/plan'||u.pathname==='/api/v1/dhcp/gss/install/plan')result={revision:'kea-install',proposedRevision:'new',simulation:'Inst kea'};
 else if(u.pathname==='/api/v1/dhcp/install'){assert.equal(body.revision,'kea-install');assert(body.confirm);result={detail:'done'};}
 else if(u.pathname==='/api/v1/dhcp/gss/install/start')result={id:'0123456789abcdef0123456789abcdef'};
 else if(u.pathname==='/api/v1/dhcp/gss/install/status')result={state:'complete'};
 else result={};
 await route.fulfill({json:result});});
 const base='http://127.0.0.1:'+server.address().port;
 await page.goto(base+'/printers');await page.getByRole('heading',{name:'Служба CUPS работает'}).waitFor();
 await page.getByRole('button',{name:'Принтеры',exact:true}).click();await page.getByRole('button',{name:'Добавить принтер…'}).waitFor();assert.equal(await page.locator('#printing-panel tbody tr').count(),50);
 await page.getByRole('button',{name:'→',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('#printing-panel tbody tr').length===11);
 await page.getByLabel('Поиск',{exact:true}).fill('Printer_60');await page.getByRole('button',{name:'Найти',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('#printing-panel tbody tr').length===1);
 await page.getByRole('button',{name:'Добавить принтер…'}).click();await page.getByLabel('Имя очереди').fill('New_Printer');await page.getByLabel('URI устройства (без пароля)').fill('ipp://new-device/ipp/print');await page.getByRole('button',{name:'Проверить изменения…'}).click();await page.getByRole('button',{name:'Подтвердить и применить'}).click();await page.getByText('Изменения применены.').waitFor({timeout:1000}).catch(()=>{});assert(calls.some(c=>c.path.endsWith('queue.apply')));
 await page.getByRole('button',{name:'Драйверы Linux / PPD'}).click();await page.getByText('Katusha M133',{exact:true}).waitFor();assert.equal(await page.locator('#printing-panel img').count(),0);assert((await page.locator('#printing-panel').innerText()).includes('invalid constraints'));
 await page.getByRole('button',{name:'Общий журнал печати'}).click();await page.getByText('job-completed-successfully',{exact:true}).waitFor();await page.getByLabel('Пользователь',{exact:true}).fill('user@REALM');await page.getByRole('button',{name:'Применить фильтры'}).click();assert(calls.some(c=>c.path.endsWith('/journal')&&c.query.get('user')==='user@REALM'));
 await page.getByText('job-completed-successfully',{exact:true}).waitFor();await page.screenshot({path:path.join(dir,'printing-journal.png'),fullPage:true});
 await page.getByRole('button',{name:'IPP / Kerberos'}).click();await page.getByLabel('Keytab',{exact:true}).setInputFiles({name:'fixture.keytab',mimeType:'application/octet-stream',buffer:Buffer.from('fixture-keytab')});await page.getByRole('button',{name:'Проверить и настроить keytab'}).click();await page.getByText('Keytab проверен, служба настроена.').waitFor();assert.equal(await page.getByLabel('Keytab',{exact:true}).inputValue(),'');
 await page.goto(base+'/readonly');assert.equal(await page.getByRole('button',{name:'IPP / Kerberos'}).count(),0);await page.getByRole('button',{name:'Принтеры',exact:true}).click();assert.equal(await page.getByRole('button',{name:'Добавить принтер…'}).count(),0);
 await page.goto(base+'/roles');const roles=page.locator('#dashboard-roles');assert.equal(await roles.isVisible(),false);await page.getByRole('button',{name:'Добавить роли и службы',exact:true}).click();await roles.waitFor();await roles.locator('[name=node] option[value="print.example.test"]').waitFor({state:'attached'});
 for(const kind of ['cups','dhcp6','gss']){await roles.locator('[name=role]').selectOption(kind);await roles.locator('[name=node]').selectOption('print.example.test');await roles.locator('[data-role-plan]').click();await roles.locator('[data-role-confirm]').click();await roles.getByText(/настройка роли завершена/).waitFor();}
 assert(calls.some(c=>c.path==='/api/v1/printing/install.start'));assert(calls.some(c=>c.path==='/api/v1/dhcp/install'&&c.query.get('family')==='6'));assert(calls.some(c=>c.path==='/api/v1/dhcp/gss/install/start'));await page.screenshot({path:path.join(dir,'roles-dialog.png'),fullPage:true});await roles.locator('[data-role-close]').click();await page.setViewportSize({width:390,height:844});await page.getByRole('button',{name:'Добавить роли и службы',exact:true}).click();assert.equal(await roles.evaluate(e=>e.scrollWidth>e.clientWidth),false,'role dialog mobile overflow');await roles.locator('[data-role-close]').click();await page.goto(base+'/printers');await page.getByRole('heading',{name:'Служба CUPS работает'}).waitFor();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'printing mobile overflow');await page.screenshot({path:path.join(dir,'printing-mobile.png'),fullPage:true});assert.deepEqual(errors,[]);
 console.log('PASS: queue plans, pagination/search, quarantined PPDs, XSS, common journal filters, keytab clearing, readonly access, home CUPS/Kea/GSS installation; '+dir);
 }finally{await browser.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;server.close();});
