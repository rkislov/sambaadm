const {chromium}=require('playwright'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-dashboard-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{const url=new URL(req.url,'http://localhost'),p=url.pathname,role=url.searchParams.get('role')==='readonly'?'readonly':'admin',file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,p.startsWith('/sso-')?p.slice(1)+'.html':role+'-.html');if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));});
const unit = (id, unit, state, extra={}) => ({id, unit, state, subState: state === 'active' ? 'running' : 'dead', ...extra});
const names = {dc:'dc01.example.org', secondary:'dc02.example.org', files:'fs01.example.org', reserve:'fs02.example.org', dhcp:'dhcp01.example.org', empty:'spare01.example.org', stopped:'fs03.example.org'};
const clusterKey = 'files@'+'d'.repeat(64);
const pairID = 'c'.repeat(64);
const overview = {
 observed: '2026-11-26T11:46:00Z',
 servers: [
  {name:names.dc, site:'HQ', controller:true, helper:'online', services:[unit('ad','samba.service','active'),unit('smb','','absent'),unit('dhcp4','','absent'),unit('dhcp6','','absent'),unit('dns','named.service','active')]},
  {name:names.secondary, site:'Branch', controller:true, rodc:true, helper:'online', services:[unit('ad','samba.service','failed'),unit('smb','','absent'),unit('dhcp4','','absent'),unit('dhcp6','','absent')]},
  {name:names.files, helper:'online', services:[unit('ad','','absent'), unit('smb','smb.service','inactive'),unit('dhcp4','','absent'),unit('dhcp6','','absent'),unit('pacemaker','pacemaker.service','active')]},
  {name:names.reserve, helper:'unavailable', services:[]},
  {name:names.empty, helper:'online', services:[unit('ad','','absent'),unit('smb','','absent')]},
  {name:names.stopped, helper:'online', services:[unit('smb','smb.service','inactive')]},
  {name:names.dhcp, helper:'online', services:[
   unit('ad','','absent'),unit('smb','','absent'),
   unit('dhcp4','kea-dhcp4.service','active',{dhcp:{source:'runtime',socketState:'ready',relationships:[{mode:'hot-standby',name:'dhcp-primary',role:'primary',state:'partner-down',pairID,serving:true,peer:'dhcp-secondary',peerState:'hot-standby',interrupted:true,inTouch:true,ageSeconds:13}]}}),
   unit('dhcp6','kea-dhcp6.service','active',{dhcp:{source:'runtime',standalone:true,socketState:'ready'}})
  ]}
 ],
 clusters:[{name:'files.example.org',key:clusterKey,state:'degraded',owner:names.files,quorum:true,
  nodes:[{name:names.files,state:'active',readyPaths:2,totalPaths:2},{name:names.reserve,state:'unknown',readyPaths:0,totalPaths:0}]}]
};
const out = process.env.SAMBAADM_DASHBOARD_SCREENSHOTS || dir;
fs.mkdirSync(out,{recursive:true});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],calls=[];let degraded=false,ssoCalls=0,many=false;
 page.on('pageerror',e=>errors.push(e.message));await page.route('**/api/v1/**',async route=>{const p=new URL(route.request().url()).pathname.slice(7);calls.push(p);let result=[];
 if(p==='/services/overview')result=many?{...overview,servers:overview.servers.concat(Array.from({length:12},(_,index)=>({name:'extra-'+index+'.example.org',helper:'online',services:[]})))}:overview;if(p==='/users')result=Array(23).fill({});if(p==='/computers')result=Array(22).fill({});if(p==='/gpo')result=Array(10).fill({guid:'{test}',displayName:'Test'});if(p==='/sites/controllers')result=Array.from({length:8},(_,i)=>({dns:'dc'+i+'.example.org'}));
 if(p==='/services/ha-notifications')result={items:[],unread:0};
 if(p==='/services/ha-history'){
 const query=new URL(route.request().url()).searchParams,kind=query.get('kind'),id=query.get('id');
 assert.equal(id,kind==='smb'?clusterKey:pairID);
 result={since:overview.observed,members:{primary:'fs01.example.org',standby:'fs02.example.org'},events:[
  {at:'2026-11-26T11:47:00Z',type:'node-down',node:'primary'},
  {at:'2026-11-26T11:47:30Z',type:'service-moved',previous:['primary'],serving:['standby']},
  {at:'2026-11-26T11:49:20Z',type:'reserve-restored',node:'primary',serving:['standby'],reserve:['primary']}
 ]};}
 if(p==='/repl/status')result={health:degraded?'degraded':'healthy'};if(p==='/domain')result={dnsRoot:'example.org',baseDN:'DC=example,DC=org'};
 if(p==='/system/metrics')result={host:'dc0',os:'linux',cpus:2,diskPath:'/',samples:[{time:Date.now(),cpu:2.5,memory:42,disk:38,errors:[]}]};await route.fulfill({json:result});});
 const url='http://127.0.0.1:'+server.address().port;await page.goto(url+'/');await page.getByText('Репликация в порядке',{exact:true}).waitFor();await page.locator('.host-metric-values').filter({hasText:'42.0%'}).waitFor();
 assert.equal(await page.locator('#dashboard-domain-details').evaluate(e=>e.open),false);assert.equal(await page.locator('#host-metrics').evaluate(e=>e.open),false);assert.equal(await page.locator('.replication-details').evaluate(e=>e.open),false);assert.equal(await page.locator('#domain-overview').isVisible(),false);assert.equal(await page.locator('#host-metrics svg').count(),0);assert.equal(calls.includes('/sites'),false,'hidden survey should not load its tables');await page.screenshot({path:path.join(dir,'dashboard-before.png'),fullPage:true});assert.ok((await page.locator('#dashboard-services').boundingBox()).y<300);
 await page.getByText('DHCPv4 · обслуживает за пару',{exact:true}).waitFor();
 const overviewArea=page.locator('#dashboard-services');
 assert.equal(await overviewArea.locator('tbody tr').count(),7);
 assert.deepEqual(await overviewArea.locator('thead th').allTextContents(),['Сервер','Службы','Статус','Примечание']);
 const hostRow=name=>overviewArea.locator('tbody tr').filter({has:page.getByRole('button',{name,exact:true})});
 assert.equal(await hostRow(names.empty).locator('.service-glyph').count(),0);
 assert.equal(await hostRow(names.stopped).locator('.service-glyph.bad').count(),1);
 assert.equal(await hostRow(names.dhcp).locator('.service-glyph.good').count(),2);
 assert.equal(await hostRow(names.dhcp).locator('.service-glyph-attention').count(),1);
 assert.equal(await hostRow(names.files).getByRole('button',{name:/Кластер SMB/}).count(),1);
 assert.equal(await overviewArea.getByText('DHCPv6 · вне HA',{exact:true}).count(),1);
 const clusterLink=overviewArea.locator('#service-overview-clusters').getByRole('link',{name:'files.example.org'});
 assert.equal(new URL(await clusterLink.getAttribute('href'),url).searchParams.get('cluster'),clusterKey);
 await page.screenshot({path:path.join(out,'dashboard-desktop.png'),fullPage:true});
 await hostRow(names.files).getByRole('button',{name:/Кластер SMB/}).click();
 const smbHistory=page.getByRole('dialog',{name:'SMB HA · files.example.org'});
 await smbHistory.getByText('Резерв восстановлен',{exact:true}).waitFor();
 assert.equal(await smbHistory.getByRole('link',{name:'Открыть файловый кластер'}).count(),1);
 await page.keyboard.press('Escape');
 const dhcpButton=overviewArea.getByRole('button',{name:'DHCPv4 · '+names.dhcp});
 await dhcpButton.click();
 const detail=page.getByRole('dialog',{name:'DHCPv4 HA · '+names.dhcp});
 await detail.getByText('Узел недоступен',{exact:true}).waitFor();
 await detail.getByText('fs01.example.org → fs02.example.org',{exact:true}).waitFor();
 await detail.getByRole('button',{name:'Состояние',exact:true}).click();
 await detail.getByText('Прервана',{exact:true}).waitFor();
 assert.equal(new URL(await detail.getByRole('link',{name:'Управление DHCP'}).getAttribute('href'),url).searchParams.get('view'),'ha');
 await page.screenshot({path:path.join(out,'dashboard-dhcp-ha.png')});
 await page.keyboard.press('Escape');
 assert.equal(await dhcpButton.evaluate(e=>document.activeElement===e),true);
 await overviewArea.getByLabel('Требуют внимания').check();
 assert.equal(await overviewArea.getByRole('button',{name:names.dc,exact:true}).count(),0);
 assert.equal(await overviewArea.getByRole('button',{name:names.secondary,exact:true}).count(),1);
 await overviewArea.getByLabel('Требуют внимания').uncheck();
 many=true;
 await overviewArea.getByRole('button',{name:'Обновить службы'}).click();
 await overviewArea.getByText('1–8 из 19',{exact:true}).waitFor();
 assert.equal(await overviewArea.locator('tbody tr').count(),8);
 await overviewArea.getByRole('button',{name:'Далее',exact:true}).click();
 await overviewArea.getByText('9–16 из 19',{exact:true}).waitFor();
 await overviewArea.getByRole('searchbox',{name:'Найти сервер'}).fill('extra-11');
 await hostRow('extra-11.example.org').waitFor();
 assert.equal(await overviewArea.locator('tbody tr').count(),1);
 await overviewArea.getByRole('searchbox',{name:'Найти сервер'}).clear();
 many=false;
 await overviewArea.getByRole('button',{name:'Обновить службы'}).click();
 await overviewArea.getByText('DHCPv4 · обслуживает за пару',{exact:true}).waitFor();
 await page.locator('#host-metrics > summary').click();await page.locator('#host-metrics svg').nth(2).waitFor();assert.equal(await page.locator('#host-metrics svg').count(),3);await page.locator('#host-metrics > summary').click();await Promise.all([page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/sites'),page.locator('#dashboard-domain-details > summary').click()]);await page.locator('#domain-overview').waitFor();assert.ok(calls.includes('/sites'));await page.locator('#dashboard-domain-details > summary').click();
 degraded=true;await page.getByRole('button',{name:'Обновить сводку',exact:true}).click();await page.getByText('Репликация требует внимания',{exact:true}).waitFor();assert.equal(await page.locator('.replication-details').evaluate(e=>e.open),true,'problems must remain visible');
 degraded=false;await page.getByRole('button',{name:'Обновить сводку',exact:true}).click();await page.getByText('Репликация в порядке',{exact:true}).waitFor();await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,'dashboard-mobile.png'),fullPage:true});
 await page.goto(url+'/?role=readonly');await page.getByRole('button',{name:'DHCPv4 · '+names.dhcp}).click();
 const viewer=page.getByRole('dialog',{name:'DHCPv4 HA · '+names.dhcp});
 await viewer.getByText('Служба перешла',{exact:true}).waitFor();
 await viewer.getByRole('button',{name:'Состояние',exact:true}).click();
 await viewer.getByText('Прервана',{exact:true}).waitFor();
 assert.equal(await page.getByRole('link',{name:'Управление DHCP'}).count(),0);

 await page.route('**/auth/kerberos',async route=>{ssoCalls++;await route.fulfill({status:401,body:'Negotiate required'});});await page.goto(url+'/sso-auto');await page.getByText('Автоматический вход недоступен. Используйте логин и пароль.',{exact:true}).waitFor();assert.equal(ssoCalls,1);assert.ok(await page.locator('input[name=password]').isVisible());await page.getByRole('button',{name:'Войти через домен',exact:true}).click();await page.getByText('Автоматический вход недоступен. Используйте логин и пароль.',{exact:true}).waitFor();assert.equal(ssoCalls,2);await page.goto(url+'/sso-manual');assert.ok(await page.locator('input[name=password]').isVisible());assert.equal(ssoCalls,2,'manual login must not trigger SSO again');assert.deepEqual(errors,[]);
 console.log('PASS: compact landing, lazy details, expandable charts, visible replication failures, mobile and password fallback alongside optional automatic SSO');console.log('Screenshots:',out);
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
