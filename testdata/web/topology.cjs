// Browser regression: production topology renderer with synthetic domains of varying size.
// Same NODE_PATH / PLAYWRIGHT_CHROMIUM_EXECUTABLE setup as workspace.cjs.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict');
const {execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-topology-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
let role='readonly',controllers=[],connections=[],sites=[],subnets=[],siteLinks=[],trusts=[],trustUnavailable=false;const mutations=[],errors=[];
const server=http.createServer((req,res)=>{
 const pathname=new URL(req.url,'http://localhost').pathname;
 const file=pathname.startsWith('/static/')?path.join(repo,'internal/web',pathname):path.join(dir,`${role}-repl.html`);
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));
});
function domain(count){
 controllers=Array.from({length:count},(_,i)=>({name:`DC${i}`,dns:`dc${i}.example.com`,site:`site${i%8}`,revision:String(i)}));
 connections=controllers.slice(1).flatMap((dc,i)=>[
  {source:controllers[i].dns,destination:dc.dns,enabled:true},
  {source:dc.dns,destination:controllers[i].dns,enabled:i%2===0}
 ]);
}
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const req=route.request(),endpoint=new URL(req.url()).pathname.replace('/api/v1','');
   if(req.method()!=='GET'){
    mutations.push({endpoint,method:req.method(),payload:req.postDataJSON()});
    if(endpoint==='/sites/controllers/dc0.example.com/move')controllers[0].site=req.postDataJSON().site;
   }
   if(endpoint==='/trusts'&&trustUnavailable){
    await route.fulfill({status:502,json:{error:'LDAP unavailable'}});
    return;
   }
   await route.fulfill({json:{'/sites/topology':{controllers,sites,subnets},'/sites/links':siteLinks,
    '/repl/connections':connections,'/domain':{dnsRoot:'example.com'},'/trusts':trusts}[endpoint]??[]});
  });
  const open=async()=>{
   await page.goto(`http://127.0.0.1:${server.address().port}/repl`);
   if(await page.locator('.workspace-menu summary').count())await page.locator('.workspace-menu summary').click();
   await page.getByRole('button',{name:'Топология',exact:true}).click();
   await page.locator('.topology-viewport').waitFor();
   await page.waitForFunction(()=>document.querySelector('.topology-map')?.style.transform.includes('scale('));
   return page.getByRole('dialog');
  };
  const fitInside=async()=>assert.ok(await page.evaluate(()=>{
   const bounds=document.querySelector('.topology-viewport').getBoundingClientRect();
   return [...document.querySelectorAll('.topology-node:not([hidden])')].every(n=>{
    const r=n.getBoundingClientRect();return r.left>=bounds.left-1&&r.top>=bounds.top-1&&r.right<=bounds.right+1&&r.bottom<=bounds.bottom+1;
   });
  }),'fit must include every visible controller');
  for(const count of [0,1,8,64,256,1000]){
   domain(count);const dialog=await open();assert.equal(await dialog.locator('.topology-node').count(),count);await fitInside();
   const height=await dialog.locator('.topology-viewport').evaluate(e=>e.getBoundingClientRect().height);assert.ok(height<=482);
   if(!count){await dialog.getByText('Контроллеры не найдены',{exact:true}).first().waitFor();continue;}
   const transform=()=>dialog.locator('.topology-map').evaluate(e=>e.style.transform);
   const original=await transform();await dialog.getByRole('button',{name:'Увеличить масштаб',exact:true}).click();assert.notEqual(await transform(),original);
   await dialog.getByRole('button',{name:'Вписать целиком',exact:true}).click();await fitInside();
   const viewport=dialog.locator('.topology-viewport');await viewport.focus();await page.keyboard.press('ArrowRight');assert.notEqual(await transform(),original);
   await page.keyboard.press('0');await fitInside();
   const box=await viewport.boundingBox();await page.mouse.move(box.x+5,box.y+5);await page.mouse.down();await page.mouse.move(box.x+60,box.y+40);await page.mouse.up();assert.notEqual(await transform(),original);
   await dialog.getByRole('button',{name:'Вписать целиком',exact:true}).click();await fitInside();
   const target=`dc${count-1}.example.com`,search=dialog.getByRole('searchbox',{name:'Найти контроллер',exact:true});
   await search.fill(target);assert.equal(await dialog.locator('.topology-node:visible').count(),1);await fitInside();
   await search.fill('no-controller-here');assert.equal(await dialog.locator('.topology-node:visible').count(),0);
   await search.fill('');await dialog.getByRole('combobox',{name:'Фильтр по сайту',exact:true}).selectOption('site0');
   assert.equal(await dialog.locator('.topology-node:visible').count(),Math.ceil(count/8));await fitInside();
   await dialog.getByRole('combobox',{name:'Фильтр по сайту',exact:true}).selectOption('');
   const focus=dialog.getByRole('switch',{name:'Связи выбранного DC',exact:true});assert.equal(await focus.isChecked(),count>20);
   if(count>20){
    assert.equal(await dialog.locator('polyline:visible').count(),0);
    await search.fill(target);await dialog.locator('.topology-node:visible').click();await search.fill('');
    assert.equal(await dialog.locator('polyline:visible').count(),2);
    await focus.uncheck();assert.equal(await dialog.locator('polyline:visible').count(),connections.length);
   }
   // Repeated refresh and close must dispose the previous viewport.
   await dialog.getByRole('button',{name:'Обновить',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.topology-map')?.style.transform.includes('scale('));
   assert.equal(await dialog.locator('.topology-viewport').count(),1);
   await dialog.locator('.workspace-dialog-close button').click();assert.equal(await page.getByRole('dialog').count(),0);
  }
  domain(128);await page.setViewportSize({width:390,height:844});let dialog=await open();await fitInside();
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'mobile document must not overflow horizontally');
  await dialog.getByRole('searchbox').fill('dc127.example.com');await fitInside();
  await page.screenshot({path:path.join(dir,'mobile-128-controllers.png'),fullPage:true});
  role='admin';domain(8);await page.setViewportSize({width:1440,height:1000});dialog=await open();
  await dialog.getByRole('searchbox').fill('dc7.example.com');await dialog.locator('.topology-node:visible').click();
  assert.equal(await dialog.getByLabel('Источник',{exact:true}).inputValue(),'dc7.example.com');
  await dialog.getByRole('searchbox').fill('dc0.example.com');await dialog.locator('.topology-node:visible').click();
  assert.equal(await dialog.getByLabel('Назначение',{exact:true}).inputValue(),'dc0.example.com');
  assert.deepEqual(mutations,[],'view controls and selection must never create connections');
  sites=Array.from({length:8},(_,i)=>({name:'site'+i,dn:'CN=site'+i+',CN=Sites'})).concat({name:'Empty & remote'});
  subnets=[{name:'10.0.0.0/24',site:sites[0].dn}];
  siteLinks=[{name:'WAN <core> & backup',sites:['site0','site1','Empty & remote'],cost:75,interval:30}];
  controllers[0].rodc=true;
  trusts=[
   {domain:'both.example.net',scope:'external',rawDirection:'3'},
   {domain:'in.example.net',scope:'forest',rawDirection:'1'},
   {domain:'out.example.net',scope:'within_forest',rawDirection:'2'},
   {domain:'off.example.net',scope:'external',rawDirection:'0'}
  ];
  dialog=await open();
  const rowsInTrusts=dialog.locator('.topology-trust-row');
  await rowsInTrusts.filter({hasText:'both.example.net'}).getByText('Двустороннее · Внешнее',{exact:true}).waitFor();
  assert.equal(await rowsInTrusts.count(),4);
  const node=dialog.locator('[data-dc="dc0.example.com"]');
  const other=dialog.locator('[data-dc="dc1.example.com"]');
  const wire=dialog.locator('polyline[data-source="dc0.example.com"][data-destination="dc1.example.com"]');
  const coords=()=>node.evaluate(e=>({x:+e.dataset.x,y:+e.dataset.y}));
  const center=async locator=>{const b=await locator.boundingBox();return {x:b.x+b.width/2,y:b.y+b.height/2};};
  const drag=async (from,to,during)=>{
   await page.mouse.move(from.x,from.y);await page.mouse.down();
   await page.mouse.move(to.x,to.y,{steps:8});
   if(during)await during();
   await page.mouse.up();
  };
  const before=await coords(),beforeWire=await wire.getAttribute('points'),from=await center(node);
  await drag(from,{x:from.x+12,y:from.y+6},async()=>{
   assert.notDeepEqual(await coords(),before,'node should follow the pointer before release');
   assert.notEqual(await wire.getAttribute('points'),beforeWire,'wires should reroute before release');
  });
  const afterNode=await coords();assert.notDeepEqual(afterNode,before);
  const site0=dialog.locator('.topology-site-frame[data-site="site0"]');
  const heading=site0.getByRole('button',{name:'site0',exact:true});
  const handle=await center(heading);
  await drag(handle,{x:handle.x+14,y:handle.y+7});
  const repositioned=await coords();assert.notDeepEqual(repositioned,afterNode,'site carries its controllers');
  assert.equal(await wire.getAttribute('marker-end'),'url(#ad-replication-arrow)');
  const refresh=async()=>{
   await dialog.getByRole('button',{name:'Обновить',exact:true}).click();
   await node.waitFor();
   await page.waitForFunction(()=>document.querySelector('.topology-map')?.style.transform.includes('scale('));
  };
  await refresh();assert.deepEqual(await coords(),repositioned,'view refresh should keep manual positions');
  const action=dialog.getByRole('combobox',{name:'Действие при перетаскивании'});
  await action.selectOption('connect');
  await drag(await center(node),await center(other));
  assert.equal(await dialog.getByLabel('Источник',{exact:true}).inputValue(),'dc0.example.com');
  assert.equal(await dialog.getByLabel('Назначение',{exact:true}).inputValue(),'dc1.example.com');
  assert.deepEqual(await coords(),repositioned,'staging a connection must restore the node');

  await dialog.getByRole('searchbox').fill('dc0.example.com');
  const [download]=await Promise.all([page.waitForEvent('download'),dialog.getByRole('button',{name:'Скачать .drawio'}).click()]);
  assert.equal(download.suggestedFilename(),'ad-topology.drawio');
  await download.saveAs(path.join(dir,'ad-topology.drawio'));
  const xmlText=fs.readFileSync(path.join(dir,'ad-topology.drawio'),'utf8');
  const model=await page.evaluate(xml=>{
   const d=new DOMParser().parseFromString(xml,'application/xml');
   if(d.querySelector('parsererror'))throw Error('invalid draw.io XML');
   return [...d.querySelectorAll('mxfile > diagram > mxGraphModel > root mxCell')].map(cell=>({
    ...Object.fromEntries([...cell.attributes].map(a=>[a.name,a.value])),
    id:cell.getAttribute('id')||cell.parentElement.getAttribute('id'),
    label:cell.parentElement.getAttribute('label'),
    sheet:cell.closest('diagram').getAttribute('id'),
    geometry:cell.querySelector('mxGeometry')?Object.fromEntries([...cell.querySelector('mxGeometry').attributes].map(a=>[a.name,a.value])):null
   }));
  },xmlText);
  const site=model.find(c=>c.value==='site0'),dc=model.find(c=>c.value==='dc0.example.com\nRODC');
  assert.ok(site&&dc&&dc.parent===site.id);
  assert.ok(model.some(c=>c.parent===site.id&&c.label?.includes('10.0.0.0/24')));
  assert.ok(Math.abs(+site.geometry.x + +dc.geometry.x + 90-repositioned.x)<=1);
  assert.ok(Math.abs(+site.geometry.y + +dc.geometry.y + 31-repositioned.y)<=1);
  const link=model.find(c=>c.value?.startsWith('WAN <core> & backup'));
  assert.equal(model.filter(c=>c.source===link.id).length,3);
  assert.ok(model.some(c=>c.source===dc.id&&c.target&&c.style.includes('endArrow=block')));
  assert.equal(model.filter(c=>c.id?.startsWith('dc-')).length,8,'export includes controllers hidden by the filter');
  const trustCells=model.filter(c=>c.sheet==='domain-trusts');
  assert.equal(trustCells.find(c=>c.id==='trust-local').value,'example.com');
  for(const [partner,start,end] of [['both','block','block'],['in','block','none'],['out','none','block'],['off','none','none']]){
   const target=trustCells.find(c=>c.value===partner+'.example.net');
   const edge=trustCells.find(c=>c.source==='trust-local'&&c.target===target.id);
   assert.ok(edge.style.includes('startArrow='+start+';')&&edge.style.includes('endArrow='+end+';'));
  }

  await dialog.getByRole('searchbox').fill('');
  await page.screenshot({path:path.join(dir,'topology-editor.png'),fullPage:true});
  await action.selectOption('site');
  await drag(await center(node),await center(other));
  const applyMove=dialog.getByRole('button',{name:'Перенести DC в AD',exact:true});
  await applyMove.waitFor();assert.deepEqual(mutations,[],'staged drag must not mutate AD');
  await dialog.getByRole('button',{name:'Отменить перенос'}).click();
  assert.equal(await applyMove.count(),0);
  await drag(await center(node),await center(other));
  await applyMove.click();
  await page.waitForFunction(()=>document.querySelector('[data-dc="dc0.example.com"]')?.dataset.site==='site1');
  assert.deepEqual(mutations,[{endpoint:'/sites/controllers/dc0.example.com/move',method:'POST',payload:{site:'site1',revision:'0'}}]);
  trustUnavailable=true;await refresh();
  await dialog.locator('.topology-trusts').getByText('Доверительные отношения недоступны · LDAP unavailable',{exact:true}).waitFor();
  assert.equal(await dialog.locator('.topology-node').count(),8);
  assert.deepEqual(errors,[]);
  console.log('PASS: 0/1/8/64/256/1000 DCs, fit, zoom, pan, keyboard, search, site filter, edge focus, refresh/close, mobile, admin selection, drag preview, draw.io export, cancel and confirmed move');
  console.log('Screenshots:',dir);
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
