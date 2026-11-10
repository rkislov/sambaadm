// Browser regression: production topology renderer with synthetic domains of varying size.
// Same NODE_PATH / PLAYWRIGHT_CHROMIUM_EXECUTABLE setup as workspace.cjs.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict');
const {execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-topology-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
let role='readonly',controllers=[],connections=[];const mutations=[],errors=[];
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
   if(req.method()!=='GET')mutations.push(endpoint);
   await route.fulfill({json:endpoint==='/sites/topology'?{controllers,sites:[],subnets:[]}:endpoint==='/repl/connections'?connections:[]});
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
  assert.deepEqual(mutations,[],'view controls and selection must never create connections');assert.deepEqual(errors,[]);
  console.log('PASS: 0/1/8/64/256/1000 DCs, fit, zoom, pan, keyboard, search, site filter, edge focus, refresh/close, mobile, admin selection without mutation');
  console.log('Screenshots:',dir);
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
