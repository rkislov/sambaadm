const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-permission-map-'));
execFileSync('go',['test','./internal/web','-run','^TestShareTreeBrowserFixture$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_SHARE_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{
 const p=new URL(req.url,'http://localhost').pathname;
 const file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,p.includes('readonly')?'readonly-map.html':'admin-map.html');
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));
});
const access='group::r-x\ngroup:1001:r-x\nmask::r-x\nother::---\nuser::rwx';
const paths=['.','Finance','Finance/Archive','Finance2','finance'];
const snapshot={share:'docs',root:'.',revision:'snapshot-1',created:'2026-11-26T12:00:00Z',complete:true,skippedLinks:1,warnings:[],nodes:paths.map(p=>({path:p,parent:p==='.'?'':p.includes('/')?'Finance':'.',name:p==='.'?'docs':p.split('/').at(-1),identity:p,revision:p,mode:'0750',owner:'admin',group:'EXAMPLE\\Domain Users',access,default:'',entries:[{kind:'group',qualifier:'1001',identity:'EXAMPLE\\Finance',perms:'r-x',default:false}]}))};
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],requests=[];let stale=false,partial=false;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const u=new URL(route.request().url());assert.equal(u.searchParams.get('node'),'files-02');requests.push({url:u.pathname,method:route.request().method()});
   let json;
   if(u.pathname==='/api/v1/groups')json=[{samAccountName:'Finance',description:'Финансы',category:'security'},{samAccountName:'Mailing',category:'distribution'}];
   else if(u.pathname.endsWith('/permission-map'))json=snapshot;
   else if(u.pathname.endsWith('/plan')){
    const input=route.request().postDataJSON();assert.equal(input.snapshotRevision,'snapshot-1');assert.equal(input.overlays[0].recursive,true);assert.equal(input.overlays[0].template.rules[0].group,'Finance');assert.equal(input.overlays[0].template.id,undefined);
    if(stale){await route.fulfill({status:409,json:{error:'Дерево изменилось'}});return;}
    json={revision:'plan-1',snapshotRevision:'snapshot-1',directories:5,groups:{2001:'Finance'},changes:snapshot.nodes.map(n=>({path:n.path,before:n,access:access+'\ngroup:2001:rwx',default:'',templates:input.overlays.map(o=>o.template.name)}))};
   }else if(u.pathname.endsWith('/apply')){
    const input=route.request().postDataJSON();assert.equal(input.confirm,true);assert.equal(input.planRevision,'plan-1');
    json={id:'op-1',status:partial?'partial':'complete',journal:'/private/permission-maps/op-1.json',items:paths.map((p,i)=>({path:p,status:partial?(i===0?'applied':i===1?'failed':'pending'):'applied',error:partial&&i===1?'write failed':''}))};
   }else throw Error('Unexpected API '+u.pathname);
   await route.fulfill({json});
  });
  const base='http://127.0.0.1:'+server.address().port;
  await page.goto(base+'/shares/docs/permission-map?node=files-02');
  const apply=page.getByRole('button',{name:'Применить к дереву папок',exact:true,includeHidden:true});assert.equal(await apply.isDisabled(),true);
  assert.equal(requests.filter(r=>r.method==='POST').length,0);
  await page.getByRole('button',{name:'Снять карту прав',exact:true}).click();await page.getByRole('button',{name:'Finance/Archive',exact:true}).waitFor();
  assert.equal(await page.locator('.share-map-node').count(),5);assert.equal(await page.getByRole('button',{name:'Finance',exact:true}).count(),1);assert.equal(await page.getByRole('button',{name:'finance',exact:true}).count(),1);
  await page.getByRole('button',{name:'Шаблоны прав',exact:true}).click();await page.getByRole('button',{name:'Новый шаблон',exact:true}).click();
  const placeholder=page.getByLabel('Название шаблона',{exact:true});await placeholder.fill('Финансы — чтение');await page.getByLabel('Группа безопасности AD',{exact:true}).fill('Finance');
  await page.getByRole('button',{name:'Сохранить шаблон',exact:true}).click();
  await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();
  assert.equal(await page.locator('.share-map-node.has-overlay').count(),5);assert.equal(await apply.isDisabled(),true);
  await page.getByRole('button',{name:'Finance/Archive',exact:true}).click();await page.getByRole('button',{name:'Шаблоны прав',exact:true}).click();await page.getByRole('button',{name:'Новый шаблон',exact:true}).click();await placeholder.fill('Архив — запись');await page.getByLabel('Группа безопасности AD',{exact:true}).fill('Finance');await page.getByLabel('Права группы',{exact:true}).selectOption('rwx');await page.getByRole('button',{name:'Сохранить шаблон',exact:true}).click();await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();
  assert.equal(await page.locator('.share-map-assignment').count(),2);
  await page.getByRole('button',{name:/^Предпросмотр изменений/}).click();await page.getByText('Изменится папок: 5 из 5',{exact:true}).waitFor();
  assert.equal(await apply.isDisabled(),true);await page.getByLabel('Подтверждаю применение показанных изменений к каталогам',{exact:true}).check();assert.equal(await apply.isDisabled(),false);
  await page.getByRole('button',{name:'Посмотреть на карте',exact:true}).click();
  // Changing the root invalidates both the preview and its confirmation.
  await page.getByLabel('Корень снимка (путь внутри ресурса)',{exact:true}).fill('Finance');assert.equal(await apply.isDisabled(),true);assert.equal(await page.getByLabel('Подтверждаю применение показанных изменений к каталогам',{exact:true}).isChecked(),false);
  await page.getByLabel('Корень снимка (путь внутри ресурса)',{exact:true}).fill('.');await page.getByRole('button',{name:'Снять карту прав',exact:true}).click();await page.getByRole('button',{name:'Finance/Archive',exact:true}).waitFor();
  const library=page.getByLabel('Шаблон для наложения',{exact:true});await library.selectOption({label:'Архив — запись'});await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();
  stale=true;await page.getByRole('button',{name:/^Предпросмотр изменений/}).click();await page.getByText('Дерево изменилось',{exact:true}).waitFor();assert.equal(await apply.isDisabled(),true);
  stale=false;await page.getByRole('button',{name:'Снять карту прав',exact:true}).click();await page.getByRole('button',{name:'Finance/Archive',exact:true}).waitFor();await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();await page.getByRole('button',{name:/^Предпросмотр изменений/}).click();await page.getByText('Изменится папок: 5 из 5',{exact:true}).waitFor();
  await page.getByLabel('Подтверждаю применение показанных изменений к каталогам',{exact:true}).check();partial=true;await apply.click();await page.getByRole('heading',{name:'Применено частично',exact:true}).waitFor();assert.equal(await apply.isDisabled(),true);await page.getByText('Finance · Ошибка (ACL мог измениться частично): write failed',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Закрыть отчёт',exact:true}).click();
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'mobile overflow');
  if(process.env.SAMBAADM_PERMISSION_MAP_SCREENSHOT)await page.screenshot({path:process.env.SAMBAADM_PERMISSION_MAP_SCREENSHOT,fullPage:true});
  await page.reload();assert.equal(await library.locator('option').count(),3,'template library did not persist');
  await page.getByRole('button',{name:'Шаблоны прав',exact:true}).click();await page.getByText('Импорт и экспорт шаблонов',{exact:true}).click();
  await page.getByLabel('Импорт шаблонов JSON',{exact:true}).setInputFiles({name:'templates.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({format:1,templates:[{name:'Импортированный',inherit:true,rules:[{group:'Finance',permissions:'r-x',gid:'stale-server-gid'}]}]}))});
  await library.locator('option').filter({hasText:'Импортированный'}).waitFor({state:'attached'});assert.equal(await page.evaluate(()=>localStorage.getItem('sambaadm.permission-templates.v1').includes('stale-server-gid')),false,'GID leaked into portable library');
  const downloading=page.waitForEvent('download');await page.getByRole('button',{name:'Экспорт шаблонов',exact:true}).click();const exported=JSON.parse(fs.readFileSync(await(await downloading).path(),'utf8'));assert.equal(exported.format,1);assert.equal(exported.templates.length,3);

  await page.goto(base+'/readonly?node=files-02');assert.equal(await page.getByRole('button',{name:'Применить к дереву папок',exact:true}).count(),0);await page.getByRole('button',{name:'Снять карту прав',exact:true}).click();await page.getByRole('button',{name:'Finance/Archive',exact:true}).waitFor();
  assert.deepEqual(errors,[]);console.log('PASS map snapshot, case-sensitive folder IDs, template library, subtree overlays, preview invalidation, conflict, partial result, readonly, mobile');
 }finally{await browser.close();server.close();fs.rmSync(dir,{recursive:true,force:true});}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
