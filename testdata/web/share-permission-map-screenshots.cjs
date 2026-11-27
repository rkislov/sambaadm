// Render real application screens with deterministic demo API responses.
const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),fixtures=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-map-gallery-'));
const output=path.resolve(process.argv[2]||path.join(os.tmpdir(),'sambaadm-permission-map-gallery'));
fs.mkdirSync(output,{recursive:true});
execFileSync('go',['test','./internal/web','-run','^TestShareTreeBrowserFixture$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_SHARE_FIXTURE_DIR:fixtures}});
const server=http.createServer((req,res)=>{
 const p=new URL(req.url,'http://localhost').pathname;
 const file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(fixtures,'admin-map.html');
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));
});
const library=[
 {id:'team',name:'Совместная работа отдела',inherit:true,rules:[{group:'Finance_RW',permissions:'rwx'},{group:'Finance_Readers',permissions:'r-x'}]},
 {id:'read',name:'Документы для чтения',inherit:true,rules:[{group:'Domain Users',permissions:'r-x'}]},
 {id:'archive',name:'Архив — только чтение',inherit:true,rules:[{group:'Finance_RW',permissions:'r-x'},{group:'Finance_Readers',permissions:'r-x'}]}
];
const groups={'1100':'CORP\\File_Admins','2101':'Finance_RW','2102':'Finance_Readers','513':'Domain Users'};
const access='group::r-x\ngroup:1100:rwx\nmask::rwx\nother::---\nuser::rwx';
function entries(text,def=false){return text.split('\n').filter(Boolean).map(line=>{const p=line.replace(/^default:/,'').split(':');return {kind:p[0],qualifier:p[1],perms:p[2],default:def,identity:groups[p[1]]};});}
const paths=['.','Бухгалтерия','Бухгалтерия/Отчёты','Бухгалтерия/Архив','Продажи','Продажи/Договоры','Общие документы','Общие документы/Шаблоны'];
const snapshot={share:'docs',root:'.',created:'2026-11-26T09:40:00Z',revision:'demo-snapshot',complete:true,skippedLinks:0,warnings:[],nodes:paths.map(p=>({path:p,parent:p==='.'?'':p.includes('/')?p.slice(0,p.lastIndexOf('/')):'.',name:p==='.'?'Документы компании':p.split('/').at(-1),identity:'demo-'+p,revision:'node-'+p,mode:'0770',owner:'CORP\\administrator',group:'CORP\\Domain Users',access,default:'',entries:entries(access)}))};
const contains=(parent,child)=>parent==='.'||parent===child||child.startsWith(parent+'/');
function makePlan(input){
 const changes=[];
 for(const node of snapshot.nodes){
  const assignments=input.overlays.filter(o=>o.path===node.path||o.recursive&&contains(o.path,node.path));if(!assignments.length)continue;
  const acl=new Map(node.access.split('\n').map(line=>{const p=line.split(':');return [p.slice(0,2).join(':'),p[2]];}));
  const defaults=new Map([['user:','rwx'],['group:','r-x'],['other:','---'],['mask:','rwx']]);let inherit=false;
  for(const o of assignments)for(const r of o.template.rules){
   const gid=r.group==='Finance_RW'?'2101':r.group==='Finance_Readers'?'2102':'513';
   if(r.permissions==='remove')acl.delete('group:'+gid);else acl.set('group:'+gid,r.permissions);
   if(o.template.inherit){inherit=true;if(r.permissions==='remove')defaults.delete('group:'+gid);else defaults.set('group:'+gid,r.permissions);}
  }
  const after=[...acl].map(([k,v])=>k+':'+v).sort().join('\n');
  const afterDefault=inherit?[...defaults].map(([k,v])=>'default:'+k+':'+v).sort().join('\n'):'';
  if(after!==node.access||afterDefault!==node.default)changes.push({path:node.path,before:node,access:after,default:afterDefault,templates:assignments.map(o=>o.template.name)});
 }
 return {revision:'demo-plan',snapshotRevision:snapshot.revision,directories:snapshot.nodes.length,groups,changes};
}
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});
 try{
  const context=await browser.newContext({viewport:{width:1600,height:1060},deviceScaleFactor:1,locale:'ru-RU',timezoneId:'Europe/Moscow',reducedMotion:'reduce'});
  await context.addInitScript(value=>localStorage.setItem('sambaadm.permission-templates.v1',JSON.stringify(value)),library);
  const page=await context.newPage(),errors=[];let lastPlan;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const u=new URL(route.request().url());let json;
   if(u.pathname==='/api/v1/groups')json=Object.values(groups).map(g=>({samAccountName:g.replace('CORP\\',''),category:'security'}));
   else if(u.pathname.endsWith('/permission-map'))json=snapshot;
   else if(u.pathname.endsWith('/plan'))json=lastPlan=makePlan(route.request().postDataJSON());
   else if(u.pathname.endsWith('/apply'))json={status:'complete',id:'demo-operation',journal:'/var/lib/sambaadm-helper/permission-maps/demo-operation.json',items:lastPlan.changes.map(c=>({path:c.path,status:'applied'}))};
   else throw Error('Unexpected demo API '+u.pathname);
   await route.fulfill({json});
  });
  const shoot=async name=>{await page.evaluate(()=>scrollTo(0,0));await page.evaluate(()=>document.fonts.ready);await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));await page.screenshot({path:path.join(output,name),animations:'disabled',fullPage:name==='06-mobile.png'});};
  await page.goto('http://127.0.0.1:'+server.address().port+'/shares/docs/permission-map?node=files-02');
  await page.getByRole('button',{name:'Снять карту прав',exact:true}).click();await page.getByRole('button',{name:'Бухгалтерия',exact:true}).click();
  await shoot('01-map.png');
  await page.getByRole('button',{name:'Шаблоны прав',exact:true}).click();await shoot('02-template-library.png');
  const item=page.locator('.share-map-template-item').filter({has:page.getByRole('heading',{name:'Совместная работа отдела',exact:true})});await item.getByRole('button',{name:'Изменить',exact:true}).click();await shoot('03-template-editor.png');
  await page.getByRole('button',{name:'Сохранить шаблон',exact:true}).click();
  await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();
  await page.getByRole('button',{name:'Бухгалтерия/Архив',exact:true}).click();await page.getByLabel('Шаблон для наложения',{exact:true}).selectOption('archive');await page.getByRole('button',{name:'Наложить на выбранную папку',exact:true}).click();
  await shoot('04-overlays.png');
  await page.getByRole('button',{name:/^Предпросмотр изменений/}).click();await page.getByRole('dialog',{name:'Проверка изменений',exact:true}).waitFor();await shoot('05-review.png');
  await page.getByRole('button',{name:'Посмотреть на карте',exact:true}).click();await page.setViewportSize({width:390,height:900});await page.getByRole('button',{name:'Бухгалтерия',exact:true}).click();await shoot('06-mobile.png');
  await page.setViewportSize({width:1600,height:1060});await page.getByRole('button',{name:/^Предпросмотр изменений/}).click();await page.getByLabel('Подтверждаю применение показанных изменений к каталогам',{exact:true}).check();await page.getByRole('button',{name:'Применить к дереву папок',exact:true}).click();await page.getByRole('heading',{name:'Применено',exact:true}).waitFor();await shoot('07-result.png');
  assert.deepEqual(errors,[]);console.log('Rendered demo screenshots: '+output);
 }finally{await browser.close();server.close();fs.rmSync(fixtures,{recursive:true,force:true});}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
