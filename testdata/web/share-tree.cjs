const {chromium}=require('playwright');
const fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-share-tree-'));
execFileSync('go',['test','./internal/web','-run','^TestShareTreeBrowserFixture$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_SHARE_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{
 const p=new URL(req.url,'http://localhost').pathname;
 const file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,p.includes('readonly')?'readonly-tree.html':'admin-tree.html');
 if(!fs.existsSync(file)){res.writeHead(404).end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));
});
(async()=>{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],reads=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
   const u=new URL(route.request().url());let json;
   if(u.pathname.endsWith('/directories')){
    assert.equal(u.searchParams.get('node'),'files-02');
    const rel=u.searchParams.get('path');reads.push(rel);
    json=rel==='.'?{directories:[{name:'Отдел & проекты',path:'Отдел & проекты'}],next:u.searchParams.get('offset')==='0'?200:0}:rel==='Отдел & проекты'?{directories:[{name:'nested',path:'Отдел & проекты/nested'}]}:{directories:[]};
    if(u.searchParams.get('offset')==='200')json={directories:[{name:'<img src=x onerror=alert(1)>',path:'safe'}]};
   }else if(u.pathname==='/api/v1/groups')json=[{samAccountName:'Finance',category:'security',description:'Финансовый отдел'},{samAccountName:'Mailing',category:'distribution'}];
   else throw Error('Unexpected API '+u.pathname);
   await route.fulfill({json});
  });
  const base='http://127.0.0.1:'+server.address().port;
  await page.goto(base+'/shares/docs/acl?node=files-02&path='+encodeURIComponent('Отдел & проекты/nested'));
  await page.getByRole('link',{name:'nested',exact:true}).waitFor();
  assert(reads.includes('Отдел & проекты'));
  const current=page.locator('#share-directory-tree [aria-current=page]');assert.equal(await current.textContent(),'nested');
  const currentURL=new URL(await current.getAttribute('href'),base);assert.equal(currentURL.searchParams.get('path'),'Отдел & проекты/nested');assert.equal(currentURL.searchParams.get('node'),'files-02');
  await page.getByRole('button',{name:'Показать ещё',exact:true}).click();
  await page.getByRole('link',{name:'<img src=x onerror=alert(1)>',exact:true}).waitFor();assert.equal(await page.locator('#share-directory-tree img').count(),0);
  await page.locator('[name=acl_x]').click();assert.equal(await page.locator('[name=acl_x]').isChecked(),true,'directory read lost search');
  await page.locator('[name=acl_r]').uncheck();await page.locator('[name=acl_x]').click();assert.equal(await page.locator('[name=acl_x]').isChecked(),false,'explicit revocation blocked');
  await page.locator('[name=acl_w]').check();assert.equal(await page.locator('[name=acl_x]').isChecked(),true,'directory write lost search');
  await page.locator('[name=acl_w]').uncheck();await page.locator('[name=acl_r]').check();
  const picker=page.getByLabel('Доменная группа безопасности',{exact:true});
  await picker.locator('option[value="Finance"]').waitFor({state:'attached'});assert.equal(await picker.locator('option[value="Mailing"]').count(),0);
  await picker.selectOption('Finance');assert.equal(await page.locator('[name=acl_name]').isDisabled(),true);
  for(const form of await page.locator('form[action*="/shares/docs/acl"]').all()){
   const target=new URL(await form.getAttribute('action'),base);assert.equal(target.searchParams.get('node'),'files-02');assert.equal(target.searchParams.get('path'),'Отдел & проекты/nested');
  }
  await page.locator('.share-acl-edit[data-default=true]').click();
  assert.equal(await page.locator('[name=acl_scope]').inputValue(),'default');assert.equal(await page.locator('[name=acl_name]').inputValue(),'12345');assert.equal(await page.locator('[name=acl_name]').isDisabled(),false);assert.equal(await page.locator('[name=acl_w]').isChecked(),false);
  await page.locator('.share-acl-remove[data-name="12345"][data-default=true]').click();assert.equal(await page.locator('[name=remove_acl]').inputValue(),'d:group:12345');
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'mobile horizontal overflow');
  if(process.env.SAMBAADM_SHARE_SCREENSHOT) await page.screenshot({path:process.env.SAMBAADM_SHARE_SCREENSHOT,fullPage:true});
  await page.goto(base+'/readonly?node=files-02');assert.equal(await page.locator('#share-domain-group').count(),0);assert.equal(await page.locator('.share-acl-edit').count(),0);await page.getByRole('link',{name:'nested',exact:true}).waitFor();
  assert.deepEqual(errors,[]);
  console.log('PASS directory expansion, pagination, target server/path, escaped names, security groups, ACL editing, readonly and mobile layout');
 }finally{await browser.close();server.close();fs.rmSync(dir,{recursive:true,force:true});}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
