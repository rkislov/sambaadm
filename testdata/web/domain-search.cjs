const {chromium}=require('playwright'),fs=require('fs'),os=require('os'),path=require('path'),http=require('http'),assert=require('assert/strict'),{execFileSync}=require('child_process');
const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'sambaadm-search-'));
execFileSync('go',['test','./internal/web','-run','^TestWorkspaceBrowserFixtures$','-count=1'],{cwd:repo,env:{...process.env,SAMBAADM_WEB_FIXTURE_DIR:dir}});
const server=http.createServer((req,res)=>{const p=new URL(req.url,'http://localhost').pathname,file=p.startsWith('/static/')?path.join(repo,'internal/web',p):path.join(dir,'admin-'+p.slice(1)+'.html');if(!fs.existsSync(file)){res.writeHead(404).end();return;}res.setHeader('Content-Type',file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(file));});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true});try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],queries=[];let partial=false;
 const user={samAccountName:'alice',displayName:'Алиса <img src=x onerror=alert(1)>',dn:'CN=alice,DC=example,DC=com',enabled:true,revision:'one',attributes:{}},computer={samAccountName:'WRK01$',dnsHostName:'wrk01.example.com',dn:'CN=WRK01,DC=example,DC=com'};
 page.on('pageerror',e=>errors.push(e.message));await page.route('**/api/v1/**',async route=>{const u=new URL(route.request().url()),p=u.pathname.slice(7);let result=[];
 if(u.searchParams.has('q'))queries.push([p,u.searchParams.get('q')]);
 if(p==='/users')result=[user];if(p==='/computers')result=[computer];if(p==='/groups'){if(partial){await route.fulfill({status:503,json:{error:'unavailable'}});return;}result=[{samAccountName:'IT',dn:'CN=IT,DC=example,DC=com'}];}
 if(p==='/users/alice')result=user;if(p==='/computers/WRK01%24')result=computer;
 if(p==='/directory/tree')result={name:'example.com',kind:'domain',dn:'DC=example,DC=com',children:[]};
 await route.fulfill({json:result});});
 const url='http://127.0.0.1:'+server.address().port;
 await page.goto(url+'/computers');await page.getByRole('button',{name:'Найти в домене',exact:true}).click();let dialog=page.getByRole('dialog',{name:'Поиск в домене'});
 await dialog.getByRole('searchbox').fill('alice');await dialog.getByRole('button',{name:'Найти',exact:true}).click();await dialog.getByRole('status').filter({hasText:'Найдено: 3'}).waitFor();assert.equal(queries.length,3);assert.ok(queries.every(([,q])=>q==='alice'));assert.equal(await dialog.locator('img').count(),0);
 assert.equal(await dialog.getByRole('link').first().getAttribute('href'),'/users?object=alice');await dialog.getByRole('link').first().click();dialog=page.locator('.workspace-dialog');await dialog.getByLabel('Отображаемое имя',{exact:true}).waitFor();assert.equal(await page.locator('tbody tr').count(),1);await dialog.getByRole('button',{name:'Закрыть окно',exact:true}).click();
 await page.getByRole('button',{name:'Найти в домене',exact:true}).click();dialog=page.getByRole('dialog',{name:'Поиск в домене'});partial=true;await dialog.getByRole('searchbox').fill('WRK');await dialog.getByRole('button',{name:'Найти',exact:true}).click();await dialog.getByRole('status').filter({hasText:'Часть разделов недоступна'}).waitFor();assert.equal(await dialog.getByRole('link').count(),2);await page.setViewportSize({width:390,height:844});assert.equal(await dialog.evaluate(e=>e.scrollWidth>e.clientWidth),false);await page.keyboard.press('Escape');assert.equal(await dialog.isVisible(),false);
 await page.goto(url+'/computers?object=WRK01%24');dialog=page.locator('.workspace-dialog');await dialog.getByText('Основные сведения',{exact:true}).waitFor();assert.deepEqual(errors,[]);
 console.log('PASS: domain-wide server search, escaped results, direct user/computer cards, partial failures, mobile and keyboard close');
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
