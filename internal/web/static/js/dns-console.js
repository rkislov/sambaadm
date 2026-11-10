/* DNS manager: authoritative server queries, grouped zones and selectable owners. */
(function(){'use strict';
 window.sambaadmDNSConsole=function({sidebar,main,request,admin,onOpen,onCreate,onDelete}){
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b,enc=encodeURIComponent;
  const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
  const button=(label,fn)=>{const e=el('button','',label);e.type='button';e.onclick=fn;return e;};
  let zones=[],selected='',owner='@',serial=0,records=[],page=0,sort='name',direction=1,controller=null;const names=new Map(),expanded=new Set(),collator=new Intl.Collator(ru?'ru':'en',{numeric:true});
  sidebar.classList.add('dns-console-tree');main.classList.add('dns-console-main');main.replaceChildren();
  const heading=el('h2'),location=el('p','muted'),tools=el('div','dns-console-tools'),search=el('input'),type=el('select'),notice=el('p','workspace-message');
  search.type='search';search.placeholder=t('Поиск в текущем списке','Search current list');search.setAttribute('aria-label',search.placeholder);type.setAttribute('aria-label',t('Тип записи','Record type'));
  for(const v of ['ALL','A','AAAA','CNAME','NS','PTR','MX','SRV','TXT','SOA']){const o=el('option','',v==='ALL'?t('Все типы','All types'):v);o.value=v;type.append(o);}
  tools.append(search,type,button(t('Обновить записи','Refresh records'),()=>loadRecords(selected,owner)));
  if(admin)tools.append(button(t('Новая запись','New record'),()=>onCreate(zones.find(z=>z.name===selected),owner)),button(t('Удалить зону','Delete zone'),()=>onDelete(zones.find(z=>z.name===selected))));
  const wrap=el('div','workspace-table'),table=el('table','dns-record-table'),head=el('tr'),body=el('tbody');
  for(const [key,label] of [['name',t('Имя','Name')],['type',t('Тип','Type')],['data',t('Данные','Data')],['ttl','TTL']]){const th=el('th');th.scope='col';th.dataset.sort=key;const b=button(label,()=>{direction=sort===key?-direction:1;sort=key;renderRows();});b.setAttribute('aria-label',label);th.append(b);head.append(th);}head.append(el('th','',t('Действия','Actions')));const thead=el('thead');thead.append(head);table.append(thead,body);wrap.append(table);
  const pager=el('div','policy-list-pager'),previous=button(t('Назад','Previous'),()=>{page--;renderRows();}),next=button(t('Далее','Next'),()=>{page++;renderRows();}),info=el('output');pager.append(previous,info,next);
  notice.setAttribute('aria-live','polite');main.append(heading,location,tools,notice,wrap,pager,el('p','muted',t('Показаны записи выбранного имени и вложенные узлы. Откройте узел, чтобы просмотреть его записи. Изменения выполняются на DNS-сервере.','Records of the selected owner and its child nodes are shown. Open a node to inspect its records. Changes are sent to the DNS server.')));
  function renderRows(){
   const children=new Map();for(const name of names.get(selected)||[]){if(name==='@')continue;let rest=name;if(owner!=='@'){if(!name.toLowerCase().endsWith('.'+owner.toLowerCase()))continue;rest=name.slice(0,-owner.length-1);}const label=rest.split('.').at(-1);if(label)children.set(label.toLowerCase(),{name:label+(owner==='@'?'':'.'+owner),type:'FOLDER',data:'',folder:true});}
   const needle=search.value.trim().toLocaleLowerCase(),rows=[...(type.value==='ALL'?children.values():[]),...records].filter(r=>(type.value==='ALL'||r.type===type.value)&&(!needle||[r.name,r.type,r.data].join(' ').toLocaleLowerCase().includes(needle))).sort((a,b)=>direction*(sort==='ttl'?Number(a.ttl||0)-Number(b.ttl||0):collator.compare(String(a[sort]||''),String(b[sort]||''))));
   page=Math.min(Math.max(0,page),Math.max(0,Math.ceil(rows.length/100)-1));body.replaceChildren();for(const h of head.children)if(h.dataset.sort)h.setAttribute('aria-sort',sort===h.dataset.sort?(direction===1?'ascending':'descending'):'none');
   for(const r of rows.slice(page*100,page*100+100)){const tr=el('tr'),name=el('td');name.append(button(r.name||'@',()=>r.folder?loadRecords(selected,r.name):onOpen(zones.find(z=>z.name===selected),r.name||owner,r)));tr.append(name,el('td','',r.folder?t('Узел','Node'):r.type),el('td','mono',r.data||''),el('td','',r.ttl==null?'—':String(r.ttl)));const actions=el('td');actions.append(button(r.folder?t('Открыть','Open'):admin?t('Свойства','Properties'):t('Просмотр','View'),()=>r.folder?loadRecords(selected,r.name):onOpen(zones.find(z=>z.name===selected),r.name||owner,r)));tr.append(actions);tr.ondblclick=()=>r.folder?loadRecords(selected,r.name):onOpen(zones.find(z=>z.name===selected),r.name||owner,r);body.append(tr);}
   if(!rows.length){const tr=el('tr'),cell=el('td','muted',t('Записи не найдены','No records found'));cell.colSpan=5;tr.append(cell);body.append(tr);}previous.disabled=page===0;next.disabled=(page+1)*100>=rows.length;info.textContent=(rows.length?page*100+1:0)+'–'+Math.min(rows.length,page*100+100)+' / '+rows.length;
  }
  function tree(){
   sidebar.replaceChildren(el('h2','',t('Диспетчер DNS','DNS Manager')));
   for(const [reverse,title] of [[false,t('Зоны прямого просмотра','Forward Lookup Zones')],[true,t('Зоны обратного просмотра','Reverse Lookup Zones')]]){
    const group=el('details');group.open=true;group.append(el('summary','',title));sidebar.append(group);
    for(const z of zones.filter(z=>/(?:^|\.)(in-addr|ip6)\.arpa\.?$/i.test(z.name)===reverse).sort((a,b)=>collator.compare(a.name,b.name))){
     const branch=el('details');branch.open=z.name===selected||expanded.has(z.name);const summary=el('summary'),b=button(z.name,()=>loadRecords(z.name,'@'));b.classList.toggle('selected',z.name===selected&&owner==='@');summary.append(b);branch.append(summary);branch.ontoggle=()=>branch.open?expanded.add(z.name):expanded.delete(z.name);group.append(branch);
     const root={children:new Map()};for(const value of names.get(z.name)||[]){if(value==='@')continue;let n=root,parts=[];for(const label of value.split('.').reverse()){parts.unshift(label);const key=label.toLowerCase();if(!n.children.has(key))n.children.set(key,{label,name:parts.join('.'),children:new Map()});n=n.children.get(key);}}
     function append(parent,n){for(const child of [...n.children.values()].sort((a,b)=>collator.compare(a.label,b.label))){const key=z.name+'/'+child.name;const b=button(child.label,()=>loadRecords(z.name,child.name));b.classList.toggle('selected',z.name===selected&&owner===child.name);b.title=child.name+'.'+z.name;if(child.children.size){const d=el('details');d.open=expanded.has(key)||(z.name===selected&&(owner===child.name||owner.endsWith('.'+child.name)));const s=el('summary');s.append(b);d.append(s);d.ontoggle=()=>d.open?expanded.add(key):expanded.delete(key);append(d,child);parent.append(d);}else parent.append(b);}}
     append(branch,root);
    }
   }
   if(!zones.length)sidebar.append(el('p','muted',t('Зоны не найдены','No zones found')));
  }
  async function loadRecords(zone,name){
   if(!zone)return;const id=++serial;controller?.abort();controller=new AbortController();const signal=controller.signal;selected=zone;owner=name||'@';page=0;records=[];heading.textContent=zone;location.textContent=(owner==='@'?t('Корень зоны','Zone apex'):owner+'.'+zone);notice.setAttribute('role','status');notice.textContent=t('Загрузка записей…','Loading records…');renderRows();tree();
   const known=names.get(zone),virtual=known&&owner!=='@'&&!known.some(n=>n.toLowerCase()===owner.toLowerCase())&&known.some(n=>n.toLowerCase().endsWith('.'+owner.toLowerCase()));
   const reads=[virtual?Promise.resolve([]):request('/dns/zones/'+enc(zone)+'/records?'+new URLSearchParams({name:owner,type:'ALL',exact:'true'}),'GET',undefined,{signal}),names.has(zone)?Promise.resolve(names.get(zone)):request('/dns/zones/'+enc(zone)+'/nodes','GET',undefined,{signal})];const [data,owners]=await Promise.allSettled(reads);if(id!==serial)return;
   if(owners.status==='fulfilled'){names.set(zone,owners.value);tree();}
   if(data.status==='fulfilled'){records=data.value||[];notice.textContent=owners.status==='rejected'?t('Записи получены, но дерево имён недоступно: ','Records loaded, but owner hierarchy is unavailable: ')+owners.reason.message:t('Записи загружены','Records loaded');}else{notice.textContent=data.reason.message;notice.setAttribute('role','alert');}renderRows();
  }
  search.oninput=()=>{page=0;renderRows();};type.onchange=()=>{page=0;renderRows();};
  return {setZones(list){zones=list;names.clear();if(!zones.some(z=>z.name===selected)){selected=zones[0]?.name||'';owner='@';}tree();if(selected)loadRecords(selected,owner);else{heading.textContent=t('Выберите или создайте зону','Select or create a zone');records=[];renderRows();}},refresh(deleted=false,name){names.delete(selected);return loadRecords(selected,deleted?'@':(name||owner));}};
 };
})();
