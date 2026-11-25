/* DNS routing: explicit preview, one delegation or one rule, per-server results. */
(()=>{'use strict';
 const panel=document.querySelector('#dns-routing-panel');if(!panel)return;
 const message=document.querySelector('#dns-routing-message'),csrf=document.querySelector('meta[name=csrf-token]')?.content,enc=encodeURIComponent;
 const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
 const button=(text,fn)=>{const b=el('button','',text);b.type='button';b.onclick=()=>Promise.resolve(fn()).catch(showError);return b;};
 const showError=e=>{message.textContent=e.message||String(e);message.setAttribute('role','alert');};
 const api=async(path,method='GET',body)=>{const response=await fetch('/api/v1'+path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},...(body?{body:JSON.stringify(body)}:{})});const value=await response.json();if(!response.ok)throw Error(value.error||'Ошибка DNS');return value;};
 const field=(form,label,tag='input',value='')=>{const wrap=el('label','',label),input=el(tag);input.value=value;input.setAttribute("aria-label",label);wrap.append(input);form.append(wrap);return input;};
 const select=(form,label,options)=>{const s=field(form,label,'select');for(const [v,t] of options){const o=el('option','',t);o.value=v;s.append(o);}return s;};
 const note=(box,text)=>box.append(el('p','muted',text));
 let generation=0,nodes=[],zones=[];
 function preview(box,title,value){const d=el('details');d.open=true;d.append(el('summary','',title));const pre=el('pre','dns-routing-preview',value);d.append(pre);box.append(d);}
 function checkbox(box,label){const l=el('label','dns-routing-check'),c=el('input');c.type='checkbox';l.append(c,document.createTextNode(label));box.append(l);return c;}
 function invalidate(form,box){form.addEventListener('input',()=>{box._ticket=null;box.replaceChildren();});form.addEventListener('change',()=>{box._ticket=null;box.replaceChildren();});}
 function tab(name){const id=++generation;message.textContent='';panel.replaceChildren();for(const b of document.querySelectorAll('[data-dns-tab]'))b.setAttribute('aria-selected',String(b.dataset.dnsTab===name));const fn={delegations,forwarding,backend}[name];Promise.resolve(fn(id)).catch(showError);}
 async function delegations(id){
  const card=el('div','card'),tools=el('div','dns-routing-fields'),list=el('div'),form=el('form','dns-routing-fields'),result=el('div');form.onsubmit=e=>e.preventDefault();
  const zone=select(tools,'Родительская зона',zones.filter(z=>!/(in-addr|ip6)\.arpa\.?$/i.test(z.name)).map(z=>[z.name,z.name]));card.append(tools,list,el('h2','','Делегирование поддомена'),form,result);panel.append(card);
  const child=field(form,'Поддомен (например app)'),servers=field(form,'DNS-серверы: имя и IP-адреса, по одному серверу в строке','textarea');servers.placeholder='ns1.app.ipr.loc 10.10.2.53\nns2.other.loc';servers.rows=3;
  note(card,'Для сервера внутри поддомена нужны IP-адреса (glue). Внешнему серверу достаточно полного DNS-имени. Изменения AD-зоны реплицируются между контроллерами, включая BIND9 DLZ.');invalidate(form,result);
  let state=null,loadID=0;
  async function load(){const seq=++loadID;result.replaceChildren();list.textContent='Загрузка…';const data=await api('/dns/zones/'+enc(zone.value)+'/delegations');if(id!==generation||seq!==loadID)return;state=data;list.replaceChildren();if(!state.delegations.length)note(list,'Делегирований нет.');for(const d of state.delegations){const row=el('div','dns-routing-row'),desc=el('span');desc.append(el('strong','',d.domain),el('small','',d.servers.map(s=>s.name+(s.addresses.length?' · '+s.addresses.join(', '):'')).join('; ')));row.append(desc,button('Настроить',()=>{child.value=d.child;servers.value=d.servers.map(s=>[s.name,...s.addresses].join(' ')).join('\n');result.replaceChildren();}),button('Удалить',()=>plan(true,d.child)));list.append(row);}}
  const input=remove=>({child:child.value,servers:remove?[]:servers.value.split('\n').map(s=>s.trim()).filter(Boolean).map(line=>{const [name,...addresses]=line.split(/[\s,]+/);return {name,addresses};}),remove});
  async function plan(remove=false,target){const ticket=Symbol();result._ticket=ticket;const zoneName=zone.value;const body=input(remove);if(target)body.child=target;result.replaceChildren();const p=await api('/dns/zones/'+enc(zone.value)+'/delegations/plan','POST',body);if(id!==generation||result._ticket!==ticket||zone.value!==zoneName)return;preview(result,(remove?'Удаление: ':'Изменения: ')+p.domain,p.changes.map(c=>(c.remove?'− ':'+ ')+c.name+' '+c.type+' '+c.data).join('\n')||'Изменений нет');note(result,p.warning);if(!p.changes.length)return;const agree=checkbox(result,'Подтверждаю изменение делегирования');const apply=button('Применить',async()=>{if(!agree.checked)throw Error('Подтвердите изменение');apply.disabled=true;try{await api('/dns/zones/'+enc(zone.value)+'/delegations','PUT',{...body,revision:p.revision,proposedRevision:p.proposedRevision,confirm:true});await load();message.textContent='Делегирование сохранено в AD-зоне.';}finally{apply.disabled=false;}});result.append(apply);}
  form.append(button('Предпросмотр',()=>plan()));zone.onchange=()=>load().catch(showError);await load();
 }
 async function forwarding(id){
  const card=el('div','card'),form=el('form','dns-routing-fields'),list=el('div'),result=el('div');form.onsubmit=e=>e.preventDefault();const source=select(form,'Просмотреть правила сервера',nodes.map(n=>[n,n])),targets=el('div','dns-routing-targets');
  card.append(form,targets,list,result);panel.append(card);let state=null,loadID=0;
  const domain=field(form,'Домен пересылки (например app.ipr.loc)'),servers=field(form,'IP-адреса DNS-серверов через пробел'),mode=select(form,'Если целевые DNS недоступны',[['only','Возвращать ошибку — только указанные серверы'],['first','Пробовать обычное рекурсивное разрешение']]);
  note(card,'Правило действует на домен и все вложенные имена. Для поддомена собственной AD-зоны сначала создайте делегирование на первой вкладке. Правила BIND не реплицируются через AD: выберите серверы доставки. Остальные правила каждого сервера сохраняются.');
  const checks=new Map();targets.append(el('strong','','Доставить на серверы:'));for(const n of nodes){const c=checkbox(targets,n);c.disabled=true;c.checked=false;checks.set(n,c);}targets.append(button('Выбрать все',()=>{for(const c of checks.values())if(!c.disabled)c.checked=true;result._ticket=null;result.replaceChildren();}));invalidate(form,result);targets.addEventListener('change',()=>{result._ticket=null;result.replaceChildren();});
  async function load(){const seq=++loadID;result.replaceChildren();state=await api('/dns/forwarding?node='+enc(source.value));if(id!==generation||seq!==loadID)return;list.replaceChildren();if(!state.editable){note(list,state.warning||'Пересылка недоступна. Проверьте DNS-бэкенд и обновите helper.');return;}note(list,'BIND · '+source.value+' · '+state.path);if(!state.rules.length)note(list,'Управляемых правил нет. Правила, заданные вне sambaadm, сохраняются.');for(const r of state.rules){const row=el('div','dns-routing-row'),desc=el('span');desc.append(el('strong','',r.domain),el('small','',r.servers.join(', ')+' · '+(r.mode==='only'?'Только пересылка':'С рекурсивным резервом')));row.append(desc,button('Настроить',()=>{domain.value=r.domain;servers.value=r.servers.join(' ');mode.value=r.mode;result.replaceChildren();}),button('Удалить',()=>plan(true,r.domain)));list.append(row);}}
  async function plan(remove=false,target,retryNodes){
   const ticket=Symbol();result._ticket=ticket;result.replaceChildren();
   const selected=retryNodes||[...checks].filter(([,c])=>c.checked).map(([n])=>n);
   if(!selected.length)throw Error('Выберите хотя бы один сервер');
   const name=(target||domain.value).trim().toLowerCase().replace(/\.$/,'');if(!name)throw Error('Укажите домен');
   const rule={domain:name,servers:servers.value.split(/[\s,]+/).filter(Boolean),mode:mode.value},plans=[],failed=[];let unchanged=0;
   const active=()=>id===generation&&result._ticket===ticket;
   const signature=rules=>JSON.stringify(rules.map(r=>({domain:r.domain,servers:r.servers,mode:r.mode})).sort((a,b)=>a.domain.localeCompare(b.domain)));
   const retry=nodes=>result.append(button('Повторить для недоставленных',()=>plan(remove,name,nodes)));
   for(const node of selected){
    try{
     const current=await api('/dns/forwarding?node='+enc(node));if(!active())return;
     if(!current.editable)throw Error(current.warning||'BIND недоступен');
     const rules=current.rules.filter(r=>r.domain!==name);if(!remove)rules.push(rule);
     const p=await api('/dns/forwarding/plan?node='+enc(node),'POST',{rules,revision:current.revision});if(!active())return;
     if(signature(current.rules)===signature(p.rules)){unchanged++;note(result,node+': уже актуально, повторная запись не нужна.');continue;}
     preview(result,node+' · предпросмотр','Было:\n'+(p.before||'Нет управляемых правил')+'\nСтанет:\n'+p.proposed);plans.push({node,rules,p});
    }catch(e){if(!active())return;failed.push(node);note(result,node+': не доставлено — '+e.message);}
   }
   if(failed.length)note(result,'Часть серверов недоступна. Примените изменения на доступных серверах, затем повторите доставку для остальных.');
   if(!plans.length){if(failed.length)retry(failed);else note(result,'Все выбранные серверы уже содержат нужные настройки.');return;}
   const agree=checkbox(result,'Подтверждаю применение на выбранных серверах');
   const apply=button('Применить на '+plans.length+(plans.length===1?' сервере':' серверах'),async()=>{
    if(!active())return;if(!agree.checked)throw Error('Подтвердите применение');apply.disabled=true;
    const report=el('div'),pending=[...failed];let delivered=0;result.append(report);
    for(const {node,rules,p} of plans){
     try{const out=await api('/dns/forwarding?node='+enc(node),'PUT',{rules,revision:p.revision,proposedRevision:p.proposedRevision,confirm:true});delivered++;note(report,node+': применено. Резервная копия: '+out.backup);}
     catch(e){pending.push(node);note(report,node+': не доставлено — '+e.message);}
    }
    note(report,'Обработка завершена. Доставлено: '+delivered+'. Уже актуально: '+unchanged+'. Не доставлено: '+pending.length+'.');
    if(active()&&pending.length)retry(pending);
   });result.append(apply);
  }
  const planButton=button('Предпросмотр',()=>plan());planButton.disabled=true;form.append(planButton);source.onchange=()=>load().catch(showError);
  if(nodes.length){const pending=el('p','muted','Определяем работающие DNS-бэкенды…');targets.append(pending);await Promise.all(nodes.map(async n=>{try{const status=await api('/dns/forwarding?node='+enc(n));if(id!==generation)return;const c=checks.get(n);c.disabled=!status.editable;c.checked=!!status.editable;if(!status.editable){const hint=el('small','muted',' · BIND недоступен');hint.title=status.warning||'Выберите этот сервер в списке просмотра для подробностей';c.parentElement.append(hint);}}catch(e){if(id===generation){const hint=el('small','muted',' · Нет связи');hint.title=e.message;checks.get(n).parentElement.append(hint);}}}));if(id!==generation)return;pending.remove();planButton.disabled=false;await load();}else note(list,'Зарегистрируйте helper в настройках серверов.');
 }
 async function backend(id){
  const card=el('div','card'),form=el('form','dns-routing-fields'),result=el('div'),log=el('pre','dns-routing-preview');form.onsubmit=e=>e.preventDefault();const node=select(form,'Контроллер домена',nodes.map(n=>[n,n])),target=select(form,'DNS-бэкенд',[['BIND9_DLZ','BIND9 DLZ — условная пересылка и AD-зоны'],['SAMBA_INTERNAL','Встроенный DNS Samba']]),reinstall=checkbox(form,'Переустановить пакеты BIND');card.append(el('h2','','Установка и переключение DNS'),form,result,log);panel.append(card);note(card,'Мастер для ALT Linux. Выбранный DC временно перезапустит Samba и DNS. При возврате на встроенный DNS правила BIND сохранятся, но перестанут действовать. Зоны AD остаются в домене.');invalidate(form,result);
  let timer=null;const storageKey=()=> 'sambaadm-dns-backend:'+node.value;
  async function poll(jobID,server){if(id!==generation||node.value!==server)return;try{const st=await api('/dns/backend/status?'+new URLSearchParams({node:server,id:jobID}));if(id!==generation||node.value!==server)return;log.textContent=server+' · '+st.state+'\n'+(st.log||[]).join('\n')+(st.warning?'\n'+st.warning:'');if(['queued','running'].includes(st.state))timer=setTimeout(()=>poll(jobID,server),2500);else message.textContent=st.state==='completed'?'Переключение DNS завершено.':'Проверьте журнал: задание не завершилось успешно.';}catch(e){if(id===generation){showError(e);timer=setTimeout(()=>poll(jobID,server),5000);}}}
  form.append(button('Предпросмотр',async()=>{result.replaceChildren();const input={target:target.value,reinstall:reinstall.checked},server=node.value,p=await api('/dns/backend/plan?node='+enc(server),'POST',input);if(id!==generation)return;preview(result,server+' · '+p.backend+' → '+p.target,p.steps.map((s,i)=>(i+1)+'. '+s).join('\n'));note(result,p.warning);const agree=checkbox(result,'Подтверждаю перезапуск DNS и Samba на этом DC'),start=button('Начать',async()=>{if(!agree.checked)throw Error('Подтвердите перезапуск');start.disabled=true;try{const job=await api('/dns/backend/start?node='+enc(server),'POST',{...input,revision:p.revision,confirm:true});localStorage.setItem('sambaadm-dns-backend:'+server,job.id);poll(job.id,server);}catch(e){start.disabled=false;throw e;}});result.append(start);}));
  node.onchange=()=>{clearTimeout(timer);log.textContent='';const job=localStorage.getItem(storageKey());if(job)poll(job,node.value);};target.onchange=()=>{if(target.value==='SAMBA_INTERNAL')reinstall.checked=false;reinstall.disabled=target.value==='SAMBA_INTERNAL';};if(node.value)node.onchange();
 }
 for(const b of document.querySelectorAll('[data-dns-tab]')){b.disabled=true;b.onclick=()=>tab(b.dataset.dnsTab);}
 message.textContent='Загрузка DNS…';
 Promise.all([api('/dns/zones'),api('/dns/routing/nodes')]).then(([z,n])=>{zones=z;nodes=n||[];for(const b of document.querySelectorAll('[data-dns-tab]'))b.disabled=false;tab('delegations');}).catch(showError);
})();
