/* Role installation belongs to the home console; service pages manage live services. */
(() => {
 'use strict';
 const root=document.getElementById('dashboard-roles');if(!root)return;
 const csrf=document.querySelector('meta[name=csrf-token]')?.content;
 const node=root.querySelector('[name=node]'),role=root.querySelector('[name=role]'),target=root.querySelector('[name=backend]'),form=root.querySelector('form'),output=root.querySelector('[role=status]'),review=root.querySelector('[data-role-review]'),preview=root.querySelector('[data-role-preview]'),confirm=root.querySelector('[data-role-confirm]'),planButton=root.querySelector('[data-role-plan]');
 const opener=document.getElementById('dashboard-role-add');
 function open(){if(!root.open)root.showModal();}
 opener?.addEventListener('click',open);root.querySelector('[data-role-close]').addEventListener('click',()=>root.close());
 window.addEventListener('hashchange',()=>{if(location.hash==='#dashboard-roles')open();});if(location.hash==='#dashboard-roles')open();
 let servers=[],ticket=null,busy=false;
 const settings={ad:{label:'Контроллер Samba AD',path:'/settings/domain-init'},smb:{label:'Файловый сервер Samba',path:'/settings/domain-init?role=member'},cluster:{label:'Отказоустойчивый файловый кластер',path:'/file-clusters?setup=1'},helper:{label:'Подключение сервера (helper)',path:'/settings/helpers'}};
 const api=async(path,body)=>{const response=await fetch('/api/v1'+path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:body?JSON.stringify(body):undefined});const result=await response.json();if(!response.ok)throw Error(result.error||'Ошибка '+response.status);return result;};
 const params=(name=node.value,family=role.value==='dhcp6'?'6':'4')=>'?'+new URLSearchParams({node:name,family});
 const message=(text,error=false)=>{output.textContent=text;output.classList.toggle('error',error);};
 const lock=state=>{busy=state;for(const input of form.elements)input.disabled=state;confirm.disabled=state;};
 function invalidate(){ticket=null;preview.replaceChildren();review.hidden=true;target.closest('label').hidden=role.value!=='dns';node.closest('label').hidden=!!settings[role.value];planButton.textContent=settings[role.value]?'Открыть мастер настройки':'Проверить установку…';}
 form.addEventListener('change',invalidate);
 form.addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;
  if(settings[role.value]){location.href=settings[role.value].path;return;}
  if(!node.value){message('Выберите сервер с подключённым helper.',true);return;}
  lock(true);message('Проверяем план на '+node.value+'…');
  try{
   const kind=role.value,server=node.value,q=params(),body={family:kind==='dhcp6'?'6':'4'};
   let plan;
   if(kind==='cups')plan=await api('/printing/install.plan?'+new URLSearchParams({node:server}),{});
   else if(kind==='dns')plan=await api('/dns/backend/plan?'+new URLSearchParams({node:server}),{target:target.value,reinstall:false});
   else plan=await api('/dhcp'+(kind==='gss'?'/gss/install/plan':'/install/plan')+q,body);
   ticket={kind,server,q,body,plan,target:target.value};preview.replaceChildren();
   const title=document.createElement('h3');title.textContent=server+' · '+role.selectedOptions[0].textContent;
   const text=document.createElement('pre');text.textContent=[plan.description,plan.proposed,plan.simulation||plan.validation,plan.steps?.join('\n'),plan.warning].filter(Boolean).join('\n\n');preview.append(title,text);
   const note=document.createElement('p');note.textContent=kind==='dns'?'Будут перезапущены Samba и DNS выбранного DC. Зоны AD сохраняются.':'Установка выполняется через helper из репозиториев ALT. После установки откройте раздел службы для настройки.';preview.append(note);review.hidden=false;message('План готов к подтверждению.');
  }catch(e){message(e.message,true);}finally{lock(false);}
 });
 async function poll(job){
  for(;;){
   const path=job.kind==='cups'?'/printing/install.status?'+new URLSearchParams({node:job.server,id:job.id}):job.kind==='dns'?'/dns/backend/status?'+new URLSearchParams({node:job.server,id:job.id}):'/dhcp/gss/install/status'+job.q+'&jobID='+encodeURIComponent(job.id);
   const state=await api(path);message(job.server+': '+(state.phase||state.state)+(state.detail?'\n'+state.detail:'')+(state.log?'\n'+state.log.join('\n'):''),state.state==='failed');
   if(['complete','completed','failed'].includes(state.state)){localStorage.removeItem('sambaadm-role-job');if(state.state==='failed')throw Error('Установка не завершена; проверьте журнал задания.');return;}
   await new Promise(resolve=>setTimeout(resolve,2000));
  }
 }
 confirm.addEventListener('click',async()=>{
  if(!ticket||busy)return;const current=ticket;ticket=null;lock(true);review.hidden=true;message('Выполняем настройку на '+current.server+'…');
  try{
   let result;
   if(current.kind==='cups')result=await api('/printing/install.start?'+new URLSearchParams({node:current.server}),{revision:current.plan.revision,confirm:true});
   else if(current.kind==='dns')result=await api('/dns/backend/start?'+new URLSearchParams({node:current.server}),{target:current.target,reinstall:false,revision:current.plan.revision,confirm:true});
   else result=await api('/dhcp'+(current.kind==='gss'?'/gss/install/start':'/install')+current.q,{...current.body,revision:current.plan.revision,proposedRevision:current.plan.proposedRevision,confirm:true});
   if(['dns','gss','cups'].includes(current.kind)){const job={kind:current.kind,server:current.server,q:current.q,id:result.id};localStorage.setItem('sambaadm-role-job',JSON.stringify(job));await poll(job);}
   message(current.server+': настройка роли завершена. '+(result.detail||''));
   const link=document.createElement('a');link.className='btn';link.textContent='Открыть управление службой';link.href=current.kind==='cups'?'/printers?node='+encodeURIComponent(current.server):current.kind==='dns'?'/dns':'/dhcp'+current.q+(current.kind==='ddns'||current.kind==='gss'?'&view=ddns':'');output.append(document.createTextNode(' '),link);
   document.getElementById('service-overview-refresh')?.click();
  }catch(e){message(e.message,true);}finally{lock(false);}
 });
 api('/services/overview').then(data=>{
  servers=(data.servers||[]).filter(s=>s.helper==='online'||s.helper==='legacy');
  for(const server of servers){const option=document.createElement('option');option.value=option.textContent=server.name;node.append(option);}
  if(!servers.length)message('Для установки службы сначала подключите сервер через helper.');
  invalidate();
  try{const job=JSON.parse(localStorage.getItem('sambaadm-role-job'));if(job&&['dns','gss','cups'].includes(job.kind)&&servers.some(s=>s.name===job.server)){lock(true);poll(job).catch(e=>message(e.message,true)).finally(()=>lock(false));}}catch{}
 }).catch(e=>message(e.message,true));
 invalidate();
})();
