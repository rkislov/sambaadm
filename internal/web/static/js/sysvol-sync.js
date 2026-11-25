(()=>{
'use strict';
const root=document.querySelector('[data-sysvol-sync]');if(!root)return;
const base='/api/v1/gpo/sysvol-sync',csrf=document.querySelector('meta[name=csrf-token]')?.content||'';
const make=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
let metadata,job,timer,generation=0;
const states={pending:'Ожидает проверки',planning:'Предпросмотр',planned:'Предпросмотр готов',running:'Выполняется',ready:'Готово к переносу',blocked:'Проверка не пройдена',conflict:'Конфликт изменений',identical:'Совпадает',applied:'Синхронизировано',failed:'Ошибка',unknown:'Нужно проверить',interrupted:'Прервано',completed:'Завершено',partial:'Частично выполнено'};
async function api(path='',body){const r=await fetch(base+path,{method:body?'POST':'GET',credentials:'same-origin',headers:body?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw Error(d.error||'Запрос не выполнен');return d;}
function button(text,fn,primary=false){const b=make('button',text,primary?'di-primary':'');b.type='button';b.onclick=()=>Promise.resolve().then(fn).catch(error);return b;}
function error(e){const n=root.querySelector('[role=status]');if(n){n.className='di-notice di-error';n.textContent=e.message;}else root.append(make('p',e.message,'di-notice di-error'));}
function note(parent){const n=make('p',undefined,'di-notice');n.role='status';n.setAttribute('aria-live','polite');parent.append(n);return n;}
function remember(){try{sessionStorage.setItem('sambaadm-sysvol-sync',job.id);}catch{}}
function field(parent,title,input){const label=make('label',title);label.append(input);parent.append(label);return input;}
function picker(parent,title,options,selected){const box=make('fieldset'),legend=make('legend',title),list=make('div',undefined,'ss-picker');box.append(legend,list);for(const [value,title]of options){const label=make('label'),check=make('input');check.type='checkbox';check.value=value;check.checked=selected.has(value);label.append(check,document.createTextNode(title));list.append(label);}parent.append(box);return list;}
function setup(input){
 clearTimeout(timer);generation++;job=null;try{sessionStorage.removeItem('sambaadm-sysvol-sync');}catch{}
 root.replaceChildren();const card=make('section',undefined,'di-card');root.append(card);card.append(make('h2','Источник и получатели'));
 const status=note(card),form=make('form'),grid=make('div',undefined,'di-grid'),source=make('select');source.required=true;
 const empty=make('option','Выберите исходный DC');empty.value='';source.append(empty);
 for(const dc of metadata.controllers.filter(d=>!d.rodc)){const o=make('option',dc.dns+' · '+dc.site);o.value=dc.dns;source.append(o);}
 source.value=input?.source||'';field(grid,'Источник SYSVOL (Windows / Samba)',source);
 const info=make('details');info.append(make('summary','Как выполняется синхронизация'),make('p','Читаем GPO через SMB с Kerberos от служебной учётной записи панели. На источник ничего не записываем. Проверяем LDAP, GPT.INI, SHA-256 файлов, владельцев, группы и DACL. Каталоги GPO переключаются с сохранением исходной копии. SACL, дополнительные потоки, отдельный NETLOGON и центральное хранилище ADMX не входят в этот перенос. Это управляемая доставка, а не DFSR.'));
 grid.append(info);form.append(grid);
 const choices=make('div',undefined,'di-grid ss-options');
 const targets=picker(choices,'Контроллеры-получатели',metadata.targets.map(n=>[n,n]),new Set(input?.targets||[]));
 const policies=picker(choices,'Политики GPO',metadata.policies.map(p=>[p.guid,p.displayName]),new Set(input?.policies||metadata.policies.map(p=>p.guid)));
 form.append(choices);
 source.onchange=()=>{for(const check of targets.querySelectorAll('input')){check.disabled=check.value===source.value;if(check.disabled)check.checked=false;}};source.onchange();
 form.append(make('p','Перед переносом остановите параллельное редактирование и внешнюю синхронизацию выбранных GPO. Если LDAP ещё не реплицирован, получатель будет заблокирован.','di-muted'));
 const actions=make('div',undefined,'di-actions'),go=make('button','Подготовить предпросмотр','di-primary');go.type='submit';actions.append(go);form.append(actions);card.append(form);
 form.onsubmit=async event=>{event.preventDefault();if(!form.reportValidity())return;go.disabled=true;status.textContent='Подготовка задания…';try{job=await api('/plan',{source:source.value,targets:[...targets.querySelectorAll('input:checked')].map(e=>e.value),policies:[...policies.querySelectorAll('input:checked')].map(e=>e.value)});remember();show();}catch(e){error(e);}finally{go.disabled=false;}};
 const history=make('details');history.append(make('summary','Последние задания'));const list=make('div',undefined,'ss-history');
 for(const old of metadata.history||[])list.append(button(new Date(old.created).toLocaleString('ru-RU')+' · '+old.input.source+' · '+(states[old.state]||old.state),()=>{job=old;remember();show();}));
 if(!list.children.length)list.append(make('p','Заданий пока нет','di-muted'));history.append(list);card.append(history);
}
function show(){
 const current=++generation;clearTimeout(timer);root.replaceChildren();
 const card=make('section',undefined,'di-card'),status=note(card),body=make('div'),actions=make('div',undefined,'ss-controls');root.append(card);card.prepend(make('h2','Отчёт синхронизации'));card.append(body,actions);
 async function poll(){try{
  job=await api('/jobs/'+encodeURIComponent(job.id));if(current!==generation)return;
  status.className=['partial','interrupted'].includes(job.state)?'di-notice ss-warning':'di-notice';status.textContent=(states[job.state]||job.state)+' · Источник: '+job.input.source+(job.error?' · '+job.error:'');body.replaceChildren();actions.replaceChildren();
  const table=make('table'),head=make('tr');for(const title of ['Политика','Получатель','Версии: получатель → источник','Результат'])head.append(make('th',title));const thead=make('thead');thead.append(head);table.append(thead);const tbody=make('tbody');
  for(const item of job.items){
   const tr=make('tr'),name=make('td',item.name),target=make('td',item.target),version=make('td',item.versionKnown?'ПК: '+(item.targetVersionKnown?String(item.targetVersion&65535):'нет копии')+' → '+String(item.version&65535)+'; пользователь: '+(item.targetVersionKnown?String(item.targetVersion>>>16):'нет копии')+' → '+String(item.version>>>16):'—'),result=make('td');
   const badge=make('strong',states[item.state]||item.state,'ss-state');badge.dataset.state=item.state;result.append(badge,make('p',item.message||''));
   if(item.changes||item.aclChanges){const d=make('details',undefined,'ss-item-details');d.append(make('summary','Изменений: '+item.changes+'; права: '+item.aclChanges));for(const p of item.paths||[])d.append(make('p',p));if(item.aclPaths?.length)d.append(make('p','Владельцы, группы, DACL: '+item.aclPaths.join(', ')));if(item.changes>(item.paths||[]).length||item.aclChanges>(item.aclPaths||[]).length)d.append(make('p','Показаны первые 50 путей; проверяется и переносится всё выбранное дерево.','di-muted'));result.append(d);}
   if(item.record){const receipt=make('details',undefined,'ss-item-details');receipt.open=['failed','unknown','conflict'].includes(item.state);receipt.append(make('summary','Запись восстановления'),make('p',item.record,'di-muted'));result.append(receipt);}tr.append(name,target,version,result);tbody.append(tr);
  }
  table.append(tbody);const wrap=make('div',undefined,'ss-table');wrap.append(table);body.append(wrap);
  if(['planning','running'].includes(job.state)){timer=setTimeout(poll,2000);return;}
  if(job.state==='planned'&&job.items.some(i=>['ready','identical'].includes(i.state))){
   const form=make('form'),label=make('label',undefined,'di-check'),check=make('input');check.type='checkbox';check.required=true;
   label.append(check,document.createTextNode('Подтверждаю источник, получателей, изменения файлов и прав. Окно обслуживания согласовано.'));
   const apply=make('button','Синхронизировать готовые пары GPO/DC','di-primary');apply.type='submit';form.append(label,apply);body.append(form);
   form.onsubmit=async e=>{e.preventDefault();if(!form.reportValidity())return;apply.disabled=true;try{await api('/jobs/'+encodeURIComponent(job.id)+'/apply',{revision:job.revision,confirm:true});show();}catch(e){error(e);}};
  }
  metadata.history=[job,...(metadata.history||[]).filter(j=>j.id!==job.id)].slice(0,30);
  actions.append(button('Перечитать журнал',poll),button('Новый предпросмотр',()=>setup(job.input)),button('Скачать отчёт',()=>{
   const u=URL.createObjectURL(new Blob([JSON.stringify(job,null,2)],{type:'application/json'}));const a=make('a');a.href=u;a.download='SYSVOL-'+job.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
  }));
  const link=make('a','Открыть политики','di-button');link.href='/gpo';actions.append(link);
  if(job.items.some(i=>['failed','unknown','conflict','blocked'].includes(i.state)))body.append(make('p','Неудачные пары не мешают остальным. Для повтора подготовьте новый предпросмотр: совпадающие копии не записываются повторно. Незавершённые операции разбирайте через «Свойства политики → Исправление SYSVOL». Изменённый после прошлой доставки получатель автоматически не перезаписывается.','di-notice'));
 }catch(e){if(current===generation){error(e);actions.replaceChildren(button('Перечитать журнал',poll));}}}
 poll();
}
(async()=>{root.append(make('p','Чтение контроллеров и политик…'));metadata=await api();let saved;try{saved=sessionStorage.getItem('sambaadm-sysvol-sync');}catch{}if(saved){job={id:saved};show();}else setup();})().catch(error);
window.addEventListener('pagehide',()=>{generation++;clearTimeout(timer);});
})();
