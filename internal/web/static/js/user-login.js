/* Read-only account checks never attempt authentication with a user's password. */
'use strict';
window.sambaadmUserLogin=function({container,request,path,canUnlock,current,onChanged}){
 let serial=0,working=false;
 const el=(tag,text='',cls='')=>{const e=document.createElement(tag);e.textContent=text;e.className=cls;return e;};
 const notice=el('p','','workspace-message'),toolbar=el('div','','workspace-tools'),refresh=el('button','Обновить диагностику'),body=el('div');notice.setAttribute('role','status');refresh.type='button';toolbar.append(refresh);container.append(toolbar,notice,body);
 function alive(id){return current()&&id===serial&&container.isConnected;}
 function render(model){
  body.replaceChildren();body.append(el('p',model.login+' · DC: '+model.controller),el('p','Проверено: '+window.sambaadmFormatTime(model.observedAt),'muted'));
  for(const check of model.checks||[]){const row=el('section','','login-check login-check-'+check.state);row.append(el('h4',check.title),el('p',check.detail));body.append(row);}
  if(model.resultantPSO){const policy=el('section','','login-check');policy.append(el('h4','Результирующая парольная политика (PSO)'),el('p',model.resultantPSO,'mono'));body.append(policy);}
  if(canUnlock&&model.canUnlock){
   const form=el('form','','workspace-form'),label=el('label','Подтверждаю снятие блокировки пользователя '+model.login),confirm=el('input'),unlock=el('button','Разблокировать пользователя');confirm.type='checkbox';confirm.required=true;label.prepend(confirm);unlock.type='submit';form.append(label,unlock);body.append(form);
   form.addEventListener('submit',async event=>{event.preventDefault();if(working||!form.reportValidity())return;working=true;unlock.disabled=true;refresh.disabled=true;notice.textContent='Снимаем блокировку и проверяем результат…';const id=++serial;
    try{const result=await request(path+'/unlock','POST',{revision:model.revision,confirm:true});if(!alive(id))return;render(result);notice.textContent='Блокировка снята, результат подтверждён контроллером. Остальные ограничения показаны ниже.';await onChanged?.();}
    catch(error){if(!alive(id))return;notice.textContent=error.message;notice.className='workspace-message error';form.remove();body.prepend(el('p','Обновите диагностику перед повторной операцией.','error'));}
    finally{working=false;if(alive(id))refresh.disabled=false;}
   });
  }
  const limits=el('details');limits.append(el('summary','Что проверяет диагностика'));for(const note of model.limitations||[])limits.append(el('p',note,'muted'));body.append(limits);
 }
 async function load(){if(working)return;const id=++serial;refresh.disabled=true;notice.className='workspace-message';notice.textContent='Читаем состояние учётной записи…';body.replaceChildren();try{const model=await request(path+'/login-status');if(alive(id)){render(model);notice.textContent='Диагностика обновлена. Пароль пользователя не проверялся.';}}catch(error){if(alive(id)){notice.textContent=error.message;notice.className='workspace-message error';}}finally{if(alive(id))refresh.disabled=false;}}
 refresh.addEventListener('click',load);load();
};
