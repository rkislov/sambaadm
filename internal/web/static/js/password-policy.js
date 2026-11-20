(function(){
 'use strict';
 window.sambaadmPasswordPolicy=async function({container,admin,load,save,current}){
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
  let model,busy=false;const notice=el('p','workspace-message'),body=el('div');notice.setAttribute('aria-live','polite');container.append(notice,body);
  const status=(text,error=false)=>{notice.textContent=text;notice.setAttribute('role',error?'alert':'status');notice.classList.toggle('error',error);};
  const definitions=[
   ['minLength',t('Минимальная длина пароля','Minimum password length'),0,255,1],
   ['historyLength',t('Количество паролей в истории','Password history length'),0,1024,1],
   ['minAgeDays',t('Минимальный срок действия дней','Minimum password age in days'),0,998,'any'],
   ['maxAgeDays',t('Максимальный срок действия дней 0 без срока','Maximum password age in days 0 never expires'),0,999,'any'],
   ['lockoutThreshold',t('Порог блокировки попыток 0 без блокировки','Lockout threshold attempts 0 disabled'),0,999,1],
   ['lockoutDurationMinutes',t('Длительность блокировки минут 0 до разблокировки','Lockout duration minutes 0 until administrator unlock'),0,99999,'any'],
   ['lockoutWindowMinutes',t('Сброс счётчика ошибок через минут','Reset failed attempt counter after minutes'),0,99999,'any']
  ];
  function render(){
   body.replaceChildren();body.append(el('p','mono',model.dn),el('p','alert',t('Это общая политика паролей доменных учётных записей. Парольные настройки рабочей станции в GPO её не заменяют. Для отдельных пользователей или групп могут действовать детальные политики PSO.','This is the default password policy for domain accounts. Workstation GPO password settings do not replace it. Fine-grained PSO policies may override it for users or groups.')));
   const form=el('form','workspace-form password-policy-form'),inputs=new Map();body.append(form);
   for(const [key,label,min,max,step]of definitions){const l=el('label','',label),i=el('input');i.type='number';i.min=min;i.max=max;i.step=step;i.required=true;i.value=model[key];i.disabled=!admin;i.setAttribute('aria-label',label);l.append(i);form.append(l);inputs.set(key,i);}
   const l=el('label','',t('Требовать сложность паролей','Require password complexity')),complexity=el('input');complexity.type='checkbox';complexity.checked=model.complexity;complexity.disabled=!admin;l.prepend(complexity);form.append(l);
   form.append(el('p','muted',model.reversibleEncryption?t('В домене включено обратимое хранение паролей. Этот флаг показывается для проверки и сохраняется без изменения.','Reversible password storage is enabled in the domain. This flag is displayed for review and is preserved unchanged.'):t('Обратимое хранение паролей отключено.','Reversible password storage is disabled.')));
   const preview=el('section','password-policy-preview');preview.setAttribute('aria-label',t('Изменения парольной политики','Password policy changes'));form.append(preview);
   const value=()=>Object.fromEntries([...inputs].map(([key,input])=>[key,Number(input.value)]).concat([['complexity',complexity.checked]]));
   let confirm,submit;
   function update(){if(confirm)confirm.checked=false;const next=value(),changes=[];for(const [key,label]of definitions)if(next[key]!==model[key])changes.push(label+': '+model[key]+' → '+next[key]);if(next.complexity!==model.complexity)changes.push(t('Сложность: ','Complexity: ')+(model.complexity?t('включена','on'):t('отключена','off'))+' → '+(next.complexity?t('включена','on'):t('отключена','off')));preview.replaceChildren();if(changes.length){preview.append(el('h4','',t('Будут изменены параметры','Parameters to change')));for(const text of changes)preview.append(el('p','',text));}else preview.append(el('p','muted',t('Изменений нет.','No changes.')));if(submit)submit.disabled=!changes.length;}
   for(const input of [...inputs.values(),complexity])input.addEventListener('input',update);
   const controls=el('div','workspace-tools');
   if(admin){const l=el('label','workspace-confirm',t('Подтверждаю изменение парольной политики всего домена','I confirm changing the default password policy for the entire domain'));confirm=el('input');confirm.type='checkbox';confirm.required=true;l.prepend(confirm);form.append(l);submit=el('button','',t('Сохранить парольную политику','Save password policy'));submit.type='submit';controls.append(submit);}
   const reset=el('button','',t('Отменить изменения','Discard changes'));reset.type='button';reset.addEventListener('click',()=>{render();status('');});const refresh=el('button','',t('Перечитать политику','Reload policy'));refresh.type='button';refresh.addEventListener('click',refreshPolicy);controls.append(reset,refresh);form.append(controls);update();
   form.addEventListener('submit',async event=>{event.preventDefault();if(!admin||busy||!form.reportValidity())return;busy=true;body.querySelectorAll('button,input').forEach(x=>x.disabled=true);status(t('Сохранение…','Saving…'));try{const result=await save({revision:model.revision,policy:value()});if(!current())return;model=result;render();status(t('Парольная политика сохранена. Изменения требований проверяйте при смене пароля тестовой учётной записи.','Password policy saved. Verify the requirements by changing a test account password.'));}catch(e){if(current()){body.querySelectorAll('button,input').forEach(x=>x.disabled=false);status(e.message,true);}}finally{busy=false;}});
  }
  async function refreshPolicy(){if(busy)return;busy=true;status(t('Чтение парольной политики…','Reading password policy…'));body.replaceChildren();try{model=await load();if(!current())return;render();status('');}catch(e){if(current()){status(e.message,true);const b=el('button','',t('Повторить','Retry'));b.type='button';b.addEventListener('click',refreshPolicy);body.append(b);}}finally{busy=false;}}
  await refreshPolicy();
 };
})();
