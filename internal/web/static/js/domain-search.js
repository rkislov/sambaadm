(function(){
  'use strict';
  const trigger=document.querySelector('[data-domain-search]');if(!trigger)return;
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const el=(tag,text='',cls='')=>{const e=document.createElement(tag);e.textContent=text;e.className=cls;return e;};
  const dialog=el('dialog','','workspace-dialog domain-search-dialog'),title=el('h2',t('Поиск в домене','Domain search')),form=el('form','', 'domain-search-form'),label=el('label',t('Имя, логин или имя компьютера','Name, login or computer name')),input=el('input'),submit=el('button',t('Найти','Search')),notice=el('p','','workspace-message'),results=el('div'),close=el('button',t('Закрыть','Close'));
  dialog.setAttribute('aria-labelledby','domain-search-title');title.id='domain-search-title';input.type='search';input.required=true;input.minLength=2;input.maxLength=128;input.placeholder=t('Начните вводить имя или логин','Enter a name or login');label.append(input);submit.type='submit';form.append(label,submit);notice.setAttribute('role','status');const header=el('div','','dialog-heading');close.className='dialog-dismiss';close.setAttribute('aria-label',t('Закрыть','Close'));header.append(title,close);dialog.append(header,form,notice,results);document.body.append(dialog);
  let controller,serial=0;
  function cancel(){serial++;controller?.abort();submit.disabled=false;dialog.close();trigger.focus();}
  trigger.addEventListener('click',()=>{dialog.showModal();input.focus();});close.addEventListener('click',cancel);dialog.addEventListener('cancel',e=>{e.preventDefault();cancel();});
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(!form.reportValidity())return;
    controller?.abort();controller=new AbortController();const id=++serial,query=input.value.trim();if(query.length<2)return;
    results.replaceChildren();notice.textContent=t('Поиск…','Searching…');submit.disabled=true;
    const specs=[['users',t('Пользователи','Users')],['groups',t('Группы','Groups')],['computers',t('Компьютеры','Computers')]];
    const found=await Promise.allSettled(specs.map(async([kind])=>{const response=await fetch('/api/v1/'+kind+'?q='+encodeURIComponent(query),{credentials:'same-origin',signal:AbortSignal.any([controller.signal,AbortSignal.timeout(15000)])});if(response.status===401)throw Error(t('Сессия истекла. Войдите заново.','Session expired. Sign in again.'));if(!response.ok)throw Error(t('Поиск недоступен','Search unavailable')+' (HTTP '+response.status+')');const data=await response.json();if(!Array.isArray(data))throw Error(t('Некорректный ответ','Invalid response'));return data;}));
    if(id!==serial)return;let count=0,failed=0;
    for(let i=0;i<specs.length;i++){
      const [kind,label]=specs[i],section=el('section','', 'domain-search-section');section.append(el('h3',label));results.append(section);
      if(found[i].status==='rejected'){failed++;section.append(el('p',found[i].reason.message,'error'));continue;}
      const rows=found[i].value;count+=rows.length;
      if(!rows.length)section.append(el('p',t('Совпадений нет','No matches'),'muted'));
      for(const row of rows.slice(0,10)){
        const link=el('a','','domain-search-result');link.href='/'+kind+'?'+new URLSearchParams({object:row.samAccountName});
        link.append(el('strong',row.displayName||row.samAccountName),el('span',row.samAccountName),el('small',row.dn));section.append(link);
      }
      if(rows.length>10){const more=el('a',t('Все результаты: ','All results: ')+rows.length);more.href='/'+kind+'?'+new URLSearchParams({q:query});section.append(more);}
    }
    notice.textContent=(count?t('Найдено: ','Found: ')+count:t('Объекты не найдены','No objects found'))+(failed?t(' · Часть разделов недоступна',' · Some sections unavailable'):'');submit.disabled=false;
  });
})();
