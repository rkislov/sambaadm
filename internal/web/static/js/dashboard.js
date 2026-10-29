/* Dashboard data comes from authenticated, read-only domain APIs. */
(function(){
  'use strict';
  const root=document.getElementById('domain-dashboard');if(!root)return;
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const node=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=text||'';if(cls)e.className=cls;return e;};
  const refresh=node('button',t('Обновить сводку','Refresh summary'));refresh.type='button';
  const notice=node('p','','workspace-message');notice.setAttribute('aria-live','polite');const cards=node('div','','dashboard-cards'),health=node('section');root.append(refresh,notice,cards,health);
  async function get(path){const response=await fetch('/api/v1'+path,{credentials:'same-origin',headers:{Accept:'application/json'},signal:AbortSignal.timeout(30000)});if(!response.ok){let data={};try{data=await response.json();}catch(_){}const hint=data.code==='upstream_access_denied'?t('Недостаточно прав у ldap.bind.user. Вход в браузере не меняет служебную учётную запись. ','ldap.bind.user lacks AD permissions. Browser login does not change the service account. '):'';throw new Error(response.status===401?t('Сессия истекла','Session expired'):hint+(data.error||'HTTP '+response.status));}return response.json();}
  async function load(){refresh.disabled=true;cards.replaceChildren();health.replaceChildren();notice.textContent=t('Загрузка…','Loading…');
    const specs=[['users',t('Пользователи','Users'),'/users'],['gpo',t('Групповые политики','Group policies'),'/gpo'],['computers',t('Компьютеры','Computers'),'/computers'],['controllers',t('Контроллеры домена','Domain controllers'),'/sites/controllers']];
    const results=await Promise.all(specs.map(async([key,label,path])=>{const card=node('a','','dashboard-card');card.href=key==='controllers'?'/repl':path;card.dataset.metric=key;const count=node('strong','…');card.append(node('span',label),count);cards.append(card);try{const data=await get(path);if(!Array.isArray(data))throw new Error(t('Неожиданный ответ','Unexpected response'));count.textContent=String(data.length);return data;}catch(e){count.textContent=t('Недоступно','Unavailable');card.append(node('small',e.message));return null;}}));
    health.append(node('h2',t('Состояние репликации','Replication status')));const summary=node('p',t('Проверка контроллеров…','Checking controllers…'));summary.dataset.replicationSummary='';health.append(summary);const list=node('ul','', 'replication-health');health.append(list);
    const controllers=results[3];if(!controllers||!controllers.length){summary.textContent=controllers?t('Нет контроллеров — состояние не подтверждено','No controllers — health unverified'):t('Список контроллеров недоступен — состояние неизвестно','Controller list unavailable — health unknown');}
    else {
      const counts={healthy:0,degraded:0,unknown:0};let next=0;
      const entries=controllers.map(dc=>{const li=node('li',dc.dns+' — '+t('Проверка…','Checking…'));list.append(li);return li;});
      async function worker(){while(next<controllers.length){const i=next++,dc=controllers[i];try{const status=await get('/repl/status?dc='+encodeURIComponent(dc.dns));const label=status.health==='healthy'?t('Успешно','Healthy'):status.health==='degraded'?t('Есть ошибки','Degraded'):status.health==='no-partners'?t('Нет партнёров — состояние не подтверждено','No partners — health unverified'):t('Неизвестно','Unknown');counts[status.health==='healthy'?'healthy':status.health==='degraded'?'degraded':'unknown']++;entries[i].textContent=dc.dns+' — '+label;}catch(e){counts.unknown++;entries[i].textContent=dc.dns+' — '+t('Недоступно: ','Unavailable: ')+e.message;}}}
      await Promise.all(Array.from({length:Math.min(3,controllers.length)},worker));
      summary.textContent=t('Успешно: ','Healthy: ')+counts.healthy+t(' · С ошибками: ',' · Degraded: ')+counts.degraded+t(' · Не подтверждено: ',' · Unverified: ')+counts.unknown;
      summary.className=counts.degraded||counts.unknown?'alert error':'';
    }
    const link=node('a',t('Открыть репликацию и топологию','Open replication and topology'));link.href='/repl';health.append(link);notice.textContent=t('Проверено: ','Checked: ')+new Date().toLocaleString(ru?'ru-RU':'en-US')+t('. Сводка по текущему домену.','. Current domain summary.');refresh.disabled=false;
  }
  refresh.addEventListener('click',load);load();
})();
