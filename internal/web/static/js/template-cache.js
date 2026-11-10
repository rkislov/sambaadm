(function(){'use strict';
 const root=document.getElementById('gpo-template-cache');if(!root)return;
 const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
 const button=document.createElement('button');button.type='button';button.textContent=t('Импортировать / обновить шаблоны','Import / refresh templates');
 const notice=document.createElement('p');notice.className='workspace-message';notice.setAttribute('aria-live','polite');root.append(button,notice);
 button.addEventListener('click',async()=>{
  button.disabled=true;notice.textContent=t('Импорт шаблонов…','Importing templates…');const started=Date.now(),controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),125000),progress=setInterval(()=>notice.textContent=t('Первичный импорт шаблонов: ','Initial template import: ')+Math.floor((Date.now()-started)/1000)+t(' с. Уже сохранённый кэш остаётся доступным.',' s. Any previously saved cache remains available.'),5000);
  try{
   const response=await fetch('/api/v1/gpo/templates/import',{method:'POST',credentials:'same-origin',signal:controller.signal,headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf-token]')?.content||''}});
   const data=await response.json();if(!response.ok)throw Error(response.status===504?t('Импорт превысил две минуты. Проверьте доступ к источнику и обновите helper для пакетной загрузки.','Import exceeded two minutes. Check source access and update the helper for bulk loading.'):(data.error||'HTTP '+response.status));
   notice.textContent=t('Шаблоны сохранены локально. Определений: ','Templates saved locally. Definitions: ')+data.count+t('. Кэш действует один час; данные самих GPO продолжают читаться с контроллера.','. Cache lasts one hour; GPO data is still read from the controller.');
  }catch(e){notice.textContent=e.name==='AbortError'?t('Импорт остановлен по таймауту. Проверьте helper и повторите.','Import timed out. Check the helper and retry.'):e.message;}
  finally{clearTimeout(timeout);clearInterval(progress);button.disabled=false;}
 });
})();
