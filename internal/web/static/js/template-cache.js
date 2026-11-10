(function(){'use strict';
 const root=document.getElementById('gpo-template-cache');if(!root)return;
 const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
 const button=document.createElement('button');button.type='button';button.textContent=t('Импортировать / обновить шаблоны','Import / refresh templates');
 const notice=document.createElement('p');notice.className='workspace-message';notice.setAttribute('aria-live','polite');const problems=document.createElement('details');problems.className='template-import-issues';problems.hidden=true;root.append(button,notice,problems);
 function showIssues(issues){
  problems.replaceChildren();problems.hidden=!issues.length;if(!issues.length)return;
  problems.open=true;const summary=document.createElement('summary');summary.textContent=t('Проблемные файлы: ','Problem files: ')+issues.length;problems.append(summary);
  const hint=document.createElement('p');hint.textContent=t('Эти шаблоны пропущены. Исправьте файлы и повторите импорт.','These templates were skipped. Fix the files and repeat the import.');problems.append(hint);
  const list=document.createElement('ul');for(const issue of issues){const item=document.createElement('li'),name=document.createElement('strong'),reason=document.createElement('p');name.textContent=issue.file+(issue.template&&issue.template!==issue.file?' ('+issue.template+')':'');reason.textContent=issue.error;item.append(name,reason);list.append(item);}problems.append(list);
 }
 button.addEventListener('click',async()=>{
  button.disabled=true;notice.textContent=t('Импорт шаблонов…','Importing templates…');const started=Date.now(),controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),125000),progress=setInterval(()=>notice.textContent=t('Первичный импорт шаблонов: ','Initial template import: ')+Math.floor((Date.now()-started)/1000)+t(' с. Уже сохранённый кэш остаётся доступным.',' s. Any previously saved cache remains available.'),5000);
  try{
   const response=await fetch('/api/v1/gpo/templates/import',{method:'POST',credentials:'same-origin',signal:controller.signal,headers:{'X-CSRF-Token':document.querySelector('meta[name=csrf-token]')?.content||''}});
   const data=await response.json();showIssues(Array.isArray(data.issues)?data.issues:[]);if(!response.ok)throw Error(response.status===504?t('Импорт превысил две минуты. Проверьте доступ к источнику и обновите helper для пакетной загрузки.','Import exceeded two minutes. Check source access and update the helper for bulk loading.'):(data.error||'HTTP '+response.status));
   notice.textContent=data.saved===false?t('Нет пригодных определений. Прежний кэш не изменён.','No usable definitions. The previous cache was not changed.'):t('Шаблоны сохранены локально. Определений: ','Templates saved locally. Definitions: ')+data.count+t('. Шаблоны хранятся постоянно и обновляются только этой кнопкой; данные GPO читаются с контроллера.','. Templates are kept permanently and refreshed only with this button; GPO data is read from the controller.');
  }catch(e){notice.textContent=e.name==='AbortError'?t('Импорт остановлен по таймауту. Проверьте helper и повторите.','Import timed out. Check the helper and retry.'):e.message;}
  finally{clearTimeout(timeout);clearInterval(progress);button.disabled=false;}
 });
})();
