/* Move existing controls, preserving their handlers and form ownership. */
(function(){
 'use strict';
 const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
 const selector='[data-compact-actions],td.actions,.dns-console-tools';
 function compact(bar){
  const keep=Number(bar.dataset.compactActions||1),existing=bar.querySelector(':scope > .compact-action-menu');
  const controls=[...bar.children].filter(n=>n.matches('button,a.btn,form')&&!n.matches('[hidden]'));
  if(!existing&&controls.length<=keep)return;
  let menu=existing,list;
  if(!menu){menu=document.createElement('details');menu.className='compact-action-menu';const summary=document.createElement('summary');summary.textContent=t('Действия','Actions');summary.setAttribute('aria-label',t('Дополнительные действия','More actions'));list=document.createElement('div');list.className='compact-action-list';menu.append(summary,list);bar.append(menu);
  }else list=menu.querySelector('.compact-action-list');
  for(const control of controls.slice(keep))list.append(control);
 }
 let queued=false;
 function schedule(){if(queued)return;queued=true;queueMicrotask(()=>{queued=false;document.querySelectorAll(selector).forEach(compact);});}
 new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true});
 document.addEventListener('click',event=>document.querySelectorAll('.compact-action-menu[open]').forEach(menu=>{if(!menu.contains(event.target))menu.open=false;else if(event.target.closest('.compact-action-list button,.compact-action-list a')){menu.open=false;if(!document.querySelector('dialog[open]'))menu.querySelector('summary').focus();}}));
 document.addEventListener('toggle',event=>{const menu=event.target;if(menu.matches('.compact-action-menu[open]'))document.querySelectorAll('.compact-action-menu[open]').forEach(other=>{if(other!==menu)other.open=false;});},true);
 document.addEventListener('keydown',event=>{if(event.key!=='Escape')return;const menu=event.target.closest('.compact-action-menu[open]');if(menu){event.preventDefault();event.stopPropagation();menu.open=false;menu.querySelector('summary').focus();}},true);
 schedule();
})();
