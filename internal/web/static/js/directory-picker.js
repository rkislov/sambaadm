/* Graphical, accessible domain/OU selection for GPO links. */
(function(){
 'use strict';
 window.sambaadmDirectoryPicker=function({input,tree,loadTree,allowContainers=false}){
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
  const root=el('section','directory-picker'),tools=el('div','workspace-tools'),search=el('input'),refresh=el('button','',t('Обновить дерево','Refresh tree')),notice=el('p','workspace-message'),list=el('div','directory-picker-tree'),selection=el('output','directory-picker-selection');
  search.type='search';search.placeholder=t('Найти подразделение','Find organizational unit');search.setAttribute('aria-label',search.placeholder);refresh.type='button';tools.append(search,refresh);list.setAttribute('role','tree');list.setAttribute('aria-label',allowContainers?'Дерево подразделений и контейнеров':t('Дерево домена для привязки GPO','Domain tree for GPO links'));notice.setAttribute('aria-live','polite');selection.setAttribute('aria-live','polite');root.append(tools,notice,list,selection);
  input.readOnly=true;input.removeAttribute('list');input.placeholder=t('Выберите домен или OU в дереве','Select the domain or an OU in the tree');
  function render(){
   list.replaceChildren();const needle=search.value.toLocaleLowerCase();
   const matches=node=>!needle||(node.label+' '+node.dn).toLocaleLowerCase().includes(needle)||(node.children||[]).some(matches);
   function append(parent,node,depth,ancestors){
    if(!matches(node))return;
    const linkable=['domain','ou',...(allowContainers?['container']:[])].includes(node.kind),label=(node.label||node.dn).replace(/^OU=/i,''),control=el('button','directory-picker-node',label);control.type='button';control.title=node.dn;control.setAttribute('role','treeitem');control.setAttribute('aria-level',String(depth+1));control.setAttribute('aria-selected',String(input.value===node.dn));control.classList.toggle('selected',input.value===node.dn);control.dataset.dn=node.dn;
    if(!linkable){control.disabled=true;control.title=t('Этот контейнер не поддерживает привязку GPO: ','This container does not support GPO links: ')+node.dn;}
    const children=node.children||[];let branch;
    if(children.length){branch=el('details');branch.open=depth===0||!!needle;const summary=el('summary'),group=el('div');group.setAttribute('role','group');summary.append(control);branch.append(summary,group);parent.append(branch);for(const child of children)append(group,child,depth+1,[...ancestors,label]);}
    else parent.append(control);
    control.addEventListener('click',event=>{event.preventDefault();if(branch)branch.open=true;input.value=node.dn;input.dispatchEvent(new Event('change',{bubbles:true}));selection.textContent=t('Выбрано: ','Selected: ')+[...ancestors,label].join(' › ');for(const b of list.querySelectorAll('[role=treeitem]')){const selected=b===control;b.setAttribute('aria-selected',String(selected));b.classList.toggle('selected',selected);}});
    control.addEventListener('keydown',event=>{
     const visible=[...list.querySelectorAll('[role=treeitem]')].filter(e=>!e.disabled&&e.getClientRects().length),index=visible.indexOf(control);
     if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();visible[index+(event.key==='ArrowDown'?1:-1)]?.focus({preventScroll:true});}
     if(event.key==='ArrowRight'&&branch){event.preventDefault();branch.open=true;}
     if(event.key==='ArrowLeft'){event.preventDefault();if(branch?.open)branch.open=false;else control.parentElement.closest('details')?.parentElement.closest('details')?.querySelector('summary [role=treeitem]')?.focus();}
    });
   }
   if(tree)append(list,tree,0,[]);else list.append(el('p','muted',t('Дерево домена не загружено.','The domain tree is unavailable.')));
   if(!list.childElementCount)list.append(el('p','muted',t('Подразделения не найдены.','No organizational units found.')));
  }
  async function refreshTree(){refresh.disabled=true;notice.textContent=t('Чтение структуры домена…','Reading domain hierarchy…');try{tree=await loadTree();if(!root.isConnected)return;render();notice.textContent='';}catch(e){if(root.isConnected){notice.textContent=e.message;notice.setAttribute('role','alert');}}finally{refresh.disabled=false;}}
  search.addEventListener('input',render);refresh.addEventListener('click',refreshTree);render();if(!tree)queueMicrotask(refreshTree);return root;
 };
})();
