/* RSAT-style catalogue view. Directory and template text always uses textContent. */
(function(){
  'use strict';
  window.sambaadmPolicyPath=s=>s.categoryPath?.length?s.categoryPath:[{id:JSON.stringify([s.template||'ALT',s.category||'']),label:s.category|| (document.documentElement.lang==='ru'?'Общие':'General')}];
  window.sambaadmPolicyConsole=function(options){
    const {settings,matches,scope,state,onScope,onCategory,onOpen,editing}=options;
    const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
    const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
    const button=(label,fn,cls='')=>{const b=el('button',cls,label);b.type='button';b.addEventListener('click',fn);return b;};
    const isALT=s=>(s.template||'').toLowerCase().startsWith('basealt')||(s.key||'').toLowerCase().startsWith('software\\basealt\\');
    const badge=()=>{const b=el('span','policy-platform-badge','ALT');b.title=t('Шаблон ALT','ALT template');return b;};
    const collator=new Intl.Collator(ru?'ru':'en',{numeric:true});
    const stateLabel=s=>({'enabled':t('Включено','Enabled'),'disabled':t('Отключено','Disabled'),'not-configured':t('Не настроено','Not configured'),'unsupported':t('Только просмотр','Read only')}[s]||s);
    function categoryTree(items){
      const nodes=new Map(),roots=new Map();
      for(const setting of items){let siblings=roots;for(const category of window.sambaadmPolicyPath(setting)){
        if(!nodes.has(category.id))nodes.set(category.id,{...category,children:new Map(),count:0});
        const node=nodes.get(category.id);node.count++;siblings.set(node.id,node);siblings=node.children;
      }}
      return {nodes,roots};
    }
    const {nodes}=categoryTree(settings);
    const selectedCategory=nodes.get(options.category);
    const selectedPath=selectedCategory?window.sambaadmPolicyPath(settings.find(s=>window.sambaadmPolicyPath(s).some(c=>c.id===options.category))):[];
    const categoryPath=selectedPath.slice(0,selectedPath.findIndex(c=>c.id===options.category)+1);
    const layout=el('div','policy-console'),nav=el('nav','policy-console-tree'),main=el('section','policy-console-main');
    nav.dataset.scope=scope;nav.setAttribute('aria-label',t('Дерево разделов политики','Policy configuration tree'));layout.append(nav,main);
    for(const [id,label] of [['Machine',t('Конфигурация компьютера','Computer Configuration')],['User',t('Конфигурация пользователя','User Configuration')]]){
      const branch=el('details','policy-console-scope');branch.dataset.scope=id;branch.open=state.disclosures?.get(id)??true;branch.addEventListener('toggle',()=>{if(branch.isConnected)(state.disclosures??=new Map()).set(id,branch.open);});
      const summary=el('summary');const scopeButton=button(label,()=>onScope(id),id===scope?'selected':'');scopeButton.dataset.scopeSelect=id;summary.append(scopeButton);branch.append(summary);nav.append(branch);
      const branchSettings=options.models[id].settings,{roots}=categoryTree(branchSettings);
      const policies=el('details');policies.open=state.disclosures?.get(id+'/policies')??true;policies.addEventListener('toggle',()=>{if(policies.isConnected)(state.disclosures??=new Map()).set(id+'/policies',policies.open);});policies.append(el('summary','',t('Политики','Policies')));branch.append(policies);
      const templates=el('details');templates.open=state.disclosures?.get(id+'/templates')??true;templates.addEventListener('toggle',()=>{if(templates.isConnected)(state.disclosures??=new Map()).set(id+'/templates',templates.open);});templates.append(el('summary','',t('Административные шаблоны','Administrative Templates')));policies.append(templates);
      const all=button(t('Все параметры','All Settings')+' ('+branchSettings.length+')',()=>onCategory('',id),'policy-folder'+(id===scope&&!options.category?' selected':''));all.dataset.category='';all.dataset.scope=id;all.setAttribute('aria-current',String(id===scope&&!options.category));templates.append(all);
      function appendFolders(parent,children){
        for(const node of [...children.values()].sort((a,b)=>collator.compare(a.label,b.label))){
          const selected=id===scope&&node.id===options.category;
          const item=button(node.label+' ('+node.count+')',()=>onCategory(node.id,id),'policy-folder'+(selected?' selected':''));
          item.dataset.category=node.id;item.dataset.scope=id;item.title=node.label;item.setAttribute('aria-current',String(selected));
          if(!node.children.size){parent.append(item);continue;}
          const folder=el('details'),summary=el('summary');folder.dataset.folder=node.id;
          const folderKey=id+'/'+node.id;folder.open=state.expanded.has(folderKey)||(id===scope&&categoryPath.some(c=>c.id===node.id));
          summary.append(item);folder.append(summary);parent.append(folder);
          folder.addEventListener('toggle',()=>{if(folder.isConnected)folder.open?state.expanded.add(folderKey):state.expanded.delete(folderKey);});
          appendFolders(folder,node.children);
        }
      }
      appendFolders(templates,roots);
      const preferences=el('details');preferences.open=true;preferences.append(el('summary','',t('Настройки','Preferences')));
      const system=el('details');system.open=true;system.append(el('summary','',t('Настройки системы','System settings')));
      const drives=button(t('Сетевые диски','Drive Maps'),()=>options.onDrives(id),'policy-folder'+(options.mode==='drives'&&id===scope?' selected':''));drives.dataset.drives=id;drives.setAttribute('aria-current',String(options.mode==='drives'&&id===scope));system.append(drives);preferences.append(system);branch.append(preferences);
    }
    const editor=el('section','policy-properties');
    if(editing||options.mode==='drives'){main.append(editor);return {layout,editor};}
    const heading=el('h3','policy-console-heading',selectedCategory?categoryPath.map(c=>c.label).join(' \u203a '):t('Все параметры','All Settings'));main.append(heading);
    if(selectedCategory?.children.size){
      const folders=el('div','policy-subfolders');folders.setAttribute('aria-label',t('Вложенные разделы','Subfolders'));
      for(const node of [...selectedCategory.children.values()].sort((a,b)=>collator.compare(a.label,b.label)))folders.append(button(node.label,()=>onCategory(node.id),'policy-folder'));
      main.append(folders);
    }
    const tools=el('div','policy-list-tools'),filter=el('select');filter.setAttribute('aria-label',t('Состояние параметра','Setting state'));
    for(const [value,label] of [['',t('Все состояния','All states')],['not-configured',stateLabel('not-configured')],['enabled',stateLabel('enabled')],['disabled',stateLabel('disabled')],['unsupported',stateLabel('unsupported')]]){const o=el('option','',label);o.value=value;filter.append(o);}filter.value=state.status;
    const count=el('output');count.setAttribute('aria-live','polite');tools.append(filter,count);main.append(tools);
    const wrap=el('div','policy-settings-scroll'),table=el('table','policy-settings-table'),thead=el('thead'),head=el('tr'),body=el('tbody');
    const columns=[['label',t('Параметр','Setting')],['state',t('Состояние','State')],['template',t('Шаблон','Template')],['category',t('Путь','Path')]];
    for(const [key,label] of columns){const th=el('th');th.scope='col';const sort=button(label,()=>{state.direction=state.sort===key?-state.direction:1;state.sort=key;state.page=0;renderList();});sort.setAttribute('aria-label',label);th.dataset.sort=key;th.append(sort);head.append(th);}
    thead.append(head);table.append(thead,body);wrap.append(table);main.append(wrap);
    const pages=el('div','policy-list-pager'),previous=button(t('Назад','Previous'),()=>{state.page--;renderList();}),next=button(t('Далее','Next'),()=>{state.page++;renderList();}),pageInfo=el('span');pages.append(previous,pageInfo,next);main.append(pages);
    const preview=el('section','policy-list-preview');preview.setAttribute('aria-label',t('Описание параметра','Setting description'));main.append(preview);
    function describe(setting){
      state.selected=setting?.id||'';for(const row of body.children)row.classList.toggle('selected',row.dataset.policy===state.selected);
      preview.replaceChildren();if(!setting){preview.append(el('p','muted',t('Выберите параметр для просмотра описания. Дважды нажмите строку или откройте название для настройки.','Select a setting to read its description. Double-click a row or open its name to configure it.')));return;}
      preview.append(el('h4','',setting.label||setting.id));if(isALT(setting))preview.append(badge());preview.append(el('p','policy-state',stateLabel(setting.state)));
      if(setting.description)preview.append(el('p','policy-help-text',setting.description));
      if(setting.supportedOn)preview.append(el('p','muted',t('Поддерживается: ','Supported on: ')+setting.supportedOn));
      if(setting.unsupported)preview.append(el('p','alert error',setting.unsupported));
      preview.append(button(t('Открыть параметр','Open setting'),()=>onOpen(setting.id)));
    }
    function renderList(){
      const items=matches.filter(s=>!state.status||(s.unsupported?'unsupported':s.state)===state.status).sort((a,b)=>{
        const value=s=>state.sort==='state'?stateLabel(s.unsupported?'unsupported':s.state):state.sort==='category'?window.sambaadmPolicyPath(s).map(c=>c.label).join(' / '):(s[state.sort]||s.id);
        return state.direction*(collator.compare(String(value(a)),String(value(b)))||a.id.localeCompare(b.id));
      });
      const pageSize=100,totalPages=Math.max(1,Math.ceil(items.length/pageSize));state.page=Math.min(Math.max(0,state.page),totalPages-1);
      const start=state.page*pageSize;body.replaceChildren();count.textContent=t('Найдено: ','Found: ')+items.length+' / '+settings.length;
      for(const th of head.children)th.setAttribute('aria-sort',th.dataset.sort===state.sort?(state.direction===1?'ascending':'descending'):'none');
      for(const setting of items.slice(start,start+pageSize)){
        const row=el('tr');row.dataset.policy=setting.id;row.tabIndex=0;row.addEventListener('keydown',e=>{if(e.target!==row)return;if(e.key==='Enter'){e.preventDefault();onOpen(setting.id);}else if(e.key===' '){e.preventDefault();describe(setting);}});row.addEventListener('focus',()=>describe(setting));const name=el('td'),link=button(setting.label||setting.id,()=>onOpen(setting.id),'policy-setting-link');link.title=setting.id;name.append(link);if(isALT(setting))name.append(badge());row.append(name);
        row.append(el('td','policy-state state-'+(setting.unsupported?'unsupported':setting.state),stateLabel(setting.unsupported?'unsupported':setting.state)),el('td','',setting.template||'ALT'),el('td','',window.sambaadmPolicyPath(setting).map(c=>c.label).join(' \u203a ')));
        row.addEventListener('click',e=>{if(!e.target.closest('button'))describe(setting);});row.addEventListener('dblclick',e=>{if(!e.target.closest('button'))onOpen(setting.id);});body.append(row);
      }
      if(!items.length){const row=el('tr'),cell=el('td','muted',t('Параметры не найдены','No settings found'));cell.colSpan=4;row.append(cell);body.append(row);}
      previous.disabled=state.page===0;next.disabled=state.page===totalPages-1;
      pageInfo.textContent=(items.length?start+1:0)+'–'+Math.min(start+pageSize,items.length)+' / '+items.length;
      describe(items.find(s=>s.id===state.selected)||null);
    }
    filter.addEventListener('change',()=>{state.status=filter.value;state.page=0;renderList();});renderList();return {layout,editor};
  };
})();
