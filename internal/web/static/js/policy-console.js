/* RSAT-style catalogue view. Directory and template text always uses textContent. */
(function(){
  'use strict';
  window.sambaadmPolicyConsole=function(options){
    const {settings,matches,scope,state,onScope,onCategory,onOpen,editing}=options;
    const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
    const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
    const button=(label,fn,cls='')=>{const b=el('button',cls,label);b.type='button';b.addEventListener('click',fn);return b;};
    const stateLabel=s=>({'enabled':t('Включено','Enabled'),'disabled':t('Отключено','Disabled'),'not-configured':t('Не настроено','Not configured'),'unsupported':t('Только просмотр','Read only')}[s]||s);
    const layout=el('div','policy-console'),nav=el('nav','policy-console-tree'),main=el('section','policy-console-main');
    nav.setAttribute('aria-label',t('Дерево разделов политики','Policy configuration tree'));layout.append(nav,main);
    for(const [id,label] of [['Machine',t('Конфигурация компьютера','Computer Configuration')],['User',t('Конфигурация пользователя','User Configuration')]]){
      const branch=el('details','policy-console-scope');branch.open=id===scope;
      const summary=el('summary');summary.append(button(label,()=>{if(id!==scope)onScope(id);},id===scope?'selected':''));branch.append(summary);nav.append(branch);
      if(id!==scope){branch.append(button(t('Открыть раздел','Open configuration'),()=>onScope(id)));continue;}
      const policies=el('details');policies.open=true;policies.append(el('summary','',t('Политики','Policies')));branch.append(policies);
      const templates=el('details');templates.open=true;templates.append(el('summary','',t('Административные шаблоны','Administrative Templates')));policies.append(templates);
      const all=button(t('Все параметры','All Settings')+' ('+settings.length+')',()=>onCategory(''),'policy-folder'+(!options.category?' selected':''));all.setAttribute('aria-current',String(!options.category));templates.append(all);
      const groups=new Map();
      for(const s of settings){const template=s.template||'ALT',category=s.category||'';if(!groups.has(template))groups.set(template,new Map());const categories=groups.get(template);categories.set(category,(categories.get(category)||0)+1);}
      for(const [template,categories] of [...groups].sort((a,b)=>a[0].localeCompare(b[0]))){
        const folder=el('details');folder.open=state.expanded.has(template)||[...categories.keys()].some(k=>k&&k===options.category);
        folder.append(el('summary','',template));folder.addEventListener('toggle',()=>folder.open?state.expanded.add(template):state.expanded.delete(template));templates.append(folder);
        for(const [category,count] of [...categories].sort((a,b)=>a[0].localeCompare(b[0]))){
          // Category identifiers may be namespaced ADMX references. Keep them intact.
          const name=category||t('Общие','General'),value=category||template;
          const item=button(name+' ('+count+')',()=>onCategory(value),'policy-folder'+(value===options.category?' selected':''));item.title=template+' / '+name;item.setAttribute('aria-current',String(value===options.category));folder.append(item);
        }
      }
    }
    const editor=el('section','policy-properties');
    if(editing){main.append(editor);return {layout,editor};}
    const heading=el('h3','policy-console-heading',options.category||t('Все параметры','All Settings'));main.append(heading);
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
      preview.append(el('h4','',setting.label||setting.id),el('p','policy-state',stateLabel(setting.state)));
      if(setting.description)preview.append(el('p','policy-help-text',setting.description));
      if(setting.supportedOn)preview.append(el('p','muted',t('Поддерживается: ','Supported on: ')+setting.supportedOn));
      if(setting.unsupported)preview.append(el('p','alert error',setting.unsupported));
      preview.append(button(t('Открыть параметр','Open setting'),()=>onOpen(setting.id)));
    }
    function renderList(){
      const items=matches.filter(s=>!state.status||(s.unsupported?'unsupported':s.state)===state.status).sort((a,b)=>{
        const value=s=>state.sort==='state'?stateLabel(s.unsupported?'unsupported':s.state):(s[state.sort]||s.id);
        return state.direction*(String(value(a)).localeCompare(String(value(b)),ru?'ru':'en',{numeric:true})||a.id.localeCompare(b.id));
      });
      const pageSize=100,totalPages=Math.max(1,Math.ceil(items.length/pageSize));state.page=Math.min(Math.max(0,state.page),totalPages-1);
      const start=state.page*pageSize;body.replaceChildren();count.textContent=t('Найдено: ','Found: ')+items.length+' / '+settings.length;
      for(const th of head.children)th.setAttribute('aria-sort',th.dataset.sort===state.sort?(state.direction===1?'ascending':'descending'):'none');
      for(const setting of items.slice(start,start+pageSize)){
        const row=el('tr');row.dataset.policy=setting.id;const name=el('td'),link=button(setting.label||setting.id,()=>onOpen(setting.id),'policy-setting-link');link.title=setting.id;name.append(link);row.append(name);
        row.append(el('td','policy-state state-'+(setting.unsupported?'unsupported':setting.state),stateLabel(setting.unsupported?'unsupported':setting.state)),el('td','',setting.template||'ALT'),el('td','',setting.category||t('Общие','General')));
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
