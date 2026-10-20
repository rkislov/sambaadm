/* Domain administration workspace. All directory text is inserted with textContent. */
(function () {
  'use strict';
  const root = document.getElementById('workspace');
  if (!root) return;
  const ru = document.documentElement.lang === 'ru';
  const t = (a, b) => ru ? a : b;
  const enc = encodeURIComponent;
  const admin = root.dataset.role === 'admin';
  const helpdesk = admin || root.dataset.role === 'helpdesk';
  const base = root.dataset.baseDn;
  const api = '/api/v1';
  const field = (key, label, options = {}) => ({key, label, ...options});
  const text = (key, a, b, options) => field(key, t(a, b), options);
  const name = () => text('name', 'Имя', 'Name');
  const dn = (key = 'dn') => text(key, 'Полный DN', 'Full DN', {placeholder: base, list:'directory-dns'});
  const ou = (key = 'ou') => text(key, 'Подразделение или контейнер DN', 'OU or container DN', {optional: true, list: 'directory-dns'});
  const description = () => text('description', 'Описание', 'Description', {optional: true});
  const action = (label, method, path, fields = [], options = {}) => ({label, method, path, fields, ...options});
  const view = (label, path, fields = []) => action(label, 'GET', path, fields);
  const remove = (path, fields = []) => action(t('Удалить', 'Delete'), 'DELETE', path, fields, {danger: true});
  const move = path => action(t('Переместить', 'Move'), 'POST', path, [ou('toOU')].map(f => ({...f, optional: false})));
  const password = () => text('password', 'Новый пароль', 'New password', {type: 'password'});
  const queryFields = () => [text('name', 'Имя записи', 'Record name', {value: '@'}), text('type', 'Тип записи', 'Record type', {value: 'ALL', choices: ['ALL','A','AAAA','CNAME','MX','NS','PTR','SOA','SRV','TXT']})];
  const recordFields = () => [text('name', 'Имя записи', 'Record name', {value: '@'}), text('type', 'Тип записи', 'Record type', {value: 'A', choices: ['A','AAAA','CNAME','MX','NS','PTR','SRV','TXT']}), text('data', 'Значение записи', 'Record value')];
  const gpoID = r => r.guid;
  const utcDays=['Воскресенье','Понедельник','Вторник','Среда','Четверг','Пятница','Суббота'];
  const scheduleFields=()=>utcDays.map((day,i)=>text('day'+i,day+' UTC (09:00-18:00; пусто — закрыто)',['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][i]+' UTC (09:00-18:00; empty — closed)',{optional:true,value:'00:00-24:00'}));
  const scheduleOperation=(path)=>action(t('Расписание UTC','UTC schedule'),'PUT',path,scheduleFields(),{revision:true,confirm:true,when:r=>r.scheduleSupported!==false&&r.scheduleEditable!==false,prefill:r=>Object.fromEntries((r.schedule||Array(7).fill('00:00-24:00')).map((v,i)=>['day'+i,v])),encode:body=>({revision:body.revision,schedule:utcDays.map((_,i)=>body['day'+i]||'')})});
  const linkFields=()=>[text('sites','Сайты через точку с запятой','Sites separated by semicolons',{array:true}),text('cost','Стоимость (1–32767)','Cost (1–32767)',{type:'number',numeric:true,value:100}),text('interval','Интервал, минут (15–10080, шаг 15)','Interval, minutes (15–10080, step 15)',{type:'number',numeric:true,value:180})];
  const configs = {
    '/users': {title:t('Пользователи','Users'), endpoint:'/users', directory:'users', id:r=>r.samAccountName,
      columns:[['samAccountName',t('Логин','Login')],['displayName',t('Имя','Name')],['enabled',t('Состояние','Status')],['dn','DN']],
      create:action(t('Создать пользователя','Create user'),'POST','/users',[text('login','Логин','Login'),text('displayName','Отображаемое имя','Display name',{optional:true}),password(),ou(),text('mail','Почта','Email',{type:'email',optional:true}),description(),text('enabled','Учётная запись включена','Account enabled',{type:'checkbox',value:true})]),
      actions:[{...view(t('Свойства','Properties'),r=>'/users/'+enc(r.samAccountName)),userCard:true},
        action(t('Включить','Enable'),'POST',r=>'/users/'+enc(r.samAccountName)+'/enable',[],{support:true,when:r=>!r.enabled}),
        action(t('Отключить','Disable'),'POST',r=>'/users/'+enc(r.samAccountName)+'/disable',[],{support:true,when:r=>r.enabled,confirm:true}),
        action(t('Сбросить пароль','Reset password'),'POST',r=>'/users/'+enc(r.samAccountName)+'/password',[password()],{support:true,secret:true}),
        move(r=>'/users/'+enc(r.samAccountName)+'/move'),remove(r=>'/users/'+enc(r.samAccountName))]},
    '/groups':{title:t('Группы','Groups'),endpoint:'/groups',directory:'groups',id:r=>r.samAccountName,
      columns:[['samAccountName',t('Группа','Group')],['description',t('Описание','Description')],['members',t('Участники','Members')],['dn','DN']],
      create:action(t('Создать группу','Create group'),'POST','/groups',[name(),ou(),description()]),
      actions:[view(t('Свойства','Properties'),r=>'/groups/'+enc(r.samAccountName)),view(t('Участники','Members'),r=>'/groups/'+enc(r.samAccountName)+'/members'),
        action(t('Добавить участника','Add member'),'POST',r=>'/groups/'+enc(r.samAccountName)+'/members',[dn('memberDN')]),
        action(t('Исключить участника','Remove member'),'DELETE',r=>'/groups/'+enc(r.samAccountName)+'/members',[dn('memberDN')],{confirm:true}),remove(r=>'/groups/'+enc(r.samAccountName))]},
    '/computers':{title:t('Компьютеры','Computers'),endpoint:'/computers',directory:'computers',id:r=>r.samAccountName,
      columns:[['samAccountName',t('Имя','Name')],['dnsHostName','DNS'],['operatingSystem',t('ОС','OS')],['dn','DN']],
      actions:[view(t('Свойства','Properties'),r=>'/computers/'+enc(r.samAccountName)),move(r=>'/computers/'+enc(r.samAccountName)+'/move'),remove(r=>'/computers/'+enc(r.samAccountName))]},
    '/ou':{title:t('Подразделения','Organizational units'),endpoint:'/ou',directory:'ou',id:r=>r.dn,
      columns:[['name',t('Имя','Name')],['description',t('Описание','Description')],['dn','DN']],
      create:action(t('Создать OU','Create OU'),'POST','/ou',[name(),ou('parentDN'),description()]),
      actions:[action(t('Переместить','Move'),'POST','/ou/move',[dn(),text('toParent','Новый родительский DN','New parent DN',{list:'directory-dns'})],{prefill:r=>({dn:r.dn})}),
        remove(r=>'/ou?dn='+enc(r.dn))]},
    '/dns':{title:'DNS',endpoint:'/dns/zones',id:r=>r.name,
      columns:[['name',t('Зона','Zone')],['source',t('Источник','Source')],['dn','DN']],
      hint:t('Выберите зону в дереве. Для записей укажите относительное имя узла; @ — корень зоны.','Select a zone. Record names are relative to the zone; @ is the zone apex.'),
      create:action(t('Создать зону','Create zone'),'POST','/dns/zones',[name()]),
      actions:[view(t('Записи','Records'),r=>'/dns/zones/'+enc(r.name)+'/records',queryFields()),
        action(t('Добавить запись','Add record'),'POST',r=>'/dns/zones/'+enc(r.name)+'/records',recordFields()),
        action(t('Изменить запись','Update record'),'PUT',r=>'/dns/zones/'+enc(r.name)+'/records',[...recordFields().slice(0,2),text('oldData','Прежнее значение','Previous value'),text('newData','Новое значение','New value')]),
        action(t('Удалить запись','Delete record'),'DELETE',r=>'/dns/zones/'+enc(r.name)+'/records',recordFields(),{danger:true}),remove(r=>'/dns/zones/'+enc(r.name))]},
    '/gpo':{title:t('Групповые политики','Group policies'),endpoint:'/gpo',id:gpoID,
      hint:t('Политики хранятся отдельно от ссылок на OU. Доставка SYSVOL не подтверждает применение на клиенте.','Policies and OU links are separate. SYSVOL distribution does not confirm client application.'),
      columns:[['displayName',t('Политика','Policy')],['guid','GUID'],['source',t('Источник','Source')]],
      create:action(t('Создать GPO','Create GPO'),'POST','/gpo',[name()]),
      toolbar:[view(t('Ссылки на контейнер','Container links'),'/gpo/links',[dn('container')]),action(t('Восстановить в новую GPO','Restore as new GPO'),'POST','/gpo/restore',[text('name','Имя новой политики','New policy name'),text('path','Каталог копии policy/{GUID} на сервере','Backup policy/{GUID} directory on server')],{confirm:true})],
      actions:[view(t('Свойства','Properties'),r=>'/gpo/'+enc(gpoID(r))),
 {...view(t('Параметры ALT','ALT settings'),r=>'/gpo/'+enc(gpoID(r))+'/alt-settings'),editor:true},
        action(t('Привязать к OU','Link to OU'),'POST',r=>'/gpo/'+enc(gpoID(r))+'/link',[dn('container')]),
        action(t('Отвязать от OU','Unlink from OU'),'POST',r=>'/gpo/'+enc(gpoID(r))+'/unlink',[dn('container')],{confirm:true}),
        action(t('Резервная копия','Back up'),'POST',r=>'/gpo/'+enc(gpoID(r))+'/backup',[text('path','Каталог на сервере','Directory on server')]),
        action(t('Доставить на контроллеры','Distribute to DCs'),'POST',r=>'/gpo/'+enc(gpoID(r))+'/distribute',[],{confirm:true,job:true}),remove(r=>'/gpo/'+enc(gpoID(r)))]},
    '/trusts':{title:t('Доверия','Trusts'),endpoint:'/trusts',id:r=>r.domain,
      columns:[['domain',t('Домен','Domain')],['direction',t('Направление','Direction')],['type',t('Тип','Type')]],
      create:action(t('Создать доверие','Create trust'),'POST','/trusts',[text('domain','Домен','Domain'),text('netbios','NetBIOS удалённого домена','Remote NetBIOS domain'),text('sid','SID удалённого домена','Remote domain SID'),text('direction','Направление','Direction',{choices:['both','incoming','outgoing']}),text('type','Тип','Type',{choices:['external','forest']}),password()],{confirm:true}),
      actions:[action(t('Проверить','Validate'),'POST',r=>'/trusts/'+enc(r.domain)+'/validate'),remove(r=>'/trusts/'+enc(r.domain))]},
    '/repl':{title:t('Репликация','Replication'),endpoint:'/repl/partners',id:r=>r.dn,
      columns:[['name',t('Контроллер в AD','Configured DC')],['status',t('Наличие в каталоге','Directory registration')],['dn','DN']],
      hint:t('Наличие объекта в AD не подтверждает исправность репликации. Откройте состояние выбранного контроллера.','AD registration does not imply replication health. Inspect a controller status.'),
      toolbar:[view(t('Состояние репликации','Replication status'),'/repl/status',[text('dc','Контроллер (пусто — текущий)','Controller (empty — current)',{optional:true})]),view(t('Соединения репликации','Replication connections'),'/repl/connections'),action(t('Создать соединение','Create connection'),'POST','/repl/connections',[text('source','Контроллер источник','Source DC'),text('destination','Контроллер назначения','Destination DC')],{confirm:true}),action(t('Пересчитать топологию KCC','Recalculate KCC topology'),'POST','/repl/kcc',[text('dc','Контроллер','Controller')],{confirm:true}),action(t('Синхронизировать','Synchronize'),'POST','/repl/sync',[text('from','Контроллер источник','Source DC'),text('dest','Контроллер назначения','Destination DC',{optional:true}),text('nc','Раздел каталога DN','Naming context DN',{optional:true})],{confirm:true})],actions:[]},
    '/sites':{title:t('Сайты','Sites'),endpoint:'/sites',id:r=>r.name,
      columns:[['name',t('Сайт','Site')],['dn','DN']],create:action(t('Создать сайт','Create site'),'POST','/sites',[name()]),
      toolbar:[view(t('Топология сайтов','Site topology'),'/sites/topology'),view(t('Контроллеры','Controllers'),'/sites/controllers'),view(t('Связи сайтов','Site links'),'/sites/links'),action(t('Создать связь сайтов','Create site link'),'POST','/sites/links',[name(),...linkFields()],{confirm:true}),view(t('Подсети','Subnets'),'/subnets'),action(t('Переназначить подсеть','Reassign subnet'),'PUT','/subnets/site',[text('subnet','Подсеть CIDR','Subnet CIDR'),text('site','Новый сайт','New site')],{confirm:true}),action(t('Создать подсеть','Create subnet'),'POST','/subnets',[text('subnet','Подсеть CIDR','Subnet CIDR'),text('site','Имя сайта','Site name')]),action(t('Удалить подсеть','Delete subnet'),'POST','/subnets/delete',[text('subnet','Подсеть CIDR','Subnet CIDR')],{danger:true})],actions:[remove(r=>'/sites/'+enc(r.name))]},
    '/domain':{title:t('Домен и FSMO','Domain and FSMO'),endpoint:'/domain/fsmo',id:r=>r.role,
      columns:[['role',t('Роль','Role')],['owner',t('Владелец','Owner')],['source',t('Источник','Source')]],
      toolbar:[view(t('Свойства домена','Domain properties'),'/domain'),view(t('Функциональные уровни','Functional levels'),'/domain/level'),
        action(t('Повысить уровень','Raise level'),'POST','/domain/level/raise',[text('domain','Уровень домена','Domain level',{optional:true}),text('forest','Уровень леса','Forest level',{optional:true})],{danger:true})],
      actions:[action(t('Передать роль','Transfer role'),'POST','/domain/fsmo/transfer',[text('role','Роль','Role')],{prefill:r=>({role:r.role}),confirm:true}),action(t('Захватить роль','Seize role'),'POST','/domain/fsmo/seize',[text('role','Роль','Role')],{prefill:r=>({role:r.role}),danger:true,warning:t('Применяйте только при безвозвратной потере владельца роли.','Use only when the role owner is permanently lost.')})]},
    '/shares':{title:t('Общие папки','File shares'),endpoint:'/shares',id:r=>r.name,
      columns:[['name',t('Имя','Name')],['path',t('Путь','Path')],['validUsers',t('Доступ','Access')]],
      create:{label:t('Создать папку','Create share'),href:'/shares/new',method:'POST'},
      toolbar:[action(t('Перечитать конфигурацию Samba','Reload Samba configuration'),'POST','/shares/reload',[],{confirm:true}),view(t('Права каталога','Directory permissions'),'/acl',[text('path','Путь на сервере','Path on server')]),
        action(t('Изменить права каталога','Change directory permissions'),'POST','/acl',[text('path','Путь на сервере','Path on server'),text('owner','Владелец user:group','Owner user:group',{optional:true}),text('mode','Режим например 0770','Mode e.g. 0770',{optional:true}),text('acl','POSIX ACL','POSIX ACL',{optional:true}),text('defaultAcl','ACL по умолчанию','Default ACL',{optional:true}),text('recursive','Рекурсивно','Recursive',{type:'checkbox'}),text('defaultRecursive','Рекурсивно для ACL по умолчанию','Recursive default ACL',{type:'checkbox'}),text('clearAcl','Очистить ACL','Clear ACL',{type:'checkbox'}),text('clearDefault','Очистить ACL по умолчанию','Clear default ACL',{type:'checkbox'}),text('removeAcl','Удалить запись ACL','Remove ACL entry',{optional:true}),text('copyToDefault','Скопировать ACL в наследуемый','Copy to default ACL',{type:'checkbox'}),text('xattrName','Имя расширенного атрибута','Extended attribute name',{optional:true}),text('xattrValue','Значение расширенного атрибута','Extended attribute value',{optional:true}),text('xattrRemove','Удалить расширенный атрибут','Remove extended attribute',{optional:true})],{confirm:true})],
      actions:[{label:t('Права и ACL','Access and ACL'),method:'GET',href:r=>'/shares/'+enc(r.name)+'/acl'},
        view(t('Свойства','Properties'),r=>'/shares/'+enc(r.name)),action(t('Параметр Samba','Samba parameter'),'POST',r=>'/shares/'+enc(r.name)+'/param',[text('key','Параметр','Parameter'),text('value','Значение','Value')]),remove(r=>'/shares/'+enc(r.name))]},
    '/printers':{title:t('Принтеры','Printers'),endpoint:'/printers',id:r=>r.name,
      columns:[['name',t('Имя','Name')],['printerName',t('Очередь','Queue')],['path',t('Путь','Path')]],
      create:{label:t('Добавить принтер','Add printer'),href:'/printers/new',method:'POST'},actions:[remove(r=>'/printers/'+enc(r.name))]}
  };
  const cfg = configs[root.dataset.module];
  if (!cfg) return;
  let rows = [], tree = null, selectedDN = '', selectedIDs = null, selectedObject = '', selectedContainer = '', search = '', loadID = 0;
  let dialogGeneration = 0, lastFocus = null;
  const opened = new Set();
  function el(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  }
  function button(label, fn, className = '') { const b = el('button',className,label); b.type='button';b.addEventListener('click',fn);return b; }
  function message(node, content, error = false) { node.textContent=content;node.className='workspace-message'+(error?' error':'');node.setAttribute('role',error?'alert':'status'); }
  async function request(path, method = 'GET', body) {
    const headers = {'Accept':'application/json'};
    if (method !== 'GET') {headers['Content-Type']='application/json';headers['X-CSRF-Token']=document.querySelector('meta[name="csrf-token"]')?.content || '';}
    const response=await fetch(api+path,{method,headers,credentials:'same-origin',body:body === undefined ? undefined : JSON.stringify(body)});
    if(response.status===401) throw new Error(t('Сессия истекла. Войдите снова.','Session expired. Sign in again.'));
    const type=response.headers.get('content-type')||'';
    if(!type.includes('application/json')) throw new Error(t('Сервер вернул неожиданный ответ. Обновите страницу.','Unexpected server response. Reload this page.'));
    const result=await response.json();
    if(!response.ok) {const error=new Error(result.error || `HTTP ${response.status}`);error.status=response.status;throw error;}
    return result;
  }
  const head=el('div','workspace-head');
  head.append(el('h1','',cfg.title));
  const tools=el('div','workspace-tools');head.append(tools);root.append(head);
  const status=el('p','workspace-message');status.setAttribute('aria-live','polite');root.append(status);
  if(cfg.hint)root.append(el('p','muted',cfg.hint));
  const filter=el('form','workspace-filter');const searchInput=el('input');searchInput.type='search';searchInput.placeholder=t('Поиск по списку','Search list');searchInput.setAttribute('aria-label',searchInput.placeholder);
  filter.append(searchInput,button(t('Найти','Search'),()=>{search=searchInput.value;renderRows();}));filter.addEventListener('submit',e=>{e.preventDefault();search=searchInput.value;renderRows();});root.append(filter);
  const content=el('div','workspace-columns');const sidebar=el('aside','workspace-tree');sidebar.setAttribute('aria-label',t('Дерево объектов','Object hierarchy'));const main=el('section','workspace-list');content.append(sidebar,main);root.append(content);
  const selection=el('p','workspace-selection');main.append(selection);
  const tableWrap=el('div','workspace-table');const table=el('table');const thead=el('thead');const tr=el('tr');cfg.columns.forEach(c=>tr.append(el('th','',c[1])));tr.append(el('th','',t('Операции','Actions')));thead.append(tr);table.append(thead);const tbody=el('tbody');table.append(tbody);tableWrap.append(table);main.append(tableWrap);
  const detail=el('section','workspace-detail');detail.setAttribute('aria-live','polite');root.append(detail);
  const dialog=el('dialog','workspace-dialog');dialog.setAttribute('aria-labelledby','operation-title');root.append(dialog);
  const choices=el('datalist');choices.id='directory-dns';root.append(choices);
  function allowed(a) {return a.method==='GET' || (a.support?helpdesk:admin);}
  function addAction(parent,a,row) {
    if(!allowed(a)||a.when&&!a.when(row))return;
    // Samba LDAP fallback can return GPOs without a GUID. Do not send a fabricated identifier.
    if(cfg===configs['/gpo'] && row && !row.guid)return;
    if(a.href){const link=el('a','btn',a.label);link.href=typeof a.href==='function'?a.href(row):a.href;parent.append(link);return;}
    parent.append(button(a.label,()=>openOperation(a,row),a.danger?'danger':''));
  }
  tools.append(button(t('Обновить','Refresh'),()=>load()));
  if(cfg.create)addAction(tools,cfg.create);
  (cfg.toolbar||[]).forEach(a=>addAction(tools,a));
  function value(v) {if(v===true)return t('Включён','Enabled');if(v===false)return t('Отключён','Disabled');if(Array.isArray(v))return v.length;return v??'—';}
  function renderRows() {
    tbody.replaceChildren();let count=0;
    for(const row of rows) {
      if(selectedIDs && !selectedIDs.has((row.dn||'').toLowerCase()))continue;
      if(selectedObject && cfg.id(row)!==selectedObject)continue;
      if(search && !JSON.stringify(row).toLocaleLowerCase().includes(search.toLocaleLowerCase()))continue;
      count++;const r=el('tr');
      cfg.columns.forEach(([key])=>{const cell=el('td',key==='dn'?'mono':'',value(row[key]));r.append(cell);});
      const cell=el('td','workspace-actions');(cfg.actions||[]).forEach(a=>addAction(cell,a,row));r.append(cell);tbody.append(r);
    }
    if(!count){const cell=el('td','muted',t('Объекты не найдены','No objects found'));cell.colSpan=cfg.columns.length+1;const r=el('tr');r.append(cell);tbody.append(r);}
    selection.textContent=(selectedDN||selectedObject||t('Все объекты','All objects'))+' · '+count;
  }
  function chooseNode(node) {
    selectedObject='';selectedDN=node.dn;selectedContainer=['ou','container','domain'].includes(node.kind)?node.dn:node.parentDN;selectedIDs=new Set();
    function collect(n){selectedIDs.add((n.objectDN||n.dn).toLowerCase());(n.children||[]).forEach(collect);}collect(node);
    renderRows();renderTree();
  }
  function renderTree() {
    sidebar.replaceChildren();sidebar.append(el('h2','',t('Дерево','Hierarchy')));
    sidebar.append(button(t('Все объекты','All objects'),()=>{selectedDN='';selectedContainer='';selectedIDs=null;selectedObject='';renderRows();renderTree();}));
    if(tree && cfg!==configs['/gpo']) {
      const list=el('ul','directory-tree');
      function appendNode(parent,node,depth){
        const li=el('li');
        if(node.children?.length){const d=el('details');d.open=depth===0||opened.has(node.dn);d.addEventListener('toggle',()=>d.open?opened.add(node.dn):opened.delete(node.dn));const summary=el('summary');const b=button(node.label,()=>chooseNode(node),selectedDN===node.dn?'selected':'');b.title=node.dn;summary.append(b);d.append(summary);const ul=el('ul');node.children.forEach(n=>appendNode(ul,n,depth+1));d.append(ul);li.append(d);}
        else {const b=button(node.label,()=>chooseNode(node),selectedDN===node.dn?'selected':'');b.title=node.dn;li.append(b);}parent.append(li);
      }
      appendNode(list,tree,0);sidebar.append(list);return;
    }
    if(cfg.directory){sidebar.append(el('p','muted',t('Дерево недоступно. Список можно использовать отдельно.','Hierarchy unavailable. The list remains usable.')));return;}
    const list=el('ul','directory-tree');
    rows.forEach(row=>{const id=cfg.id(row);const label=row.name||row.displayName||row.domain||row.role||id||'—';const li=el('li');
      li.append(button(label,()=>{selectedObject=id;selectedDN='';selectedIDs=null;renderRows();},selectedObject===id?'selected':''));
      if(cfg===configs['/dns']) {
        const d=el('details');const summary=el('summary','',t('Имена записей','Record names'));const children=el('ul');d.append(summary,children);li.append(d);
        let loaded=false,loading=false;
        const loadNodes=async()=>{if(loaded||loading||!d.open)return;loading=true;children.replaceChildren(el('li','muted',t('Загрузка…','Loading…')));
          try{const nodes=await request('/dns/zones/'+enc(row.name)+'/nodes');children.replaceChildren();
            for(const name of nodes){const child=el('li');child.append(button(name,()=>openOperation({...cfg.actions[0],prefill:()=>({name,type:'ALL'})},row)));children.append(child);}
            if(!nodes.length)children.append(el('li','muted',t('Нет записей','No records')));loaded=true;
          }catch(e){children.replaceChildren(el('li','error',e.message));children.append(button(t('Повторить','Retry'),loadNodes));}
          finally{loading=false;}
        };d.addEventListener('toggle',loadNodes);
        li.append(button(t('Запросить запись…','Query record…'),()=>openOperation(cfg.actions[0],row),'linkish'));
      }
      if(cfg===configs['/gpo']){const ul=el('ul');const sub=el('li');sub.textContent=row.guid||t('GUID отсутствует','GUID missing');ul.append(sub);li.append(ul);}
      list.append(li);
    });sidebar.append(list);
    if(cfg===configs['/gpo'] && tree){
      sidebar.append(el('h3','',t('Ссылки домена и OU','Domain and OU links')));
      const links=el('ul','directory-tree');
      function linkNode(parent,node){const li=el('li');li.append(button(node.label,()=>openOperation({...cfg.toolbar[0],prefill:()=>({container:node.dn})})));if(node.children.length){const ul=el('ul');node.children.forEach(n=>linkNode(ul,n));li.append(ul);}parent.append(li);}
      linkNode(links,tree);sidebar.append(links);
    }
  }
  async function load() {
    const id=++loadID;message(status,t('Загрузка…','Loading…'));root.setAttribute('aria-busy','true');
    const results=await Promise.allSettled([request(cfg.endpoint),(cfg.directory||cfg===configs['/gpo'])?request('/directory/tree?kind='+(cfg.directory||'ou')):Promise.resolve(null)]);
    if(id!==loadID)return;root.setAttribute('aria-busy','false');
    if(results[0].status==='rejected'){rows=[];tree=null;renderRows();renderTree();message(status,results[0].reason.message,true);return;}
    rows=results[0].value||[];tree=results[1].status==='fulfilled'?results[1].value:null;
    choices.replaceChildren();
    function options(node){if(!node)return;if(['ou','container','domain'].includes(node.kind)){const option=el('option');option.value=node.dn;choices.append(option);}node.children.forEach(options);}options(tree);
    if(selectedDN && tree && cfg.directory){let found;function find(n){if(n.dn===selectedDN)found=n;n.children.forEach(find);}find(tree);if(found)chooseNode(found);else{selectedDN='';selectedIDs=null;}}
    if(selectedObject && !rows.some(r=>cfg.id(r)===selectedObject))selectedObject='';
    renderRows();renderTree();message(status,results[1].status==='rejected'?t('Список загружен, но дерево недоступно: ','List loaded, but hierarchy failed: ')+results[1].reason.message:t('Данные обновлены','Data refreshed'),results[1].status==='rejected');
  }
  function describe(result,parent) {
    if(result==null){parent.append(el('p','muted',t('Нет данных','No data')));return;}
    if(typeof result!=='object'){parent.append(el('pre','workspace-output',String(result)));return;}
    if(Array.isArray(result)) {if(!result.length)parent.append(el('p','muted',t('Нет данных','No data')));else result.forEach(r=>describe(r,parent));return;}
    const dl=el('dl','workspace-properties');Object.entries(result).forEach(([k,v])=>{dl.append(el('dt','',k));const dd=el('dd');if(v&&typeof v==='object')describe(v,dd);else dd.textContent=value(v);dl.append(dd);});parent.append(dl);
  }
  function closeOperation(){dialogGeneration++;dialog.close();dialog.replaceChildren();if(lastFocus?.isConnected)lastFocus.focus();}
  dialog.addEventListener('cancel',e=>{e.preventDefault();closeOperation();});
  async function openUserCard(a,row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Карточка пользователя','User profile'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    const tabs=el('div','workspace-tools');let activeTab='profile';const profileTab=button(t('Атрибуты','Attributes'),()=>selectTab('profile'));const groupsTab=button(t('Группы','Groups'),()=>selectTab('groups'));tabs.append(profileTab,groupsTab,button(t('Перезагрузить карточку','Reload profile'),refresh),button(t('Закрыть','Close'),closeOperation));dialog.append(title,notice,tabs,body);dialog.showModal();
    function selectTab(tab){activeTab=tab;for(const part of body.children)part.hidden=part.dataset.profileTab!==tab;profileTab.setAttribute('aria-pressed',String(tab==='profile'));groupsTab.setAttribute('aria-pressed',String(tab==='groups'));}
    const path='/users/'+enc(row.samAccountName);let profile;
    async function refresh(){message(notice,t('Загрузка…','Loading…'));body.replaceChildren();try{const user=await request(path);if(generation!==dialogGeneration)return;profile=user;render();message(notice,'');}catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}}
    function render(){
      body.replaceChildren();const attributes=el('section');attributes.dataset.profileTab='profile';body.append(attributes);describe({[t('Логин','Login')]:profile.samAccountName,UPN:profile.userPrincipalName||'',DN:profile.dn,[t('Состояние','Status')]:profile.enabled?t('Включён','Enabled'):t('Отключён','Disabled')},attributes);
      const form=el('form','workspace-form');const fields=[['displayName','Отображаемое имя','Display name'],['givenName','Имя','First name'],['surname','Фамилия','Last name'],['mail','Почта','Email'],['telephone','Телефон','Phone'],['department','Подразделение организации','Department'],['title','Должность','Job title'],['description','Описание','Description']];
      const controls=[];
      for(const [key,ruLabel,enLabel] of fields){const label=el('label','',t(ruLabel,enLabel));const input=el('input');input.type=key==='mail'?'email':'text';input.value=profile[key]||'';input.disabled=!admin;input.maxLength=['givenName','surname','telephone','department','title'].includes(key)?64:key==='description'?1024:256;label.append(input);form.append(label);controls.push([key,input]);}
      if(admin){const save=el('button','',t('Сохранить атрибуты','Save attributes'));save.type='submit';form.append(save);
        form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;const patch={revision:profile.revision};for(const [key,input] of controls)if(input.value!==(profile[key]||''))patch[key]=input.value;
          if(Object.keys(patch).length===1){message(notice,t('Нет изменений','No changes'));return;}save.disabled=true;
          try{const updated=await request(path,'PUT',patch);if(generation!==dialogGeneration)return;profile=updated;render();message(notice,t('Атрибуты сохранены','Attributes saved'));await load();}
          catch(err){if(generation!==dialogGeneration)return;message(notice,err.message,true);save.disabled=err.status===409;}
        });
      }attributes.append(form);
      const account=el('div','workspace-tools');cfg.actions.slice(1).forEach(action=>addAction(account,action,profile));attributes.append(account);
      const groups=el('section');groups.dataset.profileTab='groups';groups.append(el('h3','',t('Группы пользователя','User groups')),el('p','muted',t('Прямое членство и основная группа. Вложенные группы здесь не перечисляются.','Direct memberships and primary group. Nested memberships are not listed.')));body.append(groups);
      let knownGroups=new Set();
      const groupNotice=el('p','workspace-message');groupNotice.setAttribute('aria-live','polite');const members=el('div');groups.append(groupNotice,members);
      async function refreshGroups(){try{const data=await request(path+'/groups');if(generation!==dialogGeneration||!groups.isConnected)return;knownGroups=new Set(data.map(g=>g.name.toLowerCase()));members.replaceChildren();
        if(!data.length)members.append(el('p','muted',t('Группы не найдены','No groups found')));
        for(const group of data){const line=el('div','workspace-tools');line.append(el('span','',group.name+(group.primary?t(' — основная группа',' — primary group'):'')));if(admin&&!group.primary){const remove=button(t('Исключить из группы','Remove from group'),()=>mutateGroup(group,'DELETE',remove));remove.setAttribute('aria-label',t('Исключить из ','Remove from ')+group.name);line.append(remove);}members.append(line);}
      }catch(err){if(generation===dialogGeneration&&groups.isConnected){message(groupNotice,err.message,true);members.replaceChildren(button(t('Повторить загрузку групп','Retry groups'),refreshGroups));}}}
      async function mutateGroup(group,method,trigger){trigger.disabled=true;try{await request('/groups/'+enc(group.name)+'/members',method,{memberDN:profile.dn});if(generation!==dialogGeneration||!groups.isConnected)return;message(groupNotice,t('Членство обновлено','Membership updated'));await refreshGroups();}catch(err){if(generation===dialogGeneration&&groups.isConnected)message(groupNotice,err.message,true);}finally{trigger.disabled=method==='POST'&&knownGroups.has(group.name.toLowerCase());}}
      if(admin){const search=el('form','workspace-form');const label=el('label','',t('Найти группу','Find group'));const input=el('input');input.required=true;input.maxLength=128;label.append(input);search.append(label);const find=el('button','',t('Найти группы','Search groups'));find.type='submit';search.append(find);const results=el('div');search.append(results);groups.append(search);
        search.addEventListener('submit',async e=>{e.preventDefault();if(!search.reportValidity())return;find.disabled=true;results.replaceChildren();try{const matches=await request('/groups?q='+enc(input.value.trim()));if(generation!==dialogGeneration||!groups.isConnected)return;for(const match of matches){const line=el('div','workspace-tools');line.append(el('span','',match.samAccountName));const add=button(t('Добавить в группу','Add to group'),()=>mutateGroup({name:match.samAccountName},'POST',add));add.setAttribute('aria-label',t('Добавить в ','Add to ')+match.samAccountName);add.disabled=knownGroups.has(match.samAccountName.toLowerCase());line.append(add);results.append(line);}if(!matches.length)results.append(el('p','muted',t('Группы не найдены','No groups found')));}catch(err){if(generation===dialogGeneration&&groups.isConnected)message(groupNotice,err.message,true);}finally{find.disabled=false;}});
      }
      selectTab(activeTab);refreshGroups();
    }
    await refresh();
  }

  async function openALTEditor(a,row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',a.label);title.id='operation-title';dialog.append(title,el('p','',row.displayName||row.guid),el('p','muted',t('Политики systemd для компьютеров ALT. Включение задаёт автозапуск службы; применение проверяется на клиенте.','ALT computer systemd policies. Enabled configures service startup; verify application on the client.')));
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const content=el('div');dialog.append(notice,content,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    const path=a.path(row);let model;
    const stateLabel=s=>({'enabled':t('Включено','Enabled'),'disabled':t('Отключено','Disabled'),'not-configured':t('Не настроено','Not configured'),'unsupported':t('Другое значение — используйте GPUI','Other value — use GPUI')}[s]||s);
    function render(){
      content.replaceChildren(el('p','mono',t('Версия ','Version ')+model.version+' · Machine'));
      if(model.machineDisabled)content.append(el('p','alert error',t('Машинный раздел этой GPO отключён. Настройки не применятся, пока раздел не будет включён.','The computer section of this GPO is disabled. Settings will not apply until it is enabled.')));
      for(const setting of model.settings){
        const form=el('form','workspace-form');const label=el('label','',setting.label);const select=el('select');
        const states=setting.state==='unsupported'?['unsupported']:['not-configured','enabled','disabled'];
        for(const state of states){const option=el('option','',stateLabel(state));option.value=state;select.append(option);}select.value=setting.state;select.disabled=!admin||setting.state==='unsupported';select.id='alt-setting-'+model.settings.indexOf(setting);label.htmlFor=select.id;form.append(label,select);
        if(admin&&setting.state!=='unsupported'){
          const confirmLabel=el('label','workspace-confirm',t('Подтверждаю изменение этой политики','I confirm this policy change'));const confirm=el('input');confirm.type='checkbox';confirm.required=true;confirmLabel.prepend(confirm);form.append(confirmLabel);
          const save=el('button','',t('Сохранить','Save'));save.type='submit';form.append(save);
          form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;content.querySelectorAll('button,select,input').forEach(x=>x.disabled=true);message(notice,t('Сохранение…','Saving…'));
            try{const result=await request(path,'PUT',{id:setting.id,state:select.value,revision:model.revision});if(generation!==dialogGeneration)return;model=result;render();message(notice,t('Сохранено. Проверьте gpupdate и gpresult на ALT-клиенте.','Saved. Verify gpupdate and gpresult on the ALT client.'));}
            catch(err){if(generation!==dialogGeneration)return;message(notice,err.message,true);content.replaceChildren(button(t('Перезагрузить параметры','Reload settings'),()=>refresh()));}
          });
        }content.append(form);
      }
    }
    async function refresh(){message(notice,t('Загрузка…','Loading…'));try{const result=await request(path);if(generation!==dialogGeneration)return;model=result;render();message(notice,'');}catch(err){if(generation===dialogGeneration){message(notice,err.message,true);content.replaceChildren(button(t('Повторить','Retry'),refresh));}}}
    await refresh();
  }
  async function openOperation(a,row) {
    if(a.userCard)return openUserCard(a,row);
    if(a.editor)return openALTEditor(a,row);
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',a.label);title.id='operation-title';dialog.append(title);
    if(row)dialog.append(el('p','mono',cfg.id(row)||row.dn||''));
    if(a.warning)dialog.append(el('p','alert error',a.warning));
    if(a.danger)dialog.append(el('p','alert error',t('Изменение применяется в домене. Проверьте выбранный объект. Удаление может быть необратимым.','This changes the domain. Check the selected object. Deletion may be irreversible.')));
    const form=el('form','workspace-form');const defaults=a.prefill?a.prefill(row):{};
    const inputs=[];
    for(const f of a.fields){const label=el('label','',f.label);let input;
      if(f.choices){input=el('select');f.choices.forEach(c=>{const option=el('option','',c);option.value=c;input.append(option);});}
      else {input=el('input');input.type=f.type||'text';}
      input.name=f.key;input.required=!f.optional&&f.type!=='checkbox';input.autocomplete=f.type==='password'?'new-password':'off';
      if(f.type==='checkbox')input.checked=!!f.value;else input.value=defaults[f.key]??f.value??((f.key==='ou'||f.key==='parentDN')?selectedContainer:'');
      if(f.key==='container' && !input.value)input.value=selectedContainer||'';
      if(f.placeholder)input.placeholder=f.placeholder;if(f.list)input.setAttribute('list',f.list);
      label.append(input);form.append(label);inputs.push([f,input]);
      if(f.type==='password'){
        const confirm=el('label','',t('Повторите пароль','Repeat password'));const repeat=el('input');repeat.type='password';repeat.autocomplete='new-password';repeat.required=!f.optional;confirm.append(repeat);form.append(confirm);
        const validate=()=>repeat.setCustomValidity(repeat.value===input.value?'':t('Пароли не совпадают','Passwords do not match'));repeat.addEventListener('input',validate);input.addEventListener('input',validate);validate();
      }
    }
    if(a.danger||a.confirm){const label=el('label','workspace-confirm',t('Подтверждаю операцию для выбранного объекта','I confirm this operation on the selected object'));const c=el('input');c.type='checkbox';c.required=true;label.prepend(c);form.append(label);}
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');form.append(notice);
    const output=el('div','workspace-result');
    const controls=el('div','workspace-tools');const submit=el('button',a.danger?'danger':'',a.method==='GET'?t('Показать','Show'):t('Выполнить','Apply'));submit.type='submit';controls.append(submit,button(t('Закрыть','Close'),closeOperation));form.append(controls);dialog.append(form,output);
    form.addEventListener('submit',async e=>{
      e.preventDefault();if(!form.reportValidity())return;
      let path=typeof a.path==='function'?a.path(row):a.path;const body={};
      inputs.forEach(([f,input])=>{if(f.type==='checkbox')body[f.key]=input.checked;else if(input.value!==''||!f.optional)body[f.key]=f.numeric?Number(input.value):f.array?input.value.split(';').map(v=>v.trim()).filter(Boolean):f.type==='password'?input.value:input.value.trim();});
      if(a.revision)body.revision=row.revision;if(a.preset)Object.assign(body,a.preset);
      const payload=a.encode?a.encode(body):body;
      if(a.method==='GET'&&Object.keys(body).length)path+=(path.includes('?')?'&':'?')+new URLSearchParams(body);
      submit.disabled=true;message(notice,t('Выполняется…','Working…'));output.replaceChildren();
      try{
        const result=await request(path,a.method,a.method==='GET'?undefined:payload);
        if(generation!==dialogGeneration){if(a.method!=='GET')load();return;}
        message(notice,a.job?t('Доставка запущена','Distribution started'):t('Операция выполнена','Operation completed'));
        // Passwords are never included in rendered results or retained in form controls after success.
        form.querySelectorAll('input[type=password]').forEach(i=>{i.value='';});
        if(a.job) await pollJob(result,output,generation);
        else if(a.method==='GET')renderResult(result,output,a,row,body);
        else {if(result.output)describe(result.output,output);await load();}
      }catch(err){if(generation===dialogGeneration)message(notice,err.message,true);}
      finally{submit.disabled=false;}
    });
    if(!dialog.open)dialog.showModal();(inputs[0]?.[1]||submit).focus();
    if(a.method==='GET'&&!a.fields.length)form.requestSubmit();
  }
  function topologyTable(parent,rows,columns,actions=[]){
    const wrap=el('div','workspace-table');const table=el('table');const head=el('tr');columns.forEach(c=>head.append(el('th','',c[1])));if(actions.length)head.append(el('th','',t('Операции','Actions')));table.append(head);
    for(const row of rows){const tr=el('tr');columns.forEach(([key])=>tr.append(el('td','',Array.isArray(row[key])?row[key].join('; '):value(row[key]))));if(actions.length){const td=el('td');for(const a of actions){if(allowed(a)&&(!a.when||a.when(row)))td.append(button(a.label,()=>openOperation(a,row),a.danger?'danger':''));}tr.append(td);}table.append(tr);}wrap.append(table);parent.append(wrap);if(!rows.length)parent.append(el('p','muted',t('Нет объектов','No objects')));
  }
  function renderResult(result,parent,a,row,query) {
    const endpoint=typeof a.path==='function'?a.path(row):a.path;
    if(endpoint==='/sites/links'){
 parent.append(el('p','muted',t('Расписания Site Link заблокированы из-за ошибки KCC в Samba. Расписания отдельных соединений доступны в разделе «Репликация».','Site Link schedule writes are blocked due to a Samba KCC defect. Connection schedules are available under Replication.')));
      topologyTable(parent,result,[['name',t('Связь','Link')],['sites',t('Сайты','Sites')],['cost',t('Стоимость','Cost')],['interval',t('Минуты','Minutes')]],
        [action(t('Настроить связь','Configure link'),'PUT',r=>'/sites/links/'+enc(r.name),linkFields(),{revision:true,confirm:true,prefill:r=>({sites:r.sites.join(';'),cost:r.cost,interval:r.interval})}),scheduleOperation(r=>'/sites/links/'+enc(r.name)+'/schedule'),{...remove(r=>'/sites/links/'+enc(r.name)),revision:true}]);return;
    }
    if(endpoint==='/sites/controllers'){
      topologyTable(parent,result,[['name',t('Контроллер','DC')],['dns','DNS'],['site',t('Сайт','Site')]],
        [action(t('Перенести в сайт','Move to site'),'POST',r=>'/sites/controllers/'+enc(r.name)+'/move',[text('site','Новый сайт','New site')],{revision:true,confirm:true}),{...view(t('Проверить репликацию','Inspect replication'),'/repl/status',[text('dc','Контроллер','Controller')]),prefill:r=>({dc:r.dns})}]);return;
    }
    if(endpoint==='/sites/topology'){
      for(const site of result.sites){const title=el('h3','',site.name);parent.append(title);const list=el('ul');for(const dc of result.controllers.filter(dc=>dc.site===site.name))list.append(el('li','',t('Контроллер: ','DC: ')+dc.dns));for(const subnet of result.subnets.filter(sub=>(sub.site||'').toLowerCase()===site.dn.toLowerCase()))list.append(el('li','',t('Подсеть: ','Subnet: ')+subnet.name));parent.append(list);}return;
    }
    if(endpoint==='/repl/connections'){
      parent.append(el('p','muted',t('Автоматические соединения управляются KCC: он может восстановить их после изменений. Ручные соединения используйте осознанно.','KCC manages automatic connections and may recreate them. Use manual connections deliberately.')));
      topologyTable(parent,result,[['source',t('Источник','Source')],['destination',t('Назначение','Destination')],['enabled',t('Включено','Enabled')],['automatic','KCC']],
        [action(t('Включить соединение','Enable connection'),'PUT',r=>'/repl/connections/'+enc(r.id),[],{revision:true,preset:{enabled:true},confirm:true,when:r=>!r.enabled}),action(t('Отключить соединение','Disable connection'),'PUT',r=>'/repl/connections/'+enc(r.id),[],{revision:true,preset:{enabled:false},confirm:true,when:r=>r.enabled}),scheduleOperation(r=>'/repl/connections/'+enc(r.id)),{...remove(r=>'/repl/connections/'+enc(r.id)),revision:true}]);return;
    }
    if(endpoint==='/repl/status'){
      const health={healthy:t('Успешно','Healthy'),degraded:t('Есть ошибки','Degraded'),'no-partners':t('Нет партнёров — состояние не подтверждено','No partners — health unverified')};parent.append(el('h3','',result.server||''),el('p','',health[result.health]||t('Неизвестно','Unknown')));
      topologyTable(parent,result.neighbors||[],[['direction',t('Направление','Direction')],['partner',t('Партнёр','Partner')],['partition',t('Раздел','Partition')],['failures',t('Ошибки подряд','Consecutive failures')],['lastSuccess',t('Последний успех','Last success')],['result',t('Последний результат','Last result')]]);return;
    }
    // Keep DNS query results under the chosen zone, with explicit values for edits.
    if(cfg===configs['/dns']&&Array.isArray(result)) {
      const ul=el('ul','directory-tree');const li=el('li','',row.name);const inner=el('ul');
      result.forEach(record=>{const node=el('li','mono',record.raw||`${record.type}: ${record.data}`);inner.append(node);});li.append(inner);ul.append(li);parent.append(ul);
      if(!result.length)parent.append(el('p','muted',t('Записи не найдены','No records found')));
    }else describe(result,parent);
  }
  async function pollJob(job,parent,generation) {
    while(generation===dialogGeneration){
      parent.replaceChildren();parent.append(el('h3','',t('Доставка GPO','GPO distribution')));
      const progress=el('progress');progress.max=100;progress.value=job.progress;parent.append(progress,el('p','',`${job.progress}% · ${job.status}`));
      const list=el('ol');(job.steps||[]).forEach(step=>list.append(el('li','',`${step.title} — ${step.status}${step.message?' · '+step.message:''}`)));parent.append(list);
      if(job.error)parent.append(el('p','alert error',job.error));
      if(job.status==='ok'||job.status==='failed')return;
      await new Promise(resolve=>setTimeout(resolve,1200));if(generation!==dialogGeneration)return;
      job=await request('/gpo/distribute/'+enc(job.id));
    }
  }
  load();
})();
