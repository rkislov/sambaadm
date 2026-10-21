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
  const linkFields=()=>[text('sites','Сайты','Sites',{array:true,multiple:true}),text('cost','Стоимость (1–32767)','Cost (1–32767)',{type:'number',numeric:true,value:100}),text('interval','Интервал, минут (15–10080, шаг 15)','Interval, minutes (15–10080, step 15)',{type:'number',numeric:true,value:180})];
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
      toolbar:[view(t('Ссылки на контейнер','Container links'),'/gpo/links',[dn('container')]),{label:t('Область действия','Scope and inheritance'),method:'GET',scope:true},action(t('Восстановить в новую GPO','Restore as new GPO'),'POST','/gpo/restore',[text('name','Имя новой политики','New policy name'),text('path','Каталог копии policy/{GUID} на сервере','Backup policy/{GUID} directory on server')],{confirm:true})],
      actions:[view(t('Свойства','Properties'),r=>'/gpo/'+enc(gpoID(r))),
 {label:t('Фильтрация безопасности','Security filtering'),method:'GET',filter:true},
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
      toolbar:[{label:t('Топология','Topology'),method:'GET',topology:true},view(t('Состояние репликации','Replication status'),'/repl/status',[text('dc','Контроллер (пусто — текущий)','Controller (empty — current)',{optional:true})]),view(t('Соединения репликации','Replication connections'),'/repl/connections'),action(t('Создать соединение','Create connection'),'POST','/repl/connections',[text('source','Контроллер источник','Source DC'),text('destination','Контроллер назначения','Destination DC')],{confirm:true}),action(t('Пересчитать топологию KCC','Recalculate KCC topology'),'POST','/repl/kcc',[text('dc','Контроллер','Controller')],{confirm:true}),action(t('Синхронизировать','Synchronize'),'POST','/repl/sync',[text('from','Контроллер источник','Source DC'),text('dest','Контроллер назначения','Destination DC',{optional:true}),text('nc','Раздел каталога DN','Naming context DN',{optional:true})],{confirm:true})],actions:[]},
    '/sites':{title:t('Сайты','Sites'),endpoint:'/sites',id:r=>r.name,
      columns:[['name',t('Сайт','Site')],['dn','DN']],create:action(t('Создать сайт','Create site'),'POST','/sites',[name()]),
      toolbar:[{label:t('Топология','Topology'),method:'GET',topology:true},view(t('Топология сайтов','Site topology'),'/sites/topology'),view(t('Контроллеры','Controllers'),'/sites/controllers'),view(t('Связи сайтов','Site links'),'/sites/links'),action(t('Создать связь сайтов','Create site link'),'POST','/sites/links',[name(),...linkFields()],{confirm:true}),view(t('Подсети','Subnets'),'/subnets'),action(t('Переназначить подсеть','Reassign subnet'),'PUT','/subnets/site',[text('subnet','Подсеть CIDR','Subnet CIDR'),text('site','Новый сайт','New site')],{confirm:true}),action(t('Создать подсеть','Create subnet'),'POST','/subnets',[text('subnet','Подсеть CIDR','Subnet CIDR'),text('site','Имя сайта','Site name')]),action(t('Удалить подсеть','Delete subnet'),'POST','/subnets/delete',[text('subnet','Подсеть CIDR','Subnet CIDR')],{danger:true})],actions:[remove(r=>'/sites/'+enc(r.name))]},
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
  filter.append(searchInput,button(t('Найти','Search'),()=>{search=searchInput.value;renderRows();}));filter.addEventListener('submit',e=>{e.preventDefault();search=searchInput.value;renderRows();});root.append(filter);searchInput.addEventListener('input',()=>{search=searchInput.value;renderRows();});filter.append(el('span','muted',t('Поиск по имени, логину и атрибутам в выбранной ветви. Для всего домена выберите «Все объекты».','Search name, login and attributes in the selected branch. Select All objects to search the whole domain.')));
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
  function normalizeSearch(text){return text.normalize('NFKC').toLocaleLowerCase().trim();}
  function renderRows() {
    tbody.replaceChildren();let count=0;
    for(const row of rows) {
      if(selectedIDs && !selectedIDs.has((row.dn||'').toLowerCase()))continue;
      if(selectedObject && cfg.id(row)!==selectedObject)continue;
      if(search && !normalizeSearch(search).split(/\s+/).every(word=>normalizeSearch(JSON.stringify(row)).includes(word)))continue;
      count++;const r=el('tr');
      cfg.columns.forEach(([key])=>{const cell=el('td',key==='dn'?'mono':'',value(key==='displayName'?(row[key]||row.name):row[key]));r.append(cell);});
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
      if(cfg===configs['/gpo']){const branch=el('details');branch.append(el('summary','',t('Параметры политики','Policy settings')));for(const a of cfg.actions.slice(0,3))branch.append(button(a.label,()=>openOperation(a,row)));li.append(branch);}
      list.append(li);
    });sidebar.append(list);
    if(cfg===configs['/gpo'] && tree){
      sidebar.append(el('h3','',t('Ссылки домена и OU','Domain and OU links')));
      const links=el('ul','directory-tree');
      function linkNode(parent,node){const li=el('li');li.append(button(node.label,()=>openScope(node.dn)));if(node.children.length){const ul=el('ul');node.children.forEach(n=>linkNode(ul,n));li.append(ul);}parent.append(li);}
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
  function describeTree(data,parent){
    if(!data||typeof data!=='object'){describe(data,parent);return;}
    const list=el('ul','directory-tree');for(const [name,item] of Object.entries(data)){const li=el('li');const branch=el('details');branch.append(el('summary','',name));describeTree(item,branch);li.append(branch);list.append(li);}parent.append(list);
  }
  function closeOperation(){dialogGeneration++;dialog.close();dialog.replaceChildren();if(lastFocus?.isConnected)lastFocus.focus();}
  dialog.addEventListener('cancel',e=>{e.preventDefault();closeOperation();});
  async function openUserCard(a,row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Карточка пользователя','User profile'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    const tabs=el('div','workspace-tools');let activeTab='profile';const profileTab=button(t('Атрибуты','Attributes'),()=>selectTab('profile'));const groupsTab=button(t('Группы','Groups'),()=>selectTab('groups'));const extendedTab=button(t('Расширенные атрибуты','Extended attributes'),()=>selectTab('extended'));tabs.append(profileTab,extendedTab,groupsTab,button(t('Перезагрузить карточку','Reload profile'),refresh),button(t('Закрыть','Close'),closeOperation));dialog.append(title,notice,tabs,body);dialog.showModal();
    function selectTab(tab){activeTab=tab;for(const part of body.children)part.hidden=part.dataset.profileTab!==tab;profileTab.setAttribute('aria-pressed',String(tab==='profile'));groupsTab.setAttribute('aria-pressed',String(tab==='groups'));extendedTab.setAttribute('aria-pressed',String(tab==='extended'));}
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
      const extended=el('section');extended.dataset.profileTab='extended';body.append(extended);
      const extraForm=el('form','workspace-form');const extraControls=[];
      const sections=[['Контакты','Contacts',[
        ['initials','Инициалы','Initials',6],['physicalDeliveryOfficeName','Офис','Office',128],['wWWHomePage','Веб-страница','Web page',2048],['mobile','Мобильный телефон','Mobile phone',64],['homePhone','Домашний телефон','Home phone',64],['pager','Пейджер','Pager',64],['facsimileTelephoneNumber','Факс','Fax',64]]],
        ['Адрес','Address',[['streetAddress','Улица, дом','Street address',1024],['l','Город','City',128],['st','Регион','State',128],['postalCode','Почтовый индекс','Postal code',40],['co','Страна (название)','Country name',128]]],
        ['Организация','Organization',[['company','Организация','Company',64],['division','Отделение','Division',256],['employeeID','Табельный идентификатор','Employee ID',16],['employeeNumber','Табельный номер','Employee number',512]]]];
      for(const [ru,en,fields] of sections){const section=el('fieldset');section.append(el('legend','',t(ru,en)));for(const [key,ruLabel,enLabel,max] of fields){const label=el('label','',t(ruLabel,enLabel));const input=el('input');const values=profile.attributes?.[key]||[];input.value=values[0]||'';input.maxLength=max;input.disabled=!admin||values.length>1;label.append(input);section.append(label);extraControls.push([key,input]);}extraForm.append(section);}
      if(admin){const save=el('button','',t('Сохранить расширенные атрибуты','Save extended attributes'));save.type='submit';extraForm.append(save);extraForm.addEventListener('submit',async e=>{e.preventDefault();if(!extraForm.reportValidity())return;const changes={};for(const [key,input] of extraControls)if(!input.disabled&&input.value!==(profile.attributes?.[key]?.[0]||''))changes[key]=input.value;if(!Object.keys(changes).length){message(notice,t('Нет изменений','No changes'));return;}save.disabled=true;try{const updated=await request(path,'PUT',{revision:profile.revision,attributes:changes});if(generation!==dialogGeneration)return;profile=updated;render();message(notice,t('Атрибуты сохранены','Attributes saved'));await load();}catch(err){if(generation!==dialogGeneration)return;message(notice,err.message,true);save.disabled=err.status===409;}});}
      extended.append(extraForm,el('h3','',t('Учётная запись и LDAP-атрибуты (просмотр)','Account and LDAP attributes (read only)')),el('p','muted',t('Значения показаны в формате LDAP; временные поля AD могут содержать FILETIME. Права безопасности и делегирование этим редактором не изменяются.','Values use LDAP format; AD timestamps may contain FILETIME. This editor does not modify security permissions or delegation.')));
      describe({cn:profile.name||'',...(profile.attributes||{})},extended);
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
    const title=el('h2','',a.label);title.id='operation-title';dialog.append(title,el('p','',row.displayName||row.guid),el('p','muted',t('Политики ALT из шаблонов домена. Выберите раздел и найдите нужную настройку. Применение проверяется на ALT-клиенте.','ALT policies from domain templates. Select a scope and find a setting. Verify application on the ALT client.')));
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');
    const toolbar=el('div','workspace-form policy-toolbar');
    const scopeSelect=el('select');scopeSelect.id='alt-scope';for(const [value,label] of [['Machine',t('Компьютер','Computer')],['User',t('Пользователь','User')]]){const o=el('option','',label);o.value=value;scopeSelect.append(o);}
    const scopeLabel=el('label','',t('Раздел политики','Policy scope'));scopeLabel.htmlFor=scopeSelect.id;
    const search=el('input');search.type='search';search.id='alt-search';search.placeholder=t('Название, описание или параметр','Name, description or parameter');const searchLabel=el('label','',t('Поиск политик','Search policies'));searchLabel.htmlFor=search.id;
    const category=el('select');category.id='alt-category';const categoryLabel=el('label','',t('Категория','Category'));categoryLabel.htmlFor=category.id;
    toolbar.append(scopeLabel,scopeSelect,searchLabel,search,categoryLabel,category);
    const content=el('div');dialog.append(notice,toolbar,content,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    const path=a.path(row);let model,selectedPolicy='',loading=0;const expanded=new Set();
    const stateLabel=s=>({'enabled':t('Включено','Enabled'),'disabled':t('Отключено','Disabled'),'not-configured':t('Не настроено','Not configured'),'unsupported':t('Неподдерживаемое значение — только просмотр','Unsupported value — read only')}[s]||s);
    function render(){
      if(!model)return;
      content.replaceChildren(el('p','mono',t('Версия ','Version ')+model.version+' · '+(model.scope||scopeSelect.value)));
      if(model.controller)content.append(el('p','mono',t('Удалённый DC: ','Remote DC: ')+model.controller+' · SMB'));
      if(model.templateSource)content.append(el('p','mono',t('Шаблоны: ','Templates: ')+model.templateSource));
      if(model.sectionDisabled||((model.scope||'Machine')==='Machine'&&model.machineDisabled))content.append(el('p','alert error',scopeSelect.value==='User'?t('Пользовательский раздел этой GPO отключён. Настройки не применятся, пока раздел не будет включён.','The user section of this GPO is disabled.'):t('Машинный раздел этой GPO отключён. Настройки не применятся, пока раздел не будет включён.','The computer section of this GPO is disabled. Settings will not apply until it is enabled.')));
      const needle=search.value.toLocaleLowerCase();const matches=model.settings.filter(s=>(!category.value||category.value===(s.category||s.template||''))&&[s.label,s.id,s.description,s.key,...(s.fields||[]).map(f=>f.label+' '+f.value)].join(' ').toLocaleLowerCase().includes(needle));
      content.append(el('p','muted',t('Найдено: ','Found: ')+matches.length+' / '+model.settings.length));
      const layout=el('div','policy-layout');const navigation=el('nav','policy-navigation directory-tree');navigation.setAttribute('aria-label',t('Дерево политик ALT','ALT policy tree'));const detail=el('section','policy-detail');layout.append(navigation,detail);content.append(layout);
      const groups=new Map();for(const setting of matches){const template=setting.template||'ALT';if(!groups.has(template))groups.set(template,new Map());const categories=groups.get(template);const name=setting.category||t('Общие','General');if(!categories.has(name))categories.set(name,[]);categories.get(name).push(setting);}
      for(const [template,categories] of groups){const branch=el('details');branch.open=!!needle||expanded.has(template);branch.append(el('summary','',template));branch.addEventListener('toggle',()=>branch.open?expanded.add(template):expanded.delete(template));navigation.append(branch);
        for(const [name,settings] of categories){const key=template+'/'+name;const folder=el('details');folder.open=!!needle||expanded.has(key);folder.append(el('summary','',name+' ('+settings.length+')'));folder.addEventListener('toggle',()=>folder.open?expanded.add(key):expanded.delete(key));branch.append(folder);
          for(const setting of settings){const item=button(setting.label,()=>{selectedPolicy=setting.id;expanded.add(template);expanded.add(key);render();content.querySelector('[aria-current=true]')?.focus();},selectedPolicy===setting.id?'selected':'');item.title=stateLabel(setting.state);item.setAttribute('aria-current',selectedPolicy===setting.id?'true':'false');folder.append(item);}
        }
      }
      if(!matches.some(s=>s.id===selectedPolicy))detail.append(el('p','muted',t('Выберите политику в дереве слева. Поиск раскрывает подходящие ветви.','Select a policy in the tree. Search expands matching branches.')));
      for(const setting of matches.filter(s=>s.id===selectedPolicy)){
        const form=el('form','workspace-form');form.style.marginBottom='1.5rem';const label=el('label','',setting.label);const select=el('select');
        const readonly=setting.state==='unsupported'||!!setting.unsupported;
        const states=readonly?['unsupported']:['not-configured','enabled','disabled'];for(const state of states){const option=el('option','',stateLabel(state));option.value=state;select.append(option);}select.value=readonly?'unsupported':setting.state;select.disabled=!admin||readonly;select.id='alt-setting-'+model.settings.indexOf(setting);label.htmlFor=select.id;form.append(label,select);
        if(setting.template)form.append(el('p','mono',setting.template+' · '+(setting.category||'')+' · '+(setting.supportedOn||'')));
        if(setting.description){const detail=el('details');const text=el('p','',setting.description);text.style.whiteSpace='pre-wrap';detail.append(el('summary','',t('Описание и требования','Description and requirements')),text);form.append(detail);}
        if(setting.unsupported)form.append(el('p','alert error',setting.unsupported));
        const controls=[];
        for(const field of setting.fields||[]){
          let input;const current=setting.values&&Object.hasOwn(setting.values,field.id)?setting.values[field.id]:field.default;
          if(field.kind==='enum'){input=el('select');for(const [i,c] of (field.choices||[]).entries()){const o=el('option','',c.label);o.value=String(i);input.append(o);}input.value=current==null?'0':String(current);}
          else if(field.kind==='list'){input=el('textarea');input.rows=4;input.value=Array.isArray(current)?current.join('\n'):'';input.placeholder=t('По одному значению в строке','One value per line');}
          else {input=el('input');input.type=field.kind==='boolean'?'checkbox':field.kind==='decimal'?'number':'text';if(field.kind==='boolean')input.checked=!!current;else input.value=current==null?'':String(current);if(field.kind==='decimal'){input.min=String(field.min);input.max=String(field.max);input.step='1';}if(field.kind==='text'&&field.maxLength)input.maxLength=field.maxLength;}
          input.id=select.id+'-field-'+controls.length;const fieldLabel=el('label','',field.label||field.id);fieldLabel.htmlFor=input.id;form.append(fieldLabel,input);controls.push({field,input});
        }
        const updateFields=()=>{for(const {field,input} of controls){input.disabled=!admin||readonly||select.value!=='enabled';input.required=select.value==='enabled'&&(field.required||field.kind==='decimal');}};select.addEventListener('change',updateFields);updateFields();
        if(admin&&!readonly){
          const confirmLabel=el('label','workspace-confirm',t('Подтверждаю изменение этой политики','I confirm this policy change'));const confirm=el('input');confirm.type='checkbox';confirm.required=true;confirmLabel.prepend(confirm);form.append(confirmLabel);
          const save=el('button','',t('Сохранить','Save'));save.type='submit';form.append(save);
          form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;
            const values={};if(select.value==='enabled')for(const {field,input} of controls){values[field.id]=field.kind==='boolean'?input.checked:field.kind==='list'?input.value.split(/\r?\n/).filter(x=>x!==''):input.value;}
            const payload={id:setting.id,state:select.value,revision:model.revision,scope:model.scope||scopeSelect.value,values};
            dialog.querySelectorAll('button,select,input,textarea').forEach(x=>x.disabled=true);message(notice,t('Сохранение…','Saving…'));
            try{const result=await request(path,'PUT',payload);if(generation!==dialogGeneration)return;model=result;render();message(notice,t('Сохранено. Проверьте gpupdate и gpresult на ALT-клиенте.','Saved. Verify gpupdate and gpresult on the ALT client.'));}
            catch(err){if(generation!==dialogGeneration)return;message(notice,err.message,true);content.replaceChildren(button(t('Перезагрузить параметры','Reload settings'),()=>refresh()));}
            finally{if(generation===dialogGeneration){toolbar.querySelectorAll('input,select').forEach(x=>x.disabled=false);dialog.querySelectorAll('button').forEach(x=>x.disabled=false);}}
          });
        }detail.append(form);
      }
    }
    async function refresh(){const requestID=++loading;model=null;content.replaceChildren();search.disabled=category.disabled=scopeSelect.disabled=true;message(notice,t('Загрузка…','Loading…'));try{
      const result=await request(path+(scopeSelect.value==='User'?'?scope=User':''));if(generation!==dialogGeneration||requestID!==loading)return;model=result;
      category.replaceChildren();const all=el('option','',t('Все категории','All categories'));all.value='';category.append(all);for(const name of [...new Set(model.settings.map(s=>s.category||s.template||'').filter(Boolean))].sort()){const o=el('option','',name);o.value=name;category.append(o);}
      render();message(notice,'');
    }catch(err){if(generation===dialogGeneration&&requestID===loading){message(notice,err.message,true);content.replaceChildren(button(t('Повторить','Retry'),refresh));}}finally{if(generation===dialogGeneration&&requestID===loading)search.disabled=category.disabled=scopeSelect.disabled=false;}}
    scopeSelect.addEventListener('change',()=>{search.value='';selectedPolicy='';refresh();});search.addEventListener('input',render);category.addEventListener('change',render);
    await refresh();
  }
  async function openOperation(a,row) {
    if(a.scope)return openScope();
    if(a.filter)return openFilter(row);
    if(a.topology||(a.path==='/repl/connections'&&a.method==='POST'))return openTopology();
    if(a.userCard)return openUserCard(a,row);
    if(a.editor)return openALTEditor(a,row);
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',a.label);title.id='operation-title';dialog.append(title);
    if(row)dialog.append(el('p','mono',cfg.id(row)||row.dn||''));
    if(a.warning)dialog.append(el('p','alert error',a.warning));
    if(a.danger)dialog.append(el('p','alert error',t('Изменение применяется в домене. Проверьте выбранный объект. Удаление может быть необратимым.','This changes the domain. Check the selected object. Deletion may be irreversible.')));
    const endpoint=typeof a.path==='function'?a.path(row):a.path;
    let fields=a.fields;
    const needsSites=fields.some(f=>f.key==='sites'||f.key==='site');
    const needsDCs=endpoint.startsWith('/repl/')&&fields.some(f=>['dc','from','dest'].includes(f.key));
    if(needsSites||needsDCs){
      const pending=el('p','',t('Загрузка списка объектов…','Loading objects…'));dialog.append(pending);if(!dialog.open)dialog.showModal();
      try{const [sites,dcs]=await Promise.all([needsSites?request('/sites'):[],needsDCs?request('/sites/controllers'):[]]);if(generation!==dialogGeneration)return;
        fields=fields.map(f=>f.key==='sites'||f.key==='site'?{...f,choices:sites.map(s=>s.name)}:needsDCs&&['dc','from','dest'].includes(f.key)?{...f,choices:dcs.map(dc=>dc.dns)}:f);pending.remove();
      }catch(err){if(generation===dialogGeneration){message(pending,err.message,true);dialog.append(button(t('Закрыть','Close'),closeOperation));}return;}
    }
    const form=el('form','workspace-form');const defaults=a.prefill?a.prefill(row):{};
    const inputs=[];
    for(const f of fields){const label=el('label','',f.label);let input;
      if(f.choices){input=el('select');input.multiple=!!f.multiple;if(!f.multiple){const empty=el('option','',f.optional?t('По умолчанию','Default'):t('Выберите объект','Select object'));empty.value='';input.append(empty);}f.choices.forEach(c=>{const option=el('option','',c);option.value=c;input.append(option);});}
      else {input=el('input');input.type=f.type||'text';}
      input.setAttribute('aria-label',f.label);input.name=f.key;input.required=!f.optional&&f.type!=='checkbox';input.autocomplete=f.type==='password'?'new-password':'off';
      if(f.type==='checkbox')input.checked=!!f.value;else input.value=defaults[f.key]??f.value??((f.key==='ou'||f.key==='parentDN')?selectedContainer:'');
      if(f.multiple){const selected=String(defaults[f.key]??f.value??'').split(';');for(const o of input.options)o.selected=selected.includes(o.value);}
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
      inputs.forEach(([f,input])=>{if(f.multiple)body[f.key]=Array.from(input.selectedOptions,o=>o.value);else if(f.type==='checkbox')body[f.key]=input.checked;else if(input.value!==''||!f.optional)body[f.key]=f.numeric?Number(input.value):f.array?input.value.split(';').map(v=>v.trim()).filter(Boolean):f.type==='password'?input.value:input.value.trim();});
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
  async function openScope(initialDN=''){
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();const title=el('h2','',t('Область действия и наследование GPO','GPO scope and inheritance'));title.id='operation-title';const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');dialog.append(title,notice,body,button(t('Закрыть','Close'),closeOperation));if(!dialog.open)dialog.showModal();let model,selected=initialDN,serial=0;
    async function refresh(){message(notice,t('Загрузка…','Loading…'));try{model=await request('/gpo/scope');if(generation!==dialogGeneration)return;if(!model.containers.some(c=>c.dn===selected))selected=model.containers.find(c=>!c.parent)?.dn;render();message(notice,'');}catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}}
    function render(){body.replaceChildren();const layout=el('div','policy-layout'),nav=el('nav','directory-tree policy-navigation'),panel=el('section','policy-detail');layout.append(nav,panel);body.append(layout);nav.setAttribute('aria-label',t('Домен и подразделения','Domain and OUs'));
      function branch(parent,dn){for(const c of model.containers.filter(c=>c.parent.toLowerCase()===dn.toLowerCase())){const d=el('details');d.open=true;const summary=el('summary');summary.append(button(c.name+(c.block?' ⛔':''),()=>{selected=c.dn;render();},selected===c.dn?'selected':''));d.append(summary);branch(d,c.dn);parent.append(d);}}branch(nav,'');
      const c=model.containers.find(c=>c.dn===selected);if(!c)return;panel.append(el('h3','',c.name),el('p','mono',c.dn));let links=c.links.map(l=>({...l}));const form=el('form','workspace-form');const block=el('input');block.type='checkbox';block.checked=c.block;block.disabled=!admin;const blockLabel=el('label','',t('Блокировать наследование','Block inheritance'));blockLabel.prepend(block);form.append(blockLabel);const list=el('div');form.append(list);
      function renderLinks(){list.replaceChildren();links.forEach((link,i)=>{const card=el('div','scope-link');card.append(el('strong','',(i+1)+'. '+link.name));for(const [key,label] of [['enabled',t('Ссылка включена','Link enabled')],['enforced',t('Принудительно','Enforced')]]){const input=el('input');input.type='checkbox';input.checked=link[key];input.disabled=!admin;input.addEventListener('change',()=>link[key]=input.checked);const l=el('label','',label);l.prepend(input);card.append(l);}if(link.missing)card.append(el('p','alert error',t('GPO не найдена','GPO not found')));if(admin){for(const [label,delta] of [['↑',-1],['↓',1]]){const b=button(label,()=>{[links[i],links[i+delta]]=[links[i+delta],links[i]];renderLinks();});b.setAttribute('aria-label',(delta<0?t('Повысить приоритет ','Move up '):t('Понизить приоритет ','Move down '))+link.name);b.disabled=i+delta<0||i+delta>=links.length;card.append(b);}card.append(button(t('Отвязать','Unlink'),()=>{links.splice(i,1);renderLinks();}));}if(link.guid)card.append(button(t('Фильтрация безопасности','Security filtering'),()=>openFilter({guid:link.guid})));list.append(card);});if(!links.length)list.append(el('p','muted',t('Прямых ссылок нет','No direct links')));}
      renderLinks();if(admin){const policies=el('select');policies.setAttribute('aria-label',t('Добавить GPO','Add GPO'));for(const p of model.policies){const o=el('option','',p.displayName);o.value=p.dn;policies.append(o);}form.append(policies,button(t('Добавить ссылку','Add link'),()=>{const p=model.policies.find(p=>p.dn===policies.value);if(p&&!links.some(l=>l.dn.toLowerCase()===p.dn.toLowerCase())){links.push({dn:p.dn,name:p.displayName,guid:p.guid,enabled:true,enforced:false});renderLinks();}}));const confirm=el('input');confirm.type='checkbox';confirm.required=true;const label=el('label','',t('Подтверждаю изменение ссылок и наследования','Confirm link and inheritance changes'));label.prepend(confirm);form.append(label);const save=el('button','',t('Сохранить область действия','Save scope'));save.type='submit';form.append(save);form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;save.disabled=true;try{await request('/gpo/scope','PUT',{container:c.dn,revision:c.revision,block:block.checked,links:links.map(l=>({dn:l.dn,enabled:l.enabled,enforced:l.enforced}))});if(generation!==dialogGeneration)return;await refresh();message(notice,t('Область действия сохранена','Scope saved'));}catch(e){if(generation===dialogGeneration){message(notice,e.message,true);save.disabled=e.status===409;panel.append(button(t('Перезагрузить','Reload'),refresh));}}});}
      panel.append(form,el('h3','',t('Наследование: сначала высокий приоритет','Inheritance: highest precedence first')),el('p','muted',t('Предпросмотр ссылок домена и OU. Сайт, права получателя, WMI, loopback и результат gpupdate здесь не вычисляются. Порядок 1 — высший приоритет.','Domain/OU link preview. Site, target permissions, WMI, loopback and client results are not evaluated. Order 1 has highest precedence.')));const preview=el('div');panel.append(preview);const id=++serial;request('/gpo/scope?container='+enc(c.dn)).then(result=>{if(generation!==dialogGeneration||id!==serial)return;const reason={candidate:t('Кандидат','Candidate'),disabled:t('Ссылка отключена','Link disabled'),blocked:t('Заблокирована наследованием','Blocked by inheritance'),missing:t('GPO не найдена','GPO missing'),'unknown-options':t('Неизвестные параметры','Unknown options')};topologyTable(preview,result.map(l=>({...l,state:reason[l.reason],sections:l.flags===3?t('Оба раздела отключены','Both disabled'):l.flags===1?t('Пользователь отключён','User disabled'):l.flags===2?t('Компьютер отключён','Computer disabled'):t('Оба включены','Both enabled')})),[['name','GPO'],['source',t('Источник','Source')],['state',t('Состояние','State')],['enforced',t('Принудительно','Enforced')],['sections',t('Разделы','Sections')],['wmi','WMI']]);}).catch(e=>{if(generation===dialogGeneration&&id===serial)message(preview,e.message,true);});
    }await refresh();
  }
  async function openFilter(row){
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();const title=el('h2','',t('Фильтрация безопасности GPO','GPO security filtering'));title.id='operation-title';const notice=el('p','workspace-message'),body=el('div');notice.setAttribute('aria-live','polite');dialog.append(title,el('p','',t('Здесь изменяется только явное разрешение «Применять групповую политику». Чтение GPO и SYSVOL должно быть разрешено отдельно. Удаление разрешения не является запретом: доступ может оставаться через группы. Наследуемые, запрещающие и совмещённые права доступны только для просмотра.','Only explicit Apply Group Policy permissions are edited here. GPO and SYSVOL read access must also exist. Removing an allow is not a deny: groups may still grant access. Inherited, deny and combined rights are read only.')),notice,body,button(t('Закрыть','Close'),closeOperation));if(!dialog.open)dialog.showModal();const path='/gpo/'+enc(row.guid)+'/filter';let model;
    async function change(payload){dialog.querySelectorAll('button').forEach(b=>b.disabled=true);try{await request(path,'PUT',{...payload,revision:model.revision});if(generation!==dialogGeneration)return;await refresh();message(notice,t('Фильтр сохранён','Filter saved'));}catch(e){if(generation===dialogGeneration){message(notice,e.message,true);body.replaceChildren(button(t('Перезагрузить','Reload'),refresh));}}finally{if(generation===dialogGeneration)dialog.querySelectorAll('button').forEach(b=>b.disabled=false);}}
    async function refresh(){message(notice,t('Загрузка…','Loading…'));try{const [data,groups,users,computers]=await Promise.all([request(path),admin?request('/groups'):[],admin?request('/users'):[],admin?request('/computers'):[]]);if(generation!==dialogGeneration)return;model=data;body.replaceChildren();for(const entry of model.entries){const card=el('div','scope-link');const deny=[1,6].includes(entry.type);card.append(el('strong','',entry.name||entry.sid||t('Нестандартная ACE','Nonstandard ACE')),el('p','mono',entry.sid+' · 0x'+entry.mask.toString(16)),el('p','', (deny?t('Запрет','Deny'):t('Разрешение/другая ACE','Allow/other ACE'))+' · '+(entry.apply?t('Применение GPO','Apply GPO'):t('Другие права','Other rights'))+(entry.inherited?' · '+t('Наследуется','Inherited'):'')));if(admin&&entry.editable){const form=el('form');const check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю удаление разрешения','Confirm removing this allow'));label.prepend(check);const b=el('button','danger',t('Удалить разрешение','Remove allow'));b.type='submit';form.append(label,b);form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())change({remove:entry.id});});card.append(form);}body.append(card);}
      if(admin){const form=el('form','workspace-form'),select=el('select');select.setAttribute('aria-label',t('Получатель разрешения','Permission recipient'));const all=el('option','','Authenticated Users');all.value='S-1-5-11';form.append(select);select.append(all);for(const [label,list] of [[t('Группы','Groups'),groups],[t('Пользователи','Users'),users],[t('Компьютеры','Computers'),computers]]){const group=el('optgroup');group.label=label;for(const p of list){const o=el('option','',p.samAccountName);o.value=p.dn;group.append(o);}select.append(group);}const check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю предоставление права применения','Confirm granting Apply Group Policy'));label.prepend(check);const save=el('button','',t('Разрешить применение','Allow application'));save.type='submit';form.append(label,save);form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())change({principal:select.value});});body.append(form);}message(notice,'');
    }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}}await refresh();
  }
  async function openTopology(){
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Топология репликации','Replication topology'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    dialog.append(title,notice,button(t('Обновить','Refresh'),refresh),body,button(t('Закрыть','Close'),closeOperation));if(!dialog.open)dialog.showModal();
    let serial=0;
    async function refresh(){const current=++serial;body.replaceChildren();message(notice,t('Загрузка…','Loading…'));
      try{const [topology,connections]=await Promise.all([request('/sites/topology'),request('/repl/connections')]);if(generation!==dialogGeneration||current!==serial)return;
        const dcs=topology.controllers||[];message(notice,'');
        body.append(el('p','muted',t('Стрелки показывают направление источник → назначение. Сплошная линия — включено, пунктир — отключено. Это конфигурация AD, а не подтверждение исправности репликации.','Arrows show source → destination. Solid: enabled; dashed: disabled. AD configuration does not confirm replication health.')));
        const map=el('div','topology-map');const width=720,height=Math.max(180,Math.ceil(dcs.length/3)*145+40);map.style.aspectRatio=width+'/'+height;
        const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox',`0 0 ${width} ${height}`);svg.setAttribute('aria-hidden','true');map.append(svg);
        const shape=(tag,attrs)=>{const n=document.createElementNS(svg.namespaceURI,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,v);return n;};
        const defs=shape('defs',{}),marker=shape('marker',{id:'topology-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:7,markerHeight:7,orient:'auto-start-reverse'});marker.append(shape('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#477887'}));defs.append(marker);svg.append(defs);
        const positions=new Map(dcs.map((dc,i)=>[dc.dns.toLowerCase(),{x:width/(Math.min(3,dcs.length-Math.floor(i/3)*3)+1)*((i%3)+1),y:80+Math.floor(i/3)*145}]));
        const missing=[];for(const connection of connections){const from=positions.get(connection.source.toLowerCase()),to=positions.get(connection.destination.toLowerCase());if(!from||!to){missing.push(connection);continue;}const reverse=connections.some(c=>c.source.toLowerCase()===connection.destination.toLowerCase()&&c.destination.toLowerCase()===connection.source.toLowerCase());const offset=reverse?18:0,dx=to.x-from.x,dy=to.y-from.y,length=Math.hypot(dx,dy)||1;const line=shape('polyline',{points:`${from.x},${from.y} ${(from.x+to.x)/2-dy/length*offset},${(from.y+to.y)/2+dx/length*offset} ${to.x},${to.y}`,fill:'none',stroke:'#477887','stroke-width':2,'stroke-dasharray':connection.enabled?'':'7 5','marker-mid':'url(#topology-arrow)'});const hint=shape('title',{});hint.textContent=connection.source+' → '+connection.destination+(connection.automatic?' (KCC)':'');line.append(hint);svg.append(line);}
        const form=el('form','workspace-form');const source=el('select'),destination=el('select');source.name='source';destination.name='destination';
        for(const select of [source,destination]){select.required=true;const empty=el('option','',t('Выберите контроллер','Select controller'));empty.value='';select.append(empty);for(const dc of dcs){const option=el('option','',dc.dns+' · '+dc.site);option.value=dc.dns;select.append(option);}}
        const update=()=>{map.querySelectorAll('.topology-node').forEach(n=>{n.classList.toggle('source',n.dataset.dc===source.value);n.classList.toggle('destination',n.dataset.dc===destination.value);});destination.setCustomValidity(source.value&&source.value===destination.value?t('Выберите разные контроллеры','Choose different controllers'):'');confirm.checked=false;};
        let dragged='';for(const dc of dcs){const point=positions.get(dc.dns.toLowerCase());const node=button(dc.name+'\n'+dc.site,()=>{if(!admin)return;if(!source.value||destination.value){source.value=dc.dns;destination.value='';}else destination.value=dc.dns;update();},'topology-node');node.title=dc.dns;node.style.left=point.x/width*100+'%';node.style.top=point.y/height*100+'%';node.draggable=admin;node.dataset.dc=dc.dns;
          node.addEventListener('dragstart',e=>{dragged=dc.dns;e.dataTransfer.setData('text/plain',dc.dns);e.dataTransfer.effectAllowed='link';});node.addEventListener('dragend',()=>{dragged='';});node.addEventListener('dragover',e=>{if(admin&&dragged&&dragged!==dc.dns){e.preventDefault();e.dataTransfer.dropEffect='link';}});node.addEventListener('drop',e=>{e.preventDefault();if(!admin||!dragged||dragged===dc.dns)return;source.value=dragged;destination.value=dc.dns;dragged='';update();form.scrollIntoView({block:'nearest'});});map.append(node);}
        body.append(map);if(!dcs.length)body.append(el('p','muted',t('Контроллеры не найдены','No controllers found')));
        if(missing.length)body.append(el('p','alert error',t('Некоторые соединения ссылаются на отсутствующие контроллеры: ','Some connections reference missing controllers: ')+missing.length));
        const confirm=el('input');confirm.type='checkbox';confirm.required=true;
        if(admin){body.append(el('p','',t('Перетащите источник на назначение или нажмите два узла по очереди. Можно также выбрать контроллеры из списков. Связь создаётся только после подтверждения.','Drag the source onto the destination or click two nodes in order. You can also use the lists. Confirm before creating the connection.')));
          for(const [labelText,select] of [[t('Источник','Source'),source],[t('Назначение','Destination'),destination]]){const label=el('label','',labelText);select.setAttribute('aria-label',labelText);label.append(select);form.append(label);select.addEventListener('change',update);}
          const confirmation=el('label','',t('Подтверждаю создание соединения источник → назначение','Confirm creating the source → destination connection'));confirmation.prepend(confirm);form.append(confirmation);const save=el('button','',t('Создать соединение','Create connection'));save.type='submit';save.disabled=dcs.length<2;form.append(save);body.append(form);if(dcs.length<2)form.append(el('p','muted',t('Для соединения нужны как минимум два контроллера.','At least two controllers are required.')));
          form.addEventListener('submit',async e=>{e.preventDefault();updateValidity();if(!form.reportValidity())return;const payload={source:source.value,destination:destination.value};if(connections.some(c=>c.source.toLowerCase()===payload.source.toLowerCase()&&c.destination.toLowerCase()===payload.destination.toLowerCase())){message(notice,t('Такое соединение уже существует','This connection already exists'),true);return;}save.disabled=true;try{await request('/repl/connections','POST',payload);if(generation!==dialogGeneration)return;await refresh();message(notice,t('Соединение создано','Connection created'));}catch(err){if(generation===dialogGeneration){message(notice,err.message,true);save.disabled=false;}}});
          function updateValidity(){destination.setCustomValidity(source.value===destination.value?t('Выберите разные контроллеры','Choose different controllers'):'');}
        }
        const list=el('details');list.append(el('summary','',t('Соединения и операции','Connections and actions')));renderResult(connections,list,{path:'/repl/connections'});body.append(list);
      }catch(err){if(generation===dialogGeneration&&current===serial)message(notice,err.message,true);}
    }
    await refresh();
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
    if(cfg===configs['/gpo']){describeTree(result,parent);return;}
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
