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
      actions:[view(t('Свойства','Properties'),r=>'/groups/'+enc(r.samAccountName)),{...view(t('Участники','Members'),r=>'/groups/'+enc(r.samAccountName)+'/members'),groupMembers:true},
        {label:t('Добавить участника','Add member'),method:'POST',groupMembers:true},
        {label:t('Исключить участника','Remove member'),method:'DELETE',groupMembers:true},remove(r=>'/groups/'+enc(r.samAccountName))]},
    '/computers':{title:t('Компьютеры','Computers'),endpoint:'/computers',directory:'computers',id:r=>r.samAccountName,
      columns:[['samAccountName',t('Имя','Name')],['dnsHostName','DNS'],['operatingSystem',t('ОС','OS')],['whenCreated',t('Дата создания','Created')],['dn','DN']],
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
      actions:[{...view(t('Записи','Records'),r=>'/dns/zones/'+enc(r.name)+'/records',queryFields()),dnsEditor:true},
        remove(r=>'/dns/zones/'+enc(r.name))]},
    '/gpo':{title:t('Групповые политики','Group policies'),endpoint:'/gpo',id:gpoID,
      hint:t('Политики хранятся отдельно от ссылок на OU. Доставка SYSVOL не подтверждает применение на клиенте.','Policies and OU links are separate. SYSVOL distribution does not confirm client application.'),
      columns:[['displayName',t('Политика','Policy')],['guid','GUID'],['source',t('Источник','Source')]],
      create:action(t('Создать GPO','Create GPO'),'POST','/gpo',[name()]),
      toolbar:[{label:t('Почему применяется GPO','Why a GPO applies'),method:'GET',explain:true},{label:t('Моделирование политики','Policy modeling'),method:'GET',model:true},view(t('Ссылки на контейнер','Container links'),'/gpo/links',[dn('container')]),{label:t('Область действия','Scope and inheritance'),method:'GET',scope:true},action(t('Восстановить в новую GPO','Restore as new GPO'),'POST','/gpo/restore',[text('name','Имя новой политики','New policy name'),text('path','Каталог копии policy/{GUID} на сервере','Backup policy/{GUID} directory on server')],{confirm:true})],
      actions:[view(t('Свойства','Properties'),r=>'/gpo/'+enc(gpoID(r))),
 {label:t('Согласованность SYSVOL','SYSVOL consistency'),method:'GET',consistency:true},
 {label:t('Исправление SYSVOL','Repair SYSVOL'),method:'PUT',repair:true},
 {label:t('Делегирование LDAP/SYSVOL','LDAP/SYSVOL delegation'),method:'PUT',fullDelegation:true},
 {label:t('Права объекта LDAP','LDAP object permissions'),method:'GET',delegation:true},
 {label:t('Фильтрация безопасности','Security filtering'),method:'GET',filter:true},
 {...view(t('Параметры ALT','ALT settings'),r=>'/gpo/'+enc(gpoID(r))+'/alt-settings'),editor:true},
        view(t('Сценарии','Scripts'),r=>'/gpo/'+enc(gpoID(r))+'/scripts'),
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
        view(t('Свойства','Properties'),r=>'/shares/'+enc(r.name)),action(t('Параметр Samba','Samba parameter'),'POST',r=>'/shares/'+enc(r.name)+'/param',[text('key','Параметр','Parameter',{list:'samba-parameters',placeholder:'read only'}),text('value','Значение','Value',{optional:true})],{sambaParam:true,help:t('Изменяет параметр выбранной секции в smb.conf на сервере sambaadm и перечитывает конфигурацию Samba. Например: read only = yes — только чтение; browseable = no — скрыть из списка; valid users = @Finance — разрешить группе. Права файловой системы настраиваются в «Права и ACL».','Updates this share section in smb.conf on the sambaadm host and reloads Samba configuration. Examples: read only = yes; browseable = no; valid users = @Finance. Configure filesystem permissions under Access and ACL.')}),remove(r=>'/shares/'+enc(r.name))]},
    '/printers':{title:t('Принтеры','Printers'),endpoint:'/printers',id:r=>r.name,
      columns:[['name',t('Имя','Name')],['printerName',t('Очередь','Queue')],['path',t('Путь','Path')]],
      create:{label:t('Добавить принтер','Add printer'),href:'/printers/new',method:'POST'},actions:[remove(r=>'/printers/'+enc(r.name))]}
  };
  const sambaParameters=el('datalist');sambaParameters.id='samba-parameters';for(const key of ['comment','browseable','read only','valid users','write list','read list','create mask','directory mask','inherit acls','map acl inherit']){const option=el('option');option.value=key;sambaParameters.append(option);}root.append(sambaParameters);
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
    if(!response.ok) {const hint=result.code==='upstream_access_denied'?t('Служебной учётной записи ldap.bind.user не хватает прав в AD. Вход администратором в браузере не меняет эту учётную запись. ','The configured ldap.bind.user lacks AD permissions. Browser login does not change this account. '):(result.hint?result.hint+' ':'');const error=new Error(hint+(result.error || `HTTP ${response.status}`));error.status=response.status;throw error;}
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
  function attributeValue(key, values) {
    key=key.toLowerCase();
    const filetime=['accountexpires','pwdlastset','lastlogontimestamp','lastlogon','lockouttime'].includes(key);
    if(!filetime&&!['whencreated','whenchanged'].includes(key))return undefined;
    return (Array.isArray(values)?values:[values]).map(raw=>{
      if(raw==null||raw==='')return '—';
      const text=String(raw);let date;
      if(filetime){
        if(!/^\d+$/.test(text))return text;
        const ticks=BigInt(text);
        if(key==='accountexpires'&&(ticks===0n||ticks===9223372036854775807n))return t('Никогда','Never');
        if(ticks===0n)return key==='pwdlastset'?t('Сменить пароль при следующем входе','Change password at next sign-in'):key==='lockouttime'?t('Не заблокирована','Not locked'):t('Нет данных о входе','No sign-in recorded');
        date=new Date(Number(ticks/10000n-11644473600000n));
      }else{
        const match=/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d+))?(Z|[+-]\d{4})$/.exec(text);
        if(!match)return text;
        const [,y,m,d,h,min,sec,fraction,zone]=match;
        date=new Date(`${y}-${m}-${d}T${h}:${min}:${sec}.${(fraction||'0').slice(0,3).padEnd(3,'0')}${zone==='Z'?'Z':zone.slice(0,3)+':'+zone.slice(3)}`);
      }
      return Number.isNaN(date.getTime())?text:date.toLocaleString(ru?'ru-RU':'en-US',{timeZoneName:'short'});
    }).join('; ');
  }
  function normalizeSearch(text){return text.normalize('NFKC').toLocaleLowerCase().trim();}
  function renderRows() {
    tbody.replaceChildren();let count=0;
    for(const row of rows) {
      if(selectedIDs && !selectedIDs.has((row.dn||'').toLowerCase()))continue;
      if(selectedObject && cfg.id(row)!==selectedObject)continue;
      if(search && !normalizeSearch(search).split(/\s+/).every(word=>normalizeSearch(JSON.stringify(row)).includes(word)))continue;
      count++;const r=el('tr');
      cfg.columns.forEach(([key])=>{const cell=el('td',key==='dn'?'mono':'',attributeValue(key,row[key])??value(key==='displayName'?(row[key]||row.name):row[key]));r.append(cell);});
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
      if(cfg===configs['/gpo']){const branch=el('details');branch.append(el('summary','',t('Параметры политики','Policy settings')));for(const a of cfg.actions.slice(0,4))branch.append(button(a.label,()=>openOperation(a,row)));li.append(branch);}
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
    const dl=el('dl','workspace-properties');Object.entries(result).forEach(([k,v])=>{dl.append(el('dt','',k));const dd=el('dd');const formatted=attributeValue(k,v);if(formatted!==undefined){dd.append(el('span','',formatted));const raw=el('details');raw.append(el('summary','',t('Исходное значение LDAP','Raw LDAP value')),el('code','',Array.isArray(v)?v.join('; '):String(v)));dd.append(raw);}else if(v&&typeof v==='object')describe(v,dd);else dd.textContent=value(v);dl.append(dd);});parent.append(dl);
  }
  function describeTree(data,parent){
    if(!data||typeof data!=='object'){describe(data,parent);return;}
    const list=el('ul','directory-tree');for(const [name,item] of Object.entries(data)){const li=el('li');const branch=el('details');branch.append(el('summary','',name));describeTree(item,branch);li.append(branch);list.append(li);}parent.append(list);
  }
  function closeOperation(){dialogGeneration++;dialog.close();dialog.replaceChildren();if(lastFocus?.isConnected)lastFocus.focus();}
  dialog.addEventListener('cancel',e=>{e.preventDefault();closeOperation();});
  async function openGroupMembers(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Участники группы','Group members'));title.id='operation-title';
    const notice=el('p','workspace-message'),members=el('div'),results=el('div');notice.setAttribute('aria-live','polite');
    dialog.append(title,el('p','',row.samAccountName),el('p','muted',t('Участниками могут быть пользователи, группы и компьютеры. Основная группа пользователя задаётся атрибутом primaryGroupID и не отображается в списке прямого членства.','Members may be users, groups or computers. A user’s primary group is set by primaryGroupID and is not listed as direct membership.')),notice,members);
    const path='/groups/'+enc(row.samAccountName)+'/members';let current=new Set(),serial=0;
    async function change(memberDN,method,trigger){
      trigger.disabled=true;
      try{await request(path,method,{memberDN});if(generation!==dialogGeneration)return;await refresh();serial++;results.replaceChildren();message(notice,t('Членство обновлено','Membership updated'));await load();}
      catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}
      finally{trigger.disabled=false;}
    }
    async function refresh(){
      const list=await request(path);if(generation!==dialogGeneration)return;
      current=new Set((list||[]).map(dn=>dn.toLowerCase()));members.replaceChildren(el('h3','',t('Прямые участники','Direct members')));
      if(!current.size)members.append(el('p','muted',t('Прямых участников нет','No direct members')));
      for(const member of list||[]){const line=el('div','scope-link');line.append(el('span','mono',member));if(admin){const confirmation=el('input');confirmation.type='checkbox';const label=el('label','',t('Подтверждаю исключение','Confirm removal'));label.prepend(confirmation);const remove=button(t('Исключить','Remove'),()=>{if(confirmation.checked)change(member,'DELETE',remove);},'danger');remove.disabled=true;confirmation.addEventListener('change',()=>remove.disabled=!confirmation.checked);line.append(label,remove);}members.append(line);}
    }
    if(admin){
      const search=el('form','workspace-filter'),input=el('input');input.type='search';input.required=true;input.placeholder=t('Имя или логин участника','Member name or login');input.setAttribute('aria-label',input.placeholder);
      const kind=el('select');kind.setAttribute('aria-label',t('Тип участника','Member type'));for(const [key,label] of [['users',t('Пользователи','Users')],['groups',t('Группы','Groups')],['computers',t('Компьютеры','Computers')]]){const option=el('option','',label);option.value=key;kind.append(option);}
      const find=el('button','',t('Найти участника','Find member'));find.type='submit';search.append(input,kind,find);dialog.append(el('h3','',t('Добавить участника','Add member')),search,results);
      kind.addEventListener('change',()=>{serial++;results.replaceChildren();});input.addEventListener('input',()=>{serial++;results.replaceChildren();});
      search.addEventListener('submit',async e=>{e.preventDefault();if(!search.reportValidity())return;const id=++serial;find.disabled=true;message(notice,t('Поиск…','Searching…'));
        try{const matches=await request('/'+kind.value+'?q='+enc(input.value.trim()));if(generation!==dialogGeneration||id!==serial)return;results.replaceChildren();let count=0;
          for(const match of matches){if(match.dn.toLowerCase()===row.dn.toLowerCase())continue;count++;const line=el('div','scope-link');line.append(el('strong','',match.samAccountName),el('p','mono',match.dn));const add=button(t('Добавить','Add'),()=>change(match.dn,'POST',add));add.disabled=current.has(match.dn.toLowerCase());line.append(add);results.append(line);}
          message(notice,count?'':t('Объекты не найдены','No objects found'));
        }catch(e){if(generation===dialogGeneration&&id===serial)message(notice,e.message,true);}finally{find.disabled=false;}
      });
    }
    dialog.append(button(t('Закрыть','Close'),closeOperation));dialog.showModal();message(notice,t('Загрузка…','Loading…'));
    try{await refresh();if(generation===dialogGeneration)message(notice,'');}catch(e){if(generation===dialogGeneration){message(notice,e.message,true);members.append(button(t('Повторить','Retry'),()=>openGroupMembers(row)));}}
  }
  async function openScriptsEditor(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Сценарии групповой политики','Group policy scripts'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    dialog.append(title,el('p','',row.displayName||row.guid),el('p','muted',t('Команды выполняются на клиентах при обработке политики. Сохраняется выбранное событие и тип сценариев. Удаление назначения сохраняет файл в SYSVOL.','Commands run on clients during policy processing. Save updates the selected event and script type. Removing an assignment retains its SYSVOL file.')),notice,body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    if(admin)title.after(button(t('Резервные копии и восстановление','Backups and recovery'),()=>openScriptMaintenance(row)));
    const path='/gpo/'+enc(row.guid)+'/scripts';let model,scope='Machine',event='startup',kind='script',entries=[],pending=[],dirty=false,busy=false,conflict=false;
    const current=()=>generation===dialogGeneration;
    const eventNames={startup:t('Запуск','Startup'),shutdown:t('Завершение работы','Shutdown'),logon:t('Вход','Logon'),logoff:t('Выход','Logoff')};
    async function refresh(){busy=true;body.replaceChildren();message(notice,t('Чтение SYSVOL…','Reading SYSVOL…'));try{const data=await request(path);if(!current())return;model=data;conflict=false;reset();message(notice,'');}catch(e){if(current()){message(notice,e.message,true);body.replaceChildren(button(t('Повторить','Retry'),refresh));}}finally{busy=false;}}
    function reset(){entries=(model.scripts||[]).filter(s=>s.scope===scope&&s.event===event&&s.kind===kind).sort((a,b)=>a.order-b.order).map(s=>({command:s.command,parameters:s.parameters}));pending=[];dirty=false;render();}
    function render(){
      body.replaceChildren();body.append(el('p','mono',model.controller+' · '+t('Версия ','Version ')+model.version));
      if(scope==='Machine'?model.machineDisabled:model.userDisabled)body.append(el('p','alert',t('Этот раздел GPO отключён. Сценарии не применятся, пока раздел не будет включён.','This GPO scope is disabled. Scripts will not apply until the scope is enabled.')));
      const selectors=el('div','workspace-tools');
      function selector(label,values,value,change){const l=el('label','',label),input=el('select');input.setAttribute('aria-label',label);for(const [key,label]of values){const option=el('option','',label);option.value=key;input.append(option);}input.value=value;input.disabled=dirty;input.addEventListener('change',()=>{change(input.value);reset();});l.append(input);selectors.append(l);return input;}
      const selects=[];selects.push(selector(t('Раздел сценариев','Script scope'),[['Machine',t('Компьютер','Computer')],['User',t('Пользователь','User')]],scope,v=>{scope=v;event=v==='Machine'?'startup':'logon';}));
      selects.push(selector(t('Событие сценариев','Script event'),(scope==='Machine'?['startup','shutdown']:['logon','logoff']).map(k=>[k,eventNames[k]]),event,v=>event=v));
      selects.push(selector(t('Тип сценариев','Script type'),[['script',t('Обычные сценарии','Standard scripts')],['PowerShell','PowerShell']],kind,v=>kind=v));body.append(selectors);
      const form=el('form','workspace-form'),list=el('div');form.append(list);body.append(form);
      let save,confirm;
      function changed(){dirty=true;selects.forEach(s=>s.disabled=true);if(confirm)confirm.checked=false;if(save)save.disabled=conflict;if(!conflict)message(notice,t('Есть несохранённые изменения. Сохраните или отмените их для перехода к другому событию.','Unsaved changes. Save or discard them before selecting another event.'));}
      if(!entries.length)list.append(el('p','muted',t('Сценарии не назначены','No scripts assigned')));
      entries.forEach((entry,i)=>{const card=el('fieldset');card.append(el('legend','',eventNames[event]+' · '+(i+1)));
        for(const [key,label]of [['command',t('Команда сценария','Script command')],['parameters',t('Аргументы сценария','Script arguments')]]){const l=el('label','',label),input=el('input');input.setAttribute('aria-label',label+' '+(i+1));input.value=entry[key]||'';input.disabled=!admin;input.required=key==='command';input.maxLength=key==='command'?259:8192;input.addEventListener('input',()=>{entry[key]=input.value;changed();});l.append(input);card.append(l);}
        if(admin){const actions=el('div','workspace-tools');for(const [label,delta]of [[t('Выше','Move up'),-1],[t('Ниже','Move down'),1]]){const move=button(label,()=>{[entries[i],entries[i+delta]]=[entries[i+delta],entries[i]];changed();render();});move.disabled=i+delta<0||i+delta>=entries.length;actions.append(move);}actions.append(button(t('Удалить назначение','Remove assignment'),()=>{entries.splice(i,1);changed();render();},'danger'));card.append(actions);}list.append(card);
      });
      if(admin)form.append(button(t('Добавить команду','Add command'),()=>{entries.push({command:'',parameters:''});changed();render();}));
      const files=el('section');files.append(el('h3','',t('Файлы выбранного события','Files for this event')));
      const assignedFiles=(model.files||[]).filter(f=>f.scope===scope&&f.event===event);
      if(!assignedFiles.length)files.append(el('p','muted',t('Файлов в каталоге события нет','No files in the event directory')));
      for(const file of assignedFiles){const line=el('p'),link=el('a','',file.name+' · '+file.size+' '+t('байт','bytes'));link.href=api+path+'/file?'+new URLSearchParams({scope,event,name:file.name,revision:model.revision});link.download=file.name;line.append(link);files.append(line);}
      if(admin){const label=el('label','',t('Загрузить и назначить файлы','Upload and assign files')),upload=el('input');upload.type='file';upload.multiple=true;upload.setAttribute('aria-label',t('Загрузить и назначить файлы','Upload and assign files'));label.append(upload);files.append(label,el('p','muted',t('До 2 МиБ на файл и 4 МиБ за сохранение. Совпадающее имя заменяет содержимое файла после сохранения.','Up to 2 MiB per file and 4 MiB per save. Matching names replace file contents when saved.')));
        upload.addEventListener('change',async()=>{const files=[...upload.files];if(!files.length)return;busy=true;form.querySelectorAll('button,input,select').forEach(e=>e.disabled=true);
          try{if(files.some(f=>f.size>2*1024*1024)||files.reduce((n,f)=>n+f.size,0)+pending.reduce((n,f)=>n+f.size,0)>4*1024*1024)throw Error(t('Превышен размер файлов','File size limit exceeded'));const staged=[];for(const file of files){const bytes=new Uint8Array(await file.arrayBuffer());let value='';for(let i=0;i<bytes.length;i+=32768)value+=String.fromCharCode(...bytes.subarray(i,i+32768));staged.push({name:file.name,data:btoa(value),size:file.size});}if(!current())return;for(const file of staged){pending=pending.filter(f=>f.name.toLowerCase()!==file.name.toLowerCase());pending.push(file);if(!entries.some(s=>s.command.toLowerCase()===file.name.toLowerCase()))entries.push({command:file.name,parameters:''});}changed();render();message(notice,t('Файлы подготовлены. Проверьте назначения и сохраните.','Files staged. Review assignments and save.'));}
          catch(e){if(current()){render();message(notice,e.message,true);}}finally{busy=false;}
        });
      }
      for(const file of pending)files.append(el('p','',t('Будет загружен: ','Will upload: ')+file.name+' · '+file.size+' '+t('байт','bytes')));form.append(files);
      if(admin){const l=el('label','',t('Подтверждаю сохранение сценариев выбранного раздела','Confirm saving scripts for this scope'));confirm=el('input');confirm.type='checkbox';confirm.required=true;l.prepend(confirm);save=el('button','',t('Сохранить сценарии','Save scripts'));save.type='submit';save.disabled=!dirty||conflict;form.append(l,save,button(t('Отменить изменения','Discard changes'),()=>{conflict=false;reset();message(notice,'');}));
        form.addEventListener('submit',async e=>{e.preventDefault();if(busy||conflict||!dirty||!form.reportValidity())return;busy=true;form.querySelectorAll('button,input,select').forEach(e=>e.disabled=true);message(notice,t('Сохранение с резервной копией…','Saving with backup…'));
          try{const result=await request(path,'PUT',{revision:model.revision,scope,event,kind,entries:entries.map(s=>({...s})),files:pending.map(({name,data})=>({name,data}))});if(!current())return;model=result;reset();message(notice,t('Сценарии сохранены. Проверьте применение на клиенте.','Scripts saved. Verify client application.'));if(result.backup)body.append(el('p','muted',t('Резервная копия в каталоге GPO: ','Backup in the GPO directory: ')+result.backup));if(result.backupWarning)body.append(el('p','alert',result.backupWarning));}
          catch(e){if(!current())return;conflict=true;render();message(notice,e.message+t(' Правки сохранены в форме. Перечитайте политику перед повторным сохранением.','Your edits remain in the form. Reload the policy before saving again.'),true);body.append(button(t('Перечитать и сбросить правки','Reload and discard edits'),refresh));}finally{busy=false;}
        });
      }
    }
    await refresh();
  }
  async function openScriptMaintenance(row){
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();const title=el('h2','',t('Резервные копии и восстановление','Backups and recovery'));title.id='operation-title';
    const notice=el('p','workspace-message'),list=el('div'),preview=el('section');notice.setAttribute('aria-live','polite');dialog.append(title,el('p','',row.displayName||row.guid),notice,list,preview,button(t('Вернуться к сценариям','Back to scripts'),()=>openScriptsEditor(row)),button(t('Закрыть','Close'),closeOperation));if(!dialog.open)dialog.showModal();
    const path='/gpo/'+enc(row.guid)+'/scripts';let state,working=false;const current=()=>generation===dialogGeneration;
    async function refresh(){message(notice,t('Загрузка копий…','Loading backups…'));try{const data=await request(path+'/maintenance');if(!current())return;state=data;preview.replaceChildren();render();message(notice,'');}catch(e){if(current())message(notice,e.message,true);}}
    function download(name,label){const link=el('a','btn',label);link.href=api+path+'/backup?'+new URLSearchParams({name,revision:state.revision});link.download=name==='pending'?'sambaadm-pending-recovery.json':name;return link;}
    async function apply(payload){if(working)return;working=true;dialog.querySelectorAll('button,input').forEach(e=>e.disabled=true);message(notice,t('Применение…','Applying…'));try{await request(path+'/maintenance','POST',payload);if(!current())return;await refresh();message(notice,payload.operation==='restore'?t('Восстановление завершено. Версия GPO обновлена.','Recovery completed. GPO version updated.'):t('Список копий обновлён','Backups updated'));}catch(e){if(current()){message(notice,e.message,true);preview.replaceChildren();list.append(button(t('Перезагрузить список','Reload backups'),refresh));}}finally{working=false;if(current())dialog.querySelectorAll('button,input').forEach(e=>e.disabled=false);}}
    function render(){list.replaceChildren();list.append(el('p','',t('Копий: ','Backups: ')+state.backups.length+' · '+state.totalBytes+' '+t('байт. Лимит: ','bytes. Limit: ')+state.keep+' / '+Math.round(state.maxBytes/1048576)+' MiB'),el('p','muted',t('Последняя копия защищена от удаления. При незавершённом сохранении очистка приостанавливается.','The newest backup is protected. Retention pauses while recovery is pending.')));
      if(state.pending){const panel=el('div','alert');panel.append(el('strong','',t('Обнаружено незавершённое сохранение','An unfinished save was found')),el('p','',t('Сначала просмотрите состояние файлов и выберите возврат к исходному состоянию или завершение сохранения.','Preview file states, then choose to roll back or complete the save.')),download('pending',t('Скачать журнал','Download journal')));if(state.recoveryError)panel.append(el('p','error',state.recoveryError),el('p','',t('Можно выбрать корректную резервную копию и явно подтвердить замену повреждённого журнала.','Choose a valid backup to explicitly replace a damaged journal.')));else panel.append(button(t('Предпросмотр возврата','Preview rollback'),()=>showPreview('pending','before')),button(t('Предпросмотр завершения','Preview completion'),()=>showPreview('pending','after')));list.append(panel);}
      if(!state.backups.length)list.append(el('p','muted',t('Резервных копий пока нет','No backups yet')));
      for(const item of state.backups){const card=el('article','scope-link');card.append(el('p','mono',item.name),el('p','',new Date(item.modified).toLocaleString()+' · '+item.size+' '+t('байт','bytes')),download(item.name,t('Скачать копию','Download backup')),button(t('Предпросмотр восстановления','Preview restore'),()=>showPreview(item.name,'before')));
        if(!item.protected){const form=el('form','workspace-tools'),check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю удаление этой копии','Confirm deleting this backup'));label.prepend(check);const remove=el('button','danger',t('Удалить копию','Delete backup'));remove.type='submit';form.append(label,remove);form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())apply({operation:'delete',source:item.name,revision:state.revision});});card.append(form);}list.append(card);
      }
      if(!state.pending&&state.prunable.length){const form=el('form','workspace-form');form.append(el('p','',t('Очистка удалит копии сверх лимита: ','Retention will delete: ')+state.prunable.join(', ')));const check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю очистку копий сверх лимита','Confirm pruning backups above the limit'));label.prepend(check);const run=el('button','',t('Очистить по лимитам','Apply retention'));run.type='submit';form.append(label,run);form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())apply({operation:'prune',revision:state.revision});});list.append(form);}
    }
    async function showPreview(source,mode){if(working)return;message(notice,t('Проверка состояния файлов…','Checking file states…'));try{const plan=await request(path+'/preview?'+new URLSearchParams({source,mode}));if(!current())return;preview.replaceChildren(el('h3','',t('План восстановления','Recovery plan')),el('p','',plan.scope+' · '+t('Версия ','Version ')+plan.version+' → '+plan.nextVersion),el('p','muted',t('Восстанавливаются перечисленные файлы целиком. До записи создаётся страховочная копия. Не сохраняйте эту GPO параллельно в другом редакторе.','Listed files are restored in full. A safety backup is created first. Do not save this GPO concurrently in another editor.')));
        const statuses={before:t('Исходное состояние','Original state'),after:t('Результат сохранения','Saved state'),changed:t('Внешнее или частичное изменение','External or partial change')};for(const file of plan.files)preview.append(el('p','mono',(file.action==='delete'?t('Удалить: ','Delete: '):t('Записать: ','Write: '))+file.path+' · '+(statuses[file.state]||file.state)+' · '+file.size+' '+t('байт','bytes')));
        const form=el('form','workspace-form');let conflicts;
        if(plan.conflicts.length){form.append(el('p','alert',t('Будут заменены изменённые данные: ','Changed data will be replaced: ')+plan.conflicts.join(', ')));conflicts=el('input');conflicts.type='checkbox';conflicts.required=true;const label=el('label','',t('Разрешаю заменить перечисленные внешние или частичные изменения','Allow replacing listed external or partial changes'));label.prepend(conflicts);form.append(label);}
        const check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю восстановление по этому плану','Confirm recovery using this plan'));label.prepend(check);const save=el('button','',t('Применить восстановление','Apply recovery'));save.type='submit';form.append(label,save);form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())apply({operation:'restore',source,mode,revision:plan.revision,allowConflicts:!!conflicts?.checked});});preview.append(form);message(notice,'');preview.scrollIntoView({block:'start',behavior:'smooth'});
      }catch(e){if(current()){preview.replaceChildren();message(notice,e.message,true);}}
    }
    await refresh();
  }
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
      extended.append(extraForm,el('h3','',t('Учётная запись и LDAP-атрибуты (просмотр)','Account and LDAP attributes (read only)')),el('p','muted',t('Даты показаны в часовом поясе браузера; исходное значение LDAP можно раскрыть. Права безопасности и делегирование этим редактором не изменяются.','Dates use the browser time zone; expand to see the raw LDAP value. This editor does not modify security permissions or delegation.')));
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
    }catch(err){if(generation===dialogGeneration&&requestID===loading){message(notice,err.message,true);content.replaceChildren(el('p','muted',t('Для шаблонов включите gpo.editor_enabled и укажите gpo.admx_path, если ADMX/ADML установлены локально. Пустой путь использует SYSVOL Central Store. Сценарии запуска и входа доступны отдельно, без ADMX.','Enable gpo.editor_enabled and set gpo.admx_path for locally installed ADMX/ADML. An empty path uses the SYSVOL Central Store. Startup and logon scripts are available separately without ADMX.')),button(t('Сценарии','Scripts'),()=>openOperation(view(t('Сценарии','Scripts'),r=>'/gpo/'+enc(gpoID(r))+'/scripts'),row)),button(t('Повторить','Retry'),refresh));}}finally{if(generation===dialogGeneration&&requestID===loading)search.disabled=category.disabled=scopeSelect.disabled=false;}}
    scopeSelect.addEventListener('change',()=>{search.value='';selectedPolicy='';refresh();});search.addEventListener('input',render);category.addEventListener('change',render);
    await refresh();
  }
  async function openDNSEditor(zone, initialName) {
    lastFocus=document.activeElement;
    const generation=++dialogGeneration;
    dialog.replaceChildren();
    const title=el('h2','',t('Записи DNS · ','DNS records · ')+zone.name);title.id='operation-title';
    const notice=el('p','workspace-message'), body=el('div'), editor=el('div');
    const query=el('form','workspace-form');
    const owner=el('input');owner.value=initialName;owner.required=true;owner.setAttribute('aria-label',t('Имя записи','Record name'));
    const filter=el('select');filter.setAttribute('aria-label',t('Тип записи','Record type'));
    const types=['A','AAAA','CNAME','NS','PTR','MX','SRV','TXT'];
    for(const v of ['ALL',...types,'SOA']){const o=el('option','',v);o.value=v;filter.append(o);}
    const fetchButton=el('button','',t('Показать','Show'));fetchButton.type='submit';query.append(owner,filter,fetchButton);
    dialog.append(title,el('p','muted',t('Выберите имя в дереве зоны или укажите его здесь. @ — корень зоны. Изменение затрагивает только выбранное значение.','Choose a name in the zone tree or enter it here. @ is the zone root. Editing affects only the selected value.')),query,notice,body,editor,button(t('Закрыть','Close'),closeOperation));
    if(!dialog.open)dialog.showModal();
    const path='/dns/zones/'+enc(zone.name)+'/records';let serial=0;
    async function refresh(){const id=++serial;message(notice,t('Загрузка…','Loading…'));try{
      const records=await request(path+'?'+new URLSearchParams({name:owner.value,type:filter.value}));
      if(generation!==dialogGeneration||id!==serial)return;
      body.replaceChildren();const table=el('table'), head=el('tr');
      for(const label of [t('Имя','Name'),t('Тип','Type'),t('Значение','Value'),t('Действия','Actions')])head.append(el('th','',label));
      const thead=el('thead');thead.append(head);const tbody=el('tbody');table.append(thead,tbody);
      for(const record of records){const tr=el('tr');for(const value of [record.name,record.type,record.data])tr.append(el('td','mono',value));
        const actions=el('td');if(admin&&types.includes(record.type)){actions.append(button(t('Изменить','Edit'),()=>edit(record)),button(t('Удалить','Delete'),()=>edit(record,true),'danger'));}tr.append(actions);tbody.append(tr);}
      body.append(table);if(!records.length)body.append(el('p','muted',t('Записи не найдены','No records found')));
      if(admin)body.append(button(t('Добавить запись','Add record'),()=>edit(null)));
      message(notice,'');
    }catch(e){if(generation===dialogGeneration&&id===serial)message(notice,e.message,true);}}
    function edit(record,remove=false){
      editor.replaceChildren();const form=el('form','workspace-form');
      form.append(el('h3','',remove?t('Удаление записи','Delete record'):record?t('Изменение записи','Edit record'):t('Новая запись','New record')));
      const fields={};function input(key,label,value='',numeric=false){const l=el('label','',label),i=el('input');i.value=value;i.required=true;if(numeric){i.type='number';i.min='0';i.max='65535';i.step='1';}fields[key]=i;l.append(i);form.append(l);return i;}
      const name=input('name',t('Имя','Name'),record?.name||owner.value);name.readOnly=!!record;
      const label=el('label','',t('Тип','Type')),type=el('select');type.setAttribute('aria-label',t('Тип','Type'));for(const v of types){const o=el('option','',v);o.value=v;type.append(o);}type.value=record?.type||'A';type.disabled=!!record;label.append(type);form.append(label);
      const dataBox=el('div');form.append(dataBox);
      function rebuild(){dataBox.replaceChildren();const parts=(record?.data||'').trim().split(/\s+/);const typ=type.value;
        function valueField(key,label,value,numeric){const i=input(key,label,value,numeric);dataBox.append(i.parentNode);i.readOnly=remove;}
        if(typ==='SRV'){valueField('target',t('Целевой сервер','Target host'),parts[0]===''?'':parts[0],false);valueField('port',t('Порт','Port'),parts[1]||'389',true);valueField('priority',t('Приоритет','Priority'),parts[2]||'0',true);valueField('weight',t('Вес','Weight'),parts[3]||'0',true);}
        else if(typ==='MX'){valueField('target',t('Почтовый сервер','Mail host'),record?parts[0]:'',false);valueField('priority',t('Приоритет','Preference'),parts[1]||'10',true);}
        else valueField('data',typ==='A'||typ==='AAAA'?t('IP-адрес','IP address'):typ==='TXT'?t('TXT в формате DNS (например "текст")','DNS TXT syntax (e.g. "text")'):t('Целевое DNS-имя','Target DNS name'),record?.data||'',false);
      }
      type.addEventListener('change',rebuild);rebuild();
      const confirm=el('input');confirm.type='checkbox';confirm.required=true;const consent=el('label','',t('Подтверждаю изменение выбранной записи','Confirm changing the selected record'));consent.prepend(confirm);form.append(consent);
      const error=el('p','workspace-message'),submit=el('button',remove?'danger':'',remove?t('Удалить','Delete'):t('Сохранить','Save'));submit.type='submit';form.append(error,submit,button(t('Отмена','Cancel'),()=>editor.replaceChildren()));editor.append(form);
      form.addEventListener('submit',async e=>{e.preventDefault();if(!form.reportValidity())return;
        const typ=type.value;let data=typ==='SRV'?[fields.target.value,fields.port.value,fields.priority.value,fields.weight.value].join(' '):typ==='MX'?[fields.target.value,fields.priority.value].join(' '):fields.data.value;
        const payload={name:name.value,type:typ};if(record&&!remove){payload.oldData=record.data;payload.newData=data;}else payload.data=remove?record.data:data;
        submit.disabled=true;try{await request(path,remove?'DELETE':record?'PUT':'POST',payload);if(generation!==dialogGeneration)return;editor.replaceChildren();await refresh();}catch(err){if(generation===dialogGeneration)message(error,err.message,true);}finally{submit.disabled=false;}
      });
    }
    query.addEventListener('submit',e=>{e.preventDefault();editor.replaceChildren();refresh();});
    await refresh();
  }
  async function openOperation(a,row) {
    if(a.dnsEditor)return openDNSEditor(row,a.prefill?.(row)?.name||'@');
    if(a.explain)return openPolicyExplain();
    if(a.model)return openPolicyModel();
    if(a.scope)return openScope();
    if(a.consistency)return openConsistency(row);
    if(a.repair)return openRepair(row);
    if(a.fullDelegation)return openFullDelegation(row);
    if(a.delegation)return openDelegation(row);
    if(a.filter)return openFilter(row);
    if(a.topology||(a.path==='/repl/connections'&&a.method==='POST'))return openTopology();
    if((typeof a.path==='function'?a.path(row):a.path)?.endsWith('/scripts'))return openScriptsEditor(row);
    if(a.groupMembers)return openGroupMembers(row);
    if(a.userCard)return openUserCard(a,row);
    if(a.editor)return openALTEditor(a,row);
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',a.label);title.id='operation-title';dialog.append(title);
    if(row)dialog.append(el('p','mono',cfg.id(row)||row.dn||''));
    if(a.warning)dialog.append(el('p','alert error',a.warning));
    if(a.help)dialog.append(el('p','muted',a.help));
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
    if(a.sambaParam){
      const key=inputs.find(([f])=>f.key==='key')[1],valueInput=inputs.find(([f])=>f.key==='value')[1],current=el('p','muted');form.append(current);
      function showCurrent(fill){const stored=Object.entries(row.params||{}).find(([name])=>name.toLowerCase()===key.value.trim().toLowerCase());current.textContent=stored?t('Сейчас в smb.conf: ','Current smb.conf value: ')+stored[1]:t('Параметр явно не задан в этой секции; могут действовать значения по умолчанию.','Not explicitly set in this section; defaults may apply.');if(fill)valueInput.value=stored?.[1]||'';}
      key.addEventListener('change',()=>showCurrent(true));showCurrent(false);
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
  async function openRepair(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Исправление SYSVOL','Repair SYSVOL'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div'),endpoint='/gpo/'+enc(gpoID(row))+'/repair';let serial=0;
    dialog.append(title,el('p','alert',t('Выполняйте в окне обслуживания: остановите другие редакторы GPO и синхронизацию SYSVOL. При переключении каталог GPO кратковременно недоступен. Источник выбирает администратор; LDAP не изменяется.','Use a maintenance window: stop other GPO editors and SYSVOL synchronizers. The GPO directory is briefly unavailable during cutover. The administrator chooses the source; LDAP is unchanged.')),notice,body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    const states={pending:t('Требуется восстановление','Recovery required'),complete:t('Завершено','Completed'),'rolled-back':t('Исходная копия возвращена','Original copy restored')};
    async function refresh(){const current=++serial;body.replaceChildren();
      try{const [records,dcs]=await Promise.all([request(endpoint),request('/sites/controllers')]);if(generation!==dialogGeneration||current!==serial)return;
        const result=el('section');result.setAttribute('aria-live','polite');const form=el('form','workspace-form'),source=el('select'),target=el('select');
        for(const [select,labelText] of [[source,t('Источник SYSVOL','SYSVOL source')],[target,t('Целевой DC','Target DC')]]){select.required=true;select.setAttribute('aria-label',labelText);for(const [value,text] of [['',t('Выберите DC','Select DC')],...dcs.map(d=>[d.dns,d.dns])]){const option=el('option','',text);option.value=value;select.append(option);}const label=el('label','',labelText);label.append(select);form.append(label);}
        const run=el('button','',t('Предпросмотр исправления','Preview repair'));run.type='submit';form.append(run);form.addEventListener('change',()=>result.replaceChildren());form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())preview({operation:'repair',source:source.value,target:target.value});});body.append(form,el('h3','',t('Журнал исправлений','Repair history')));
        for(const record of records){const card=el('div','scope-link');card.append(el('strong','',record.source+' → '+record.target),el('p','',states[record.state]||record.state),el('p','mono',record.id+' · '+record.created));if(record.state==='pending')card.append(button(t('Предпросмотр завершения','Preview completion'),()=>preview({operation:'complete',record:record.id})));if(record.state!=='rolled-back')card.append(button(t('Предпросмотр отката','Preview rollback'),()=>preview({operation:'rollback',record:record.id})));body.append(card);}
        body.append(result);
        async function preview(input){result.replaceChildren();for(const c of body.querySelectorAll('button,input,select'))c.disabled=true;message(notice,t('Чтение копий и расчёт изменений…','Reading copies and calculating changes…'));
          try{const plan=await request(endpoint,'POST',input);if(generation!==dialogGeneration||current!==serial)return;
            result.append(el('h3','',t('Предпросмотр','Preview')),el('p','',plan.source+' → '+plan.target),el('p','alert',t('Будет заменено дерево SYSVOL на целевом DC. Исходная копия сохраняется на DC и в закрытом локальном журнале. Копируются содержимое обычных файлов, владельцы, группы и DACL. SACL, альтернативные потоки и расширенные атрибуты не переносятся. Служебные копии sambaadm остаются в исходном каталоге.','The target SYSVOL tree will be replaced. The original is retained on the DC and in a private local journal. Ordinary file contents, owners, groups and DACLs are copied. SACLs, alternate streams and extended attributes are not copied. Sambaadm service backups remain in the original directory.')));
            const kinds={add:t('Добавить','Add'),remove:t('Удалить','Remove'),content:t('Заменить содержимое','Replace content'),type:t('Заменить тип объекта','Replace object type'),'sysvol-acl':t('Заменить права','Replace permissions')};topologyTable(result,plan.changes.map(c=>({...c,kind:kinds[c.kind]||c.kind})),[['path',t('Путь','Path')],['kind',t('Изменение','Change')]]);
            for(const acl of plan.aclChanges||[]){const details=el('details');details.append(el('summary','',t('Права: ','Permissions: ')+acl.path),el('p','',t('Владелец: ','Owner: ')+(acl.OwnerBefore||'—')+' → '+(acl.OwnerAfter||'—')),el('p','',t('Группа: ','Group: ')+(acl.GroupBefore||'—')+' → '+(acl.GroupAfter||'—')),el('p','',t('Защита DACL: ','DACL protected: ')+acl.ProtectedBefore+' → '+acl.ProtectedAfter));topologyTable(details,[...(acl.Before||[]).map(a=>({...a,side:t('До','Before')})),...(acl.After||[]).map(a=>({...a,side:t('После','After')}))].map(a=>({side:a.side,sid:a.sid,type:a.type,mask:'0x'+a.mask.toString(16),inherited:a.inherited})),[['side',t('Состояние','State')],['sid','SID'],['type',t('Тип','Type')],['mask',t('Маска','Mask')],['inherited',t('Унаследовано','Inherited')]]);result.append(details);}
            const confirm=el('form','workspace-form'),check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю выбранные DC, изменения и окно обслуживания','Confirm the selected DCs, changes and maintenance window'));label.prepend(check);const apply=el('button','',t('Применить исправление SYSVOL','Apply SYSVOL repair'));apply.type='submit';confirm.append(label,apply);result.append(confirm);message(notice,t('Предпросмотр готов','Preview ready'));
            confirm.addEventListener('submit',async e=>{e.preventDefault();if(!confirm.reportValidity())return;for(const c of body.querySelectorAll('button,input,select'))c.disabled=true;
              try{const done=await request(endpoint,'PUT',{...input,preview:plan.preview});if(generation!==dialogGeneration||current!==serial)return;await refresh();message(notice,(states[done.state]||done.state)+' · '+done.record+(done.verificationError?' · '+done.verificationError:done.report?' · '+t('Повторная проверка: ','Recheck: ')+({consistent:t('копии совпадают','copies match'),different:t('есть расхождения','differences remain'),incomplete:t('неполная','incomplete'),'single-controller':t('один DC','single DC')}[done.report.status]||done.report.status):''),!!done.verificationError);}
              catch(err){if(generation===dialogGeneration&&current===serial){await refresh();message(notice,err.message,true);}}
            });
          }catch(err){if(generation===dialogGeneration&&current===serial)message(notice,err.message,true);}
          finally{if(generation===dialogGeneration&&current===serial)for(const c of body.querySelectorAll('button,input,select'))c.disabled=false;}
        }
      }catch(err){if(generation===dialogGeneration&&current===serial)message(notice,err.message,true);}
    }
    await refresh();
  }

  async function openConsistency(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Согласованность GPO между контроллерами','GPO consistency across controllers'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    dialog.append(title,el('p','muted',t('Чтение LDAP и SYSVOL всех обнаруженных DC. Сравниваются версии, SHA-256 файлов, владельцы, группы и DACL. Проверка не запускает репликацию и ничего не исправляет. Контроллер сравнения не считается заведомо правильной копией.','Reads LDAP and SYSVOL on all discovered DCs. Compares versions, file SHA-256, owners, groups and DACLs. Does not trigger replication or repair anything. The comparison controller is not assumed to be authoritative.')),notice,body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    try{
      const controllers=await request('/sites/controllers');if(generation!==dialogGeneration)return;
      const form=el('form','workspace-form'),select=el('select');select.setAttribute('aria-label',t('Контроллер для сравнения','Comparison controller'));
      for(const [val,label] of [['',t('Автоматически: первая полностью прочитанная копия','Automatic: first fully read copy')],...controllers.map(dc=>[dc.dns,dc.dns])]){const o=el('option','',label);o.value=val;select.append(o);}
      const label=el('label','',t('Контроллер для сравнения','Comparison controller'));label.append(select);const run=el('button','',t('Проверить согласованность','Check consistency'));run.type='submit';form.append(label,run);const result=el('section');result.setAttribute('aria-live','polite');body.append(form,result);form.addEventListener('change',()=>result.replaceChildren());
      const statuses={consistent:t('Совпадает','Matches'),reference:t('Копия для сравнения','Comparison copy'),different:t('Есть расхождения','Differences found'),incomplete:t('Проверка неполная','Check incomplete'),unavailable:t('Недоступно','Unavailable'),changing:t('Изменилось во время чтения','Changed during read'),pending:t('Незавершённая запись','Pending write'),'single-controller':t('Один DC — сравнение между контроллерами невозможно','Single DC — cross-controller comparison unavailable'),'not-compared':t('Нет доступной копии для сравнения','No available comparison copy'),ok:t('Прочитано','Read'),missing:t('Отсутствует','Missing'),error:t('Ошибка чтения','Read error'),'not-checked':t('Не проверено','Not checked')};
      const kinds={'local-version':t('LDAP и GPT.INI на одном DC','LDAP vs GPT.INI on one DC'),'ldap-version':t('Версия LDAP','LDAP version'),'gpt-version':t('Версия GPT.INI','GPT.INI version'),'ldap-acl':t('Права объекта LDAP','LDAP object permissions'),'ldap-metadata':t('Метаданные LDAP','LDAP metadata'),content:t('Содержимое файла','File content'),'sysvol-acl':t('Права SYSVOL','SYSVOL permissions'),missing:t('Нет на этом DC','Missing on this DC'),extra:t('Дополнительный путь','Additional path'),type:t('Тип объекта','Object type'),'path-case':t('Регистр имени пути','Path name case')};
      const version=v=>v===undefined||v===null?'—':v+' (M: '+(v&65535)+', U: '+(v>>>16)+')';
      form.addEventListener('submit',async event=>{event.preventDefault();run.disabled=true;select.disabled=true;result.replaceChildren();message(notice,t('Проверка контроллеров… Обычно до 45 секунд.','Checking controllers… Usually up to 45 seconds.'));
        try{const report=await request('/gpo/'+enc(gpoID(row))+'/consistency','POST',{reference:select.value});if(generation!==dialogGeneration)return;
          result.append(el('h3',report.status==='consistent'?'':'alert',statuses[report.status]||report.status),el('p','mono',report.started+' → '+report.finished),el('p','',t('Сравнение с: ','Compared with: ')+(report.reference||'—')));
          if(!report.complete)result.append(el('p','alert error',t('Не все копии проверены. Совпадение доступных DC не подтверждает согласованность всего домена.','Not all copies were checked. Matching accessible DCs does not establish domain-wide consistency.')));
          if(report.hasDifferences)result.append(el('p','alert error',t('Обнаружены подтверждённые расхождения в прочитанных данных.','Differences were found in the data read.')));
          result.append(button(t('Скачать отчёт JSON','Download JSON report'),()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='gpo-consistency.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
          topologyTable(result,report.controllers.map(dc=>({dns:dc.dns,state:statuses[dc.status]||dc.status,ldap:statuses[dc.ldap]||dc.ldap,sysvol:statuses[dc.sysvol]||dc.sysvol,ldapVersion:version(dc.ldapVersion),gptVersion:version(dc.gptVersion),count:dc.files.length,diffs:dc.differenceCount})),[['dns','DC'],['state',t('Результат','Result')],['ldap','LDAP'],['sysvol','SYSVOL'],['ldapVersion',t('Версия LDAP','LDAP version')],['gptVersion','GPT.INI'],['count',t('Объектов','Objects')],['diffs',t('Различий','Differences')]]);
          for(const dc of report.controllers){const details=el('details');details.open=dc.errors.length>0||dc.differenceCount>0;details.append(el('summary','',dc.dns+' · '+(statuses[dc.status]||dc.status)));for(const error of dc.errors)details.append(el('p','alert error',error));if(dc.pending)details.append(el('p','alert error',t('В SYSVOL найден журнал незавершённой записи.','A pending write journal exists in SYSVOL.')));
            topologyTable(details,dc.differences.map(d=>({...d,kind:kinds[d.kind]||d.kind,reference:d.reference||'—',value:d.value||'—'})),[['kind',t('Что отличается','Difference')],['path',t('Путь / атрибут','Path / attribute')],['reference',t('Копия для сравнения','Comparison copy')],['value',t('Этот DC','This DC')]]);
            if(dc.differenceCount>dc.differences.length)details.append(el('p','muted',t('Список различий сокращён; полный манифест файлов доступен в JSON.','Difference list truncated; the full file manifest is included in JSON.')));result.append(details);
          }
          result.append(el('p','muted',t('Это не атомарный снимок и не проверка применения GPO на клиенте. SACL и эффективный доступ не вычисляются. Служебные .sambaadm-* в корне исключены; журнал незавершённой записи учитывается отдельно.','This is not an atomic snapshot or proof of client-side application. SACL and effective access are not evaluated. Root .sambaadm-* metadata is excluded; a pending write journal is reported separately.')));message(notice,t('Отчёт готов','Report ready'));
        }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}finally{if(generation===dialogGeneration){run.disabled=false;select.disabled=false;}}
      });
    }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}
  }
  async function openFullDelegation(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Делегирование GPO · LDAP и SYSVOL','GPO delegation · LDAP and SYSVOL'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div'),path='/gpo/'+enc(gpoID(row))+'/delegation/full';let serial=0;
    dialog.append(title,el('p','muted',t('Согласованная выдача прав объекту GPO и существующим файлам/каталогам SYSVOL. Исходные ACL сохраняются в закрытом журнале на сервере sambaadm. На время операции остановите другие редакторы этой GPO. Роли sambaadm не меняются.','Coordinated permissions for the GPO and existing SYSVOL files/directories. Original ACLs are stored in a private journal on the sambaadm server. Stop other editors of this GPO during the operation. Sambaadm roles are unchanged.')),notice,button(t('Обновить','Refresh'),refresh),body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    const profiles=[['read',t('Чтение LDAP/SYSVOL','Read LDAP/SYSVOL')],['read-apply',t('Чтение и применение GPO','Read and apply GPO')],['edit',t('Редактирование LDAP/SYSVOL','Edit LDAP/SYSVOL')]];
    const operations={grant:t('Выдача','Grant'),revoke:t('Отзыв','Revoke'),complete:t('Завершение','Complete'),rollback:t('Возврат исходных ACL','Restore original ACLs')};
    async function refresh(){const current=++serial;body.replaceChildren();message(notice,t('Загрузка…','Loading…'));
      try{
        const [state,groups,users,computers]=await Promise.all([request(path),request('/groups'),request('/users'),request('/computers')]);if(generation!==dialogGeneration||current!==serial)return;message(notice,'');
        const result=el('section');result.setAttribute('aria-live','polite');
        if(state.pending){body.append(el('p','alert error',t('Незавершённая операция: ','Pending operation: ')+state.pending));body.append(button(t('Предпросмотр завершения','Preview completion'),()=>preview({operation:'complete',source:state.pending})),button(t('Предпросмотр возврата','Preview rollback'),()=>preview({operation:'rollback',source:state.pending})));}
        else{
          const form=el('form','workspace-form'),principal=el('select'),profile=el('select');principal.setAttribute('aria-label',t('Получатель делегирования','Delegation recipient'));profile.setAttribute('aria-label',t('Профиль LDAP/SYSVOL','LDAP/SYSVOL profile'));
          for(const [val,label] of [['',t('Выберите получателя','Select a recipient')],['S-1-5-11','Authenticated Users'],...[...groups,...users,...computers].filter(p=>p.dn).map(p=>[p.dn,(p.samAccountName||p.name||p.dn)+' · '+p.dn])]){const o=el('option','',label);o.value=val;principal.append(o);}principal.required=true;
          for(const [val,label] of profiles){const o=el('option','',label);o.value=val;profile.append(o);}
          const a=el('label','',t('Получатель делегирования','Delegation recipient')),b=el('label','',t('Профиль LDAP/SYSVOL','LDAP/SYSVOL profile'));a.append(principal);b.append(profile);const run=el('button','',t('Предпросмотр выдачи','Preview grant'));run.type='submit';form.append(a,b,run);body.append(form);
          form.addEventListener('change',()=>result.replaceChildren());form.addEventListener('submit',e=>{e.preventDefault();if(form.reportValidity())preview({operation:'grant',principal:principal.value,profile:profile.value});});
        }
        body.append(el('h3','',t('Журнал делегирования','Delegation history')));
        for(const record of state.records){const card=el('div','scope-link');card.append(el('strong','',(operations[record.operation]||record.operation)+' · '+record.sid),el('p','',(profiles.find(([v])=>v===record.profile)?.[1]||record.profile)+' · '+record.created),el('p','mono',record.id),el('p','',record.revoked?t('Отозвано','Revoked'):({pending:t('Не завершено','Pending'),complete:t('Завершено','Completed'),'rolled-back':t('Исходные ACL восстановлены','Original ACLs restored')})[record.state]||record.state));
          if(!state.pending&&record.operation==='grant'&&record.state==='complete'&&!record.revoked)card.append(button(t('Предпросмотр отзыва','Preview revocation'),()=>preview({operation:'revoke',source:record.id})));body.append(card);
        }
        if(!state.records.length)body.append(el('p','muted',t('Записанных выдач пока нет','No recorded grants yet')));
        body.append(el('p','muted',t('Отзыв возвращает ACL до выбранной выдачи и сохраняет исходный доступ. При изменении ACL или состава файлов операция блокируется; существующие права могут сохраняться через другие ACE и группы. Отзыв старых выдач обычно требует сначала отозвать более новые.','Revocation restores ACLs from before the selected grant and preserves original access. Changed ACLs or file inventory block the operation; other ACEs and groups may still grant access. Older grants usually require newer grants to be revoked first.')),result);
        let previewSerial=0;
        async function preview(input){const attempt=++previewSerial;result.replaceChildren();for(const c of body.querySelectorAll('button,input,select'))c.disabled=true;message(notice,t('Чтение ACL и расчёт…','Reading ACLs and calculating…'));
          try{const p=await request(path,'POST',input);if(generation!==dialogGeneration||current!==serial||attempt!==previewSerial)return;
            result.append(el('h3','',operations[input.operation]),el('p','mono',p.dn+' · '+p.sid),el('p','',profiles.find(([v])=>v===p.profile)?.[1]||p.profile));
            const states={before:t('Исходные права','Original permissions'),after:t('Права после операции','Permissions after operation'),unchanged:t('Без изменения','Unchanged'),conflict:t('Конфликт','Conflict')};
            result.append(el('p','', 'LDAP: '+(states[p.ldapState]||p.ldapState)));
            function aclDetails(label,added,removed){if(!(added?.length||removed?.length))return;const box=el('details');box.append(el('summary','',label));topologyTable(box,[...(added||[]).map(a=>({...a,action:t('Добавить','Add')})),...(removed||[]).map(a=>({...a,action:t('Удалить','Remove')}))].map(a=>({sid:a.sid||'—',action:a.action,type:a.type,mask:'0x'+a.mask.toString(16)})),[['action',t('Изменение','Change')],['sid','SID'],['type',t('Тип ACE','ACE type')],['mask',t('Маска прав','Access mask')]]);result.append(box);}
            aclDetails(t('Изменения ACL в LDAP','LDAP ACL changes'),p.ldapAdded,p.ldapRemoved);
            topologyTable(result,p.files.map(f=>({path:f.path,state:states[f.state]||f.state,changed:f.changed?t('Да','Yes'):t('Нет','No')})),[['path',t('Путь SYSVOL','SYSVOL path')],['state',t('Состояние','State')],['changed',t('ACL меняется','ACL changes')]]);
            for(const f of p.files)aclDetails('SYSVOL · '+f.path,f.added,f.removed);
            if(p.conflicts.length){for(const conflict of p.conflicts)result.append(el('p','alert error',t('Конфликт: ','Conflict: ')+conflict));message(notice,t('Операция заблокирована: состояние изменилось.','Operation blocked: state changed.'),true);return;}
            const confirm=el('form','workspace-form'),check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю показанное изменение прав LDAP и SYSVOL','Confirm the shown LDAP and SYSVOL permission changes'));label.prepend(check);const apply=el('button','',t('Применить согласованные права','Apply coordinated permissions'));apply.type='submit';confirm.append(label,apply);result.append(confirm);message(notice,t('Предпросмотр готов','Preview ready'));
            confirm.addEventListener('submit',async e=>{e.preventDefault();if(!confirm.reportValidity())return;for(const c of body.querySelectorAll('button,input,select'))c.disabled=true;
              try{await request(path,'PUT',{...input,preview:p.preview});if(generation!==dialogGeneration||current!==serial)return;await refresh();message(notice,t('Операция завершена и проверена','Operation completed and verified'));}
              catch(err){if(generation===dialogGeneration&&current===serial){await refresh();message(notice,err.message,true);}}
            });
          }catch(err){if(generation===dialogGeneration&&current===serial)message(notice,err.message,true);}
          finally{if(generation===dialogGeneration&&current===serial)for(const c of body.querySelectorAll('button,input,select'))c.disabled=false;}
        }
      }catch(err){if(generation===dialogGeneration&&current===serial)message(notice,err.message,true);}
    }
    await refresh();
  }
  async function openDelegation(row) {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Права объекта GPO · LDAP','GPO object permissions · LDAP'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    const path='/gpo/'+enc(gpoID(row))+'/delegation';
    dialog.append(title,el('p','muted',t('Выдача дополнительных разрешений на объект и дочерние объекты LDAP. Существующие ACE сохраняются. Права файлов SYSVOL и роли sambaadm не меняются; для редактирования файлов политики потребуется отдельное разрешение SYSVOL. Запреты и членство в группах могут влиять на фактический доступ.','Grant additional permissions on the LDAP object and its descendants. Existing ACEs are preserved. SYSVOL file permissions and sambaadm roles are unchanged; editing policy files requires separate SYSVOL access. Deny entries and group membership may affect effective access.')),notice,button(t('Обновить','Refresh'),refresh),body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    let serial=0;
    const permissionName=e=>e.mask===0x20094?t('Чтение LDAP','Read LDAP'):e.mask===0x200b7?t('Редактирование LDAP','Edit LDAP'):e.apply&&e.mask===0x100?t('Применение GPO','Apply GPO'):t('Другие или совмещённые права','Other or combined permissions');
    const aceName=e=>[0,5].includes(e.type)?t('Разрешение','Allow'):[1,6].includes(e.type)?t('Запрет','Deny'):t('Нестандартная ACE','Nonstandard ACE');
    const profiles=[['read',t('Чтение LDAP','Read LDAP')],['read-apply',t('Чтение LDAP и применение GPO','Read LDAP and apply GPO')],['edit-ldap',t('Редактирование LDAP без изменения DACL/владельца','Edit LDAP without changing DACL/owner')]];
    async function refresh(){const current=++serial;body.replaceChildren();message(notice,t('Загрузка…','Loading…'));
      try {
        const [model,groups,users,computers]=await Promise.all([request(path),admin?request('/groups'):[],admin?request('/users'):[],admin?request('/computers'):[]]);
        if(generation!==dialogGeneration||current!==serial)return;message(notice,'');
        topologyTable(body,model.entries.map(e=>({name:e.name||e.sid||'—',sid:e.sid||'—',rights:permissionName(e),type:aceName(e),mask:'0x'+e.mask.toString(16),inherited:e.inherited?t('Да','Yes'):t('Нет','No')})),[['name',t('Получатель','Principal')],['sid','SID'],['rights',t('Права','Permissions')],['type',t('Тип ACE','ACE type')],['mask',t('Маска прав','Access mask')],['inherited',t('Наследуется','Inherited')]]);
        if(!admin)return;
        const form=el('form','workspace-form'),principal=el('select'),profile=el('select');principal.setAttribute('aria-label',t('Получатель разрешения','Permission recipient'));profile.setAttribute('aria-label',t('Профиль разрешений','Permission profile'));
        for(const [val,label] of [['S-1-5-11','Authenticated Users'],...[...groups,...users,...computers].filter(p=>p.dn).map(p=>[p.dn,(p.samAccountName||p.name||p.dn)+' · '+p.dn])]){const o=el('option','',label);o.value=val;principal.append(o);}
        for(const [val,label] of profiles){const o=el('option','',label);o.value=val;profile.append(o);}
        const principalLabel=el('label','',t('Получатель разрешения','Permission recipient')),profileLabel=el('label','',t('Профиль разрешений','Permission profile'));principalLabel.append(principal);profileLabel.append(profile);
        const preview=el('button','',t('Предпросмотр прав','Preview permissions'));preview.type='submit';const result=el('div');form.append(principalLabel,profileLabel,preview);body.append(form,result);
        let plan=null,payload=null;
        form.addEventListener('change',()=>{plan=null;payload=null;result.replaceChildren();});
        form.addEventListener('submit',async event=>{
          event.preventDefault();plan=null;result.replaceChildren();preview.disabled=true;principal.disabled=true;profile.disabled=true;
          const input={revision:model.revision,principal:principal.value,profile:profile.value};
          try {
            const p=await request(path,'POST',input);if(generation!==dialogGeneration||current!==serial)return;plan=p;payload=input;
            result.append(el('h3','',t('Будут добавлены разрешения','Permissions to add')),el('p','mono',p.dn+' · '+p.sid),el('p','',t('Существующих ACE сохраняется: ','Existing ACEs preserved: ')+p.unchanged));
            topologyTable(result,p.added.map(e=>({sid:e.sid,rights:permissionName(e),type:aceName(e),mask:'0x'+e.mask.toString(16)})),[['sid','SID'],['rights',t('Права','Permissions')],['type',t('Тип ACE','ACE type')],['mask',t('Маска прав','Access mask')]]);
            if(!p.added.length){result.append(el('p','',t('Такие явные разрешения уже существуют. Изменений нет.','These explicit permissions already exist. No changes.')));return;}
            const confirmation=el('form','workspace-form'),check=el('input');check.type='checkbox';check.required=true;const label=el('label','',t('Подтверждаю выдачу показанных прав только в LDAP','Confirm granting the shown LDAP-only permissions'));label.prepend(check);
            const apply=el('button','',t('Выдать права LDAP','Grant LDAP permissions'));apply.type='submit';confirmation.append(label,apply);result.append(confirmation);
            confirmation.addEventListener('submit',async e=>{
              e.preventDefault();if(!confirmation.reportValidity()||!plan)return;apply.disabled=true;preview.disabled=true;principal.disabled=true;profile.disabled=true;
              try{await request(path,'PUT',{...payload,preview:plan.preview});if(generation!==dialogGeneration||current!==serial)return;await refresh();message(notice,t('Права LDAP выданы. Права SYSVOL не изменялись.','LDAP permissions granted. SYSVOL permissions unchanged.'));}
              catch(err){if(generation===dialogGeneration&&current===serial){plan=null;result.replaceChildren();message(notice,err.message,true);preview.disabled=true;principal.disabled=true;profile.disabled=true;}}
            });
          }catch(e){if(generation===dialogGeneration&&current===serial)message(notice,e.message,true);}
          finally{if(generation===dialogGeneration&&current===serial){preview.disabled=false;principal.disabled=false;profile.disabled=false;}}
        });
      }catch(e){if(generation===dialogGeneration&&current===serial)message(notice,e.message,true);}
    }
    await refresh();
  }
  async function openPolicyExplain() {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Почему применяется GPO','Why a GPO applies'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    dialog.append(title,el('p','muted',t('Проверка связей и разделов по LDAP. Условный кандидат ещё не означает применение на клиенте: права, SYSVOL, WMI, сайт и loopback требуют отдельной проверки.','LDAP link and section checks. A conditional candidate does not prove client application: permissions, SYSVOL, WMI, site and loopback need separate verification.')),notice,body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    try {
      const [model,users,computers]=await Promise.all([request('/gpo/scope'),request('/users'),request('/computers')]);if(generation!==dialogGeneration)return;
      const form=el('form','workspace-form'),controls={};
      for(const [key,label,rows] of [['user',t('Пользователь или его OU','User or user OU'),users],['computer',t('Компьютер или его OU','Computer or computer OU'),computers]]){
        const wrap=el('label','',label),select=el('select');select.name=key;select.setAttribute('aria-label',label);
        for(const [dn,name] of [['',t('Не выбран','Not selected')],...rows.filter(r=>r.dn).map(r=>[r.dn,r.samAccountName+' · '+r.dn]),...model.containers.map(c=>[c.dn,c.dn])]){const option=el('option','',name);option.value=dn;select.append(option);}wrap.append(select);form.append(wrap);controls[key]=select;
      }
      const run=el('button','',t('Объяснить применение','Explain application'));run.type='submit';form.append(run);const result=el('section');result.setAttribute('aria-live','polite');body.append(form,result);form.addEventListener('change',()=>result.replaceChildren());
      const codes={'link-options':t('Параметры ссылки','Link options'),'link-enabled':t('Ссылка включена','Link enabled'),'policy-exists':t('GPO видна в LDAP','GPO visible in LDAP'),'inheritance':t('Наследование; при отказе указан блокирующий контейнер','Inheritance; on failure, the blocking container is shown'),'enforced':t('Принудительная ссылка проходит блокировку наследования','Enforced link bypasses inheritance blocking'),'section-enabled':t('Раздел включён','Section enabled'),'security':t('Токен получателя и права чтения/применения GPO','Target token and GPO read/apply permissions'),'sysvol':t('Чтение SYSVOL получателем','Target SYSVOL read access'),'wmi':t('Результат WMI-фильтра','WMI filter result'),'no-wmi-filter':t('WMI-фильтр отсутствует','No WMI filter'),'higher-priority-link':t('Та же GPO уже учтена по ссылке выше приоритетом','Same GPO already represented by a higher-priority link')};
      form.addEventListener('submit',async event=>{
        event.preventDefault();if(!controls.user.value&&!controls.computer.value){message(notice,t('Выберите пользователя, компьютер или OU.','Select a user, computer or OU.'),true);return;}
        result.replaceChildren();for(const c of form.elements)c.disabled=true;message(notice,t('Чтение LDAP…','Reading LDAP…'));
        try {
          const report=await request('/gpo/explain','POST',{user:controls.user.value,computer:controls.computer.value});if(generation!==dialogGeneration)return;
          result.append(el('h3','',t('Объяснение области действия','Scope explanation')),el('p','mono',report.generatedAt),button(t('Скачать отчёт JSON','Download JSON report'),()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='gpo-explanation.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
          for(const section of report.sections){
            const part=el('section');part.append(el('h3','',section.scope==='Machine'?t('Конфигурация компьютера','Computer configuration'):t('Конфигурация пользователя','User configuration')),el('p','mono',section.target));
            part.append(el('h4','',t('Путь наследования: домен → OU','Inheritance path: domain → OU')));
            for(const c of section.path)part.append(el('p','mono',c.dn+(c.block?' · '+t('Наследование заблокировано','Inheritance blocked'):'')));
            part.append(el('p','muted',t('Приоритет 1 — наивысший. Порядок обработки показан для условных кандидатов; фильтры могут сократить этот список.','Priority 1 is highest. Processing order is shown for conditional candidates; filters may reduce this list.')));
            topologyTable(part,section.links.map(l=>({...l,priority:l.priority||'—',processingOrder:l.processingOrder||'—',status:l.status==='excluded'?t('Исключена из расчёта','Excluded from calculation'):t('Условный кандидат — требуется проверка','Conditional candidate — verification required')})),[['priority',t('Приоритет','Priority')],['processingOrder',t('Обработка','Processing')],['name','GPO'],['source',t('Источник','Source')],['status',t('Решение','Decision')]]);
            for(const link of section.links){const detail=el('details');detail.append(el('summary','',link.name+' · '+link.source));topologyTable(detail,link.checks.map(c=>({condition:codes[c.code]||c.code,state:({pass:t('Подтверждено','Confirmed'),fail:t('Исключает из расчёта','Excludes from calculation'),unknown:t('Не проверено','Not verified')})[c.state]||c.state,detail:c.detail||'—'})),[['condition',t('Условие','Condition')],['state',t('Результат','Result')],['detail',t('Основание','Evidence')]]);part.append(detail);}result.append(part);
          }
          result.append(el('p','muted',t('Это снимок LDAP, а не отчёт gpresult. Локальные и сайтовые политики, loopback, исполнение расширений и изменения каталога во время чтения не учитываются.','This is an LDAP snapshot, not gpresult. Local/site policies, loopback, extension execution and directory changes during the read are not evaluated.')));message(notice,t('Отчёт готов','Report ready'));
        }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}finally{if(generation===dialogGeneration)for(const c of form.elements)c.disabled=false;}
      });
    }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}
  }
  async function openPolicyModel() {
    lastFocus=document.activeElement;const generation=++dialogGeneration;dialog.replaceChildren();
    const title=el('h2','',t('Моделирование результирующей политики · ALT / Windows','Resultant policy modeling · ALT / Windows'));title.id='operation-title';
    const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');const body=el('div');
    dialog.append(title,el('p','muted',t('Сценарий читает GPO и SYSVOL без изменения каталога. Итоговые параметры ALT рассчитываются по шаблонам домена. Права безопасности, доступ к SYSVOL и результаты WMI задаются как допущения. Это прогноз; применение зависит от движка политик клиента.','The scenario reads GPOs and SYSVOL without directory changes. ALT settings use domain templates. Security, SYSVOL access and WMI outcomes are scenario assumptions. This is a prediction; application depends on the client policy engine.')),notice,body,button(t('Закрыть','Close'),closeOperation));dialog.showModal();
    try {
      const [model,users,computers]=await Promise.all([request('/gpo/scope'),request('/users'),request('/computers')]);if(generation!==dialogGeneration)return;
      const form=el('form','workspace-form');const controls={};
      function select(key,label,items){const wrapper=el('label','',label),input=el('select');for(const [val,label] of items){const o=el('option','',label);o.value=val;input.append(o);}wrapper.append(input);form.append(wrapper);controls[key]=input;return input;}
      const containers=model.containers.map(c=>[c.dn,c.dn]);
      const empty=['',t('Не выбран','Not selected')];
      select('user',t('Пользователь или его OU','User or user OU'),[empty,...users.filter(p=>p.dn).map(p=>[p.dn,p.samAccountName+' · '+p.dn]),...containers]);
      select('computer',t('Компьютер или его OU','Computer or computer OU'),[empty,...computers.filter(p=>p.dn).map(p=>[p.dn,p.samAccountName+' · '+p.dn]),...containers]);
      select('userOU',t('Моделировать перемещение пользователя в OU','Simulate user move to OU'),[['',t('Текущее расположение','Current location')],...containers]);
      select('computerOU',t('Моделировать перемещение компьютера в OU','Simulate computer move to OU'),[['',t('Текущее расположение','Current location')],...containers]);
      select('loopback','Loopback',[['none',t('Без loopback','No loopback')],['merge','Merge'],['replace','Replace']]);
      const outcomes=[['unknown',t('Неизвестно — неполный расчёт','Unknown — incomplete calculation')],['allow',t('Предположить: разрешено / истина','Assume: allowed / true')],['deny',t('Предположить: запрещено / ложь','Assume: denied / false')]];
      select('security',t('Безопасность и чтение SYSVOL — для всех GPO','Security and SYSVOL read — all GPOs'),outcomes);
      select('wmi',t('WMI — для всех связанных фильтров','WMI — all linked filters'),outcomes);
      const exceptions=el('details');exceptions.append(el('summary','',t('Индивидуальные допущения по GPO','Per-GPO assumptions')));const overrides=[];
      for(const p of model.policies){const card=el('div','scope-link');card.append(el('strong','',p.displayName));const pair={guid:p.guid};for(const [key,label] of [['security',t('Безопасность','Security')],['wmi','WMI']]){const wrap=el('label','',label),input=el('select');for(const [v,l] of [['',t('Общее допущение','Default assumption')],...outcomes]){const o=el('option','',l);o.value=v;input.append(o);}wrap.append(input);card.append(wrap);pair[key]=input;}exceptions.append(card);overrides.push(pair);}form.append(exceptions);
      const run=el('button','',t('Рассчитать результат','Calculate result'));run.type='submit';form.append(run);const result=el('section');result.setAttribute('aria-live','polite');body.append(form,result);
      // Any edited scenario invalidates the displayed report.
      form.addEventListener('change',()=>result.replaceChildren());
      form.addEventListener('submit',async event=>{
        event.preventDefault();if(!form.reportValidity())return;const input=Object.fromEntries(Object.entries(controls).map(([k,v])=>[k,v.value]));if(!input.user&&!input.computer){message(notice,t('Выберите пользователя, компьютер или OU.','Select a user, computer or OU.'),true);return;}if(input.loopback!=='none'&&(!input.user||!input.computer)){message(notice,t('Для loopback выберите и пользователя, и компьютер (либо их OU).','Loopback requires both user and computer targets (or their OUs).'),true);return;}if((input.userOU&&!input.user)||(input.computerOU&&!input.computer)){message(notice,t('Для условного перемещения сначала выберите получателя.','Select a target before simulating its move.'),true);return;}input.securityOverrides={};input.wmiOverrides={};for(const pair of overrides){if(pair.security.value)input.securityOverrides[pair.guid]=pair.security.value;if(pair.wmi.value)input.wmiOverrides[pair.guid]=pair.wmi.value;}
        run.disabled=true;result.replaceChildren();message(notice,t('Чтение SYSVOL и расчёт…','Reading SYSVOL and calculating…'));for(const c of form.elements)c.disabled=true;
        try{const report=await request('/gpo/model','POST',input);if(generation!==dialogGeneration)return;renderReport(report);message(notice,t('Сценарий рассчитан','Scenario calculated'));}catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}finally{if(generation===dialogGeneration)for(const c of form.elements)c.disabled=false;}
      });
      function renderReport(report){
        result.replaceChildren();result.append(el('h3','',t('Отчёт моделирования','Modeling report')),el('p','mono',report.controller+' · '+report.generatedAt+' · '+report.templateSource));
        result.append(button(t('Скачать отчёт JSON','Download JSON report'),()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='policy-model.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
        result.append(el('p','muted',t('Допущения безопасности и WMI: ','Security and WMI assumptions: ')+controls.security.selectedOptions[0].text+' / '+controls.wmi.selectedOptions[0].text));
        for(const [key,label] of [['securityOverrides',t('Безопасность','Security')],['wmiOverrides','WMI']])for(const [guid,outcome] of Object.entries(report.scenario[key]||{})){const policy=model.policies.find(p=>p.guid===guid);result.append(el('p','muted',label+' · '+(policy?.displayName||guid)+' · '+(outcomes.find(([v])=>v===outcome)?.[1]||outcome)));}
        const reasons={applied:t('Включена в сценарий','Included in scenario'),disabled:t('Ссылка отключена','Link disabled'),blocked:t('Заблокирована наследованием','Blocked inheritance'),missing:t('GPO отсутствует','GPO missing'),'section-disabled':t('Раздел отключён','Section disabled'),'security-denied':t('Безопасность: отказ (допущение)','Security: denied (assumed)'),'security-unknown':t('Безопасность: неизвестно','Security: unknown'),'wmi-false':t('WMI: ложь (допущение)','WMI: false (assumed)'),'wmi-unknown':t('WMI: неизвестно','WMI: unknown'),'read-error':t('Ошибка чтения','Read error'),'unknown-options':t('Неизвестные параметры ссылки','Unknown link options'),'unknown-flags':t('Неизвестные флаги GPO','Unknown GPO flags')};
        for(const section of report.sections){const part=el('section');part.append(el('h3','',section.scope==='Machine'?t('Конфигурация компьютера','Computer configuration'):t('Конфигурация пользователя','User configuration')),el('p','mono',section.container));if(section.incomplete)part.append(el('p','alert error',t('Расчёт неполный: ниже показан результат только прочитанных GPO с известными условиями. Неизвестные условия, ошибки и неподдерживаемые директивы могут изменить значения и GPO-победителей.','Incomplete: only readable GPOs with known conditions contribute below. Unknown conditions, errors and unsupported directives may change values and winning GPOs.')));
          for(const warning of section.warnings)part.append(el('p','alert error',warning));
          part.append(el('h4','',t('Применение GPO · высокий приоритет первым','GPO processing · highest precedence first')));topologyTable(part,section.links.map((l,i)=>({...l,priority:i+1,status:reasons[l.reason]||l.reason})),[['priority','№'],['name','GPO'],['source',t('Источник','Source')],['status',t('Решение','Decision')],['enforced','Enforced']]);
          part.append(el('h4','',t('Результирующие параметры ALT','Resultant ALT settings')));topologyTable(part,section.settings.map(s=>({modelConflict:s.conflicts.length>0,conflict:s.conflicts.length?t('Конфликт','Conflict'):'—',label:s.label,category:s.category,state:({enabled:t('Включено','Enabled'),disabled:t('Отключено','Disabled'),unsupported:t('Не поддерживается или конфликт формата','Unsupported or conflicting format')})[s.state]||s.state,values:JSON.stringify(s.values||{}),sources:s.sources.map(l=>l.name+' · '+l.source).join('; ')})),[['conflict',t('Конфликты','Conflicts')],['label',t('Параметр','Setting')],['category',t('Категория','Category')],['state',t('Состояние','State')],['values',t('Значения','Values')],['sources',t('GPO-источники','Source GPOs')]]);
          const conflicts=section.values.filter(v=>v.conflict);
          if(conflicts.length){const box=el('details','policy-model-conflicts');box.open=true;box.append(el('summary','',t('Конфликты значений: ','Value conflicts: ')+conflicts.length),el('p','muted',t('Победитель определяется порядком GPO: принудительные ссылки, наследование и порядок ссылок (1 — выше). В loopback Merge пользовательские параметры из расположения компьютера идут перед параметрами из расположения пользователя.','The winner follows GPO precedence: enforced links, inheritance and link order (1 is highest). In loopback Merge, user settings from the computer location precede those from the user location.')));for(const v of conflicts){box.append(el('h4','mono',v.key+'\\'+v.name),el('p','',t('Победившая GPO: ','Winning GPO: ')+v.winner.name+' · '+v.winner.source+' · '+(v.winner.enforced?'Enforced · ':'')+t('порядок ссылки ','link order ')+v.winner.order));topologyTable(box,v.contributions.map((c,i)=>({gpo:c.source.name,source:c.source.source,type:c.type,value:c.deleted?t('Удаление значения','Delete value'):c.value,status:i===0?t('Победитель','Winner'):t('Перекрыта','Overridden')})),[['gpo','GPO'],['source',t('Источник','Source')],['type',t('Тип','Type')],['value',t('Значение','Value')],['status',t('Результат','Result')]]);}part.append(box);}
          const raw=el('details');raw.append(el('summary','',t('Значения Registry.pol и конкурирующие GPO','Registry.pol values and competing GPOs')));topologyTable(raw,section.values.map(v=>({...v,modelConflict:v.conflict,conflict:v.conflict?t('Конфликт','Conflict'):'—',value:v.deleted?t('Удаление значения','Delete value'):v.value,winner:v.winner.name,precedence:v.precedence.map(l=>l.name+' · '+l.source).join(' ← ')})),[['conflict',t('Конфликты','Conflicts')],['key',t('Ключ','Key')],['name',t('Имя','Name')],['value',t('Значение','Value')],['winner',t('Победившая GPO','Winning GPO')],['precedence',t('Приоритет GPO','GPO precedence')]]);part.append(raw);result.append(part);
        }
        const limits=el('details');limits.append(el('summary','',t('Границы расчёта','Calculation limits')));for(const item of report.limitations)limits.append(el('p','muted',item));result.append(limits);
      }
    }catch(e){if(generation===dialogGeneration)message(notice,e.message,true);}
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
    for(const row of rows){const tr=el('tr',row.modelConflict?'policy-model-conflict':'');columns.forEach(([key])=>tr.append(el('td','',Array.isArray(row[key])?row[key].join('; '):value(row[key]))));if(actions.length){const td=el('td');for(const a of actions){if(allowed(a)&&(!a.when||a.when(row)))td.append(button(a.label,()=>openOperation(a,row),a.danger?'danger':''));}tr.append(td);}table.append(tr);}wrap.append(table);parent.append(wrap);if(!rows.length)parent.append(el('p','muted',t('Нет объектов','No objects')));
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
