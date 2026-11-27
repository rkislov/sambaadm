(function () {
  'use strict';
  const host = document.getElementById('share-permission-map');
  if (!host) return;
  const admin = host.dataset.admin === 'true', share = host.dataset.share;
  const server = new URLSearchParams(location.search).get('node');
  const endpoint = '/api/v1/shares/' + encodeURIComponent(share) + '/permission-map';
  const storageKey = 'sambaadm.permission-templates.v1';
  const templateID = () => globalThis.crypto?.randomUUID?.() || 'template-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
  const el = (tag, text = '', cls = '') => { const e = document.createElement(tag); e.textContent = text; if (cls) e.className = cls; return e; };
  const button = (text, fn) => { const b = el('button', text); b.type = 'button'; b.onclick = fn; return b; };
  const field = (parent, label, input) => { const l = el('label', label); input.setAttribute('aria-label', label); l.append(input); parent.append(l); return input; };
  const contains = (parent, child) => parent === '.' || parent === child || child.startsWith(parent + '/');
  function url(path, query = {}) { const u = new URL(path, location.origin); for (const [k, v] of Object.entries(query)) u.searchParams.set(k, v); if (server) u.searchParams.set('node', server); return u.pathname + u.search; }
  async function request(path, method = 'GET', body) {
    const r = await fetch(path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name=csrf-token]')?.content || ''}, body: body === undefined ? undefined : JSON.stringify(body)});
    const data = await r.json(); if (!r.ok) { const error = Error(data.error || 'HTTP ' + r.status); error.status = r.status; throw error; } return data;
  }
  let snapshot = null, overlays = [], plan = null, selected = '.', busy = false, outdated = false;
  let templates = [];
  try { const saved = JSON.parse(localStorage.getItem(storageKey) || '[]'); if (Array.isArray(saved)) templates = saved.slice(0,64).map(t => { try { return cleanTemplate(t, typeof t?.id === 'string' ? t.id : templateID()); } catch (_) { return null; } }).filter(Boolean); } catch (_) { /* A broken browser library never becomes an apply request. */ }
  function modal(title, cls) {
    const dialog = el('dialog', '', 'share-map-dialog ' + cls);
    const heading = el('header', '', 'share-map-dialog-heading');
    const h = el('h2', title); h.id = cls + '-title'; dialog.setAttribute('aria-labelledby', h.id);
    const close = button('×', () => dialog.close()); close.className = 'share-map-close'; close.setAttribute('aria-label', 'Закрыть окно');
    heading.append(h, close); dialog.append(heading); host.append(dialog);
    dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
    return dialog;
  }
  function showDialog(dialog) { if (!dialog.open) dialog.showModal(); }
  const tools = el('div', '', 'share-map-toolbar');
  const rootInput = field(tools, 'Корень снимка (путь внутри ресурса)', el('input')); rootInput.value = host.dataset.root || '.';
  const capture = button('Снять карту прав', captureMap), exportSnapshot = button('Скачать снимок JSON', () => download('permission-map.json', {format:1, server, snapshot}));
  tools.append(capture); host.append(tools);
  const extra = el('details', '', 'share-map-extra'); extra.append(el('summary','Ещё'),exportSnapshot); tools.append(extra);
  const snapshotMeta = el('p', '', 'share-map-meta'); host.append(snapshotMeta);
  const status = el('p', '', 'share-map-status'); status.setAttribute('role', 'status'); status.hidden = true; host.append(status);
  const empty = el('section','','share-map-start');
  empty.append(el('h2','Начните со снимка дерева'),el('p','Укажите папку внутри ресурса и нажмите «Снять карту прав». Затем выберите каталог на схеме и наложите шаблон.'));
  host.append(empty);
  const workbench = el('div', '', 'share-map-workbench'), diagram = el('section', '', 'share-map-diagram'), aside = el('aside', '', 'share-map-sidebar');
  workbench.hidden = true;
  const legend = el('div','','share-map-legend');
  for (const [cls,label] of [['snapshot','Снимок'],['overlay','Наложен шаблон'],['change','ACL изменится'],['error','Ошибка чтения']]) legend.append(el('span',label,cls));
  const canvas = el('div'), detail = el('section', '', 'share-map-detail'); diagram.append(legend, canvas); workbench.append(diagram, aside); host.append(workbench);
  const selection = el('p', 'Выберите папку на карте.', 'share-map-selection'); aside.append(selection);
  const sideTabs = el('div','','share-map-side-tabs'), folderPane = el('section'), assignments = el('section','','share-map-assignments');
  const folderTab = button('Права папки', () => showSideTab('folder')), overlaysTab = button('Наложения · 0', () => showSideTab('overlays'));
  sideTabs.append(folderTab); if (admin) sideTabs.append(overlaysTab);
  folderPane.append(detail); aside.append(sideTabs,folderPane,assignments);
  function showSideTab(tab) { folderPane.hidden = tab !== 'folder'; assignments.hidden = tab !== 'overlays'; folderTab.setAttribute('aria-pressed',String(tab === 'folder')); overlaysTab.setAttribute('aria-pressed',String(tab === 'overlays')); }
  showSideTab('folder');
  const library = el('section'), previewArea = el('section','','share-map-preview'), resultArea = el('section','','share-map-result');
  let templateSelect, recursive, preview, apply, confirm, afterToggle, overlayButton;
  let libraryDialog, reviewDialog, reportDialog, libraryList, libraryNotice, templateEditor, libraryManager, editorTab, managerTab;
  const nameInput = el('input'), rulesBox = el('div'), inheritInput = el('input'); inheritInput.type = 'checkbox'; inheritInput.checked = true;
  const groupList = el('datalist'); groupList.id = 'permission-map-groups'; host.append(groupList);
  if (admin) setupEditor();
  else aside.append(el('p', 'Режим просмотра. Изменять права может администратор.', 'muted'));
  const help=el('details','','share-map-help');help.append(el('summary','О карте прав'),el('p','Карта показывает POSIX ACL каталогов и права по умолчанию для новых объектов. Она не рассчитывает итоговый SMB-доступ. Существующие файлы сохраняют права. Применение нескольких папок не является атомарным; исходные ACL сохраняются в журнале.'));host.append(help);
  rootInput.addEventListener('input', () => { if (!snapshot) return; outdated=true; invalidate(); message('Корень снимка изменён. Снимите новую карту перед наложением шаблонов.'); });
  sync();

  function download(name, data) { const a = el('a'); const href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'})); a.href = href; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(href), 1000); }
  function message(text, error = false) { status.textContent = text; status.hidden = !text; status.classList.toggle('error', error); if (libraryDialog?.open) { libraryNotice.textContent = text; libraryNotice.classList.toggle('error',error); } }
  function sync() {
    snapshotMeta.textContent = snapshot ? 'Каталогов: ' + snapshot.nodes.length + ' · ' + new Date(snapshot.created).toLocaleString() + (outdated ? ' · снимок устарел' : ' · только каталоги, существующие файлы сохраняют права') : '';
    empty.hidden = !!snapshot; workbench.hidden = !snapshot;
    capture.disabled = busy; rootInput.disabled = busy; exportSnapshot.disabled = busy || !snapshot;
    if (!admin) return;
    preview.disabled = busy || !snapshot?.complete || outdated || !overlays.length;
    apply.disabled = busy || !plan?.changes.length || !confirm.checked || outdated;
    confirm.disabled = busy || !plan?.changes.length || outdated;
    templateSelect.disabled = busy || !snapshot?.complete || outdated;
    overlayButton.disabled = busy || !snapshot?.complete || outdated || !templateSelect.value;
    preview.textContent = 'Предпросмотр изменений';
    afterToggle.closest('label').hidden = !plan;
  }
  function setBusy(value) {
    busy = value;
    for (const input of host.querySelectorAll('button,input,select')) {
      if (value) { input.dataset.wasDisabled = String(input.disabled); input.disabled = true; }
      else input.disabled = input.dataset.wasDisabled === 'true';
    }
    sync();
  }
  function invalidate() { plan = null; if (confirm) confirm.checked = false; previewArea.replaceChildren(); sync(); }
  async function captureMap() {
    if (busy) return; setBusy(true); invalidate(); message('Чтение дерева и POSIX ACL…');
    try {
      const data = await request(url(endpoint, {path:rootInput.value}));
      snapshot = data; selected = data.root; overlays = []; outdated = false; resultArea.replaceChildren();
      renderAssignments(); showSideTab('folder'); draw();
      message(data.complete ? '' : 'Карта неполная, применение заблокировано. ' + data.warnings.join(' '), !data.complete);
    } catch (error) { message(error.message, true); outdated = true; }
    finally { setBusy(false); }
  }
  function setupEditor() {
    libraryDialog = modal('Библиотека шаблонов', 'share-map-library-dialog');
    libraryNotice = el('p','','share-map-library-notice'); libraryNotice.setAttribute('role','status');
    const tabs = el('div','','share-map-editor-tabs');
    managerTab = button('Сохранённые шаблоны', () => libraryMode('library'));
    editorTab = button('Редактор шаблона', () => libraryMode('editor')); tabs.append(managerTab,editorTab);
    libraryManager = el('section'); templateEditor = el('section','','share-map-template-editor');
    libraryList = el('div','','share-map-template-list');
    const newTemplate = button('Новый шаблон', () => editTemplate()); newTemplate.className='share-map-primary';
    libraryManager.append(newTemplate,libraryList);
    templateEditor.append(el('p','Назначьте права доменным группам. Остальные записи сохранят эффективные разрешения.','muted'));
    templateEditor.append(el('p','В каталогах x означает проход внутрь папки: для чтения нужен r-x, для записи — rwx. ACL-маска тоже должна сохранять x.','muted'));
    field(templateEditor, 'Название шаблона', nameInput);
    templateEditor.append(rulesBox, button('Добавить группу в шаблон', () => addRule()));
    field(templateEditor, 'Те же права для новых объектов (ACL по умолчанию)', inheritInput);
    const save = button('Сохранить шаблон', saveTemplate); save.className='share-map-primary'; templateEditor.append(save);
    const transfers = el('details', '', 'share-map-library-transfer'); transfers.append(el('summary','Импорт и экспорт шаблонов'));
    transfers.append(button('Экспорт шаблонов', () => download('permission-templates.json', {format:1, templates})));
    const file = field(transfers, 'Импорт шаблонов JSON', el('input')); file.type = 'file'; file.accept = '.json,application/json';
    file.onchange = async () => {
      try {
        if (!file.files[0] || file.files[0].size > 262144) throw Error('Файл шаблонов должен быть меньше 256 КБ.');
        const data = JSON.parse(await file.files[0].text());
        if (data.format !== 1 || !Array.isArray(data.templates) || data.templates.length > 64) throw Error('Неверный формат библиотеки.');
        for (const t of data.templates) validateTemplate(t);
        templates = [...templates, ...data.templates.map(t => cleanTemplate(t,templateID()))].slice(0,64); persistTemplates(); file.value = '';
      } catch (error) { message(error.message, true); }
    };
    libraryManager.append(transfers,el('p','Библиотека хранится в этом браузере. Для переноса на другой компьютер используйте экспорт.','muted'));
    library.append(tabs,libraryNotice,libraryManager,templateEditor); libraryDialog.append(library);
    const libraryButton = button('Шаблоны прав', () => { libraryMode('library'); libraryNotice.textContent=''; showDialog(libraryDialog); });
    tools.insertBefore(libraryButton,extra);
    const assignBox = el('section','','share-map-assign-box'); assignBox.append(el('h3','Назначить шаблон'));
    templateSelect = field(assignBox, 'Шаблон для наложения', el('select')); templateSelect.onchange=sync;
    recursive = field(assignBox, 'Всё выбранное поддерево каталогов', el('input')); recursive.type = 'checkbox'; recursive.checked = true;
    overlayButton = button('Наложить на выбранную папку', () => addOverlay()); assignBox.append(overlayButton);
    folderPane.append(assignBox);
    reviewDialog = modal('Проверка изменений', 'share-map-review-dialog');
    reviewDialog.append(previewArea);
    const reviewFooter=el('footer','','share-map-review-footer');
    confirm = field(reviewFooter, 'Подтверждаю применение показанных изменений к каталогам', el('input')); confirm.type = 'checkbox'; confirm.onchange = sync;
    const reviewActions=el('div','','share-map-review-actions');
    apply = button('Применить к дереву папок', applyChanges); apply.className='share-map-primary';
    reviewActions.append(button('Посмотреть на карте',()=>reviewDialog.close()),apply); reviewFooter.append(reviewActions); reviewDialog.append(reviewFooter);
    preview = button('Предпросмотр изменений', previewChanges); preview.className='share-map-primary';tools.insertBefore(preview,extra);
    afterToggle = field(diagram, 'Показывать ACL после предпросмотра', el('input')); afterToggle.type='checkbox'; afterToggle.checked=true;afterToggle.onchange=()=>draw(); afterToggle.closest('label').className='share-map-after-toggle';
    reportDialog=modal('Результат применения','share-map-report-dialog');reportDialog.append(resultArea);
    const reportFooter=el('footer','','share-map-review-actions');reportFooter.append(button('Закрыть отчёт',()=>reportDialog.close()),button('Снять новую карту',()=>{reportDialog.close();captureMap();}));reportDialog.append(reportFooter);
    addRule(); renderLibrary(); libraryMode('library');
    request(url('/api/v1/groups')).then(groups => {
      for (const g of groups.filter(g => g.category === 'security')) { const o = el('option'); o.value = g.samAccountName; o.label = g.description || g.samAccountName; groupList.append(o); }
    }).catch(e => message('Не удалось загрузить группы: ' + e.message, true));
  }
  function libraryMode(mode) { libraryDialog.querySelector('header h2').textContent=mode==='library'?'Библиотека шаблонов':'Редактор шаблона';libraryManager.hidden=mode!=='library';templateEditor.hidden=mode!=='editor';managerTab.setAttribute('aria-pressed',String(mode==='library'));editorTab.setAttribute('aria-pressed',String(mode==='editor')); }
  function editTemplate(t) {
    nameInput.value=t?.name || '';inheritInput.checked=t?.inherit ?? true;rulesBox.replaceChildren();
    for(const rule of t?.rules || [{}])addRule(rule);
    libraryNotice.textContent='';libraryMode('editor');showDialog(libraryDialog);nameInput.focus();
  }
  function addRule(rule = {}) {
    if (rulesBox.children.length >= 32) { message('В шаблоне не более 32 групп.', true); return; }
    const row = el('div', '', 'share-map-rule');
    const group = field(row, 'Группа безопасности AD', el('input')); group.setAttribute('list', groupList.id); group.value = rule.group || ''; group.dataset.ruleGroup = '1';
    const permissions = field(row, 'Права группы', el('select')); permissions.dataset.rulePermissions = '1';
    for (const [value, title] of [['r-x','Чтение и проход (r-x)'],['rwx','Чтение, запись и проход (rwx)'],['remove','Удалить прямую запись группы']]) { const o = el('option', title); o.value = value; permissions.append(o); }
    permissions.value = rule.permissions || 'r-x';
    const remove=button('×', () => row.remove());remove.setAttribute('aria-label','Убрать группу');remove.className='share-map-rule-remove';row.append(remove); rulesBox.append(row);
  }
  function validateTemplate(t) {
    if (typeof t.name !== 'string' || !t.name.trim() || t.name.length > 120 || !Array.isArray(t.rules) || !t.rules.length || t.rules.length > 32 || typeof t.inherit !== 'boolean') throw Error('Шаблон должен содержать название и от 1 до 32 групп.');
    const seen = new Set();
    for (const r of t.rules) { if (typeof r.group !== 'string' || !r.group.trim() || !['r-x','rwx','remove'].includes(r.permissions) || seen.has(r.group.toLowerCase())) throw Error('Укажите разные группы и поддерживаемые права.'); seen.add(r.group.toLowerCase()); }
  }
  function cleanTemplate(t, id) {
    validateTemplate(t);
    return {id, name:t.name.trim(), inherit:t.inherit, rules:t.rules.map(r => ({group:r.group.trim(), permissions:r.permissions}))};
  }
  function saveTemplate() {
    if (busy) return;
    try {
      const t = {id:templateID(), name:nameInput.value.trim(), inherit:inheritInput.checked, rules:[...rulesBox.children].map(row => ({group:row.querySelector('[data-rule-group]').value.trim(), permissions:row.querySelector('[data-rule-permissions]').value}))};
      validateTemplate(t);
      const existing = templates.findIndex(x => x.name === t.name);
      if (existing >= 0) { t.id = templates[existing].id; templates[existing] = t; } else { if (templates.length >= 64) throw Error('В библиотеке не более 64 шаблонов.'); templates.push(t); }
      persistTemplates(); templateSelect.value = t.id;libraryDialog.close();showSideTab('folder');sync();message('Шаблон «'+t.name+'» сохранён. Можно наложить его на выбранную папку.');
    } catch (error) { message(error.message, true); }
  }
  function persistTemplates() { try { localStorage.setItem(storageKey, JSON.stringify(templates)); } catch (_) { message('Библиотека работает в памяти; браузер не разрешил постоянное сохранение.', true); } renderLibrary(); }
  function renderLibrary() {
    const previous = templateSelect.value; templateSelect.replaceChildren();
    const blank = el('option', 'Выберите сохранённый шаблон'); blank.value = ''; templateSelect.append(blank);
    for (const t of templates) { const option = el('option', t.name); option.value = t.id; templateSelect.append(option); }
    if (templates.some(t => t.id === previous)) templateSelect.value = previous;
    libraryList.replaceChildren();
    if (!templates.length) libraryList.append(el('p','Сохранённых шаблонов пока нет. Создайте первый шаблон или импортируйте библиотеку.','muted'));
    for(const t of templates){
      const row=el('article','','share-map-template-item'), description=el('div');
      description.append(el('h3',t.name),el('p',t.rules.map(r=>r.group+' · '+(r.permissions==='remove'?'удалить запись':r.permissions)).join(' / ')),el('small',t.inherit?'С правами для новых объектов':'Только права существующих папок'));
      const actions=el('div','','share-map-template-actions');
      actions.append(button('Выбрать',()=>{templateSelect.value=t.id;libraryDialog.close();showSideTab('folder');sync();}),button('Изменить',()=>editTemplate(t)));
      const remove=button('Удалить',()=>{templates=templates.filter(x=>x.id!==t.id);persistTemplates();sync();});remove.className='share-map-quiet';actions.append(remove);
      row.append(description,actions);libraryList.append(row);
    }
  }
  function addOverlay() {
    if (busy || !snapshot?.complete || outdated) { message('Сначала снимите полную актуальную карту.', true); return; }
    const t = templates.find(t => t.id === templateSelect.value);
    if (!t) { message('Сохраните и выберите шаблон.', true); return; }
    if (overlays.length >= 64) { message('Не более 64 наложений в одном плане.', true); return; }
    overlays.push({path:selected, recursive:recursive.checked, template:JSON.parse(JSON.stringify(t))});
    // IDs belong to the local library and are not part of the server schema.
    delete overlays[overlays.length - 1].template.id;
    invalidate(); renderAssignments(); draw();showSideTab('overlays');message('Шаблон наложен на план. Права на сервере пока не менялись.');
  }
  function renderAssignments() {
    if (!admin) return;overlaysTab.textContent='Наложения · '+overlays.length; assignments.replaceChildren(el('p','При пересечении последнее правило группы имеет приоритет.','muted'));
    if(!overlays.length)assignments.append(el('p','Выберите папку на карте и назначьте ей шаблон.','muted'));
    overlays.forEach((o, i) => {
      const row = el('div', '', 'share-map-assignment');
      row.append(el('strong', (i+1) + '. ' + o.template.name), el('p', o.path + (o.recursive ? ' — всё поддерево' : ' — только эта папка')));
      row.append(button('Выше', () => { if (busy || !i) return; [overlays[i-1],overlays[i]]=[overlays[i],overlays[i-1]]; invalidate(); renderAssignments(); draw(); }), button('Убрать наложение', () => { if (busy) return; overlays.splice(i,1); invalidate(); renderAssignments(); draw(); })); assignments.append(row);
    });
  }
  function payload() { return {root:snapshot.root, snapshotRevision:snapshot.revision, overlays}; }
  async function previewChanges() {
    if (busy || !snapshot?.complete || outdated || !overlays.length) return;
    if(plan){showDialog(reviewDialog);return;}
    invalidate(); setBusy(true); message('Проверка дерева, групп и расчёт изменений…');
    try {
      plan = await request(url(endpoint + '/plan'), 'POST', payload());
      previewArea.replaceChildren(el('h3', 'Изменится папок: ' + plan.changes.length + ' из ' + plan.directories));
      previewArea.append(el('p','Исходные ACL будут сохранены в журнале. Применение затрагивает каталоги и их ACL по умолчанию; существующие файлы сохраняют права.','muted'));
      const explanation=el('details','','share-map-apply-explanation');explanation.append(el('summary','Как выполняется применение'),el('p','Дерево и права повторно проверяются перед записью. Папки обновляются последовательно; при ошибке операция остановится с отчётом. На время применения остановите другие редакторы прав.'));previewArea.append(explanation);
      plan.changes.forEach((change,index) => {
        const d=el('details','','share-map-change');d.open=index===0;
        d.append(el('summary',change.path+' · '+change.templates.join(' → ')));
        const names=new Map((change.before.entries||[]).filter(e=>e.qualifier).map(e=>[e.qualifier,e.identity||e.qualifier]));
        for(const [gid,name] of Object.entries(plan.groups||{}))names.set(gid,name);
        const parse=text=>new Map(text.split('\n').filter(Boolean).map(line=>{const parts=line.split(':');const perms=parts.pop();return [parts.join(':'),perms];}));
        const before=parse(change.before.access+'\n'+change.before.default),after=parse(change.access+'\n'+change.default);
        const diff=el('div','','share-map-diff'),baseDiff=el('div','','share-map-diff');let baseCount=0;
        for(const key of new Set([...before.keys(),...after.keys()])){
          if(before.get(key)===after.get(key))continue;
          const parts=key.split(':'),def=parts[0]==='default';if(def)parts.shift();
          const who=names.get(parts[1])||parts[1]||({user:'Владелец',group:'Группа-владелец',mask:'ACL-маска',other:'Остальные'})[parts[0]];
          const row=el('div','','share-map-diff-row'),label=el('div');label.append(el('strong',who),el('small',def?'Новые объекты':'Доступ к папке'));
          row.append(label,el('code',before.get(key)||'нет','before'),el('span','→'),el('code',after.get(key)||'удалено','after'));
          if(!parts[1]&&parts[0]!=='mask'){baseDiff.append(row);baseCount++;}else diff.append(row);
        }
        d.append(diff);
        if(baseCount){const base=el('details','','share-map-base-diff');base.append(el('summary','Базовые записи · '+baseCount),baseDiff);d.append(base);}
        const raw=el('details','','share-map-raw');raw.append(el('summary','Исходный POSIX ACL'));
        const columns=el('div','','share-map-raw-columns');
        for(const [label,text]of [['До',change.before.access+'\n'+change.before.default],['После',change.access+'\n'+change.default]]){const box=el('div');box.append(el('h4',label),el('pre',text));columns.append(box);}raw.append(columns);d.append(raw);previewArea.append(d);
      });
      draw(); showDialog(reviewDialog);
      message(plan.changes.length ? 'Предпросмотр готов. Проверьте ACL и подтвердите применение.' : 'Шаблоны уже соответствуют правам. Изменений нет.');
    } catch (error) { plan = null; if (error.status === 409) outdated = true; message(error.message, true); }
    finally { setBusy(false); }
  }
  async function applyChanges() {
    if (busy || !plan?.changes.length || !confirm.checked || outdated) return;
    const input = {...payload(), planRevision:plan.revision, confirm:true}; setBusy(true); message('Применение шаблонов к каталогам…');
    try {
      const result = await request(url(endpoint + '/apply'), 'POST', input);
      reviewDialog.close();
      const applied=result.items.filter(i=>i.status==='applied').length;
      resultArea.replaceChildren(el('h3',result.status==='complete'?'Применено':'Применено частично'),el('p','Права записаны и проверены: '+applied+' из '+result.items.length+' папок.'));
      if(result.error)resultArea.append(el('p',result.error,'error'));
      const labels={applied:'Права записаны и проверены',failed:'Ошибка (ACL мог измениться частично)',pending:'Не изменялось',applying:'Запись не подтверждена'};
      const items=el('details');items.open=result.status!=='complete';items.append(el('summary','Результат по папкам'));
      for(const item of result.items)items.append(el('p',item.path+' · '+(labels[item.status]||item.status)+(item.error?': '+item.error:'')));
      const technical=el('details');technical.append(el('summary','Журнал исходных ACL'),el('p',result.journal));resultArea.append(items,technical);showDialog(reportDialog);
      outdated = true; message(result.status === 'complete' ? 'Шаблоны применены. Снимите новую карту для дальнейшей работы.' : 'Операция остановлена после ошибки. Проверьте отчёт и снимите новую карту.', result.status !== 'complete');
    } catch (error) { outdated = true; reviewDialog.close();resultArea.replaceChildren(el('h2','Результат не подтверждён'),el('p',error.message+' Снимите новую карту; при обрыве соединения проверьте журнал на сервере.'));showDialog(reportDialog);message('Результат операции не подтверждён. Проверьте отчёт.',true); }
    finally { invalidate(); draw(); setBusy(false); }
  }
  function nodeEntries(node) {
    const change = afterToggle?.checked && plan?.changes.find(c => c.path === node.path);
    if (!change) return node.entries || [];
    const names = new Map((node.entries || []).filter(e => e.qualifier).map(e => [e.qualifier,e.identity || e.qualifier]));
    for (const [gid, group] of Object.entries(plan.groups || {})) names.set(gid, group);
    return (change.access + '\n' + change.default).split('\n').filter(Boolean).map(line => { const parts = line.split(':'), def = parts[0] === 'default'; if (def) parts.shift(); return {kind:parts[0],qualifier:parts[1],perms:parts[2],default:def,identity:names.get(parts[1])}; });
  }
  function inspect(node) {
    selection.textContent=node.path==='.'?share+' /':node.path;
    detail.replaceChildren(el('h2','Доступ к папке'));
    if(node.error){detail.append(el('p',node.error,'error'));return;}
    const entries=nodeEntries(node);
    for(const [def,title]of [[false,plan&&afterToggle?.checked?'После применения':'Права в снимке'],[true,'Новые объекты']]){
      const selectedEntries=entries.filter(e=>e.default===def);if(!selectedEntries.length)continue;
      detail.append(el('h3',title));const list=el('div','','share-map-acl-list');
      for(const entry of selectedEntries){
        const who=entry.identity||entry.qualifier||({group:node.group+' (группа-владелец)',user:node.owner+' (владелец)',mask:'ACL-маска',other:'Остальные'})[entry.kind];
        const row=el('div','','share-map-acl-row');row.append(el('span',who),el('code',entry.effective||entry.perms));
        if(entry.effective)row.title='Назначено '+entry.perms+'; с учётом маски '+entry.effective;list.append(row);
      }detail.append(list);
    }
    const properties=el('details','','share-map-properties');properties.append(el('summary','Владелец и режим'),el('p','Владелец: '+node.owner),el('p','Группа: '+node.group),el('p','Режим снимка: '+node.mode));detail.append(properties);
    const link=el('a','Подробный редактор ACL');link.href=url('/shares/'+encodeURIComponent(share)+'/acl',{path:node.path});detail.append(link);
  }

  function draw() {
    canvas.replaceChildren(); if (!snapshot) return;
    const byParent = new Map(); for (const n of snapshot.nodes) { const parent = n.parent || ''; if (!byParent.has(parent)) byParent.set(parent,[]); byParent.get(parent).push(n); }
    const positions = new Map(), ordered = [];
    let leafRows=0;
    function visit(n,depth) {
      ordered.push(n);const children=byParent.get(n.path)||[];for(const child of children)visit(child,depth+1);
      const y=children.length?(positions.get(children[0].path).y+positions.get(children.at(-1).path).y)/2:25+leafRows++*128;
      positions.set(n.path,{x:30+depth*280,y});
    }
    const root = snapshot.nodes.find(n => n.path === snapshot.root); if (root) visit(root,0);
    const width = Math.max(400,...[...positions.values()].map(p => p.x+250)), height = Math.max(280,leafRows*128+40);
    const map = el('div','','topology-map share-rights-map');
    const wires = document.createElementNS('http://www.w3.org/2000/svg','svg'); wires.setAttribute('width',width); wires.setAttribute('height',height); wires.classList.add('share-map-wires');
    for (const n of ordered) {
      const p = positions.get(n.path), parent = positions.get(n.parent);
      if (parent) { const line = document.createElementNS(wires.namespaceURI,'polyline'); line.setAttribute('points',`${parent.x+220},${parent.y+52} ${p.x-25},${parent.y+52} ${p.x-25},${p.y+52} ${p.x},${p.y+52}`); line.dataset.source=n.parent;line.dataset.destination=n.path;wires.append(line); }
    }
    map.append(wires);
    for (const n of ordered) {
      const p = positions.get(n.path), affected = overlays.filter(o => o.path === n.path || o.recursive && contains(o.path,n.path));
      const change = plan?.changes.find(c => c.path === n.path);
      const b = button('',() => { if (busy) return; selected=n.path; inspect(n);showSideTab('folder'); map.querySelectorAll('.share-map-node').forEach(x => x.classList.toggle('selected',x.dataset.dc===selected)); });
      b.className='topology-node share-map-node'; b.dataset.dc=n.path;b.dataset.x=p.x+110;b.dataset.y=p.y+52;
      b.style.left=p.x+'px';b.style.top=p.y+'px'; b.setAttribute('aria-label',n.path);b.classList.toggle('selected',n.path===selected);
      b.classList.toggle('has-overlay',affected.length>0); b.classList.toggle('has-change',!!change); b.classList.toggle('has-error',!!n.error);
      const access = afterToggle?.checked && change ? change.access : n.access;
      const mask = access.split('\n').find(line=>line.startsWith('mask:'))?.split(':')[2] || 'нет';
      b.append(el('strong',n.name),el('span','ACL-маска: '+mask),el('span',n.error?'Ошибка чтения':change?'Изменение ACL':affected.map(o=>o.template.name).join(' → ') || 'Снимок ACL'));
      b.append(el('span',nodeEntries(n).filter(e=>e.kind==='group' && e.qualifier && !e.default).map(e=>(e.identity||e.qualifier)+': '+e.perms).join(' · ') || 'Именованных групп нет'));
      const title = n.path + '\n' + nodeEntries(n).filter(e=>e.kind==='group').map(e=>(e.identity||e.qualifier||n.group)+': '+e.perms).join('\n');b.title=title;
      // Search includes group names as well as directory names.
      const index=el('span',title,'share-map-search-index');index.hidden=true;b.append(index);map.append(b);
    }
    if (window.sambaadmTopologyViewport) canvas.append(window.sambaadmTopologyViewport(map,width,height,{directory:true,caseSensitive:true,selected}));else canvas.append(map);
    const selectedNode=snapshot.nodes.find(n=>n.path===selected)||root;if(selectedNode)inspect(selectedNode);
  }
})();
