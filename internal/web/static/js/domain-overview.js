/* Read-only overview. Observations retain their source, time and partial states. */
(function () {
  'use strict';
  const root = document.getElementById('domain-overview');
  if (!root) return;
  const admin = root.dataset.admin === 'true', ru = document.documentElement.lang === 'ru';
  const t = (a, b) => ru ? a : b;
  const el = (tag, text = '') => { const n = document.createElement(tag); n.textContent = text; return n; };
  const unknown = t('Не проверено / неизвестно', 'Not checked / unknown');
  const statusText = value => ({complete:t('Сбор завершён', 'Collection complete'),partial:t('Неполные данные', 'Partial data'),available:t('Доступно', 'Available'),unavailable:t('Недоступно', 'Unavailable'),unknown:t('Неизвестно', 'Unknown'),review:t('Требует проверки', 'Needs review'),ok:t('Проверено', 'Checked')})[value] || value;
  const findingText = code => ru ? ({unresolved_fromServer:'Не найдён источник репликации',missing_fromServer:'Нет ссылки на источник репликации',connection_parent:'Не найден родитель соединения',ntds_parent:'Не найден сервер для NTDS Settings',server_without_ntds:'Сервер без NTDS Settings',server_without_computer:'Нет ссылки на учётную запись DC',server_computer_reference:'Не подтверждена учётная запись DC',site_without_servers:'Сайт без серверов',dc_computer_without_server:'Учётная запись DC без объекта сервера',unresolved_siteObject:'Не найден сайт подсети',missing_siteObject:'Подсеть без ссылки на сайт',unresolved_siteList:'Не найден сайт в связи',missing_siteList:'Связь без ссылок на сайты'})[code] || code : code;
  const formatTime = window.sambaadmFormatTime;

  const report = {schema: 1, sections: {}, checks: {}, replication: {status:'not-checked'}};
  document.addEventListener('sambaadm:replication', e => { report.replication = {observed:new Date().toISOString(),controllers:e.detail}; });
  const actions = el('div'); actions.className = 'overview-actions';
  const refresh = el('button', t('Обновить обзор домена', 'Refresh domain overview'));
  const download = el('button', t('Скачать отчёт обследования JSON', 'Download survey JSON'));
  actions.append(refresh, download); root.append(el('h2', t('Обзор и обследование домена', 'Domain overview and survey')), actions);
  root.append(el('p', t('Отчёт содержит наблюдения разных моментов времени. Недоступная проверка не означает исправность. Экспорт включает имена объектов и события аудита.', 'Observations are taken at different times. An unavailable check does not mean healthy. Export includes object names and audit events.')));
  const sections = {};
  for (const [id, title] of [['domain', t('Состояние домена', 'Domain state')], ['controllers', t('Конфигурация контроллеров', 'Controller configuration')], ['sites', t('Региональные площадки', 'Regional sites')], ['diagnostics', t('Журналы и диагностика', 'Logs and diagnostics')]]) {
    const section = el('section'); section.className = 'overview-section'; section.dataset.overview = id;
    const content = el('div'); section.append(el('h3', title), content); root.append(section); sections[id] = content;
  }
  async function request(path, body) {
    const response = await fetch('/api/v1' + path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', signal: AbortSignal.timeout(path.endsWith("/cleanup/apply") ? 300000 : path.endsWith("/cleanup/checks") ? 90000 : 35000), headers: {Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''}, body: body === undefined ? undefined : JSON.stringify(body)});
    const data = await response.json(); if (!response.ok) throw Error(data.error || 'HTTP ' + response.status); return data;
  }
  let pending = 0;
  async function observe(key, path, body) {
    pending++; refresh.disabled = true;
    const entry = {source: path, started: new Date().toISOString()};
    try { entry.data = await request(path, body); entry.status = 'available'; } catch (e) { entry.status = 'unavailable'; entry.error = e.message; }
    entry.finished = new Date().toISOString(); report.sections[key] = entry; if (key === 'diagnostics') report.checks.dnsHealth = {status:entry.status,section:key}; if (key === 'sysvol') report.checks.sysvolConsistency = {status:entry.status,section:key,scope:path}; pending--; if (!pending) refresh.disabled = false; return entry;
  }
  function table(parent, headings, rows) {
    const wrap = el('div'); wrap.className = 'overview-table'; const table = el('table'), head = el('tr');
    headings.forEach(h => head.append(el('th', h))); const thead = el('thead'); thead.append(head); table.append(thead);
    const body = el('tbody'); for (const row of rows) { const tr = el('tr'); row.forEach(v => tr.append(el('td', v == null || v === '' ? unknown : typeof v === 'boolean' ? (v ? t('Да', 'Yes') : t('Нет', 'No')) : String(v)))); body.append(tr); } table.append(body); wrap.append(table); parent.append(wrap);
    if (!rows.length) parent.append(el('p', t('В ответе нет записей. Полнота зависит от прав чтения.', 'No entries returned. Completeness depends on read permissions.')));
  }
  function block(parent, title, result, render) {
    const box = el('div'); box.append(el('h4', title)); parent.append(box);
    box.append(el('p', t('Получено: ', 'Observed: ') + formatTime(result.finished)));
    if (result.status !== 'available') { box.append(el('p', t('Недоступно: ', 'Unavailable: ') + result.error)); return; }
    try { render(box, result.data); } catch (_) { result.status = 'unavailable'; result.error = 'Unexpected response'; box.append(el('p', unknown)); }
  }
  function jsonDetail(parent, title, value) { const details = el('details'); details.append(el('summary', title), el('pre', JSON.stringify(value, null, 2))); parent.append(details); }
  function control(parent, label, type = 'text') { const wrap = el('label', label), input = el('input'); input.type = type; wrap.append(input); parent.append(wrap); return input; }
  function action(parent, label, fn) { const button = el('button', label); button.type = 'button'; parent.append(button); button.addEventListener('click', async () => { button.disabled = true; try { await fn(); } finally { button.disabled = false; } }); return button; }
  function resultPanel(parent, key, label, path, body, render) {
    const output = el('div');
    action(parent, label, async () => { output.replaceChildren(el('p', t('Проверка…', 'Checking…'))); const result = await observe(key, typeof path === 'function' ? path() : path, body); output.replaceChildren(); block(output, label, result, render); }); parent.append(output);
  }
  function controllerTools(parent, controllers) {
    if (!admin) { parent.append(el('p', t('Сведения ОС, PRP и журналы доступны администратору.', 'OS details, PRP and logs require administrator access.'))); return; }
    const label = el('label', t('Контроллер для обследования', 'Controller to inspect')), select = el('select'); select.setAttribute('aria-label', t('Контроллер для обследования', 'Controller to inspect')); label.append(select); parent.append(label);
    for (const dc of controllers) { const option = el('option', dc.dns + ' · ' + (dc.rodc ? 'RODC' : 'RWDC')); option.value = dc.dns; select.append(option); }
    if (!controllers.length) return;
    const panel = el('div'); parent.append(panel);
    function selected() {
      panel.replaceChildren(); const name = select.value, base = '/sites/controllers/' + encodeURIComponent(name);
      resultPanel(panel, 'inventory:' + name, t('Проверить версию и службы', 'Check version and services'), base + '/inventory', undefined, (box, d) => {
        box.append(el('p', d.controller + ' · ' + formatTime(d.observed))); table(box, [t('Проверка', 'Check'), t('Статус', 'Status'), t('Подробности', 'Details')], d.checks.map(c => [c.id === 'samba_version' ? t('Версия Samba', 'Samba version') : c.id.replaceAll('_', ' '), statusText(c.status), c.detail]));
        box.append(el('p', t('Имена служб отличаются между дистрибутивами. Неактивный альтернативный unit не доказывает отказ DC.', 'Service names differ between distributions. An inactive alternative unit does not prove DC failure.')));
      });
      if (controllers.find(dc => dc.dns === name)?.rodc) resultPanel(panel, 'prp:' + name, t('Показать настройки кэширования RODC', 'Show RODC cache settings'), base + '/rodc', undefined, (box, d) => {
        for (const [key, title] of [['allowed', 'PRP allow'], ['denied', 'PRP deny'], ['cached', t('Кэшированные записи', 'Cached accounts')]]) table(box, [title, 'DN'], (d[key] || []).map(p => [p.name, p.dn]));
        jsonDetail(box, t('Полный ответ PRP', 'Full PRP response'), d);
      });
      const filters = el('div'); filters.className = 'overview-actions'; panel.append(filters);
      const after = control(filters, t('С даты (местное время)', 'From (local time)'), 'datetime-local');
      const before = control(filters, t('По дату (местное время)', 'To (local time)'), 'datetime-local');
      const account = control(filters, t('Учётная запись', 'Account')); account.maxLength = 256;
      const output = el('div');
      action(panel, t('Показать авторизации выбранного DC', 'Show selected DC authentications'), async () => {
        output.replaceChildren(); if (after.value && before.value && after.value > before.value) { output.append(el('p', t('Начало периода позже конца.', 'Start is after end.'))); return; }
        const q = new URLSearchParams({account: account.value}); if (after.value) q.set('after', new Date(after.value).toISOString()); if (before.value) q.set('before', new Date(before.value).toISOString());
        output.append(el('p', t('Чтение журнала…', 'Reading audit…'))); const r = await observe('auth:' + name, base + '/authentications?' + q); output.replaceChildren();
        block(output, t('Авторизации', 'Authentications'), r, (box, d) => { box.append(el('p', d.source + ' · ' + statusText(d.status)), el('p', d.warning)); table(box, [t('Время', 'Time'), t('Учётная запись', 'Account'), t('Клиент', 'Client'), t('Результат', 'Result'), t('Служба', 'Service')], d.events.map(e => [formatTime(e.time), e.domain + '\\' + e.account, e.client, e.status, e.service])); });
      }); panel.append(output);
    }
    select.addEventListener('change', selected); selected();
  }
  function domainBackupTools(parent, dns, plan) {
    const controllers = (report.sections.controllers?.data || []).filter(dc => !dc.rodc && !plan.objects.some(o => o.dn.toLowerCase() === (dc.dn || '').toLowerCase()));
    if (!controllers.length) return;
    const label = el('label', t('RWDC для резервной копии домена', 'RWDC for domain backup')), select = el('select');
    for (const dc of controllers) { const option = el('option', dc.dns); option.value = dc.dns; select.append(option); }
    label.append(select); parent.append(label);
    parent.append(el('p', t('Холодная копия: выбранный DC должен быть остановлен администратором, LDAP приложения — доступен через другой RWDC. Helper не останавливает службы. Архив содержит секреты домена. После копирования helper проверяет восстановление и пробную очистку в изоляции. Перед применением снова запустите DC.', 'Cold backup: stop the selected DC first; the application needs another reachable RWDC for LDAP. Helper never stops services. Archive contains domain secrets. Helper then verifies isolated restore and rehearses cleanup. Restart the DC before applying.')));
    const checksOutput = el('div');
    action(parent, t('Проверить зависимости и сверить с этим RWDC', 'Check dependencies and compare with this RWDC'), async () => {
      checksOutput.replaceChildren(el('p',t('Проверка…','Checking…')));
      try { const result = await request('/sites/topology/cleanup/checks',{dns,revision:plan.revision,peer:select.value});
        checksOutput.replaceChildren(el('p',formatTime(result.observed)));
        table(checksOutput,[t('Проверка','Check'),t('Статус','Status'),t('Подробности','Details')],result.checks.map(c=>[c.id,c.status,c.detail]));
        table(checksOutput,['DC',t('Источник','Source'),t('Атрибут','Attribute'),t('Ссылка','Reference')],result.dependencies.map(d=>[d.controller,d.source,d.attribute,d.target]));
      } catch(e) { checksOutput.replaceChildren(el('p',e.message)); }
    }); parent.append(checksOutput);
    const confirm = control(parent, t('Подтверждаю создание полной копии на выбранном RWDC', 'Confirm full backup on selected RWDC'), 'checkbox');
    const id = control(parent, t('Идентификатор задания копирования', 'Backup job ID')); id.maxLength = 36;
    const output = el('div');
    const render = job => {
      const states = {queued:t('В очереди','Queued'),running:t('Выполняется','Running'),backed_up:t('Архив создан и проверен','Archive created and verified'),failed:t('Ошибка','Failed'),interrupted:t('Прервано — копия не подтверждена','Interrupted — backup unconfirmed'),unknown:t('Состояние неизвестно','Status unknown')};
      output.replaceChildren(el('p', states[job.status] || job.status), el('p', 'ID: '+job.id), el('p', formatTime(job.finished || job.started)));
      if (job.sha256) output.append(el('p','SHA-256: '+job.sha256),el('p',t('Размер, байт: ','Size, bytes: ')+job.bytes));
      if (job.error) output.append(el('p',job.error));
      output.append(el('p',job.restoreVerified ? t('Проверены пробная очистка, повторное восстановление, запуск DC в изоляции, вход тестового пользователя и чтение SYSVOL по SMB — отдельно с NTLM и Kerberos.','Verified cleanup rehearsal, second restore, isolated DC startup, test-user login and SYSVOL read over SMB with both NTLM and mandatory Kerberos.') : t('Восстановление этой копии ещё не проверено.','Restore of this backup has not been verified.')));
      if (job.applyReserved) output.append(el('p',t('Применение уже запускалось: повтор заблокирован. Проверьте журнал.','Apply was already reserved: retry blocked. Inspect the journal.')));
      if (job.applyEvents?.length) table(output,[t('Время','Time'),'DN',t('Статус','Status'),t('Подробности','Details')],job.applyEvents.map(e=>[formatTime(e.time),e.dn || '',e.status,e.detail || '']));
    };
    action(parent, t('Создать резервную копию домена', 'Create domain backup'), async () => {
      if (!confirm.checked) { output.replaceChildren(el('p',t('Подтвердите создание копии.','Confirm backup creation.'))); return; }
      if (!id.value) id.value = crypto.randomUUID();
      try { render(await request('/sites/topology/cleanup/backup', {dns,revision:plan.revision,controller:select.value,id:id.value})); }
      catch(e) { output.replaceChildren(el('p',e.message),el('p',t('Сохраните ID и проверьте статус перед повтором: ','Keep the ID and check status before retrying: ')+id.value)); }
    });
    action(parent, t('Проверить статус копии', 'Check backup status'), async () => {
      if (!id.value) return;
      try { render(await request('/sites/controllers/'+encodeURIComponent(select.value)+'/backups/'+encodeURIComponent(id.value))); }
      catch(e) { output.replaceChildren(el('p',e.message)); }
    });
    const retireConfirm = control(parent,t('Подтверждаю окончательный вывод выбранных DC из эксплуатации; повторный запуск исключён','Confirm selected DCs are permanently decommissioned and will not be restarted'),'checkbox');
    const applyConfirm = control(parent,t('Подтверждаю удаление объектов плана; изменения топологии другими администраторами приостановлены','Confirm deletion of planned objects; other administrators have paused topology changes'),'checkbox');
    action(parent,t('Применить план очистки','Apply cleanup plan'),async()=>{
      if (!applyConfirm.checked || !id.value) {output.replaceChildren(el('p',t('Подтвердите удаление и укажите ID проверенной копии.','Confirm deletion and enter a verified backup ID.')));return;}
      applyConfirm.checked=false;
      output.replaceChildren(el('p',t('Повторная проверка и применение… Не запускайте повторно; журнал доступен по ID копии.','Rechecking and applying… Do not retry; the journal is available under the backup ID.')));
      try {const result=await request('/sites/topology/cleanup/apply',{dns,revision:plan.revision,controller:select.value,id:id.value,confirm:true,confirmDecommissioned:retireConfirm.checked});
        output.replaceChildren(el('p',result.status==='completed' ? t('Очистка подтверждена на всех оставшихся контроллерах.','Cleanup confirmed on all surviving controllers.') : t('Выполнение остановлено. Проверьте журнал; автоматического отката нет.','Execution stopped. Inspect the journal; there is no automatic rollback.')));
        table(output,[t('Время','Time'),'DN',t('Статус','Status'),t('Подробности','Details')],result.events.map(e=>[formatTime(e.time),e.dn || '',e.status,e.detail || '']));
      } catch(e) {output.replaceChildren(el('p',e.message),el('p',t('Проверьте статус копии и журнал до любых повторных действий.','Check backup status and journal before any retry.')));}
    });
    select.addEventListener('change',()=>{confirm.checked=false;applyConfirm.checked=false;retireConfirm.checked=false;output.replaceChildren();}); parent.append(output);
  }
  function cleanupTools(box, findings) {
    const choices = el('div'), output = el('div'), selected = new Set();
    box.append(el('h4', t('Подготовка очистки LDAP', 'LDAP cleanup preparation')));
    box.append(el('p', t('Поддерживаются пустые сайты и устаревшие связи; NTDS, разрешённые RID/DFSR-объекты и DNS-записи выведенных DC. Снимок выбранных атрибутов не заменяет резервную копию домена и проверку восстановления.', 'Empty sites and stale links are supported; retired DC NTDS, supported RID/DFSR objects and DNS records. A selective attribute snapshot does not replace a domain backup and restore rehearsal.')));
    for (const dn of [...new Set(findings.map(f => f.dn))]) {
      const label = el('label'), check = el('input'); check.type = 'checkbox';
      label.append(check, document.createTextNode(dn)); choices.append(label);
      check.addEventListener('change', () => { if (check.checked) selected.add(dn); else selected.delete(dn); output.replaceChildren(); });
    }
    box.append(choices);
    action(box, t('Предпросмотр без изменений', 'Preview without changes'), async () => {
      output.replaceChildren(); const dns = [...selected];
      if (!dns.length || dns.length > 50) { output.append(el('p', t('Выберите от 1 до 50 объектов.', 'Select 1 to 50 objects.'))); return; }
      try {
        const plan = await request('/sites/topology/cleanup/preview', {dns});
        output.append(el('p', t('План получен: ', 'Plan observed: ') + formatTime(plan.observed)));
        table(output, ['DN', t('Действие','Action'), t('Ревизия объекта', 'Object revision'),t('Изменения','Changes')], plan.objects.map(o => [o.dn, o.remove ? t('Удалить выбранные значения','Remove selected values') : t('Удалить объект','Delete object'), o.usn, o.remove ? Object.entries(o.remove).map(([key,values])=>key+': '+values.length).join(', ') : '']));
        output.append(el('p', t('Применение заблокировано: нужны сверка на другом RWDC, проверки зависимостей/FSMO/репликации, полноценная копия домена и репетиция восстановления.', 'Apply is blocked: another RWDC, dependency/FSMO/replication checks, domain backup and restore rehearsal are required.')));
        jsonDetail(output, t('План и ограничения', 'Plan and limitations'), plan);
        const receipt = el('div');
        action(output, t('Сохранить и проверить снимок через helper', 'Save and verify snapshot through helper'), async () => {
          receipt.replaceChildren();
          try { const saved = await request('/sites/topology/cleanup/snapshot', {dns, revision:plan.revision}); receipt.append(el('p', t('Снимок сохранён и прочитан обратно: ', 'Snapshot saved and read back: ') + saved.id), el('p', 'SHA-256: ' + saved.sha256), el('p', formatTime(saved.created))); }
          catch (e) { receipt.append(el('p', e.message)); }
        }); output.append(receipt);
        domainBackupTools(output, dns, plan);
      } catch (e) { output.append(el('p', e.message)); }
    }); box.append(output);
  }
  async function load() {
    refresh.disabled = true;
    for (const section of Object.values(sections)) section.replaceChildren(el('p', t('Загрузка…', 'Loading…')));
    report.sections = {}; report.started = new Date().toISOString(); report.checks = {dnsHealth: unknown, sysvolConsistency: unknown, auditRetention: unknown, auditEnabledOnAllDCs: unknown};
    const specs = [['domain', '/domain'], ['fsmo', '/domain/fsmo'], ['controllers', '/sites/controllers'], ['sites', '/sites'], ['subnets', '/subnets'], ['links', '/sites/links'], ['connections', '/repl/connections'], ['dns', '/dns/zones'], ['gpo', '/gpo']];
    // Bound parallelism; do not probe every controller's OS or read every audit log.
    let index = 0; await Promise.all(Array.from({length: 3}, async () => { while (index < specs.length) { const [key, path] = specs[index++]; await observe(key, path); } }));
    for (const section of Object.values(sections)) section.replaceChildren();
    block(sections.domain, t('Домен', 'Domain'), report.sections.domain, (box, d) => table(box, [t('Параметр', 'Property'), t('Значение', 'Value')], [['DNS', d.dnsRoot], ['NetBIOS', d.netbios], ['Base DN', d.baseDN], ['SID', d.domainSid], [t('Функциональный уровень', 'Functional level'), d.functionLevel]]));
    block(sections.domain, 'FSMO', report.sections.fsmo, (box, d) => table(box, [t('Роль', 'Role'), t('Владелец', 'Owner')], d.map(r => [r.role, r.owner])));
    block(sections.domain, t('Зоны DNS', 'DNS zones'), report.sections.dns, (box, d) => { table(box, [t('Зона', 'Zone')], d.map(z => [z.name])); box.append(el('p', t('Список зон не подтверждает исправность DNS. Проверки SRV доступны в диагностике.', 'Listing zones does not verify DNS health. SRV checks are available in diagnostics.'))); });
    sections.domain.append(el('p', t('Состояние репликации по DC показано выше. SYSVOL проверяется отдельно для выбранной GPO.', 'Per-DC replication status is shown above. SYSVOL is checked separately for a selected GPO.')));
    block(sections.controllers, t('Контроллеры из LDAP', 'LDAP controllers'), report.sections.controllers, (box, d) => { table(box, ['DC', t('Тип', 'Type'), t('Площадка', 'Site')], d.map(dc => [dc.dns, dc.rodc ? 'RODC' : 'RWDC', dc.site])); controllerTools(box, d); });
    block(sections.sites, t('Сайты', 'Sites'), report.sections.sites, (box, d) => table(box, [t('Название', 'Name'), 'DN'], d.map(s => [s.name, s.dn])));
    block(sections.sites, t('Подсети', 'Subnets'), report.sections.subnets, (box, d) => table(box, [t('Подсеть', 'Subnet'), t('Площадка', 'Site')], d.map(s => [s.name, s.site])));
    block(sections.sites, 'Site Links', report.sections.links, (box, d) => table(box, [t('Название', 'Name'), t('Сайты', 'Sites'), t('Стоимость', 'Cost'), t('Интервал, мин', 'Interval, min'), t('Расписание / ограничения', 'Schedule / restrictions')], d.map(l => [l.name, l.sites.join(', '), l.cost, l.interval, l.scheduleWarning || (l.schedule || []).join('; ')])));
    block(sections.sites, t('Соединения репликации', 'Replication connections'), report.sections.connections, (box, d) => table(box, [t('Источник', 'Source'), t('Получатель', 'Destination'), t('Включено', 'Enabled'), 'KCC'], d.map(c => [c.source, c.destination, c.enabled, c.automatic])));
    const diag = sections.diagnostics;
    diag.append(el('p', t('Срок хранения аудита и полнота его включения пока не подтверждены. Журнал выбранного DC доступен в разделе контроллеров; читается до 8 МиБ и 500 подходящих событий.', 'Audit retention and enablement completeness remain unverified. Select a DC above to read its audit: up to 8 MiB and 500 matching events.')));
    if (admin) {
      resultPanel(diag, 'diagnostics', t('Проверить подключения и DNS', 'Check connections and DNS'), '/system/diagnostics', {}, (box, d) => table(box, [t('Проверка', 'Check'), t('Статус', 'Status'), t('Подробности', 'Details')], d.checks.map(c => [c.id, c.status, c.detail + (c.hint ? ' · ' + c.hint : '')])));
      resultPanel(diag, 'topologyAudit', t('Проверить остатки DC и связей LDAP', 'Check stale DC and LDAP links'), '/sites/topology/audit', {}, (box, d) => {
        box.append(el('p', statusText(d.status) + ' · ' + t('Объектов: ', 'Objects: ') + d.objects)); if (d.ldapServer) box.append(el('p', 'LDAP: ' + d.ldapServer + ' · ' + d.baseDN)); if (ru) { box.append(el('p', 'Сверьте находки на другом DC и с историей вывода серверов. Права чтения и задержка репликации могут скрыть объекты. Пустые сайты могут быть запланированы, возраст объекта не доказывает неактивность. Объекты не удаляются.')); if (d.status === 'partial') box.append(el('p', 'Некоторые проверки не завершены из-за прав, ошибок или лимитов. Подробности доступны в JSON-отчёте.')); } else d.warnings.forEach(w => box.append(el('p', w)));
        table(box, [t('Проверка', 'Check'), t('Статус', 'Status'), 'DN', t('Ссылка', 'Reference'), t('Причина', 'Reason'), t('Изменён', 'Changed')], d.findings.map(f => [findingText(f.code), statusText(f.severity), f.dn, f.reference, f.detail, formatTime(f.changed)]));
        if (d.status === 'complete' && d.findings.length) cleanupTools(box, d.findings);
      });
    }
    const policies = report.sections.gpo;
    if (policies.status === 'available' && Array.isArray(policies.data) && policies.data.length) {
      const label = el('label', t('GPO для проверки SYSVOL', 'GPO for SYSVOL check')), select = el('select');
      for (const p of policies.data) { const option = el('option', p.displayName || p.guid); option.value = p.guid; select.append(option); } select.setAttribute('aria-label', t('GPO для проверки SYSVOL', 'GPO for SYSVOL check')); label.append(select); diag.append(label);
      resultPanel(diag, 'sysvol', t('Проверить согласованность SYSVOL', 'Check SYSVOL consistency'), () => '/gpo/' + encodeURIComponent(select.value) + '/consistency', {}, (box, d) => { box.append(el('p', statusText(d.status) + ' · ' + t('Полный отчёт: ', 'Complete: ') + d.complete)); table(box, ['DC', 'Status', 'LDAP', 'SYSVOL', t('Различий', 'Differences')], d.controllers.map(c => [c.dns, c.status, c.ldap, c.sysvol, c.differenceCount])); jsonDetail(box, t('Подробности проверки', 'Check details'), d); });
    } else diag.append(el('p', t('Список GPO недоступен или пуст — SYSVOL не проверен.', 'GPO list unavailable or empty — SYSVOL not checked.')));
    report.finished = new Date().toISOString(); refresh.disabled = false;
  }
  download.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify({...report, exported: new Date().toISOString()}, null, 2)], {type: 'application/json'})); const a = el('a'); a.href = url; a.download = 'sambaadm-domain-survey.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  refresh.addEventListener('click', load); load();
})();
