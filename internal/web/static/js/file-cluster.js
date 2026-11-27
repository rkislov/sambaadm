(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const root = $('file-cluster');
  if (!root) return;
  const canManage = root.dataset.canManage === 'true';
  const make = (tag, text, className) => {
    const el = document.createElement(tag);
    if (text != null) el.textContent = text;
    if (className) el.className = className;
    return el;
  };
  const pill = (text, tone) => make('span', text, 'fc-pill ' + tone);
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  const requestID = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, '0')).join('');
  let catalog = {nodes: [], clusters: [], drafts: []};
  let draft = null, wizard = false, view = 'status', owner = '';
  let statusSeq = 0, polling = 0, submitting = false;
  let selectedKey = new URLSearchParams(location.search).get('cluster') || '', snapshotKey = '';
  let schedule = null;
  const scheduleLabels = {60:'Каждый час', 360:'Каждые 6 часов', 1440:'Ежедневно'};
  const clusterKey = row => row.name + '@' + row.revision;
  const activeCluster = () => catalog.clusters.find(item => clusterKey(item) === selectedKey);
  const phases = {nodes: 0, storage: 1, connected: 1, mapped: 2, fenced: 3, done: 3};
  const panels = ['nodes', 'storage', 'fencing', 'deploy'];
  const actionLabels = {
    prepare: 'Подготовка пакетов на обоих узлах…', discover: 'Поиск общей цели iSCSI…',
    connect: 'Подключение iSCSI на обоих узлах…', map: 'Проверка LUN и настройка multipath…',
    fence: 'Проверка выключения и возврата узлов…', deploy: 'Развёртывание ZFS и Samba…'
  };

  async function api(path = '', body) {
    const headers = {Accept: 'application/json'};
    if (body !== undefined) Object.assign(headers, {'Content-Type': 'application/json', 'X-CSRF-Token': csrf});
    const response = await fetch('/api/v1/file-clusters' + path, {
      headers, credentials: 'same-origin', method: body === undefined ? 'GET' : 'POST',
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (response.status === 401) throw new Error('Сессия истекла. Войдите снова.');
    if (response.status === 403) throw new Error('Нужны права администратора и действующая сессия.');
    const result = await response.json().catch(() => { throw new Error('Панель вернула неожиданный ответ.'); });
    if (!response.ok) throw new Error(result.error || 'Операция не выполнена.');
    return result;
  }

  function showError(message = '', el = $('fc-alert')) {
    el.textContent = message;
    el.hidden = !message;
  }
  function options(select, rows, valueOf, titleOf, blank) {
    const last = select.value;
    select.replaceChildren();
    if (blank) select.append(new Option(blank, ''));
    for (const row of rows) select.append(new Option(titleOf(row), valueOf(row)));
    if (Array.from(select.options).some(option => option.value === last)) select.value = last;
  }
  function fact(term, value) {
    const row = make('div');
    row.append(make('dt', term), make('dd', value));
    return row;
  }
  function switchMode(inWizard) {
    wizard = inWizard;
    $('fc-setup').hidden = !wizard;
    $('fc-dashboard').hidden = wizard;

    showError();
  }
  function displayCatalog() {
    const rows = catalog.clusters;
    if (!rows.some(item => clusterKey(item) === selectedKey)) selectedKey = rows.length ? clusterKey(rows[0]) : '';
    $('fc-choice').hidden = !rows.length;
    $('fc-live').hidden = !rows.length;
    $('fc-empty').hidden = Boolean(rows.length);
    options($('fc-select'), rows, clusterKey, item => item.name + '.' + item.realm);
    $('fc-select').value = selectedKey;
    if (!canManage) return;
    $('fc-drafts').replaceChildren(...catalog.drafts.map(item => {
      const text = item.action ? 'Операция выполняется' : 'Продолжить настройку';
      const b = make('button', item.plan.name + ' · ' + text);
      b.type = 'button';
      b.addEventListener('click', () => openDraft(item.id));
      return b;
    }));
    const pair = $('fc-pair').elements;
    for (const key of ['first', 'second']) options(pair[key], catalog.nodes, n => n.name, n => n.name, 'Выберите хелпер');


  }

  async function loadCatalog() {
    $('fc-refresh').disabled = true;
    try {
      const data = await api();
      catalog = {nodes: data.nodes || [], clusters: data.clusters || [], drafts: data.drafts || []};
      catalog.clusters.sort((a, b) => a.name.localeCompare(b.name));
      displayCatalog();
      if (!wizard) await refreshStatus();
    } catch (error) { showError(error.message); }
    finally { $('fc-refresh').disabled = false; }
  }

  function showView(next) {
    view = next;
    for (const button of root.querySelectorAll('[data-view]')) button.setAttribute('aria-pressed', String(button.dataset.view === view));
    $('fc-status').hidden = view !== 'status';
    $('fc-snapshots').hidden = view !== 'snapshots';
  }
  function pathCard(node, membership, active) {
    const article = make('article', null, 'fc-panel fc-node');
    const top = make('div', null, 'fc-row fc-node-top');
    const text = make('div');
    text.append(make('h3', node.node), make('p', node.platform ? 'ALT ' + node.platform : 'Хелпер'));
    let badge = pill('Недоступен', 'bad');
    if (node.error && membership.includes(node.node)) badge = pill('Хелпер недоступен', 'warn');
    else if (!node.error && active === node.node) badge = pill('Активный', 'good');
    else if (!node.error && membership.includes(node.node)) badge = pill('Резервный', '');
    else if (!node.error) badge = pill('Вне кластера', 'warn');
    top.append(text, badge);
    article.append(top);
    const storage = make('div', null, 'fc-map');
    if (node.multipath) {
      const paths = node.multipath.paths || [];
      const count = paths.filter(path => path.ready).length;
      const summary = make('div', null, 'fc-row');
      summary.append(make('strong', 'Multipath'), pill(count + ' из ' + paths.length + ' путей', count > 0 && count === paths.length ? 'good' : 'warn'));
      storage.append(summary);
      for (const path of paths) {
        const row = make('div', null, 'fc-path');
        const endpoint = make('div');
        endpoint.append(make('code', path.portal));
        if (path.device) endpoint.append(make('small', path.device));
        row.append(endpoint, pill(path.ready ? 'Готов' : path.state === 'missing' ? 'Нет пути' : 'Сбой', path.ready ? 'good' : 'warn'));
        storage.append(row);
      }
      const info = make('details', null, 'fc-extra');
      info.append(make('summary', 'Карта и WWID'), make('p', node.multipath.map + ' · ' + node.multipath.wwid));
      storage.append(info);
    } else {
      storage.append(make('p', node.storageError || 'Состояние multipath недоступно.', 'fc-muted'));
    }
    if (node.error) {
      const detail = make('details', null, 'fc-extra');
      detail.append(make('summary', 'Ответ хелпера'), make('p', node.error));
      storage.append(detail);
    } else if (node.clusterError) {
      storage.append(make('p', node.clusterError, 'fc-muted'));
    }
    article.append(storage);
    return article;
  }

  function renderStatus(nodes) {
    const peers = nodes.filter(n => !n.error && n.quorum);
    const owners = [...new Set(peers.map(n => n.owner).filter(Boolean))];
    const active = owners.length === 1 && peers.find(n => n.owner === owners[0] && n.localNode === n.node && n.node === owners[0]);
    owner = active ? active.node : '';
    const membership = [...new Set(peers.flatMap(n => n.onlineNodes || []))];
    const allOK = nodes.every(n => !n.error && n.quorum);
    $('fc-quorum').replaceChildren(pill(peers.length ? (allOK ? 'Есть кворум' : 'Есть кворум · не все узлы') : 'Кворум не подтверждён', peers.length ? (allOK ? 'good' : 'warn') : 'bad'));
    const cards = make('div', null, 'fc-node-grid');
    cards.append(...nodes.map(node => pathCard(node, membership, owner)));
    $('fc-status').replaceChildren(cards);
    renderSnapshots(active && !active.snapshotError ? active.snapshots || [] : null, active ? active.schedule : null);
  }
  const smbToken = item => item.name.replace(/^sambaadm_/, '@GMT-');
  function snapshotPath(item) {
    const cluster = activeCluster();
    return ['','',cluster.name + '.' + cluster.realm,'files',smbToken(item)].join(String.fromCharCode(92));
  }
  function showSnapshotInfo(item) {
    $('fc-info-label').textContent = item.label + (item.automatic ? ' · Автоматический' : ' · Ручной');
    $('fc-info-path').value = snapshotPath(item);
    $('fc-copy-result').textContent = '';
    $('fc-info-dialog').showModal();
  }
  function snapshotMenu(item) {
    const menu = make('details', null, 'compact-action-menu');
    const summary = make('summary', 'Действия');
    summary.setAttribute('aria-label', 'Действия со снимком ' + item.label);
    const actions = make('div', null, 'compact-action-list');
    const info = make('button', 'Сведения');
    const copy = make('button', 'Копировать SMB-путь');
    actions.append(info, copy);
    if (canManage) {
      const restore = make('button', 'Восстановить из снимка');
      restore.addEventListener('click', () => { summary.focus(); openRestore(item); });
      actions.append(restore);
    }
    menu.append(summary, actions);
    info.addEventListener('click', () => { summary.focus(); showSnapshotInfo(item); });
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(snapshotPath(item));
        $('fc-snapshot-announcement').textContent = 'SMB-путь скопирован.';
      } catch { showSnapshotInfo(item); }
    });
    return menu;
  }
  function renderSnapshots(snapshots, policy = null) {
    schedule = policy || null;
    if (canManage) {
      $('fc-new-snapshot').disabled = snapshots === null;
      $('fc-edit-schedule').disabled = !schedule;
    }
    $('fc-schedule-summary').textContent = !schedule ? 'Расписание недоступно' : schedule.enabled
      ? scheduleLabels[schedule.intervalMinutes] + ' · хранить ' + schedule.retain
      : 'Автоснимки выключены';
    const key = JSON.stringify([selectedKey, snapshots]);
    if (key === snapshotKey) return;
    snapshotKey = key;
    const list = $('fc-snapshot-list');
    list.replaceChildren();
    if (!snapshots?.length) {
      list.append(make('p', snapshots === null ? 'Список появится после подтверждения активного узла.' : 'Именных снимков пока нет.', 'fc-muted'));
      return;
    }
    for (const item of [...snapshots].sort((a, b) => b.name.localeCompare(a.name))) {
      const row = make('div', null, 'fc-snapshot-row');
      const name = make('div');
      name.append(make('strong', item.label));
      if (item.automatic) name.append(make('span', 'Авто', 'fc-auto-label'));
      name.append(make('code', smbToken(item)));
      const stamp = item.name.match(/^sambaadm_(\d{4})\.(\d{2})\.(\d{2})-(\d{2})\.(\d{2})\.(\d{2})$/);
      const local = stamp ? new Date(stamp.slice(1, 4).join('-') + 'T' + stamp.slice(4).join(':') + 'Z') : null;
      row.append(name, make('span', local ? local.toLocaleString('ru-RU', {dateStyle: 'medium', timeStyle: 'short'}) : item.name, 'fc-muted'), snapshotMenu(item));
      list.append(row);
    }
  }

  async function waitForJob(node, id, attempts = 90, onUpdate = () => {}) {
    for (let attempt = 0; attempt < attempts; attempt++) {
      const job = await api('/jobs/' + encodeURIComponent(id) + '?node=' + encodeURIComponent(node));
      onUpdate(job);
      if (job.state === 'completed') return job.result;
      if (job.state === 'failed' || job.state === 'interrupted') throw new Error(job.error || 'Задание не завершено.');
      await wait(1000);
    }
    throw new Error('Хелпер не вернул результат. Обновите состояние перед повтором.');
  }

  async function refreshStatus() {
    const cluster = activeCluster();
    if (!cluster || wizard) return;
    const wanted = ++statusSeq;
    $('fc-live-name').textContent = cluster.name + '.' + cluster.realm;
    $('fc-unc').textContent = '\\\\' + cluster.name + '.' + cluster.realm + '\\files · ' + cluster.vip;
    const search = new URLSearchParams({ name: cluster.name, revision: cluster.revision });
    for (const node of cluster.nodes) search.append('node', node);
    try {
      const nodes = await api('/status?' + search);
      if (wanted === statusSeq && !wizard) renderStatus(nodes);
    } catch (error) {
      if (wanted !== statusSeq) return;
      owner = '';
      $('fc-status').replaceChildren(make('p', 'Состояние недоступно.'));
      renderSnapshots(null);
      showError(error.message);
    }
  }
  function review(plan) {
    const facts = $('fc-review');
    facts.replaceChildren(
      fact('SMB-адрес', plan.name + '.' + plan.realm + ' · ' + plan.virtualIP + '/' + plan.prefix),
      fact('Хелперы', plan.nodes.map(node => node.name).join(' · ')),
      fact('LUN · ZFS', plan.nodes[0].diskWWID),
      fact('iSCSI multipath', plan.portals.join(' · ')),
      fact('Fencing', 'Перезагрузка обоих узлов подтверждена'));
  }
  function inputLabel(title, name, placeholder, type = 'text') {
    const label = make('label', title);
    const field = make('input');
    Object.assign(field, {name, placeholder, type, required: true, autocomplete: type === 'password' ? 'new-password' : 'off'});
    label.append(field);
    return label;
  }
  function fenceFields(nodes) {
    const box = $('fc-fence-fields');
    if (box.dataset.nodes === nodes.map(n => n.name).join()) return;
    box.dataset.nodes = nodes.map(n => n.name).join();
    box.replaceChildren(...nodes.map((node, index) => {
      const card = make('fieldset');
      card.append(make('legend', node.name), inputLabel('Адрес Redfish', 'address' + index, '192.0.2.9' + (index + 1) + ':443'),
        inputLabel('Путь системы', 'system' + index, '/redfish/v1/Systems/1'),
        inputLabel('Имя пользователя', 'user' + index, 'fence'), inputLabel('Пароль', 'pass' + index, '', 'password'));
      return card;
    }));
  }
  function renderDraft() {
    const phase = draft?.phase || 'nodes';
    const step = phases[phase] ?? 0;
    const busy = Boolean(draft?.action || submitting);
    for (const panel of root.querySelectorAll('[data-step]')) panel.hidden = panel.dataset.step !== panels[step];
    root.querySelectorAll('.fc-steps li').forEach((item, index) => {
      if (index === step) item.setAttribute('aria-current', 'step');
      else item.removeAttribute('aria-current');
      item.classList.toggle('done', index < step);
    });
    for (const el of $('fc-setup').querySelectorAll('form :is(input,textarea,select,button)')) el.disabled = busy;
    if (draft) {
      const pair = $('fc-pair').elements;
      for (const [key, value] of Object.entries({first: draft.plan.nodes[0].name, second: draft.plan.nodes[1].name,
        address1: draft.plan.nodes[0].address, address2: draft.plan.nodes[1].address, name: draft.plan.name,
        realm: draft.plan.realm, vip: draft.plan.virtualIP, prefix: draft.plan.prefix})) {
        pair[key].value = value;
        pair[key].disabled = true;
      }
      const portals = $('fc-discover').elements.portals;
      if (!portals.value && draft.plan.portals?.length) portals.value = draft.plan.portals.join('\n');
      $('fc-discover').hidden = phase === 'connected';
      $('fc-connect').hidden = phase !== 'storage' || !draft.targets?.length;
      $('fc-map').hidden = phase !== 'connected';
      options($('fc-connect').elements.target, draft.targets || [], x => x, x => x);
      options($('fc-map').elements.wwid, draft.luns || [], x => x.wwid, x => x.wwid + ' · ' + (x.size / (1024 ** 3)).toLocaleString('ru-RU') + ' ГиБ');
      if (phase === 'mapped') fenceFields(draft.plan.nodes);
      if (phase === 'fenced') {
        review(draft.plan);
        for (const field of ['workgroup', 'controller', 'groupSID']) {
          if (draft[field]) {
            $('fc-deploy').elements[field].value = draft[field];
            $('fc-deploy').elements[field].disabled = true;
          }
        }
      }
    }
    // Fence fieldsets are created when their step becomes visible.
    if (busy) for (const field of $('fc-fence').elements) field.disabled = true;
    const progress = $('fc-progress');
    progress.hidden = !draft?.action && !draft?.log?.length;
    $('fc-progress-message').textContent = draft?.action ? actionLabels[draft.action] : draft?.error ? 'Шаг не завершён.' : 'Шаг завершён.';
    $('fc-log').replaceChildren(...(draft?.log || []).map(line => make('li', line)));
    if (draft?.error) showError(draft.error);
  }

  async function pollDraft(id) {
    const seq = ++polling;
    while (wizard && seq === polling && draft?.id === id && draft.action) {
      await wait(1000);
      if (!wizard || seq !== polling) return;
      try {
        const result = await api('/setup/' + id);
        if (seq !== polling || !wizard) return;
        draft = result;
        if (draft.phase === 'done') {
          selectedKey = draft.plan.name + '@' + draft.revision;
          switchMode(false);
          await loadCatalog();
          return;
        }
        showError();
        renderDraft();
      } catch (error) {
        showError(error.message + ' Журнал можно открыть повторно из списка кластеров.');
        return;
      }
    }
  }
  async function openDraft(id) {
    try {
      draft = await api('/setup/' + id);
      switchMode(true);
      renderDraft();
      if (draft.action) pollDraft(id);
    } catch (error) { showError(error.message); }
  }
  function registerForm(id, handler) {
    const form = $(id);
    form?.addEventListener('submit', async event => {
      event.preventDefault();
      if (submitting || draft?.action) return;
      const fields = Object.fromEntries(new FormData(form));
      submitting = true;
      showError();
      renderDraft();
      try { await handler(fields); }
      catch (error) { showError(error.message); }
      finally {
        for (const password of form.querySelectorAll('input[type=password]')) password.value = '';
        submitting = false;
        renderDraft();
      }
    });
  }
  async function runAction(action, fields = {}) {
    draft = await api('/setup/' + draft.id + '/' + action, fields);
    pollDraft(draft.id);
  }
  registerForm('fc-pair', async fields => {
    if (!draft) draft = await api('/setup', {plan: {
      name: fields.name.trim(), realm: fields.realm.trim().toLowerCase(), virtualIP: fields.vip.trim(),
      prefix: Number(fields.prefix), nodes: [{name: fields.first, address: fields.address1.trim()}, {name: fields.second, address: fields.address2.trim()}]
    }});
    await runAction('prepare', {dedicatedZFS: !!fields.dedicatedZFS});
  });
  registerForm('fc-discover', fields => runAction('discover', {portals: fields.portals.split(/\s+/).filter(Boolean)}));
  registerForm('fc-connect', fields => runAction('connect', fields));
  registerForm('fc-map', fields => runAction('map', fields));
  registerForm('fc-fence', fields => runAction('fence', {confirm: !!fields.confirm, fences: [0, 1].map(index => ({
    address: fields['address' + index].trim(), system: fields['system' + index].trim(),
    username: fields['user' + index].trim(), password: fields['pass' + index]
  }))}));
  registerForm('fc-deploy', fields => runAction('deploy', {
    confirm: !!fields.confirm, wwid: draft.plan.nodes[0].diskWWID,
    workgroup: (fields.workgroup || draft.workgroup).trim().toUpperCase(),
    controller: (fields.controller || draft.controller).trim().toLowerCase(),
    groupSID: (fields.groupSID || draft.groupSID).trim(), username: fields.username.trim(), password: fields.password
  }));
  function startSetup() {
    draft = null;
    for (const form of $('fc-setup').querySelectorAll('form')) form.reset();
    $('fc-fence-fields').replaceChildren();
    delete $('fc-fence-fields').dataset.nodes;
    switchMode(true);
    renderDraft();
  }
  $('fc-close-setup')?.addEventListener('click', () => {
    ++polling;
    switchMode(false);
    loadCatalog();
  });
  $('fc-refresh').addEventListener('click', loadCatalog);
  $('fc-select').addEventListener('change', () => {
    selectedKey = $('fc-select').value;
    $('fc-status').replaceChildren(make('p', 'Загрузка состояния…'));
    $('fc-quorum').replaceChildren();
    renderSnapshots(null);
    refreshStatus();
  });
  for (const button of root.querySelectorAll('[data-view]')) button.addEventListener('click', () => showView(button.dataset.view));

  const dialog = $('fc-snapshot-dialog');
  const snapForm = $('fc-snapshot-form');
  $('fc-new-snapshot')?.addEventListener('click', () => {
    snapForm.reset();
    showError('', $('fc-snapshot-error'));
    $('fc-snapshot-target').textContent = 'Снимок данных на активном узле ' + owner + '.';
    dialog.showModal();
  });
  $('fc-cancel-snapshot')?.addEventListener('click', () => dialog.close());
  dialog?.addEventListener('cancel', event => { if (snapForm.querySelector('[type=submit]').disabled) event.preventDefault(); });
  snapForm?.addEventListener('submit', async event => {
    event.preventDefault();
    const control = snapForm.querySelector('[type=submit]');
    const cancel = $('fc-cancel-snapshot');
    if (control.disabled) return;
    control.disabled = cancel.disabled = true;
    control.textContent = 'Создаётся…';
    showError('', $('fc-snapshot-error'));
    try {
      const cluster = activeCluster();
      const {node, id} = await api('/snapshot', {cluster, label: snapForm.elements.label.value.trim(), requestID: requestID()});
      await waitForJob(node, id);
      dialog.close();
      await refreshStatus();
    } catch (error) { showError(error.message, $('fc-snapshot-error')); }
    finally { control.disabled = cancel.disabled = false; control.textContent = 'Создать'; }
  });
  const scheduleDialog = $('fc-schedule-dialog');
  const scheduleForm = $('fc-schedule-form');
  const refreshScheduleFields = () => {
    const enabled = scheduleForm.elements.enabled.checked;
    $('fc-schedule-fields').hidden = !enabled;
  };
  $('fc-edit-schedule')?.addEventListener('click', () => {
    if (!schedule) return;
    scheduleForm.elements.enabled.checked = schedule.enabled;
    scheduleForm.elements.intervalMinutes.value = schedule.intervalMinutes;
    scheduleForm.elements.retain.value = schedule.retain;
    showError('', $('fc-schedule-error'));
    refreshScheduleFields();
    scheduleDialog.showModal();
  });
  scheduleForm?.elements.enabled.addEventListener('change', refreshScheduleFields);
  $('fc-cancel-schedule')?.addEventListener('click', () => scheduleDialog.close());
  scheduleDialog?.addEventListener('cancel', event => {
    if (scheduleForm.querySelector('[type=submit]').disabled) event.preventDefault();
  });
  scheduleForm?.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = scheduleForm.querySelector('[type=submit]');
    if (submit.disabled) return;
    const fields = scheduleForm.elements;
    const policy = {enabled: fields.enabled.checked, intervalMinutes: Number(fields.intervalMinutes.value), retain: Number(fields.retain.value)};
    const controls = Array.from(fields);
    for (const control of controls) control.disabled = true;
    submit.textContent = 'Сохраняется…';
    showError('', $('fc-schedule-error'));
    try {
      const {node, id} = await api('/snapshot-schedule', {cluster: activeCluster(), policy, requestID: requestID()});
      await waitForJob(node, id);
      scheduleDialog.close();
      await refreshStatus();
    } catch (error) { showError(error.message, $('fc-schedule-error')); }
    finally {
      submit.textContent = 'Сохранить';
      for (const control of controls) control.disabled = false;
    }
  });
  $('fc-close-info').addEventListener('click', () => $('fc-info-dialog').close());
  $('fc-copy-path').addEventListener('click', async () => {
    const field = $('fc-info-path');
    try {
      await navigator.clipboard.writeText(field.value);
      $('fc-copy-result').textContent = 'Путь скопирован.';
    } catch {
      field.focus();
      field.select();
      $('fc-copy-result').textContent = 'Путь выделен. Скопируйте его.';
    }
  });
  const restoreDialog = $('fc-restore-dialog');
  let restoration;
  const restoreLabels = {
    create: 'Создать', replace: 'Перезаписать', merge: 'Вернуть права папки',
    keep: 'Сохранить папку', skip: 'Пропустить', blocked: 'Конфликт'
  };
  function restoreControls() {
    const {path, directory, offset, nextOffset, busy, plan} = restoration;
    $('fc-restore-up').disabled = busy || !directory;
    $('fc-restore-prev').hidden = offset <= 0;
    $('fc-restore-prev').disabled = busy;
    $('fc-restore-next').hidden = nextOffset == null;
    $('fc-restore-next').disabled = busy;
    $('fc-restore-preview').disabled = busy || !path;
    $('fc-restore-overwrite').disabled = busy;
    $('fc-restore-confirm').disabled = busy || !plan?.canApply;
    $('fc-restore-apply').disabled = busy || !plan?.canApply || !$('fc-restore-confirm').checked;
    $('fc-restore-back').disabled = busy;
    $('fc-restore-close').disabled = busy;
    for (const row of $('fc-restore-entries').querySelectorAll('button')) row.disabled = busy;
    $('fc-restore-selection').textContent = path ? 'Выбрано: ' + path : 'Выберите файл или папку.';
  }
  async function restoreJob(operation, fields, busyText) {
    const state = restoration;
    state.busy = true;
    showError('', $('fc-restore-error'));
    $('fc-restore-progress').textContent = busyText;
    restoreControls();
    try {
      const {node, id} = await api('/restore/' + operation, {
        cluster: state.cluster, snapshot: state.snapshot.name, requestID: requestID(), ...fields
      });
      return await waitForJob(node, id, operation === 'apply' ? 3700 : 120, job => {
        if (operation === 'apply') $('fc-restore-progress').textContent = job.log?.at(-1) || busyText;
      });
    } catch (error) {
      showError(error.message, $('fc-restore-error'));
      return null;
    } finally {
      $('fc-restore-progress').textContent = '';
      state.busy = false;
      restoreControls();
    }
  }
  function chooseRestore(path, button) {
    restoration.path = path;
    for (const item of $('fc-restore-entries').querySelectorAll('[aria-pressed]')) item.setAttribute('aria-pressed', String(item === button));
    restoreControls();
  }
  async function browseRestore(path = '', offset = 0) {
    const response = await restoreJob('browse', {path, offset}, 'Читаю содержимое снимка…');
    if (!response) return;
    Object.assign(restoration, {directory: path, offset, nextOffset: response.nextOffset});
    const list = $('fc-restore-entries');
    $('fc-restore-directory').textContent = '/' + path;
    list.replaceChildren();
    for (const entry of response.entries || []) {
      const row = make('div', null, 'fc-restore-row');
      const relative = [path, entry.name].filter(Boolean).join('/');
      const select = make('button', entry.name, 'fc-restore-name');
      select.type = 'button';
      select.setAttribute('aria-pressed', String(restoration.path === relative));
      if (entry.kind === 'unsupported') {
        row.append(make('span', entry.name), make('span', 'Недоступно', 'fc-muted'));
      } else {
        select.addEventListener('click', () => chooseRestore(relative, select));
        row.append(select);
        if (entry.kind === 'directory') {
          const open = make('button', 'Открыть');
          open.type = 'button';
          open.setAttribute('aria-label', 'Открыть папку ' + entry.name);
          open.addEventListener('click', () => browseRestore(relative));
          row.append(open);
        } else row.append(make('span', 'Файл', 'fc-muted'));
      }
      list.append(row);
    }
    if (!list.childElementCount) list.append(make('p', 'Пустая папка', 'fc-muted'));
    restoreControls();
  }
  function openRestore(item) {
    restoration = {cluster: activeCluster(), snapshot: item, directory: '', offset: 0, path: '', plan: null, busy: false};
    $('fc-restore-context').textContent = item.label + ' · ' + restoration.cluster.name + '.' + restoration.cluster.realm;
    $('fc-restore-picker').hidden = false;
    $('fc-restore-review').hidden = true;
    $('fc-restore-confirm').checked = $('fc-restore-overwrite').checked = false;
    $('fc-restore-entries').replaceChildren();
    $('fc-restore-directory').textContent = '/';
    restoreDialog.showModal();
    browseRestore();
  }
  $('fc-restore-up')?.addEventListener('click', () => browseRestore(restoration.directory.split('/').slice(0,-1).join('/')));
  $('fc-restore-prev')?.addEventListener('click', () => browseRestore(restoration.directory, Math.max(0,restoration.offset-100)));
  $('fc-restore-next')?.addEventListener('click', () => browseRestore(restoration.directory,restoration.nextOffset));
  $('fc-restore-preview')?.addEventListener('click', async () => {
    restoration.overwrite = $('fc-restore-overwrite').checked;
    const plan = await restoreJob('preview', {path: restoration.path, overwrite: restoration.overwrite}, 'Сверяю снимок с текущим ресурсом…');
    if (!plan) return;
    restoration.plan = plan;
    $('fc-restore-picker').hidden = true;
    $('fc-restore-review').hidden = false;
    $('fc-restore-confirm').checked = false;
    $('fc-restore-counts').replaceChildren(...Object.entries(plan.counts).filter(([,n]) => n).map(([key,n]) =>
      pill(restoreLabels[key] + ' · ' + n, key === 'blocked' ? 'bad' : key === 'replace' || key === 'merge' ? 'warn' : '')));
    $('fc-restore-items').replaceChildren(...(plan.items || []).map(item => {
      const row = make('div',null,'fc-restore-row');
      row.append(make('span',item.path),make('strong',restoreLabels[item.action]));
      return row;
    }));
    if (plan.counts.blocked) showError('Устраните конфликты или выберите другой путь.', $('fc-restore-error'));
    restoreControls();
  });
  $('fc-restore-back')?.addEventListener('click', () => {
    restoration.plan = null;
    showError('', $('fc-restore-error'));
    $('fc-restore-review').hidden = true;
    $('fc-restore-picker').hidden = false;
    restoreControls();
  });
  $('fc-restore-confirm')?.addEventListener('change', restoreControls);
  $('fc-restore-apply')?.addEventListener('click', async () => {
    const plan = restoration.plan;
    const result = await restoreJob('apply', {path: restoration.path, overwrite: restoration.overwrite,
      planRevision: plan.revision, confirm: $('fc-restore-confirm').checked}, 'Задание восстановления принято…');
    if (!result) {
      restoration.plan = null;
      restoreControls();
      return;
    }
    $('fc-restore-review').hidden = true;
    $('fc-restore-progress').textContent = 'Восстановление завершено. Файлы: ' + result.files + ', папки: ' + result.directories + '.';
  });
  $('fc-restore-close')?.addEventListener('click', () => restoreDialog.close());
  restoreDialog?.addEventListener('cancel', event => { if (restoration?.busy) event.preventDefault(); });
  showView('status');
  loadCatalog().then(()=>{if(new URLSearchParams(location.search).get('setup')==='1')startSetup();});
  setInterval(() => { if (!document.hidden && !wizard) refreshStatus(); }, 15000);
})();
