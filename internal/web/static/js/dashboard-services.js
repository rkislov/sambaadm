(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const root = $('dashboard-services');
  if (!root) return;

  const ru = document.documentElement.lang === 'ru';
  const t = (r, e) => ru ? r : e;
  const admin = root.dataset.admin === 'true';
  const refresh = $('service-overview-refresh');
  const summary = $('service-overview-summary');
  const warning = $('service-overview-warning');
  const filter = $('service-overview-filter');
  const search = $('service-overview-search');
  const pages = $('service-overview-pages');
  const prev = $('service-overview-prev');
  const next = $('service-overview-next');
  const pageSize = 8;
  const serversPanel = $('service-overview-servers');
  const clustersPanel = $('service-overview-clusters');
  const dialog = $('service-overview-detail');
  const labels = {
    cups: 'Печать CUPS', ad: 'Samba AD', smb: t('Файловые ресурсы (SMB)', 'File shares (SMB)'),
    dhcp4: 'DHCPv4', dhcp6: 'DHCPv6', ddns: 'Kea DDNS', 'kea-control': 'Kea Control Agent',
    dns: 'DNS (BIND)', ntp: 'NTP (Chrony)', winbind: 'Winbind', sssd: 'SSSD',
    pacemaker: 'Pacemaker', corosync: 'Corosync', multipath: 'Multipath', iscsi: 'iSCSI',
    zed: 'ZFS Event Daemon', ctdb: 'CTDB'
  };
  const states = {
    active: [t('Работает', 'Running'), 'good'],
    inactive: [t('Остановлена', 'Stopped'), 'muted'],
    failed: [t('Сбой', 'Failed'), 'bad'],
    transition: [t('Переход', 'Changing'), 'warn'],
    absent: [t('Нет службы', 'No service'), 'muted'],
    unknown: [t('Нет данных', 'Unknown'), 'warn'],
    degraded: [t('Работает с ограничениями', 'Degraded'), 'warn'],
    'no-owner': [t('Нет активного SMB', 'No active SMB'), 'bad'],
    reserve: [t('Резервный', 'Standby'), 'muted'],
    offline: [t('Узел недоступен', 'Node unavailable'), 'bad'],
    owner: [t('Активный', 'Active'), 'good']
  };
  const helper = {
    online: [t('Хелпер на связи', 'Helper online'), 'good'],
    unavailable: [t('Хелпер недоступен', 'Helper unreachable'), 'bad'],
    unregistered: [t('Хелпер не подключён', 'No helper registered'), 'warn'],
    legacy: [t('Хелпер требует обновления', 'Helper update required'), 'warn'],
    'no-systemd': [t('Нет ответа systemd', 'No data from systemd'), 'warn']
  };
  const haModes = {
    'hot-standby': t('Горячий резерв', 'Hot standby'),
    'load-balancing': t('Балансировка нагрузки', 'Load balancing'),
    'passive-backup': t('Пассивный резерв', 'Passive backup')
  };
  const haStates = {
    'hot-standby': haModes['hot-standby'], 'load-balancing': haModes['load-balancing'],
    'passive-backup': haModes['passive-backup'], 'partner-down': t('Партнёр недоступен', 'Partner down'),
    'communication-recovery': t('Восстановление связи', 'Communication recovery'),
    'partner-in-maintenance': t('Партнёр на обслуживании', 'Partner in maintenance'),
    'in-maintenance': t('Обслуживание', 'In maintenance'), 'syncing': t('Синхронизация', 'Syncing'),
    waiting: t('Ожидание', 'Waiting'), ready: t('Готов к запуску', 'Ready'),
    terminated: t('HA остановлен', 'HA terminated'), backup: t('Резервный', 'Backup')
  };
  const haRoles = {primary: t('Основной', 'Primary'), secondary: t('Вторичный', 'Secondary'),
    standby: t('Резервный', 'Standby'), backup: t('Резервная копия', 'Backup')};

  let data, detail, opener, renderedKey = '', page = 0;
  let linkedHistory = new URLSearchParams(location.search);
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  function chip(state, attention = false) {
    const [label, tone] = states[state] || states.unknown;
    return el('span', label, 'service-chip ' + (attention && tone === 'muted' ? 'bad' : tone));
  }
  function link(label, path, query) {
    const node = el('a', label);
    node.href = path + (query ? '?' + new URLSearchParams(query) : '');
    return node;
  }
  const clusterLink = (cluster, label = cluster.name) => link(label, '/file-clusters', {cluster: cluster.key});
  const clusterNode = (cluster, server) => cluster.nodes.find(node => node.name.toLowerCase() === server.name.toLowerCase());
  const nodeClusters = server => data.clusters.filter(cluster => clusterNode(cluster, server));
  const lookup = (server, id) => {
    const matches = server.services.filter(service => service.id === id);
    return matches.find(service => service.state === 'active') || matches[0] || {id, state: 'unknown'};
  };
  function hasHAProblem(ha) {
    if (ha.interrupted === true || (ha.inTouch === false && ha.mode !== 'passive-backup')) return true;
    if (ha.state && !['hot-standby', 'load-balancing', 'passive-backup', 'backup'].includes(ha.state)) return true;
    return Boolean(ha.peerState && !['hot-standby', 'load-balancing', 'passive-backup', 'backup'].includes(ha.peerState));
  }
  function dhcpLabel({dhcp: health}) {
    if (!health?.source) return t('Режим неизвестен', 'HA mode unknown');
    if (health.standalone) return t('Вне HA', 'Standalone');
    if (health.source === 'runtime' && health.relationships?.some(hasHAProblem)) return t('HA требует внимания', 'HA needs attention');
    if (health.source !== 'runtime') return t('HA настроен · нет статуса', 'HA configured · no status');
    if (health.relationships?.length > 1) return 'HA · ' + health.relationships.length;
    const mode = health.relationships?.[0]?.mode;
    return 'HA' + (haModes[mode] ? ' · ' + haModes[mode] : '');
  }
  function unitAttention(server, service) {
    const {state, id, dhcp} = service;
    if (state === 'failed' || state === 'transition') return true;
    if (id === 'ad' && server.controller && state !== 'active') return true;
    if (state === 'unknown' || state === 'absent' || state === 'inactive') return !!service.enabled;
    if (!id.startsWith('dhcp')) return false;
    return ['retrying','failed'].includes(dhcp?.socketState) ||
      (dhcp?.relationships || []).some(hasHAProblem) || !dhcp?.source ||
      (!dhcp.standalone && (dhcp.source !== 'runtime' || !dhcp.relationships?.length));
  }
  const needsAttention = server => server.helper !== 'online' ||
    unitAttention(server, lookup(server, 'ad')) ||
    server.services.some(service => unitAttention(server, service)) ||
    nodeClusters(server).some(cluster => cluster.state !== 'active');

  function inspectButton(server, scope, label, options = {}) {
    const button = el('button', null, 'service-inspect');
    button.type = 'button';
    button.setAttribute('aria-label', label);
    button.setAttribute('aria-haspopup', 'dialog');
    button.addEventListener('click', () => {
      opener = button;
      detail = {name: server.name, scope, view: 'history', ...options};
      showDetail();
      dialog.showModal();
    });
    return button;
  }

  const iconPaths = {
    ad: 'M3 4h7v7H3zM14 4h7v7h-7zM3 15h7v6H3zM14 15h7v6h-7z',
    smb: 'M3 7V5h6l2 3h10v11H3z',
    'smb-ha': 'M3 4h5l2 2h7v4H3zM7 14h5l2 2h7v4H7zM10 10v2m4 0v2',
    dhcp: 'M12 3a7 7 0 0 0-7 7c0 4 7 11 7 11s7-7 7-11a7 7 0 0 0-7-7zM10 10h4m-2-2v4',
    'dhcp-ha': 'M3 8h17l-4-4m5 12H4l4 4M3 8l4 4m14 4-4-4',
    dns: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18m-9-9c-5 5-5 13 0 18 5-5 5-13 0-18',
    ntp: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l4 2',
    storage: 'M4 4h16v7H4zM4 14h16v6H4zM7 8h1m-1 9h1',
    service: 'M12 3v3m0 12v3M3 12h3m12 0h3M6 6l2 2m8 8 2 2M6 18l2-2m8-8 2-2M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z'
  };
  const iconLabels = {
    ad: 'AD', smb: 'SMB', 'smb-ha': 'SMB HA', dhcp4: 'DHCPv4', dhcp6: 'DHCPv6', dns: 'DNS', ntp: 'NTP',
    cups: 'CUPS', ddns: 'DDNS', 'kea-control': 'Kea API', winbind: 'Winbind', sssd: 'SSSD', pacemaker: 'Pacemaker',
    corosync: 'Corosync', multipath: 'MPIO', iscsi: 'iSCSI', zed: 'ZFS', ctdb: 'CTDB'
  };
  function icon(path) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const shape = document.createElementNS(ns, 'path');
    shape.setAttribute('d', iconPaths[path] || iconPaths.service);
    svg.append(shape);
    return svg;
  }

  function dhcpNote(server, service) {
    const health = service.dhcp;
    const relations = health?.relationships || [];
    const label = labels[service.id];
    if (service.state !== 'active') return '';
    if (health?.socketState === 'failed') return label + ' · ' + t('сбой сокетов', 'socket failure');
    if (health?.socketState === 'retrying') return label + ' · ' + t('повтор открытия сокетов', 'retrying sockets');
    if (relations.some(ha => ha.state === 'partner-down' && ha.serving !== false)) {
      return label + ' · ' + t('обслуживает за пару', 'serving for both');
    }
    if (unitAttention(server, service)) return label + ' · ' + dhcpLabel(service);
    if (health.standalone) return label + ' · ' + t('вне HA', 'standalone');
    if (relations.some(ha => ha.serving === true)) return label + ' · ' + t('активен', 'active');
    if (relations.length && relations.every(ha => ha.serving === false)) return label + ' · ' + t('резерв', 'standby');
    return label + ' · HA';
  }

  function presentServices(server) {
    const clusters = nodeClusters(server);
    const ids = [...new Set(server.services.map(unit => unit.id))];
    if (server.controller && !ids.includes('ad')) ids.unshift('ad');
    return ids.map(id => lookup(server, id)).filter(unit => {
      if (unit.id === 'ad' && server.controller) return true;
      if (!unit.unit || unit.state === 'absent') return false;
      // A cluster-managed smbd has its own unit. An unused packaged SMB unit
      // on a cluster node is only useful in the detailed server inventory.
      return unit.id !== 'smb' || !clusters.length || unit.enabled || ['active','failed','transition'].includes(unit.state);
    });
  }

  function rowStatus(server, units, clusters) {
    if (server.helper === 'unavailable') return [t('Нет связи', 'Unreachable'), 'bad'];
    if (server.helper === 'unregistered' || server.helper === 'no-systemd') return states.unknown;
    if (!units.length && !clusters.length) return [t('Нет служб', 'No services'), 'muted'];
    if (needsAttention(server)) return [t('Требует внимания', 'Needs attention'), 'warn'];
    if (!clusters.length && units.every(unit => unit.state === 'inactive')) return [t('Службы остановлены', 'Services stopped'), 'bad'];
    return [t('В норме', 'Healthy'), 'good'];
  }

  function configureIcon(control, glyph, label, status, tone, attention) {
    control.classList.add('service-glyph', tone);
    control.title = label + ' · ' + status;
    control.append(icon(glyph), el('span', label, 'service-glyph-label'));
    if (attention) control.append(el('span', '!', 'service-glyph-attention'));
    return control;
  }

  function renderServers(rows) {
    const table = el('table', null, 'service-matrix');
    const heading = table.createTHead().insertRow();
    const headers = [t('Сервер', 'Server'), t('Службы', 'Services'), t('Статус', 'Status'), t('Примечание', 'Note')];
    for (const label of headers) {
      const th = el('th', label);
      th.scope = 'col';
      heading.append(th);
    }
    const body = table.createTBody();
    for (const server of rows) {
      const row = body.insertRow();
      const host = el('th');
      host.scope = 'row';
      const serverButton = inspectButton(server, 'server', server.name);
      serverButton.append(el('strong', server.name));
      host.append(serverButton);
      row.append(host);

      const units = presentServices(server);
      const clusters = nodeClusters(server);
      const services = el('div', null, 'service-row-icons');
      const notes = [];
      let otherIssues = 0;
      if (server.helper !== 'online') notes.push((helper[server.helper] || helper.unavailable)[0]);
      if (server.controller) notes.push((server.rodc ? 'RODC' : 'AD') + (server.site ? ' · ' + server.site : ''));
      for (const cluster of clusters) {
        const node = clusterNode(cluster, server);
        const state = node.state === 'active' ? 'owner' : node.state;
        const [status, tone] = states[state] || states.unknown;
        const label = t('Кластер SMB', 'SMB cluster') + ' · ' + cluster.name + ' · ' + server.name;
        const button = inspectButton(server, 'smb-ha', label, {cluster, history: [{kind: 'smb', id: cluster.key}]});
        button.setAttribute('aria-description', status);
        services.append(configureIcon(button, 'smb-ha', iconLabels['smb-ha'], status, state === 'unknown' ? 'unknown' : tone, state === 'owner' && cluster.state !== 'active'));
        notes.push('SMB · ' + (state === 'owner' && cluster.state !== 'active'
          ? t('активен, без полного резерва', 'active, redundancy reduced') : status.toLowerCase()));
      }
      for (const unit of units) {
        const dhcp = unit.id === 'dhcp4' || unit.id === 'dhcp6';
        const clustered = dhcp && unit.dhcp?.source && !unit.dhcp.standalone;
        const glyph = dhcp ? (clustered ? 'dhcp-ha' : 'dhcp')
          : ['winbind','sssd'].includes(unit.id) ? 'ad'
          : ['multipath','iscsi','zed'].includes(unit.id) ? 'storage' : unit.id;
        const [status, defaultTone] = states[unit.state] || states.unknown;
        const tone = unit.state === 'inactive' ? 'bad' : unit.state === 'unknown' ? 'unknown' : defaultTone;
        const label = labels[unit.id] || unit.id;
        const pairIDs = new Set((unit.dhcp?.relationships || []).map(ha => ha.pairID).filter(Boolean));
        const options = clustered ? {history: [...pairIDs].map(id => ({kind: unit.id, id}))} : {};
        const button = inspectButton(server, unit.id, label + ' · ' + server.name, options);
        button.setAttribute('aria-description', status + (clustered && unit.state === 'active' ? ' · ' + dhcpLabel(unit) : ''));
        const short = iconLabels[unit.id] || unit.id;
        services.append(configureIcon(button, glyph, clustered ? short + ' HA' : short, status, tone,
          unit.state === 'active' && unitAttention(server, unit)));
        const note = dhcp ? dhcpNote(server, unit) : '';
        if (note) notes.push(note);
        else if (unitAttention(server, unit)) {
          if (['ad','smb','dhcp4','dhcp6'].includes(unit.id)) notes.push(label + ' · ' + status.toLowerCase());
          else otherIssues++;
        }
      }

      if (server.helper === 'online' && otherIssues) {
        notes.push(t('Доп. службы требуют внимания', 'Other services need attention') + ' · ' + otherIssues);
      }
      const important = clusters.length + units.filter(unit => ['ad','smb','dhcp4','dhcp6'].includes(unit.id)).length;
      const visible = Math.max(4, important);
      if (services.children.length > visible) {
        const hidden = services.children.length - visible;
        while (services.children.length > visible) services.lastChild.remove();
        const more = inspectButton(server, 'server', t('Все службы', 'All services') + ' · ' + server.name);
        more.classList.add('service-glyph', 'muted');
        more.textContent = '+' + hidden;
        more.title = t('Открыть все службы', 'Open all services');
        services.append(more);
      }
      const serviceCell = row.insertCell();
      serviceCell.dataset.label = headers[1];
      serviceCell.append(services);
      const statusCell = row.insertCell();
      statusCell.dataset.label = headers[2];
      const [status, tone] = rowStatus(server, units, clusters);
      statusCell.append(el('span', status, 'service-chip ' + tone));
      const noteCell = row.insertCell();
      noteCell.dataset.label = headers[3];
      noteCell.className = 'service-row-note';
      const combined = [];
      for (const note of new Set(notes)) {
        const family = note.match(/^DHCPv([46]) · (.+)$/);
        const same = family && combined.find(item => item === 'DHCPv4 · ' + family[2]);
        if (same && family[1] === '6') combined[combined.indexOf(same)] = 'DHCPv4/v6 · ' + family[2];
        else combined.push(note);
      }
      for (const note of combined) noteCell.append(el('span', note));
    }
    return table;
  }

  function render() {
    const {servers, clusters, observed} = data;
    const problemCount = servers.filter(needsAttention).length;
    summary.textContent = servers.length
      ? t('Серверы', 'Servers') + ' ' + servers.length + ' · ' +
        (problemCount ? t('Требуют внимания', 'Needs attention') + ' ' + problemCount : t('Без замечаний', 'No issues')) +
        ' · ' + new Date(observed).toLocaleTimeString(ru ? 'ru-RU' : 'en', {hour: '2-digit', minute: '2-digit', second: '2-digit'})
      : t('Серверы пока не обнаружены.', 'No servers discovered yet.');
    $('service-overview-filter-label').hidden = !servers.length;
    if (servers.length > pageSize) search.hidden = false;
    const query = search.value.trim().toLocaleLowerCase();
    const found = servers.filter(server => (!filter.checked || needsAttention(server)) &&
      (!query || server.name.toLocaleLowerCase().includes(query)));
    const lastPage = Math.max(0, Math.ceil(found.length / pageSize) - 1);
    page = Math.min(page, lastPage);
    const first = page * pageSize, shown = found.slice(first, first + pageSize);
    pages.hidden = found.length <= pageSize;
    prev.disabled = page === 0;
    next.disabled = page === lastPage;
    $('service-overview-range').textContent = (first + 1) + '–' + (first + shown.length) +
      t(' из ', ' of ') + found.length;
    const key = JSON.stringify([shown, clusters, filter.checked, query]);
    if (renderedKey === key) return;
    renderedKey = key;
    const focused = document.activeElement;
    const focusedLabel = serversPanel.contains(focused) ? focused.getAttribute('aria-label') : null;
    serversPanel.replaceChildren(...(shown.length ? [renderServers(shown)] : query
      ? [el('p', t('Серверы по запросу не найдены.', 'No matching servers.'))] : filter.checked
      ? [el('p', t('Серверов, требующих внимания, нет.', 'No servers need attention.'))] : []));
    if (focusedLabel) {
      [...serversPanel.querySelectorAll('button')].find(button => button.getAttribute('aria-label') === focusedLabel)
        ?.focus({preventScroll: true});
    }
    const shownClusters = filter.checked ? clusters.filter(cluster => cluster.state !== 'active') : clusters;
    clustersPanel.hidden = !shownClusters.length;
    clustersPanel.querySelector('ul').replaceChildren(...shownClusters.map(cluster => {
      const li = el('li');
      const anchor = clusterLink(cluster);
      anchor.prepend(icon('smb-ha'));
      li.append(anchor, chip(cluster.state));
      li.append(el('small', cluster.owner ? t('Активный узел', 'Active node') + ' · ' + cluster.owner
        : cluster.quorum ? t('Кворум есть', 'Quorum confirmed') : t('Кворум не подтверждён', 'Quorum unconfirmed')));
      return li;
    }));
    if (dialog.open) showDetail();
  }

  function addFact(list, label, value) {
    if (value !== '' && value != null) list.append(el('dt', label), el('dd', String(value)));
  }
  function describeDHCP(parent, unit) {
    const health = unit.dhcp;
    if (!health?.source || health.source === 'last-known') {
      parent.append(el('p', t('Режим Kea не удалось определить.', 'Kea HA mode could not be determined.')));
      return;
    }
    const haList = el('dl');
    const modes = [...new Set((health.relationships || []).map(ha => haModes[ha.mode]).filter(Boolean))];
    addFact(haList, t('Режим', 'Mode'), health.standalone ? t('Вне HA', 'Standalone') : modes.join(', ') || 'HA');
    if (!health.standalone) addFact(haList, t('Состояние HA', 'HA status'), dhcpLabel(unit));
    addFact(haList, t('Источник', 'Source'), health.source === 'runtime' ? 'Kea status-get' : t('Файл конфигурации', 'Configuration file'));
    if (health.socketState) {
      const socketStates = {ready: t('Готовы', 'Ready'), retrying: t('Повторное открытие', 'Retrying'), failed: t('Сбой', 'Failed')};
      addFact(haList, t('Сокеты DHCP', 'DHCP sockets'), socketStates[health.socketState]);
    }
    parent.append(haList);
    if (unit.state === 'active' && health.source === 'config' && !health.standalone) {
      parent.append(el('p', t('Текущее состояние HA доступно через локальный UNIX-сокет Kea.', 'Live HA status is available through Kea’s local UNIX socket.')));
    }
    for (const [index, ha] of (health.relationships || []).entries()) {
      const facts = el('dl');
      parent.append(el('h4', haModes[ha.mode] || 'HA ' + (index + 1)), facts);
      addFact(facts, t('Узел в Kea', 'Kea server name'), ha.name);
      addFact(facts, t('Роль', 'Role'), haRoles[ha.role] || ha.role);
      addFact(facts, t('Текущее состояние', 'Current state'), haStates[ha.state] || ha.state);
      if (ha.serving != null) addFact(facts, t('Обслуживает клиентов', 'Serving clients'),
        ha.serving ? t('Да', 'Yes') : t('Нет', 'No'));
      addFact(facts, t('Партнёр', 'Peer'), ha.peer);
      addFact(facts, t('Последнее состояние партнёра', 'Last peer state'), haStates[ha.peerState] || ha.peerState);
      if (health.source === 'runtime' && (ha.peer || ha.inTouch != null || ha.interrupted != null)) {
        const communication = ha.interrupted === true ? t('Прервана', 'Interrupted')
          : ha.inTouch === false ? t('Ещё не подтверждена', 'Not established yet')
          : ha.inTouch === true || ha.interrupted === false ? t('Есть', 'Available') : states.unknown[0];
        addFact(facts, t('Связь с партнёром', 'Peer communication'), communication);
        if (ha.ageSeconds != null) addFact(facts, t('Возраст данных о партнёре', 'Age of peer data'), ha.ageSeconds + t(' с', ' s'));
      }
    }
  }
  function describeUnit(server, unit) {
    const block = el('section', null, 'service-detail-unit');
    const heading = el('h3', labels[unit.id] || unit.id);
    heading.append(chip(unit.state, unitAttention(server, unit)));
    block.append(heading);
    const facts = el('dl');
    addFact(facts, t('Служба', 'Service'), unit.unit);
    addFact(facts, 'systemd', unit.subState);
    if (facts.childNodes.length) block.append(facts);
    if (unit.id.startsWith('dhcp') && unit.state !== 'absent') describeDHCP(block, unit);
    return block;
  }
  function historyLabel(event, members) {
    const serverName = name => members?.[name] || name;
    const list = names => (names || []).map(serverName).join(', ');
    const serving = list(event.serving);
    if (event.type === 'node-down') return [
      t('Узел недоступен', 'Node unavailable'), serverName(event.node), 'bad'
    ];
    if (event.type === 'service-moved') return [
      t('Служба перешла', 'Service moved'), list(event.previous) + ' → ' + serving, 'warn'
    ];
    if (event.type === 'reserve-restored') {
      const reserve = list(event.reserve);
      return [t('Резерв восстановлен', 'Redundancy restored'),
        t('Вернулся', 'Returned') + ' · ' + serverName(event.node) + ' / ' +
        t('Обслуживает', 'Serving') + ' · ' + serving +
        (reserve ? ' / ' + t('Резерв', 'Standby') + ' · ' + reserve : ''), 'good'];
    }
    return null;
  }

  function formatTimestamp(value) {
    return new Date(value).toLocaleString(ru ? 'ru-RU' : 'en', {
      day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }

  async function loadHistory(target, queries) {
    target.replaceChildren(el('p', t('Загружаем историю…', 'Loading history…')));
    const responses = await Promise.allSettled(queries.map(async query => {
      const response = await fetch('/api/v1/services/ha-history?' + new URLSearchParams(query));
      if (!response.ok) throw new Error(String(response.status));
      return response.json();
    }));
    if (!target.isConnected) return;
    target.replaceChildren();
    for (const [index, response] of responses.entries()) {
      if (response.status !== 'fulfilled') {
        target.append(el('p', t('Не удалось загрузить историю.', 'Could not load history.'), 'service-history-error'));
        continue;
      }
      const {events, since, members} = response.value;
      if (queries.length > 1) {
        const name = Object.values(members || {}).join(' / ');
        target.append(el('h4', name || t('HA-пара', 'HA pair') + ' ' + (index + 1)));
      }
      const list = el('ol', null, 'service-timeline');
      for (const event of [...(events || [])].sort((a,b) => Date.parse(b.at) - Date.parse(a.at))) {
        const value = historyLabel(event, members);
        if (!value) continue;
        const [title, description, tone] = value;
        const entry = el('li', null, 'service-timeline-entry ' + tone);
        const time = el('time', formatTimestamp(event.at));
        time.dateTime = event.at;
        const body = el('div');
        body.append(el('strong', title), el('p', description));
        entry.append(time, body);
        list.append(entry);
      }
      if (list.children.length) target.append(list);
      else target.append(el('p', t('Переключений пока не зафиксировано.', 'No failovers have been recorded yet.')));
      if (since) target.append(el('small', t('Запись с', 'Recording since') + ' ' + formatTimestamp(since) + '. ' +
        t('Время подтверждения событий панелью.', 'Times indicate confirmation by the panel.')));
    }
  }

  function historyDialog(box, selection) {
    const tabs = el('div', null, 'service-detail-tabs');
    for (const [key, label] of [['history', t('История', 'History')], ['status', t('Состояние', 'Status')]]) {
      const button = el('button', label);
      button.type = 'button';
      button.disabled = key === 'status' && !selection.name;
      button.setAttribute('aria-pressed', String(selection.view === key));
      button.addEventListener('click', () => {
        selection.view = key;
        showDetail();
        dialog.querySelector('.service-detail-tabs [aria-pressed=true]')?.focus();
      });
      tabs.append(button);
    }
    box.append(tabs);
    if (selection.view === 'status') return false;
    const section = el('section', null, 'service-history');
    const heading = el('div', null, 'service-history-heading');
    heading.append(el('h3', t('История переключений', 'Failover history')));
    section.append(heading);
    if (selection.history.length) {
      const body = el('div');
      body.setAttribute('aria-live', 'polite');
      const update = el('button', t('Обновить историю', 'Refresh history'));
      update.type = 'button';
      update.addEventListener('click', () => loadHistory(body, selection.history));
      heading.append(update);
      section.append(body);
      box.append(section);
      loadHistory(body, selection.history);
    } else {
      section.append(el('p', t('Для этой конфигурации HA история недоступна.', 'History is unavailable for this HA configuration.')));
      box.append(section);
    }
    if (selection.cluster) {
      const nav = el('nav', null, 'service-detail-links');
      nav.append(clusterLink(selection.cluster, t('Открыть файловый кластер', 'Open file cluster')));
      box.append(nav);
    }
    return true;
  }

  function showDetail() {
    const server = data.servers.find(server => server.name === detail.name);
    if (!server && !detail.history) return;
    const scope = detail.scope;
    const box = $('service-detail-body');
    const cluster = detail.cluster && (data.clusters.find(item => item.key === detail.cluster.key) || detail.cluster);
    $('service-detail-title').textContent = cluster ? 'SMB HA · ' + cluster.name
      : detail.history ? (labels[scope] || 'SMB') + ' HA' + (server ? ' · ' + server.name : '') : server.name;
    box.replaceChildren();
    if (detail.history && historyDialog(box, detail)) return;
    if (cluster) {
      const facts = el('dl');
      const status = el('section', null, 'service-detail-unit');
      status.append(el('h3', t('Файловый кластер', 'File cluster')), facts);
      addFact(facts, t('Состояние SMB', 'SMB status'), (states[cluster.state] || states.unknown)[0]);
      addFact(facts, t('Активный узел', 'Active node'), cluster.owner);
      for (const node of cluster.nodes) {
        const label = (states[node.state === 'active' ? 'owner' : node.state] || states.unknown)[0];
        addFact(facts, node.name, label + (node.totalPaths ? ' · Multipath ' + node.readyPaths + '/' + node.totalPaths : ''));
      }
      box.append(status);
      const nav = el('nav', null, 'service-detail-links');
      nav.append(clusterLink(cluster, t('Открыть файловый кластер', 'Open file cluster')));
      box.append(nav);
      return;
    }
    if (scope === 'server') {
      const description = [helper[server.helper]?.[0], server.site].filter(Boolean).join(' · ');
      box.append(el('p', description, 'service-detail-hint'));
    }
    let units = server.services;
    if (scope === 'server') {
      units = ['ad','smb','dhcp4','dhcp6'].map(id => lookup(server, id)).filter(unit => unit.state !== 'absent')
        .concat(server.services.filter(unit => !['ad','smb','dhcp4','dhcp6'].includes(unit.id)));
    } else {
      units = (scope === 'dhcp' ? ['dhcp4','dhcp6'] : [scope]).map(id => lookup(server, id));
    }
    for (const unit of units) box.append(describeUnit(server, unit));

    const links = el('nav', null, 'service-detail-links');
    links.setAttribute('aria-label', t('Связанные разделы', 'Related sections'));
    if ((scope === 'server' || scope === 'ad') && server.controller) {
      links.append(link(t('Контроллеры домена', 'Domain controllers'), '/sites'), link(t('Репликация', 'Replication'), '/repl'));
    }
    if (scope === 'smb' || (scope === 'server' && lookup(server, 'smb').state === 'active')) {
      if (server.helper !== 'unregistered') links.append(link(t('Общие папки сервера', 'Server shares'), '/shares', {node: server.name}));
    }
    if (scope === 'server' || scope === 'smb') {
      for (const cluster of nodeClusters(server)) links.append(clusterLink(cluster));
    }
    if (admin && (scope.startsWith('dhcp') || scope === 'server') && server.helper !== 'unregistered') {
      const family = scope === 'dhcp6' || (scope === 'server' && !lookup(server, 'dhcp4').unit && lookup(server, 'dhcp6').unit) ? '6' : '4';
      const query = {node: server.name, family};
      const health = lookup(server, 'dhcp' + family).dhcp;
      if (scope.startsWith('dhcp') && health?.source && !health.standalone) query.view = 'ha';
      links.append(link(t('Управление DHCP', 'Manage DHCP'), '/dhcp', query));
    }
    if (scope === 'cups' || (scope === 'server' && lookup(server,'cups').unit)) links.append(link(t('Управление печатью','Manage printing'),'/printers',{node:server.name}));
    if (admin && scope === 'server') links.append(link(t('Настройка хелперов', 'Helper settings'), '/settings/helpers'));
    if (links.childNodes.length) box.append(links);
  }

  function openLinkedHistory() {
    const kind = linkedHistory?.get('haKind'), id = linkedHistory?.get('haID');
    if (!['smb','dhcp4','dhcp6'].includes(kind) || !/^(?:[a-zA-Z0-9-]{1,63}@)?[a-f0-9]{64}$/.test(id || '')) return;
    linkedHistory = null;
    const cluster = kind === 'smb' ? data.clusters.find(item => item.key === id) : null;
    const server = cluster ? data.servers.find(item => item.name === (cluster.owner || cluster.nodes[0]?.name))
      : data.servers.find(item => lookup(item, kind).dhcp?.relationships?.some(ha => ha.pairID === id));
    detail = {scope: kind, name: server?.name, cluster, view: 'history', history: [{kind,id}]};
    opener = null;
    showDetail();
    if (!dialog.open) dialog.showModal();
  }

  async function load() {
    if (refresh.disabled) return;
    refresh.disabled = true;
    try {
      const response = await fetch('/api/v1/services/overview', {headers: {Accept: 'application/json'}});
      if (!response.ok) throw new Error();
      const next = await response.json();
      if (!Array.isArray(next.servers) || !Array.isArray(next.clusters)) throw new Error();
      if (data) {
        for (const server of next.servers) {
          if (!['unavailable','no-systemd'].includes(server.helper)) continue;
          const earlier = data.servers.find(item => item.name === server.name);
          if (!earlier) continue;
          server.services = earlier.services.filter(unit => unit.unit && unit.state !== 'absent').map(unit => ({
            id: unit.id, unit: unit.unit, enabled: unit.enabled, state: 'unknown',
            dhcp: unit.dhcp?.source ? {source: 'last-known', standalone: unit.dhcp.standalone,
              relationships: unit.dhcp.relationships?.map(ha => ({pairID: ha.pairID}))} : undefined
          }));
        }
      }
      data = next;
      const warnings = [];
      if (data.directoryUnknown) warnings.push(t('Список контроллеров AD недоступен.', 'The AD controller list is unavailable.'));
      if (data.helpersUnknown) warnings.push(t('Список хелперов недоступен.', 'The helper registry is unavailable.'));
      if (data.catalogPartial) warnings.push(t('Список файловых кластеров может быть неполным.', 'The file cluster list may be incomplete.'));
      warning.textContent = warnings.join(' ');
      warning.hidden = !warnings.length;
      render();
      openLinkedHistory();
    } catch {
      warning.textContent = data
        ? t('Обновление не удалось. Показаны данные последней проверки.', 'Refresh failed. Showing the last successful check.')
        : t('Не удалось загрузить состояние служб.', 'Service status could not be loaded.');
      warning.hidden = false;
      if (!data) summary.textContent = '';
    } finally {
      refresh.disabled = false;
    }
  }
  dialog.addEventListener('close', () => {
    if (opener?.isConnected) opener.focus();
    else refresh.focus();
    detail = null;
  });
  const resetPage = () => { page = 0; if (data) render(); };
  filter.addEventListener('change', resetPage);
  search.addEventListener('input', resetPage);
  prev.addEventListener('click', () => { page--; render(); });
  next.addEventListener('click', () => { page++; render(); });
  refresh.addEventListener('click', load);
  load();
  setInterval(() => { if (!document.hidden && !dialog.open) load(); }, 45000);
})();
