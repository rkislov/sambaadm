(() => {
  'use strict';
  const bell = document.getElementById('ha-notification-bell');
  if (!bell) return;

  const dialog = document.getElementById('ha-notifications');
  const announcement = document.getElementById('ha-notification-announcement');
  const badge = bell.querySelector('.ha-notification-badge');
  const list = dialog.querySelector('.ha-notification-list');
  const message = dialog.querySelector('.ha-notification-message');
  const refresh = dialog.querySelector('[data-notification-refresh]');
  const mark = dialog.querySelector('[data-notification-read]');
  const ru = document.documentElement.lang === 'ru';
  const t = (r, e) => ru ? r : e;
  const endpoint = '/api/v1/services/ha-notifications';
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  let current, inFlight, rendered = '';

  function el(tag, contents, className) {
    const node = document.createElement(tag);
    if (contents) node.textContent = contents;
    if (className) node.className = className;
    return node;
  }

  function row(item) {
    const smb = item.sources.some(source => source.kind === 'smb');
    const descriptions = {
      'node-down': [t('Узел недоступен', 'Node unavailable'), item.node, 'critical'],
      'service-moved': [smb ? t('Переключение SMB', 'SMB failover') : t('Переключение DHCP', 'DHCP failover'),
        (item.previous || []).join(', ') + ' → ' + (item.serving || []).join(', '), 'change'],
      'reserve-restored': [t('Резерв восстановлен', 'Redundancy restored'), item.node, 'recovered']
    };
    const [title, description, tone] = descriptions[item.type];
    const entry = el('li', null, 'ha-notification-row ' + tone);
    entry.dataset.notificationId = item.id;
    entry.dataset.eventType = item.type;
    entry.dataset.read = String(item.read);
    const heading = el('div', null, 'ha-notification-row-heading');
    const time = el('time', new Date(item.at).toLocaleString(ru ? 'ru-RU' : 'en', {
      dateStyle: 'short', timeStyle: 'medium'
    }));
    time.dateTime = item.at;
    heading.append(el('strong', title), time);
    const links = el('div', null, 'ha-notification-sources');
    for (const source of item.sources) {
      const link = el('a', source.label);
      link.href = '/?' + new URLSearchParams({haKind: source.kind, haID: source.id}) + '#dashboard-services';
      links.append(link);
    }
    entry.append(heading, el('p', description), links);
    return entry;
  }

  function render(data) {
    if (current && !dialog.open) {
      const known = new Set(current.items.map(item => item.id));
      const added = data.items.filter(item => !item.read && !known.has(item.id)).length;
      if (added) announcement.textContent = t('Новые уведомления: ', 'New notifications: ') + added;
    }
    current = data;
    badge.hidden = data.unread === 0;
    badge.textContent = String(data.unread);
    bell.setAttribute('aria-label', t('Уведомления', 'Notifications') +
      (data.unread ? t(', непрочитанных ', ', unread ') + data.unread : ''));
    mark.hidden = data.unread === 0;
    const warning = data.items.length ? '' : t('Уведомлений о переключениях пока нет.', 'No failover notifications yet.');
    if (message.textContent !== warning) message.textContent = warning;
    const next = JSON.stringify(data.items);
    if (next === rendered) return;
    rendered = next;
    const focused = list.contains(document.activeElement) ? document.activeElement : null;
    const focusedID = focused?.closest('li')?.dataset.notificationId;
    const focusedHref = focused?.getAttribute('href');
    list.replaceChildren(...data.items.map(row));
    if (focusedID) {
      const kept = [...list.children].find(entry => entry.dataset.notificationId === focusedID);
      [...(kept?.querySelectorAll('a') || [])].find(link => link.getAttribute('href') === focusedHref)
        ?.focus({preventScroll: true});
    }
  }

  function load(ids) {
    if (inFlight) return inFlight;
    refresh.disabled = mark.disabled = true;
    const url = ids ? endpoint + '/read' : endpoint;
    const options = ids ? {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
      body: JSON.stringify({ids})
    } : {};
    inFlight = (async () => {
      try {
        const response = await fetch(url, options);
        if (!response.ok) throw new Error();
        const feed = await response.json();
        if (!Array.isArray(feed.items) || !Number.isInteger(feed.unread)) throw new Error();
        render(feed);
        if (ids && mark.hidden && dialog.open) refresh.focus();
      } catch {
        const warning = t('Не удалось обновить уведомления.', 'Could not update notifications.');
        if (message.textContent !== warning) message.textContent = warning;
      } finally {
        refresh.disabled = mark.disabled = false;
        inFlight = null;
      }
    })();
    return inFlight;
  }

  bell.addEventListener('click', () => {
    dialog.showModal();
    load();
  });
  dialog.addEventListener('close', () => bell.focus());
  refresh.addEventListener('click', () => load());
  mark.addEventListener('click', () => {
    const ids = (current?.items || []).filter(item => !item.read).map(item => item.id);
    if (ids.length) load(ids);
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
  load();
  setInterval(() => { if (!document.hidden) load(); }, 10000);
})();
