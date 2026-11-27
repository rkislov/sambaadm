/* Shared page chrome for server-rendered pages and asynchronously built consoles. */
(() => {
  'use strict';

  const main = document.querySelector('main');
  if (!main || main.id === 'printing-console') return;

  const russian = document.documentElement.lang !== 'en';
  const label = (ru, en) => russian ? ru : en;
  const path = location.pathname.replace(/\/$/, '') || '/';
  const section = path.split('/')[1];
  const sections = {
    dns: ['/dns', label('DNS', 'DNS')],
    gpo: ['/gpo', label('Групповые политики', 'Group Policy')],
    settings: ['/settings', label('Настройки', 'Settings')],
    shares: ['/shares', label('Файловые ресурсы', 'File resources')],
  };
  const infrastructure = ['dns', 'dhcp', 'shares', 'file-clusters', 'sites', 'repl', 'trusts'];
  const descriptions = {
    users: label('Учётные записи, доступ и свойства пользователей', 'User accounts, access and properties'),
    groups: label('Группы безопасности и членство в домене', 'Security groups and domain membership'),
    computers: label('Компьютеры домена и параметры устройств', 'Domain computers and device settings'),
    gpo: label('Политики домена, моделирование и параметры', 'Domain policies, modeling and settings'),
    dhcp: label('Области, аренды и отказоустойчивость Kea', 'Kea scopes, leases and high availability'),
    dns: label('Зоны, записи и маршрутизация DNS', 'DNS zones, records and routing'),
  };

  function link(href, title) {
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.textContent = title;
    return anchor;
  }

  function breadcrumb(title) {
    const nav = document.createElement('nav');
    nav.className = 'console-breadcrumb';
    nav.setAttribute('aria-label', label('Путь к разделу', 'Breadcrumb'));
    nav.append(link('/', label('Консоль', 'Console')));

    function append(item) {
      const separator = document.createElement('span');
      separator.textContent = '/';
      separator.setAttribute('aria-hidden', 'true');
      nav.append(separator, item);
    }

    const parent = sections[section];
    if (parent && path.startsWith(parent[0] + '/')) {
      append(link(...parent));
    } else if (infrastructure.includes(section)) {
      const category = document.createElement('span');
      category.textContent = label('Инфраструктура', 'Infrastructure');
      append(category);
    }

    const current = document.createElement('strong');
    current.setAttribute('aria-current', 'page');
    current.textContent = title;
    append(current);
    return nav;
  }

  function decorate() {
    const heading = main.querySelector('h1');
    if (!heading || heading.closest('dialog') || heading.dataset.consoleHeading) return;

    if (heading.previousElementSibling?.classList.contains('console-breadcrumb')) return;
    heading.dataset.consoleHeading = 'true';

    const parent = heading.parentElement;
    let group = parent;
    if (parent === main || parent.classList.contains('workspace-head')) {
      group = document.createElement(parent === main ? 'header' : 'div');
      group.className = parent === main ? 'console-page-heading' : 'console-title-group';
      heading.before(group);
      group.append(heading);
    } else {
      group.classList.add('console-title-group');
    }

    group.insertBefore(breadcrumb(heading.textContent.trim()), heading);
    if (path === '/' + section && descriptions[section] && !group.querySelector('p')) {
      const subtitle = document.createElement('p');
      subtitle.className = 'console-page-subtitle';
      subtitle.textContent = descriptions[section];
      group.append(subtitle);
    }
  }

  decorate();
  // The workspace and provisioning wizard can render their heading after load.
  if (main.id === 'workspace' || main.classList.contains('di-shell')) {
    new MutationObserver(decorate).observe(main, {subtree: true, childList: true});
  }
})();
