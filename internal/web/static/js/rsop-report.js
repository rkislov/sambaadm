/* Read Windows RSoP reports locally. XML nodes never enter the page DOM. */
(function () {
  'use strict';

  const namespace = 'http://www.microsoft.com/GroupPolicy/Rsop';
  const limit = 16 * 1024 * 1024;
  const children = (node, name) => Array.from(node?.children || []).filter(child => child.localName === name);
  const child = (node, name) => children(node, name)[0];
  const value = (node, name) => child(node, name)?.textContent.trim() || '';

  function decode(buffer) {
    const [first, second, third, fourth] = new Uint8Array(buffer, 0, Math.min(4, buffer.byteLength));
    let encoding = 'utf-8';
    if ((first === 255 && second === 254) || (first === 60 && second === 0 && third === 63 && fourth === 0)) {
      encoding = 'utf-16le';
    } else if ((first === 254 && second === 255) || (first === 0 && second === 60 && third === 0 && fourth === 63)) {
      encoding = 'utf-16be';
    }
    return new TextDecoder(encoding, {fatal: true}).decode(buffer);
  }

  function parse(buffer, t) {
    const xml = decode(buffer);
    if (xml.includes('<!DOCTYPE')) throw new Error(t('Отчёт содержит недопустимое объявление DTD.', 'The report contains a disallowed DTD.'));
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    const root = doc.documentElement;
    if (root.localName !== 'Rsop' || root.namespaceURI !== namespace || doc.getElementsByTagName('parsererror').length) {
      throw new Error(t('Выберите XML-отчёт RSoP, созданный командой gpresult /x.', 'Select an RSoP XML report created with gpresult /x.'));
    }
    const dataType = value(root, 'DataType');
    if (dataType && dataType !== 'LoggedData') {
      throw new Error(t('Для результатов применения нужен отчёт RSoP в режиме журналирования.', 'Select an RSoP report from logging mode.'));
    }
    const sections = [
      [t('Конфигурация компьютера', 'Computer Configuration'), child(root, 'ComputerResults')],
      [t('Конфигурация пользователя', 'User Configuration'), child(root, 'UserResults')]
    ].filter(([, section]) => section);
    if (!sections.length) throw new Error(t('В отчёте нет данных компьютера или пользователя.', 'The report has no computer or user results.'));
    return {sections, time: value(root, 'ReadTime')};
  }

  function identifier(gpo) {
    const id = child(gpo, 'Identifier');
    return value(id, 'Identifier') || id?.textContent.trim() || value(gpo, 'ID');
  }

  function extensionRows(section) {
    const result = [];
    for (const data of children(section, 'ExtensionData')) {
      const extension = child(data, 'Extension');
      const category = value(data, 'Name') || extension?.getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'type') || '';
      const pending = Array.from(extension?.children || []).reverse();
      while (pending.length) {
        const node = pending.pop();
        if (child(node, 'GPO') || child(node, 'Precedence')) result.push({node, category});
        else for (let index = node.children.length - 1; index >= 0; index--) pending.push(node.children[index]);
      }
    }
    return result;
  }

  function mount(container, {t, el, button, message}) {
    const label = el('label', '', t('XML-отчёт Windows', 'Windows XML report'));
    const file = el('input');
    file.type = 'file';
    file.accept = '.xml,application/xml,text/xml';
    label.append(file);
    const guide = el('p', 'muted', t('На компьютере Windows выполните ', 'On the Windows computer, run '));
    guide.append(el('code', '', 'gpresult /x result.xml'));
    const notice = el('p', 'workspace-message');
    notice.setAttribute('aria-live', 'polite');
    const body = el('section');
    container.append(guide, label, notice, body);
    let generation = 0;
    file.addEventListener('change', async () => {
      const current = ++generation;
      body.replaceChildren();
      message(notice, '');
      const reportFile = file.files[0];
      if (!reportFile) return;
      if (reportFile.size > limit) {
        message(notice, t('Размер отчёта превышает 16 МиБ.', 'The report exceeds 16 MiB.'), true);
        return;
      }
      try {
        const report = parse(await reportFile.arrayBuffer(), t);
        if (current !== generation || !container.isConnected) return;
        message(notice, t('Отчёт прочитан', 'Report loaded'));
        render(report);
      } catch (error) {
        if (current !== generation || !container.isConnected) return;
        const detail = error instanceof TypeError ? t('Не удалось прочитать кодировку XML.', 'Could not decode the XML report.') : error.message;
        message(notice, detail, true);
      }
    });

    function render(report) {
      const tabs = el('div', 'workspace-tools');
      tabs.setAttribute('role', 'group');
      tabs.setAttribute('aria-label', t('Раздел отчёта', 'Report section'));
      const output = el('section');
      if (report.time) {
        const time = new Date(report.time);
        body.append(el('p', 'muted', t('Время отчёта ', 'Report time ') + (Number.isNaN(time.getTime()) ? report.time : window.sambaadmFormatTime(time))));
      }
      body.append(tabs, output);
      const controls = [];
      for (const [title, section] of report.sections) {
        const control = button(title, () => select(control, section));
        controls.push(control);
        tabs.append(control);
      }
      select(controls[0], report.sections[0][1]);
      function select(control, section) {
        for (const option of controls) {
          option.setAttribute('aria-pressed', String(option === control));
          option.classList.toggle('btn-primary', option === control);
        }
        output.replaceChildren();
        renderSection(output, section);
      }
    }

    function renderSection(output, section) {
      const target = value(section, 'Name') || value(section, 'AccountName');
      if (target) output.append(el('h3', '', target));
      const policies = children(section, 'GPO');
      const names = new Map(policies.map(gpo => [identifier(gpo).toLowerCase(), value(gpo, 'Name')]).filter(([id]) => id));
      const settings = extensionRows(section);
      output.append(el('h3', '', t('Объекты групповой политики', 'Group Policy Objects')));
      list(output, [t('Политика', 'Policy'), t('Состояние', 'Status'), t('Порядок', 'Order')], policies.map(gpo => {
        const orders = children(gpo, 'Link').map(link => value(link, 'AppliedOrder')).filter(order => Number(order) > 0);
        const applied = orders.length > 0 || value(gpo, 'IsApplied') === 'true';
        let status = t('Есть в отчёте', 'Listed in report');
        if (value(gpo, 'AccessDenied') === 'true') status = t('Отказано в доступе', 'Access denied');
        else if (value(gpo, 'FilterAllowed') === 'false') status = t('Отфильтрована', 'Filtered');
        else if (value(gpo, 'Enabled') === 'false') status = t('Отключена', 'Disabled');
        else if (applied) status = t('Применена', 'Applied');
        return {node:gpo, cells:[value(gpo, 'Name') || identifier(gpo), status, orders.join(', ')]};
      }));
      output.append(el('h3', '', t('Параметры из отчёта', 'Settings from the report')));
      list(output, [t('Параметр', 'Setting'), t('Раздел', 'Category'), t('Состояние или значение', 'State or value'), t('Исходная GPO', 'Source GPO'), t('Приоритет', 'Precedence')], settings.map(({node, category}) => {
        const gpo = child(node, 'GPO');
        const id = identifier(gpo);
        const settingValue = value(node, 'SettingNumber') || value(node, 'SettingString') || value(node, 'SettingBoolean') || value(node, 'Value');
        return {node, cells:[
          value(node, 'Name') || value(node, 'KeyName') || value(node, 'Key') || node.localName,
          value(node, 'Category') || category,
          [value(node, 'State'), settingValue].filter(Boolean).join(' · '),
          names.get(id.toLowerCase()) || value(gpo, 'Name') || id,
          value(node, 'Precedence')
        ]};
      }));
    }

    function list(output, headers, rows) {
      if (!rows.length) {
        output.append(el('p', 'muted', t('Нет данных в отчёте', 'No data in the report')));
        return;
      }
      const filter = el('input');
      filter.type = 'search';
      filter.placeholder = t('Поиск', 'Search') + ' · ' + headers[0];
      filter.setAttribute('aria-label', filter.placeholder);
      const wrap = el('div', 'workspace-table');
      const table = el('table');
      const head = el('thead'), heading = el('tr'), tbody = el('tbody');
      for (const title of headers) heading.append(el('th', '', title));
      head.append(heading);
      table.append(head, tbody);
      wrap.append(table);
      const pager = el('div', 'workspace-tools');
      const previous = button(t('Назад', 'Previous'), () => {page--; update();});
      const next = button(t('Далее', 'Next'), () => {page++; update();});
      const count = el('span', 'muted');
      count.setAttribute('aria-live', 'polite');
      pager.append(previous, count, next);
      output.append(filter, wrap, pager);
      const pageSize = 100;
      let page = 0;
      filter.addEventListener('input', () => {page = 0; update();});
      function update() {
        const query = filter.value.trim().toLocaleLowerCase();
        const matches = query ? rows.filter(row => row.cells.some(cell => cell.toLocaleLowerCase().includes(query))) : rows;
        tbody.replaceChildren();
        const start = page * pageSize;
        for (const {cells, node} of matches.slice(start, start + pageSize)) {
          const row = el('tr');
          const name = el('td');
          const details = el('details');
          details.append(el('summary', '', cells[0] || '—'));
          details.addEventListener('toggle', () => {
            if (details.open && details.childElementCount === 1) {
              details.append(el('pre', 'workspace-output', new XMLSerializer().serializeToString(node)));
            }
          });
          name.append(details);
          row.append(name);
          for (const cell of cells.slice(1)) row.append(el('td', '', cell || '—'));
          tbody.append(row);
        }
        previous.disabled = page === 0;
        next.disabled = start + pageSize >= matches.length;
        count.textContent = matches.length ? `${start + 1}–${Math.min(start + pageSize, matches.length)} / ${matches.length}` : '0';
      }
      update();
    }
  }

  window.sambaadmRSOP = {mount};
})();
