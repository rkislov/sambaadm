(function () {
  'use strict';

  function render(parent, report, policyName, {el, t, button}) {
    const states = {
      consistent: t('Совпадает', 'Matches'),
      reference: t('Копия для сравнения', 'Comparison copy'),
      different: t('Есть расхождения', 'Differences found'),
      incomplete: t('Проверка неполная', 'Check incomplete'),
      unavailable: t('Недоступно', 'Unavailable'),
      changing: t('Изменилось во время чтения', 'Changed during read'),
      pending: t('Незавершённая запись', 'Pending write'),
      'single-controller': t('Один DC — сравнение между контроллерами невозможно', 'Single DC — cross-controller comparison unavailable'),
      'not-compared': t('Нет доступной копии для сравнения', 'No available comparison copy'),
      ok: t('Прочитано', 'Read'),
      missing: t('Отсутствует', 'Missing'),
      error: t('Ошибка чтения', 'Read error'),
      'not-checked': t('Не проверено', 'Not checked')
    };
    const kinds = {
      'local-version': t('LDAP и GPT.INI на одном DC', 'LDAP vs GPT.INI on one DC'),
      'ldap-version': t('Версия LDAP', 'LDAP version'),
      'gpt-version': t('Версия GPT.INI', 'GPT.INI version'),
      'ldap-acl': t('Права объекта LDAP', 'LDAP object permissions'),
      'ldap-metadata': t('Метаданные LDAP', 'LDAP metadata'),
      content: t('Содержимое файла', 'File content'),
      'sysvol-acl': t('Права SYSVOL', 'SYSVOL permissions'),
      missing: t('Нет на этом DC', 'Missing on this DC'),
      extra: t('Дополнительный путь', 'Additional path'),
      type: t('Тип объекта', 'Object type'),
      'path-case': t('Регистр имени пути', 'Path name case')
    };
    const read = dc => dc.ldap === 'ok' && dc.sysvol === 'ok' && !dc.pending && dc.status !== 'changing';
    const needsReview = dc => !read(dc) || dc.differenceCount > 0 || dc.errors.length > 0 || dc.status === 'not-compared';
    const controllers = [...report.controllers].sort((a, b) => Number(needsReview(b)) - Number(needsReview(a)));
    const version = v => v == null ? '—' : v + ' (M: ' + (v & 65535) + ', U: ' + (v >>> 16) + ')';
    const title = t('Согласованность SYSVOL', 'SYSVOL consistency');
    const sysvolLocation = dc => '\\\\' + dc + '\\SYSVOL\\' + report.sysvolPath;
    const content = el('article', 'consistency-report');

    function download(filename, data, type) {
      const url = URL.createObjectURL(new Blob([data], {type}));
      const link = el('a');
      link.href = url;
      link.download = filename;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function table(parent, headings, rows) {
      const wrap = el('div', 'workspace-table');
      const table = el('table');
      const head = el('thead'), header = el('tr'), body = el('tbody');
      for (const heading of headings) {
        const cell = el('th', '', heading);
        cell.scope = 'col';
        header.append(cell);
      }
      head.append(header);
      for (const row of rows) {
        const tr = el('tr');
        for (const value of row) {
          const cell = el('td');
          if (value instanceof Node) cell.append(value);
          else cell.textContent = value == null || value === '' ? '—' : value;
          tr.append(cell);
        }
        body.append(tr);
      }
      table.append(head, body);
      wrap.append(table);
      parent.append(wrap);
    }

    function list(parent, items) {
      const ul = el('ul');
      for (const item of items) ul.append(el('li', '', item));
      parent.append(ul);
    }

    function nextSteps(dc) {
      const checks = new Set();
      const has = (...types) => dc.differences.some(diff => types.includes(diff.kind));
      if (dc.errors.some(error => /deadline exceeded|timeout|timed out/i.test(error))) {
        checks.add(t('Проверьте доступность DC и задержки LDAP/SMB, затем повторите проверку.', 'Check DC connectivity and LDAP/SMB latency, then rerun the check.'));
      }
      if (dc.errors.some(error => /SYSVOL object\/depth limit|SYSVOL content exceeds/i.test(error))) {
        checks.add(t('Проверьте число файлов, вложенность и объём папки GPO в SYSVOL. Чтение прервано лимитом отчёта.', 'Check the file count, nesting and size of the GPO folder in SYSVOL. A report limit stopped the scan.'));
      }
      if (dc.ldap === 'missing') {
        checks.add(t('Найдите объект по указанному DN на этом DC и проверьте входящую репликацию раздела домена.', 'Look up the DN on this DC and check inbound replication of the domain partition.'));
      } else if (dc.ldap !== 'ok' && dc.ldap !== 'not-checked') {
        checks.add(t('Проверьте DNS и подключение к LDAP этого DC, а также права чтения объекта GPO служебной учётной записи.', 'Check DNS, the LDAP connection to this DC and the service account’s read access to the GPO object.'));
      }
      if (dc.sysvol === 'missing') {
        checks.add(t('Проверьте наличие папки GPO в SYSVOL этого DC и журнал доставки SYSVOL.', 'Check that the GPO folder exists in this DC’s SYSVOL and review the SYSVOL delivery log.'));
      } else if (dc.sysvol !== 'ok' && dc.sysvol !== 'not-checked') {
        checks.add(t('Проверьте доступность SMB и права чтения указанной папки SYSVOL на этом DC.', 'Check SMB connectivity and read access to the listed SYSVOL folder on this DC.'));
      }
      if (dc.ldap === 'not-checked' || dc.sysvol === 'not-checked') {
        checks.add(t('Этот DC не успели прочитать. Проверьте доступность контроллеров и повторите проверку.', 'The check did not reach this DC. Check controller availability and rerun the check.'));
      }
      if (dc.pending) {
        checks.add(t('Откройте журнал незавершённой записи SYSVOL для этой GPO и проверьте состояние операции перед повторным сравнением.', 'Inspect the pending SYSVOL write journal for this GPO before comparing again.'));
      }
      if (dc.status === 'changing') {
        checks.add(t('Дождитесь завершения редактирования или доставки GPO и повторите проверку.', 'Wait for GPO edits or delivery to finish, then rerun the check.'));
      }
      if (has('local-version')) {
        checks.add(t('Сопоставьте versionNumber объекта LDAP и Version в GPT.INI на этом DC. Проверьте, завершились ли изменение GPO и доставка SYSVOL.', 'Compare LDAP versionNumber with Version in GPT.INI on this DC. Check whether the GPO change and SYSVOL delivery finished.'));
      }
      if (has('ldap-version', 'ldap-metadata')) {
        checks.add(t('Сравните указанные атрибуты LDAP на двух DC и проверьте репликацию раздела домена.', 'Compare the listed LDAP attributes on the two DCs and check replication of the domain partition.'));
      }
      if (has('ldap-acl')) {
        checks.add(t('Сравните владельца, группу и DACL объекта GPO по указанному DN на обоих DC.', 'Compare the owner, group and DACL of the GPO object at the listed DN on both DCs.'));
      }
      if (has('gpt-version', 'content', 'missing', 'extra', 'type', 'path-case')) {
        checks.add(t('Сравните указанные пути в папках SYSVOL двух DC и проверьте журнал доставки GPO.', 'Compare the listed paths in the two SYSVOL folders and review the GPO delivery log.'));
      }
      if (has('sysvol-acl')) {
        checks.add(t('Сравните владельца, группу и DACL файла или каталога по указанному пути SYSVOL на обоих DC.', 'Compare the owner, group and DACL of the listed SYSVOL file or directory on both DCs.'));
      }
      if (dc.status === 'not-compared') {
        checks.add(t('Проверьте доступность выбранной копии для сравнения и повторите проверку.', 'Check the availability of the selected comparison copy and rerun the check.'));
      }
      return checks;
    }

    content.append(el('h3', report.status === 'consistent' ? '' : 'alert', states[report.status] || report.status));
    content.append(el('p', '', [policyName, report.gpo].filter(Boolean).join(' · ')));
    content.append(el('p', 'mono', window.sambaadmFormatTime(report.started) + ' → ' + window.sambaadmFormatTime(report.finished)));
    content.append(el('p', '', t('Сравнение с: ', 'Compared with: ') + (report.reference || '—')));
    if (report.reference && report.sysvolPath) content.append(el('p', 'mono', sysvolLocation(report.reference)));
    if (report.ldapDN) content.append(el('p', 'mono', 'LDAP DN · ' + report.ldapDN));
    if (!report.complete) {
      content.append(el('p', 'alert error', t('Не все копии проверены. Совпадение доступных DC не подтверждает согласованность всего домена.', 'Not all copies were checked. Matching accessible DCs does not establish domain-wide consistency.')));
    }
    if (report.hasDifferences) {
      content.append(el('p', 'alert error', t('Обнаружены подтверждённые расхождения в прочитанных данных.', 'Differences were found in the data read.')));
    }

    const reviewed = controllers.filter(needsReview).length;
    content.append(el('h4', '', t('Сводка по контроллерам', 'Controller summary')));
    content.append(el('p', '', t('Контроллеров: ', 'Controllers: ') + controllers.length + ' · ' + t('Требуют внимания: ', 'Need attention: ') + reviewed));
    const controllerId = index => 'gpo-consistency-dc-' + (index + 1);
    table(content, ['DC', t('Результат', 'Result'), 'LDAP', 'SYSVOL', t('Версия LDAP', 'LDAP version'), 'GPT.INI', t('Объектов', 'Objects'), t('Различий', 'Differences')], controllers.map((dc, index) => {
      const name = needsReview(dc) ? el('a', '', dc.dns) : dc.dns;
      if (needsReview(dc)) {
        name.href = '#' + controllerId(index);
        name.addEventListener('click', event => {
          event.preventDefault();
          const detail = content.querySelector('#' + controllerId(index));
          detail.open = true;
          detail.scrollIntoView({block: 'start'});
          detail.querySelector('summary').focus({preventScroll: true});
        });
      }
      return [name, states[dc.status] || dc.status, states[dc.ldap] || dc.ldap, states[dc.sysvol] || dc.sysvol, version(dc.ldapVersion), version(dc.gptVersion), dc.files.length, dc.differenceCount];
    }));

    controllers.forEach((dc, index) => {
      if (!needsReview(dc)) return;
      const details = el('details');
      details.id = controllerId(index);
      details.open = controllers.length <= 10;
      details.append(el('summary', '', dc.dns + ' · ' + (states[dc.status] || dc.status)));
      if (report.sysvolPath) {
        details.append(el('p', 'mono', sysvolLocation(dc.dns)));
      }
      const checks = nextSteps(dc);
      if (checks.size) {
        details.append(el('h4', '', t('Что проверить дальше', 'What to check next')));
        list(details, checks);
      }
      if (dc.errors.length) {
        details.append(el('h4', '', t('Ошибки чтения', 'Read errors')));
        list(details, dc.errors);
      }
      if (dc.differences.length) {
        details.append(el('h4', '', t('Расхождения', 'Differences')));
        table(details, [t('Что отличается', 'Difference'), t('Путь / атрибут', 'Path / attribute'), t('Копия для сравнения', 'Comparison copy'), t('Этот DC', 'This DC')],
          dc.differences.map(diff => [kinds[diff.kind] || diff.kind, diff.path, diff.reference, diff.value]));
      }
      if (dc.differenceCount > dc.differences.length) {
        details.append(el('p', 'muted', t('Показано ', 'Showing ') + dc.differences.length + ' / ' + dc.differenceCount + t('. Манифест файлов доступен в JSON.', '. The file manifest is included in JSON.')));
      }
      content.append(details);
    });

    content.append(el('p', 'muted', t('Копия для сравнения служит ориентиром. Состояние применения политики на клиенте проверяется отдельно.', 'The comparison copy is a baseline. Verify policy application separately on the client.')));
    if (report.limitations?.length) {
      const limits = el('details');
      limits.append(el('summary', '', t('Ограничения проверки', 'Check limitations')));
      list(limits, report.limitations);
      content.append(limits);
    }

    const tools = el('div', 'workspace-tools');
    tools.append(
      button(t('Скачать отчёт HTML', 'Download HTML report'), () => download('gpo-consistency.html', standalone(title, content), 'text/html;charset=utf-8')),
      button(t('Скачать отчёт JSON', 'Download JSON report'), () => download('gpo-consistency.json', JSON.stringify(report, null, 2), 'application/json'))
    );
    parent.append(tools, content);
  }

  function standalone(title, content) {
    const doc = document.implementation.createHTMLDocument(title);
    doc.documentElement.lang = document.documentElement.lang;
    const charset = doc.createElement('meta');
    charset.setAttribute('charset', 'utf-8');
    const policy = doc.createElement('meta');
    policy.httpEquiv = 'Content-Security-Policy';
    policy.content = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
    const viewport = doc.createElement('meta');
    viewport.name = 'viewport';
    viewport.content = 'width=device-width, initial-scale=1';
    doc.head.prepend(charset, policy, viewport);
    const style = doc.createElement('style');
    style.textContent = `
      body { max-width: 78rem; margin: auto; padding: 1.5rem; color: #172433; font: 15px/1.5 system-ui, sans-serif; overflow-wrap: anywhere; }
      h1, h3, h4 { line-height: 1.25; }
      table { width: 100%; border-collapse: collapse; margin: .5rem 0 1rem; }
      th, td { padding: .5rem; text-align: left; vertical-align: top; border-bottom: 1px solid #cbd5e1; }
      th { background: #edf2f7; }
      a { color: #075e59; }
      .mono { font-family: ui-monospace, monospace; }
      .muted { color: #475569; }
      .alert { border-left: .25rem solid #b45309; padding: .5rem .75rem; background: #fffbeb; }
      details { padding: .75rem; border: 1px solid #cbd5e1; border-radius: .5rem; margin-block: .75rem; }
      details:target { border-color: #0f766e; }
      summary { cursor: pointer; font-weight: 600; }
      @media print { body { padding: 0; } tr { break-inside: avoid; } h3, h4, summary { break-after: avoid; } }
    `;
    doc.head.append(style);
    const heading = doc.createElement('h1');
    heading.textContent = title;
    const report = doc.importNode(content, true);
    for (const details of report.querySelectorAll('details[id]')) details.open = true;
    doc.body.append(heading, report);
    return '<!doctype html>\n' + doc.documentElement.outerHTML;
  }

  window.sambaadmConsistencyReport = {render};
})();
