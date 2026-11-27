(() => {
  'use strict';
  const byID = id => document.getElementById(id);
  const root = byID('ha-mail');
  if (!root) return;
  const form = byID('ha-mail-form');
  const fields = form.elements;
  const rows = byID('ha-mail-recipients');
  const password = byID('ha-mail-password');
  const feedback = byID('ha-mail-message');
  const refresh = byID('ha-mail-refresh');
  const testRecipient = byID('ha-mail-test-recipient');
  const testAddress = byID('ha-mail-test-address');
  const testSend = byID('ha-mail-test-send');
  const testResult = byID('ha-mail-test-result');
  const endpoint = '/api/v1/services/ha-mail';
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const events = {
    'node-down': 'Потеря узла',
    'smb-moved': 'Переключение SMB',
    'dhcp-moved': 'Переключение DHCP',
    'reserve-restored': 'Восстановление резерва'
  };
  const states = {
    queued: 'В очереди', sending: 'Отправляется', sent: 'Принято SMTP',
    failed: 'Ошибка', uncertain: 'Приём не подтверждён', cancelled: 'Отменено'
  };
  const ports = {starttls: 587, tls: 465, local: 25};
  let passwordPresent = false, testing = false;

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function passwordHint() {
    password.hidden = !fields.username.value;
    password.querySelector('span').textContent = passwordPresent ? 'Пароль задан.' : 'Пароль пока не задан.';
  }

  function recipient(item = {address: '', events: Object.keys(events)}) {
    const group = el('fieldset', null, 'ha-mail-recipient');
    group.append(el('legend', 'Получатель'));
    const contact = el('label', 'Адрес');
    const address = el('input');
    address.type = 'email';
    address.placeholder = 'ops@example.org';
    address.value = item.address;
    address.required = true;
    address.maxLength = 254;
    contact.append(address);
    const filters = el('div', null, 'ha-mail-event-list');
    filters.setAttribute('role', 'group');
    filters.setAttribute('aria-label', 'События получателя');
    for (const [key, label] of Object.entries(events)) {
      const checkbox = el('input');
      checkbox.type = 'checkbox';
      checkbox.value = key;
      checkbox.checked = item.events.includes(key);
      const choice = el('label', null, 'ha-mail-check');
      choice.append(checkbox, document.createTextNode(label));
      filters.append(choice);
    }
    const remove = el('button', 'Удалить получателя');
    remove.type = 'button';
    address.addEventListener('input', syncTestRecipients);
    remove.addEventListener('click', () => { group.remove(); syncTestRecipients(); byID('ha-mail-add').focus(); });
    group.append(contact, filters, remove);
    rows.append(group);
    return address;
  }

  function showConfig(config) {
    for (const field of ['host','port','security','from','username']) fields[field].value = config[field];
    fields.enabled.checked = config.enabled;
    rows.replaceChildren();
    for (const entry of config.recipients || []) recipient(entry);
    syncTestRecipients();
    passwordHint();
  }

  function showDelivery(data) {
    passwordPresent = data.passwordPresent;
    passwordHint();
    const parts = Object.entries(states).filter(([state]) => data.counts[state] > 0)
      .map(([state, label]) => label + ' · ' + data.counts[state]);
    byID('ha-mail-summary').textContent = parts.length ? parts.join(' / ') : 'Отправлений пока нет.';
    byID('ha-mail-recent').replaceChildren(...data.recent.map(item => {
      const entry = el('li');
      const time = el('time', new Date(item.at).toLocaleString(undefined, {dateStyle:'short', timeStyle:'medium'}));
      time.dateTime = item.at;
      const status = el('strong', states[item.state] || item.state, 'ha-mail-state');
      status.dataset.state = item.state;
      const description = el('span', (events[item.event] || item.event) + ' · ' + item.to);
      entry.append(time, description, status);
      if (item.reason) entry.append(el('small', item.reason));
      return entry;
    }));
  }

  function smtpValues() {
    return {
      host: fields.host.value, port: Number(fields.port.value), security: fields.security.value,
      from: fields.from.value, username: fields.username.value
    };
  }

  function selectedTestAddress() {
    return testRecipient.value === 'other' ? testAddress.value.trim() : testRecipient.value;
  }

  function updateTestButton() {
    byID('ha-mail-test-custom').hidden = testRecipient.value !== 'other';
    testSend.disabled = testing || !selectedTestAddress();
  }

  function syncTestRecipients() {
    const saved = testRecipient.value;
    const addresses = new Map();
    for (const input of rows.querySelectorAll('input[type="email"]')) {
      const value = input.value.trim();
      if (value && input.validity.valid) addresses.set(value.toLowerCase(), value);
    }
    testRecipient.replaceChildren(new Option('Выберите адрес', ''));
    for (const address of addresses.values()) testRecipient.add(new Option(address, address));
    testRecipient.add(new Option('Другой адрес…', 'other'));
    if ([...testRecipient.options].some(option => option.value === saved) && saved) {
      testRecipient.value = saved;
    } else if (!addresses.size) {
      testRecipient.value = 'other';
    }
    updateTestButton();
  }

  testRecipient.addEventListener('change', updateTestButton);
  testAddress.addEventListener('input', updateTestButton);
  testSend.addEventListener('click', async () => {
    const recipient = selectedTestAddress();
    if (testing || !recipient) return;
    testing = true;
    updateTestButton();
    testResult.dataset.state = 'sending';
    testResult.textContent = 'Проверяем SMTP…';
    try {
      const response = await fetch(endpoint + '/test', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({smtp: smtpValues(), recipient})
      });
      const result = await response.json().catch(() => ({}));
      if (response.ok && result.state === 'sent') {
        testResult.dataset.state = 'sent';
        testResult.textContent = 'SMTP принял тестовое письмо для ' + result.recipient + '.';
      } else {
        testResult.dataset.state = 'failed';
        testResult.textContent = result.error || 'Не удалось проверить отправку.';
      }
    } catch {
      testResult.dataset.state = 'failed';
      testResult.textContent = 'Ответ панели не получен. Проверьте SMTP перед повторной отправкой.';
    } finally {
      testing = false;
      updateTestButton();
    }
  });

  async function load(options) {
    const response = await fetch(endpoint, options);
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || 'Не удалось получить настройки почты.');
    }
    return response.json();
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const config = {
      ...smtpValues(), enabled: fields.enabled.checked,
      recipients: [...rows.children].map(row => ({
        address: row.querySelector('input[type=email]').value,
        events: [...row.querySelectorAll('input[type=checkbox]:checked')].map(input => input.value)
      }))
    };
    byID('ha-mail-fields').disabled = true;
    feedback.textContent = 'Сохраняем…';
    try {
      const saved = await load({
        method:'PUT', headers:{'Content-Type':'application/json', 'X-CSRF-Token':csrf}, body:JSON.stringify(config)
      });
      showDelivery(saved);
      showConfig(saved.config);
      feedback.textContent = 'Настройки сохранены.';
    } catch (error) { feedback.textContent = error.message; }
    finally { byID('ha-mail-fields').disabled = false; }
  });

  byID('ha-mail-add').addEventListener('click', () => recipient().focus());
  fields.username.addEventListener('input', passwordHint);
  fields.security.addEventListener('change', () => {
    if (!fields.port.value || Object.values(ports).includes(Number(fields.port.value))) {
      fields.port.value = ports[fields.security.value];
    }
  });
  refresh.addEventListener('click', async () => {
    refresh.disabled = true;
    try { showDelivery(await load()); }
    catch (error) { byID('ha-mail-summary').textContent = error.message; }
    finally { refresh.disabled = false; }
  });
  load().then(data => {
    showDelivery(data);
    showConfig(data.config);
    byID('ha-mail-fields').disabled = false;
  }).catch(error => { feedback.textContent = error.message; });
})();
