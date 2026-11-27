const fs = require('node:fs');
const os = require('node:os');
const https = require('node:https');
const {createHash} = require('node:crypto');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawn, execFileSync} = require('node:child_process');
const {chromium} = require('playwright');

const repo = path.resolve(__dirname, '../..');
const output = process.env.SAMBAADM_CLUSTER_SCREENSHOTS;
const lab = process.env.SAMBAADM_CLUSTER_BROWSER_LAB;
const dashboardOnly = process.env.SAMBAADM_SERVICE_DASHBOARD_ONLY;
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'sambaadm-file-cluster-browser-'));
const time = ms => new Promise(resolve => setTimeout(resolve, ms));
const server = spawn('go', ['test', './internal/web', '-run', '^TestFileClusterBrowserHarness$', '-count=1'], {
  cwd: repo, env: {...process.env, SAMBAADM_CLUSTER_BROWSER: base}, stdio: ['ignore', 'pipe', 'pipe']
});
let serverOutput = '';
server.stdout.on('data', chunk => serverOutput += chunk);
server.stderr.on('data', chunk => serverOutput += chunk);
const exit = new Promise(resolve => server.on('exit', resolve));

async function connection() {
  for (let attempt = 0; attempt < 300; attempt++) {
    const file = path.join(base, 'browser.json');
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
    if (server.exitCode !== null) throw Error(serverOutput || 'Harness exited');
    await time(200);
  }
  throw Error('Harness never started: ' + serverOutput);
}

async function screenshot(page, name, fullPage = false) {
  if (!output) return;
  fs.mkdirSync(output, {recursive: true});
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({path: path.join(output, name), fullPage, animations: 'disabled'});
}

async function runWizard(page) {
  await page.goto(new URL('/', page.url()).href);
  await page.getByRole('button', {name: 'Добавить роли и службы', exact: true}).click();
  const roles = page.locator('#dashboard-roles');
  await roles.locator('select[name=role]').selectOption('cluster');
  await roles.getByRole('button', {name: 'Открыть мастер настройки', exact: true}).click();
  await page.waitForURL('**/file-clusters?setup=1');
  const form = page.locator('#fc-pair');
  await form.locator('[name=first]').selectOption('fs-01.corp.example');
  await form.locator('[name=second]').selectOption('fs-02.corp.example');
  await form.locator('[name=address1]').fill('10.77.0.11');
  await form.locator('[name=address2]').fill('10.77.0.12');
  await form.locator('[name=name]').fill('files');
  await form.locator('[name=vip]').fill('10.77.0.50');
  await form.locator('[name=dedicatedZFS]').check();
  await screenshot(page, '01-nodes.png');

  await page.getByRole('button', {name: 'Проверить и подготовить узлы'}).click();
  await page.getByRole('heading', {name: 'Общее хранилище'}).waitFor();
  await page.getByRole('button', {name: 'К кластерам', exact: false}).click();
  await page.getByRole('button', {name: /Продолжить настройку/}).click();
  await page.locator('[name=portals]').fill('10.0.2.80:3260\n10.0.3.80:3260');
  await page.getByRole('button', {name: 'Найти цели'}).click();
  await page.getByRole('button', {name: 'Подключить цель'}).click();
  await page.locator('#fc-map').waitFor({timeout:10000}).catch(async error => { console.log(await page.locator('#file-cluster').innerText()); throw error; });
  await screenshot(page, '02-iscsi.png');

  await page.getByRole('button', {name: 'Настроить multipath'}).click();
  await page.getByRole('heading', {name: 'Fencing через Redfish'}).waitFor();
  const fencing = page.locator('#fc-fence');
  for (const i of [0,1]) {
    await fencing.locator('[name=address'+i+']').fill('10.77.0.9' + (i+1) + ':443');
    await fencing.locator('[name=system'+i+']').fill('/redfish/v1/Systems/' + (i+1));
    await fencing.locator('[name=user'+i+']').fill('samba-fence');
    await fencing.locator('[name=pass'+i+']').fill('fixture-pass');
  }
  await page.getByLabel('Разрешаю поочерёдное отключение узлов').check();
  await screenshot(page, '03-fencing.png');
  await page.getByRole('button', {name: 'Проверить fencing'}).click();

  await page.getByRole('heading', {name: 'Проверка и развёртывание'}).waitFor();
  const deploy = page.locator('#fc-deploy');
  await deploy.locator('[name=workgroup]').fill('CORP');
  await deploy.locator('[name=controller]').fill('dc1.corp.example');
  await deploy.locator('[name=groupSID]').fill('S-1-5-21-1100-2200-3300-513');
  await deploy.locator('[name=username]').fill('deploy@corp.example');
  await deploy.locator('[name=password]').fill('fixture-join-pass');
  await deploy.locator('[name=confirm]').check();
  await screenshot(page, '04-deploy.png');
  await page.getByRole('button', {name: 'Развернуть кластер'}).click();
  await page.getByRole('heading', {name: 'files.corp.example', exact: true}).waitFor();
  await page.getByText('Активный', {exact: true}).waitFor();
  assert.equal(await page.locator('#fc-alert').isVisible(), false);
  console.log('PASS wizard through all steps, signed fixture helper pair, draft resumes after leaving wizard');
}

function labCommand(node, command, input) {
  const guests = JSON.parse(fs.readFileSync(path.join(lab, 'vms.json'), 'utf8'));
  const short = node.split('.')[0];
  assert.match(short, /^fs[12]$/);
  const guest = guests[short];
  assert.ok(guest);
  return execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=4',
    '-o', 'UserKnownHostsFile=' + path.join(lab, 'known_hosts'), '-i', path.join(lab, 'lab_ed25519'),
    '-p', String(guest.sshPort), 'root@127.0.0.1', 'test -f /etc/sambaadm-ha-lab && ' + command], {timeout: 30000, input});
}

async function runLive(page) {
  await page.getByText('Есть кворум', {exact: true}).waitFor({timeout: 30000});
  await page.getByText('Активный', {exact: true}).waitFor();
  await page.getByText('Резервный', {exact: true}).waitFor();
  const hasMaps = page.getByText('2 из 2 путей', {exact: true});
  await hasMaps.first().waitFor();
  assert.equal(await hasMaps.count(), 2);
  await screenshot(page, '05-status.png');
  if (process.env.SAMBAADM_CLUSTER_BROWSER_DEGRADE === '1') {
    const reserve = await page.locator('.fc-node').filter({hasText: 'Резервный'}).locator('h3').textContent();
    const ssh = shell => labCommand(reserve, shell);
    const port = lab.endsWith('-p10') ? 3261 : 3260;
    const session = 'iscsiadm -m node -T iqn.2026-11.test.sambaadm:ha -p 10.0.3.2:' + port;
    try {
      ssh(session + ' --logout');
      await page.getByRole('button', {name: 'Обновить', exact:true}).click();
      await page.getByText('1 из 2 путей', {exact: true}).waitFor({timeout: 20000});
      await page.getByText('Нет пути', {exact: true}).waitFor();
      await screenshot(page, '05b-path-loss.png');
    } finally {
      ssh(session + ' --login');
      await page.getByRole('button', {name: 'Обновить', exact:true}).click();
    }
    await page.waitForFunction(() => [...document.querySelectorAll('.fc-map .fc-pill')].filter(el => el.textContent === '2 из 2 путей').length === 2);
    console.log('PASS reserve-node path loss and reconnection reflected in browser');
  }
  await page.getByRole('button', {name: 'Снимки', exact: true}).click();
  await page.getByText('До отключения активного узла', {exact: true}).first().waitFor();
  if (process.env.SAMBAADM_CLUSTER_BROWSER_SNAPSHOT === '1') {
    const label = 'Проверка снимка из панели ' + new Date().toISOString().slice(11,19);
    await page.getByRole('button', {name: 'Создать снимок', exact: true}).click();
    await page.getByLabel('Имя снимка', {exact: true}).fill(label);
    await page.getByRole('dialog').getByRole('button', {name: 'Создать', exact: true}).click();
    await page.getByText(label, {exact:true}).waitFor();
    console.log('PASS named snapshot created and read back through live helper API');
  }
  if (process.env.SAMBAADM_CLUSTER_BROWSER_SCHEDULE === '1') await runSchedule(page);
  if (process.env.SAMBAADM_CLUSTER_BROWSER_RESTORE === '1') await runRestore(page);
  await screenshot(page, '06-snapshots.png');
  await page.setViewportSize({width: 390, height: 870});
  await page.getByRole('button', {name: 'Состояние', exact: true}).click();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await screenshot(page, '07-mobile.png', true);
  console.log('PASS live cluster discovery, two nodes, quorum, both multipath maps and snapshots');
}

async function runRestore(page) {
  const cluster = lab.endsWith('-p10') ? 'files10' : 'files11';
  const active = await page.locator('.fc-node').filter({hasText: 'Активный'}).locator('h3').textContent();
  const reserve = await page.locator('.fc-node').filter({hasText: 'Резервный'}).locator('h3').textContent();
  const fixture = 'restore-ui-' + Date.now();
  const live = '/srv/samba-ha/' + cluster + '/data/' + fixture;
  const file = live + '/notes.txt';
  const sub = live + '/Договоры';
  const orig = 'before-snapshot';
  const metadata = path => labCommand(active,
    'stat -c "%u:%g:%a" ' + path + ' && getfacl -cpn ' + path).toString();
  labCommand(active, `mountpoint -q /srv/samba-ha/${cluster}/data && mkdir -m 0700 ${live} && chown 0:1000513 ${live} &&
    setfacl -m u:1000500:r-x,d:u:1000500:r-x ${live} &&
    mkdir ${sub} && chown 0:1000513 ${sub} && chmod g+s ${sub} &&
    printf %s ${orig} > ${file} && chown 0:1000513 ${file} && setfacl -m u:1000500:r-- ${file} &&
    setfattr -n user.sambaadm-check -v original ${file} &&
    printf %s recreated > ${sub}/recreated.txt`);
  const fileACL = metadata(file), dirACL = metadata(live), subACL = metadata(sub);
  const label = 'До изменения документов ' + fixture.split('-').at(-1);
  await page.getByRole('button', {name: 'Создать снимок', exact: true}).click();
  await page.getByLabel('Имя снимка', {exact: true}).fill(label);
  await page.getByRole('dialog').getByRole('button', {name: 'Создать', exact: true}).click();
  const row = page.locator('.fc-snapshot-row').filter({hasText: label});
  await row.waitFor();

  labCommand(active, `printf %s changed > ${file} && chmod 0600 ${file} && setfacl -b ${file} &&
    setfattr -n user.sambaadm-check -v changed ${file} && rm ${sub}/recreated.txt &&
    printf %s keep-live > ${live}/extra.txt && setfacl -b -k ${live} && chmod 0700 ${live} &&
    setfacl -b -k ${sub} && chmod 0700 ${sub}`);

  const dialog = page.getByRole('dialog', {name:'Восстановить из снимка'});
  const preview = dialog.getByRole('button',{name:'Предпросмотр',exact:true});
  const overwrite = dialog.locator('#fc-restore-overwrite');
  const confirm = dialog.locator('#fc-restore-confirm');
  const apply = dialog.getByRole('button',{name:'Восстановить',exact:true});
  const change = dialog.getByRole('button',{name:'Изменить выбор',exact:true});
  const open = async () => {
    await row.locator('summary').click();
    await row.getByRole('button',{name:'Восстановить из снимка',exact:true}).click();
    await dialog.getByRole('button',{name:fixture,exact:true}).waitFor();
  };

  await open();
  await dialog.getByRole('button',{name:'Открыть папку '+fixture,exact:true}).click();
  await dialog.getByRole('button',{name:'notes.txt',exact:true}).click();
  await preview.click();
  await dialog.getByText('Пропустить · 1',{exact:true}).waitFor();
  assert.equal(await apply.isEnabled(),false);
  await change.click();
  await overwrite.check();
  await preview.click();
  await dialog.getByText('Перезаписать · 1',{exact:true}).waitFor();
  labCommand(active, `printf %s changed-after-preview > ${file}`);
  await confirm.check();
  await apply.click();
  await dialog.getByText('Данные изменились. Сформируйте новый предпросмотр.',{exact:true}).waitFor();
  assert.equal(labCommand(active, 'cat ' + file).toString(), 'changed-after-preview');
  await change.click();
  await preview.click();
  await dialog.getByText('Перезаписать · 1',{exact:true}).waitFor();
  await confirm.check();
  await apply.click();
  await dialog.getByText(/Восстановление завершено/).waitFor();
  assert.equal(labCommand(active, 'cat ' + file).toString(), orig);
  assert.equal(metadata(file),fileACL);
  assert.equal(labCommand(active, 'getfattr --only-values -n user.sambaadm-check ' + file + ' 2>/dev/null').toString(),'original');
  await dialog.getByRole('button',{name:'Закрыть',exact:true}).click();

  await open();
  await dialog.getByRole('button',{name:fixture,exact:true}).click();
  await overwrite.check();
  await preview.click();
  await dialog.getByText('Создать · 1',{exact:true}).waitFor();
  await dialog.getByText('Вернуть права папки · 2',{exact:true}).waitFor();
  await screenshot(page,'10-restore-preview.png');
  await confirm.check();
  await apply.click();
  await dialog.getByText(/Восстановление завершено/).waitFor();
  assert.equal(metadata(live),dirACL);
  assert.equal(metadata(sub),subACL);
  assert.equal(metadata(file),fileACL);
  assert.equal(labCommand(active, 'cat '+sub+'/recreated.txt').toString(),'recreated');
  assert.equal(labCommand(active, 'cat '+live+'/extra.txt').toString(),'keep-live');
  const readSMB = (user, password) => labCommand(reserve,
    `umask 077 && auth=$(mktemp) && trap 'rm -f "$auth"' EXIT && cat >"$auth" &&
     smbclient //${cluster}.sambaadm.test/files -I 10.77.0.50 -A "$auth" --client-protection=sign -c 'get ${fixture}/notes.txt -'`,
    'username = '+user+'\npassword = '+password+'\ndomain = SAMBAADM\n').toString();
  assert.ok(readSMB('Administrator',process.env.SAMBAADM_LAB_DOMAIN_PASSWORD).includes(orig));
  assert.throws(() => readSMB('hadenied',process.env.SAMBAADM_LAB_DENIED_PASSWORD), error => {
    assert.match(String(error.stdout || '') + String(error.stderr || ''), /NT_STATUS_ACCESS_DENIED/);
    return true;
  });
  await dialog.getByRole('button',{name:'Закрыть',exact:true}).click();
  console.log('PASS browser restore: stale preview refused, file and merged folder restored with POSIX/default ACL, UID/GID, mode, xattr and signed SMB access enforcement');
}

async function runSchedule(page) {
  const label = page.locator('#fc-schedule-summary');
  const original = await label.textContent();
  assert.equal(original, 'Автоснимки выключены', 'use a disposable cluster with auto snapshots disabled');
  const before = await page.locator('.fc-auto-label').count();
  const auto = page.getByRole('button', {name: 'Автоснимки', exact: true});
  const dialog = page.getByRole('dialog', {name: 'Автоснимки', exact: true});
  const enabled = dialog.getByLabel('Включить расписание');
  const save = dialog.getByRole('button', {name: 'Сохранить', exact: true});
  await auto.click();
  await enabled.check();
  await dialog.locator('[name=intervalMinutes]').selectOption('360');
  await dialog.getByLabel('Хранить последних', {exact: true}).fill('7');
  await screenshot(page, '08-autosnapshots.png');
  await save.click();
  try {
    await dialog.waitFor({state: 'hidden', timeout: 40000}).catch(async err => {
      console.log(await dialog.innerText()); throw err;
    });
    await page.getByText('Каждые 6 часов · хранить 7', {exact: true}).waitFor();
    if (process.env.SAMBAADM_CLUSTER_BROWSER_SWITCHOWNER === '1') {
      // A prior timer test left one automatic snapshot in the current slot.
      // Planned migration confirms that the other timer sees the same policy.
      assert.ok(before > 0);
      await page.getByRole('button', {name:'Состояние',exact:true}).click();
      const rows = page.locator('.fc-node');
      const owner = await rows.filter({hasText:'Активный'}).locator('h3').textContent();
      const reserve = await rows.filter({hasText:'Резервный'}).locator('h3').textContent();
      assert.match(owner, /^fs[12]\.sambaadm\.test$/);
      const standby = 'crm_standby --node ' + owner + ' --update ';
      const cluster = lab.endsWith('-p10') ? 'files10' : 'files11';
      try {
        labCommand(reserve, standby + 'on');
        await rows.filter({hasText:reserve}).getByText('Активный',{exact:true}).waitFor({timeout:60000});
        await page.getByRole('button', {name:'Снимки',exact:true}).click();
        await page.getByText('Каждые 6 часов · хранить 7',{exact:true}).waitFor();
        labCommand(reserve, 'systemctl start sambaadm-' + cluster + '-snapshots.service');
        await page.getByRole('button',{name:'Обновить',exact:true}).click();
        await page.getByText('Каждые 6 часов · хранить 7',{exact:true}).waitFor();
        assert.equal(await page.locator('.fc-auto-label').count(),before);
        console.log('PASS shared schedule and no duplicate snapshot after active node changed');
      } finally { labCommand(reserve, standby + 'off'); }
    } else {
      // Observe a real timer tick without starting the oneshot manually.
      await page.waitForFunction(previous => document.querySelectorAll('.fc-auto-label').length > previous, before, {timeout: 100000});
    }
    await page.getByText('До отключения активного узла', {exact: true}).first().waitFor();
    const row = page.locator('.fc-snapshot-row').filter({has: page.locator('.fc-auto-label')}).first();
    await row.locator('summary').click();
    await screenshot(page, '09-snapshot-menu.png');
    await row.getByRole('button', {name: 'Сведения', exact: true}).click();
    const info = page.getByRole('dialog', {name: 'Сведения о снимке'});
    assert.match(await info.getByLabel('Путь к предыдущей версии по SMB').inputValue(), /files.*@GMT-/);
    await info.getByRole('button', {name: 'Закрыть', exact: true}).click();
    console.log('PASS persisted schedule, automatic and manual snapshots, SMB path menu');
  } finally {
    if (await dialog.isVisible()) {
      if (await save.isEnabled()) await dialog.getByRole('button', {name:'Отмена'}).click();
    }
    if (!(await dialog.isVisible()) && await label.textContent() !== original) {
      await auto.click();
      await enabled.uncheck();
      await save.click();
      await dialog.waitFor({state:'hidden',timeout:40000});
      await page.getByText(original, {exact: true}).waitFor();
    }
  }
}

async function checkViewer(browser, info, role, clusterPath = '/file-clusters') {
  const context = await browser.newContext({viewport: {width: 1440, height: 900}, locale: 'ru-RU'});
  try {
    await context.addCookies([{name: 'sambaadm_session', value: info[role], url: info.url}]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(info.url + clusterPath);
    await page.locator('#fc-status').getByText('Активный', {exact: true}).waitFor();
    await page.getByRole('button', {name: 'Снимки', exact: true}).click();
    assert.equal(await page.locator('#fc-setup, #fc-drafts, #fc-new, #fc-new-snapshot, #fc-edit-schedule, #fc-restore-dialog').count(), 0);
    const menu = page.locator('.fc-snapshot-row .compact-action-menu').first();
    await menu.locator('summary').click();
    assert.equal(await menu.getByRole('button', {name: 'Восстановить из снимка'}).count(), 0);
    assert.equal(await menu.getByRole('button', {name: 'Копировать SMB-путь'}).count(), 1);
    if (role === 'readonly' && dashboardOnly) await screenshot(page, 'file-cluster-readonly.png');
    await page.keyboard.press('Escape');
    assert.equal(await menu.evaluate(node => node.open), false);
    assert.equal(await menu.locator('summary').evaluate(node => node === document.activeElement), true);
    await menu.locator('summary').click();
    await menu.getByRole('button', {name: 'Сведения'}).click();
    await page.getByRole('dialog', {name: 'Сведения о снимке'}).waitFor();
    assert.deepEqual(errors, []);
  } finally { await context.close(); }
}

function redfish(node, reset) {
  return new Promise((resolve, reject) => {
    const short = node.split('.')[0];
    assert.match(short, /^fs[12]$/);
    const basePath = '/redfish/v1/Systems/' + short;
    const body = reset ? JSON.stringify({ResetType: reset}) : undefined;
    const request = https.request({
      hostname: '127.0.0.1',
      port: fs.realpathSync(lab).endsWith('-p10') ? 18082 : 18081,
      ca: fs.readFileSync(path.join(lab, 'power.crt')),
      auth: 'lab:' + fs.readFileSync(path.join(lab, 'power.secret'), 'utf8').trim(),
      path: basePath + (reset ? '/Actions/ComputerSystem.Reset' : ''),
      method: reset ? 'POST' : 'GET',
      headers: reset ? {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)} : {},
      timeout: 18000
    }, res => {
      let result = '';
      res.on('data', chunk => { result += chunk; });
      res.on('end', () => {
        if (res.statusCode !== (reset ? 204 : 200)) return reject(Error('Redfish returned '+res.statusCode));
        resolve(reset ? null : JSON.parse(result).PowerState);
      });
    });
    request.on('timeout', () => request.destroy(Error('Redfish timed out')));
    request.on('error', reject);
    request.end(body);
  });
}

async function runDashboardFailover(page, info, recoveryOnly = false) {
  const dashboard = page.locator('#dashboard-services');
  const refresh = page.getByRole('button', {name: 'Обновить службы', exact: true});
  const isOverview = response => new URL(response.url()).pathname === '/api/v1/services/overview';
  async function collect(start) {
    const pending = page.waitForResponse(isOverview, {timeout: 20000});
    if (start) await page.goto(info.url);
    else await refresh.click();
    const response = await pending;
    assert.equal(response.status(), 200);
    const result = await response.json();
    await page.waitForFunction(() => !document.getElementById('service-overview-refresh').disabled);
    return result;
  }
  const row = node => dashboard.locator('tbody tr').filter({has: page.getByRole('button', {name: node, exact: true})});
  const lease = (data, node, serving, state) => ['dhcp4','dhcp6'].every(id => {
    const unit = data.servers.find(host => host.name === node)?.services.find(unit => unit.id === id);
    return unit?.state === 'active' && unit.dhcp?.source === 'runtime' &&
      !['failed','retrying'].includes(unit.dhcp.socketState) &&
      unit.dhcp.relationships?.some(ha => ha.state === state && ha.serving === serving &&
        (state !== 'hot-standby' || (ha.inTouch === true && ha.interrupted !== true && ha.peerState === state)));
  });
  async function shot(name) {
    if (!output) return;
    fs.mkdirSync(output, {recursive: true});
    await page.evaluate(() => document.fonts.ready);
    const box = await dashboard.boundingBox();
    await page.screenshot({path: path.join(output, name), animations: 'disabled',
      clip: {x: 0, y: 0, width: page.viewportSize().width, height: Math.ceil(box.y+box.height+18)}});
  }
  function testLeases(node) {
    const ip = node.startsWith('fs1.') ? 11 : 12;
    const test = fs.readFileSync(path.join(repo, 'testdata/kea/lab-client.py'));
    console.log(labCommand(node, 'ip netns exec sambaadm-dhcp python3 - '+ip, test).toString().trim());
  }
  if (recoveryOnly) {
    const data = await collect(true);
    const cluster = data.clusters.find(cluster => cluster.state === 'active' && cluster.quorum);
    assert.ok(cluster && data.servers.filter(server => server.helper === 'online').length === 2, JSON.stringify(data));
    const primary = cluster.nodes.find(node => lease(data, node.name, true, 'hot-standby'));
    const standby = cluster.nodes.find(node => lease(data, node.name, false, 'hot-standby'));
    assert.ok(primary && standby, JSON.stringify(data.servers));
    await row(primary.name).getByText('DHCPv4/v6 · активен').waitFor();
    await row(standby.name).getByText('DHCPv4/v6 · резерв').waitFor();
    await shot('04-recovered.png');
    console.log('Both helpers restored; DHCP active on', primary.name, 'SMB active on', cluster.owner);
    return;
  }
  const baseline = await collect(true);
  const primary = baseline.clusters.find(cluster => cluster.state === 'active' && cluster.quorum);
  assert.ok(primary?.owner, JSON.stringify(baseline));
  const {owner, key, name} = primary;
  const reserve = primary.nodes.find(node => node.name !== owner).name;
  assert.ok(lease(baseline, owner, true, 'hot-standby'), 'The initial SMB owner must also serve DHCP');
  assert.ok(lease(baseline, reserve, false, 'hot-standby'), 'Kea reserve not ready');
  assert.equal(await redfish(owner), 'On');
  assert.equal(await redfish(reserve), 'On');
  await row(owner).getByText('DHCPv4/v6 · активен').waitFor();
  await row(reserve).getByText('DHCPv4/v6 · резерв').waitFor();
  await shot('01-before.png');
  testLeases(owner);
  console.log('Before power off', name, 'SMB and DHCP', owner);

  let dhcpSeconds, smbSeconds;
  const started = Date.now();
  let recoveryNeeded = true;
  try {
    await redfish(owner, 'ForceOff');
    assert.equal(await redfish(owner), 'Off', 'QEMU guest must be powered off');
    let live;
    for (;;) {
      const data = await collect();
      const cluster = data.clusters.find(cluster => cluster.key === key);
      const down = data.servers.find(server => server.name === owner && server.helper === 'unavailable');
      const dhcpReady = lease(data, reserve, true, 'partner-down');
      const smbReady = cluster?.owner === reserve && cluster.quorum;
      if (down && dhcpReady && dhcpSeconds == null) {
        dhcpSeconds = Math.round((Date.now()-started)/1000);
        await row(owner).getByText('Нет связи', {exact:true}).waitFor();
        await row(reserve).getByText('DHCPv4/v6 · обслуживает за пару').waitFor();
        await shot('02-node-off.png');
        testLeases(reserve);
      }
      if (smbReady && smbSeconds == null) smbSeconds = Math.round((Date.now()-started)/1000);
      if (down && dhcpReady && smbReady) {
        live = cluster;
        break;
      }
      assert.ok(Date.now()-started < 115000, JSON.stringify({cluster, dhcpReady, smbReady, down: !!down}));
      await time(1250);
    }
    assert.equal(await redfish(owner), 'Off');
    assert.equal(live.state, 'degraded');
    await row(reserve).getByText('SMB · активен, без полного резерва').waitFor();
    await shot('03-failover.png');
    assert.match(name, /^files1[01]\.sambaadm\.test$/);
    const unit = 'sambaadm-'+name.split('.')[0]+'-smb';
    labCommand(reserve, 'systemctl is-active --quiet '+unit+' && ip -4 addr show | grep -q "inet 10\\.77\\.0\\.50/"');
    console.log('Guest off, DHCP and SMB moved to', reserve, 'reported after', dhcpSeconds, 's and', smbSeconds, 's');
    await redfish(owner, 'On');
    recoveryNeeded = false;
    const wake = Date.now();
    for (;;) {
      const data = await collect();
      const cluster = data.clusters.find(cluster => cluster.key === key);
      if (data.servers.filter(server => server.helper === 'online').length === 2 &&
          lease(data, owner, true, 'hot-standby') && lease(data, reserve, false, 'hot-standby') &&
          cluster?.state === 'active') {
        await row(owner).getByText('DHCPv4/v6 · активен').waitFor();
        await shot('04-recovered.png');
        console.log('Recovered:', name, 'SMB owner', cluster.owner, 'DHCP primary', owner,
          'multipath', cluster.nodes.map(node => node.readyPaths + '/' + node.totalPaths).join(', '));
        break;
      }
      assert.ok(Date.now()-wake < 100000, 'Recovery timed out: '+JSON.stringify({cluster, servers: data.servers}));
      await time(1500);
    }
  } finally {
    if (recoveryNeeded || await redfish(owner) === 'Off') await redfish(owner, 'On');
  }
}

async function runHAHistory(page, info, verifyNotifications = false, verifyMail = false) {
  const source = info.url + '/api/v1/services/';
  const api = async path => {
    const result = await page.request.get(source + path);
    assert.equal(result.status(), 200);
    return result.json();
  };
  const baseline = await api('overview');
  const cluster = baseline.clusters.find(item => item.state === 'active' && item.owner);
  assert.ok(cluster, JSON.stringify(baseline));
  const owner = cluster.owner, reserve = cluster.nodes.find(node => node.name !== owner).name;
  const ha = (node, kind) => baseline.servers.find(server => server.name === node)?.services
    .find(unit => unit.id === kind)?.dhcp?.relationships?.[0];
  const ids = {smb: cluster.key};
  for (const kind of ['dhcp4','dhcp6']) {
    const primary = ha(owner, kind), standby = ha(reserve, kind);
    assert.ok(primary?.pairID && primary.state === 'hot-standby' && primary.serving, JSON.stringify(primary));
    assert.ok(standby?.pairID === primary.pairID && standby.state === 'hot-standby' && !standby.serving, JSON.stringify(standby));
    ids[kind] = primary.pairID;
  }
  const entries = Object.entries(ids);
  const history = ([kind,id]) => api('ha-history?' + new URLSearchParams({kind,id}));
  const initial = await Promise.all(entries.map(history));
  assert.ok(initial.every(value => value.since && value.events.length === 0));
  if (verifyNotifications) assert.deepEqual(await api('ha-notifications'), {items:[], unread:0});
  const mailRoutes = [
    {address:'ops@ha.invalid', events:['node-down','smb-moved','dhcp-moved','reserve-restored']},
    {address:'dhcp@ha.invalid', events:['dhcp-moved']},
    {address:'reserve@ha.invalid', events:['reserve-restored']}
  ];
  const eventNames = {
    'node-down':'Потеря узла', 'smb-moved':'Переключение SMB',
    'dhcp-moved':'Переключение DHCP', 'reserve-restored':'Восстановление резерва'
  };
  async function capturedMail() {
    const result = await page.request.get(info.url + '/__ha_mail_test_sink');
    assert.equal(result.status(), 200);
    return result.json();
  }
  const mailKeys = feed => feed.items.flatMap(item => {
    const type = item.type === 'service-moved'
      ? (item.sources.some(source => source.kind === 'smb') ? 'smb-moved' : 'dhcp-moved') : item.type;
    return mailRoutes.filter(route => route.events.includes(type)).map(route => {
      const hash = createHash('sha256').update(JSON.stringify([item.id, route.address])).digest('hex');
      return route.address + ' <' + hash + '@ha.invalid>';
    });
  }).sort();
  const receivedKeys = messages => messages.map(mail => mail.to+' '+mail.messageID).sort();
  async function waitMail(feed) {
    const expected = mailKeys(feed);
    const deadline = Date.now()+30000;
    for (;;) {
      const messages = await capturedMail();
      assert.ok(messages.length <= expected.length, JSON.stringify(receivedKeys(messages)));
      if (messages.length === expected.length) {
        assert.deepEqual(receivedKeys(messages), expected);
        assert.ok(messages.every(mail => mail.subject.startsWith('Samba Admin') && mail.body.includes('Подтверждено панелью')));
        return messages;
      }
      assert.ok(Date.now()<deadline, 'SMTP capture timed out: '+JSON.stringify(await api('ha-mail')));
      await time(800);
    }
  }
  if (verifyMail) {
    await page.goto(info.url + '/settings/ha-mail');
    await page.getByLabel('SMTP-сервер').fill('127.0.0.1');
    await page.getByLabel('Подключение').selectOption('local');
    await page.getByLabel('Порт', {exact:true}).fill(String(info.smtpPort));
    await page.getByLabel('Отправитель').fill('monitor@ha.invalid');
    for (const route of mailRoutes) {
      await page.getByRole('button', {name:'Добавить получателя'}).click();
      const row = page.locator('.ha-mail-recipient').last();
      await row.getByLabel('Адрес', {exact:true}).fill(route.address);
      for (const [event,label] of Object.entries(eventNames)) {
        if (!route.events.includes(event)) await row.getByRole('checkbox', {name:label, exact:true}).uncheck();
      }
    }
    await page.getByRole('checkbox', {name:'Отправлять уведомления'}).check();
    await page.getByRole('button', {name:'Сохранить настройки'}).click();
    await page.getByText('Настройки сохранены.', {exact:true}).waitFor();
    const settings = await api('ha-mail');
    assert.deepEqual(settings.config.recipients, mailRoutes.map(route => ({address:route.address,events:[...route.events].sort()}))
      .sort((a,b) => a.address.localeCompare(b.address)));
    assert.deepEqual(await capturedMail(), []);
    await page.goto('about:blank');
  }
  const descriptors = ([kind]) => kind === 'smb' ? [owner,reserve] : [ha(owner,kind).name,ha(reserve,kind).name];
  const testLeases = node => {
    const ip = node.startsWith('fs1.') ? 11 : 12;
    const test = fs.readFileSync(path.join(repo, 'testdata/kea/lab-client.py'));
    console.log(labCommand(node, 'ip netns exec sambaadm-dhcp python3 - '+ip, test).toString().trim());
  };
  async function waitHistory(check, timeout) {
    const deadline = Date.now() + timeout;
    do {
      const contents = await Promise.all(entries.map(history));
      if (contents.every((value,index) => check(value.events, entries[index]))) return contents;
      if (Date.now() > deadline) throw Error('History incomplete: '+JSON.stringify(contents));
      await time(1700);
    } while (true);
  }
  async function assertStableFeed(restored) {
    const original = await api('ha-notifications');
    const ids = original.items.map(item => item.id);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal(original.unread, ids.length);
    const lost = original.items.filter(item => item.type === 'node-down');
    assert.equal(lost.length, 1, JSON.stringify(original));
    assert.equal(lost[0].node, owner);
    assert.deepEqual(lost[0].sources.map(entry => entry.kind).sort(), ['dhcp4','dhcp6','smb']);
    const assertSourcesOnce = (type, predicate=(item)=>true) => assert.deepEqual(
      original.items.filter(item => item.type === type && predicate(item)).flatMap(item => item.sources.map(entry => entry.kind)).sort(),
      ['dhcp4','dhcp6','smb']);
    assertSourcesOnce('service-moved', item => item.previous.includes(owner) && item.serving.includes(reserve));
    if (restored) assertSourcesOnce('reserve-restored');
    const mailBefore = verifyMail ? await waitMail(original) : null;
    for (let round = 0; round < 3; round++) {
      const [, left, right] = await Promise.all([api('overview'), api('ha-notifications'), api('ha-notifications')]);
      assert.deepEqual(left, original);
      assert.deepEqual(right, original);
      if (round === 1) await time(11000);
    }
    console.log('Stable notifications through concurrent and background polls:', ids.length, restored ? 'recovered' : 'node off');
    if (verifyMail) {
      assert.deepEqual(await capturedMail(), mailBefore);
      const status = await api('ha-mail');
      assert.equal(status.counts.sent, mailBefore.length);
      console.log('SMTP receipts after repeated polls:', mailBefore.length, restored ? 'recovered' : 'node off');
    }
    return original;
  }
  assert.equal(await redfish(owner), 'On');
  assert.equal(await redfish(reserve), 'On');
  const started = Date.now();
  try {
    await redfish(owner, 'ForceOff');
    assert.equal(await redfish(owner), 'Off');
    await waitHistory((events, entry) => {
      const [from,to] = descriptors(entry);
      return events.some(e => e.type === 'node-down' && e.node === from) &&
        events.some(e => e.type === 'service-moved' && e.previous?.includes(from) && e.serving?.includes(to));
    }, 115000);
    testLeases(reserve);
    assert.match(cluster.name, /^files1[01]\.sambaadm\.test$/);
    labCommand(reserve, 'systemctl is-active --quiet sambaadm-'+cluster.name.split('.')[0]+'-smb');
    assert.equal(await redfish(owner), 'Off');
    console.log('History recorded real node loss and takeover with dashboard closed:', owner, '→', reserve);
    if (verifyNotifications) await assertStableFeed(false);
    await redfish(owner, 'On');
    const completed = await waitHistory((events, entry) => {
      const [from,to] = descriptors(entry);
      const serving = entry[0] === 'smb' ? to : from;
      return events.some(e => e.type === 'reserve-restored' && e.node === from && e.serving?.includes(serving));
    }, 115000);
    for (const [index, recorded] of completed.entries()) {
      assert.ok(recorded.events.every(event => Date.parse(event.at) >= started));
      console.log(entries[index][0], JSON.stringify(recorded.events));
    }
    if (verifyNotifications) {
      const expected = await assertStableFeed(true);
      await page.goto(info.url);
      const bell = page.locator('#ha-notification-bell');
      await bell.locator('.ha-notification-badge').waitFor();
      assert.equal(await bell.locator('.ha-notification-badge').textContent(), String(expected.items.length));
      await bell.click();
      const notifications = page.getByRole('dialog', {name:'Уведомления', exact:true});
      assert.deepEqual(await notifications.locator('[data-notification-id]').evaluateAll(rows =>
        rows.map(row => row.dataset.notificationId)), expected.items.map(item => item.id));
      await screenshot(page, 'ha-notifications.png');
      const read = notifications.getByRole('button', {name:'Отметить все прочитанными'});
      await read.click();
      await bell.locator('.ha-notification-badge').waitFor({state:'hidden'});
      assert.equal((await api('ha-notifications')).unread, 0);
      await notifications.getByRole('link', {name:'DHCPv4 HA', exact:true}).first().click();
      const details = page.locator('#service-overview-detail');
      await details.getByText('История переключений', {exact:true}).waitFor();
      await details.getByText('Резерв восстановлен', {exact:true}).waitFor();
      await details.getByRole('button', {name:'Закрыть', exact:true}).click();
      await page.reload();
      assert.equal((await api('ha-notifications')).unread, 0);
      if (verifyMail) {
        await page.goto(info.url + '/settings/ha-mail');
        await page.getByText('Принято SMTP · '+mailKeys(expected).length, {exact:true}).waitFor();
        await screenshot(page, 'ha-mail.png', true);
      }
      const other = await page.context().browser().newContext();
      try {
        await other.addCookies([{name:'sambaadm_session', value:info.helpdesk, url:info.url}]);
        const response = await other.request.get(source+'ha-notifications');
        assert.equal(response.status(), 200);
        assert.equal((await response.json()).unread, expected.items.length);
        if (verifyMail) assert.equal((await other.request.get(source+'ha-mail')).status(),403);
      } finally { await other.close(); }
      console.log('Bell order, history links, persistent acknowledgment and independent Helpdesk state verified');
      return;
    }
    await page.goto(info.url);
    const dialog = page.locator('#service-overview-detail');
    for (const [kind, label] of [['smb','Кластер SMB · '+cluster.name+' · '+reserve], ['dhcp4','DHCPv4 · '+reserve], ['dhcp6','DHCPv6 · '+reserve]]) {
      await page.getByRole('button', {name:label, exact:true}).click();
      await dialog.getByText('История переключений', {exact:true}).waitFor();
      await dialog.getByText('Узел недоступен', {exact:true}).waitFor();
      await dialog.getByText('Служба перешла', {exact:true}).first().waitFor();
      await dialog.getByText('Резерв восстановлен', {exact:true}).waitFor();
      await screenshot(page, 'history-'+kind+'.png');
      await dialog.getByRole('button', {name:'Закрыть', exact:true}).click();
    }
  } finally {
    if (await redfish(owner) === 'Off') await redfish(owner, 'On');
  }
}

async function checkLiveDashboard(page, info) {
  const response = await page.request.get(info.url + '/api/v1/services/overview');
  assert.equal(response.status(), 200);
  const {servers, clusters} = await response.json();
  assert.equal(servers.filter(s => s.helper === 'online').length, 2, JSON.stringify(servers));
  const cluster = clusters.find(c => c.owner && c.quorum);
  assert.ok(cluster, JSON.stringify(clusters));
  assert.ok(cluster.nodes.every(node => node.totalPaths > 0));
  console.log('PASS live service inventory:', cluster.name, cluster.state, 'owner', cluster.owner,
    'multipath', cluster.nodes.map(node => node.readyPaths + '/' + node.totalPaths).join(', '));
  await page.goto(info.url);
  await page.getByRole('heading', {name: 'Серверы и службы'}).waitFor();
  await page.locator('#service-overview-clusters').getByRole('link', {name: cluster.name}).waitFor();
  await screenshot(page, 'live-dashboard.png');
  await page.locator('#service-overview-clusters').getByRole('link', {name: cluster.name}).click();
  await page.locator('#fc-live-name').getByText(cluster.name, {exact: true}).waitFor();
  return '/file-clusters?cluster=' + encodeURIComponent(cluster.key);
}

(async () => {
  const info = await connection();
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 1010}, locale: 'ru-RU', timezoneId: 'Europe/Moscow'});
    await context.addCookies([{name: 'sambaadm_session', value: info.session, url: info.url}]);
    const page = await context.newPage();
    const failures = [];
    page.on('pageerror', error => failures.push(error.message));
    if (process.env.SAMBAADM_CLUSTER_BROWSER_DEBUG === '1') page.on('response', async response => {
      if (!response.url().includes('/api/v1/file-clusters')) return;
      const value = await response.json().catch(() => ({}));
      console.log(response.status(), new URL(response.url()).pathname, value.phase || '', value.action || '', value.error || '');
    });
    if (['history','notifications','mail'].includes(dashboardOnly) && lab) {
      await runHAHistory(page, info, dashboardOnly !== 'history', dashboardOnly === 'mail');
    } else if (['failover','recovered'].includes(dashboardOnly) && lab) {
      await runDashboardFailover(page, info, dashboardOnly === 'recovered');
    } else if (dashboardOnly && lab) {
      const clusterPath = await checkLiveDashboard(page, info);
      await checkViewer(browser, info, 'readonly', clusterPath);
      await checkViewer(browser, info, 'helpdesk', clusterPath);
    } else {
      await page.goto(info.url + '/file-clusters');
      if (lab) await runLive(page);
      else {
        await runWizard(page);
        await checkViewer(browser, info, 'readonly');
        await checkViewer(browser, info, 'helpdesk');
      }
    }
    assert.deepEqual(failures, []);
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  console.error(serverOutput);
  process.exitCode = 1;
}).finally(async () => {
  fs.writeFileSync(path.join(base, 'done'), '');
  const code = await exit;
  if (code) {console.error(serverOutput);process.exitCode = 1;}
  fs.rmSync(base, {recursive: true, force: true});
});
