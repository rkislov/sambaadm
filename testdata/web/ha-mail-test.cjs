const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
  const info = JSON.parse(fs.readFileSync(process.env.SAMBAADM_SMTP_BROWSER_INFO, 'utf8'));
  const url = process.env.SAMBAADM_SMTP_BROWSER_URL || info.url;
  const output = process.env.SAMBAADM_SMTP_SCREENSHOTS;
  if (output) fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({headless:true});
  try {
    const context = await browser.newContext({viewport:{width:1360,height:1000},locale:'ru-RU',timezoneId:'Europe/Moscow'});
    await context.addCookies([{name:'sambaadm_session',value:info.session,url}]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(url+'/settings/ha-mail');
    await page.getByLabel('SMTP-сервер').fill('127.0.0.1');
    await page.getByLabel('Подключение').selectOption('local');
    await page.getByLabel('Порт', {exact:true}).fill(String(info.smtpPort));
    await page.getByLabel('Отправитель').fill('monitor@ha.invalid');
    await page.getByRole('button',{name:'Добавить получателя'}).click();
    await page.locator('.ha-mail-recipient').last().getByLabel('Адрес',{exact:true}).fill('ops@ha.invalid');
    const recipient = page.getByLabel('Получатель тестового письма');
    await recipient.selectOption('ops@ha.invalid');
    const send = page.getByRole('button',{name:'Отправить тестовое письмо',exact:true});
    await send.click();
    await page.getByText('SMTP принял тестовое письмо для ops@ha.invalid.',{exact:true}).waitFor();
    if (output) await page.screenshot({path:path.join(output,'01-accepted.png')});
    await recipient.selectOption('other');
    await page.getByLabel('Другой адрес',{exact:true}).fill('reject@ha.invalid');
    await send.click();
    await page.getByText('SMTP отклонил получателя · SMTP 550',{exact:true}).waitFor();
    if (output) await page.screenshot({path:path.join(output,'02-rejected.png')});
    const captured = await (await page.request.get(url+'/__ha_mail_test_sink')).json();
    assert.equal(captured.length,1);
    assert.equal(captured[0].to,'ops@ha.invalid');
    assert.equal(captured[0].subject,'Samba Admin · Тестовое письмо');
    const settings = await (await page.request.get(url+'/api/v1/services/ha-mail')).json();
    assert.ok(!settings.config.enabled && !settings.config.host);
    assert.deepEqual(settings.counts,{});
    assert.deepEqual(errors,[]);
    console.log('PASS: test message with unsaved settings, actual SMTP acceptance, 550 shown, no changes to configuration or outbox');
  } finally {
    await browser.close();
  }
})().catch(error=>{console.error(error); process.exitCode=1;});
