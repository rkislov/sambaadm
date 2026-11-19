(() => {
  'use strict';
  const form = document.getElementById('survey-import'), list = document.getElementById('survey-list');
  const status = document.getElementById('survey-status'), view = document.getElementById('survey-view');
  let currentMaterial = null;
  const before = document.getElementById('survey-before'), diff = document.getElementById('survey-diff');
  const stamp = window.sambaadmFormatTime || (s => new Date(s).toLocaleString());
  const element = (name, text) => { const node = document.createElement(name); node.textContent = text; return node; };
  const endpoint = '/api/v1/surveys';
  async function request(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) { const message = await response.json().catch(() => ({})); throw Error(message.error || 'HTTP '+response.status); }
    return response.json();
  }
  function table(headers, rows, target = view) {
    const table = document.createElement('table'), head = table.createTHead().insertRow(), body = table.createTBody();
    headers.forEach(h => head.append(element('th', h)));
    rows.forEach(row => { const tr = body.insertRow(); row.forEach(v => tr.insertCell().append(element('span',v ?? '—'))); });
    const wrap=element('div','');wrap.className='survey-scroll';wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label',headers.join(', '));wrap.append(table);target.append(wrap);
  }
  async function show() {
    const id = list.value; currentMaterial=null; view.replaceChildren(); diff.replaceChildren(); if (!id) return;
    const item = await request(endpoint+'/'+id); if (list.value !== id) return;
    currentMaterial=item;
    if (item.imported) view.append(element('p','Получено панелью: '+stamp(item.imported)+'. Имя узла и часы источника указаны отправителем; SHA-256 не подтверждает автора.'));
    view.append(element('h2',item.node || 'Обзор домена'),element('p',(item.site || 'Площадка не указана')+' · SHA-256 исходного файла: '+item.sha256));
    if (item.snapshot) {
      const s = item.snapshot;
      view.append(element('p',(s.profile==='alt-workstation'?'Рабочая станция ALT · ':'')+s.helper+' · '+stamp(s.started)+' — '+stamp(s.finished)));
      const model=surveyStationModel(item);
      if (model) {
        view.append(element('h3','Карточка рабочей станции'),element('p','Наблюдений с данными: '+model.observed+' / '+model.total+'. Наличие данных не подтверждает успешный вход.'));
        for (const warning of model.warnings) view.append(element('p',warning));
        view.append(element('h3','SSSD и Kerberos · разрешённые параметры'));
        table(['Файл','Статус','Секция','Параметр','Значение'],model.rows);
        table(['Файл','Права','Владелец','Статус','Исключено назначений'],model.configs.map(f=>[f.path,f.mode,f.owner,f.status,f.omitted]));
        view.append(element('h3','Серверы SSSD и кандидаты locator'));
        if(model.endpoints.length)table(['Источник','Время','Статус','Наблюдение'],model.endpoints.map(o=>[o.source,stamp(o.observed),o.status,o.detail]));
        else view.append(element('p','Данные активных серверов SSSD и locator отсутствуют в этом снимке. Фактический KDC неизвестен.'));
        view.append(element('h3','DNS через каждый заданный резолвер'));
        table(['Резолвер','Имя / тип','Транспорт','Время наблюдения','Результат','Ответы с TTL','Длительность мс'],model.dns.map(q=>[q.resolver,q.name+' '+q.type,q.transport,stamp(q.observed),q.status+' · '+(q.rcode || 'Ответ не получен'),(q.answers || []).join(' / '),q.durationMs]));
        view.append(element('p','NXDOMAIN — наблюдаемый отрицательный ответ. Тайм-аут — неизвестность. SRV и locator содержат кандидатов; фактический KDC подтверждается отдельной трассой входа.'));
        const download=element('button','Скачать снимок станции');download.type='button';
        download.onclick=()=>{const blob=new Blob([JSON.stringify(s,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=element('a','');a.href=url;a.download='workstation-survey.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
        view.append(download);
      }
      const raw=document.createElement('details');raw.append(element('summary','Все исходные наблюдения'));view.append(raw);
      table(['Источник','Время наблюдения','Статус','Наблюдение'],s.checks.map(o=>[o.source,stamp(o.observed),o.status,o.detail]),raw);
    }
    if (item.overview) {
      view.append(element('p','Выгрузка обзора от '+stamp(item.overview.exported)));
      for (const [key,section] of Object.entries(item.overview.sections)) {
        const details = document.createElement('details');
        details.append(element('summary',key+' · '+section.status+' · '+stamp(section.finished)),element('pre',JSON.stringify(section.data ?? section.error,null,2)));view.append(details);
      }
      for (const key of ['checks','replication']) if (item.overview[key]) {
        const details=document.createElement('details');details.append(element('summary',key),element('pre',JSON.stringify(item.overview[key],null,2)));view.append(details);
      }
    }
    const audit = item.audit || item.snapshot?.audit;
    if (audit) {
      view.append(element('h3','Авторизации'),element('p',audit.source+' · '+audit.status+' · Ошибочных строк: '+audit.malformed+(audit.truncated?' · Выборка ограничена':'')),element('p',audit.warning));
      table(['Время события','Учётная запись','Клиент','Служба','Результат'],(audit.events || []).map(e=>[stamp(e.time),[e.domain,e.account].filter(Boolean).join('\\'),e.client,e.service,e.status]));
    }
  }
  const sources = document.getElementById('survey-sources'), report = document.getElementById('survey-report');
  const build = document.getElementById('survey-build');
  async function buildReport() {
    const ids = Array.from(sources.selectedOptions, option => option.value);
    report.replaceChildren();
    if (!ids.length) { report.textContent = 'Выберите хотя бы один материал.'; return; }
    build.disabled = true;
    const rows = [], latest = new Map(), gaps = new Set();
    const requiredSections = {domain:'Домен', controllers:'RWDC и RODC', fsmo:'FSMO', sites:'Сайты', subnets:'Подсети', links:'Связи сайтов', connections:'Соединения репликации', dns:'Зоны DNS'};
    const seen = new Set(), coverageInputs = [];
    const workstations = [];
    try {
      for (const id of ids) {
        const m = await request(endpoint+'/'+id);
        coverageInputs.push(surveyCoverageInput(id,m));
        const site = m.site || 'Площадка не указана', node = m.node || 'Источник не указан';
        const row = (source, time, result) => rows.push([site,node,source,time ? stamp(time) : '—',result,id.slice(0,12)]);
        if (m.snapshot) {
          const s = m.snapshot, key = JSON.stringify([site,node.toLowerCase()]);
          for (const o of s.checks) {
            if (s.profile==='alt-workstation') workstations.push([site,node,o.source,stamp(o.observed),o.status,o.detail]);
            else row(o.source,o.observed,o.status === 'observed' ? o.detail : o.status+' · '+o.detail);
            if (o.status !== 'observed') gaps.add(site+' / '+node+' · повторить проверку '+o.source);
          }
          const previous = latest.get(key);
          if (s.profile!=='alt-workstation' && (!previous || Date.parse(s.finished) > Date.parse(previous.finished))) {
            latest.set(key,{site,node,finished:s.finished,values:new Map(s.checks.filter(o=>o.status==='observed').map(o=>[o.source,o.detail]))});
          }
        }
        if (m.overview) {
          for (const [key,section] of Object.entries(m.overview.sections)) {
            row(requiredSections[key] || key,section.finished,section.status === 'available' ? 'Раздел получен' : 'Раздел недоступен');
            if (section.status === 'available') seen.add(key);
          }
        }
        const audit = m.audit || m.snapshot?.audit;
        if (audit) {
          row('Журнал авторизаций',m.snapshot?.finished,audit.status+' · событий в выборке: '+(audit.events || []).length);
        }
      }
      const coverage = surveyCoverage(coverageInputs,stamp);
      report.append(element('h3','Охват контроллеров по площадкам'));
      if (coverage.baseline) report.append(element('p','Перечень LDAP от '+coverage.baseline));
      for (const warning of coverage.warnings) report.append(element('p',warning));
      if (coverage.rows.length) table(['Площадка LDAP','Контроллер','Роль','Последний снимок','Авторизации в выборке','Что запросить'],coverage.rows,report);
      if (workstations.length) {
        report.append(element('h3','§2.3 · Рабочие станции ALT'));
        table(['Площадка','Станция','Источник','Время','Статус','Результат'],workstations,report);
      }
      rows.sort((a,b)=>a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
      report.append(element('h3','§2.2, §2.5 · Материалы обследования'));
      table(['Площадка','Узел','Проверка','Время наблюдения','Результат','Материал'],rows,report);
      for (const [key,label] of Object.entries(requiredSections)) {
        if (!seen.has(key)) gaps.add('Получить раздел обзора домена «'+label+'»');
      }
      if (!latest.size) gaps.add('Собрать локальные снимки контроллеров через helper');
      report.append(element('h3','Различия между последними снимками узлов'));
      const differences = [];
      for (const probe of ['samba --version','/etc/os-release','rpm -q chrony','rpm -q samba']) {
        const results = [...latest.values()].filter(s=>s.values.has(probe));
        if (new Set(results.map(s=>s.values.get(probe))).size > 1) {
          for (const s of results) differences.push([probe,s.site,s.node,s.values.get(probe),stamp(s.finished)]);
        }
      }
      if (differences.length) table(['Проверка','Площадка','Узел','Значение','Снимок'],differences,report);
      else report.append(element('p','По доступным парам наблюдений различий версий ОС, Samba и chrony не выявлено. Узлов со снимками: '+latest.size));
      report.append(element('h3','Что проверить дальше'));
      gaps.add('Сверить охват с перечнем площадок и DC заказчика. Подтвердить работоспособность репликации и состояние базы отдельными проверками.');
      if (!workstations.length) gaps.add('§2.3 · Проверить на рабочей станции выбор DC/DNS/KDC, локальный кэш, применение GPO и регистрацию DNS.');
      const ul = document.createElement('ul');
      for (const gap of gaps) ul.append(element('li',gap));
      report.append(ul);
    } catch (e) { report.textContent = 'Не удалось сформировать отчёт: '+e.message; }
    finally { build.disabled = false; }
  }
  build.onclick = buildReport;
  async function refresh(selected) {
    const entries = await request(endpoint); list.replaceChildren();
    entries.forEach(e => list.add(new Option(stamp(e.imported)+' · '+e.id.slice(0,12),e.id)));
    sources.replaceChildren(...Array.from(list.options, option => new Option(option.text,option.value)));
    before.replaceChildren(...Array.from(list.options, option => new Option(option.text,option.value)));
    if (selected) list.value = selected; await show();
  }
  function error(e) {status.textContent=e.message;}
  function fields(){const helper=form.elements.format.value==='helper';form.elements.node.disabled=helper;form.elements.site.disabled=helper;form.elements.node.required=form.elements.format.value==='audit';}
  form.elements.format.onchange=fields;fields();
  form.onsubmit=async event=>{
    event.preventDefault(); const file=form.elements.material.files[0];if (!file) return;
    if(file.size>16*1024*1024){error(Error('Размер файла превышает 16 МиБ'));return;}
    const button=form.querySelector('button');button.disabled=true;
    try{
      const q=new URLSearchParams({format:form.elements.format.value,node:form.elements.node.value,site:form.elements.site.value});
      const result=await request(endpoint+'?'+q,{method:'POST',body:file,headers:{'Content-Type':'application/octet-stream','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]').content}});
      await refresh(result.id);status.textContent='Материал доступен для просмотра.';
    } catch(e){error(e);} finally {button.disabled=false;}
  };
  document.getElementById('survey-compare').onclick=async()=>{
    diff.replaceChildren();const current=currentMaterial;
    if (!current || !before.value) {diff.textContent='Выберите текущий и исходный материалы.';return;}
    try {const old=await request(endpoint+'/'+before.value);if(current!==currentMaterial)return;
      const result=surveyCompareStations(old,current);
      if(result.error){diff.textContent=result.error;return;}
      if(result.warning)diff.append(element('p',result.warning));
      if(result.rows.length)table(['Источник / параметр','До','После','Вывод'],result.rows,diff);
      else diff.append(element('p','По доступным парным наблюдениям изменений не выявлено. Это не проверка работоспособности.'));
    }catch(e){diff.textContent=e.message;}
  };
  list.onchange=()=>show().catch(error); refresh().catch(error);
})();
