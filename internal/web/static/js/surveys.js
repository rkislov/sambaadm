(() => {
  'use strict';
  const form = document.getElementById('survey-import'), list = document.getElementById('survey-list');
  const status = document.getElementById('survey-status'), view = document.getElementById('survey-view');
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
    target.append(table);
  }
  async function show() {
    const id = list.value; view.replaceChildren(); if (!id) return;
    const item = await request(endpoint+'/'+id); if (list.value !== id) return;
    view.append(element('h2',item.node || 'Обзор домена'),element('p',(item.site || 'Площадка не указана')+' · SHA-256 исходного файла: '+item.sha256));
    if (item.snapshot) {
      const s = item.snapshot;
      view.append(element('p',s.helper+' · '+stamp(s.started)+' — '+stamp(s.finished)));
      table(['Источник','Время наблюдения','Статус','Наблюдение'],s.checks.map(o=>[o.source,stamp(o.observed),o.status,o.detail]));
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
    const seen = new Set();
    try {
      for (const id of ids) {
        const m = await request(endpoint+'/'+id);
        const site = m.site || 'Площадка не указана', node = m.node || 'Источник не указан';
        const row = (source, time, result) => rows.push([site,node,source,time ? stamp(time) : '—',result,id.slice(0,12)]);
        if (m.snapshot) {
          const s = m.snapshot, key = JSON.stringify([site,node.toLowerCase()]);
          for (const o of s.checks) {
            row(o.source,o.observed,o.status === 'observed' ? o.detail : o.status+' · '+o.detail);
            if (o.status !== 'observed') gaps.add(site+' / '+node+' · повторить проверку '+o.source);
          }
          const previous = latest.get(key);
          if (!previous || Date.parse(s.finished) > Date.parse(previous.finished)) {
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
          if (audit.status !== 'available') gaps.add(site+' / '+node+' · проверить полноту журнала авторизаций');
        }
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
      gaps.add('§2.3 · Проверить на рабочей станции выбор DC/DNS/KDC, локальный кэш, применение GPO и регистрацию DNS.');
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
  list.onchange=()=>show().catch(error); refresh().catch(error);
})();
