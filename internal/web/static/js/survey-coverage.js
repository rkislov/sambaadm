// Summarize each import while it is in memory; keep raw audit events out of the matrix.
function surveyCoverageInput(id, material) {
  const sections = material.overview?.sections || {};
  const inventory = sections.controllers;
  const evidence = [];
  function addAudit(node, site, audit, source, time) {
    evidence.push({id,node,site,source,time,status:audit?.status || 'unavailable',
      count:Array.isArray(audit?.events) ? audit.events.length : 0,
      partial:!!(audit?.malformed || audit?.truncated)});
  }
  if (material.snapshot && material.snapshot.profile !== 'alt-workstation') {
    const s = material.snapshot;
    evidence.push({id,node:s.node,site:s.site,source:'snapshot',time:s.finished});
    addAudit(s.node,s.site,s.audit,'snapshotAudit',s.finished);
  }
  if (material.audit) addAudit(material.node,material.site,material.audit,'log');
  for (const [name,section] of Object.entries(sections)) {
    if (name.startsWith('auth:')) {
      const audit = section.status === 'available' ? section.data : null;
      addAudit(name.slice(5),'',audit,'overviewAudit',section.finished);
    }
  }
  return {id,inventory,evidence};
}

function surveyCoverage(inputs, stamp) {
  const norm = value => typeof value === 'string' ? value.trim().toLowerCase().replace(/\.$/,'') : '';
  const newer = (a,b) => Date.parse(b.time)-Date.parse(a.time) || a.id.localeCompare(b.id);
  const inventories = inputs.filter(i=>i.inventory).map(i=>({...i,time:i.inventory.finished})).sort(newer);
  const base = inventories[0];
  const rows = [], warnings = new Set();
  const result = {rows,warnings,baseline:base ? stamp(base.time)+' · '+base.id.slice(0,12) : ''};
  if (base?.inventory.status !== 'available' || !Array.isArray(base.inventory.data) || !base.inventory.data.length) {
    warnings.add('Запросить JSON обзора домена с доступным непустым разделом «Контроллеры из LDAP». Охват определить невозможно.');
    return result;
  }
  const controllers = base.inventory.data.filter(dc=>norm(dc?.dns));
  if (controllers.length !== base.inventory.data.length) warnings.add('В LDAP-выгрузке есть строка без DNS-имени. Уточнить перечень контроллеров.');
  const evidenceByDC = new Map(controllers.map(dc=>[dc,[]]));
  for (const e of inputs.flatMap(i=>i.evidence)) {
    const name = norm(e.node);
    const matches = controllers.filter(dc=>norm(dc.dns)===name || (!name.includes('.') && norm(dc.dns).split('.')[0]===name));
    if (matches.length === 1) evidenceByDC.get(matches[0]).push(e);
    else warnings.add((e.node || 'Узел без имени')+' · '+e.id.slice(0,12)+' · уточнить FQDN и принадлежность к LDAP-перечню.');
  }
  for (const [dc,items] of evidenceByDC) {
    const actions = [];
    const site = norm(dc.site) ? dc.site : 'Площадка не указана';
    if (!norm(dc.site)) actions.push('Уточнить сайт DC в LDAP');
    if (typeof dc.rodc!=='boolean') actions.push('Уточнить роль DC');
    if (dc.site && items.some(e=>e.site && norm(e.site)!==norm(dc.site))) actions.push('Сверить метку площадки материала с LDAP');
    const snapshot = items.filter(e=>e.source==='snapshot').sort(newer)[0];
    if (!snapshot) actions.push('Запросить снимок sambaadm-helper collect');
    const audits = items.filter(e=>e.source==='log' || e.source==='overviewAudit' || (snapshot && e.source==='snapshotAudit' && e.id===snapshot.id));
    const auditText = audits.map(e=>{
      const status = e.partial || e.status==='partial' ? 'Частичная выборка' : e.status==='available' ? 'Источник доступен' : 'Источник недоступен';
      const source = {log:'Журнал',overviewAudit:'Обзор',snapshotAudit:'Снимок'}[e.source];
      return source+' '+e.id.slice(0,12)+' · '+status+(status==='Источник недоступен' ? '' : ' · событий: '+e.count);
    });
    if (!audits.length) actions.push('Запросить журнал Samba Authentication за период обследования');
    else if (!audits.some(e=>e.status==='available' && !e.partial)) {
      actions.push(audits.some(e=>e.partial || e.status==='partial') ? 'Запросить полную выгрузку журнала за период' : 'Проверить источник аудита и запросить журнал');
    }
    rows.push([site,dc.dns,typeof dc.rodc==='boolean' ? (dc.rodc?'RODC':'RWDC') : 'Неизвестна',
      snapshot ? stamp(snapshot.time)+' · '+snapshot.id.slice(0,12) : 'Отсутствует',
      auditText.join(' / ') || 'Отсутствует',actions.join('. ') || 'Оба вида материалов получены']);
  }
  rows.sort((a,b)=>a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  return result;
}
