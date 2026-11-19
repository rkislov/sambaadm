// Pure presentation models: imported facts are untrusted, never treated as execution plans.
function surveyStationModel(material, now = Date.now()) {
  const s = material.snapshot;
  if (!s || s.profile !== 'alt-workstation') return null;
  const checks = s.checks || [], w = s.workstation;
  const configs = w?.configs || [], dns = w?.dns || [];
  const rows = configs.flatMap(f => (f.settings || []).map(v => [f.path, f.status, v.section, v.key, v.value]));
  const warnings = [...(w?.warnings || [])];
  if (!w) warnings.push('Старый снимок без структурированной диагностики SSSD/Kerberos. Повторите сбор новой версией helper.');
  if (!dns.length) warnings.push('Проверки через заданные резолверы не выполнены. Задайте --dns-resolvers и --dns-queries при сборе.');
  for (const f of configs) for (const issue of f.issues || []) warnings.push(f.path + ' · ' + issue);
  const settings=configs.filter(f=>f.status==='observed').flatMap(f=>f.settings || []);
  if (settings.some(v=>v.section.startsWith('realms/') && v.key==='kdc')) warnings.push('В [realms] наблюдаются явные KDC. Наличие DNS SRV и dns_lookup_kdc само по себе не подтверждает их использование; проверьте locator и трассу входа.');
  if (settings.some(v=>v.key==='ad_enable_dns_sites' && v.value.toLowerCase()==='false')) warnings.push('Обнаружение по сайтам отключено в одном из файлов SSSD. Проверьте итоговый профиль и порядок включений.');
  const endpoints=checks.filter(c=>c.source.startsWith('sssctl domain-status ') || /\/(kdcinfo|kpasswdinfo)\./.test(c.source));
  const finished = Date.parse(s.finished), age = Number.isFinite(finished) ? Math.floor((now-finished)/60000) : null;
  if (age === null || age < 0) warnings.push('Часы источника требуют сверки: время завершения некорректно или находится в будущем.');
  else if (age > 1440) warnings.push('Снимок старше суток по часам панели; актуальность подтвердите перед испытанием.');
  return {rows,configs,dns,endpoints,warnings,age,observed: checks.filter(c=>c.status==='observed').length,total:checks.length};
}
function surveyStationValues(snapshot) {
  const out = new Map();
  for (const c of snapshot.checks || []) out.set('Проверка · '+c.source,{status:c.status,value:c.detail});
  for (const f of snapshot.workstation?.configs || []) {
    out.set('Файл · '+f.path,{status:f.status,value:[f.mode,f.owner].filter(Boolean).join(' ')});
    const groups = new Map();
    for (const s of f.settings || []) {
      const key='Параметр · '+JSON.stringify([f.path,s.section,s.key]);
      if (!groups.has(key)) groups.set(key,[]);
      groups.get(key).push(s.value);
    }
    for (const [key,values] of groups) {const parts=JSON.parse(key.slice('Параметр · '.length));out.set(key,{label:'Параметр · '+parts[0]+' · ['+parts[1]+'] '+parts[2],status:f.status,value:values.join('\n')});}
  }
  for (const q of snapshot.workstation?.dns || []) {
    // Keep transport and resolver separate; differing TTL alone is not a new DNS target.
    const key='DNS · '+JSON.stringify([q.resolver,q.name,q.type,q.transport]);
    const answers=(q.answers || []).map(a=>a.replace(/^(\S+)\s+\d+\s+/,'$1 ')).sort();
    out.set(key,{label:'DNS · '+q.resolver+' · '+q.name+' '+q.type+' / '+q.transport,status:q.status,value:q.rcode+'\n'+answers.join('\n')});
  }
  return out;
}
function surveyCompareStations(before, after) {
  const a=before.snapshot, b=after.snapshot;
  const norm=n=>String(n || '').trim().toLowerCase().replace(/\.$/,'');
  if (!a || !b || a.profile!=='alt-workstation' || b.profile!=='alt-workstation' || norm(a.node)!==norm(b.node)) {
    return {error:'Выберите два снимка рабочей станции с одинаковым FQDN.',rows:[]};
  }
  if (Date.parse(a.finished)>=Date.parse(b.finished)) return {error:'Исходный снимок должен быть старше текущего по времени источника. Проверьте часы и порядок снимков.',rows:[]};
  const av=surveyStationValues(a),bv=surveyStationValues(b),rows=[];
  for (const key of [...new Set([...av.keys(),...bv.keys()])].sort()) {
    const x=av.get(key),y=bv.get(key);
    if (!x || !y || x.status!=='observed' || y.status!=='observed') {
      rows.push([y?.label || x?.label || key,x?.value || 'Нет наблюдения',y?.value || 'Нет наблюдения','Нет достоверной пары; удаление не установлено']);
    } else if (x.value!==y.value) rows.push([y.label || x.label || key,x.value,y.value,'Изменение наблюдаемых данных']);
  }
  return {rows,warning:norm(a.site)!==norm(b.site)?'Метки площадок отличаются; проверьте принадлежность станции.':''};
}
