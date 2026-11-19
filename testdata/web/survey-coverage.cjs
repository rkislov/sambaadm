const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const api = vm.createContext({});
vm.runInContext(fs.readFileSync(path.resolve(__dirname,'../../internal/web/static/js/survey-coverage.js'),'utf8'),api);
const input = api.surveyCoverageInput;
const time = '2026-11-05T10:00:00Z';
const list = [
  {dns:'dc1.lab.test',site:'HQ',rodc:false},
  {dns:'dc2.lab.test',site:'Branch',rodc:true},
  {dns:'dc3.lab.test',site:'Branch',rodc:false}
];
const overview = input('inventory',{overview:{sections:{controllers:{finished:time,status:'available',data:list}}}});
const snapshot = input('snapshot',{snapshot:{node:'DC1.LAB.TEST.',site:'HQ',finished:time,audit:{status:'available',events:[]}}});
const audit = input('audit',{node:'dc2',site:'HQ',audit:{status:'partial',events:[{}],truncated:true}});
const generate = materials=>api.surveyCoverage(materials,t=>t);
const report = generate([overview,snapshot,audit]);
assert.equal(report.rows.length,3);
const row = name=>report.rows.find(r=>r[1]===name+'.lab.test');
assert.match(row('dc1')[4],/Источник доступен · событий: 0/);
assert.equal(row('dc1')[5],'Оба вида материалов получены');
assert.match(row('dc2')[5],/Сверить метку.*снимок.*полную выгрузку/);
assert.match(row('dc3')[5],/снимок.*журнал/);
assert.equal(generate([audit]).rows.length,0);
const unavailable = input('new',{overview:{sections:{controllers:{finished:'2026-11-06T10:00:00Z',status:'unavailable'}}}});
assert.equal(generate([overview,unavailable,snapshot]).rows.length,0);
list.push({dns:'dc2.other.test',site:'HQ',rodc:false});
assert.match([...generate([overview,audit]).warnings].join(' '),/уточнить FQDN/);
const workstation = input('workstation',{snapshot:{profile:'alt-workstation',node:'dc3.lab.test',site:'Branch',finished:time}});
assert.equal(workstation.evidence.length,0);
