(() => {
'use strict';
const $ = s => document.querySelector(s), consoleEl = $('.kea-console');
if (!consoleEl) return;
const server = $('#kea-server'), tree = $('#kea-tree'), panel = $('#kea-panel'), dialog = $('#kea-dialog'), dialogContent = $('#kea-dialog-content');
const initial = new URLSearchParams(location.search);
const selectedNode = [...server.options].find(option => option.value.toLowerCase() === initial.get('node')?.toLowerCase());
if (selectedNode) server.value = selectedNode.value;
let family = initial.get('family') === '6' ? '6' : '4', status = null, doc = null, raw = '', dirty = false, selection = 'root', subnetIndex = -1, pair = null, busy = false;
let ddnsStatus=null;
let leaseRows = [], leaseNext = '', leaseView = 0, leaseLoading=false, leaseSearch='', leaseAbort=null;
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const root = () => doc?.['Dhcp'+family];
const msg = (s, error = false) => { $('#kea-message').textContent = s; $('#kea-message').classList.toggle('kea-error',error); };
const changed = () => { dirty=true; raw=JSON.stringify(doc,null,2)+'\n'; $('#kea-dirty').textContent='Есть изменения'; pair=null; };
const action = (text, fn) => {const b=document.createElement('button'); b.type='button'; b.textContent=text;b.addEventListener('click',()=>safely(fn));return b;};
async function safely(fn) { if (busy) return; try { await fn(); } catch(e) { msg(e.message,true); } }
async function api(path, request, node = server.value, f = family, query = {}, signal) {
 const response = await fetch('/api/v1/dhcp'+path+'?'+new URLSearchParams({node,family:f,...query}), {method:request?'POST':'GET',headers:request?{'Content-Type':'application/json','X-CSRF-Token':consoleEl.dataset.csrf}:{},body:request?JSON.stringify({family:f,...request}):undefined,signal});
 let result;try{result=await response.json();}catch{throw new Error('Сервер вернул неверный ответ ('+response.status+'). Обновите состояние перед повтором.');}
 if(!response.ok) throw new Error(result.error||'Ошибка '+response.status);return result;
}
async function work(fn) {busy=true; const buttons=[...consoleEl.querySelectorAll('button,select')];const disabled=buttons.map(b=>b.disabled);buttons.forEach(b=>b.disabled=true);try{return await fn();}finally{buttons.forEach((b,i)=>{b.disabled=disabled[i];});busy=false;}}
function discard() {return !dirty || window.confirm('Отменить несохранённые изменения DHCP?');}
async function load() {
 leaseView++;leaseAbort?.abort();leaseLoading=false;ddnsStatus=null;
 if(!server.value)return;
 await work(async()=>{status=await api('');doc=status.document||null;raw=status.config||'';dirty=false;pair=null;selection='root';subnetIndex=-1;leaseView++;leaseRows=[];leaseNext='';$('#kea-dirty').textContent='';renderTree();render();$('#kea-status').textContent=`${server.value} · IPv${family} · ${status.unit} · ${status.service||'состояние неизвестно'} · ${status.version||'Kea не найден'}`;msg(status.warning||'Конфигурация прочитана с сервера.');});
}
function treeButton(label,kind,index=-1) {const li=document.createElement('li'),b=action(label,async()=>{leaseAbort?.abort();leaseLoading=false;leaseView++;selection=kind;subnetIndex=index;renderTree();render();if(kind==='leases')await fetchLeases();if(kind==='ddns')await loadDDNS();});b.setAttribute('aria-current',String(selection===kind&&subnetIndex===index));li.append(b);return li;}
function renderTree() {
 tree.replaceChildren();const top=document.createElement('ul'),host=treeButton('▣ '+server.value,'server');top.append(host);const protocols=document.createElement('ul');host.append(protocols);
 for(const f of ['4','6']) {const li=document.createElement('li'),b=action('▾ IPv'+f,async()=>{if(f!==family){if(!discard())return;family=f;await load();}else{selection='root';subnetIndex=-1;renderTree();render();}});li.append(b);protocols.append(li);if(f!==family)continue;
  const items=document.createElement('ul');li.append(items);items.append(treeButton('⚙ Параметры сервера','root'),treeButton('▤ Параметры сервера','options'),treeButton('⌁ Классы клиентов / Option 82','classes'),treeButton('⇄ Отказоустойчивость','ha'),treeButton('↔ DNS и DDNS','ddns'),treeButton('⌘ Конфигурация Kea','expert'));
  (root()?.['subnet'+family]||[]).forEach((s,i)=>{const item=treeButton('▾ Область ['+s.subnet+']','subnet',i),children=document.createElement('ul');children.append(treeButton('▦ Пул адресов','pools',i),treeButton('◷ Активные аренды','leases',i),treeButton('▣ Резервирования','reservations',i),treeButton('▤ Параметры области','subnet-options',i));item.append(children);items.append(item);});
 }
 tree.append(top);
}
function field(label,name,value='',type='text') {return `<label>${esc(label)}<input name="${esc(name)}" type="${type}" value="${esc(value)}"></label>`;}
function area(label,name,value,rows=7) {return `<label>${esc(label)}<textarea name="${esc(name)}" rows="${rows}" spellcheck="false">${esc(value)}</textarea></label>`;}
function form(html,save,label='Сохранить в проекте изменений') {
 const f=document.createElement('form');f.innerHTML=html;const b=document.createElement('button');b.textContent=label;f.append(b);f.addEventListener('submit',e=>{e.preventDefault();safely(async()=>{await save(new FormData(f));});});panel.append(f);return f;
}
function heading(title,text='') {panel.innerHTML=`<h2>${esc(title)}</h2>${text?'<p>'+esc(text)+'</p>':''}`;}
function actions(...buttons) {const d=document.createElement('div');d.className='kea-actions';d.append(...buttons);panel.append(d);}
function number(v,name) {if(!/^\d+$/.test(v)||Number(v)>4294967295)throw new Error(name+': требуется целое число 0–4294967295');return Number(v);}
function json(value,kind=Array) {const v=JSON.parse(value);if(kind===Array?!Array.isArray(v):!v||Array.isArray(v)||typeof v!=='object')throw new Error('Неверный тип JSON');return v;}
function render() {
 if(selection==='server') {heading('Сервер DHCP — '+server.value,'Управление службами IPv4 и IPv6 выполняет helper. Выберите протокол в дереве.');return;}
 if(selection==='ddns'){renderDDNS();return;}
 if(selection==='expert') {heading('Конфигурация IPv'+family,'Текстовый режим сохраняет комментарии. Визуальный редактор сохраняет неизвестные параметры, но переводит документ в обычный JSON без комментариев. Include-файлы требуют ручного управления.');form(area('Конфигурация Kea','config',raw,24),data=>{raw=data.get('config');try{doc=JSON.parse(raw);}catch{doc=null;}dirty=true;pair=null;$('#kea-dirty').textContent='Есть изменения';renderTree();msg('Текст сохранён в проекте изменений. Выполните проверку Kea.');});return;}
 if(!root()) {heading('DHCPv'+family+' — начальная настройка',status?.warning||'Конфигурация отсутствует.');actions(action('Создать начальную конфигурацию',()=>{doc={['Dhcp'+family]:{'interfaces-config':{interfaces:[]},'valid-lifetime':3600,'renew-timer':900,'rebind-timer':1800,'lease-database':{type:'memfile',persist:true},['subnet'+family]:[]}};changed();renderTree();render();msg('Укажите интерфейсы и создайте область адресов перед включением службы.');}));return;}
 if(selection==='root') {
  heading('DHCPv'+family+' — свойства сервера',`${status.path} · Служба: ${status.service||'неизвестно'} · Автозапуск: ${status.enabled||'неизвестно'}`);
  form(field('Сетевые интерфейсы (через запятую)','interfaces',(root()['interfaces-config']?.interfaces||[]).join(', '))+(family==='4'?`<label>Приём DHCPv4<select name="socketType"><option value="raw" ${root()['interfaces-config']?.['dhcp-socket-type']!=='udp'?'selected':''}>Прямые клиенты и relay (raw)</option><option value="udp" ${root()['interfaces-config']?.['dhcp-socket-type']==='udp'?'selected':''}>Только relay (UDP)</option></select></label>`:'')+field('Срок аренды, секунд','valid',root()['valid-lifetime']??3600,'number')+field('Обновление T1, секунд','renew',root()['renew-timer']??900,'number')+field('Перепривязка T2, секунд','rebind',root()['rebind-timer']??1800,'number'),d=>{
   const valid=number(d.get('valid'),'Срок аренды'),renew=number(d.get('renew'),'T1'),rebind=number(d.get('rebind'),'T2');if(!(renew<rebind&&rebind<valid))throw new Error('Требуется T1 < T2 < срок аренды');
   root()['interfaces-config']={...root()['interfaces-config'],interfaces:d.get('interfaces').split(',').map(v=>v.trim()).filter(Boolean)};if(family==='4')root()['interfaces-config']['dhcp-socket-type']=d.get('socketType');Object.assign(root(),{'valid-lifetime':valid,'renew-timer':renew,'rebind-timer':rebind});changed();msg('Свойства сохранены в проекте изменений.');});
  actions(action('Создать область…',addSubnet),...['start','stop','restart','enable','disable'].map((a,i)=>action(['Запустить…','Остановить…','Перезапустить…','Включить автозапуск и запустить…','Выключить автозапуск…'][i],()=>serviceAction(a))));return;
 }
 if(selection==='ha') {renderHA();return;}
 if(selection==='classes') {renderCollection(root(),'client-classes','Классы клиентов / Option 82',[['name','Имя класса'],['test','Выражение Kea']],{name:'relay-vlan100',test:family==='4'?"relay4[1].hex == 0x766c616e313030":"relay6[0].option[18].text == 'vlan100'"});return;}
 const sub=root()['subnet'+family]?.[subnetIndex];
 if(selection==='leases'&&sub) {renderLeases();return;}
 if(selection==='subnet'&&sub) {
  heading('Область '+sub.subnet,'Прямые клиенты и relay: Kea выбирает область по giaddr (IPv4), link-address или Interface-ID (IPv6). Явные адреса relay нужны, когда адрес relay не входит в подсеть области. Для нескольких областей за одним relay используйте классы клиентов. Локальный интерфейс не требуется для удалённой подсети.');
  form(field('Имя области','name',sub['user-context']?.['sambaadm-name']||'')+field('Подсеть CIDR','subnet',sub.subnet)+field('ID области','id',sub.id,'number')+field('Локальный интерфейс (необязательно)','interface',sub.interface||'')+field('Адреса relay (giaddr / link-address), через запятую','relays',(sub.relay?.['ip-addresses']||[]).join(', '))+(family==='6'?field('Interface-ID relay DHCPv6','interfaceID',sub['interface-id']||''):'')+field('Класс клиентов для выбора области (необязательно)','class',sub['client-class']||''),d=>{const id=number(d.get('id'),'ID');if(!id)throw new Error('ID должен быть больше нуля');if(root()['subnet'+family].some((s,i)=>i!==subnetIndex&&s.id===id))throw new Error('ID уже занят');const relay=d.get('relays').split(',').map(v=>v.trim()).filter(Boolean);const iface=d.get('interface').trim(),interfaceID=d.get('interfaceID')?.trim();if(family==='6'&&iface&&interfaceID)throw new Error('Для DHCPv6 локальный интерфейс и relay Interface-ID несовместимы');if(relay.length)sub.relay={...sub.relay,'ip-addresses':relay};else delete sub.relay;for(const [k,v]of [['interface',iface],['interface-id',interfaceID],['client-class',d.get('class').trim()]]){if(v)sub[k]=v;else delete sub[k];}Object.assign(sub,{id,subnet:d.get('subnet').trim(),'user-context':{...sub['user-context'],'sambaadm-name':d.get('name')}});changed();renderTree();msg('Свойства области сохранены.');});
  actions(action('Удалить область…',()=>{if(window.confirm('Удалить область '+sub.subnet+' и её пулы и резервирования?')){root()['subnet'+family].splice(subnetIndex,1);changed();selection='root';subnetIndex=-1;renderTree();render();}}));return;
 }
 if(selection==='options'||selection==='subnet-options') {renderCollection(selection==='options'?root():sub,'option-data','Параметры '+(sub?'области '+sub.subnet:'сервера'),[['name','Имя опции'],['data','Значение'],['code','Код (для произвольной опции)'],['space','Пространство опций']],{name:family==='4'?'domain-name-servers':'dns-servers',data:''});return;}
 if(selection==='pools'&&sub) {renderCollection(sub,'pools','Пул адресов — '+sub.subnet,[['pool','Диапазон A - B или CIDR'],['client-class','Класс клиентов (необязательно)']],{pool:''});return;}
 if(selection==='reservations'&&sub) {renderCollection(sub,'reservations','Резервирования — '+sub.subnet,family==='4'?[['hw-address','MAC-адрес'],['ip-address','IP-адрес'],['hostname','Имя клиента']]:[['duid','DUID клиента'],['ip-addresses','IPv6-адреса через запятую'],['hostname','Имя клиента']],{});return;}
}
function leaseRef(lease) {return {address:lease['ip-address'],type:lease.type,subnetID:lease['subnet-id'],revision:lease.revision};}
function leaseScope() {return root()?.['subnet'+family]?.[subnetIndex];}
function leaseTableKey(){return server.value+'|'+family+'|leases|'+subnetIndex;}
function renderLeases() {
 const sub=leaseScope();if(!sub)return;
 const focused=document.activeElement?.getAttribute('aria-label')==='Поиск в таблице',caret=focused?document.activeElement.selectionStart:0;
 heading('Активные аренды — '+sub.subnet,'Аренды читаются из работающей Kea. Поиск выполняется по всей базе выбранной области; список загружается постранично. Сортировка автоматически применяется по мере загрузки.');
 const tools=document.createElement('div');tools.className='kea-actions';tools.append(action('Обновить аренды',()=>fetchLeases()),action('Включить управление арендами…',enableLeaseControl));if(leaseLoading)tools.append(action('Остановить загрузку',()=>leaseAbort?.abort()));else if(leaseNext)tools.append(action('Продолжить загрузку',()=>fetchLeases(true)));panel.append(tools);
 const columns=[{key:'ip',label:'IP-адрес / префикс',type:'ip',get:l=>l['ip-address'],format:l=>l['ip-address']+(l.type==='IA_PD'?'/'+l['prefix-len']:'')},{key:'hostname',label:'Имя клиента',get:l=>l.hostname},{key:'identifier',label:'MAC / DUID / client-id',get:l=>(family==='4'?[l['hw-address'],l['client-id']]:[l.duid,l['hw-address'],l.iaid!==undefined?'IAID: '+l.iaid:'']).filter(Boolean).join('\n')},{key:'type',label:'Тип',get:l=>l.type||'IPv4'},{key:'expires',label:'Истечение аренды',type:'number',get:l=>l.infinite?Number.MAX_SAFE_INTEGER:Date.parse(l.expiresAt),format:l=>l.infinite?'Бессрочная':l.expiresAt?new Date(l.expiresAt).toLocaleString():'Неизвестно'}];
 dataTable(leaseTableKey(),columns,leaseRows,lease=>[action('Создать резервирование…',()=>reserveFromLease(lease)),action('Удалить аренду…',()=>deleteLease(lease))],{defaultSort:'ip',className:'kea-leases',loading:leaseLoading,remoteSearch:query=>safely(()=>fetchLeases(false,query))});
 if(focused){const input=panel.querySelector('[aria-label="Поиск в таблице"]');input.focus();input.setSelectionRange(caret,caret);}
 if(leaseLoading){const p=document.createElement('p');p.textContent='Читаются следующие страницы сервера. Поиск и сортировка охватят весь список после завершения загрузки.';panel.append(p);}
}
async function fetchLeases(more=false,query) {
 const sub=leaseScope();if(!sub)return;
 leaseAbort?.abort();const controller=new AbortController();leaseAbort=controller;
 const current=++leaseView,node=server.value,f=family,id=sub.id;
 const state=tableStates.get(leaseTableKey());leaseSearch=query===undefined?(state?.search||''):query;
 if(!more){leaseRows=[];leaseNext='start';if(state){state.search=leaseSearch;state.page=1;}}
 leaseLoading=true;renderLeases();msg('Загрузка аренд с сервера…');let scanned=0,observed;
 try {
  do {
   const result=await api('/leases',null,node,f,{subnetID:id,from:leaseNext||'start',search:leaseSearch},controller.signal);
   if(current!==leaseView||selection!=='leases'||family!==f||server.value!==node){controller.abort();return;}
   const seen=new Set(leaseRows.map(l=>l['ip-address']+'|'+l.type));for(const lease of result.leases){const key=lease['ip-address']+'|'+lease.type;if(!seen.has(key)){leaseRows.push(lease);seen.add(key);}}
   leaseNext=result.next||'';scanned+=result.scanned||0;observed=result.observed;renderLeases();msg('Загружено аренд области: '+leaseRows.length+'. Просмотрено записей базы: '+scanned+(leaseNext?'. Загрузка продолжается…':'. Список загружен полностью.'));
  } while(leaseNext);
 } catch(e){if(current===leaseView){msg(e.name==='AbortError'?'Загрузка остановлена. Поиск и сортировка пока охватывают загруженную часть списка.':e.message,e.name!=='AbortError');}}
 finally{if(current===leaseView){leaseLoading=false;renderLeases();if(observed&&!controller.signal.aborted&&!leaseNext)msg('Загружено активных аренд области: '+leaseRows.length+'. Наблюдение: '+new Date(observed).toLocaleString()+'. Поиск охватывает всю область.');}}
}
function localControlSocket(service, family) {
 const name='/run/kea/kea'+family+'-ctrl-socket';
 const sockets=service['control-sockets'];
 if(Array.isArray(sockets)) {
  const unix=sockets.find(s=>s['socket-type']==='unix');
  if(unix){if(!unix['socket-name']||unix['socket-name'].startsWith('/tmp/'))unix['socket-name']=name;}
  else sockets.push({'socket-type':'unix','socket-name':name});
 } else if(service['control-socket']?.['socket-type']==='unix') {
  const socket=service['control-socket'];if(!socket['socket-name']||socket['socket-name'].startsWith('/tmp/'))socket['socket-name']=name;
 } else {
  const socket={'socket-type':'unix','socket-name':name};
  if(service['control-socket']){service['control-sockets']=[service['control-socket'],socket];delete service['control-socket'];}
  else service['control-socket']=socket;
 }
}
function hasLocalControlSocket(service) {
 const candidates=[service['control-socket'],...(service['control-sockets']||[])];
 return candidates.some(socket=>socket?.['socket-type']==='unix' && socket['socket-name']?.startsWith('/') && !socket['socket-name'].startsWith('/tmp/'));
}
function enableLeaseControl() {
 const service=root(),library=haHook(status.hooks,'libdhcp_lease_cmds.so');
 const libraries=service['hooks-libraries']??=[];
 if(!libraries.some(h=>/(^|\/)libdhcp_lease_cmds\.so$/.test(h.library)))libraries.push({library});
 localControlSocket(service,family);
 changed();msg('Управление арендами подготовлено. Нажмите «Проверить и применить…», затем обновите аренды. Служба должна быть запущена.');
}
function deleteLease(lease) {
 const node=server.value,f=family,reference=leaseRef(lease),ha=(root()['hooks-libraries']||[]).some(h=>/(^|\/)libdhcp_ha\.so$/.test(h.library));
 showDialog('Удаление аренды '+lease['ip-address'],`<p>Удалить аренду на сервере <strong>${esc(node)}</strong>? Клиент может продолжать использовать адрес до обновления аренды. Резервирование сохранится.</p>`+(ha?'<p>Настроена HA. Удаление выполняется только на выбранном сервере; проверьте запись у партнёра отдельно.</p>':'')+`<label><input type="checkbox" name="ddns">Отправить удаление DNS-записей через настроенный DDNS Kea</label><label><input type="checkbox" required>Подтверждаю удаление выбранной аренды</label>`,async data=>{
  const result=await work(()=>api('/leases/delete',{lease:reference,confirm:true,updateDDNS:!!data.get('ddns')},node,f));
  dialog.close();await fetchLeases();msg(result.detail);
 });
}
function reserveFromLease(lease) {
 if(dirty)throw new Error('Сначала примените или отмените несохранённые изменения конфигурации.');
 const node=server.value,f=family,reference=leaseRef(lease),revision=status.revision;
 showDialog('Создать резервирование из аренды',`<p>Область: ${esc(leaseScope().subnet)} · Адрес: ${esc(lease['ip-address'])}${lease.type==='IA_PD'?'/'+esc(lease['prefix-len']):''}</p><p>Идентификатор: ${esc(f==='4'?(lease['hw-address']||lease['client-id']):lease.duid)}</p>`+field('Имя клиента','hostname',lease.hostname||''),async data=>{
  const plan=await work(()=>api('/leases/reservation/plan',{lease:reference,revision,reservationHostname:data.get('hostname')},node,f));
  dialog.close();
  dialogContent.innerHTML='<h2>Создание резервирования — '+esc(node)+'</h2><p>Резервирование будет записано в конфигурацию области. Существующая аренда сохранится. Работающая служба будет перезапущена. Для HA подготовьте обновление конфигурации партнёра через мастер пары.</p><details><summary>До изменения</summary><pre>'+esc(plan.before)+'</pre></details><details open><summary>После изменения</summary><pre>'+esc(plan.proposed)+'</pre></details><pre>'+esc(plan.validation)+'</pre>';
  dialogContent.append(action('Подтверждаю — создать резервирование',async()=>{
   const result=await work(()=>api('/apply',{lease:reference,config:plan.proposed,revision:plan.revision,proposedRevision:plan.proposedRevision,confirm:true},node,f));
   status=result.status;doc=status.document||null;raw=status.config;dirty=false;pair=null;$('#kea-dirty').textContent='';dialog.close();renderTree();render();await fetchLeases();msg('Резервирование создано; аренда сохранена. Резервная копия: '+result.backup);
  }));dialog.showModal();
 });
}
function addSubnet() {
 const next=Math.max(0,...(root()['subnet'+family]||[]).map(s=>s.id||0))+1;
 showDialog('Новая область',field('Имя области','name')+field('Подсеть CIDR','subnet',family==='4'?'192.168.10.0/24':'2001:db8:10::/64')+field('ID области','id',next,'number'),d=>{
  const id=number(d.get('id'),'ID');if(!id||(root()['subnet'+family]||[]).some(s=>s.id===id))throw new Error('ID должен быть уникальным и больше нуля');
  (root()['subnet'+family]??=[]).push({id,subnet:d.get('subnet').trim(),pools:[],reservations:[],'option-data':[],'user-context':{'sambaadm-name':d.get('name')}});changed();renderTree();render();});
}
function showDialog(title,html,save) {
 dialogContent.innerHTML='<h2>'+esc(title)+'</h2>';const f=document.createElement('form');f.className='kea-properties';f.innerHTML=html;const b=document.createElement('button');b.textContent='ОК';f.append(b);f.addEventListener('submit',e=>{e.preventDefault();safely(async()=>{await save(new FormData(f));if(f.isConnected)dialog.close();});});dialogContent.append(f);dialog.showModal();
}
const tableStates = new Map();
const collator = new Intl.Collator('ru',{numeric:true,sensitivity:'base'});
function ipValue(value) {
 let text=String(value??'').trim().split(/[ /,]/)[0];
 if(/^\d+\.\d+\.\d+\.\d+$/.test(text)){const octets=text.split('.').map(Number);if(octets.some(n=>n>255))return null;return [4,octets.reduce((n,v)=>(n<<8n)+BigInt(v),0n)];}
 text=text.split('%')[0];if(!text.includes(':'))return null;
 if(text.includes('.')){const split=text.lastIndexOf(':'),tail=ipValue(text.slice(split+1));if(!tail||tail[0]!==4)return null;text=text.slice(0,split+1)+(tail[1]>>16n).toString(16)+':'+(tail[1]&65535n).toString(16);}
 const halves=text.split('::');if(halves.length>2)return null;const left=halves[0]?halves[0].split(':'):[],right=halves.length===2&&halves[1]?halves[1].split(':'):[];
 const missing=8-left.length-right.length;if(halves.length===1&&missing!==0||halves.length===2&&missing<1)return null;
 const fields=[...left,...Array(halves.length===2?missing:0).fill('0'),...right];if(fields.length!==8||fields.some(f=>! /^[0-9a-f]{1,4}$/i.test(f)))return null;
 return [6,fields.reduce((n,v)=>(n<<16n)+BigInt('0x'+v),0n)];
}
function compareTable(a,b,type) {
 if(type==='ip'){const x=ipValue(a),y=ipValue(b);if(x&&y)return x[0]-y[0]||(x[1]<y[1]?-1:x[1]>y[1]?1:0);}
 if(type==='number'||type==='date'){const x=type==='date'?Date.parse(a):Number(a),y=type==='date'?Date.parse(b):Number(b);if(Number.isFinite(x)&&Number.isFinite(y))return x-y;}
 return collator.compare(String(a??''),String(b??''));
}
function dataTable(key,columns,rows,rowActions,options={}) {
 const saved=tableStates.get(key)||{search:'',sort:options.defaultSort||columns[0].key,descending:false,page:1,size:25};tableStates.set(key,saved);
 const wrap=document.createElement('section');wrap.className='kea-data-table';
 const search=document.createElement('form');search.className='kea-table-tools';search.setAttribute('role','search');
 const label=document.createElement('label');label.textContent='Поиск';const input=document.createElement('input');input.type='search';input.value=saved.draftSearch??saved.search;input.maxLength=256;input.setAttribute('aria-label','Поиск в таблице');label.append(input);search.append(label);
 const find=document.createElement('button');find.textContent='Найти';search.append(find);
 const sizeLabel=document.createElement('label');sizeLabel.textContent='Строк на странице';const size=document.createElement('select');size.setAttribute('aria-label','Строк на странице');for(const n of [10,25,50,100]){const o=document.createElement('option');o.value=n;o.textContent=n;o.selected=saved.size===n;size.append(o);}sizeLabel.append(size);search.append(sizeLabel);wrap.append(search);
 const scroll=document.createElement('div');scroll.className='kea-table-scroll';const table=document.createElement('table');table.className=options.className||'';scroll.append(table);wrap.append(scroll);
 const footer=document.createElement('div');footer.className='kea-table-pages';footer.setAttribute('aria-label','Пагинация таблицы');wrap.append(footer);panel.append(wrap);
 function draw() {
  const needle=saved.search.toLocaleLowerCase();let entries=rows.map((value,index)=>({value,index}));if(needle&&!options.remoteSearch)entries=entries.filter(item=>columns.some(c=>String(c.get(item.value)??'').toLocaleLowerCase().includes(needle))||JSON.stringify(item.value).toLocaleLowerCase().includes(needle));
  const column=columns.find(c=>c.key===saved.sort)||columns[0];entries.sort((a,b)=>(saved.descending?-1:1)*compareTable(column.get(a.value),column.get(b.value),column.type)||a.index-b.index);
  const pages=Math.max(1,Math.ceil(entries.length/saved.size));saved.page=Math.min(Math.max(saved.page,1),pages);
  table.replaceChildren();const head=document.createElement('thead'),headRow=document.createElement('tr');head.append(headRow);table.append(head);
  for(const c of columns){const th=document.createElement('th'),selected=c.key===saved.sort;th.setAttribute('aria-sort',selected?(saved.descending?'descending':'ascending'):'none');th.append(action(c.label+(selected?(saved.descending?' ▼':' ▲'):''),()=>{if(saved.sort===c.key)saved.descending=!saved.descending;else{saved.sort=c.key;saved.descending=false;}saved.page=1;draw();}));headRow.append(th);}
  const ah=document.createElement('th');ah.textContent='Действия';headRow.append(ah);
  const body=document.createElement('tbody');table.append(body);
  for(const entry of entries.slice((saved.page-1)*saved.size,saved.page*saved.size)){const row=document.createElement('tr');for(const c of columns){const cell=document.createElement('td');cell.textContent=c.format?c.format(entry.value):String(c.get(entry.value)??'');row.append(cell);}const cell=document.createElement('td');cell.className='kea-lease-actions';cell.append(...rowActions(entry.value,entry.index));row.append(cell);body.append(row);}
  if(!entries.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=columns.length+1;td.textContent=options.loading?'Загрузка записей…':'Записей не найдено.';tr.append(td);body.append(tr);}
  footer.replaceChildren();const previous=action('Предыдущая страница',()=>{saved.page--;draw();}),next=action('Следующая страница',()=>{saved.page++;draw();});previous.disabled=saved.page===1;next.disabled=saved.page===pages;const text=document.createElement('span');text.textContent=`Страница ${saved.page} из ${pages} · Записей: ${entries.length}`;footer.append(previous,text,next);
 }
 input.addEventListener('input',()=>{saved.draftSearch=input.value;});
 search.addEventListener('submit',event=>{event.preventDefault();saved.search=input.value.trim();delete saved.draftSearch;saved.page=1;if(options.remoteSearch)options.remoteSearch(saved.search);else draw();});
 size.addEventListener('change',()=>{saved.size=Number(size.value);saved.page=1;draw();});draw();return wrap;
}
function renderCollection(target,key,title,fields,defaults) {
 if(!target)return;heading(title);
 const edit=(index)=>{const current=index===null?{...defaults}:target[key][index];showDialog(index===null?'Создать запись':'Свойства записи',fields.map(([k,l])=>field(l,k,Array.isArray(current[k])?current[k].join(', '):current[k]??'')).join('')+area('Дополнительные свойства (JSON-объект)','extra',JSON.stringify(Object.fromEntries(Object.entries(current).filter(([k])=>!fields.some(([f])=>f===k))),null,2),4),d=>{
  const value=json(d.get('extra'),Object);for(const [k] of fields){const v=d.get(k).trim();if(v){value[k]=k==='code'?number(v,'Код'):k==='ip-addresses'?v.split(',').map(x=>x.trim()):v;}}
  if(key==='pools'&&!value.pool)throw new Error('Укажите диапазон адресов');
  if(key==='reservations'&&!(value['hw-address']||value.duid||value['client-id']||value['flex-id']||value['circuit-id']))throw new Error('Укажите идентификатор клиента');
  if(key==='option-data'&&!value.name&&value.code===undefined)throw new Error('Укажите имя или код опции');
  if(index===null)(target[key]??=[]).push(value);else target[key][index]=value;changed();render();});};
 const columns=fields.map(([k,label])=>({key:k,label,type:['pool','ip-address','ip-addresses'].includes(k)?'ip':k==='code'?'number':'text',get:v=>Array.isArray(v[k])?v[k].join(', '):v[k]}));
 dataTable(server.value+'|'+family+'|'+selection+'|'+subnetIndex,columns,target[key]||[],(_,i)=>[action('Свойства…',()=>edit(i)),action('Удалить',()=>{if(window.confirm('Удалить запись?')){target[key].splice(i,1);changed();render();}})],{defaultSort:fields.some(([k])=>k==='ip-address')?'ip-address':fields.some(([k])=>k==='ip-addresses')?'ip-addresses':fields[0][0]});
 actions(action('Создать…',()=>edit(null)));
}
function haHook(hooks,name){const path=hooks?.[name];if(!path)throw new Error('На сервере отсутствует '+name+'. Установите hook-библиотеки Kea.');return path;}
function haConfig(document,st,f,ha) {
 const service=document['Dhcp'+f],libraries=service['hooks-libraries']||[];
 const lease=haHook(st.hooks,'libdhcp_lease_cmds.so'),high=haHook(st.hooks,'libdhcp_ha.so');
 const other=libraries.filter(h=>!/(^|\/)libdhcp_(ha|lease_cmds)\.so$/.test(h.library));
 const oldLease=libraries.find(h=>h.library===lease)||{library:lease};
 const oldHA=libraries.find(h=>/(^|\/)libdhcp_ha\.so$/.test(h.library));
 if (st.service === 'active' && !service['control-socket'] && !service['control-sockets']?.length) localControlSocket(service,f);
 service['multi-threading']={...service['multi-threading'],'enable-multi-threading':true};
 service['hooks-libraries']=[...other,oldLease,{...oldHA,library:high,parameters:{...oldHA?.parameters,'high-availability':[ha]}}];
}
async function loadDDNS() {
 const node=server.value,f=family;ddnsStatus=null;renderDDNS();
 const result=await work(()=>api('/ddns',null,node,f));if(server.value!==node||selection!=='ddns')return;ddnsStatus=result;renderDDNS();
}
function newTSIGSecret() {const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);return btoa(String.fromCharCode(...bytes));}
function renderDDNS() {
 heading('DNS и динамическое обновление (DDNS)','Мастер устанавливает связь DHCPv4/IPv6 с локальной службой kea-dhcp-ddns (D2), обновляющей прямые A/AAAA и обратные PTR-записи. Зоны создаются администратором DNS по подсказке ниже.');
 if(!ddnsStatus){panel.append(document.createTextNode('Чтение состояния DDNS…'));return;}
 const st=ddnsStatus,settings=st.settings||{};
 const statusLine=document.createElement('p');statusLine.textContent=`${st.path} · D2: ${st.service||'неизвестно'} · Автозапуск: ${st.enabled||'неизвестно'} · ${st.version||'пакет не установлен'}`;panel.append(statusLine);
 if(st.warning){const p=document.createElement('p');p.textContent=st.warning;panel.append(p);}
 if(st.credentialTimer){const p=document.createElement('p');p.textContent='Таймер Kerberos: '+st.credentialTimer+' · Результат: '+(st.credentialResult||'неизвестно')+' · Билет: '+(st.credentialCacheValid?'действует':'недействителен')+' · Последний запуск: '+(st.credentialLastRun||'ожидается');panel.append(p);}
 const hint=document.createElement('section');hint.className='alert';hint.innerHTML='<strong>Подготовьте DNS-зоны</strong><p>Создайте прямую зону для имён клиентов и обратные зоны для адресов областей. Разрешите подписанные обновления A, AAAA и PTR выбранному ключу или Kerberos principal. При TSIG также используется DHCID; для Samba AD — режим без DHCID с проверкой прав AD. Подсказка рассчитывается по областям обоих протоколов:</p>';
 const list=document.createElement('ul');for(const name of [settings.forwardZone||consoleEl.dataset.domain,...(st.zoneHints||[])].filter(Boolean)){const item=document.createElement('li');item.textContent=name;list.append(item);}hint.append(list);const link=document.createElement('a');link.href='/dns';link.textContent='Открыть диспетчер DNS';hint.append(link);panel.append(hint);
 const gssInfo=document.createElement('p');gssInfo.textContent=st.gssHook?'Для GSS-TSIG доступна библиотека: '+st.gssHook+'. Keytab с правами _kea: '+st.keytab:'Защищённые обновления Samba AD настраиваются через helper: добавьте GSS-TSIG на главной странице, затем подготовьте служебную учётную запись, права зон и keytab. Для p11 используется пакет kea-gss-tsig; для p10 — совместимый RPM GSS hook без замены Kea.';panel.append(gssInfo);
 const pairedPeer=st.gssProfile?.members?.find(n=>n!==server.value);const peers=[...server.options].filter(o=>o.value!==server.value).map(o=>'<option value="'+esc(o.value)+'"'+(o.value===pairedPeer?' selected':'')+'>'+esc(o.value)+'</option>').join('');
 const f=form(field('Прямая DNS-зона / суффикс имён','forwardZone',settings.forwardZone||consoleEl.dataset.domain||'')+area('Обратные DNS-зоны, по одной на строку','reverseZones',(settings.reverseZones?.length?settings.reverseZones:st.zoneHints||[]).join('\n'),4)+field('IP-адрес авторитетного DNS-сервера','dnsAddress',settings.dnsAddress||'')+field('Порт DNS','dnsPort',settings.dnsPort||53,'number')+field('Локальный порт D2 (127.0.0.1)','ncrPort',settings.ncrPort||53001,'number')+`<label>Подпись обновлений<select name="auth"><option value="tsig" ${settings.auth!=='gss-tsig'?'selected':''}>TSIG HMAC-SHA256 (общий ключ)</option><option value="gss-tsig" ${settings.auth==='gss-tsig'?'selected':''} >GSS-TSIG / Kerberos (DNS AD)</option></select></label>`+field('Имя TSIG-ключа','keyName',settings.keyName||'sambaadm-kea.')+field('Секрет TSIG (base64; пусто — сохранить существующий)','secret','','password')+field('Контроллер Samba AD (FQDN)','gssController',st.gssProfile?.controller||'')+field('DNS-сервер AD (FQDN; пусто — тот же DC)','gssDNSHost',settings.serverPrincipal?.match(/^DNS\/([^@]+)/)?.[1]||'')+`<label><input type="checkbox" name="gssRotate">Обновить ключ существующей управляемой учётной записи (изменит её пароль)</label>`+field('Principal DDNS-клиента (GSS-TSIG)','clientPrincipal',st.gssProfile?.principal||settings.clientPrincipal||'')+field('Principal DNS-сервера (GSS-TSIG)','serverPrincipal',st.gssProfile?.serverPrincipal||settings.serverPrincipal||'')+`<label><input type="checkbox" name="overrideClient" ${settings.overrideClient!==false?'checked':''}>Сервер обновляет прямые и обратные записи даже при запросе клиента на самостоятельное обновление</label><label>Второй сервер HA (необязательно)<select name="peer" aria-label="Второй сервер HA (необязательно)"><option value="">Только выбранный сервер</option>${peers}</select></label>`,async data=>{
  if(dirty)throw new Error('Сначала примените или отмените изменения DHCP.');
  const settings={forwardZone:data.get('forwardZone').trim(),reverseZones:data.get('reverseZones').split(/\r?\n/).map(v=>v.trim()).filter(Boolean),dnsAddress:data.get('dnsAddress').trim(),dnsPort:number(data.get('dnsPort'),'DNS-порт'),ncrPort:number(data.get('ncrPort'),'Порт D2'),auth:data.get('auth'),keyName:data.get('keyName').trim(),secret:data.get('secret').trim(),clientPrincipal:data.get('clientPrincipal').trim(),serverPrincipal:data.get('serverPrincipal').trim(),overrideClient:!!data.get('overrideClient')};
  const peer=data.get('peer');if(peer&&settings.auth==='tsig'&&!settings.secret)throw new Error('Для настройки пары укажите общий TSIG-ключ или сгенерируйте новый.');
  await reviewDDNS(settings,[server.value,...(peer?[peer]:[])]);
 },'Проверить автонастройку DDNS…');
 const generate=action('Сгенерировать TSIG-ключ',()=>{f.elements.secret.value=newTSIGSecret();msg('Создан новый ключ. После проверки скопируйте определение ключа из подсказки на DNS-сервер.');});f.elements.secret.insertAdjacentElement('afterend',generate);
 const authFields=()=>{const tsig=f.elements.auth.value==='tsig';for(const name of ['keyName','secret'])f.elements[name].closest('label').hidden=!tsig;for(const name of ['gssController','gssDNSHost','gssRotate','clientPrincipal','serverPrincipal'])f.elements[name].closest('label').hidden=tsig;};f.elements.auth.addEventListener('change',authFields);authFields();f.elements.secret.autocomplete='new-password';
 if(!settings.forwardZone)f.elements.secret.value=newTSIGSecret();
 const prepareAD=action('Настроить учётную запись AD и keytab…',()=>gssPrepareAD(f));const group=document.createElement('div');group.className='kea-actions';group.append(prepareAD);f.append(group);
 if(st.gssProfile){const summary=document.createElement('p');summary.textContent='Учётная запись: '+st.gssProfile.principal+' · KVNO '+st.gssProfile.kvno+(st.gssProfile.verified?' · Проверено '+new Date(st.gssProfile.verified).toLocaleString():' · Настройка требует завершения');f.append(summary);}

 actions(...['start','stop','restart','enable','disable'].map((name,i)=>action(['Запустить D2…','Остановить D2…','Перезапустить D2…','Включить автозапуск D2…','Выключить автозапуск D2…'][i],async()=>{if(!window.confirm('Выполнить '+name+' для kea-dhcp-ddns на '+server.value+'?'))return;await work(()=>api('/ddns/service',{action:name,revision:st.revision,confirm:true}));await loadDDNS();})));
}
function ddnsSettings(data) {
 return {forwardZone:data.get('forwardZone').trim(),reverseZones:data.get('reverseZones').split(/\r?\n/).map(v=>v.trim()).filter(Boolean),dnsAddress:data.get('dnsAddress').trim(),dnsPort:number(data.get('dnsPort'),'Порт DNS'),ncrPort:number(data.get('ncrPort'),'Порт D2'),auth:data.get('auth'),keyName:data.get('keyName').trim(),secret:data.get('secret').trim(),clientPrincipal:data.get('clientPrincipal').trim(),serverPrincipal:data.get('serverPrincipal').trim(),overrideClient:!!data.get('overrideClient')};
}
function restoreDDNSDraft(draft) {const f=panel.querySelector('form');if(!f)return;for(const [name,value] of draft){const field=f.elements.namedItem(name);if(!field)continue;if(field.type==='checkbox')field.checked=!!value;else field.value=value;}f.elements.auth.dispatchEvent(new Event('change'));}
async function gssPrepareAD(form) {
 if(dirty)throw new Error('Сначала примените или отмените изменения DHCP.');
 const data=new FormData(form),settings=ddnsSettings(data),nodes=[server.value,...(data.get('peer')?[data.get('peer')]:[])],draft=[...data];
 const gss={controller:data.get('gssController').trim(),dnsHost:data.get('gssDNSHost').trim(),rotate:!!data.get('gssRotate')};
 if(!gss.controller)throw new Error('Укажите FQDN контроллера Samba AD.');
 if(nodes.length===2){await reviewGSSPair(settings,{...gss,members:nodes},nodes,draft);return;}
 await reviewGSSNode(settings,gss,nodes,0,{},draft);
}
async function reviewGSSPair(settings,gss,nodes,draft) {
 const plan=await work(()=>api('/gss/ad/pair/plan',{ddns:settings,gss},server.value));
 const own=plan.plans[plan.nodes[0]];
 dialogContent.innerHTML='<h2>Защищённый DNS для HA-пары</h2><p>Общая учётная запись '+esc(own.principal)+' позволит обоим узлам обновлять записи партнёра после переключения HA. Keytab устанавливается на каждом узле через helper; общий пароль не возвращается в браузер.</p><p>'+esc(own.rights)+'</p><p>DNS-зоны должны существовать. Samba AD: no-check-without-dhcid, GSS-TSIG и ACL владельца. Будут проверены A/AAAA/PTR.</p>'+(gss.rotate?'<p>Ключ всей пары будет заменён. При частичном сбое завершите настройку обоих узлов до включения D2; старые keytab после смены пароля недействительны.</p>':'')+plan.nodes.map(n=>'<p>'+esc(n)+': '+esc(plan.plans[n].keytab)+'</p>').join('');
 const confirm=action('Подтверждаю — подготовить AD и keytab пары',async()=>{confirm.disabled=true;try{const result=await work(()=>api('/gss/ad/pair/apply',{ddns:settings,gss,revision:plan.revision,confirm:true},server.value));dialog.close();await loadDDNS();restoreDDNSDraft(draft);msg('Общая DNS-идентичность и keytab проверены на обоих узлах.');await reviewDDNS({...settings,auth:'gss-tsig'},nodes,result.profiles);}catch(e){msg(e.message,true);dialogContent.append(action('Повторить предпросмотр пары',async()=>{dialog.close();await reviewGSSPair(settings,gss,nodes,draft);}));}});
 dialogContent.append(confirm);dialog.showModal();
}
async function reviewGSSNode(settings,gss,nodes,index,profiles,draft) {
 const node=nodes[index],plan=await work(()=>api('/gss/ad/plan',{ddns:settings,gss},node));
 dialogContent.innerHTML='<h2>Защищённые обновления Samba AD — '+esc(node)+'</h2><p>Узел '+(index+1)+' из '+nodes.length+'. Предпросмотр каждого следующего узла выполняется после подготовки предыдущего.</p><p>Учётная запись: '+esc(plan.account)+' · '+esc(plan.principal)+'</p><p>Состояние: '+(plan.accountState?'управляемая учётная запись уже существует':'будет создана отдельная служебная учётная запись')+'</p><p>'+esc(plan.rights)+'</p><p>Keytab: '+esc(plan.keytab)+'. AES128/AES256, права 0600 для _kea. Kerberos credentials будут обновляться таймером каждые 30 минут. Пароли через браузер и файлы заданий не возвращаются.</p>'+(plan.rotate?'<p>Пароль существующей служебной учётной записи будет заменён. Старый keytab после смены пароля не восстанавливает доступ; при частичном сбое сохранится новый ключ и журнал для повторного завершения.</p>':'')+'<h3>Зоны</h3><ul>'+plan.zones.map(z=>'<li>'+esc(z.name)+'</li>').join('')+'</ul><p>Helper проверит обновление и удаление временных A/AAAA/PTR через GSS-TSIG. Samba AD: без DHCID, режим no-check-without-dhcid; доступ ограничен ACL AD. Существующие зоны и записи клиентов сохраняются.</p>';
 const confirm=action('Подтверждаю — подготовить AD и keytab',async()=>{confirm.disabled=true;try{const result=await work(()=>api('/gss/ad/apply',{ddns:settings,gss,revision:plan.revision,confirm:true},node));profiles[node]=result;dialog.close();if(index+1<nodes.length){await reviewGSSNode(settings,gss,nodes,index+1,profiles,draft);return;}await loadDDNS();restoreDDNSDraft(draft);const f=panel.querySelector('form');f.elements.auth.value='gss-tsig';f.elements.clientPrincipal.value=profiles[server.value].principal;f.elements.serverPrincipal.value=profiles[server.value].serverPrincipal;f.elements.auth.dispatchEvent(new Event('change'));msg(nodes.map(n=>n+': keytab и права зон проверены').join('\n'));await reviewDDNS({...settings,auth:'gss-tsig'},nodes,profiles);
 }catch(e){msg(node+': '+e.message,true);dialogContent.append(action('Повторить предпросмотр AD',async()=>{dialog.close();await reviewGSSNode(settings,gss,nodes,index,profiles,draft);}));}});dialogContent.append(confirm);dialog.showModal();
}
async function reviewDDNS(settings,nodes,profiles={}) {
 const plans=await work(async()=>{const out=[];for(const node of nodes){const own=profiles[node]?{...settings,auth:'gss-tsig',clientPrincipal:profiles[node].principal,serverPrincipal:profiles[node].serverPrincipal}:settings;out.push({node,settings:own,plan:await api('/ddns/plan',{ddns:own},node)});};return out;});
 dialogContent.innerHTML='<h2>Автонастройка DDNS</h2><p>D2 будет включён в автозапуск и запущен. Настроенные на узле DHCPv4/DHCPv6 будут подключены к D2; работающие службы будут перезапущены. Существующие остановленные DHCP-службы останутся остановленными. Файлы сохраняются с резервными копиями.</p><p>Создайте указанные зоны на авторитетном DNS-сервере и разрешите подписанные обновления. Для нестандартных масок IPv4 и classless delegation проверьте границы и делегирование обратных зон.</p>';
 for(const {node,plan} of plans){const section=document.createElement('section');section.innerHTML='<h3>'+esc(node)+'</h3>';for(const file of plan.files){const entry=document.createElement('details');entry.innerHTML='<summary>'+esc(file.path)+'</summary><h4>До изменения</h4><pre>'+esc(file.before)+'</pre><h4>После изменения</h4><pre>'+esc(file.proposed)+'</pre><pre>'+esc(file.validation)+'</pre>';section.append(entry);}const details=document.createElement('details');details.innerHTML='<summary>Подсказка для DNS-зон и ключа (содержит секрет TSIG)</summary>';const pre=document.createElement('pre');pre.textContent=plan.dnsInstructions;details.append(pre);section.append(details);dialogContent.append(section);}
 const confirm=action('Подтверждаю — настроить DDNS',async()=>{confirm.disabled=true;const reports=[];await work(async()=>{for(const {node,plan,settings:own} of plans){try{const result=await api('/ddns/apply',{ddns:own,revision:plan.revision,proposedRevision:plan.proposedRevision,confirm:true},node);reports.push(node+': '+result.detail+' Копии: '+Object.values(result.backups||{}).join(', '));}catch(e){reports.push(node+': ОШИБКА — '+e.message);}}});const failed=reports.some(r=>r.includes('ОШИБКА'));if(failed){const retry=action('Повторно проверить DDNS',async()=>{dialog.close();await reviewDDNS(settings,nodes,profiles);});dialogContent.append(retry);}else{dialog.close();await load();selection='ddns';subnetIndex=-1;renderTree();await loadDDNS();}msg(reports.join('\n'),failed);});dialogContent.append(confirm);dialog.showModal();
}
function renderHA() {
 const libraries=root()['hooks-libraries']||[],existing=libraries.find(h=>/(^|\/)libdhcp_ha\.so$/.test(h.library))?.parameters?.['high-availability']?.[0];
 const peers=existing?.peers||[],a=peers.find(p=>p.name===existing?.['this-server-name'])||{},b=peers.find(p=>p.name!==a.name)||{};
 heading('Отказоустойчивость DHCP — Kea HA','Мастер готовит конфигурации двух серверов и включает выделенные HTTP-слушатели Kea HA. Укажите собственный IP-адрес каждого сервера и свободный порт; для IPv4 и IPv6 используйте разные порты. Сетевой экран должен разрешать обмен между партнёрами. HTTPS требует предварительной настройки сертификатов в конфигурации Kea.');
 const options=[...server.options].filter(o=>o.value!==server.value).map(o=>`<option value="${esc(o.value)}">${esc(o.value)}</option>`).join('');
 form(`<label>Режим<select name="mode"><option value="hot-standby" ${existing?.mode==='hot-standby'?'selected':''}>Горячий резерв (hot-standby)</option><option value="load-balancing" ${existing?.mode==='load-balancing'?'selected':''}>Балансировка (load-balancing)</option></select></label>`+field('Имя этого сервера в HA','local',a.name||'dhcp-primary')+field('HTTP(S) URL Kea этого сервера','localURL',a.url||'http://192.0.2.10:'+ (family==='4'?'8000':'8001')+'/')+`<label>Партнёр (зарегистрированный helper)<select name="partner" required><option value="">Выберите сервер</option>${options}</select></label>`+field('Имя партнёра в HA','peer',b.name||'dhcp-secondary')+field('HTTP(S) URL Kea партнёра','peerURL',b.url||'http://192.0.2.11:'+ (family==='4'?'8000':'8001')+'/')+`<label><input type="checkbox" name="ack" required>Области, ID, пулы и параметры на обоих серверах будут синхронизированы из показанной конфигурации. Настройки интерфейсов, БД и журналирования партнёра сохраняются. Для запущенной Kea без канала управления мастер добавит локальный UNIX-сокет для статуса HA.</label>`,async d=>{
  if(!d.get('partner'))throw new Error('Выберите партнёра');if(d.get('local')===d.get('peer'))throw new Error('Имена HA должны различаться');
  for(const key of ['localURL','peerURL']){const url=new URL(d.get(key));if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('Укажите HTTP(S) URL без логина и пароля');}
  if(new URL(d.get('localURL')).href===new URL(d.get('peerURL')).href)throw new Error('URL партнёров должны различаться');
  const peerStatus=await work(()=>api('',null,d.get('partner')));if(!peerStatus.document)throw new Error('Конфигурация партнёра недоступна: '+peerStatus.warning);
  const localDoc=structuredClone(doc),peerDoc=structuredClone(peerStatus.document),peerRoot=peerDoc['Dhcp'+family],mode=d.get('mode');
  // Preserve all existing HA timers and authentication parameters when possible.
  const peerOld=(peerRoot['hooks-libraries']||[]).find(h=>/(^|\/)libdhcp_ha\.so$/.test(h.library))?.parameters?.['high-availability']?.[0];
  const role1='primary',role2=mode==='hot-standby'?'standby':'secondary';
  const newPeers=[{...a,name:d.get('local'),url:d.get('localURL'),role:role1,'auto-failover':true},{...b,name:d.get('peer'),url:d.get('peerURL'),role:role2,'auto-failover':true}];
  const common={...existing,mode,peers:newPeers,'multi-threading':{...existing?.['multi-threading'],'enable-multi-threading':true,'http-dedicated-listener':true}};
  // Copy scopes, options and classification, while retaining host-specific settings.
  for(const key of ['subnet'+family,'shared-networks','option-data','option-def','client-classes','reservations','valid-lifetime','renew-timer','rebind-timer','preferred-lifetime','min-valid-lifetime','max-valid-lifetime','min-preferred-lifetime','max-preferred-lifetime']){if(Object.hasOwn(root(),key))peerRoot[key]=structuredClone(root()[key]);else delete peerRoot[key];}
  haConfig(localDoc,status,family,{...common,'this-server-name':d.get('local')});
  haConfig(peerDoc,peerStatus,family,{...peerOld,...common,'this-server-name':d.get('peer')});
  doc=localDoc;changed();pair={node:d.get('partner'),family,status:peerStatus,config:JSON.stringify(peerDoc,null,2)+'\n'};renderTree();msg('Подготовлена HA-пара для '+server.value+' и '+pair.node+'. Проверьте изменения обоих серверов.');
 },'Подготовить конфигурации двух серверов');
 const p=document.createElement('p');p.textContent=existing?'Текущий режим: '+existing.mode+' · этот сервер: '+existing['this-server-name']:'HA не настроена. Требуются libdhcp_ha.so и libdhcp_lease_cmds.so на обоих серверах.';panel.append(p);
 if (existing && !hasLocalControlSocket(root())) actions(action('Подключить мониторинг HA…',()=>{
  if (!window.confirm('Добавить локальный UNIX-сокет для статуса HA? Сохраните и примените проект изменений. Если текущий сокет находится в /tmp, путь изменится на /run/kea.')) return;
  localControlSocket(root(),family);changed();render();
 }));
 if(existing)actions(action('Выключить HA на этом сервере…',()=>{if(window.confirm('Выключить HA только на этом сервере? Перед применением согласуйте вывод партнёра из пары.')){root()['hooks-libraries']=libraries.filter(h=>!/(^|\/)libdhcp_ha\.so$/.test(h.library));changed();render();}}));
}
async function review() {
 if(!status)throw new Error('Сначала прочитайте сервер');
 const drafts=[{node:server.value,family,config:raw,status},...(pair?[pair]:[])];
 const plans=await work(async()=>{const result=[];for(const d of drafts){const plan=await api('/plan',{config:d.config,revision:d.status.revision},d.node,d.family);if(plan.revision!==d.status.revision)throw new Error('Конфигурация '+d.node+' изменилась. Обновите данные и подготовьте изменения заново.');result.push({...d,plan});}return result;});
 dialogContent.innerHTML='<h2>Применение конфигурации DHCP</h2><p>Каждая конфигурация проверена бинарником Kea на соответствующем сервере. Работающие службы будут перезапущены; остановленные останутся остановленными. Резервные копии создаются до записи.</p>'+(plans.length>1?'<p>Применение пары последовательно. При частичном сбое проверьте результаты и завершите настройку партнёра. Сам факт записи не подтверждает работу HA: проверьте связь и выдачу адресов при отключении одного узла.</p>':'');
 for(const d of plans){const el=document.createElement('section');el.innerHTML='<h3>'+esc(d.node)+' · IPv'+d.family+'</h3><details><summary>До изменения</summary><pre>'+esc(d.plan.before)+'</pre></details><details open><summary>После изменения</summary><pre>'+esc(d.plan.proposed)+'</pre></details><pre>'+esc(d.plan.validation)+'</pre>';dialogContent.append(el);}
 const b=action('Подтверждаю — применить изменения',async()=>{b.disabled=true;const reports=[];await work(async()=>{for(const d of plans){try{const result=await api('/apply',{config:d.config,revision:d.plan.revision,proposedRevision:d.plan.proposedRevision,confirm:true},d.node,d.family);reports.push(d.node+': применено; копия '+(result.backup||'изменения не требуются'));if(pair?.node===d.node)pair=null;if(d.node===server.value){status=result.status;doc=status.document||null;raw=status.config;dirty=false;$('#kea-dirty').textContent='';}}catch(e){reports.push(d.node+': ОШИБКА — '+e.message);}}});dialog.close();renderTree();render();if(pair){dirty=true;$('#kea-dirty').textContent='Остались изменения партнёра HA';}msg(reports.join('\n'),reports.some(r=>r.includes('ОШИБКА')));});dialogContent.append(b);dialog.showModal();
}
async function serviceAction(actionName) {
 if(dirty)throw new Error('Сначала примените изменения конфигурации или обновите сервер.');
 if(!window.confirm('Выполнить '+actionName+' для '+status.unit+' на '+server.value+'?'))return;
 await work(()=>api('/service',{action:actionName,revision:status.revision,confirm:true}));await load();
}
$('#kea-refresh').addEventListener('click',()=>safely(async()=>{if(selection==='leases'){await fetchLeases();}else if(selection==='ddns'){await loadDDNS();}else if(discard())await load();}));
$('#kea-review').addEventListener('click',()=>safely(review));
let lastServer=server.value;
server.addEventListener('change',()=>safely(async()=>{if(!discard()){server.value=lastServer;return;}lastServer=server.value;await load();}));
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
safely(async()=>{await load();if(initial.get('view')==='ddns'){selection='ddns';renderTree();await loadDDNS();}if(status&&initial.get('view')==='ha'){selection='ha';renderTree();render();}});
})();
