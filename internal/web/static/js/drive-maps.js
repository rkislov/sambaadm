/* Native MS-GPPREF drive preferences. All directory and preference text is rendered as text. */
(function(){
 'use strict';
 window.sambaadmDriveEditor=function({container,model,scope,admin,onSave,onDirty,onConfigure}){
  const ru=document.documentElement.lang==='ru',t=(a,b)=>ru?a:b;
  const el=(tag,cls='',text='')=>{const e=document.createElement(tag);e.className=cls;e.textContent=text;return e;};
  const button=(text,fn)=>{const b=el('button','',text);b.type='button';b.addEventListener('click',fn);return b;};
  const actions={C:t('Создать','Create'),R:t('Заменить','Replace'),U:t('Обновить','Update'),D:t('Удалить подключение','Delete mapping')};
  const section=model.scopes[scope],entries=section.drives;let working=false;
  container.classList.add('drive-maps-editor');
  const heading=el('h3','',t('Сетевые диски','Drive Maps'));container.append(heading,el('p','muted',t('Настройки → Настройки системы → Сетевые диски. Подключение SMB-папок через групповую политику.','Preferences → System settings → Drive Maps. Map SMB shares through Group Policy.')));
  if(scope==='Machine'?model.machineDisabled:model.userDisabled)container.append(el('p','alert error',t('Этот раздел GPO отключён. Включите его в свойствах политики, чтобы настройки применялись.','This GPO scope is disabled. Enable it in policy properties before applying settings.')));
  const notice=el('p','workspace-message');notice.setAttribute('aria-live','polite');container.append(notice);
  const list=el('section'),properties=el('section');container.append(list,properties);
  function status(text,error=false){notice.textContent=text;notice.classList.toggle('error',error);notice.setAttribute('role',error?'alert':'status');}
  function confirmation(form){const l=el('label','workspace-confirm',t('Подтверждаю изменение сетевых дисков этой GPO','I confirm this GPO drive mapping change')),c=el('input');c.type='checkbox';c.required=true;l.prepend(c);form.append(l);return c;}
  async function mutate(payload){if(working)return;working=true;container.querySelectorAll('button,input,select,textarea').forEach(e=>e.disabled=true);status(t('Сохранение…','Saving…'));
   try{await onSave({...payload,scope,revision:model.revision});}
   catch(e){status(e.message,true);working=false;container.querySelectorAll('button,input,select,textarea').forEach(e=>e.disabled=false);if(!admin)container.querySelectorAll('input,select,textarea').forEach(e=>e.disabled=true);}
  }
  function showList(){list.hidden=false;properties.replaceChildren();onDirty(false);}
  function open(item){
   list.hidden=true;properties.replaceChildren();const isNew=!item;
   const drive=item?{...item}:{uid:'',action:'U',path:'',label:'',letter:[...'ZYXWVUTSRQPONMLKJIHGFEDCBA'].find(x=>!entries.some(e=>e.letter===x))||'Z',useLetter:true,persistent:true,disabled:false,thisDrive:'SHOW',allDrives:'NOCHANGE',description:''};
   onDirty(admin);properties.append(el('h4','',isNew?t('Новый сетевой диск','New drive mapping'):t('Свойства сетевого диска','Drive mapping properties')));
   const readonly=!admin||!!drive.readOnly;
   if(drive.readOnly)properties.append(el('p','alert error',t('Изменение этой записи ограничено: ','Editing is restricted for this item: ')+drive.readOnly));
   if(drive.hasFilters)properties.append(el('p','alert',t('Запись содержит индивидуальные условия применения. Они сохраняются при редактировании.','This item has targeting filters. They are preserved when editing.')));
   const form=el('form','workspace-form drive-maps-form');properties.append(form);const fields=el('fieldset');fields.disabled=readonly;form.append(fields);
   function input(key,label,type='text',choices){const l=el('label','',label);let i;
    if(choices){i=el('select');for(const [value,label]of choices){const o=el('option','',label);o.value=value;i.append(o);}}
    else{i=el('input');i.type=type;}
    i.setAttribute('aria-label',label);i.name=key;if(type==='checkbox')i.checked=key==='enabled'?!drive.disabled:!!drive[key];else i.value=drive[key]??'';
    if(key==='path')i.placeholder='\\\\files.example.com\\share';
    if(key==='label')i.maxLength=256;if(key==='description')i.maxLength=1024;if(key==='path')i.maxLength=2048;
    i.addEventListener('change',()=>{drive[key==='enabled'?'disabled':key]=type==='checkbox'?(key==='enabled'?!i.checked:i.checked):i.value;});
    i.addEventListener('input',()=>{if(type!=='checkbox')drive[key]=i.value;});l.append(i);fields.append(l);return i;
   }
   const action=input('action',t('Действие','Action'),'text',Object.entries(actions));const path=input('path',t('Путь к общей папке UNC','Share UNC path'));path.required=drive.action!=='D';action.addEventListener('change',()=>path.required=action.value!=='D');
   input('label',t('Название диска','Drive label'));input('letter',t('Буква диска','Drive letter'),'text',[...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map(x=>[x,x+':']));
   input('useLetter',t('Использовать фиксированную букву','Use a fixed drive letter'),'checkbox');input('persistent',t('Переподключаться при входе','Reconnect at sign-in'),'checkbox');input('enabled',t('Запись включена','Item enabled'),'checkbox');
   const visibility=[['NOCHANGE',t('Без изменений','No change')],['SHOW',t('Показать','Show')],['HIDE',t('Скрыть','Hide')]];
   input('thisDrive',t('Видимость этого диска','This drive visibility'),'text',visibility);input('allDrives',t('Видимость всех дисков','All drives visibility'),'text',visibility);input('description',t('Описание записи','Item description'));
   form.append(el('p','muted',t('Для ALT рекомендуется фиксированная буква для каждой записи. Фактическое подключение появляется в каталогах Linux. Названия с пробелами или кириллицей в старых версиях gpupdate могут требовать двойных кавычек.','For ALT, use a distinct fixed letter for each item. Actual mounts appear in Linux directories. Older gpupdate versions may require double quotes around labels containing spaces or Cyrillic characters.')));
   let confirm;if(admin)confirm=confirmation(form);const controls=el('div','workspace-tools');form.append(controls);
   if(admin&&!readonly){const save=el('button','',t('Сохранить сетевой диск','Save drive mapping'));save.type='submit';controls.append(save);}
   form.addEventListener('submit',e=>{e.preventDefault();if(readonly||!form.reportValidity())return;mutate({operation:'upsert',drive});});
   if(admin&&!isNew){
    const confirmed=fn=>{if(!confirm.reportValidity())return;fn();};
    controls.append(button(t('Удалить запись из GPO','Remove item from GPO'),()=>confirmed(()=>mutate({operation:'remove',drive:{uid:drive.uid}}))));
    if(!readonly)for(const [direction,label]of [[-1,t('Переместить выше','Move up')],[1,t('Переместить ниже','Move down')]]){const b=button(label,()=>confirmed(()=>mutate({operation:'move',direction,drive:{uid:drive.uid}})));b.disabled=entries.indexOf(item)+direction<0||entries.indexOf(item)+direction>=entries.length;controls.append(b);}
   }
   controls.append(button(t('К списку дисков','Back to drive mappings'),showList));
   if(admin&&!isNew)form.append(el('p','muted',t('Удаление записи из GPO прекращает её назначение. Чтобы убрать уже подключённый диск у клиентов, сначала сохраните запись с действием «Удалить подключение» и дождитесь применения политики.','Removing a GPO item stops assigning it. To remove an existing client mapping, first save the item with the Delete mapping action and let clients apply it.')));
  }
  const tools=el('div','workspace-tools');if(admin)tools.append(button(t('Новый сетевой диск','New drive mapping'),()=>open(null)));list.append(tools);
  if(section.disabled)list.append(el('p','alert error',t('Все записи «Сетевые диски» в этом разделе отключены.','All Drive Maps items in this scope are disabled.')));
  if(admin){const form=el('form','workspace-form drive-scope-form'),l=el('label','',t('Предпочтения сетевых дисков включены','Drive Maps preferences enabled')),enabled=el('input');enabled.type='checkbox';enabled.checked=!section.disabled;enabled.addEventListener('change',()=>onDirty(true));l.prepend(enabled);form.append(l);const confirm=confirmation(form),save=el('button','',t('Применить состояние раздела','Apply preferences state'));save.type='submit';form.append(save);form.addEventListener('submit',e=>{e.preventDefault();if(confirm.reportValidity())mutate({operation:'set-disabled',disabled:!enabled.checked});});list.append(form);}
  if(entries.length){const wrap=el('div','drive-maps-scroll'),table=el('table','drive-maps-table'),head=el('thead'),row=el('tr');for(const label of [t('Диск','Drive'),t('Путь','Path'),t('Действие','Action'),t('Состояние','State')])row.append(el('th','',label));head.append(row);const body=el('tbody');table.append(head,body);wrap.append(table);list.append(wrap);
   for(const item of entries){const row=el('tr'),name=el('td');name.append(button(item.label||item.letter+':',()=>open(item)));row.append(name,el('td','mono',item.path),el('td','',actions[item.action]||item.action),el('td','',item.disabled?t('Отключена','Disabled'):t('Включена','Enabled')));body.append(row);}
  }else list.append(el('p','muted',t('Сетевые диски не назначены.','No drive mappings assigned.')));
  const help=el('div','drive-maps-help');help.append(el('h4','',t('Применение на ALT Linux','Applying on ALT Linux')),el('p','',t('Механизм CIFS для пользователей включается в конфигурации компьютера; ссылка в домашнем каталоге — в конфигурации пользователя. Привяжите GPO к нужным OU и проверьте результат на клиенте.','Enable the user CIFS engine in Computer Configuration and the home-directory link in User Configuration. Link the GPO to the relevant OUs and verify it on the client.')));
  help.append(button(t('Настроить механизм CIFS для пользователей','Configure user CIFS engine'),()=>onConfigure('Machine','CIFSApplierUser')),button(t('Настроить ссылку в домашнем каталоге','Configure home-directory link'),()=>onConfigure('User','DriveMapsHomeUser')));list.append(help);
  return {open};
 };
})();
