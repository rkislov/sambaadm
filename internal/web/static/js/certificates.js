(function () {
  'use strict';
  document.querySelectorAll('[data-pem-target]').forEach(function (input) {
    input.addEventListener('change', async function () {
      var file = input.files[0]; if (!file) return;
      if (file.size > 256 * 1024) { input.setCustomValidity('Размер PEM-файла должен быть не больше 256 КБ'); input.reportValidity(); return; }
      input.setCustomValidity('');
      try { document.getElementById(input.dataset.pemTarget).value = await file.text(); }
      catch (_) { input.setCustomValidity('Не удалось прочитать файл'); input.reportValidity(); }
    });
  });
  var mode = document.querySelector('[data-helper-key-mode]');
  var csr = document.querySelector('[data-helper-csr]');
  if (mode && csr) {
    function updateMode() { csr.hidden = mode.value === 'generate'; csr.querySelectorAll('input,textarea').forEach(function (input) { input.disabled = csr.hidden; }); csr.querySelector('textarea').required = !csr.hidden; }
    mode.addEventListener('change', updateMode); updateMode();
  }
  var ldapCSR = document.querySelector('[data-ldap-csr]');
  if (ldapCSR) {
    function updateLDAPMode() {
      ldapCSR.hidden = document.querySelector('input[name="key_mode"]:checked').value === 'generate';
      ldapCSR.querySelectorAll('input,textarea').forEach(function (input) { input.disabled = ldapCSR.hidden; });
      ldapCSR.querySelector('textarea').required = !ldapCSR.hidden;
    }
    document.querySelectorAll('input[name="key_mode"]').forEach(function (input) { input.addEventListener('change', updateLDAPMode); });
    updateLDAPMode();
  }
  document.querySelectorAll('[data-copy-command]').forEach(function (button) {
    button.addEventListener('click', async function () {
      var code = document.getElementById(button.dataset.copyCommand);
      var status = button.nextElementSibling;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(code.textContent);
        } else {
          var range = document.createRange(); range.selectNodeContents(code);
          var selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
          if (!document.execCommand('copy')) throw new Error('copy');
          selection.removeAllRanges();
        }
        status.textContent = 'Скопировано';
      } catch (_) { status.textContent = 'Выделите команды и нажмите Ctrl+C'; }
    });
  });

  var rollout=document.querySelector('[data-certificate-rollout]');
  if(rollout){
    var plan=rollout.querySelector('[data-rollout-plan]'),notice=rollout.querySelector('[data-rollout-message]'),jobs=rollout.querySelector('[data-rollout-jobs]'),busy=false,timer;
    var phases={planned:'План готов',prepared:'Проверен, ключ создан',pending:'Ожидает проверки',unverified:'Состояние не подтверждено',blocked:'План заблокирован',running:'Выполняется',interrupted:'Прервано',failed:'Ошибка',error:'Ошибка',trusted:'Доверие установлено',installed:'Сертификат установлен',complete:'Все DC проверены','running-trust':'Установка доверия','running-install':'Установка сертификата','rolled-back':'Выполнен откат'};
    function make(tag,text){var e=document.createElement(tag);if(text)e.textContent=text;return e;}
    async function api(body){var response=await fetch('/api/v1/certificates/rollouts',{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('input[name=csrf_token]').value}:{},body:body?JSON.stringify(body):undefined});var result=await response.json();if(!response.ok)throw new Error(result.error||'Ошибка запроса');return result;}
    function render(list){jobs.replaceChildren();(list||[]).slice(0,10).forEach(function(job){var box=make('section'),title=make('h3',new Date(job.created).toLocaleString(document.documentElement.lang||'ru')+' · '+(phases[job.status]||job.status));box.append(title,make('p','План: '+job.id));if(job.error)box.append(make('p',job.error));var wrap=make('div');wrap.style.overflowX='auto';var table=make('table'),head=make('tr');['Контроллер','Состояние','Действует до','Результат'].forEach(function(text){head.append(make('th',text));});table.append(head);
      job.nodes.forEach(function(node){var row=make('tr');[node.node,phases[node.phase]||node.phase,node.expires&&!node.expires.startsWith('0001')?new Date(node.expires).toLocaleString(document.documentElement.lang||'ru'):'—',node.error||''].forEach(function(value){row.append(make('td',value));});table.append(row);});wrap.append(table);box.append(wrap);
      if(['planned','interrupted','failed'].includes(job.status)){var label=make('label',' Подтверждаю последовательные перезапуски Samba на всех DC и установку доверия к локальному УЦ.'),confirm=make('input');confirm.type='checkbox';label.prepend(confirm);var apply=make('button',job.status==='planned'?'Применить план на всех DC':'Сверить состояние и продолжить');apply.disabled=true;confirm.addEventListener('change',function(){apply.disabled=!confirm.checked;});apply.addEventListener('click',function(){operate({action:'apply',id:job.id,confirm:true});});var controls=make('div');controls.className='setup-options';label.className='session-auth-choice';controls.append(label,apply);box.append(controls);}
      if(['failed','interrupted','rolled-back','complete'].includes(job.status)){job.nodes.forEach(function(node){if(!node.error&&(!node.state||!['trusted','installed','failed','applying','rolling-back'].includes(node.state.phase)))return;var label=make('label',' Подтверждаю возврат исходных TLS-настроек '+node.node),confirm=make('input');confirm.type='checkbox';label.prepend(confirm);var rollback=make('button','Откатить '+node.node);rollback.disabled=true;confirm.addEventListener('change',function(){rollback.disabled=!confirm.checked;});rollback.addEventListener('click',function(){operate({action:'rollback',id:job.id,node:node.node,confirm:true});});var controls=make('div');controls.className='setup-options';label.className='session-auth-choice';controls.append(label,rollback);box.append(controls);});}
      jobs.append(box);
    });}
    async function refresh(){try{var list=await api();render(list);clearTimeout(timer);if((list||[]).some(function(job){return job.status==='running';}))timer=setTimeout(refresh,2000);}catch(err){notice.textContent=err.message;}}
    async function operate(body){if(busy)return;busy=true;plan.querySelector('button').disabled=true;notice.textContent=body.action==='plan'?'Проверка всех DC и подготовка ключей…':'Запрос выполняется…';try{var job=await api(body);notice.textContent=job.status==='blocked'?'План заблокирован. Исправьте ошибки на указанных DC и подготовьте новый план.':body.action==='plan'?'Проверьте список DC и фактические даты окончания сертификатов.':'Запрос принят.';await refresh();}catch(err){notice.textContent=err.message;}finally{busy=false;plan.querySelector('button').disabled=false;}}
    plan.addEventListener('submit',function(e){e.preventDefault();operate({action:'plan',years:plan.querySelector('select').value,renewCA:plan.querySelector('[name=renewCA]').checked});});refresh();
  }
})();
