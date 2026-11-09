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
})();
