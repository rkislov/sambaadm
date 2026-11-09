(function () {
  'use strict';
  var menu = document.querySelector('.app-navigation');
  if (!menu) return;
  document.addEventListener('click', function (event) { if (!menu.contains(event.target)) menu.open = false; });
  document.addEventListener('keydown', function (event) { if (event.key === 'Escape' && menu.open) { menu.open = false; menu.querySelector('summary').focus(); } });
})();
