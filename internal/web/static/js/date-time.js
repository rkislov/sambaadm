/* Display timestamps in the browser timezone; wire formats stay unchanged. */
(function () {
  'use strict';
  window.sambaadmFormatTime = function (value) {
    if (value == null || value === '') return '—';
    let input = value;
    if (typeof input === 'string') {
      const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:[.,](\d+))?(Z|[+-]\d{4})$/.exec(input);
      if (m) {
        const [,y,mo,d,h,mi,s,f,z] = m;
        input = `${y}-${mo}-${d}T${h}:${mi}:${s}.${(f || '0').slice(0,3).padEnd(3,'0')}${z === 'Z' ? 'Z' : z.slice(0,3)+':'+z.slice(3)}`;
      }
    }
    const date = input instanceof Date ? input : new Date(input);
    if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 1601) return '—';
    return new Intl.DateTimeFormat(document.documentElement.lang === 'ru' ? 'ru-RU' : 'en-GB', {
      year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23', timeZoneName:'shortOffset'
    }).format(date);
  };
})();
