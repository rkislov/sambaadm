(function () {
  'use strict';
  const tree = document.getElementById('share-directory-tree');
  if (!tree) return;
  const tips = document.querySelector('details.tips');
  if (tips) tips.open = false;
  const node = new URLSearchParams(location.search).get('node');
  const share = tree.dataset.share;
  const selected = tree.dataset.selected || '.';
  function url(path, query = {}) {
    const u = new URL(path, location.origin);
    for (const [key, value] of Object.entries(query)) u.searchParams.set(key, value);
    if (node) u.searchParams.set('node', node);
    return u.pathname + u.search;
  }
  const endpoint = '/api/v1/shares/' + encodeURIComponent(share) + '/directories';
  const page = '/shares/' + encodeURIComponent(share) + '/acl';
  function el(tag, text) { const e = document.createElement(tag); e.textContent = text || ''; return e; }
  async function json(path) {
    const r = await fetch(path, {credentials: 'same-origin'});
    const data = await r.json();
    if (!r.ok) throw Error(data.error || 'HTTP ' + r.status);
    return data;
  }
  function branch(name, path) {
    const details = el('details');
    const summary = el('summary');
    const link = el('a', name);
    link.href = url(page, {path});
    if (path === selected || (path === '.' && selected === '')) link.setAttribute('aria-current', 'page');
    // The link selects a directory; the disclosure arrow expands its children.
    link.addEventListener('click', e => e.stopPropagation());
    summary.append(link);
    const children = el('div'); children.className = 'share-tree-children';
    details.append(summary, children);
    let loaded = false, loading = false;
    async function load(offset = 0) {
      if (loading) return;
      loading = true;
      const status = el('p', 'Загрузка…'); status.setAttribute('role', 'status'); children.append(status);
      try {
        const data = await json(url(endpoint, {path, offset}));
        status.remove();
        for (const dir of data.directories) children.append(branch(dir.name, dir.path));
        if (data.next) {
          const more = el('button', 'Показать ещё'); more.type = 'button';
          more.onclick = () => { more.remove(); load(data.next); };
          children.append(more);
        } else if (!children.children.length) children.append(el('p', 'Нет вложенных каталогов'));
        loaded = true;
      } catch (error) {
        status.textContent = error.message;
        const retry = el('button', 'Повторить'); retry.type = 'button';
        retry.onclick = () => { status.remove(); retry.remove(); load(offset); }; children.append(retry);
      } finally { loading = false; }
    }
    details.addEventListener('toggle', () => { if (details.open && !loaded) load(); });
    if (path === '.' || selected === path || selected.startsWith(path + '/')) details.open = true;
    return details;
  }
  tree.append(branch(share, '.'));
  const picker = document.getElementById('share-domain-group');
  if (!picker) return;
  const search = document.getElementById('share-group-search');
  const status = document.getElementById('share-group-status');
  let serial = 0, timer;
  async function groups() {
    const attempt = ++serial;
    status.textContent = 'Загрузка групп…';
    try {
      const entries = await json(url('/api/v1/groups', {q: search.value}));
      if (attempt !== serial) return;
      const chosen = picker.value, chosenText = picker.selectedOptions[0]?.textContent;
      picker.replaceChildren();
      const blank = el('option', 'Выберите группу или используйте ручной ввод ниже'); blank.value = ''; picker.append(blank);
      for (const group of entries.filter(g => g.category === 'security')) {
        const option = el('option', group.samAccountName + (group.description ? ' — ' + group.description : ''));
        option.value = group.samAccountName; picker.append(option);
      }
      if (chosen && ![...picker.options].some(o => o.value === chosen)) { const option = el('option', chosenText); option.value = chosen; picker.append(option); }
      picker.value = chosen;
      status.textContent = 'Показаны группы безопасности AD. При сохранении группа проверяется на выбранном сервере.';
    } catch (error) { if (attempt === serial) status.textContent = error.message; }
  }
  search.addEventListener('input', () => { ++serial; clearTimeout(timer); timer = setTimeout(groups, 250); });
  picker.addEventListener('change', () => {
    const form = picker.closest('form');
    form.elements.acl_scope.value = 'access';
    for (const name of ['acl_kind', 'acl_name', 'acl', 'acl_scope']) form.elements[name].disabled = Boolean(picker.value);
  });
  const aclForm=picker.closest('form');
  function keepDirectorySearch(){
    if(tree.dataset.isDir==='false')return;
    const fields=aclForm.elements;
    if(fields.acl_r.checked||fields.acl_w.checked)fields.acl_x.checked=true;
    fields.acl_x.setAttribute('aria-description','Для чтения и записи каталогов нужен проход x');
  }
  for(const permission of ['r','w','x'])aclForm.elements['acl_'+permission].addEventListener('change',keepDirectorySearch);
  for (const button of document.querySelectorAll('.share-acl-edit,.share-acl-remove')) {
    button.addEventListener('click', () => {
      const form = picker.closest('form'), fields = form.elements, data = button.dataset;
      picker.value = ''; picker.dispatchEvent(new Event('change'));
      fields.acl.value = ''; fields.default_acl.value = ''; fields.remove_acl.value = '';
      fields.group_default.checked = false;
      fields.acl_scope.value = data.default === 'true' ? 'default' : 'access';
      if (button.classList.contains('share-acl-remove')) {
        // POSIX owner, owning group, mask and other entries are mandatory.
        if (!data.name && ['user', 'group', 'other', 'mask'].includes(data.kind)) {
          status.textContent = 'Базовую запись нельзя удалить. Измените её права.'; return;
        }
        fields.acl_kind.value = '';
        fields.remove_acl.value = (data.default === 'true' ? 'd:' : '') + data.kind + ':' + data.name;
      } else {
        fields.acl_kind.value = data.kind; fields.acl_name.value = data.name;
        for (const permission of ['r', 'w', 'x']) fields['acl_' + permission].checked = data.perms.includes(permission);
        keepDirectorySearch();
      }
      form.scrollIntoView({behavior:'smooth', block:'start'});
    });
  }
  groups();
})();
