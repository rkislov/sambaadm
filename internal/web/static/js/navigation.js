(function () {
  'use strict';
  const menu = document.querySelector('.app-navigation');
  if (menu) {
    document.addEventListener('click', event => {
      if (!menu.contains(event.target)) menu.open = false;
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && menu.open) {
        menu.open = false;
        menu.querySelector('summary').focus();
      }
    });
  }

  const main = document.querySelector('[data-console-sections]');
  const content = main?.querySelector('.console-sections');
  if (!content) return;
  const title = document.documentElement.lang === 'ru' ? 'В этом разделе' : 'In this section';
  const nav = document.createElement('nav');
  nav.className = 'console-sidebar console-tree console-section-links';
  nav.setAttribute('aria-label', title);
  const heading = document.createElement('h2');
  heading.textContent = title;
  nav.append(heading);
  const links = new Map();
  for (const section of content.children) {
    const label = section.dataset.consoleLabel || section.querySelector(':scope > h2')?.textContent.trim();
    if (!section.id || !label) continue;
    const link = document.createElement('a');
    link.className = 'console-link';
    link.href = '#' + section.id;
    link.textContent = label;
    links.set(link.hash, link);
    nav.append(link);
  }
  if (!links.size) return;
  const layout = document.createElement('div');
  layout.className = 'workspace-columns';
  content.before(layout);
  layout.append(nav, content);
  function selectLink() {
    const current = links.get(location.hash) || links.values().next().value;
    for (const link of links.values()) {
      if (link === current) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    }
  }
  selectLink();
  window.addEventListener('hashchange', selectLink);
})();
