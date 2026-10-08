/* /cv/ e /cv/en/: tema, menu, seção ativa, troca de idioma com âncora e posts do blog. */
(function () {
  'use strict';

  var root = document.documentElement;

  /* Tema */
  var themeBtn = document.querySelector('.theme-btn');

  function currentTheme() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function syncThemeButton() {
    if (!themeBtn) return;
    var dark = currentTheme() === 'dark';
    themeBtn.setAttribute('aria-label', dark ? themeBtn.dataset.toLight : themeBtn.dataset.toDark);
  }

  if (themeBtn) {
    syncThemeButton();
    themeBtn.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('cv-theme', next); } catch (e) { /* sem storage, segue sem salvar */ }
      syncThemeButton();
    });
  }

  /* Se a pessoa nunca escolheu, acompanha mudança do sistema */
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function (e) {
      var saved = null;
      try { saved = localStorage.getItem('cv-theme'); } catch (err) {}
      if (saved !== 'light' && saved !== 'dark') {
        root.setAttribute('data-theme', e.matches ? 'dark' : 'light');
        syncThemeButton();
      }
    };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  /* Menu no celular */
  var menuBtn = document.querySelector('.menu-btn');
  var nav = document.getElementById('cv-nav');

  function closeMenu() {
    if (!menuBtn || !nav) return;
    nav.classList.remove('is-open');
    menuBtn.setAttribute('aria-expanded', 'false');
  }

  if (menuBtn && nav) {
    menuBtn.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open');
      menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    nav.addEventListener('click', function (e) {
      if (e.target.closest('a')) closeMenu();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('is-open')) {
        closeMenu();
        menuBtn.focus();
      }
    });
  }

  /* Troca de idioma mantém a seção: /cv/#career -> /cv/en/#career */
  var langLink = document.querySelector('[data-lang-switch]');
  var langBase = langLink ? langLink.getAttribute('href').split('#')[0] : '';
  var activeId = '';

  function setLangHash(id) {
    if (!langLink) return;
    langLink.setAttribute('href', id ? langBase + '#' + id : langBase);
  }

  if (langLink) {
    window.addEventListener('hashchange', function () {
      setLangHash(window.location.hash.replace('#', ''));
    });
    setLangHash(window.location.hash.replace('#', ''));
  }

  /* Seção ativa na nav, conforme o scroll */
  var navLinks = Array.prototype.slice.call(document.querySelectorAll('.nav a[data-section]'));
  var sections = Array.prototype.slice.call(document.querySelectorAll('main > section[id]'));
  /* evidence e stack não estão na nav: destacam o item anterior (Sobre) */
  var navFor = { evidence: 'about', stack: 'about' };

  function markActive(id) {
    if (id === activeId) return;
    activeId = id;
    var navId = navFor[id] || id;
    navLinks.forEach(function (a) {
      if (a.dataset.section === navId) a.setAttribute('aria-current', 'true');
      else a.removeAttribute('aria-current');
    });
    setLangHash(id === 'about' ? '' : id);
  }

  if ('IntersectionObserver' in window && sections.length) {
    var visible = {};
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { visible[en.target.id] = en.isIntersecting; });
      for (var i = 0; i < sections.length; i++) {
        if (visible[sections[i].id]) { markActive(sections[i].id); break; }
      }
    }, { rootMargin: '-35% 0px -60% 0px', threshold: 0 });
    sections.forEach(function (s) { io.observe(s); });
  }

  /* Posts do blog via /feed.xml (Atom do Chirpy; aceita RSS também) */
  var box = document.querySelector('.posts[data-feed]');
  if (box && window.fetch && window.DOMParser) {
    var status = box.querySelector('.posts-status');
    var list = box.querySelector('.post-list');
    var locale = box.dataset.locale || 'pt-BR';
    status.hidden = false;

    fetch(box.dataset.feed, { headers: { Accept: 'application/atom+xml, application/rss+xml, application/xml' } })
      .then(function (r) {
        if (!r.ok) throw new Error('feed ' + r.status);
        return r.text();
      })
      .then(function (xml) {
        var doc = new DOMParser().parseFromString(xml, 'application/xml');
        if (doc.getElementsByTagName('parsererror').length) throw new Error('feed inválido');
        var nodes = doc.getElementsByTagName('entry');
        if (!nodes.length) nodes = doc.getElementsByTagName('item');
        var max = Math.min(nodes.length, 3);
        for (var i = 0; i < max; i++) {
          var n = nodes[i];
          var title = text(n, 'title');
          var linkEl = n.getElementsByTagName('link')[0];
          var href = linkEl ? (linkEl.getAttribute('href') || linkEl.textContent) : '';
          var when = text(n, 'published') || text(n, 'updated') || text(n, 'pubDate');
          if (!title || !href) continue;
          var li = document.createElement('li');
          var a = document.createElement('a');
          a.href = href;
          a.textContent = title;
          li.appendChild(a);
          var d = when ? new Date(when) : null;
          if (d && !isNaN(d)) {
            var t = document.createElement('time');
            t.dateTime = d.toISOString();
            t.textContent = d.toLocaleDateString(locale, { day: 'numeric', month: 'short', year: 'numeric' });
            li.appendChild(t);
          }
          list.appendChild(li);
        }
        status.hidden = true;
        if (list.children.length) list.hidden = false;
      })
      .catch(function () {
        /* Falhou ou não tem post: fica só o link "Ver todos os posts" */
        status.hidden = true;
      });
  }

  function text(node, tag) {
    var el = node.getElementsByTagName(tag)[0];
    return el ? el.textContent.trim() : '';
  }
})();
