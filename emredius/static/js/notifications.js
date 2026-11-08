// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Üst çubuk bildirim paneli (çan): kullanıcının gelen kutusunu yoklar, tıklanınca kaynağa götürür.
(function () {
  var btn = document.getElementById('notifBtn');
  var panel = document.getElementById('notifPanel');
  if (!btn || !panel) return;
  var badge = document.getElementById('notifBadge');
  var list = document.getElementById('notifList');
  var token = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  var ICON = { info: 'fa-circle-info', success: 'fa-circle-check', warning: 'fa-triangle-exclamation', danger: 'fa-circle-xmark' };
  var COLOR = { info: '#2563eb', success: '#16a34a', warning: '#d97706', danger: '#dc2626' };
  var items = [], lastUnread = null;

  function ago(ts) {
    var s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return 'şimdi';
    if (s < 3600) return Math.floor(s / 60) + ' dk önce';
    if (s < 86400) return Math.floor(s / 3600) + ' sa önce';
    return new Date(ts * 1000).toLocaleString('tr-TR');
  }

  function render(unread) {
    badge.textContent = unread > 99 ? '99+' : String(unread);
    badge.classList.toggle('on', unread > 0);
    var nb = document.getElementById('navNotifBadge');
    if (nb) { nb.textContent = unread > 99 ? '99+' : String(unread); nb.hidden = unread <= 0; }
    btn.setAttribute('aria-label', 'Bildirimler' + (unread ? ' (' + unread + ' okunmamış)' : ''));
    list.textContent = '';
    if (!items.length) {
      var e = document.createElement('div');
      e.className = 'notif-empty';
      e.textContent = 'Okunmamış bildiriminiz yok.';
      list.appendChild(e);
      return;
    }
    items.forEach(function (n) {
      var a = document.createElement('a');
      a.className = 'notif-item' + (n.read ? '' : ' unread');
      a.href = n.link || '#';
      a.setAttribute('data-id', n.id);
      var i = document.createElement('i');
      i.className = 'fa-solid ' + (ICON[n.severity] || ICON.info);
      i.style.color = COLOR[n.severity] || COLOR.info;
      i.style.marginTop = '.2rem';
      var box = document.createElement('div');
      box.style.minWidth = '0';
      [['ni-title', n.title], ['ni-body', n.body], ['ni-time', ago(n.ts)]].forEach(function (p) {
        if (!p[1]) return;
        var d = document.createElement('div');
        d.className = p[0];
        d.textContent = p[1];
        box.appendChild(d);
      });
      a.appendChild(i);
      a.appendChild(box);
      list.appendChild(a);
    });
  }

  function load() {
    return fetch('/api/notifications?status=unread&limit=30', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        items = d.items || [];
        if (lastUnread !== null && d.unread > lastUnread && window.EM && items.length) {
          var n = items.filter(function (x) { return !x.read; })[0];
          if (n) window.EM.toast(n.title, n.severity);
        }
        lastUnread = d.unread;
        render(d.unread);
      })
      .catch(function () {});
  }

  function post(body) {
    return fetch('/api/notifications/read', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: JSON.stringify(body)
    }).catch(function () {});
  }

  function setOpen(open) {
    panel.classList.toggle('open', open);
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) load();
  }
  btn.addEventListener('click', function (e) { e.stopPropagation(); setOpen(!panel.classList.contains('open')); });
  document.addEventListener('click', function (e) { if (!panel.contains(e.target) && e.target !== btn) setOpen(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') setOpen(false); });

  document.getElementById('notifReadAll').addEventListener('click', function () {
    post({ all: true }).then(load);
  });

  list.addEventListener('click', function (e) {
    var a = e.target.closest('a.notif-item');
    if (!a) return;
    e.preventDefault();
    var href = a.getAttribute('href');
    post({ ids: [a.getAttribute('data-id')] }).then(function () {
      setOpen(false);
      if (!href || href === '#') return load();
      var samePath = href.split('?')[0] === location.pathname;
      if (samePath && window.EM) window.EM.go(href); else location.href = href;
    });
  });

  load();
  setInterval(function () { if (!document.hidden) load(); }, 30000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) load(); });
})();
