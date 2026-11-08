// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Bildirimler sayfası: tüm bildirimler (okunmuş/okunmamış), süzgeç, sayfa yenilemeden okundu yapma.
(function () {
  var list = document.getElementById('npList');
  if (!list) return;
  var more = document.getElementById('npMore');
  var empty = document.getElementById('npEmpty');
  var PAGE = 30;
  var status = 'all', offset = 0;
  var token = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  var ICON = { info: 'fa-circle-info', success: 'fa-circle-check', warning: 'fa-triangle-exclamation', danger: 'fa-circle-xmark' };
  var COLOR = { info: '#2563eb', success: '#16a34a', warning: '#d97706', danger: '#dc2626' };
  var SOURCE = { ipscan: 'IP Tarama', snmp: 'SNMP', inventory: 'Aktif Cihazlar', alarms: 'Alarmlar' };

  function post(body) {
    return fetch('/api/notifications/read', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: JSON.stringify(body)
    });
  }

  function row(n) {
    var el = document.createElement('div');
    el.className = 'np-item' + (n.read ? '' : ' unread');
    el.setAttribute('data-id', n.id);
    var i = document.createElement('i');
    i.className = 'fa-solid ' + (ICON[n.severity] || ICON.info);
    i.style.color = COLOR[n.severity] || COLOR.info;
    var box = document.createElement('div');
    box.className = 'np-main';
    var t = document.createElement('div');
    t.className = 'ni-title';
    t.textContent = n.title;
    box.appendChild(t);
    if (n.body) { var b = document.createElement('div'); b.className = 'ni-body'; b.textContent = n.body; box.appendChild(b); }
    var meta = document.createElement('div');
    meta.className = 'ni-time';
    meta.textContent = new Date(n.ts * 1000).toLocaleString('tr-TR') + (SOURCE[n.page] ? ' · ' + SOURCE[n.page] : '');
    box.appendChild(meta);
    var act = document.createElement('div');
    act.className = 'np-actions';
    if (n.link) {
      var go = document.createElement('a');
      go.className = 'btn btn-sm btn-secondary np-go';
      go.href = n.link;
      go.innerHTML = '<i class="fa-solid fa-arrow-up-right-from-square"></i> Git';
      act.appendChild(go);
    }
    if (!n.read) {
      var rd = document.createElement('button');
      rd.type = 'button';
      rd.className = 'btn btn-sm btn-secondary np-read';
      rd.innerHTML = '<i class="fa-solid fa-check"></i> Okundu';
      act.appendChild(rd);
    }
    el.appendChild(i); el.appendChild(box); el.appendChild(act);
    return el;
  }

  function counts(d) {
    document.getElementById('npCntUnread').textContent = d.unread ? '(' + d.unread + ')' : '';
  }

  function load(reset) {
    if (reset) { offset = 0; list.textContent = ''; }
    return fetch('/api/notifications?status=' + status + '&limit=' + PAGE + '&offset=' + offset, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        d.items.forEach(function (n) { list.appendChild(row(n)); });
        offset += d.items.length;
        more.hidden = offset >= d.total;
        empty.hidden = list.children.length > 0;
        counts(d);
        if (status === 'all') document.getElementById('npCntAll').textContent = d.total ? '(' + d.total + ')' : '';
      });
  }

  document.querySelectorAll('.np-pill').forEach(function (p) {
    p.addEventListener('click', function () {
      document.querySelectorAll('.np-pill').forEach(function (x) { x.classList.remove('active'); });
      p.classList.add('active');
      status = p.getAttribute('data-status');
      load(true);
    });
  });
  more.addEventListener('click', function () { load(false); });

  document.getElementById('npReadAll').addEventListener('click', function () {
    post({ all: true }).then(function () { load(true); if (window.EM) window.EM.toast('Tüm bildirimler okundu yapıldı.', 'success'); });
  });

  list.addEventListener('click', function (e) {
    var item = e.target.closest('.np-item');
    if (!item) return;
    var id = item.getAttribute('data-id');
    var go = e.target.closest('a.np-go');
    var rd = e.target.closest('button.np-read');
    if (go) { e.preventDefault(); var href = go.getAttribute('href'); post({ ids: [id] }).then(function () { location.href = href; }); return; }
    if (rd) post({ ids: [id] }).then(function () { load(true); });
  });

  load(true);
})();
