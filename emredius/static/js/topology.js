// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  var NS = 'http://www.w3.org/2000/svg';
  var svg = document.getElementById('topoSvg'), info = document.getElementById('topoInfo');
  var gRoot = document.createElementNS(NS, 'g'), gE = document.createElementNS(NS, 'g'), gN = document.createElementNS(NS, 'g');
  gRoot.appendChild(gE); gRoot.appendChild(gN); svg.appendChild(gRoot);
  var nodes = [], edges = [], byId = {}, view = {x: 0, y: 0, k: 1}, focus = null, depth = 1, drag = null, pan = null, alpha = 0;
  var ICON = {'IP Telefon': '☎', 'Switch': '⇄', 'Router': '⬤', 'Firewall': '▦', 'Access Point': '◉', 'Sunucu': '▤', 'Ağ Cihazı': '◆', 'Bilinmiyor': '?'};
  var COLOR = {'IP Telefon': '#db2777', 'Switch': '#2563eb', 'Router': '#7c3aed', 'Firewall': '#dc2626', 'Access Point': '#0891b2', 'Sunucu': '#15803d', 'Ağ Cihazı': '#b45309', 'Bilinmiyor': '#64748b'};
  function el(n, a) { var e = document.createElementNS(NS, n); for (var k in a) e.setAttribute(k, a[k]); return e; }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function size() { var r = svg.getBoundingClientRect(); return [r.width || 800, r.height || 560]; }

  function load(first) {
    var q = document.getElementById('topoQ').value;
    fetch('/topology/data?q=' + encodeURIComponent(q)).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) return;
      var old = byId, sz = size();
      nodes = j.nodes.map(function (n) {
        var o = old[n.id];
        n.x = o ? o.x : sz[0] / 2 + (Math.random() - 0.5) * 300; n.y = o ? o.y : sz[1] / 2 + (Math.random() - 0.5) * 300;
        n.vx = 0; n.vy = 0; n.fixed = o ? o.fixed : false; return n;
      });
      byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
      edges = j.edges.map(function (e) { e.s = byId[e.source]; e.t = byId[e.target]; return e; });
      var s = j.stats;
      document.getElementById('topoStats').textContent = s.nodes + ' düğüm · ' + s.edges + ' bağlantı · ' + s.unknown + ' bilinmeyen' + (s.running ? ' · taranıyor…' : '');
      document.getElementById('topoEmpty').style.display = nodes.length ? 'none' : 'flex';
      if (focus && !byId[focus]) focus = null;
      build(); alpha = first || !Object.keys(old).length ? 1 : 0.3; tick();
    }).catch(function () {});
  }

  function visibleSet() {
    if (!focus) return null;
    var vis = {}, front = [focus]; vis[focus] = 1;
    for (var d = 0; d < depth; d++) {
      var nx = [];
      edges.forEach(function (e) {
        if (vis[e.source] && !vis[e.target]) { vis[e.target] = 1; nx.push(e.target); }
        if (vis[e.target] && !vis[e.source]) { vis[e.source] = 1; nx.push(e.source); }
      });
      front = nx;
    }
    return vis;
  }

  function build() {
    gE.innerHTML = ''; gN.innerHTML = '';
    var vis = visibleSet();
    edges.forEach(function (e) {
      if (vis && !(vis[e.source] && vis[e.target])) { e.g = null; return; }
      var g = el('g', {style: 'cursor:pointer'});
      e.line = el('line', {stroke: e.protocols.length > 1 ? '#0891b2' : '#94a3b8', 'stroke-width': 2});
      var hit = el('line', {stroke: 'transparent', 'stroke-width': 12});
      e.hit = hit; g.appendChild(e.line); g.appendChild(hit);
      g.addEventListener('click', function (ev) { ev.stopPropagation(); showEdge(e); });
      var tt = el('title', {}); tt.textContent = e.source_port + ' ↔ ' + e.target_port; g.appendChild(tt);
      e.g = g; gE.appendChild(g);
    });
    nodes.forEach(function (n) {
      if (vis && !vis[n.id]) { n.g = null; return; }
      var g = el('g', {style: 'cursor:grab'}), c = COLOR[n.type] || COLOR['Bilinmiyor'];
      var r = 14 + Math.min(n.degree, 8);
      var sq = n.type === 'Router' || n.type === 'Switch';
      var shp = {fill: c, 'fill-opacity': n.known ? 0.9 : 0.35, stroke: n.status === 'OFFLINE' ? '#dc2626' : (n.match ? '#f59e0b' : c), 'stroke-width': n.match || n.id === focus ? 4 : 2};
      if (sq) { shp.x = -r; shp.y = -r; shp.width = 2 * r; shp.height = 2 * r; shp.rx = 3; } else shp.r = r;
      g.appendChild(el(sq ? 'rect' : 'circle', shp));
      var ic = el('text', {'text-anchor': 'middle', dy: '0.35em', fill: '#fff', 'font-size': 14}); ic.textContent = ICON[n.type] || '?'; g.appendChild(ic);
      var lb = el('text', {'text-anchor': 'middle', y: r + 14, 'font-size': 12, fill: 'currentColor', style: 'fill:var(--text-primary)'}); lb.textContent = n.label; g.appendChild(lb);
      g.addEventListener('mousedown', function (ev) { ev.stopPropagation(); drag = n; n.fixed = true; });
      g.addEventListener('click', function (ev) { ev.stopPropagation(); focus = n.id; depth = 1; showNode(n); build(); tick(); });
      g.addEventListener('dblclick', function (ev) { ev.stopPropagation(); focus = n.id; depth++; build(); alpha = 0.6; tick(); });
      n.g = g; gN.appendChild(g);
    });
    draw();
  }

  function step() {
    var vis = visibleSet(), act = nodes.filter(function (n) { return n.g; }), sz = size(), cx = sz[0] / 2, cy = sz[1] / 2, i, j;
    for (i = 0; i < act.length; i++) {
      var a = act[i];
      for (j = i + 1; j < act.length; j++) {
        var b = act[j], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01, f = 6000 / d2, d = Math.sqrt(d2);
        a.vx += dx / d * f; a.vy += dy / d * f; b.vx -= dx / d * f; b.vy -= dy / d * f;
      }
      a.vx += (cx - a.x) * 0.002; a.vy += (cy - a.y) * 0.002;
    }
    edges.forEach(function (e) {
      if (!e.g) return;
      var dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 130) * 0.02;
      e.s.vx += dx / d * f; e.s.vy += dy / d * f; e.t.vx -= dx / d * f; e.t.vy -= dy / d * f;
    });
    act.forEach(function (n) { if (n.fixed) { n.vx = n.vy = 0; return; } n.x += n.vx * alpha; n.y += n.vy * alpha; n.vx *= 0.6; n.vy *= 0.6; });
  }

  function draw() {
    gRoot.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')');
    edges.forEach(function (e) {
      if (!e.g) return;
      [e.line, e.hit].forEach(function (l) { l.setAttribute('x1', e.s.x); l.setAttribute('y1', e.s.y); l.setAttribute('x2', e.t.x); l.setAttribute('y2', e.t.y); });
    });
    nodes.forEach(function (n) { if (n.g) n.g.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')'); });
  }

  var raf = 0;
  function tick() {
    if (raf) return;
    (function loop() {
      step(); draw(); alpha *= 0.985;
      raf = (alpha > 0.02 || drag) ? requestAnimationFrame(loop) : 0;
    })();
  }

  function row(k, v) { return v ? '<div><b>' + esc(k) + ':</b> ' + esc(v) + '</div>' : ''; }
  function showNode(n) {
    var nb = [];
    edges.forEach(function (e) {
      if (e.source === n.id) nb.push(e.source_port + ' → ' + e.t.label + ' (' + e.target_port + ')');
      else if (e.target === n.id) nb.push(e.target_port + ' → ' + e.s.label + ' (' + e.source_port + ')');
    });
    info.innerHTML = '<h4 style="margin:0 0 .5rem;">' + esc(n.label) + '</h4>' + row('Tür', n.type + (n.manual ? ' (elle)' : '')) + row('IP', n.ip) + row('MAC', n.mac) +
      row('Üretici', n.vendor) + row('Model', n.model) + row('Durum', n.status === 'ONLINE' ? 'Aktif' : n.status === 'OFFLINE' ? 'Pasif' : 'Envanterde yok') +
      '<div style="margin-top:.5rem;"><b>Komşular (' + nb.length + ')</b></div><ul style="padding-left:1.1rem;margin:.25rem 0;">' + nb.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>' +
      (n.ip ? '<a class="btn" href="/inventory?q=' + encodeURIComponent(n.ip) + '">Aktif Cihazlar\'da aç</a> ' : '') +
      (n.mac ? '<a class="btn" href="/macs?q=' + encodeURIComponent(n.mac) + '">MAC kaydı</a>' : '') + typePicker(n);
    bindType(n);
  }
  var TYPES = ['Router', 'Switch', 'IP Telefon', 'Firewall', 'Access Point', 'Sunucu', 'Ağ Cihazı', 'Bilinmiyor'];
  function typePicker(n) {
    var opts = '<option value="auto"' + (n.manual ? '' : ' selected') + '>Otomatik (' + esc(n.auto_type) + ')</option>' +
      TYPES.map(function (t) { return '<option' + (n.manual && n.type === t ? ' selected' : '') + '>' + esc(t) + '</option>'; }).join('');
    return '<div style="margin:.5rem 0;"><label><b>Tür (elle):</b></label> <select id="topoType">' + opts + '</select></div>';
  }
  function bindType(n) {
    var s = document.getElementById('topoType'); if (!s) return;
    s.addEventListener('change', function () {
      var t = document.querySelector('input[name="_csrf_token"]');
      fetch('/topology/type', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': t ? t.value : ''},
        body: JSON.stringify({node: n.id, type: s.value})}).then(function (r) { return r.json(); }).then(function (j) {
        if (!j.success) alert(j.error); else load(false);
      });
    });
  }
  function showEdge(e) {
    info.innerHTML = '<h4 style="margin:0 0 .5rem;">Bağlantı</h4>' + row(e.s.label, e.source_port) + row(e.t.label, e.target_port) +
      row('Protokol', e.protocols.join(' + ')) + row('Son görülme', e.last_seen);
  }

  svg.addEventListener('mousedown', function (ev) { pan = {x: ev.clientX - view.x, y: ev.clientY - view.y}; });
  window.addEventListener('mousemove', function (ev) {
    if (drag) { var r = svg.getBoundingClientRect(); drag.x = (ev.clientX - r.left - view.x) / view.k; drag.y = (ev.clientY - r.top - view.y) / view.k; alpha = Math.max(alpha, 0.3); tick(); draw(); }
    else if (pan) { view.x = ev.clientX - pan.x; view.y = ev.clientY - pan.y; draw(); }
  });
  window.addEventListener('mouseup', function () { drag = null; pan = null; });
  svg.addEventListener('wheel', function (ev) {
    ev.preventDefault();
    var r = svg.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top, k = Math.max(0.2, Math.min(4, view.k * (ev.deltaY < 0 ? 1.15 : 0.87)));
    view.x = mx - (mx - view.x) * k / view.k; view.y = my - (my - view.y) * k / view.k; view.k = k; draw();
  }, {passive: false});
  svg.addEventListener('touchstart', function (ev) { var t = ev.touches[0]; pan = {x: t.clientX - view.x, y: t.clientY - view.y}; }, {passive: true});
  svg.addEventListener('touchmove', function (ev) { if (pan && ev.touches.length === 1) { view.x = ev.touches[0].clientX - pan.x; view.y = ev.touches[0].clientY - pan.y; draw(); } }, {passive: true});
  svg.addEventListener('touchend', function () { pan = null; });
  svg.addEventListener('click', function () { if (focus) { focus = null; build(); alpha = 0.3; tick(); } });

  document.getElementById('topoQ').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { load(false); } });
  document.getElementById('topoReset').addEventListener('click', function () {
    focus = null; depth = 1; view = {x: 0, y: 0, k: 1}; document.getElementById('topoQ').value = ''; load(false);
  });
  document.getElementById('topoScan').addEventListener('click', function () {
    fetch('/topology/discover', {method: 'POST'}).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.success) alert(j.error); else setTimeout(function () { load(false); }, 3000);
    });
  });
  load(true);
  setInterval(function () { if (!drag) load(false); }, 15000);
})();
