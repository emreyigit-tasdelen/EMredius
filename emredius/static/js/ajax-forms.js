// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
/* Sayfa yenilemeden çalışma katmanı.
 *  - POST formları fetch ile gönderilir; sonuç sayfası alınıp yalnızca .content-body değiştirilir (EM.refresh / EM.swap).
 *  - JSON yanıt: mesaj toast olarak gösterilir, sayfa içeriği yenilenir. Dosya yanıtı: indirilir.
 *  - Sayfa betikleri (base dışındaki script src) yeniden çalıştırılırken önce eski belge/pencere dinleyicileri ve
 *    zamanlayıcıları temizlenir; DOMContentLoaded/load dinleyicileri doğrudan çağrılır.
 *  - Çıkış: form[data-noajax] veya target=_blank olan formlar normal gönderilir.
 *  - EM.toast(msg, type), EM.post(url, data), EM.refresh(), EM.go(url) herkese açık.
 */
(function () {
  'use strict';
  var BASE = /\/(csp-actions|security|theme|i18n_extra|i18n-now|app|ui-helpers|sidebar-scroll|ajax-forms|notifications|responsive-tables)\.js/;
  var HARD = /(?!)/;   // tam yükleme gerektiren betik kalmadı (dashboard/ntp/services var kullanıyor)
  var reg = [], timers = [], replaying = false;

  function pageScript(el) { return !!(el && el.src && !BASE.test(el.src)); }

  var origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (this === document || this === window) {
      if (replaying && (type === 'DOMContentLoaded' || type === 'load')) {
        var self = this;
        setTimeout(function () { try { fn.call(self, new Event(type)); } catch (e) { console.error(e); } }, 0);
        return;
      }
      if (pageScript(document.currentScript)) reg.push([this, type, fn, opts]);
    }
    return origAdd.call(this, type, fn, opts);
  };
  var origSetInterval = window.setInterval;
  window.setInterval = function () {
    var id = origSetInterval.apply(window, arguments);
    if (pageScript(document.currentScript)) timers.push(id);
    return id;
  };
  function teardown() {
    reg.forEach(function (r) { r[0].removeEventListener(r[1], r[2], r[3]); });
    timers.forEach(function (id) { clearInterval(id); });
    reg = []; timers = [];
  }

  /* ---------- toast ---------- */
  function toastBox() {
    var b = document.getElementById('emToasts');
    if (!b) {
      b = document.createElement('div');
      b.id = 'emToasts';
      b.className = 'em-toasts';
      b.setAttribute('role', 'status');
      b.setAttribute('aria-live', 'polite');
      document.body.appendChild(b);
    }
    return b;
  }
  function toast(msg, type) {
    if (!msg) return;
    var t = document.createElement('div');
    t.className = 'em-toast em-toast-' + (type || 'info');
    var ic = { success: 'fa-circle-check', danger: 'fa-circle-xmark', warning: 'fa-triangle-exclamation' }[type] || 'fa-circle-info';
    t.innerHTML = '<i class="fa-solid ' + ic + '"></i><span></span>';
    t.lastChild.textContent = msg;
    toastBox().appendChild(t);
    var kill = function () { t.classList.add('out'); setTimeout(function () { t.remove(); }, 180); };
    t.addEventListener('click', kill);
    setTimeout(kill, type === 'danger' ? 8000 : 4500);
  }

  /* ---------- sayfa değiştirme ---------- */
  function copyChrome(doc) {
    document.title = doc.title || document.title;
    var h1 = doc.getElementById('pageTitleText'), cur = document.getElementById('pageTitleText');
    if (h1 && cur) cur.textContent = h1.textContent;
    var active = doc.querySelector('.sidebar-nav .nav-item.active');
    document.querySelectorAll('.sidebar-nav .nav-item.active').forEach(function (a) { a.classList.remove('active'); });
    if (active) {
      var link = document.querySelector('.sidebar-nav .nav-item[href="' + active.getAttribute('href') + '"]');
      if (link) link.classList.add('active');
    }
    doc.querySelectorAll('head link[rel="stylesheet"]').forEach(function (l) {
      if (!document.querySelector('head link[href="' + l.getAttribute('href') + '"]')) document.head.appendChild(l.cloneNode());
    });
  }

  function runScripts(list, done) {
    var i = 0;
    replaying = true;
    (function next() {
      if (i >= list.length) { replaying = false; done && done(); return; }
      var src = list[i++], s = document.createElement('script');
      s.src = src;
      s.onload = s.onerror = next;
      document.body.appendChild(s);
    })();
  }

  /* hata sonrası: kullanıcının yazdığı değerleri yeni (sunucudan gelen) forma geri koy; parola alanları hariç */
  function refill(root, r) {
    var f = Array.prototype.filter.call(root.querySelectorAll('form'), function (x) { return x.getAttribute('action') === r.action; })[0];
    if (!f) return;
    r.fd.forEach(function (v, k) {
      if (k === '_csrf_token' || typeof v !== 'string') return;
      var els = f.querySelectorAll('[name="' + k.replace(/"/g, '') + '"]');
      Array.prototype.forEach.call(els, function (el) {
        if (el.type === 'password' || el.type === 'hidden' || el.type === 'file') return;
        if (el.type === 'checkbox' || el.type === 'radio') { if (el.value === v) el.setAttribute('checked', ''); }
        else if (el.tagName === 'SELECT') { Array.prototype.forEach.call(el.options, function (o) { o.selected = o.value === v; }); }
        else if (el.tagName === 'TEXTAREA') { el.textContent = v; }
        else el.setAttribute('value', v);
      });
    });
  }

  function swap(html, url, keepScroll, restore) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    var nb = doc.querySelector('.content-body'), cb = document.querySelector('.content-body');
    if (!nb || !cb) { location.href = url; return; }
    var srcs = [];
    doc.querySelectorAll('script[src]').forEach(function (s) {
      var u = s.getAttribute('src');
      if (!BASE.test(u) && srcs.indexOf(u) < 0 && !(s.closest('.sidebar,.topbar'))) srcs.push(u);
    });
    if (srcs.some(function (u) { return HARD.test(u); })) { location.href = url; return; }
    var y = window.scrollY;
    teardown();
    var failed = false;
    nb.querySelectorAll(':scope > .alert:not(#timesyncBanner)').forEach(function (a) {
      var m = /alert-(\w+)/.exec(a.className);
      if (m && (m[1] === 'danger' || m[1] === 'warning')) failed = true;
      toast(a.textContent.trim(), m ? m[1] : 'info');
      a.remove();
    });
    if (failed && restore) refill(nb, restore);
    copyChrome(doc);
    cb.innerHTML = nb.innerHTML;
    if (url && url !== location.href) history.pushState({ em: 1 }, '', url);
    runScripts(srcs, function () {
      if (keepScroll !== false) window.scrollTo(0, y);
      document.dispatchEvent(new CustomEvent('em:content'));
    });
  }

  function fetchPage(url, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.headers = Object.assign({ 'X-Requested-With': 'fetch', 'Accept': 'text/html,application/json' }, opts.headers || {});
    return fetch(url, opts);
  }

  function download(res) {
    var cd = res.headers.get('Content-Disposition') || '', m = /filename\*?=(?:UTF-8'')?"?([^";]+)/i.exec(cd);
    return res.blob().then(function (b) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(b);
      a.download = m ? decodeURIComponent(m[1]) : 'indirme';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
    });
  }

  /* yanıtı işle: html -> sayfayı değiştir, json -> toast + yenile, diğer -> indir */
  function handle(res, ctx) {
    if (res.redirected && /\/login(\?|$)/.test(res.url)) { location.href = res.url; return; }
    var ct = res.headers.get('Content-Type') || '';
    if (/json/.test(ct)) {
      return res.json().then(function (j) {
        var ok = j.success !== false && !j.error;
        toast(j.message || j.error || (ok ? 'İşlem tamamlandı.' : 'İşlem başarısız.'), ok ? 'success' : 'danger');
        if (j.redirect) { go(j.redirect); return j; }
        if (ok && ctx.refresh !== false) return refresh().then(function () { return j; });
        return j;
      });
    }
    if (/html/.test(ct)) return res.text().then(function (t) { swap(t, res.url, ctx.keepScroll !== false, ctx.restore); });
    return download(res);
  }

  function refresh() {
    return fetchPage(location.href).then(function (r) {
      var ct = r.headers.get('Content-Type') || '';
      if (/html/.test(ct)) return r.text().then(function (t) { swap(t, location.href, true); });
    });
  }
  function go(url) {
    return fetchPage(url).then(function (r) { return handle(r, { refresh: false, keepScroll: false }); })
      .catch(function () { location.href = url; });
  }
  function post(url, data) {
    var body = data instanceof FormData ? data : new URLSearchParams(data || {});
    var h = {};
    var tok = document.querySelector('meta[name="csrf-token"]');
    if (tok) h['X-CSRF-Token'] = tok.content;
    return fetchPage(url, { method: 'POST', body: body, headers: h }).then(function (r) { return handle(r, {}); });
  }

  /* ---------- form yakalama ---------- */
  window.addEventListener('submit', function (ev) {
    var f = ev.target;
    if (ev.defaultPrevented || !f || f.tagName !== 'FORM') return;
    var tgt = f.getAttribute('target');   // f.target kullanılmaz: name="target" olan input özelliği gölgeler
    var meth = (f.getAttribute('method') || 'get').toLowerCase();
    if (f.hasAttribute('data-noajax') || (tgt && tgt !== '_self')) return;
    if (!f.closest('.content-body') && !f.closest('.modal-backdrop')) return;
    if (meth === 'get') {                 // süzgeç/arama formları: yalnızca içerik yenilenir
      ev.preventDefault();
      var q = new URLSearchParams(new FormData(f)).toString(), base = f.getAttribute('action') || location.pathname;
      fetchPage(base + (q ? (base.indexOf('?') < 0 ? '?' : '&') + q : ''))
        .then(function (r) { return handle(r, { refresh: false, keepScroll: true }); })
        .catch(function () { toast('Sunucuya ulaşılamadı. Bağlantıyı kontrol edin.', 'danger'); });
      return;
    }
    if (meth !== 'post') return;
    ev.preventDefault();
    var btn = ev.submitter || f.querySelector('button[type="submit"],input[type="submit"]');
    var fd = new FormData(f);
    if (ev.submitter && ev.submitter.name) fd.set(ev.submitter.name, ev.submitter.value);
    var old = btn && btn.innerHTML;
    if (btn) { btn.disabled = true; btn.classList.add('is-busy'); }
    var hdr = {}, tok = document.querySelector('meta[name="csrf-token"]');
    if (tok) hdr['X-CSRF-Token'] = tok.content;
    fetchPage(f.getAttribute('action') || location.href, { method: 'POST', body: fd, headers: hdr })
      .then(function (r) { return handle(r, { restore: { action: f.getAttribute('action'), fd: fd } }); })
      .catch(function () { toast('Sunucuya ulaşılamadı. Bağlantıyı kontrol edin.', 'danger'); })
      .then(function () {
        if (btn && document.body.contains(btn)) { btn.disabled = false; btn.classList.remove('is-busy'); if (old != null) btn.innerHTML = old; }
      });
  });

  // security.js: durum değiştiren bağlantılar (sil/devre dışı/yeniden başlat ...) POST olarak, sayfa yenilemeden gider
  window.postNavigate = function (href) {
    var u = new URL(href, location.href);
    return post(u.pathname + u.search, {}).catch(function () { toast('Sunucuya ulaşılamadı.', 'danger'); });
  };

  window.addEventListener('popstate', function () { location.reload(); });

  window.EM = { toast: toast, refresh: refresh, go: go, post: post, swap: swap };
})();
