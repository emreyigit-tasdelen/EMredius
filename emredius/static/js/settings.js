// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// Settings page: NTP "sync now" button (in-page update + popup, no reload)
(function() {
  var btn = document.getElementById('btnSyncNtpSet');
  if (!btn) return;
  var label = btn.innerHTML;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }

  function dialog(title, message, kind) {
    var old = document.getElementById('setNtpDialogOverlay');
    if (old) old.remove();
    var ok = kind !== 'err';
    var ov = document.createElement('div');
    ov.id = 'setNtpDialogOverlay';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(15,23,42,.45);display:flex;align-items:center;justify-content:center;z-index:10000;';
    ov.innerHTML = '<div style="background:var(--card-bg,#fff);color:var(--text-primary,#0f172a);border-radius:14px;padding:1.5rem 1.6rem;min-width:300px;max-width:440px;box-shadow:0 20px 50px rgba(0,0,0,.3);text-align:center;">'
      + '<div style="font-size:2.2rem;color:' + (ok ? '#10b981' : '#ef4444') + ';"><i class="fa-solid ' + (ok ? 'fa-circle-check' : 'fa-circle-xmark') + '"></i></div>'
      + '<h3 style="margin:.5rem 0 .4rem;font-size:1.1rem;font-weight:800;">' + esc(title) + '</h3>'
      + '<div style="font-family:monospace;font-size:.88rem;color:var(--text-muted,#64748b);white-space:pre-wrap;word-break:break-word;">' + esc(message) + '</div>'
      + '<button type="button" class="btn btn-primary" style="margin-top:1.1rem;min-width:100px;">Tamam</button></div>';
    function close() { ov.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape' || e.key === 'Enter') close(); }
    ov.addEventListener('click', function(e) { if (e.target === ov || e.target.tagName === 'BUTTON') close(); });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(ov);
    ov.querySelector('button').focus();
  }

  function render(data) {
    var t = data.tracking || {};
    var off = document.getElementById('setNtpOffset');
    if (off) off.textContent = t.last_offset || '-';
    var st = document.getElementById('setNtpStatus');
    if (st) {
      st.innerHTML = t.is_synced
        ? '<span class="badge" style="background:#dcfce7; color:#15803d; font-weight:700;"><i class="fa-solid fa-check"></i> Stratum ' + esc(t.stratum) + ' (' + esc(t.ref_id) + ')</span>'
        : '<span class="badge" style="background:#fee2e2; color:#991b1b; font-weight:700;"><i class="fa-solid fa-xmark"></i> chrony yanıt vermiyor</span>';
    }
    fetch('/api/system/time').then(function(r) { return r.json(); }).then(function(d) {
      var now = document.getElementById('setNtpNow');
      if (now && d.time) now.textContent = d.time;
    }).catch(function() {});
  }

  btn.addEventListener('click', function() {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Eşitleniyor...';
    fetch('/api/ntp/sync', { method: 'POST' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        btn.disabled = false;
        btn.innerHTML = label;
        if (data.success) {
          render(data);
          dialog('NTP Başarıyla Eşitlendi', data.output, 'ok');
        } else {
          dialog('Hata', data.error, 'err');
        }
      })
      .catch(function(err) {
        btn.disabled = false;
        btn.innerHTML = label;
        dialog('Hata', String(err), 'err');
      });
  });
})();
