// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// NTP page: device config snippets filter, chrony sync / restart
// Birbirine bağlı filtre: arama + marka + cihaz tipi (AND); marka/tip satırları diğer filtrelere göre daralır
var NTP_TYPES = {
  switch: 'Switch', router: 'Router', firewall: 'Firewall',
  server: 'Sunucu & OS', loadbalancer: 'Yük Dengeleyici'
};
var NTP_BRANDS = {
  cisco: 'Cisco', mikrotik: 'MikroTik', huawei: 'Huawei', fortinet: 'Fortinet', juniper: 'Juniper',
  aruba: 'HP/Aruba', paloalto: 'Palo Alto', linux: 'Linux', windows: 'Windows', pfsense: 'pfSense/OPNsense',
  arista: 'Arista', dell: 'Dell', nokia: 'Nokia', extreme: 'Extreme', ruckus: 'Ruckus/CommScope',
  checkpoint: 'Check Point', sophos: 'Sophos', alliedtelesis: 'Allied Telesis', ruijie: 'Ruijie',
  f5: 'F5', ale: 'Alcatel-Lucent'
};
var ntpFilter = { q: '', brand: '', type: '' };
var ntpDevices = null;

function ntpCollect() {
  ntpDevices = Array.from(document.querySelectorAll('.ntp-device-card')).map(card => ({
    card: card,
    name: (card.querySelector('div[style*="font-weight: 700"]') || card).textContent.trim(),
    brand: card.getAttribute('data-vendor') || '',
    types: (card.getAttribute('data-category') || '').split(/\s+/).filter(Boolean),
    text: (card.textContent + ' ' + (NTP_BRANDS[card.getAttribute('data-vendor')] || '')).toLocaleLowerCase('tr').replace(/\s+/g, ' ')
  }));
}

function ntpMatch(d, ignore) {
  if (ntpFilter.q && d.text.indexOf(ntpFilter.q) < 0) return false;
  if (ignore !== 'brand' && ntpFilter.brand && d.brand !== ntpFilter.brand) return false;
  if (ignore !== 'type' && ntpFilter.type && d.types.indexOf(ntpFilter.type) < 0) return false;
  return true;
}

function ntpPill(label, count, active, onclick, unit) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'btn btn-sm btn-ntp-pick' + (active ? ' active' : '');
  const l = document.createElement('span');
  l.textContent = label;
  b.appendChild(l);
  if (count !== null) {
    const c = document.createElement('span');
    c.className = 'ntp-cnt';
    c.textContent = count;
    b.appendChild(c);
    if (unit) {
      const u = document.createElement('span');
      u.textContent = unit;
      b.appendChild(u);
    }
  }
  b.onclick = onclick;
  return b;
}

function ntpFill(id, nodes) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = '';
  nodes.forEach(n => el.appendChild(n));
}

function ntpReset() {
  ntpFilter.q = ''; ntpFilter.brand = ''; ntpFilter.type = '';
  const inp = document.getElementById('ntpDeviceSearch');
  if (inp) inp.value = '';
  applyNtpFiltering();
}

function applyNtpFiltering() {
  if (!ntpDevices) ntpCollect();
  // seçili marka/tip diğer filtrelerle sonuç vermiyorsa sıfırla
  if (ntpFilter.brand && !ntpDevices.some(d => ntpMatch(d, 'brand') && d.brand === ntpFilter.brand)) ntpFilter.brand = '';
  if (ntpFilter.type && !ntpDevices.some(d => ntpMatch(d, 'type') && d.types.indexOf(ntpFilter.type) >= 0)) ntpFilter.type = '';
  const list = ntpDevices.filter(d => ntpMatch(d));
  ntpDevices.forEach(d => { d.card.style.display = list.indexOf(d) >= 0 ? 'flex' : 'none'; });

  const brandCount = {}, typeCount = {};
  ntpDevices.forEach(d => {
    if (ntpMatch(d, 'brand')) brandCount[d.brand] = (brandCount[d.brand] || 0) + 1;
    if (ntpMatch(d, 'type')) d.types.forEach(t => { typeCount[t] = (typeCount[t] || 0) + 1; });
  });
  const brandTotal = ntpDevices.filter(d => ntpMatch(d, 'brand')).length;
  const typeTotal = ntpDevices.filter(d => ntpMatch(d, 'type')).length;
  ntpFill('ntpBrandPills', [ntpPill('Tümü', brandTotal, !ntpFilter.brand, () => { ntpFilter.brand = ''; applyNtpFiltering(); })]
    .concat(Object.keys(brandCount).sort((a, b) => (NTP_BRANDS[a] || a).localeCompare(NTP_BRANDS[b] || b)).map(k =>
      ntpPill(NTP_BRANDS[k] || k, brandCount[k], ntpFilter.brand === k, () => { ntpFilter.brand = ntpFilter.brand === k ? '' : k; applyNtpFiltering(); }))));
  ntpFill('ntpTypePills', [ntpPill('Tümü', typeTotal, !ntpFilter.type, () => { ntpFilter.type = ''; applyNtpFiltering(); })]
    .concat(Object.keys(NTP_TYPES).filter(k => typeCount[k]).map(k =>
      ntpPill(NTP_TYPES[k], typeCount[k], ntpFilter.type === k, () => { ntpFilter.type = ntpFilter.type === k ? '' : k; applyNtpFiltering(); }))));
  const all = ntpPill('Tümü', list.length, !ntpFilter.q && !ntpFilter.brand && !ntpFilter.type, ntpReset, 'Cihazlar');
  ntpFill('ntpDevicePills', [all].concat(list.map(d =>
    ntpPill(d.name, null, false, () => {
      d.card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      d.card.classList.add('ntp-flash');
      setTimeout(() => d.card.classList.remove('ntp-flash'), 1600);
    }))));
  const nr = document.getElementById('ntpNoResult');
  if (nr) nr.style.display = list.length ? 'none' : '';
}

function searchNtpDevices(query) {
  ntpFilter.q = (query || '').trim().toLocaleLowerCase('tr');
  applyNtpFiltering();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', applyNtpFiltering);
else applyNtpFiltering();


// in-page popup (replaces the browser alert box)
function ntpDialog(title, message, kind) {
  const old = document.getElementById('ntpDialogOverlay');
  if (old) old.remove();
  const ok = kind !== 'err';
  const ov = document.createElement('div');
  ov.id = 'ntpDialogOverlay';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(15,23,42,.45);display:flex;align-items:center;justify-content:center;z-index:10000;';
  ov.innerHTML = '<div style="background:var(--card-bg,#fff);color:var(--text-primary,#0f172a);border-radius:14px;padding:1.5rem 1.6rem;min-width:300px;max-width:440px;box-shadow:0 20px 50px rgba(0,0,0,.3);text-align:center;">'
    + '<div style="font-size:2.2rem;color:' + (ok ? '#10b981' : '#ef4444') + ';"><i class="fa-solid ' + (ok ? 'fa-circle-check' : 'fa-circle-xmark') + '"></i></div>'
    + '<h3 style="margin:.5rem 0 .4rem;font-size:1.1rem;font-weight:800;">' + ntpEsc(title) + '</h3>'
    + '<div style="font-family:monospace;font-size:.88rem;color:var(--text-muted,#64748b);white-space:pre-wrap;word-break:break-word;">' + ntpEsc(message) + '</div>'
    + '<button type="button" class="btn btn-primary" style="margin-top:1.1rem;min-width:100px;">Tamam</button></div>';
  const close = () => { ov.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape' || e.key === 'Enter') close(); };
  ov.addEventListener('click', e => { if (e.target === ov || e.target.tagName === 'BUTTON') close(); });
  document.addEventListener('keydown', onKey);
  document.body.appendChild(ov);
  ov.querySelector('button').focus();
}

function ntpEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

// refresh the status cards and the upstream source table in place (no page reload)
function renderNtpStatus(data) {
  const t = data.tracking || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('ntpStratum', 'Stratum ' + (t.stratum || '-'));
  set('ntpRef', t.ref_id || '-');
  set('ntpOffset', t.last_offset || '-');
  set('ntpLeap', t.leap_status || '-');
  const body = document.getElementById('ntpSourcesBody');
  if (!body) return;
  const rows = (data.sources || []).map((s, i) => {
    const sel = (s.state || '').indexOf('*') >= 0;
    const icon = sel
      ? '<i class="fa-solid fa-circle-check" style="color:#10b981;" title="Seçili Zaman Kaynağı (*)"></i>'
      : '<i class="fa-solid fa-circle-plus" style="color:#0284c7;" title="Aday Kaynak (+)"></i>';
    const name = s.host
      ? '<code style="color:#0f172a; font-weight:700;">' + ntpEsc(s.host) + '</code> <code style="font-size:0.78rem; color:#64748b;">' + ntpEsc(s.name) + '</code>'
      : '<code style="color:#0f172a; font-weight:700;">' + ntpEsc(s.name) + '</code>';
    return '<tr><td style="color:#94a3b8; font-weight:600;">' + (i + 1) + '</td><td>' + icon + ' ' + name + '</td>'
      + '<td><span class="badge" style="background:#eff6ff; color:#1d4ed8;">Stratum ' + ntpEsc(s.stratum) + '</span></td>'
      + '<td>' + ntpEsc(s.poll) + '</td><td><code>' + ntpEsc(s.reach) + '</code></td><td>' + ntpEsc(s.lastrx) + 's önce</td>'
      + '<td><code style="font-size:0.78rem; color:#475569;">' + ntpEsc(s.sample) + '</code></td></tr>';
  });
  body.innerHTML = rows.length ? rows.join('')
    : '<tr><td colspan="7" style="text-align:center; padding:3rem; color:#94a3b8;">Aktif yukarı akış sunucusu bulunamadı.</td></tr>';
}

function syncNtpNow() {
  const btn = document.getElementById('btnSyncNtp');
  const label = '<i class="fa-solid fa-arrows-rotate"></i> Şimdi Eşitle (Makestep)';
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Eşitleniyor...';

  fetch('/api/ntp/sync', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      btn.disabled = false;
      btn.innerHTML = label;
      if (data.success) {
        renderNtpStatus(data);
        ntpDialog('NTP Zaman Eşitleme Başarılı', data.output, 'ok');
      } else {
        ntpDialog('Eşitleme Hatası', data.error, 'err');
      }
    })
    .catch(err => {
      btn.disabled = false;
      btn.innerHTML = label;
      ntpDialog('Bağlantı Hatası', String(err), 'err');
    });
}

function restartNtpService() {
  const btn = document.getElementById('btnRestartNtp');
  const label = '<i class="fa-solid fa-power-off"></i> chronyd Yeniden Başlat';
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Başlatılıyor...';

  fetch('/api/ntp/restart', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      btn.disabled = false;
      btn.innerHTML = label;
      if (data.success) {
        renderNtpStatus(data);
        ntpDialog('chronyd Yeniden Başlatıldı', 'chronyd servisi başarıyla yeniden başlatıldı.', 'ok');
      } else {
        ntpDialog('Hata', data.error, 'err');
      }
    })
    .catch(err => {
      btn.disabled = false;
      btn.innerHTML = label;
      ntpDialog('Hata', String(err), 'err');
    });
}
