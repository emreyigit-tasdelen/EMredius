// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Users page: edit modal, password reveal, password strength meter.
function usrSetSelect(sel, val) {
  if (!sel) return;
  val = (val === null || val === undefined) ? '' : String(val);
  var found = false;
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].value === val) { found = true; break; }
  }
  if (!found && val) {
    var o = document.createElement('option');
    o.value = val;
    o.textContent = val;
    sel.appendChild(o);
  }
  sel.value = val;
}
function openUserEditModal(btn) {
  var u = {};
  try { u = JSON.parse(btn.getAttribute('data-user') || '{}'); } catch (e) { u = {}; }
  document.getElementById('editUserTitle').textContent = u.username || '';
  document.getElementById('editUsername').value = u.username || '';
  document.getElementById('editPassword').value = '';
  document.getElementById('editVlan').value = u.vlan_id || '';
  document.getElementById('editStaticIp').value = u.static_ip || '';
  usrSetSelect(document.getElementById('editRate'), u.rate_limit || '');
  usrSetSelect(document.getElementById('editGroupname'), u.groupname || '');
  document.getElementById('editWorkHours').checked = !!u.work_hours;
  document.getElementById('editSingleDevice').checked = !!u.single_device;
  document.getElementById('editDesc').value = u.description || '';
  openModal('editUserModal');
}
function _hideUserPw(cell, btn) {
  var raw = cell.querySelector('.pw-raw');
  var mask = cell.querySelector('.pw-mask');
  var icon = btn.querySelector('i');
  raw.textContent = '';
  raw.style.display = 'none';
  mask.style.display = 'inline';
  if (icon) icon.className = 'fa-regular fa-eye';
}
function revealUserPw(btn) {
  var cell = btn.parentNode;
  var raw = cell.querySelector('.pw-raw');
  var mask = cell.querySelector('.pw-mask');
  var icon = btn.querySelector('i');
  if (raw.style.display !== 'none') { _hideUserPw(cell, btn); return; }
  btn.disabled = true;
  fetch('/user/password/' + encodeURIComponent(btn.getAttribute('data-username') || ''), {
    method: 'POST',
    headers: { 'Accept': 'application/json' }
  }).then(function(r) {
    return r.json().catch(function() { return { success: false, error: 'Sunucu yanıtı okunamadı (HTTP ' + r.status + ').' }; });
  }).then(function(d) {
    if (d && d.success) {
      raw.textContent = d.password;
      raw.style.display = 'inline';
      mask.style.display = 'none';
      if (icon) icon.className = 'fa-regular fa-eye-slash';
      // Plain-text password is removed from the page again after 30 seconds
      setTimeout(function() { if (raw.style.display !== 'none') _hideUserPw(cell, btn); }, 30000);
    } else {
      alert((d && d.error) || 'Şifre görüntülenemedi.');
    }
  }).catch(function() {
    alert('Sunucuya ulaşılamadı.');
  }).then(function() {
    btn.disabled = false;
  });
}
function checkStrength(p) {
  var meter = document.getElementById('strengthMeter');
  if (!p) { meter.textContent = ''; return; }
  var score = 0;
  if (p.length >= 8) score++;
  if (/[A-Z]/.test(p)) score++;
  if (/[0-9]/.test(p)) score++;
  if (/[^A-Za-z0-9]/.test(p)) score++;
  if (score <= 1) { meter.style.color = '#ef4444'; meter.textContent = 'Güvenlik: Zayıf'; }
  else if (score == 2) { meter.style.color = '#f59e0b'; meter.textContent = 'Güvenlik: Orta'; }
  else { meter.style.color = '#10b981'; meter.textContent = 'Güvenlik: Güçlü'; }
}
