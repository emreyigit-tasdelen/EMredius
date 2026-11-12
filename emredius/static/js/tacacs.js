// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// TACACS+ page: tabs, CRUD via /api/tacacs/*, accounting refresh, rule tester
// Robust Modal Management
window.openModal = function(id) {
  var m = document.getElementById(id);
  if (m) {
    m.classList.add('show');
    m.style.display = 'flex';
    document.body.style.overflow = 'hidden';
  }
};

window.closeModal = function(id) {
  var m = document.getElementById(id);
  if (m) {
    m.classList.remove('show');
    m.style.display = 'none';
    document.body.style.overflow = '';
  }
};

function openModal(id) { window.openModal(id); }
function closeModal(id) { window.closeModal(id); }

// Tab Switching with LocalStorage & Hash Persistence
function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(function(el) { el.style.display = 'none'; });
  document.querySelectorAll('.tab-btn').forEach(function(el) { el.classList.remove('active'); });
  
  var target = document.getElementById(tabId);
  if (target) target.style.display = 'block';

  if (btn) {
    btn.classList.add('active');
  } else {
    var matchingBtn = document.querySelector('.tab-btn[data-tab="' + tabId + '"]');
    if (matchingBtn) matchingBtn.classList.add('active');
  }

  try {
    localStorage.setItem('tacacs_active_tab', tabId);
    history.replaceState(null, '', '#' + tabId);
  } catch(e) {}
}

document.addEventListener('DOMContentLoaded', function() {
  var savedTab = (location.hash ? location.hash.substring(1) : '') || localStorage.getItem('tacacs_active_tab');
  if (savedTab && document.getElementById(savedTab)) {
    var btn = document.querySelector('.tab-btn[data-tab="' + savedTab + '"]');
    switchTab(savedTab, btn);
  }
});

// Show/Hide Shared Secret (XSS-safe via dataset)
function toggleSecret(spanId) {
  var el = document.getElementById(spanId);
  if (!el) return;
  var sec = el.getAttribute('data-secret') || '';
  if (el.innerText === '••••••••') {
    el.innerText = sec;
    el.style.fontWeight = 'bold';
    el.style.fontFamily = 'monospace';
  } else {
    el.innerText = '••••••••';
    el.style.fontWeight = 'normal';
    el.style.fontFamily = 'inherit';
  }
}

// User Group Selection Sync
function onUserGroupSelect(sel) {
  var opt = sel.options[sel.selectedIndex];
  if (opt && opt.getAttribute('data-priv')) {
    var pInput = document.getElementById('mPriv');
    if (pInput) pInput.value = opt.getAttribute('data-priv');
  }
}

// Quick CLI test chip helper
function setQuickTest(cmd, user, priv) {
  var cInput = document.getElementById('testCmd');
  if (cInput) cInput.value = cmd;
  if (user) {
    var uInput = document.getElementById('testUser');
    if (uInput) uInput.value = user;
  }
  if (priv !== undefined) {
    var pInput = document.getElementById('testPriv');
    if (pInput) pInput.value = priv;
  }
  runRuleTest();
}

// Add Client Handler
function submitAddClient() {
  var name = (document.getElementById('mCliName').value || '').trim();
  var ip_cidr = (document.getElementById('mCliIp').value || '').trim();
  var sec = (document.getElementById('mCliSec').value || '').trim();
  var vendor = document.getElementById('mCliVendor').value;

  if (!name || !ip_cidr || !sec) {
    alert('Lütfen Cihaz Adı, IP / CIDR ve Ortak Parola alanlarını eksiksiz doldurun.');
    return;
  }

  var payload = {
    name: name,
    ip_cidr: ip_cidr,
    shared_secret: sec,
    vendor: vendor
  };

  fetch('/api/tacacs/clients', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      localStorage.setItem('tacacs_active_tab', 'tab-clients');
      (window.EM ? window.EM.refresh() : location.reload());
    } else {
      alert('Hata: ' + (data.error || data.message || 'Cihaz kaydedilemedi'));
    }
  })
  .catch(function(err) {
    alert('Bağlantı hatası: ' + err.message);
  });
}

// Delete Client Handler
function deleteClient(id, name) {
  if (!confirm('"' + (name || 'Cihaz #' + id) + '" adlı TACACS+ cihazını silmek istediğinize emin misiniz?')) return;
  fetch('/api/tacacs/clients/' + id, {method: 'DELETE'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        localStorage.setItem('tacacs_active_tab', 'tab-clients');
        (window.EM ? window.EM.refresh() : location.reload());
      } else {
        alert('Hata: ' + (data.error || 'Cihaz silinemedi'));
      }
    })
    .catch(function(err) { alert('Bağlantı hatası: ' + err.message); });
}

// Add User Handler
function submitAddUser() {
  var username = (document.getElementById('mUname').value || '').trim();
  var password = document.getElementById('mPass').value;
  var enPass = document.getElementById('mEnPass').value;
  var priv = parseInt(document.getElementById('mPriv').value || '1');
  var groupId = parseInt(document.getElementById('mUGroup').value || '1');

  if (!username || !password) {
    alert('Lütfen Kullanıcı Adı ve Parola alanlarını doldurun.');
    return;
  }

  var payload = {
    username: username,
    password: password,
    enable_password: enPass,
    priv_lvl: priv,
    group_id: groupId
  };

  fetch('/api/tacacs/users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      localStorage.setItem('tacacs_active_tab', 'tab-users');
      (window.EM ? window.EM.refresh() : location.reload());
    } else {
      alert('Hata: ' + (data.error || data.message || 'Kullanıcı kaydedilemedi'));
    }
  })
  .catch(function(err) {
    alert('Bağlantı hatası: ' + err.message);
  });
}

// Delete User Handler
function deleteUser(id, username) {
  if (id === 1 || (username || '').toLowerCase() === 'admin') {
    alert('Sistem ana yönetici (admin) hesabı silinemez!');
    return;
  }
  if (!confirm('"' + (username || 'Kullanıcı #' + id) + '" adlı TACACS+ kullanıcısını silmek istediğinize emin misiniz?')) return;
  fetch('/api/tacacs/users/' + id, {method: 'DELETE'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        localStorage.setItem('tacacs_active_tab', 'tab-users');
        (window.EM ? window.EM.refresh() : location.reload());
      } else {
        alert('Hata: ' + (data.error || 'Kullanıcı silinemedi'));
      }
    })
    .catch(function(err) { alert('Bağlantı hatası: ' + err.message); });
}

// Add Rule Handler
function submitAddRule() {
  var groupId = parseInt(document.getElementById('mRuleGroup').value);
  var priority = parseInt(document.getElementById('mRulePrio').value || '100');
  var pattern = (document.getElementById('mRulePattern').value || '').trim();
  var action = document.getElementById('mRuleAction').value;
  var desc = (document.getElementById('mRuleDesc') ? document.getElementById('mRuleDesc').value : '').trim();

  if (!pattern) {
    alert('Lütfen geçerli bir Regex Komut Deseni girin (Örn: ^show.* veya ^reload).');
    return;
  }

  var payload = {
    group_id: groupId,
    priority: priority,
    pattern: pattern,
    action: action,
    description: desc
  };

  fetch('/api/tacacs/rules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      localStorage.setItem('tacacs_active_tab', 'tab-rules');
      (window.EM ? window.EM.refresh() : location.reload());
    } else {
      alert('Hata: ' + (data.error || data.message || 'Kural kaydedilemedi'));
    }
  })
  .catch(function(err) {
    alert('Bağlantı hatası: ' + err.message);
  });
}

// Delete Rule Handler
function deleteRule(id) {
  if (!confirm('Bu komut yetki kuralını silmek istediğinize emin misiniz?')) return;
  fetch('/api/tacacs/rules/' + id, {method: 'DELETE'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        localStorage.setItem('tacacs_active_tab', 'tab-rules');
        (window.EM ? window.EM.refresh() : location.reload());
      } else {
        alert('Hata: ' + (data.error || 'Kural silinemedi'));
      }
    })
    .catch(function(err) { alert('Bağlantı hatası: ' + err.message); });
}

// Live Rule Tester Handler
function runRuleTest() {
  var username = (document.getElementById('testUser').value || '').trim();
  var command = (document.getElementById('testCmd').value || '').trim();
  var priv = parseInt(document.getElementById('testPriv').value || '1');
  var box = document.getElementById('testResultBox');
  var btn = document.getElementById('btnRunTest');

  if (!command) {
    alert('Lütfen test edilecek bir CLI komutu girin.');
    return;
  }

  box.style.display = 'block';
  box.style.background = 'rgba(59, 130, 246, 0.1)';
  box.style.border = '1px solid rgba(59, 130, 246, 0.3)';
  box.style.color = 'var(--text-primary)';
  box.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Kural motoru test ediliyor...';

  if (btn) btn.disabled = true;

  fetch('/api/tacacs/rules/test', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      username: username,
      command: command,
      priv_lvl: priv
    })
  })
  .then(function(r) { return r.json(); })
  .then(function(res) {
    if (btn) btn.disabled = false;
    if (res.permitted) {
      box.style.background = '#dcfce7';
      box.style.border = '1px solid #86efac';
      box.style.color = '#166534';
      box.innerHTML = '<h4 style="margin:0 0 0.5rem 0; font-size:1.05rem;"><i class="fa-solid fa-circle-check"></i> İZİN VERİLDİ (PERMITTED)</h4>' +
                      '<p style="margin:0; font-size:0.92rem; font-weight:600;">' + escHtml(res.reason || 'Kural eşleşti.') + '</p>' +
                      '<div style="font-size:0.8rem; margin-top:0.4rem; color:#14532d;">Kullanıcı: <b>' + escHtml(username) + '</b> (Priv ' + escHtml(priv) + ') | Komut: <code>' + escHtml(command) + '</code></div>';
    } else {
      box.style.background = '#fee2e2';
      box.style.border = '1px solid #fca5a5';
      box.style.color = '#991b1b';
      box.innerHTML = '<h4 style="margin:0 0 0.5rem 0; font-size:1.05rem;"><i class="fa-solid fa-circle-xmark"></i> ENGELLENDİ (DENIED)</h4>' +
                      '<p style="margin:0; font-size:0.92rem; font-weight:600;">' + escHtml(res.reason || 'Kural engellendi.') + '</p>' +
                      '<div style="font-size:0.8rem; margin-top:0.4rem; color:#7f1d1d;">Kullanıcı: <b>' + escHtml(username) + '</b> (Priv ' + escHtml(priv) + ') | Komut: <code>' + escHtml(command) + '</code></div>';
    }
  })
  .catch(function(err) {
    if (btn) btn.disabled = false;
    box.style.background = '#fee2e2';
    box.style.border = '1px solid #fca5a5';
    box.style.color = '#991b1b';
    box.innerHTML = '<b>Test Hatası:</b> ' + escHtml(err.message);
  });
}

// Filter Accounting Table
function filterAcctTable() {
  var q = (document.getElementById('acctSearch').value || '').toLowerCase();
  var rows = document.querySelectorAll('#acctTable tbody tr');
  rows.forEach(function(r) {
    var text = r.innerText.toLowerCase();
    r.style.display = text.includes(q) ? '' : 'none';
  });
}

// Refresh Accounting Logs via API
function refreshAcctLogs() {
  var btn = document.getElementById('btnRefreshAcct');
  var oldHtml = btn ? btn.innerHTML : '';
  if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Yenileniyor...';

  fetch('/api/tacacs/accounting')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (btn) btn.innerHTML = oldHtml;
      var logs = (data && data.records) ? data.records : (Array.isArray(data) ? data : []);
      var tbody = document.querySelector('#acctTable tbody');
      if (!tbody) return;

      if (document.getElementById('tabAcctCount')) {
        document.getElementById('tabAcctCount').innerText = logs.length;
      }
      if (document.getElementById('kpiAcctCount')) {
        document.getElementById('kpiAcctCount').innerText = logs.length;
      }

      if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-secondary);" data-i18n="Henüz komut denetim kaydı oluşmadı.">Henüz komut denetim kaydı oluşmadı.</td></tr>';
        return;
      }

      var htmlRows = '';
      logs.forEach(function(a) {
        var st = (a.status || '').toUpperCase();
        var badge = st === 'PERMITTED' 
          ? '<span class="badge" style="background:#dcfce7; color:#166534;">PERMITTED</span>'
          : '<span class="badge" style="background:#fee2e2; color:#991b1b;">DENIED</span>';
        htmlRows += '<tr>' +
          '<td style="font-size:0.85rem; color:var(--text-secondary);">' + escHtml(a.timestamp || '-') + '</td>' +
          '<td><code>' + escHtml(a.device_ip || '-') + '</code></td>' +
          '<td><code>' + escHtml(a.client_ip || '-') + '</code></td>' +
          '<td style="font-weight:600;">' + escHtml(a.username || '-') + '</td>' +
          '<td><span class="badge" style="background:#f1f5f9; color:#475569;">Priv ' + escHtml(a.priv_lvl || 1) + '</span></td>' +
          '<td><code>' + escHtml(a.cmd || '-') + '</code></td>' +
          '<td>' + badge + '</td>' +
        '</tr>';
      });
      tbody.innerHTML = htmlRows;
      filterAcctTable();
    })
    .catch(function(err) {
      if (btn) btn.innerHTML = oldHtml;
      alert('Loglar yenilenirken hata oluştu: ' + err.message);
    });
}

function hideTestResultBox() {
  var b = document.getElementById("testResultBox");
  if (b) b.style.display = "none";
}
