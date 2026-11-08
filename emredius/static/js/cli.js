// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Web terminal: command history, execute via /api/cli/execute, autocomplete
var cliHistory = [];
try {
  cliHistory = JSON.parse(localStorage.getItem('emredius_cli_history') || '[]');
} catch(e) {
  cliHistory = [];
}
var historyCursor = cliHistory.length;

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function scrollToBottom() {
  var el = document.getElementById('terminalScreen');
  if (el) el.scrollTop = el.scrollHeight;
}

function clearTerminalScreen() {
  var c = document.getElementById('terminalLogContainer');
  if (c) c.innerHTML = '';
}

function copyTerminalText() {
  var screen = document.getElementById('terminalScreen');
  if (!screen) return;
  var text = screen.innerText || screen.textContent;
  navigator.clipboard.writeText(text).then(function() {
    alert('Terminal çıktısı panoya kopyalandı.');
  }).catch(function() {
    prompt('Çıktıyı kopyalamak için Ctrl+C tuşlayın:', text);
  });
}

function downloadTerminalLog() {
  var screen = document.getElementById('terminalScreen');
  if (!screen) return;
  var text = screen.innerText || screen.textContent;
  var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'emredius_cli_session_' + new Date().toISOString().replace(/[:.]/g, '-') + '.log';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function toggleTerminalFullscreen() {
  var card = document.getElementById('cliTerminalCard');
  var icon = document.getElementById('iconFullscreen');
  if (!card) return;
  if (!document.fullscreenElement) {
    if (card.requestFullscreen) {
      card.requestFullscreen();
    } else if (card.webkitRequestFullscreen) {
      card.webkitRequestFullscreen();
    }
    if (icon) icon.className = 'fa-solid fa-compress';
  } else {
    if (document.exitFullscreen) {
      document.exitFullscreen();
    }
    if (icon) icon.className = 'fa-solid fa-expand';
  }
}

function runQuickCommand(cmd) {
  var inp = document.getElementById('cliCommandInput');
  if (inp) {
    inp.value = cmd;
    submitCliCommand();
  }
}

function submitCliCommand() {
  var inp = document.getElementById('cliCommandInput');
  if (!inp) return;
  var cmd = inp.value.trim();
  if (!cmd) return;

  // Save to history
  if (cliHistory[cliHistory.length - 1] !== cmd) {
    cliHistory.push(cmd);
    if (cliHistory.length > 60) cliHistory.shift();
    try {
      localStorage.setItem('emredius_cli_history', JSON.stringify(cliHistory));
    } catch(e) {}
  }
  historyCursor = cliHistory.length;

  removeExistingTabHints();
  var container = document.getElementById('terminalLogContainer');
  var btn = document.getElementById('btnRunCommand');
  var icon = document.getElementById('iconRunCmd');

  inp.value = '';
  inp.disabled = true;
  if (btn) btn.disabled = true;
  if (icon) icon.className = 'fa-solid fa-circle-notch fa-spin';

  var cmdId = 'cmd_' + Date.now();
  var d = new Date();
  var timeStr = d.toLocaleTimeString();

  var blockHtml = '<div id="' + cmdId + '" style="margin-bottom:1.1rem; border-left:2px solid #2563eb; padding-left:0.75rem;">' +
    '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem; font-size:0.8rem; color:#94a3b8;">' +
      '<div><span style="color:#10b981; font-weight:700;">root@emredius:~#</span> <strong style="color:#f8fafc; font-size:0.92rem;">' + escapeHtml(cmd) + '</strong></div>' +
      '<div id="badge_' + cmdId + '"><span style="color:#38bdf8;"><i class="fa-solid fa-spinner fa-spin"></i> Yürütülüyor...</span></div>' +
    '</div>' +
    '<pre id="out_' + cmdId + '" style="margin:0; background:#0b0f19; border:1px solid #1e293b; border-radius:6px; padding:0.75rem; color:#cbd5e1; font-family:inherit; font-size:0.84rem; white-space:pre-wrap; word-break:break-all; max-height:360px; overflow-y:auto;"></pre>' +
  '</div>';

  if (container) {
    container.insertAdjacentHTML('beforeend', blockHtml);
    scrollToBottom();
  }

  var formData = new FormData();
  formData.append('command', cmd);

  fetch('/api/cli/execute', {
    method: 'POST',
    body: formData
  })
  .then(function(r) { return r.json(); })
  .then(function(res) {
    inp.disabled = false;
    if (btn) btn.disabled = false;
    if (icon) icon.className = 'fa-solid fa-play';
    inp.focus();

    var badgeEl = document.getElementById('badge_' + cmdId);
    var outEl = document.getElementById('out_' + cmdId);

    if (!res.success) {
      if (badgeEl) {
        badgeEl.innerHTML = '<span class="badge" style="background:#fee2e2; color:#991b1b; font-size:0.75rem; font-weight:700;"><i class="fa-solid fa-circle-exclamation"></i> HATA</span>';
      }
      if (outEl) {
        outEl.style.borderColor = '#ef4444';
        outEl.style.color = '#f87171';
        outEl.textContent = res.error || 'Bilinmeyen komut çalıştırma hatası oluştu.';
      }
    } else {
      var isZero = (res.returncode === 0);
      var badgeStyle = isZero ? 'background:#dcfce7; color:#15803d;' : 'background:#fee2e2; color:#991b1b;';
      var badgeIcon = isZero ? 'fa-check' : 'fa-xmark';
      var badgeText = 'Exit: ' + res.returncode + ' (' + (res.duration_ms || 0) + 'ms)';

      if (badgeEl) {
        badgeEl.innerHTML = '<span class="badge" style="' + badgeStyle + ' font-size:0.75rem; font-weight:700;"><i class="fa-solid ' + badgeIcon + '"></i> ' + badgeText + '</span>';
      }

      var fullOut = '';
      if (res.stdout) fullOut += res.stdout;
      if (res.stderr) {
        if (fullOut) fullOut += String.fromCharCode(10) + '--- STDERR ---' + String.fromCharCode(10);
        fullOut += res.stderr;
      }
      if (!fullOut.trim()) fullOut = '(Komut herhangi bir çıktı üretmedi / Başarılı)';

      if (outEl) {
        if (!isZero) outEl.style.borderColor = '#ef4444';
        outEl.textContent = fullOut;
      }
    }
    scrollToBottom();
  })
  .catch(function(err) {
    inp.disabled = false;
    if (btn) btn.disabled = false;
    if (icon) icon.className = 'fa-solid fa-play';
    inp.focus();

    var badgeEl = document.getElementById('badge_' + cmdId);
    var outEl = document.getElementById('out_' + cmdId);
    if (badgeEl) {
      badgeEl.innerHTML = '<span class="badge" style="background:#fee2e2; color:#991b1b; font-size:0.75rem; font-weight:700;">BAĞLANTI HATASI</span>';
    }
    if (outEl) {
      outEl.textContent = 'Ağ veya sunucu yanıt vermedi: ' + err;
    }
    scrollToBottom();
  });
}

// --- CLI Tab Autocompletion Engine ---
var CLI_COMPLETIONS = {
  commands: [
    'systemctl', 'journalctl', 'radtest', 'radclient', 'radiusd', 'radwho', 'radmin', 'radlast',
    'chronyc', 'chronyd', 'ss', 'ip', 'ping', 'traceroute', 'curl', 'wget', 'firewall-cmd',
    'iptables', 'nftables', 'tcpdump', 'cat', 'tail', 'head', 'grep', 'less', 'more',
    'free', 'df', 'uptime', 'uname', 'ps', 'top', 'htop', 'chmod', 'chown', 'mkdir', 'cp',
    'mv', 'rm', 'ls', 'clear', 'echo', 'date', 'whoami', 'id', 'history', 'mysql', 'mysqldump',
    'netstat', 'find', 'which', 'whereis', 'diff', 'sed', 'awk', 'touch', 'tar', 'gzip'
  ],
  systemctl_sub: ['status', 'restart', 'start', 'stop', 'reload', 'enable', 'disable', 'is-active', 'is-enabled', 'daemon-reload', 'cat', 'show', 'reset-failed'],
  services: ['radiusd', 'radius-admin', 'tacacs', 'chronyd', 'mariadb', 'firewalld', 'sshd', 'nginx', 'rsyslog', 'network'],
  chronyc_sub: ['tracking', 'sources', 'sources -v', 'sourcestats', 'sourcestats -v', 'activity', 'serverstats', 'ntpdata'],
  firewall_sub: ['--list-all', '--reload', '--state', '--list-ports', '--list-services', '--get-active-zones', '--add-port=', '--zone=public', '--permanent'],
  ip_sub: ['a', 'addr', 'route', 'link', 'neigh', 'rule', '-br a', '-br link'],
  ss_flags: ['-tulpn', '-tuln', '-s', '-ta', '-ua'],
  journalctl_flags: ['-u radiusd', '-u tacacs', '-u chronyd', '-u mariadb', '-u radius-admin', '-n 25', '-n 50', '-n 100', '-f', '-xe', '--no-pager'],
  common_paths: [
    '/var/log/radius/radius.log',
    '/var/log/radius/',
    '/var/log/messages',
    '/var/log/secure',
    '/var/log/audit/audit.log',
    '/var/log/chrony/',
    '/var/log/mariadb/mariadb.log',
    '/etc/raddb/radiusd.conf',
    '/etc/raddb/clients.conf',
    '/etc/raddb/users',
    '/etc/raddb/mods-available/',
    '/etc/raddb/mods-enabled/',
    '/etc/raddb/sites-available/',
    '/etc/raddb/sites-enabled/',
    '/etc/raddb/',
    '/etc/chrony.conf',
    '/etc/my.cnf',
    '/etc/tacacs/tac_plus.conf',
    '/etc/tacacs/',
    '/opt/radius-admin/app.py',
    '/opt/radius-admin/',
    '/etc/systemd/system/radius-admin.service',
    '/etc/systemd/system/'
  ]
};

function getLongestCommonPrefix(strings) {
  if (!strings || strings.length === 0) return '';
  var prefix = strings[0];
  for (var i = 1; i < strings.length; i++) {
    while (strings[i].toLowerCase().indexOf(prefix.toLowerCase()) !== 0) {
      prefix = prefix.substring(0, prefix.length - 1);
      if (!prefix) return '';
    }
  }
  return prefix;
}

function removeExistingTabHints() {
  var el = document.getElementById('cliTabHintBox');
  if (el && el.parentNode) {
    el.parentNode.removeChild(el);
  }
}

function pickTabSuggestion(chosen) {
  var inp = document.getElementById('cliCommandInput');
  if (!inp) return;
  var val = inp.value;
  var cursor = inp.selectionStart != null ? inp.selectionStart : val.length;
  var before = val.substring(0, cursor);
  var after = val.substring(cursor);

  var match = before.match(/([^ \t\r\n]+)$/);
  var currentToken = match ? match[1] : '';
  var appendChar = (chosen.slice(-1) === '/') ? '' : ' ';
  var tokenStart = before.length - currentToken.length;
  var newBefore = before.substring(0, tokenStart) + chosen + appendChar;
  inp.value = newBefore + after;
  inp.focus();
  var newPos = newBefore.length;
  inp.selectionStart = inp.selectionEnd = newPos;
  removeExistingTabHints();
}

function renderTabSuggestions(matches, currentToken) {
  removeExistingTabHints();
  var container = document.getElementById('terminalLogContainer');
  if (!container) return;

  var div = document.createElement('div');
  div.id = 'cliTabHintBox';
  div.style.cssText = 'margin:0.5rem 0; padding:0.6rem 0.85rem; background:#070a12; border:1px solid #1e293b; border-radius:8px; font-family:\'JetBrains Mono\', Consolas, monospace; font-size:0.82rem;';

  var header = '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.45rem; color:#94a3b8; font-size:0.78rem;">' +
    '<div><i class="fa-solid fa-wand-magic-sparkles" style="color:#38bdf8;"></i> <strong style="color:#e2e8f0;">Tab Tamamlama:</strong> <span class="badge" style="background:#1e293b; color:#93c5fd; font-size:0.72rem; padding:0.15rem 0.4rem; border-radius:4px; margin-left:0.3rem;">' + matches.length + ' aday</span></div>' +
    '<span style="font-size:0.72rem; color:#64748b;">(Tıklayarak ekleyebilir veya yazmaya devam edebilirsiniz)</span>' +
  '</div>';

  var pills = '<div style="display:flex; flex-wrap:wrap; gap:0.4rem; max-height:160px; overflow-y:auto;">';
  for (var i = 0; i < matches.length; i++) {
    var m = matches[i];
    pills += '<span class="tab-pill cli-pill" data-pick="' + escapeHtml(m) + '">' +
      escapeHtml(m) +
    '</span>';
  }
  pills += '</div>';

  div.innerHTML = header + pills;
  container.appendChild(div);
  scrollToBottom();
}

function applyCompletionList(matches, currentToken, before, after) {
  var inp = document.getElementById('cliCommandInput');
  if (!inp) return;

  if (!matches || matches.length === 0) {
    var orig = inp.style.borderColor;
    inp.style.borderColor = '#f59e0b';
    setTimeout(function() { inp.style.borderColor = orig; }, 250);
    return;
  }

  if (matches.length === 1) {
    var chosen = matches[0];
    var appendChar = (chosen.slice(-1) === '/') ? '' : ' ';
    var tokenStart = before.length - currentToken.length;
    var newBefore = before.substring(0, tokenStart) + chosen + appendChar;
    inp.value = newBefore + after;
    inp.focus();
    inp.selectionStart = inp.selectionEnd = newBefore.length;
    removeExistingTabHints();
    return;
  }

  // Multiple matches: extend to Longest Common Prefix if possible
  var lcp = getLongestCommonPrefix(matches);
  if (lcp && lcp.length > currentToken.length) {
    var tokenStart = before.length - currentToken.length;
    var newBefore = before.substring(0, tokenStart) + lcp;
    inp.value = newBefore + after;
    inp.selectionStart = inp.selectionEnd = newBefore.length;
    currentToken = lcp;
    before = newBefore;
  }

  renderTabSuggestions(matches, currentToken);
}

function handleCliTabCompletion() {
  var inp = document.getElementById('cliCommandInput');
  if (!inp) return;
  var val = inp.value;
  var cursor = inp.selectionStart != null ? inp.selectionStart : val.length;
  var before = val.substring(0, cursor);
  var after = val.substring(cursor);

  // If input is empty, show top suggested commands
  if (!val.trim()) {
    var topSuggestions = ['systemctl status radiusd', 'systemctl status tacacs', 'journalctl -u radiusd -n 25', 'radtest test test 127.0.0.1 0 testing123', 'chronyc tracking', 'ss -tulpn', 'ip -br a', 'uptime', 'free -h'];
    renderTabSuggestions(topSuggestions, '');
    return;
  }

  var match = before.match(/([^ \t\r\n]+)$/);
  var currentToken = match ? match[1] : '';
  var tokens = before.trim().split(/[ \t\r\n]+/);
  var isAfterSpace = /[ \t\r\n]$/.test(before);
  var prevWord = isAfterSpace ? (tokens[tokens.length - 1] || '') : (tokens.length > 1 ? tokens[tokens.length - 2] : '');
  var firstWord = tokens[0] || '';

  var candidates = [];

  // Contextual completions
  if (!prevWord || (tokens.length === 1 && !isAfterSpace)) {
    candidates = CLI_COMPLETIONS.commands;
  } else if (firstWord === 'systemctl') {
    if (prevWord === 'systemctl') {
      candidates = CLI_COMPLETIONS.systemctl_sub.concat(CLI_COMPLETIONS.services);
    } else {
      candidates = CLI_COMPLETIONS.services.concat(['--no-pager', '-l']);
    }
  } else if (firstWord === 'journalctl') {
    if (prevWord === '-u') {
      candidates = CLI_COMPLETIONS.services;
    } else {
      candidates = CLI_COMPLETIONS.journalctl_flags.concat(CLI_COMPLETIONS.services);
    }
  } else if (firstWord === 'chronyc') {
    candidates = CLI_COMPLETIONS.chronyc_sub.concat(['-v']);
  } else if (firstWord === 'firewall-cmd') {
    candidates = CLI_COMPLETIONS.firewall_sub;
  } else if (firstWord === 'ip') {
    candidates = CLI_COMPLETIONS.ip_sub;
  } else if (firstWord === 'ss') {
    candidates = CLI_COMPLETIONS.ss_flags;
  } else if (firstWord === 'radtest') {
    candidates = ['test test 127.0.0.1 0 testing123'];
  } else if (['cat', 'tail', 'head', 'grep', 'less', 'more', 'vi', 'nano', 'ls'].indexOf(firstWord) !== -1 || currentToken.indexOf('/') === 0) {
    candidates = CLI_COMPLETIONS.common_paths;
  } else {
    candidates = CLI_COMPLETIONS.commands.concat(CLI_COMPLETIONS.common_paths);
  }

  // Filter local candidates
  var matches = [];
  var lowerTok = currentToken.toLowerCase();
  for (var i = 0; i < candidates.length; i++) {
    var c = candidates[i];
    if (c.toLowerCase().indexOf(lowerTok) === 0) {
      matches.push(c);
    }
  }

  // If it looks like a path or no local match found, try server autocomplete API
  if ((currentToken.indexOf('/') === 0 || currentToken.indexOf('./') === 0 || matches.length === 0) && currentToken.length > 0) {
    var fd = new FormData();
    fd.append('prefix', currentToken);
    fetch('/api/cli/autocomplete', { method: 'POST', body: fd })
      .then(function(r) { return r.json(); })
      .then(function(res) {
        if (res && res.matches && res.matches.length > 0) {
          var combined = matches.slice();
          for (var j = 0; j < res.matches.length; j++) {
            if (combined.indexOf(res.matches[j]) === -1) combined.push(res.matches[j]);
          }
          applyCompletionList(combined, currentToken, before, after);
        } else {
          applyCompletionList(matches, currentToken, before, after);
        }
      })
      .catch(function() {
        applyCompletionList(matches, currentToken, before, after);
      });
    return;
  }

  applyCompletionList(matches, currentToken, before, after);
}

document.addEventListener('click', function (e) {
  var b = e.target.closest && e.target.closest('[data-cmd]');
  if (b) runQuickCommand(b.getAttribute('data-cmd'));
});

// Global scope bindings
window.submitCliCommand = submitCliCommand;
window.runQuickCommand = runQuickCommand;
window.clearTerminalScreen = clearTerminalScreen;
window.copyTerminalText = copyTerminalText;
window.downloadTerminalLog = downloadTerminalLog;
window.toggleTerminalFullscreen = toggleTerminalFullscreen;
window.handleCliTabCompletion = handleCliTabCompletion;
window.pickTabSuggestion = pickTabSuggestion;
window.removeExistingTabHints = removeExistingTabHints;

function initCliTerminal() {
  var form = document.getElementById('cliForm');
  var inp = document.getElementById('cliCommandInput');
  var btn = document.getElementById('btnRunCommand');

  if (form && !form.dataset.cliBound) {
    form.dataset.cliBound = '1';
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      submitCliCommand();
    });
  }

  if (btn && !btn.dataset.cliBound) {
    btn.dataset.cliBound = '1';
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      submitCliCommand();
    });
  }

  if (inp && !inp.dataset.cliBound) {
    inp.dataset.cliBound = '1';
    try { inp.focus(); } catch(e) {}
    inp.addEventListener('input', function() { removeExistingTabHints(); });
    inp.addEventListener('keydown', function(e) {
      if (e.key === 'Tab' || e.keyCode === 9) {
        e.preventDefault();
        handleCliTabCompletion();
        return false;
      } else if (e.key === 'Escape' || e.keyCode === 27) {
        removeExistingTabHints();
      } else if (e.key === 'Enter' || e.keyCode === 13) {
        removeExistingTabHints();
        e.preventDefault();
        submitCliCommand();
      } else if (e.key === 'ArrowUp' || e.keyCode === 38) {
        e.preventDefault();
        if (cliHistory.length > 0 && historyCursor > 0) {
          historyCursor--;
          inp.value = cliHistory[historyCursor] || '';
        }
      } else if (e.key === 'ArrowDown' || e.keyCode === 40) {
        e.preventDefault();
        if (cliHistory.length > 0 && historyCursor < cliHistory.length - 1) {
          historyCursor++;
          inp.value = cliHistory[historyCursor] || '';
        } else {
          historyCursor = cliHistory.length;
          inp.value = '';
        }
      } else if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) {
        e.preventDefault();
        clearTerminalScreen();
      }
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initCliTerminal);
} else {
  initCliTerminal();
}

// autocomplete pills carry the suggestion in data-pick (file names never end up inside inline JS)
document.addEventListener('click', function(ev) {
  var p = ev.target.closest ? ev.target.closest('[data-pick]') : null;
  if (p) pickTabSuggestion(p.getAttribute('data-pick'));
});
