// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// Live journal viewer: unit filter, search highlight, auto refresh.
var LOG_POLL_MS = 5000;
var isPaused = false;
var autoScrollEnabled = true;
var userIsScrolledUp = false;
var currentUnit = 'all';
var box = document.getElementById("logBox");
var activeSearchQuery = '';
var journalFetchInFlight = false;

function _escLog(v) {
  if (window.escHtml) return window.escHtml(v);
  return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                                   .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Smart Scroll detection
if (box) {
  box.scrollTop = box.scrollHeight;
  box.addEventListener('scroll', function() {
    var isAtBottom = (box.scrollHeight - box.scrollTop - box.clientHeight) < 35;
    userIsScrolledUp = !isAtBottom;
    var btn = document.getElementById('btnScrollDown');
    if (btn) btn.style.display = userIsScrolledUp ? 'flex' : 'none';
  });
}

function scrollLogToBottom() {
  if (box) {
    box.scrollTop = box.scrollHeight;
    userIsScrolledUp = false;
    var btn = document.getElementById('btnScrollDown');
    if (btn) btn.style.display = 'none';
  }
}

function toggleAutoScroll() {
  autoScrollEnabled = !autoScrollEnabled;
  var lbl = document.getElementById('autoScrollLabel');
  if (lbl) {
    lbl.innerText = autoScrollEnabled ? 'Oto-Kaydır: Açık' : 'Oto-Kaydır: Kapalı';
  }
  if (autoScrollEnabled) scrollLogToBottom();
}

function togglePauseLog() {
  isPaused = !isPaused;
  var btn = document.getElementById('pauseLogBtn');
  var icon = document.getElementById('pauseLogIcon');
  var txt = document.getElementById('pauseLogText');
  var badge = document.getElementById('journalLiveBadge');

  if (isPaused) {
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-secondary');
    icon.className = 'fa-solid fa-play';
    txt.innerText = 'Devam Et';
    if (badge) badge.innerText = 'DURAKLATILDI';
  } else {
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-secondary');
    icon.className = 'fa-solid fa-pause';
    txt.innerText = 'Dondur';
    if (badge) badge.innerText = 'CANLI AKIŞ (5s)';
  }
}

function setJournalUnit(unit, btn) {
  currentUnit = unit;
  document.querySelectorAll('.btn-journal-unit').forEach(function(b) {
    b.classList.remove('active');
  });
  if (btn) btn.classList.add('active');

  var titleEl = document.getElementById('journalConsoleTitle');
  var filterLbl = document.getElementById('lblCurrentFilter');
  if (unit === 'all') {
    if (titleEl) titleEl.innerText = 'AlmaLinux Sunucu Canlı Journal Akışı (journalctl -n 200)';
    if (filterLbl) filterLbl.innerText = 'Tüm Sistem (journalctl)';
  } else {
    if (titleEl) titleEl.innerText = 'Canlı Servis Journal Akışı: ' + unit + '.service';
    if (filterLbl) filterLbl.innerText = unit + '.service';
  }

  fetchJournalStreamNow();
}

function filterLogs(q) {
  activeSearchQuery = (q || '').trim().toLowerCase();
  var clearBtn = document.getElementById('btnClearSearch');
  var matchBadge = document.getElementById('logMatchCountBadge');
  if (clearBtn) clearBtn.style.display = activeSearchQuery ? 'block' : 'none';

  var lines = box.querySelectorAll('.log-line');
  var matchCount = 0;

  lines.forEach(function(l) {
    // textContent is UNESCAPED log text: it must be escaped again before going back into innerHTML
    var text = l.textContent || '';
    var lower = text.toLowerCase();
    if (!activeSearchQuery || lower.includes(activeSearchQuery)) {
      l.style.display = 'block';
      matchCount++;
      var qIdx = activeSearchQuery ? lower.indexOf(activeSearchQuery) : -1;
      if (qIdx !== -1 && lower.length === text.length) {
        var before = text.substring(0, qIdx);
        var match = text.substring(qIdx, qIdx + activeSearchQuery.length);
        var after = text.substring(qIdx + activeSearchQuery.length);
        l.innerHTML = _escLog(before) + '<mark class="log-highlight">' + _escLog(match) + '</mark>' + _escLog(after);
      } else {
        l.innerHTML = _escLog(text);
      }
    } else {
      l.style.display = 'none';
    }
  });

  if (matchBadge) {
    if (activeSearchQuery) {
      matchBadge.style.display = 'inline-block';
      matchBadge.innerText = matchCount + ' eşleşme';
    } else {
      matchBadge.style.display = 'none';
    }
  }
}

function clearSearch() {
  var inp = document.getElementById('logSearchInput');
  if (inp) inp.value = '';
  filterLogs('');
}

function fetchJournalStreamNow() {
  if (journalFetchInFlight) return;
  journalFetchInFlight = true;
  var icon = document.getElementById('refreshBtnIcon');
  if (icon) icon.classList.add('fa-spin');

  fetch('/api/logs/stream?unit=' + encodeURIComponent(currentUnit), { credentials: 'same-origin' })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      journalFetchInFlight = false;
      if (icon) icon.classList.remove('fa-spin');
      if (data && data.success && typeof data.html === 'string') {
        box.innerHTML = data.html;  // server-side escaped lines
        var syncEl = document.getElementById('journalLastSync');
        if (syncEl) syncEl.innerText = data.timestamp || new Date().toLocaleTimeString();

        if (activeSearchQuery) {
          filterLogs(activeSearchQuery);
        }

        if (autoScrollEnabled && !userIsScrolledUp) {
          box.scrollTop = box.scrollHeight;
        }
      }
    })
    .catch(function(err) {
      journalFetchInFlight = false;
      if (icon) icon.classList.remove('fa-spin');
    });
}

// Auto-refresh stream (skipped while paused or while the tab is hidden)
setInterval(function() {
  if (!isPaused && !document.hidden) {
    fetchJournalStreamNow();
  }
}, LOG_POLL_MS);

document.addEventListener('DOMContentLoaded', function() {
  var syncEl = document.getElementById('journalLastSync');
  if (syncEl) syncEl.innerText = new Date().toLocaleTimeString();
});
