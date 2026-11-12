// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// ==================== GLOBAL SECURITY HELPERS (CSRF + XSS) ====================
(function() {
  var meta = document.querySelector('meta[name="csrf-token"]');
  window.CSRF_TOKEN = meta ? meta.getAttribute('content') : '';

  // HTML escaping for any value that ends up in innerHTML
  window.escHtml = function(v) {
    if (v === null || v === undefined) return '';
    return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };

  function sameOrigin(url) {
    try { return new URL(url, window.location.href).origin === window.location.origin; } catch (e) { return false; }
  }

  // 1) fetch(): add X-CSRF-Token to every same-origin state-changing request
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function(input, init) {
      init = init || {};
      var method = (init.method || (input && input.method) || 'GET').toUpperCase();
      var url = (typeof input === 'string') ? input : (input && input.url) || '';
      if (method !== 'GET' && method !== 'HEAD' && sameOrigin(url)) {
        var headers = new Headers(init.headers || (input && input.headers) || {});
        if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', window.CSRF_TOKEN);
        init.headers = headers;
        if (!init.credentials) init.credentials = 'same-origin';
      }
      return origFetch.call(this, input, init);
    };
  }

  function addCsrfField(form) {
    if (!form || (form.method || '').toUpperCase() !== 'POST') return;
    if (form.querySelector('input[name="_csrf_token"]')) return;
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = '_csrf_token'; i.value = window.CSRF_TOKEN;
    form.appendChild(i);
  }

  // 2) Every POST form gets the CSRF token (also forms created dynamically)
  document.addEventListener('submit', function(ev) { addCsrfField(ev.target); }, true);
  var origSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() { addCsrfField(this); return origSubmit.call(this); };

  // 3) State-changing links are sent as POST (the server no longer accepts GET for these)
  var POST_LINK_PREFIXES = [
    '/user/disable/', '/user/enable/', '/user/delete/', '/voucher/delete/', '/vouchers/purge-expired',
    '/mac/delete/', '/nas/delete/', '/session/disconnect/', '/sessions/clean-ghosts',
    '/backup/create', '/backup/restore/', '/backup/delete/', '/group/delete/', '/role/delete/',
    '/admin/toggle-status/', '/admin/delete/', '/restart-radius'
  ];
  window.postNavigate = function(href) {
    var u = new URL(href, window.location.href);
    var f = document.createElement('form');
    f.method = 'POST';
    f.action = u.pathname + u.search;
    f.style.display = 'none';
    document.body.appendChild(f);
    f.submit();
  };
  document.addEventListener('click', function(ev) {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
    var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if (!a || !sameOrigin(a.href)) return;
    var p = new URL(a.href, window.location.href).pathname;
    for (var k = 0; k < POST_LINK_PREFIXES.length; k++) {
      if (p.indexOf(POST_LINK_PREFIXES[k]) === 0) {
        ev.preventDefault();
        window.postNavigate(a.href);
        return;
      }
    }
  }, false);
})();


window.switchTab = function(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(function(el) { el.style.display = 'none'; });
  var target = document.getElementById(tabId);
  if (target) target.style.display = 'block';
  
  if (btn && btn.parentElement) {
    btn.parentElement.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
  } else {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    if (btn) btn.classList.add('active');
  }
};

window.openModal = function(id) {
  var m = document.getElementById(id);
  if (m) {
    m.style.display = 'flex';
    m.classList.add('show');
    document.body.style.overflow = 'hidden';
  }
};
window.closeModal = function(id) {
  var m = document.getElementById(id);
  if (m) {
    m.style.display = 'none';
    m.classList.remove('show');
    document.body.style.overflow = '';
  }
};
function openModal(id) {
  if (window.openModal) window.openModal(id);
}
function closeModal(id) {
  if (window.closeModal) window.closeModal(id);
}
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-backdrop.show, .modal-backdrop[style*="display: flex"], .modal-backdrop[style*="display:flex"], .modal-backdrop[style*="display: block"], .modal-backdrop[style*="display:block"]').forEach(function(m) {
      if (m.id && m.style.display !== 'none') {
        window.closeModal(m.id);
      }
    });
  }
});
document.addEventListener('click', function(e) {
  if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
    if (e.target.id) {
      window.closeModal(e.target.id);
    }
  }
});

/* Sidebar Toggle & Auto-Close Logic */
function toggleSidebar() {
  if (window.innerWidth <= 1024) {
    document.body.classList.toggle('sidebar-mobile-open');
  } else {
    var isCol = document.documentElement.classList.toggle('sidebar-collapsed');
    localStorage.setItem('sidebar_collapsed', isCol ? 'true' : 'false');
  }
}

function closeSidebarMobile() {
  document.body.classList.remove('sidebar-mobile-open');
}

window.addEventListener('resize', function() {
  if (window.innerWidth > 1024) {
    document.body.classList.remove('sidebar-mobile-open');
    if (localStorage.getItem('sidebar_collapsed') !== 'true') {
      document.documentElement.classList.remove('sidebar-collapsed');
    }
  }
});

/* Dark / Light Theme Logic */
function toggleTheme() {
  var curr = document.documentElement.getAttribute('data-theme') || 'light';
  var next = (curr === 'dark') ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('app_theme', next);
  syncThemeUI(next);
}

function syncThemeUI(theme) {
  var icon = document.getElementById('themeToggleIcon');
  if (icon) {
    if (theme === 'dark') {
      icon.className = 'fa-solid fa-sun';
      icon.style.color = '#f59e0b';
    } else {
      icon.className = 'fa-solid fa-moon';
      icon.style.color = '#cbd5e1';
    }
  }
}

/* Live NTP Clock in Topbar */
(function initNtpClock() {
  var clockEl = null;
  var offset = 0;

  function pad(n) { return n < 10 ? '0' + n : n; }

  function renderClock() {
    if (!clockEl) clockEl = document.getElementById('topbarNtpTime');
    if (!clockEl) return;
    var d = new Date(Date.now() + offset);
    clockEl.textContent = pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function syncWithServer() {
    fetch('/api/system/time')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data && data.timestamp) {
          offset = (data.timestamp * 1000) - Date.now();
          renderClock();
        }
      })
      .catch(function() {});
  }

  document.addEventListener('DOMContentLoaded', function() {
    clockEl = document.getElementById('topbarNtpTime');
    syncWithServer();
    setInterval(renderClock, 1000);
    setInterval(syncWithServer, 60000);

    // The sidebar buttons call toggleSidebar() from their onclick attribute only; a second handler here
    // toggled the sidebar twice per click (open + close again).

    // Hybrid Sidebar Scroll Preservation & Mobile Handler
    var navEl = document.getElementById('sidebarNav');
    if (navEl) {
      // Record scroll position continuously while scrolling
      navEl.addEventListener('scroll', function() {
        sessionStorage.setItem('sidebar_scroll_top', navEl.scrollTop);
      }, { passive: true });

      // Save scroll position immediately when clicking any nav item
      navEl.querySelectorAll('.nav-item').forEach(function(item) {
        item.addEventListener('click', function() {
          sessionStorage.setItem('sidebar_scroll_top', navEl.scrollTop);
          if (window.innerWidth <= 1024) {
            closeSidebarMobile();
          }
        });
      });

      // Secondary alignment check after complete page layout
      var savedPos = sessionStorage.getItem('sidebar_scroll_top');
      if (savedPos !== null) {
        navEl.scrollTop = parseInt(savedPos, 10);
      } else {
        var activeItem = navEl.querySelector('.nav-item.active');
        if (activeItem) {
          activeItem.scrollIntoView({ block: 'nearest', behavior: 'instant' });
        }
      }
    }

    // Sync theme UI icon
    syncThemeUI(document.documentElement.getAttribute('data-theme') || 'light');
  });
})();
