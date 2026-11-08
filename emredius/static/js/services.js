// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Services page: live status polling, journal terminal, restart / reboot confirmations
var currentSelectedService = 'radiusd';
    var autoRefreshTimer = null;
    var autoScrollEnabled = true;
    var userIsScrolledUp = false;
    var pendingAction = null;
    var activeSearchQuery = '';

    // In-memory array of log line objects:
    // { id, rawText, type, timestamp, isHeartbeat }
    var terminalLogLines = [];
    var knownLogLinesSet = new Set();
    var serviceInitialLoad = true;

    function toggleAutoScroll() {
      autoScrollEnabled = !autoScrollEnabled;
      const lbl = document.getElementById('autoScrollLabel');
      if (lbl) {
        lbl.innerText = autoScrollEnabled ? 'Oto-Kaydır: Açık' : 'Oto-Kaydır: Kapalı';
      }
      if (autoScrollEnabled) {
        scrollToTerminalBottom();
      }
    }

    function scrollToTerminalBottom() {
      const term = document.getElementById('serviceLogTerminal');
      if (term) {
        term.scrollTop = term.scrollHeight;
        userIsScrolledUp = false;
        const btn = document.getElementById('btnScrollToBottom');
        if (btn) btn.style.display = 'none';
      }
    }

    function selectServiceForLogs(srvKey) {
      if (currentSelectedService !== srvKey) {
        currentSelectedService = srvKey;
        serviceInitialLoad = true;
        terminalLogLines = [];
        knownLogLinesSet.clear();
        
        document.querySelectorAll('.btn-service-pill').forEach(btn => btn.classList.remove('active'));
        const pill = document.getElementById('pill-' + srvKey);
        if (pill) pill.classList.add('active');

        fetchSelectedServiceLogs();
      }
    }

    function applyLogSearchFilter(val) {
      activeSearchQuery = (val || '').trim().toLowerCase();
      const clearBtn = document.getElementById('btnClearLogSearch');
      if (clearBtn) clearBtn.style.display = activeSearchQuery ? 'block' : 'none';
      renderTerminalOutput();
    }

    function clearLogSearch() {
      const input = document.getElementById('logSearchInput');
      if (input) input.value = '';
      applyLogSearchFilter('');
    }

    function clearTerminalScreen() {
      terminalLogLines = [];
      knownLogLinesSet.clear();
      renderTerminalOutput();
    }

    function sendServiceTestPing() {
      const btn = document.getElementById('btnTestPing');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Gönderiliyor...';
      }

      fetch('/api/service/test-ping/' + currentSelectedService, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-bolt" style="color:#f97316;"></i> <span>Test Paketi Gönder</span>';
          }
          if (window.copyWithFeedback) {
            window.copyWithFeedback('', btn, data.message || 'Test paketi gönderildi!');
          }
          // Fetch immediately to capture generated log line
          setTimeout(fetchSelectedServiceLogs, 400);
        })
        .catch(err => {
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-bolt" style="color:#f97316;"></i> <span>Test Paketi Gönder</span>';
          }
        });
    }

    function fetchSelectedServiceLogs() {
      const icon = document.getElementById('terminalRefreshIcon');
      if (icon) icon.classList.add('fa-spin');

      fetch('/api/service/status/' + currentSelectedService)
        .then(r => r.json())
        .then(data => {
          if (icon) icon.classList.remove('fa-spin');
          if (data.success) {
            updateMetaBar(data.detail);
            updateLeftCard(data.detail);
            processIncomingLogs(data.lines || [], data.detail, data.timestamp);
          } else {
            console.error('Log fetch error:', data.error);
          }
        })
        .catch(err => {
          if (icon) icon.classList.remove('fa-spin');
          console.error('Log network error:', err);
        });
    }

    function processIncomingLogs(incomingLines, detail, srvTime) {
      let newlyAddedCount = 0;

      if (serviceInitialLoad) {
        serviceInitialLoad = false;
        terminalLogLines = [];
        knownLogLinesSet.clear();

        // System header indicator
        terminalLogLines.push({
          id: 'sys-start-' + Date.now(),
          rawText: '=== ' + detail.name + ' (' + detail.unit + ') Canlı Log Terminali Başlatıldı ===',
          type: 'system',
          isHeartbeat: false
        });

        incomingLines.forEach((line, idx) => {
          if (!knownLogLinesSet.has(line)) {
            knownLogLinesSet.add(line);
            terminalLogLines.push({
              id: 'init-' + idx + '-' + Date.now(),
              rawText: line,
              type: detectLineType(line),
              isHeartbeat: false
            });
            newlyAddedCount++;
          }
        });
      } else {
        // Delta stream: check for new lines
        incomingLines.forEach((line, idx) => {
          if (!knownLogLinesSet.has(line)) {
            knownLogLinesSet.add(line);
            terminalLogLines.push({
              id: 'delta-' + Date.now() + '-' + idx,
              rawText: line,
              type: detectLineType(line),
              isHeartbeat: false
            });
            newlyAddedCount++;
          }
        });
      }

      // Only update terminal output if new lines arrived or on initial load
      if (newlyAddedCount > 0) {
        if (terminalLogLines.length > 250) {
          terminalLogLines = terminalLogLines.slice(terminalLogLines.length - 250);
        }
        renderTerminalOutput();
      }
    }

    function detectLineType(line) {
      const lower = line.toLowerCase();
      if (lower.includes('failed') || lower.includes('error') || lower.includes('crit') || lower.includes('fatal')) return 'error';
      if (lower.includes('warn') || lower.includes('reject') || lower.includes('notice')) return 'warning';
      if (lower.includes('accept') || lower.includes('success') || lower.includes('started') || lower.includes('ready to process')) return 'success';
      if (lower.includes('heartbeat') || lower.includes('canli nabiz')) return 'heartbeat';
      if (lower.includes('=== systemctl') || lower.includes('=== recent journal')) return 'system';
      return 'default';
    }

    function renderTerminalOutput() {
      const term = document.getElementById('serviceLogTerminal');
      if (!term) return;

      let filtered = terminalLogLines;
      const countBadge = document.getElementById('logSearchCountBadge');

      if (activeSearchQuery) {
        filtered = terminalLogLines.filter(item => item.rawText.toLowerCase().includes(activeSearchQuery));
        if (countBadge) {
          countBadge.style.display = 'inline-block';
          countBadge.innerText = filtered.length + ' eşleşme';
        }
      } else {
        if (countBadge) countBadge.style.display = 'none';
      }

      let html = '';
      filtered.forEach(item => {
        let esc = item.rawText.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        if (activeSearchQuery) {
          const lowerEsc = esc.toLowerCase();
          const qIndex = lowerEsc.indexOf(activeSearchQuery);
          if (qIndex !== -1) {
            const before = esc.substring(0, qIndex);
            const match = esc.substring(qIndex, qIndex + activeSearchQuery.length);
            const after = esc.substring(qIndex + activeSearchQuery.length);
            esc = before + '<mark style="background:#2563eb; color:#ffffff; border-radius:3px; padding:0 3px;">' + match + '</mark>' + after;
          }
        }

        if (item.type === 'heartbeat') {
          html += '<div style="color:#38bdf8; font-size:0.77rem; opacity:0.85; padding:1px 0; display:flex; align-items:center;"><span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:#10b981; margin-right:6px; box-shadow:0 0 6px #10b981; flex-shrink:0;"></span>' + esc + '</div>';
        } else if (item.type === 'error') {
          html += '<div style="color:#ef4444; font-weight:600; padding:1px 0;">' + esc + '</div>';
        } else if (item.type === 'warning') {
          html += '<div style="color:#f59e0b; padding:1px 0;">' + esc + '</div>';
        } else if (item.type === 'success') {
          html += '<div style="color:#10b981; font-weight:600; padding:1px 0;">' + esc + '</div>';
        } else if (item.type === 'system') {
          html += '<div style="color:#38bdf8; font-weight:700; margin:0.4rem 0; border-bottom:1px solid #1e293b; padding-bottom:2px;">' + esc + '</div>';
        } else {
          html += '<div style="color:#cbd5e1; padding:1px 0;">' + esc + '</div>';
        }
      });

      if (filtered.length === 0) {
        html = '<div style="color:#64748b; text-align:center; padding:2rem;">Arama kriterine uygun log satırı bulunamadı.</div>';
      }

      term.innerHTML = html;

      // Smart Auto-Scroll: only scroll down if auto-scroll is on and user is not scrolled up reading
      if (autoScrollEnabled && !userIsScrolledUp) {
        term.scrollTop = term.scrollHeight;
      }

      const updatedEl = document.getElementById('metaLastUpdated');
      if (updatedEl) {
        updatedEl.innerText = new Date().toLocaleTimeString();
      }
    }

    function updateMetaBar(detail) {
      if (!detail) return;
      document.getElementById('metaUnitName').innerText = detail.unit;
      document.getElementById('metaPid').innerText = detail.pid || '-';
      document.getElementById('metaMem').innerText = detail.memory || '-';
      const metaStorage = document.getElementById('metaStorage');
      if (metaStorage) metaStorage.innerText = detail.storage || '-';

      const dot = document.getElementById('metaStatusDot');
      const txt = document.getElementById('metaStatusText');
      if (detail.is_active) {
        dot.style.background = '#10b981';
        txt.style.color = '#10b981';
        txt.innerText = 'AKTİF (' + detail.substate + ')';
      } else {
        dot.style.background = '#ef4444';
        txt.style.color = '#ef4444';
        txt.innerText = 'DURDURULDU (' + detail.substate + ')';
      }

      const updatedEl = document.getElementById('metaLastUpdated');
      if (updatedEl) {
        updatedEl.innerText = new Date().toLocaleTimeString();
      }
    }

    function updateLeftCard(detail) {
      if (!detail) return;
      const key = detail.key;
      const pidEl = document.getElementById('pid-val-' + key);
      const memEl = document.getElementById('mem-val-' + key);
      const storageEl = document.getElementById('storage-val-' + key);
      const subEl = document.getElementById('sub-val-' + key);
      const badgeEl = document.getElementById('badge-status-' + key);

      if (pidEl) pidEl.innerText = detail.pid || '-';
      if (memEl) memEl.innerText = detail.memory || '-';
      if (storageEl) storageEl.innerText = detail.storage || '-';
      if (subEl) subEl.innerText = detail.substate || '-';

      if (badgeEl) {
        if (detail.is_active) {
          badgeEl.innerHTML = '<span class="badge" style="background:#dcfce7; color:#15803d; font-weight:700; padding:0.35rem 0.75rem; border-radius:6px; display:inline-flex; align-items:center; gap:0.35rem;"><span class="status-dot" style="background:#16a34a; width:8px; height:8px; border-radius:50%; display:inline-block;"></span> <span>ÇALIŞIYOR</span></span>';
        } else {
          badgeEl.innerHTML = '<span class="badge" style="background:#fee2e2; color:#b91c1c; font-weight:700; padding:0.35rem 0.75rem; border-radius:6px; display:inline-flex; align-items:center; gap:0.35rem;"><span class="status-dot" style="background:#dc2626; width:8px; height:8px; border-radius:50%; display:inline-block;"></span> <span>DURDURULDU</span></span>';
        }
      }
    }

    function toggleAutoRefreshLogs() {
      const btn = document.getElementById('btnAutoRefreshLogs');
      const icon = document.getElementById('autoRefreshIcon');
      const txt = document.getElementById('autoRefreshText');
      const liveBadge = document.getElementById('liveStatusBadgeText');

      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-secondary');
        icon.className = 'fa-solid fa-play';
        txt.innerText = 'Canlı Akış (Başlat)';
        if (liveBadge) liveBadge.innerText = 'DURAKLATILDI';
      } else {
        autoRefreshTimer = setInterval(fetchSelectedServiceLogs, 1000);
        btn.classList.remove('btn-secondary');
        btn.classList.add('btn-primary');
        icon.className = 'fa-solid fa-pause';
        txt.innerText = 'Canlı Akış (1s)';
        if (liveBadge) liveBadge.innerText = 'CANLI AKIŞ (1s)';
      }
    }

    // Modal Trigger: Service Restart
        function openModal(id) {
      var m = document.getElementById(id);
      if (m) { m.style.display = 'flex'; m.classList.add('show'); document.body.style.overflow = 'hidden'; }
    }
    function closeModal(id) {
      var m = document.getElementById(id);
      if (m) { m.style.display = 'none'; m.classList.remove('show'); document.body.style.overflow = ''; }
    }

function openConfirmRestart(srvKey, srvName, unitName) {
      pendingAction = { type: 'service', key: srvKey, name: srvName, unit: unitName };

      document.getElementById('confirmModalHeader').style.background = '#fffbeb';
      document.getElementById('confirmModalHeader').style.borderBottom = '1px solid #fef3c7';
      document.getElementById('confirmModalTitle').innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="color:#f59e0b;"></i> <span>Servis Yeniden Başlatma Onayı</span>';
      document.getElementById('confirmTargetTitle').innerText = srvName + ' (' + unitName + ')';
      document.getElementById('confirmTargetPrompt').innerText = srvName + ' servisini yeniden başlatmak istediğinize emin misiniz? Aktif kimlik doğrulama veya telemetri isteklerinde kısa süreli bir kesinti yaşanabilir.';
      document.getElementById('confirmDangerAlert').style.display = 'none';

      const execBtn = document.getElementById('btnExecuteConfirm');
      execBtn.style.background = '#2563eb';
      document.getElementById('confirmExecuteBtnText').innerText = 'Evet, Yeniden Başlat';

      openModal('modalConfirmRestart');
    }

    // Modal Trigger: Server Reboot
    function openConfirmServerReboot() {
      pendingAction = { type: 'reboot' };

      document.getElementById('confirmModalHeader').style.background = '#fee2e2';
      document.getElementById('confirmModalHeader').style.borderBottom = '1px solid #fecaca';
      document.getElementById('confirmModalTitle').innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="color:#dc2626;"></i> <span style="color:#991b1b;">Sunucu Yeniden Başlatma Onayı</span>';
      document.getElementById('confirmTargetTitle').innerText = 'AlmaLinux 8.10 İşletim Sistemi Sunucusu (192.0.2.10)';
      document.getElementById('confirmTargetPrompt').innerText = 'DİKKAT: AlmaLinux sunucusunu tamamen yeniden başlatmak istediğinize emin misiniz?';
      document.getElementById('confirmDangerAlert').style.display = 'block';

      const execBtn = document.getElementById('btnExecuteConfirm');
      execBtn.style.background = '#dc2626';
      document.getElementById('confirmExecuteBtnText').innerText = 'Evet, Sunucuyu Yeniden Başlat';

      openModal('modalConfirmRestart');
    }

    // Execute Confirmed Action
    function executeConfirmedRestart() {
      closeModal('modalConfirmRestart');
      if (!pendingAction) return;

      if (pendingAction.type === 'service') {
        const srvKey = pendingAction.key;
        const srvName = pendingAction.name;
        
        selectServiceForLogs(srvKey);
        const term = document.getElementById('serviceLogTerminal');
        term.innerHTML += '<div style="color:#f59e0b; font-weight:700; margin:0.75rem 0;">>>> [İŞLEM BAŞLATILDI] ' + escHtml(srvName) + ' servisi yeniden başlatılıyor... Lütfen bekleyin...</div>';
        term.scrollTop = term.scrollHeight;

        const restartBtn = document.getElementById('btn-restart-' + srvKey);
        if (restartBtn) {
          restartBtn.disabled = true;
          restartBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Başlatılıyor...';
        }

        fetch('/api/service/restart/' + srvKey, { method: 'POST' })
          .then(r => r.json())
          .then(data => {
            if (restartBtn) {
              restartBtn.disabled = false;
              restartBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Yeniden Başlat';
            }

            if (data.is_self) {
              term.innerHTML += '<div style="color:#10b981; font-weight:700; margin:0.75rem 0;">>>> [BİLGİ] ' + escHtml(data.message) + '</div>';
              term.scrollTop = term.scrollHeight;
              
              const webOverlay = document.getElementById('webRestartOverlay');
              if (webOverlay) webOverlay.style.display = 'flex';

              let count = 5;
              const timer = setInterval(() => {
                count--;
                const el = document.getElementById('webRestartSecs');
                if (el) el.innerText = count;
                if (count <= 0) {
                  clearInterval(timer);
                  const pollInterval = setInterval(() => {
                    fetch('/', { method: 'HEAD', cache: 'no-store' })
                      .then(res => {
                        if (res.ok || res.status === 401 || res.status === 302) {
                          clearInterval(pollInterval);
                          window.location.reload();
                        }
                      })
                      .catch(() => {});
                  }, 1000);
                }
              }, 1000);
            } else {
              if (data.success) {
                term.innerHTML += '<div style="color:#10b981; font-weight:700; margin:0.75rem 0;">>>> [BAŞARILI] ' + escHtml(data.message) + '</div>';
                renderTerminalOutput(data.logs);
                updateMetaBar(data.detail);
                updateLeftCard(data.detail);
              } else {
                term.innerHTML += '<div style="color:#ef4444; font-weight:700; margin:0.75rem 0;">>>> [HATA] ' + escHtml(data.message) + '</div>';
              }
            }
          })
          .catch(err => {
            if (restartBtn) {
              restartBtn.disabled = false;
              restartBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Yeniden Başlat';
            }
            term.innerHTML += '<div style="color:#ef4444; font-weight:700;">>>> [BAĞLANTI HATASI] ' + escHtml(err) + '</div>';
          });

      } else if (pendingAction.type === 'reboot') {
        const overlay = document.getElementById('serverRebootOverlay');
        if (overlay) overlay.style.display = 'flex';

        fetch('/api/server/reboot', { method: 'POST' })
          .then(r => r.json())
          .then(data => {
            let left = 50;
            const timer = setInterval(() => {
              left--;
              const secEl = document.getElementById('rebootSecs');
              if (secEl) secEl.innerText = left;
              if (left <= 0) {
                clearInterval(timer);
                const pingTimer = setInterval(() => {
                  fetch('/', { method: 'HEAD', cache: 'no-store' })
                    .then(res => {
                      if (res.ok || res.status === 401 || res.status === 302) {
                        clearInterval(pingTimer);
                        window.location.href = '/';
                      }
                    })
                    .catch(() => {});
                }, 2000);
              }
            }, 1000);
          })
          .catch(err => {
            alert('Reboot isteği gönderildi: ' + err);
          });
      }
    }

    function pollAllServicesLive() {
      fetch('/api/services/status/all')
        .then(r => r.json())
        .then(data => {
          if (data && data.success && data.services) {
            Object.values(data.services).forEach(s => {
              updateLeftCard(s);
              if (s.key === currentSelectedService) {
                updateMetaBar(s);
              }
            });
          }
        })
        .catch(() => {});
    }

    window.addEventListener('DOMContentLoaded', () => {
      const termEl = document.getElementById('serviceLogTerminal');
      if (termEl) {
        termEl.addEventListener('scroll', () => {
          const isAtBottom = (termEl.scrollHeight - termEl.scrollTop - termEl.clientHeight) < 35;
          userIsScrolledUp = !isAtBottom;
          const scrollBtn = document.getElementById('btnScrollToBottom');
          if (scrollBtn) {
            scrollBtn.style.display = userIsScrolledUp ? 'flex' : 'none';
          }
        });
      }

      fetchSelectedServiceLogs();
      // Start truly live streaming (1-second interval)
      autoRefreshTimer = setInterval(fetchSelectedServiceLogs, 1000);
      setInterval(pollAllServicesLive, 1000); // 1 saniyede bir tum servis durumlarini guncelle
    });
