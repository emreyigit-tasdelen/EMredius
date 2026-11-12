// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// SNMP NMS page: devices, charts, alarms, topology (vis-network), sample config modal
window.TOPOLOGY_DEVICES = JSON.parse(document.getElementById('snmpTopology').textContent);
window.TOPOLOGY_SERVER_IP = JSON.parse(document.getElementById('snmpServerIp').textContent);
window._selectedTopoDevId = null;
window._selectedTopoDevIp = null;


    // Wrap (not redeclare) the shared modal helpers: a top-level function declaration with these names would replace
    // window.openModal with itself and recurse forever, killing every modal button.
    (function () {
      const baseOpen = window.openModal, baseClose = window.closeModal;
      window.openModal = function (id) {
        if (baseOpen) {
          baseOpen(id);
        } else {
          const m = document.getElementById(id);
          if (m) { m.style.display = 'flex'; m.classList.add('show'); document.body.style.overflow = 'hidden'; }
        }
        if (id === 'modalSampleSnmpConfig' && typeof renderSnmpSnippet === 'function') renderSnmpSnippet();
      };
      window.closeModal = function (id) {
        if (baseClose) {
          baseClose(id);
        } else {
          const m = document.getElementById(id);
          if (m) { m.style.display = 'none'; m.classList.remove('show'); document.body.style.overflow = ''; }
        }
      };
    })();
    // JSON fetch that surfaces HTTP/parse errors as Error(message) instead of silently failing.
    function snmpApi(url, opts) {
      return fetch(url, opts).then(function(r) {
        return r.text().then(function(t) {
          var data = null;
          try { data = JSON.parse(t); } catch (e) { /* non-JSON body */ }
          if (!r.ok || (data && data.error)) {
            throw new Error((data && data.error) || ('HTTP ' + r.status));
          }
          if (data === null) throw new Error('Geçersiz sunucu yanıtı');
          return data;
        });
      });
    }
    function snmpPost(url, payload) {
      return snmpApi(url, {method: 'POST', headers: {'Content-Type': 'application/json'},
                           body: JSON.stringify(payload || {})});
    }

    let trafficChart = null;
    let telemetryTimer = null;
    let currentDevId = null;
    let currentIfIdx = 1;

    function initTrafficChart() {
      const ctx = document.getElementById('trafficCanvas');
      if (!ctx) return;
      trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Gelen Trafik (Inbound bps)',
              borderColor: '#16a34a',
              backgroundColor: 'rgba(22, 163, 74, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              data: []
            },
            {
              label: 'Giden Trafik (Outbound bps)',
              borderColor: '#2563eb',
              backgroundColor: 'rgba(37, 99, 235, 0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              data: []
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 400 },
          scales: {
            y: {
              beginAtZero: true,
              title: { display: true, text: 'Bits Per Second (bps)' }
            },
            x: {
              title: { display: true, text: 'Zaman Damgası' }
            }
          }
        }
      });
    }

    function fetchTelemetryData() {
      if (!currentDevId || !trafficChart) return;
      snmpApi('/api/snmp/telemetry/' + currentDevId + '/' + currentIfIdx)
        .then(data => {
          if (!data || !data.points) return;
          const labels = [];
          const inData = [];
          const outData = [];
          data.points.forEach(p => {
            const timeStr = p.timestamp ? p.timestamp.split(' ')[1] || p.timestamp : '';
            labels.push(timeStr);
            inData.push(p.in_bps || 0);
            outData.push(p.out_bps || 0);
          });
          trafficChart.data.labels = labels;
          trafficChart.data.datasets[0].data = inData;
          trafficChart.data.datasets[1].data = outData;
          trafficChart.update();
        }).catch(e => console.log('Telemetry error:', e));
    }

    function viewDeviceTraffic(devId, ip) {
      currentDevId = devId;
      currentIfIdx = 1;
      const select = document.getElementById('chartDevSelect');
      if (select) select.value = devId;
      switchTab('tab-snmp-chart', document.querySelector('.tab-btn[onclick*="tab-snmp-chart"]'));
      loadDeviceInterfaces(devId);
      fetchTelemetryData();
    }

    function loadDeviceInterfaces(devId) {
      snmpApi('/api/snmp/devices/' + devId + '/interfaces')
        .then(ifs => {
          if (!Array.isArray(ifs)) ifs = [];
          const ifSel = document.getElementById('chartIfSelect');
          if (!ifSel) return;
          ifSel.innerHTML = '';
          ifs.forEach(item => {
            const opt = document.createElement('option');
            opt.value = item.if_index;
            opt.text = (item.if_name || item.if_descr || 'Port ' + item.if_index) + ' (Index: ' + item.if_index + ')';
            ifSel.appendChild(opt);
          });
          if (ifs.length > 0) {
            currentIfIdx = ifs[0].if_index;
          }
          fetchTelemetryData();
        }).catch(e => console.warn('Interface list error:', e));
    }

    function onChartDeviceChange(devId) {
      currentDevId = devId;
      loadDeviceInterfaces(devId);
    }

    function onChartIfChange(ifIdx) {
      currentIfIdx = ifIdx;
      fetchTelemetryData();
    }

    function toggleV3Fields(val) {
      document.getElementById('v2Fields').style.display = val === 'v2c' ? 'block' : 'none';
      document.getElementById('v3Fields').style.display = val === 'v3' ? 'block' : 'none';
    }

    function submitAddSnmpDev() {
      const payload = {
        ip: document.getElementById('mDevIp').value,
        port: parseInt(document.getElementById('mDevPort').value, 10) || 161,
        version: document.getElementById('mDevVer').value,
        community: document.getElementById('mDevComm').value,
        v3_user: document.getElementById('mV3User').value,
        v3_auth_proto: document.getElementById('mV3AuthProto').value,
        v3_auth_key: document.getElementById('mV3AuthKey').value,
        v3_priv_proto: document.getElementById('mV3PrivProto').value,
        v3_priv_key: document.getElementById('mV3PrivKey').value,
        vendor: document.getElementById('mDevVendor').value
      };
      snmpPost('/api/snmp/devices', payload)
        .then(() => (window.EM ? window.EM.refresh() : location.reload()))
        .catch(err => alert('Hata: ' + err.message));
    }

    function deleteSnmpDev(id) {
      if (!confirm('Bu SNMP cihazını silmek istediğinize emin misiniz?')) return;
      snmpApi('/api/snmp/devices/' + id, {method: 'DELETE'})
        .then(() => (window.EM ? window.EM.refresh() : location.reload()))
        .catch(err => alert('Silme hatası: ' + err.message));
    }

    function runDiscoveryScan() {
      const btn = document.getElementById('btnDiscScan');
      if (window._discJob) {   // second click while a background scan runs = stop it
        snmpApi('/api/snmp/discovery/scan/' + window._discJob, {method: 'DELETE'}).catch(() => {});
        btn.disabled = true;
        return;
      }
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Taranıyor...';
      const payload = {
        cidr: document.getElementById('discCidr').value,
        port: parseInt(document.getElementById('discPort').value, 10) || 161,
        community: document.getElementById('discComm').value
      };
      const pollJob = (jobId) => new Promise((resolve, reject) => {
        window._discJob = jobId;
        btn.disabled = false;
        const tick = () => snmpApi('/api/snmp/discovery/scan/' + jobId).then(r => {
          if (r.status === 'running') {
            const pct = r.total ? Math.floor(100 * (r.done || 0) / r.total) : 0;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> %' + pct + ' (' + (r.done || 0) + '/' + r.total +
              ', bulunan ' + (r.total_found || 0) + ') — durdurmak için tıkla';
            return setTimeout(tick, 3000);
          }
          if (r.status === 'error') return reject(new Error(r.error));
          resolve(r);
        }).catch(reject);
        tick();
      }).finally(() => { window._discJob = null; });
      snmpPost('/api/snmp/discovery/scan', payload).then(data => data.job_id ? pollJob(data.job_id) : data).then(data => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-radar"></i> Ağı Tara ve Keşfet';
        document.getElementById('discResults').style.display = 'block';
        const container = document.getElementById('discTableContainer');
        if (!data.devices || data.devices.length === 0) {
          container.innerHTML = '<p style="color:var(--text-secondary); text-align:center; padding:1.5rem;">Belirtilen CIDR bloğunda yanıt veren SNMP cihazı bulunamadı.</p>';
          return;
        }
        let html = '<table class="data-table"><thead><tr><th>IP</th><th>Vendor</th><th>SysName</th><th>Açıklama</th><th>Eylem</th></tr></thead><tbody>';
        data.devices.forEach(d => {
          html += '<tr><td><code>' + escHtml(d.ip) + '</code></td><td><span class="badge" style="background:#eff6ff; color:#1d4ed8;">' + escHtml(d.vendor) + '</span></td><td>' + escHtml(d.sys_name || '-') + '</td><td style="font-size:0.8rem;">' + (d.sys_descr ? escHtml(d.sys_descr.substring(0, 50)) + '...' : '-') + '</td><td><button class="btn btn-sm btn-primary" data-quick-add="1" data-ip="' + escHtml(d.ip) + '" data-vendor="' + escHtml(d.vendor) + '" data-sysname="' + escHtml(d.sys_name || '') + '">Envantere Ekle</button></td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      }).catch(err => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-radar"></i> Ağı Tara ve Keşfet';
        alert('Tarama hatası: ' + (err && err.message || err));
      });
    }

    function quickAddDevice(ip, vendor, sysName) {
      const payload = {
        ip: ip,
        port: 161,
        version: 'v2c',
        community: document.getElementById('discComm').value || 'public',
        vendor: vendor,
        sys_name: sysName
      };
      snmpPost('/api/snmp/devices', payload)
        .then(() => {
          alert(ip + ' cihazı envantere başarıyla eklendi!');
          (window.EM ? window.EM.refresh() : location.reload());
        })
        .catch(err => alert('Hata: ' + err.message));
    }

    function ackAlarm(id) {
      snmpPost('/api/snmp/alarms/' + id + '/ack')
        .then(() => (window.EM ? window.EM.refresh() : location.reload()))
        .catch(err => alert('Alarm onay hatası: ' + err.message));
    }

    function sendTestWebhook() {
      const payload = {
        telegram_bot_token: document.getElementById('mWebTgToken').value,
        telegram_chat_id: document.getElementById('mWebTgChat').value,
        slack_webhook_url: document.getElementById('mWebSlack').value
      };
      if (!payload.telegram_bot_token && !payload.slack_webhook_url) {
        alert('Telegram bot token veya Slack webhook URL girin.');
        return;
      }
      snmpPost('/api/snmp/webhooks/test', payload).then(data => {
        alert('Webhook test yanıtı: ' + JSON.stringify(data.results));
      }).catch(err => alert('Webhook test hatası: ' + err.message));
    }

    function fitTopologyView() {
      if (window.topoNetwork && typeof window.topoNetwork.fit === 'function') {
        window.topoNetwork.fit();
      }
    }

    function toggleTopologyPhysics() {
      if (window.topoNetwork) {
        const cur = (window.topoNetwork.physics && window.topoNetwork.physics.physicsEnabled !== undefined) ? window.topoNetwork.physics.physicsEnabled : true;
        window.topoNetwork.setOptions({ physics: { enabled: !cur } });
        const btn = document.getElementById('btnTopoPhysics');
        if (btn) btn.innerText = !cur ? 'Fizik: Açık' : 'Fizik: Kapalı';
        const lbl = document.getElementById('lblTopoPhysics');
        if (lbl) lbl.innerText = !cur ? 'Fizik: Açık' : 'Fizik: Kapalı';
      }
    }

    function reloadTopologyData() {
      if (typeof loadTopologyData === 'function') {
        loadTopologyData(true);
      } else {
        (window.EM ? window.EM.refresh() : location.reload());
      }
    }

    function closeTopoDetail() {
      const d = document.getElementById('topoDetailPanel');
      if (d) d.style.display = 'none';
      const c = document.getElementById('topoNodeDetailCard');
      if (c) c.style.display = 'none';
    }

    function onTopoBtnViewTrafficClick() {
      if (window._selectedTopoDevId) {
        viewDeviceTraffic(window._selectedTopoDevId, window._selectedTopoDevIp);
      }
    }

    function topoColors(st) {
      if (st === 'ONLINE') return { node: '#10b981', edge: '#3b82f6' };
      return { node: '#ef4444', edge: '#ef4444' };
    }

    // Cihaz türüne göre şekil: router/switch kare (farklı renk), diğerleri ikon (FontAwesome)
    const TOPO_KIND = {
      'Router': { shape: 'square', color: '#7c3aed' }, 'Switch': { shape: 'square', color: '#2563eb' },
      'IP Telefon': { icon: '' }, 'Access Point': { icon: '' }, 'Sunucu': { icon: '' }, 'Firewall': { icon: '' }
    };
    function topoNodeStyle(d, st) {
      const k = TOPO_KIND[d.kind] || null, c = topoColors(st).node;
      if (k && k.icon) return { shape: 'icon', icon: { face: '"Font Awesome 6 Free"', weight: '900', code: k.icon, size: 36, color: c } };
      if (k) return { shape: 'square', size: 22, color: { background: k.color, border: c, highlight: { background: k.color, border: c } } };
      return { shape: 'dot', size: 20, color: c };
    }

    let _topoBusy = false, _topoFirst = true;
    function loadTopologyData(manual) {
      if (_topoBusy) return;
      _topoBusy = true;
      initTopologyNetwork();
      fetch('/snmp/topology.json' + (manual ? '?force=1' : ''), { credentials: 'same-origin', cache: 'no-store' })
        .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(applyTopologyData)
        .catch(function(err) { console.warn('Topology refresh error:', err); })
        .finally(function() { _topoBusy = false; });
    }

    function applyTopologyData(res) {
      initTopologyNetwork();
          const devs = res.devices || [];
          window.TOPOLOGY_DEVICES.length = 0;
          devs.forEach(function(d) { window.TOPOLOGY_DEVICES.push(d); });
          const net = window.topoNetwork;
          if (net && net.body && net.body.data) {
            const nodes = net.body.data.nodes, edges = net.body.data.edges;
            devs.forEach(function(d) {
              const c = topoColors(d.live_status);
              if (nodes.get(d.id)) {
                nodes.update(Object.assign({ id: d.id, label: (d.sys_name || d.ip) + '\n(' + (d.vendor || 'SNMP') + ')', devData: d }, topoNodeStyle(d, d.live_status)));
              } else {
                nodes.add(Object.assign({ id: d.id, label: (d.sys_name || d.ip) + '\n(' + (d.vendor || 'SNMP') + ')',
                            font: { color: '#ffffff', face: 'Segoe UI, sans-serif' }, devData: d }, topoNodeStyle(d, d.live_status)));
                edges.add({ from: 'core', to: d.id, color: { color: c.edge }, width: 2 });
              }
              edges.get().filter(function(e) { return e.to === d.id; }).forEach(function(e) {
                edges.update({ id: e.id, color: { color: c.edge } });
              });
            });
            const ids = devs.map(function(d) { return d.id; });
            nodes.get().forEach(function(n) {
              if (n.id !== 'core' && ids.indexOf(n.id) < 0) {
                nodes.remove(n.id);
                edges.get().filter(function(e) { return e.to === n.id; }).forEach(function(e) { edges.remove(e.id); });
              }
            });
          }
          updateSnmpTable(devs, res);
          const lu = document.getElementById('topoLastUpdate');
          if (lu) lu.innerText = 'son güncelleme: ' + new Date().toLocaleTimeString('tr-TR');
          const sub = document.getElementById('topoLiveSummary');
          if (sub) sub.innerText = res.online_count + ' SNMP açık / ' + res.ping_only_count + ' ping var, SNMP yok / ' +
            (res.total - res.online_count - res.ping_only_count) + ' kapalı';
          if (_topoFirst && net && typeof net.fit === 'function') { net.fit(); _topoFirst = false; }
    }

    function updateSnmpTable(devs, res) {
      const sm = document.getElementById('snmpOnlineSummary');
      if (sm) sm.innerText = res.online_count + ' Çevrimiçi / ' + (res.total - res.online_count) + ' Çevrimdışı';
      devs.forEach(function(d) {
        const tr = document.querySelector('tr[data-dev-id="' + d.id + '"]');
        if (!tr) return;
        const on = d.live_status === 'ONLINE';
        const st = tr.querySelector('.c-status');
        if (st) {
          const note = (on && d.snmp_ok === false) ? ' (SNMP yok)' : '';
          st.innerHTML = '<span class="badge" style="background:' + (on ? '#dcfce7' : '#fee2e2') + '; color:' + (on ? '#166534' : '#991b1b') +
            ';"><i class="fa-solid fa-circle" style="font-size:0.5rem;"></i> ' + (on ? 'ONLINE' : 'OFFLINE') + escHtml(note) + '</span>';
        }
        const pt = tr.querySelector('.c-ports');
        if (pt) pt.innerHTML = '<span class="badge" style="background:#f8fafc; color:#334155;">' + (parseInt(d.interface_count, 10) || 0) + ' Port</span>';
        [['.c-cpu', d.last_cpu, 80], ['.c-ram', d.last_ram, 85]].forEach(function(x) {
          const el = tr.querySelector(x[0]);
          const v = parseFloat(x[1]);
          if (el) el.innerHTML = '<span style="font-weight:600; color:' + (!isNaN(v) && v > x[2] ? '#dc2626' : '#16a34a') + ';">' + (isNaN(v) ? '-' : v.toFixed(1) + '%') + '</span>';
        });
      });
    }

    // Gerçek canlı: SSE ile sunucu değişikliği anında iter; SSE yoksa/dolmuşsa 10 sn polling'e düşer. Yenile = elle anında çek.
    let _topoES = null, _topoSseOk = false;
    function stopTopologySse() {
      if (_topoES) { try { _topoES.close(); } catch(e) {} }
      _topoES = null; _topoSseOk = false;
    }
    function startTopologySse() {
      if (!window.EventSource || _topoES || document.hidden) return;
      try {
        const es = new EventSource('/snmp/topology/stream');
        _topoES = es;
        es.onmessage = function(ev) {
          try { applyTopologyData(JSON.parse(ev.data)); _topoSseOk = true; } catch(e) { console.warn('SSE parse', e); }
        };
        es.onerror = function() {
          _topoSseOk = false;
          if (es.readyState === 2) { _topoES = null; setTimeout(startTopologySse, 15000); }  // 503/limit: polling sürer
        };
      } catch(e) { _topoES = null; }
    }
    setInterval(function() { if (!document.hidden && !_topoSseOk) loadTopologyData(false); }, 10000);
    document.addEventListener('visibilitychange', function() {
      if (document.hidden) { stopTopologySse(); } else { loadTopologyData(false); startTopologySse(); }
    });
    window.addEventListener('beforeunload', stopTopologySse);
    window.addEventListener('DOMContentLoaded', startTopologySse);
    window.addEventListener('DOMContentLoaded', function() { loadTopologyData(false); });

    function initTopologyNetwork() {
      const container = document.getElementById('topologyNetworkCanvas');
      if (!container) return;
      if (window.topoNetwork) {
        try { window.topoNetwork.fit(); } catch(e) {}
        return;
      }
      if (typeof vis === 'undefined' || !vis.Network) {
        console.warn('Vis.js not loaded yet');
        return;
      }
      try {
        const rawDevs = window.TOPOLOGY_DEVICES || [];
        const serverIp = window.TOPOLOGY_SERVER_IP || '127.0.0.1';
        const nodesArray = [
          {
            id: 'core',
            label: 'Core NMS\n' + serverIp,
            shape: 'box',
            color: '#2563eb',
            font: { color: '#ffffff', face: 'Segoe UI, sans-serif' },
            margin: 10
          }
        ];
        const edgesArray = [];

        rawDevs.forEach(function(d) {
          const isOnline = (d.status === 'ONLINE');
          nodesArray.push(Object.assign({
            id: d.id,
            label: (d.sys_name || d.ip) + '\n(' + (d.vendor || 'SNMP') + ')',
            font: { color: '#ffffff', face: 'Segoe UI, sans-serif' },
            devData: d
          }, topoNodeStyle(d, d.live_status || d.status)));
          edgesArray.push({
            from: 'core',
            to: d.id,
            color: { color: isOnline ? '#3b82f6' : '#ef4444' },
            width: 2
          });
        });

        const data = {
          nodes: new vis.DataSet(nodesArray),
          edges: new vis.DataSet(edgesArray)
        };
        const options = {
          physics: {
            enabled: true,
            barnesHut: { gravitationalConstant: -2500, springLength: 120 }
          },
          interaction: { hover: true }
        };

        window.topoNetwork = new vis.Network(container, data, options);

        window.topoNetwork.on('selectNode', function(params) {
          if (params.nodes && params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            if (nodeId === 'core') {
              showTopoNodeDetail({
                sys_name: 'Core NMS Server',
                ip: serverIp,
                vendor: 'AlmaLinux OS',
                status: 'ONLINE',
                interface_count: '-',
                last_cpu: 'OK'
              });
            } else {
              const matched = rawDevs.find(function(item) { return item.id == nodeId; });
              if (matched) {
                showTopoNodeDetail(matched);
              }
            }
          }
        });

        window.topoNetwork.on('deselectNode', function() {
          closeTopoDetail();
        });
      } catch(err) {
        console.error('Topology initialization error:', err);
      }
    }

    function showTopoNodeDetail(dev) {
      window._selectedTopoDevId = dev.id || null;
      window._selectedTopoDevIp = dev.ip || '';

      const titleEl = document.getElementById('topoDetailTitle');
      if (titleEl) titleEl.innerText = dev.sys_name || dev.ip || '-';
      const ipEl = document.getElementById('topoDetailIp');
      if (ipEl) ipEl.innerText = dev.ip || '-';
      const vendorEl = document.getElementById('topoDetailVendor');
      if (vendorEl) vendorEl.innerText = dev.vendor || '-';
      const statusEl = document.getElementById('topoDetailStatus');
      if (statusEl) {
        const st = dev.live_status || dev.status || 'ONLINE';
        const bg = st === 'ONLINE' ? ['#dcfce7', '#15803d'] : ['#fee2e2', '#991b1b'];
        const txt = (st === 'ONLINE' && dev.snmp_ok === false) ? 'ONLINE (ping var, SNMP yanıt yok)' : st;
        statusEl.innerHTML = '<span class="badge" style="background:' + bg[0] + '; color:' + bg[1] + ';">' + escHtml(txt) + '</span>';
      }
      const portsEl = document.getElementById('topoDetailPorts');
      if (portsEl) portsEl.innerText = (dev.interface_count != null ? dev.interface_count : '-');
      const cpuEl = document.getElementById('topoDetailCpu');
      if (cpuEl) cpuEl.innerText = (dev.last_cpu != null ? dev.last_cpu + '%' : '-');

      const panel = document.getElementById('topoDetailPanel');
      if (panel) panel.style.display = 'block';
      const card = document.getElementById('topoNodeDetailCard');
      if (card) card.style.display = 'block';
    }

    window.addEventListener('DOMContentLoaded', () => {
      initTrafficChart();
      const devSelect = document.getElementById('chartDevSelect');
      if (devSelect && devSelect.value) {
        currentDevId = devSelect.value;
        loadDeviceInterfaces(currentDevId);
      }
      telemetryTimer = setInterval(fetchTelemetryData, 5000);
      const btnTraffic = document.getElementById('topoBtnViewTraffic');
      if (btnTraffic) {
        btnTraffic.onclick = onTopoBtnViewTrafficClick;
      }
    });
    

    const SNMP_SNIPPETS = {
      cisco: {
        v2c: `! ==========================================
! Cisco IOS / IOS-XE - SNMPv2c Yapılandırması
! ==========================================
configure terminal

! 1. Salt Okunur (Read-Only) Community Tanımlayın
snmp-server community {COMMUNITY} RO

! 2. Konum ve İletişim Bilgileri (Opsiyonel)
snmp-server location "Merkez Veri Merkezi - Kabin 1"
snmp-server contact "admin@emredius.local"

! 3. EMredius NMS Sunucusuna Trap/Alarm Gönderimini Etkinleştirin
snmp-server host {IP} version 2c {COMMUNITY}
snmp-server enable traps

! 4. Değişiklikleri Kalıcı Kaydedin
end
write memory`,
        v3: `! ==========================================
! Cisco IOS / IOS-XE - SNMPv3 Güvenli (AuthPriv)
! ==========================================
configure terminal

! 1. NMS MIB Görünümünü Tanımlayın
snmp-server view NMS_VIEW iso included

! 2. SNMPv3 Grubunu (AuthPriv Güvenlik Seviyesi) Oluşturun
snmp-server group NMS_GROUP v3 priv read NMS_VIEW

! 3. SNMPv3 Kullanıcısını Tanımlayın (SHA Kimlik Doğrulama + AES Şifreleme)
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes 128 PrivPass123!

! 4. EMredius NMS Sunucusuna SNMPv3 Trap Bildirimlerini Yönlendirin
snmp-server host {IP} version 3 priv nmsuser
snmp-server enable traps

! 5. Kaydedin
end
write memory`,
        trap: `! ==========================================
! Cisco - SNMP Trap ve Port 162 Hedefi
! ==========================================
configure terminal
snmp-server host {IP} version 2c {COMMUNITY} udp-port 162
snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart
end
write memory`
      },
      mikrotik: {
        v2c: `# ==========================================
# MikroTik RouterOS - SNMPv2c Yapılandırması
# ==========================================

# 1. EMredius Sunucusuna Özel Community Tanımlayın
/snmp community
add name={COMMUNITY} addresses={IP}/32 read-access=yes security=none

# 2. SNMP Servisini Etkinleştirin ve Trap Hedefini Belirleyin
/snmp
set enabled=yes contact="admin@emredius.local" location="Merkez Router" trap-community={COMMUNITY} trap-target={IP} trap-version=2`,
        v3: `# ==========================================
# MikroTik RouterOS - SNMPv3 Güvenli (SHA + AES)
# ==========================================

# 1. SNMPv3 Şifreli Kullanıcı ve Community Tanımlayın
/snmp community
add name=nmsuser addresses={IP}/32 read-access=yes security=private authentication-protocol=SHA authentication-password="AuthPass123!" encryption-protocol=AES encryption-password="PrivPass123!"

# 2. SNMP Servisinde v3 Trap Hedefini Ayarlayın
/snmp
set enabled=yes trap-community=nmsuser trap-target={IP} trap-version=3`,
        trap: `# ==========================================
# MikroTik - SNMP Trap Gönderimi
# ==========================================
/snmp
set trap-generators=interfaces,start-stop trap-target={IP} trap-version=2 trap-community={COMMUNITY}`
      },
      huawei: {
        v2c: `# ==========================================
# Huawei VRP - SNMPv2c Yapılandırması
# ==========================================
system-view

# 1. SNMP Ajanını Etkinleştirin ve v2c Sürümünü Seçin
snmp-agent
snmp-agent sys-info version v2c

# 2. Community ve Yetki Ayarı
snmp-agent community read {COMMUNITY}

# 3. EMredius NMS Sunucusuna Trap Hedefini Ekleyin
snmp-agent target-host trap address udp-domain {IP} params securityname {COMMUNITY} v2c
snmp-agent trap enable

# 4. Kaydedin
commit
save`,
        v3: `# ==========================================
# Huawei VRP - SNMPv3 Güvenli (USM: SHA + AES)
# ==========================================
system-view

# 1. SNMPv3 ve MIB Görünümünü Açın
snmp-agent
snmp-agent sys-info version v3
snmp-agent mib-view included NMS_VIEW iso

# 2. SNMPv3 Grubunu (Privacy Modunda) Tanımlayın
snmp-agent group NMS_GROUP v3 privacy read-view NMS_VIEW

# 3. SNMPv3 Kullanıcısını (SHA + AES128) Oluşturun
snmp-agent usm-user v3 nmsuser group NMS_GROUP
snmp-agent usm-user v3 nmsuser authentication-mode sha AuthPass123!
snmp-agent usm-user v3 nmsuser privacy-mode aes128 PrivPass123!

# 4. EMredius NMS Sunucusuna v3 Trap Bildirimlerini Yönlendirin
snmp-agent target-host trap address udp-domain {IP} params securityname nmsuser v3 privacy
snmp-agent trap enable

# 5. Kaydedin
commit
save`,
        trap: `# ==========================================
# Huawei VRP - Trap Bildirimleri
# ==========================================
system-view
snmp-agent target-host trap address udp-domain {IP} udp-port 162 params securityname {COMMUNITY} v2c
snmp-agent trap enable feature-name all
commit
save`
      },
      h3c: {
        v2c: `# ==========================================
# H3C Comware - SNMPv2c Yapılandırması
# ==========================================
system-view

# 1. SNMP Ajanını ve v2c Sürümünü Etkinleştirin
snmp-agent
snmp-agent sys-info version v2c

# 2. Community (Salt Okunur)
snmp-agent community read {COMMUNITY}

# 3. EMredius NMS Sunucusuna Trap Hedefini Ekleyin
snmp-agent target-host trap address udp-domain {IP} params securityname {COMMUNITY} v2c
snmp-agent trap enable

# 4. Kaydedin
quit
save force`,
        v3: `# ==========================================
# H3C Comware - SNMPv3 Güvenli (SHA + AES)
# ==========================================
system-view

# 1. SNMPv3 ve MIB Görünümü
snmp-agent
snmp-agent sys-info version v3
snmp-agent mib-view included NMS_VIEW iso

# 2. Grup (Privacy) ve Kullanıcı (SHA + AES128)
snmp-agent group v3 NMS_GROUP privacy read-view NMS_VIEW
snmp-agent usm-user v3 nmsuser NMS_GROUP simple authentication-mode sha AuthPass123! privacy-mode aes128 PrivPass123!

# 3. v3 Trap Hedefi
snmp-agent target-host trap address udp-domain {IP} params securityname nmsuser v3 privacy
snmp-agent trap enable

# 4. Kaydedin
quit
save force`,
        trap: `# ==========================================
# H3C Comware - Trap Bildirimleri
# ==========================================
system-view
snmp-agent target-host trap address udp-domain {IP} udp-port 162 params securityname {COMMUNITY} v2c
snmp-agent trap enable
quit
save force`
      },
      ruijie: {
        v2c: `! ==========================================
! Ruijie RGOS - SNMPv2c Yapılandırması
! ==========================================
configure terminal

! 1. Community (Salt Okunur)
snmp-server community {COMMUNITY} ro

! 2. Sistem Bilgisi
snmp-server location "Merkez"
snmp-server contact "admin@emredius.local"

! 3. EMredius NMS Sunucusuna Trap Hedefini Ekleyin
snmp-server host {IP} traps version 2c {COMMUNITY}
snmp-server enable traps

! 4. Kaydedin
end
write memory`,
        v3: `! ==========================================
! Ruijie RGOS - SNMPv3 Güvenli (SHA + AES)
! ==========================================
configure terminal

! 1. MIB Görünümü, Grup ve Kullanıcı
snmp-server view NMS_VIEW 1.3.6.1 include
snmp-server group NMS_GROUP v3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes AuthPass123!

! 2. v3 Trap Hedefi
snmp-server host {IP} traps version 3 priv nmsuser
snmp-server enable traps

! 3. Kaydedin
end
write memory`,
        trap: `! ==========================================
! Ruijie RGOS - Trap Bildirimleri
! ==========================================
configure terminal
snmp-server host {IP} traps version 2c {COMMUNITY} udp-port 162
snmp-server enable traps
end
write memory`
      },
      arista: {
        v2c: `! ========================================
! Arista EOS - SNMPv2c
! ========================================
configure terminal
snmp-server community {COMMUNITY} ro
snmp-server location "Merkez Veri Merkezi"
snmp-server contact "admin@emredius.local"
snmp-server host {IP} version 2c {COMMUNITY}
snmp-server enable traps
end
write memory`,
        v3: `! ========================================
! Arista EOS - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure terminal
snmp-server view NMS_VIEW iso included
snmp-server group NMS_GROUP v3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes PrivPass123!
snmp-server host {IP} version 3 priv nmsuser
snmp-server enable traps
end
write memory`,
        trap: `! ========================================
! Arista EOS - Trap Bildirimleri
! ========================================
configure terminal
snmp-server host {IP} version 2c {COMMUNITY} udp-port 162
snmp-server enable traps
end
write memory`
      },
      nxos: {
        v2c: `! ========================================
! Cisco NX-OS (Nexus) - SNMPv2c
! ========================================
configure terminal
snmp-server community {COMMUNITY} ro
snmp-server location "Merkez Veri Merkezi"
snmp-server host {IP} traps version 2c {COMMUNITY}
snmp-server enable traps
end
copy running-config startup-config`,
        v3: `! ========================================
! Cisco NX-OS (Nexus) - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure terminal
snmp-server user nmsuser network-operator auth sha AuthPass123! priv aes-128 PrivPass123!
snmp-server host {IP} traps version 3 priv nmsuser
snmp-server enable traps
end
copy running-config startup-config`,
        trap: `! ========================================
! Cisco NX-OS (Nexus) - Trap Bildirimleri
! ========================================
configure terminal
snmp-server host {IP} traps version 2c {COMMUNITY} udp-port 162
snmp-server enable traps link
end
copy running-config startup-config`
      },
      iosxr: {
        v2c: `! ========================================
! Cisco IOS-XR - SNMPv2c
! ========================================
configure
snmp-server community {COMMUNITY} RO
snmp-server location "Omurga POP"
snmp-server host {IP} traps version 2c {COMMUNITY}
snmp-server traps snmp linkup
snmp-server traps snmp linkdown
commit`,
        v3: `! ========================================
! Cisco IOS-XR - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure
snmp-server view NMS_VIEW iso included
snmp-server group NMS_GROUP v3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes 128 PrivPass123!
snmp-server host {IP} traps version 3 priv nmsuser
commit`,
        trap: `! ========================================
! Cisco IOS-XR - Trap Bildirimleri
! ========================================
configure
snmp-server host {IP} traps version 2c {COMMUNITY} udp-port 162
snmp-server traps snmp linkup
snmp-server traps snmp linkdown
commit`
      },
      dell: {
        v2c: `! ========================================
! Dell SmartFabric OS10 - SNMPv2c
! ========================================
configure terminal
snmp-server community {COMMUNITY} ro
snmp-server location "Merkez Veri Merkezi"
snmp-server host {IP} traps version 2c {COMMUNITY}
snmp-server enable traps all
end
write memory`,
        v3: `! ========================================
! Dell SmartFabric OS10 - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure terminal
snmp-server view NMS_VIEW 1 included
snmp-server group NMS_GROUP 3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP 3 auth sha AuthPass123! priv aes PrivPass123!
snmp-server host {IP} traps version 3 priv nmsuser
snmp-server enable traps all
end
write memory`,
        trap: `! ========================================
! Dell SmartFabric OS10 - Trap Bildirimleri
! ========================================
configure terminal
snmp-server host {IP} traps version 2c {COMMUNITY} udp-port 162
snmp-server enable traps all
end
write memory`
      },
      nokia: {
        v2c: `# ========================================
# Nokia SR OS (Classic CLI) - SNMPv2c
# ========================================
configure system security snmp community "{COMMUNITY}" r version v2c
configure log snmp-trap-group "NMS" trap-target "nms" address {IP} port 162 snmpv2c notify-community "{COMMUNITY}"
configure log log-id 98 from main
configure log log-id 98 to snmp
configure log log-id 98 no shutdown
admin save`,
        v3: `# ========================================
# Nokia SR OS (Classic CLI) - SNMPv3 Güvenli (SHA + AES)
# ========================================
configure system security snmp view "NMS_VIEW" subtree "1" mask ff type included
configure system security snmp access group "NMS_GROUP" security-model usm security-level privacy read "NMS_VIEW" notify "NMS_VIEW"
configure system security user "nmsuser" access snmp
configure system security user "nmsuser" snmp authentication sha "AuthPass123!" privacy aes-128-cfb-key "PrivPass123!"
configure system security user "nmsuser" snmp group "NMS_GROUP"
admin save`,
        trap: `# ========================================
# Nokia SR OS (Classic CLI) - Trap Bildirimleri
# ========================================
configure log snmp-trap-group "NMS" trap-target "nms" address {IP} port 162 snmpv2c notify-community "{COMMUNITY}"
configure log log-id 98 from main
configure log log-id 98 to snmp
configure log log-id 98 no shutdown
admin save`
      },
      exos: {
        v2c: `# ========================================
# Extreme Networks ExtremeXOS - SNMPv2c
# ========================================
enable snmp access
enable snmp access snmp-v1v2c
configure snmp add community readonly {COMMUNITY}
configure snmp sysLocation "Merkez"
configure snmp add trapreceiver {IP} community {COMMUNITY} port 162
enable snmp traps
save configuration`,
        v3: `# ========================================
# Extreme Networks ExtremeXOS - SNMPv3 Güvenli (SHA + AES)
# ========================================
enable snmp access
configure snmpv3 add user nmsuser authentication sha AuthPass123! privacy aes PrivPass123!
configure snmpv3 add group NMS_GROUP user nmsuser sec-model usm
configure snmpv3 add access NMS_GROUP sec-model usm sec-level priv read-view defaultAdminView
# Trap icin v2c hedefi onerilir (Trap sekmesine bakin)
save configuration`,
        trap: `# ========================================
# Extreme Networks ExtremeXOS - Trap Bildirimleri
# ========================================
configure snmp add trapreceiver {IP} community {COMMUNITY} port 162
enable snmp traps
save configuration`
      },
      ruckus: {
        v2c: `! ========================================
! Ruckus / CommScope FastIron (ICX) - SNMPv2c
! ========================================
configure terminal
snmp-server community {COMMUNITY} ro
snmp-server location "Kenar Dağıtım"
snmp-server host {IP} version v2c {COMMUNITY}
snmp-server enable traps
end
write memory`,
        v3: `! ========================================
! Ruckus / CommScope FastIron (ICX) - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure terminal
snmp-server view NMS_VIEW iso included
snmp-server group NMS_GROUP v3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes PrivPass123!
snmp-server host {IP} version v3 priv nmsuser
end
write memory`,
        trap: `! ========================================
! Ruckus / CommScope FastIron (ICX) - Trap Bildirimleri
! ========================================
configure terminal
snmp-server host {IP} version v2c {COMMUNITY} udp-port 162
snmp-server enable traps
end
write memory`
      },
      checkpoint: {
        v2c: `# ========================================
# Check Point Gaia OS (clish) - SNMPv2c
# ========================================
set snmp agent on
set snmp agent-version v2-and-v3
set snmp community {COMMUNITY} read-only
set snmp contact "admin@emredius.local"
add snmp traps receiver {IP} version v2 community {COMMUNITY}
set snmp traps enable
save config`,
        v3: `# ========================================
# Check Point Gaia OS (clish) - SNMPv3 Güvenli (SHA + AES)
# ========================================
set snmp agent on
set snmp agent-version v3-Only
add snmp usm user nmsuser security-level authPriv auth-pass-phrase AuthPass123! privacy-pass-phrase PrivPass123!
set snmp usm user nmsuser permission read-only
save config`,
        trap: `# ========================================
# Check Point Gaia OS (clish) - Trap Bildirimleri
# ========================================
add snmp traps receiver {IP} version v2 community {COMMUNITY}
set snmp traps enable
save config`
      },
      sophos: {
        v2c: `# ========================================
# Sophos Firewall (SFOS) - SNMPv2c
# ========================================
# SFOS SNMP ayarlari web arayuzunden yapilir (komut satiri yoktur).
# 1. Yonetim > Cihaz erisimi (Administration > Device access):
#    SNMP servisini NMS'in bulundugu bolge (or. LAN) icin isaretleyin.
# 2. Sistem > Yonetim > SNMP: SNMP ajanini etkinlestirin.
#    Ad / Konum / Iletisim alanlarini doldurun.
# 3. Topluluk (Community) bolumunde SNMPv1/v2c secin:
#    Community: {COMMUNITY}
#    Yonetici (Manager): {IP}
# 4. Kaydedin.`,
        v3: `# ========================================
# Sophos Firewall (SFOS) - SNMPv3 Güvenli (SHA + AES)
# ========================================
# SFOS SNMP ayarlari web arayuzunden yapilir.
# 1. Yonetim > Cihaz erisimi: SNMP'yi ilgili bolge icin acin.
# 2. SNMP ajanini etkinlestirin.
# 3. SNMPv3 kullanicisi ekleyin:
#    Kullanici: nmsuser, Kimlik dogrulama: SHA, Gizlilik: AES
#    Parolalar: AuthPass123! / PrivPass123!
#    Yonetici (Manager): {IP}
# 4. Kaydedin.`,
        trap: `# ========================================
# Sophos Firewall (SFOS) - Trap Bildirimleri
# ========================================
# 1. SNMP ajani sayfasinda "Trap hedefi" ekleyin.
# 2. Hedef IP: {IP}   Port: 162   Community: {COMMUNITY}
# 3. Kaydedin.`
      },
      alliedware: {
        v2c: `! ========================================
! Allied Telesis AlliedWare Plus - SNMPv2c
! ========================================
configure terminal
snmp-server
snmp-server community {COMMUNITY} ro
snmp-server location "Kenar Dağıtım"
snmp-server host {IP} version 2c {COMMUNITY}
snmp-server enable trap
end
write memory`,
        v3: `! ========================================
! Allied Telesis AlliedWare Plus - SNMPv3 Güvenli (SHA + AES)
! ========================================
configure terminal
snmp-server
snmp-server view NMS_VIEW 1 included
snmp-server group NMS_GROUP priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP encrypted auth sha AuthPass123! priv aes PrivPass123!
snmp-server host {IP} version 3 priv nmsuser
snmp-server enable trap
end
write memory`,
        trap: `! ========================================
! Allied Telesis AlliedWare Plus - Trap Bildirimleri
! ========================================
configure terminal
snmp-server host {IP} version 2c {COMMUNITY}
snmp-server enable trap
end
write memory`
      },
      f5: {
        v2c: `# ========================================
# F5 BIG-IP TMOS (tmsh) - SNMPv2c
# ========================================
modify sys snmp communities add { nms { community-name {COMMUNITY} source default access ro } }
modify sys snmp allowed-addresses add { {IP} }
modify sys snmp traps add { nms { host {IP} community {COMMUNITY} port 162 version 2c } }
save sys config`,
        v3: `# ========================================
# F5 BIG-IP TMOS (tmsh) - SNMPv3 Güvenli (SHA + AES)
# ========================================
modify sys snmp users add { nmsuser { username-on-device nmsuser auth-protocol sha auth-password AuthPass123! privacy-protocol aes privacy-password PrivPass123! access ro oid-subset .1 } }
modify sys snmp allowed-addresses add { {IP} }
save sys config`,
        trap: `# ========================================
# F5 BIG-IP TMOS (tmsh) - Trap Bildirimleri
# ========================================
modify sys snmp traps add { nms { host {IP} community {COMMUNITY} port 162 version 2c } }
save sys config`
      },
      omniswitch: {
        v2c: `! ========================================
! Alcatel-Lucent Enterprise AOS (OmniSwitch) - SNMPv2c
! ========================================
user {COMMUNITY} read-only all no auth
snmp community-map {COMMUNITY} user {COMMUNITY} enable
snmp station {IP} 162 {COMMUNITY} v2 enable
write memory`,
        v3: `! ========================================
! Alcatel-Lucent Enterprise AOS (OmniSwitch) - SNMPv3 Güvenli (SHA + AES)
! ========================================
! Parolalar etkilesimli sorulabilir
user nmsuser read-only all sha+aes password AuthPass123!
snmp station {IP} 162 nmsuser v3 enable
write memory`,
        trap: `! ========================================
! Alcatel-Lucent Enterprise AOS (OmniSwitch) - Trap Bildirimleri
! ========================================
snmp station {IP} 162 {COMMUNITY} v2 enable
write memory`
      },
      reyee: {
        v2c: `! ==========================================
! Ruijie ReyeeOS (Reyee Switch / EG Gateway) - SNMPv2c
! ==========================================
! Web arayüzü: Sistem > SNMP ile de yapılabilir (Reyee: Ağ > SNMP).
configure terminal
snmp-server enable
snmp-server community {COMMUNITY} ro
snmp-server location "Kenar Dağıtım"
snmp-server host {IP} traps version 2c {COMMUNITY}
snmp-server enable traps
end
write memory`,
        v3: `! ==========================================
! Ruijie ReyeeOS (Reyee Switch / EG Gateway) - SNMPv3 Güvenli (SHA + AES)
! ==========================================
! Web arayüzü: SNMP > SNMPv3 bölümünden de eklenebilir.
configure terminal
snmp-server enable
snmp-server view NMS_VIEW 1.3.6.1 include
snmp-server group NMS_GROUP v3 priv read NMS_VIEW
snmp-server user nmsuser NMS_GROUP v3 auth sha AuthPass123! priv aes PrivPass123!
snmp-server host {IP} traps version 3 priv nmsuser
snmp-server enable traps
end
write memory`,
        trap: `! ==========================================
! Ruijie ReyeeOS (Reyee Switch / EG Gateway) - Trap Bildirimleri
! ==========================================
configure terminal
snmp-server host {IP} traps version 2c {COMMUNITY} udp-port 162
snmp-server enable traps
end
write memory`
      },
      juniper: {
        v2c: `# ==========================================
# Juniper Junos - SNMPv2c Yapılandırması
# ==========================================
configure

# 1. Community ve İzin Verilen EMredius IP Adresini Tanımlayın
set snmp community {COMMUNITY} authorization read-only
set snmp community {COMMUNITY} clients {IP}/32

# 2. Trap Grubunu ve Hedef NMS Sunucusunu Belirleyin
set snmp trap-group EMREDIUS_NMS version v2
set snmp trap-group EMREDIUS_NMS targets {IP}
set snmp trap-group EMREDIUS_NMS categories [ link-up-down chassischanged configuration-management ]

# 3. Onaylayın ve Kaydedin
commit and-quit`,
        v3: `# ==========================================
# Juniper Junos - SNMPv3 Güvenli (USM)
# ==========================================
configure

# 1. SNMPv3 USM Kullanıcısını (SHA + AES128) Tanımlayın
set snmp v3 usm local-engine user nmsuser authentication-sha authentication-password "AuthPass123!"
set snmp v3 usm local-engine user nmsuser privacy-aes128 privacy-password "PrivPass123!"

# 2. Güvenlik Grubu ve VACM Yetki Erişimini Ayarlayın
set snmp v3 vacm security-to-group security-model usm security-name nmsuser group NMS_GROUP
set snmp v3 vacm access group NMS_GROUP default-context-prefix model usm level privacy read-view NMS_VIEW
set snmp v3 view NMS_VIEW oid .1 include

# 3. EMredius Trap Hedef Parametrelerini Oluşturun
set snmp target-address NMS_TARGET address {IP} port 162
set snmp target-parameters NMS_PARAMS parameters user-name nmsuser security-model usm security-level privacy
set snmp notify NMS_NOTIFY type trap tag NMS_TRAP_TAG
set snmp target-address NMS_TARGET taglist NMS_TRAP_TAG

# 4. Kaydedin
commit and-quit`,
        trap: `# ==========================================
# Juniper - Trap Bildirimleri
# ==========================================
configure
set snmp trap-options source-address lo0.0
set snmp trap-group EMREDIUS_TRAPS targets {IP}
commit and-quit`
      },
      fortinet: {
        v2c: `# ==========================================
# Fortinet FortiGate - SNMPv2c Yapılandırması
# ==========================================
config system snmp sysinfo
  set status enable
  set description "FortiGate NMS Monitored"
  set location "Merkez Güvenlik Duvarı"
end

config system snmp community
  edit 1
    set name "{COMMUNITY}"
    config hosts
      edit 1
        set ip {IP} 255.255.255.255
      next
    end
    set query-v1-status enable
    set query-v2c-status enable
    set trap-v1-status enable
    set trap-v2c-status enable
  next
end`,
        v3: `# ==========================================
# Fortinet FortiGate - SNMPv3 (AuthPriv)
# ==========================================
config system snmp sysinfo
  set status enable
end

config system snmp user
  edit "nmsuser"
    set status enable
    set trap-status enable
    set trap-lport 162
    set trap-rport 162
    set security-level auth-priv
    set auth-proto sha
    set auth-pwd "AuthPass123!"
    set priv-proto aes
    set priv-pwd "PrivPass123!"
    set queries enable
    set notify-hosts {IP}
  next
end`,
        trap: `# ==========================================
# Fortinet - SNMP Trap Ayarları
# ==========================================
config system snmp community
  edit 1
    set trap-v2c-status enable
    config hosts
      edit 1
        set ip {IP} 255.255.255.255
      next
    end
  next
end`
      },
      aruba: {
        v2c: `! ==========================================
! HP / Aruba (AOS-S / Provision) - SNMPv2c
! ==========================================
snmp-server community "{COMMUNITY}" unrestricted
snmp-server host {IP} community "{COMMUNITY}"
snmp-server enable traps
snmp-server location "Kenar Dağıtım Anahtarı"

! ArubaOS-CX için:
! snmp-server community {COMMUNITY}
! snmp-server host {IP} trap version v2c community {COMMUNITY}`,
        v3: `! ==========================================
! HP / Aruba (AOS-CX) - SNMPv3 Güvenli
! ==========================================
snmpv3 enable
snmpv3 group NMS_GROUP user nmsuser sec-level auth-priv
snmpv3 user nmsuser auth sha plaintext AuthPass123! priv aes plaintext PrivPass123!
snmpv3 access NMS_GROUP sec-model usm sec-level auth-priv read-view iso
snmpv3 targetaddr NMS_TRAP params NMS_PARAMS ip-val {IP}
snmpv3 params NMS_PARAMS user nmsuser sec-model usm sec-level auth-priv`,
        trap: `! ==========================================
! HP / Aruba - Trap Bildirimleri
! ==========================================
snmp-server host {IP} trap version v2c community "{COMMUNITY}"
snmp-server enable traps link-change`
      },
      linux: {
        v2c: `# ==========================================
# Linux NET-SNMP (/etc/snmp/snmpd.conf) - SNMPv2c
# ==========================================
# 1. Yapılandırma dosyasını düzenleyin:
# nano /etc/snmp/snmpd.conf

# Aşağıdaki satırları ekleyin:
rocommunity {COMMUNITY} {IP}
sysLocation "Sunucu Odası"
sysContact admin@emredius.local
trap2sink {IP} {COMMUNITY}

# 2. Servisi yeniden başlatın ve etkinleştirin:
systemctl enable --now snmpd
systemctl restart snmpd`,
        v3: `# ==========================================
# Linux NET-SNMP - SNMPv3 (SHA + AES)
# ==========================================
# 1. snmpd servisini geçici olarak durdurun:
systemctl stop snmpd

# 2. net-snmp-create-v3-user aracıyla kullanıcıyı oluşturun:
net-snmp-create-v3-user -ro -A AuthPass123! -a SHA -X PrivPass123! -x AES nmsuser

# 3. snmpd servisini başlatın:
systemctl start snmpd`,
        trap: `# ==========================================
# Linux NET-SNMP - Trap Gönderimi
# ==========================================
# /etc/snmp/snmpd.conf içine ekleyin:
trap2sink {IP} {COMMUNITY}
authtrapenable 1
systemctl restart snmpd`
      },
      windows: {
        v2c: `# ==========================================
# Windows Server SNMP Service (PowerShell Admin)
# ==========================================
# 1. SNMP Servis Bileşenini Yükleyin:
Install-WindowsFeature -Name SNMP-Service -IncludeManagementTools

# 2. Community ve İzin Verilen EMredius Sunucu IP'sini Ekleyin:
reg add "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\ValidCommunities" /v "{COMMUNITY}" /t REG_DWORD /d 4 /f
reg add "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\PermittedManagers" /v "1" /t REG_SZ /d "{IP}" /f
reg add "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\TrapConfiguration\\\\{COMMUNITY}" /v "1" /t REG_SZ /d "{IP}" /f

# 3. SNMP Servisini Yeniden Başlatın:
Restart-Service -Name SNMP -Force`,
        v3: `# ==========================================
# Windows Server - SNMPv3 Notu
# ==========================================
# Windows yerleşik SNMP servisi doğrudan SNMPv3 desteklememektedir.
# Windows sunucuları güvenli SNMPv3 ile izlemek için Net-SNMP Windows portu
# veya EMredius WMI / WinRM agent entegrasyonu önerilir.`,
        trap: `# ==========================================
# Windows Server - Trap Yapılandırması (PowerShell)
# ==========================================
reg add "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SNMP\\\\Parameters\\\\TrapConfiguration\\\\{COMMUNITY}" /v "1" /t REG_SZ /d "{IP}" /f
Restart-Service -Name SNMP -Force`
      }
    };

    // HPE Comware 7 (FlexNetwork) H3C Comware ile aynı sözdizimini kullanır
    SNMP_SNIPPETS.hpe = Object.fromEntries(Object.entries(SNMP_SNIPPETS.h3c).map(([k, v]) => [k, v.replace(/H3C Comware/g, 'HPE Comware')]));

    let currentSnmpVendor = 'cisco';
    let currentSnmpProto = 'v2c';

    function selectSnmpVendor(vendor, btn) {
      currentSnmpVendor = vendor;
      document.querySelectorAll('.snmp-vendor-pill').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      renderSnmpSnippet();
    }

    // Cihaz seçici: arama + marka + tip + cihaz satırları (karşılıklı filtre)
    const SNMP_DEVICES = [
      ['cisco', 'Cisco IOS/XE', 'Cisco', ['Switch', 'Router']],
      ['nxos', 'Cisco NX-OS', 'Cisco', ['Switch']],
      ['iosxr', 'Cisco IOS-XR', 'Cisco', ['Router']],
      ['mikrotik', 'MikroTik RouterOS', 'MikroTik', ['Router']],
      ['huawei', 'Huawei VRP', 'Huawei', ['Switch', 'Router']],
      ['h3c', 'H3C Comware', 'H3C', ['Switch', 'Router']],
      ['hpe', 'HPE Comware', 'HPE', ['Switch', 'Router']],
      ['aruba', 'Aruba (AOS-CX / AOS-S)', 'Aruba', ['Switch']],
      ['ruijie', 'Ruijie RGOS', 'Ruijie', ['Switch', 'Router']],
      ['reyee', 'Ruijie ReyeeOS', 'Ruijie', ['Switch', 'Router']],
      ['arista', 'Arista EOS', 'Arista', ['Switch']],
      ['dell', 'Dell OS10', 'Dell', ['Switch']],
      ['nokia', 'Nokia SR OS', 'Nokia', ['Router']],
      ['exos', 'Extreme EXOS', 'Extreme', ['Switch']],
      ['ruckus', 'Ruckus FastIron', 'Ruckus', ['Switch']],
      ['alliedware', 'Allied Telesis AW+', 'Allied Telesis', ['Switch']],
      ['omniswitch', 'ALE OmniSwitch', 'Alcatel-Lucent', ['Switch']],
      ['juniper', 'Juniper Junos', 'Juniper', ['Switch', 'Router', 'Firewall']],
      ['fortinet', 'Fortinet FortiGate', 'Fortinet', ['Firewall']],
      ['checkpoint', 'Check Point Gaia', 'Check Point', ['Firewall']],
      ['sophos', 'Sophos SFOS', 'Sophos', ['Firewall']],
      ['f5', 'F5 BIG-IP', 'F5', ['Yük Dengeleyici']],
      ['linux', 'Linux (net-snmp)', 'Linux', ['Sunucu']],
      ['windows', 'Windows Server', 'Microsoft', ['Sunucu']]
    ];
    const snmpPicker = { q: '', brand: '', type: '' };

    function snmpPickerMatch(d, ignore) {
      const q = snmpPicker.q.trim().toLocaleLowerCase('tr');
      if (q && (d[1] + ' ' + d[2] + ' ' + d[3].join(' ')).toLocaleLowerCase('tr').indexOf(q) < 0) return false;
      if (ignore !== 'brand' && snmpPicker.brand && d[2] !== snmpPicker.brand) return false;
      if (ignore !== 'type' && snmpPicker.type && d[3].indexOf(snmpPicker.type) < 0) return false;
      return true;
    }

    function snmpPickerMakeBtn(label, active, onclick, extraClass, count) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-sm btn-ntp-pick' + (extraClass ? ' ' + extraClass : '') + (active ? ' active' : '');
      const l = document.createElement('span');
      l.textContent = label;
      b.appendChild(l);
      if (count !== undefined && count !== null) {
        const c = document.createElement('span');
        c.className = 'ntp-cnt';
        c.textContent = count;
        b.appendChild(c);
      }
      b.onclick = onclick;
      return b;
    }

    function renderSnmpPicker() {
      // Seçili marka/tip diğer filtrelerle sonuç vermiyorsa sıfırla
      if (snmpPicker.brand && !SNMP_DEVICES.some(d => snmpPickerMatch(d, 'brand') && d[2] === snmpPicker.brand)) snmpPicker.brand = '';
      if (snmpPicker.type && !SNMP_DEVICES.some(d => snmpPickerMatch(d, 'type') && d[3].indexOf(snmpPicker.type) >= 0)) snmpPicker.type = '';
      const brands = [], types = [];
      SNMP_DEVICES.forEach(d => {
        if (snmpPickerMatch(d, 'brand') && brands.indexOf(d[2]) < 0) brands.push(d[2]);
        if (snmpPickerMatch(d, 'type')) d[3].forEach(t => { if (types.indexOf(t) < 0) types.push(t); });
      });
      const list = SNMP_DEVICES.filter(d => snmpPickerMatch(d));
      if (list.length && !list.some(d => d[0] === currentSnmpVendor)) {
        currentSnmpVendor = list[0][0];
        renderSnmpSnippet();
      }
      const fill = (id, nodes) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = '';
        nodes.forEach(n => el.appendChild(n));
      };
      fill('snmpBrandPills', [snmpPickerMakeBtn('Tümü', !snmpPicker.brand, () => { snmpPicker.brand = ''; renderSnmpPicker(); }, null, SNMP_DEVICES.filter(d => snmpPickerMatch(d, 'brand') && true).length)]
        .concat(brands.map(b => snmpPickerMakeBtn(b, snmpPicker.brand === b, () => { snmpPicker.brand = snmpPicker.brand === b ? '' : b; renderSnmpPicker(); }, null, SNMP_DEVICES.filter(d => snmpPickerMatch(d, 'brand') && d[2] === b).length))));
      fill('snmpTypePills', [snmpPickerMakeBtn('Tümü', !snmpPicker.type, () => { snmpPicker.type = ''; renderSnmpPicker(); }, null, SNMP_DEVICES.filter(d => snmpPickerMatch(d, 'type') && true).length)]
        .concat(types.map(t => snmpPickerMakeBtn(t, snmpPicker.type === t, () => { snmpPicker.type = snmpPicker.type === t ? '' : t; renderSnmpPicker(); }, null, SNMP_DEVICES.filter(d => snmpPickerMatch(d, 'type') && d[3].indexOf(t) >= 0).length))));
      const devNodes = list.map(d => {
        const b = snmpPickerMakeBtn(d[1], d[0] === currentSnmpVendor, null, 'snmp-vendor-pill');
        b.dataset.vendor = d[0];
        b.onclick = () => selectSnmpVendor(d[0], b);
        return b;
      });
      if (!devNodes.length) {
        const span = document.createElement('span');
        span.style.cssText = 'font-size:0.8rem; color:var(--text-muted, #94a3b8);';
        span.textContent = 'Eşleşen cihaz yok';
        devNodes.push(span);
      }
      fill('snmpVendorPills', devNodes);
    }

    function snmpPickerSearchChanged(v) {
      snmpPicker.q = v || '';
      renderSnmpPicker();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', renderSnmpPicker);
    else renderSnmpPicker();

    function selectSnmpProto(proto, btn) {
      currentSnmpProto = proto;
      document.querySelectorAll('.btn-snmp-proto').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      renderSnmpSnippet();
    }

    function resetSnmpConfigIp(defaultIp) {
      const input = document.getElementById('snmpConfigServerIp');
      if (input) input.value = defaultIp || window.SERVER_IP || '192.0.2.10';
      const commInput = document.getElementById('snmpConfigCommunity');
      if (commInput) commInput.value = 'public';
      renderSnmpSnippet();
    }

    function renderSnmpSnippet() {
      const ipInput = document.getElementById('snmpConfigServerIp');
      const commInput = document.getElementById('snmpConfigCommunity');
      const targetIp = (ipInput && ipInput.value.trim()) ? ipInput.value.trim() : (window.TOPOLOGY_SERVER_IP || '127.0.0.1');
      const targetComm = (commInput && commInput.value.trim()) ? commInput.value.trim() : 'public';

      const vendorData = SNMP_SNIPPETS[currentSnmpVendor] || SNMP_SNIPPETS['cisco'];
      let rawText = vendorData[currentSnmpProto] || vendorData['v2c'] || '';

      rawText = rawText.replaceAll('{IP}', targetIp).replaceAll('{COMMUNITY}', targetComm);
      window._currentSnmpRawText = rawText;

      const escaped = rawText.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const ipEsc = targetIp.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const highlighted = escaped.replaceAll(ipEsc, '<span class="snmp-hi-ip">' + ipEsc + '</span>');
      
      const display = document.getElementById('snmpCodeDisplay');
      if (display) display.innerHTML = highlighted;
    }

    function copyCurrentSnmpCode() {
      const text = window._currentSnmpRawText || (document.getElementById('snmpCodeDisplay') ? document.getElementById('snmpCodeDisplay').innerText : '');
      const btn = document.getElementById('btnCopySnmpCode');
      if (!text) return;

      const setSuccess = () => {
        if (btn) {
          const orig = btn.innerHTML;
          btn.innerHTML = '<i class="fa-solid fa-check" style="color:#10b981;"></i> <span style="color:#10b981;">Kopyalandı!</span>';
          setTimeout(() => { btn.innerHTML = orig; }, 2000);
        }
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(setSuccess).catch(() => {
          fallbackCopyText(text);
          setSuccess();
        });
      } else {
        fallbackCopyText(text);
        setSuccess();
      }
    }

    function fallbackCopyText(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch(e) {}
      document.body.removeChild(ta);
    }

document.addEventListener('click', function (e) {
  const b = e.target.closest('[data-quick-add]');
  if (b) quickAddDevice(b.dataset.ip, b.dataset.vendor, b.dataset.sysname);
});
