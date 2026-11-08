// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Dashboard: top-traffic chart + live system telemetry (/api/system/telemetry*). Loaded only on the dashboard page.
var storagePieChart = null;
var cpuLineChart = null;
var ramLineChart = null;
var trafficBarChart = null;
var currentTelemetryRange = '15m';
// Live telemetry polling period (ms). Live points kept on the chart = range length / period.
var TELEMETRY_POLL_MS = 5000;
var TRAFFIC_CHART = JSON.parse((document.getElementById('dashboardTrafficChart') || {}).textContent || '{"labels":[],"data":[]}');
var TRAFFIC_CHART_LABELS = TRAFFIC_CHART.labels;
var TRAFFIC_CHART_DATA = TRAFFIC_CHART.data;
var telemetryFetchInFlight = false;

var telemetryRangeLabels = {
  '15m': 'Son 15 Dk',
  '30m': 'Son 30 Dk',
  '1h': 'Son 1 Saat',
  '3h': 'Son 3 Saat',
  '6h': 'Son 6 Saat',
  '12h': 'Son 12 Saat'
};

function setTelemetryRange(range) {
  currentTelemetryRange = range;
  document.querySelectorAll('.telemetry-range-btn').forEach(btn => {
    if (btn.getAttribute('data-range') === range) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
  const lbl = telemetryRangeLabels[range] || range;
  const cpuRBadge = document.getElementById('cpuRangeBadge');
  if (cpuRBadge) cpuRBadge.innerText = 'Aralık: ' + lbl;
  const ramRBadge = document.getElementById('ramRangeBadge');
  if (ramRBadge) ramRBadge.innerText = 'Aralık: ' + lbl;
  loadTelemetryHistory(range);
}

function loadTelemetryHistory(range) {
  fetch('/api/system/telemetry/history?range=' + encodeURIComponent(range))
    .then(r => r.json())
    .then(res => {
      if (!res || !res.points) return;
      const points = res.points;
      const labels = points.map(p => p.time);
      const cpuData = points.map(p => p.cpu);
      const ramUsed = points.map(p => p.ram_used);
      const ramAvail = points.map(p => p.ram_avail);
      const swapData = points.map(p => p.swap);

      if (cpuLineChart) {
        cpuLineChart.data.labels = labels;
        cpuLineChart.data.datasets[0].data = cpuData;
        cpuLineChart.update();
      }
      if (ramLineChart) {
        ramLineChart.data.labels = labels;
        ramLineChart.data.datasets[0].data = ramUsed;
        ramLineChart.data.datasets[1].data = ramAvail;
        ramLineChart.data.datasets[2].data = swapData;
        ramLineChart.update();
      }
    })
    .catch(err => console.warn('Telemetry history load warning:', err));
}

function initAllDashboardCharts() {
  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not yet loaded, retrying in 300ms...');
    setTimeout(initAllDashboardCharts, 300);
    return;
  }

  // 1. Top Traffic Bar Chart
  try {
    const elTraffic = document.getElementById('trafficChart');
    if (elTraffic && !trafficBarChart) {
      trafficBarChart = new Chart(elTraffic.getContext('2d'), {
        type: 'bar',
        data: {
          labels: TRAFFIC_CHART_LABELS,
          datasets: [{
            label: 'Trafik (MB)',
            data: TRAFFIC_CHART_DATA,
            backgroundColor: '#3b82f6',
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true } }
        }
      });
    }
  } catch(e) {
    console.warn('Traffic chart init:', e);
  }

  // 2. Storage Pie Chart
  try {
    const elStorage = document.getElementById('storagePieChart');
    if (elStorage && !storagePieChart) {
      storagePieChart = new Chart(elStorage.getContext('2d'), {
        type: 'pie',
        data: {
          labels: ['Kullanılan Depolama (GB)', 'Boş Alan (GB)'],
          datasets: [{
            data: [4.01, 3.98],
            backgroundColor: ['#2563eb', '#10b981'],
            hoverBackgroundColor: ['#1d4ed8', '#059669'],
            borderWidth: 2,
            borderColor: '#ffffff',
            hoverOffset: 10
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 500 },
          plugins: {
            legend: { display: false },
            tooltip: {
              enabled: true,
              backgroundColor: '#0f172a',
              titleColor: '#f8fafc',
              bodyColor: '#e2e8f0',
              borderColor: '#334155',
              borderWidth: 1,
              padding: 12,
              callbacks: {
                label: function(context) {
                  const val = context.parsed;
                  const total = context.dataset.data.reduce((a, b) => a + b, 0);
                  const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0';
                  return ' ' + context.label + ': ' + val.toFixed(2) + ' GB (%' + pct + ')';
                }
              }
            }
          }
        }
      });
    }
  } catch(e) {
    console.warn('Storage pie chart init:', e);
  }

  // 3. CPU Line Chart (Zaman Serisi)
  try {
    const elCpu = document.getElementById('cpuLineChart');
    if (elCpu && !cpuLineChart) {
      cpuLineChart = new Chart(elCpu.getContext('2d'), {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'CPU Kullanımı (%)',
            data: [],
            borderColor: '#2563eb',
            backgroundColor: 'rgba(37, 99, 235, 0.15)',
            borderWidth: 2.5,
            fill: true,
            tension: 0.35,
            pointRadius: 3,
            pointHoverRadius: 6,
            pointBackgroundColor: '#2563eb'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              enabled: true,
              backgroundColor: '#0f172a',
              titleColor: '#f8fafc',
              bodyColor: '#e2e8f0',
              borderColor: '#334155',
              borderWidth: 1,
              padding: 10,
              callbacks: {
                label: function(context) {
                  return ' CPU Yükü: %' + context.parsed.y.toFixed(1);
                }
              }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              ticks: {
                callback: function(v) { return '%' + v; },
                color: '#94a3b8'
              },
              grid: { color: 'rgba(148, 163, 184, 0.15)' }
            },
            x: {
              ticks: { color: '#94a3b8', maxTicksLimit: 6 },
              grid: { display: false }
            }
          }
        }
      });
    }
  } catch(e) {
    console.warn('CPU chart init:', e);
  }

  // 4. RAM & Swap Line Chart (Zaman Serisi)
  try {
    const elRam = document.getElementById('ramLineChart');
    if (elRam && !ramLineChart) {
      ramLineChart = new Chart(elRam.getContext('2d'), {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Kullanılan RAM (MB)',
              data: [],
              borderColor: '#8b5cf6',
              backgroundColor: 'rgba(139, 92, 246, 0.15)',
              borderWidth: 2.5,
              fill: true,
              tension: 0.35,
              pointRadius: 3,
              pointHoverRadius: 6,
              pointBackgroundColor: '#8b5cf6'
            },
            {
              label: 'Kullanılabilir RAM (MB)',
              data: [],
              borderColor: '#06b6d4',
              borderWidth: 1.8,
              borderDash: [4, 4],
              fill: false,
              tension: 0.35,
              pointRadius: 0,
              pointHoverRadius: 5,
              pointBackgroundColor: '#06b6d4'
            },
            {
              label: 'Swap (MB)',
              data: [],
              borderColor: '#f59e0b',
              borderWidth: 1.8,
              fill: false,
              tension: 0.35,
              pointRadius: 0,
              pointHoverRadius: 5,
              pointBackgroundColor: '#f59e0b'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false
          },
          plugins: {
            legend: {
              display: true,
              position: 'top',
              labels: { boxWidth: 12, font: { size: 10 }, color: '#94a3b8' }
            },
            tooltip: {
              enabled: true,
              backgroundColor: '#0f172a',
              titleColor: '#f8fafc',
              bodyColor: '#e2e8f0',
              borderColor: '#334155',
              borderWidth: 1,
              padding: 10,
              callbacks: {
                label: function(context) {
                  return ' ' + context.dataset.label + ': ' + context.parsed.y.toFixed(1) + ' MB';
                }
              }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                callback: function(v) { return v + ' MB'; },
                color: '#94a3b8'
              },
              grid: { color: 'rgba(148, 163, 184, 0.15)' }
            },
            x: {
              ticks: { color: '#94a3b8', maxTicksLimit: 6 },
              grid: { display: false }
            }
          }
        }
      });
    }
  } catch(e) {
    console.warn('RAM chart init:', e);
  }
}

function telemetryMaxLivePoints() {
  // 15 Dk / 30 Dk windows are filled with live points every TELEMETRY_POLL_MS
  const secs = currentTelemetryRange === '30m' ? 1800 : 900;
  return Math.ceil((secs * 1000) / TELEMETRY_POLL_MS);
}

function updateTelemetryData() {
  // Do not poll from background tabs, and never stack requests on a slow server
  if (document.hidden || telemetryFetchInFlight) return;
  telemetryFetchInFlight = true;
  fetch('/api/system/telemetry')
    .then(r => r.json())
    .then(data => {
      telemetryFetchInFlight = false;
      if (!data) return;

      const cpu = data.cpu || { percent: 0, model: '', cores: 1, load_avg: [0,0,0], tasks: 0 };
      const ram = data.ram || { used_mb: 0, total_mb: 1, free_mb: 0, avail_mb: 0, buff_cache_mb: 0, used_pct: 0 };
      const swap = data.swap || { used_mb: 0, total_mb: 1, used_pct: 0 };
      const disk = data.disk || { used_gb: 0, total_gb: 1, free_gb: 0, used_pct: 0 };
      const gpu = data.gpu;

      // A. Update Top RADIUS Stat Cards
      if (data.radius) {
        const uEl = document.getElementById('statTotalUsers');
        if (uEl) uEl.innerText = data.radius.total_users;
        const sEl = document.getElementById('statActiveSessions');
        if (sEl) sEl.innerText = data.radius.active_sessions;
        const nEl = document.getElementById('statTotalNas');
        if (nEl) nEl.innerText = data.radius.total_nas;
        const tEl = document.getElementById('statTotalTraffic');
        if (tEl) tEl.innerText = data.radius.traffic_formatted;
      }

      // B. Update Top Spec Cards
      const cpuEl = document.getElementById('telemetryCpuPct');
      const cpuBadge = document.getElementById('telemetryCpuPctBadge');
      const cpuLiveBadge = document.getElementById('cpuChartLiveBadge');
      if (cpuEl) cpuEl.innerText = '%' + cpu.percent.toFixed(1);
      if (cpuBadge) cpuBadge.innerText = '%' + cpu.percent.toFixed(1);
      if (cpuLiveBadge) cpuLiveBadge.innerText = 'Anlık: %' + cpu.percent.toFixed(1);
      
      const cpuModelEl = document.getElementById('telemetryCpuModel');
      if (cpuModelEl && cpu.model) cpuModelEl.innerText = cpu.model + ' (' + cpu.cores + ' vCPU)';
      const loadEl = document.getElementById('telemetryLoadAvg');
      if (loadEl && cpu.load_avg) loadEl.innerText = 'Yük: ' + cpu.load_avg.join(' | ');
      const taskEl = document.getElementById('telemetryTasks');
      if (taskEl) taskEl.innerText = cpu.tasks + ' Etkin Görev / İşlem';

      const ramUsedEl = document.getElementById('telemetryRamUsed');
      const ramBadge = document.getElementById('telemetryRamPctBadge');
      const ramLiveBadge = document.getElementById('ramChartLiveBadge');
      if (ramUsedEl) ramUsedEl.innerText = ram.used_mb + ' MB / ' + (ram.total_mb/1024).toFixed(2) + ' GB';
      if (ramBadge) ramBadge.innerText = '%' + ram.used_pct.toFixed(1);
      if (ramLiveBadge) ramLiveBadge.innerText = ram.used_mb + ' MB (%' + ram.used_pct.toFixed(1) + ')';
      
      const ramFreeEl = document.getElementById('telemetryRamFree');
      if (ramFreeEl) ramFreeEl.innerText = ram.free_mb + ' MB';
      const ramCacheEl = document.getElementById('telemetryRamCache');
      if (ramCacheEl) ramCacheEl.innerText = (ram.buff_cache_mb/1024).toFixed(2) + ' GB';
      const ramAvailEl = document.getElementById('telemetryRamAvail');
      if (ramAvailEl) ramAvailEl.innerText = (ram.avail_mb/1024).toFixed(2) + ' GB';
      const swapEl = document.getElementById('telemetrySwapInfo');
      if (swapEl) swapEl.innerText = 'Swap: ' + swap.used_mb + ' MB / ' + swap.total_mb + ' MB (%' + swap.used_pct.toFixed(1) + ')';

      const diskUsedEl = document.getElementById('telemetryDiskUsed');
      const diskBadge = document.getElementById('telemetryDiskPctBadge');
      if (diskUsedEl) diskUsedEl.innerText = disk.used_gb + ' GB / ' + disk.total_gb + ' GB';
      if (diskBadge) diskBadge.innerText = '%' + disk.used_pct.toFixed(1);
      const diskFreeEl = document.getElementById('telemetryDiskFree');
      if (diskFreeEl) diskFreeEl.innerText = disk.free_gb + ' GB';
      
      const pieUsed = document.getElementById('pieLegendUsed');
      const pieFree = document.getElementById('pieLegendFree');
      if (pieUsed) pieUsed.innerText = disk.used_gb + ' GB (%' + disk.used_pct.toFixed(1) + ')';
      if (pieFree) pieFree.innerText = disk.free_gb + ' GB (%' + (100 - disk.used_pct).toFixed(1) + ')';

      if (data.os_info) {
        const sysSub = document.getElementById('telemetrySysSubtitle');
        if (sysSub) sysSub.innerText = data.os_info;
      }
      if (gpu) {
        const gpuName = document.getElementById('telemetryGpuName');
        const gpuRes = document.getElementById('telemetryGpuRes');
        const gpuDriver = document.getElementById('telemetryGpuDriver');
        const gpuBadge = document.getElementById('telemetryGpuBadge');
        if (gpuName && gpu.name) gpuName.innerText = gpu.name;
        if (gpuRes && gpu.resolution) gpuRes.innerText = gpu.resolution;
        if (gpuDriver && gpu.driver) gpuDriver.innerText = gpu.driver + ' (' + (gpu.acceleration || 'Aktif') + ')';
        if (gpuBadge && gpu.driver) gpuBadge.innerText = gpu.driver;
      }
      if (data.net) {
        const netEl = document.getElementById('telemetryNetInfo');
        const rxRate = data.net.rx_rate || '0 KB/s';
        const txRate = data.net.tx_rate || '0 KB/s';
        if (netEl) netEl.innerText = 'Ağ (' + data.net.iface + '): ↓ ' + rxRate + ' | ↑ ' + txRate + ' (Toplam: ↓ ' + data.net.rx_mb + ' MB | ↑ ' + data.net.tx_mb + ' MB)';
      }
      if (data.uptime) {
        const upEl = document.getElementById('telemetryUptime');
        if (upEl) upEl.innerText = data.uptime;
      }

      // C. Pulse Badge & Live Indicator
      const pulseLabel = document.getElementById('telemetryPulseLabel');
      if (pulseLabel) {
        pulseLabel.textContent = 'CANLI (5s) • ' + (data.timestamp || '');
      }
      const pulseBadge = document.getElementById('telemetryPulseBadge');
      if (pulseBadge) {
        pulseBadge.style.boxShadow = '0 0 12px rgba(16, 185, 129, 0.45)';
        pulseBadge.style.borderColor = '#10b981';
        setTimeout(() => {
          if (pulseBadge) {
            pulseBadge.style.boxShadow = 'none';
            pulseBadge.style.borderColor = '#bbf7d0';
          }
        }, 500);
      }

      // D. Update Storage Pie Chart
      if (storagePieChart) {
        storagePieChart.data.datasets[0].data = [disk.used_gb, disk.free_gb];
        storagePieChart.update('none');
      }

      // E. Update CPU Line Chart for all ranges
      if (cpuLineChart) {
        const maxPts = telemetryMaxLivePoints();
        if (currentTelemetryRange === '15m' || currentTelemetryRange === '30m') {
          cpuLineChart.data.labels.push(data.timestamp);
          cpuLineChart.data.datasets[0].data.push(cpu.percent);
          while (cpuLineChart.data.labels.length > maxPts) {
            cpuLineChart.data.labels.shift();
            cpuLineChart.data.datasets[0].data.shift();
          }
        } else {
          if (cpuLineChart.data.labels.length > 0) {
            const lastIdx = cpuLineChart.data.labels.length - 1;
            cpuLineChart.data.labels[lastIdx] = data.timestamp;
            cpuLineChart.data.datasets[0].data[lastIdx] = cpu.percent;
          } else {
            cpuLineChart.data.labels.push(data.timestamp);
            cpuLineChart.data.datasets[0].data.push(cpu.percent);
          }
        }
        cpuLineChart.update('none');
      }

      // F. Update RAM Line Chart for all ranges
      if (ramLineChart) {
        const maxPts = telemetryMaxLivePoints();
        if (currentTelemetryRange === '15m' || currentTelemetryRange === '30m') {
          ramLineChart.data.labels.push(data.timestamp);
          ramLineChart.data.datasets[0].data.push(ram.used_mb);
          ramLineChart.data.datasets[1].data.push(ram.avail_mb);
          ramLineChart.data.datasets[2].data.push(swap.used_mb);
          while (ramLineChart.data.labels.length > maxPts) {
            ramLineChart.data.labels.shift();
            ramLineChart.data.datasets[0].data.shift();
            ramLineChart.data.datasets[1].data.shift();
            ramLineChart.data.datasets[2].data.shift();
          }
        } else {
          if (ramLineChart.data.labels.length > 0) {
            const lastIdx = ramLineChart.data.labels.length - 1;
            ramLineChart.data.labels[lastIdx] = data.timestamp;
            ramLineChart.data.datasets[0].data[lastIdx] = ram.used_mb;
            ramLineChart.data.datasets[1].data[lastIdx] = ram.avail_mb;
            ramLineChart.data.datasets[2].data[lastIdx] = swap.used_mb;
          } else {
            ramLineChart.data.labels.push(data.timestamp);
            ramLineChart.data.datasets[0].data.push(ram.used_mb);
            ramLineChart.data.datasets[1].data.push(ram.avail_mb);
            ramLineChart.data.datasets[2].data.push(swap.used_mb);
          }
        }
        ramLineChart.update('none');
      }
    })
    .catch(err => {
      telemetryFetchInFlight = false;
      console.warn('Telemetry fetch error:', err);
    });
}

// Bulletproof Auto-Init Function
function startTelemetrySystem() {
  initAllDashboardCharts();
  loadTelemetryHistory(currentTelemetryRange);
  updateTelemetryData();

  // Canli telemetri dongusu (5 saniyede bir canli veri cek ve ekrani guncelle)
  if (!window._telemetryPollInterval) {
    window._telemetryPollInterval = setInterval(updateTelemetryData, TELEMETRY_POLL_MS);
  }

  // Gecmis veritabanini (genis pencerelerde) her 15 saniyede bir senkronize et
  if (!window._telemetryHistoryPollInterval) {
    window._telemetryHistoryPollInterval = setInterval(() => {
      if (document.hidden) return;
      if (currentTelemetryRange !== '15m' && currentTelemetryRange !== '30m') {
        loadTelemetryHistory(currentTelemetryRange);
      }
    }, 15000);
  }

  // Sekme tekrar gorunur oldugunda hemen guncelle (arka planda polling yapilmaz)
  if (!window._telemetryVisibilityBound) {
    window._telemetryVisibilityBound = true;
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) updateTelemetryData();
    });
  }
}

// Check DOM readiness immediately or hook DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startTelemetrySystem);
} else {
  startTelemetrySystem();
}
