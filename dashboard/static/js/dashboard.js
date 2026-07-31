// ============================================================
// PyWAF Dashboard - Real-Time Monitoring Logic
// ============================================================

const MAX_EVENTS = 200;
let events = [];
let eventSource = null;
let reconnectTimeout = 1000;

// Chart Instances
let threatChart = null;
let topIpChart = null;
let timelineChart = null;

// Timeline tracking
let timelineBuckets = {};

// ============================================================
// Initialization
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setupSSE();
    fetchStats();

    // Poll stats every 5 seconds
    setInterval(fetchStats, 5000);

    // Bind footer buttons
    document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
    document.getElementById('btn-export-json').addEventListener('click', exportJSON);
    document.getElementById('btn-clear-events').addEventListener('click', clearEvents);
});

// ============================================================
// SSE Connection with Auto-Reconnect
// ============================================================
function setupSSE() {
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource('/waf/api/events/stream');

    const sseDot = document.getElementById('sse-dot');
    const sseText = document.getElementById('sse-text');

    eventSource.onopen = () => {
        sseDot.className = 'dot pulse-green';
        sseText.textContent = 'Connected (Live)';
        reconnectTimeout = 1000;
    };

    eventSource.onmessage = (e) => {
        try {
            const data = JSON.parse(e.data);
            addEvent(data);
            fetchStats(); // Refresh stats on each event
        } catch (err) {
            console.error('Error parsing SSE message:', err);
        }
    };

    eventSource.onerror = () => {
        eventSource.close();
        sseDot.className = 'dot pulse-red';
        sseText.textContent = 'Reconnecting...';

        setTimeout(setupSSE, reconnectTimeout);
        reconnectTimeout = Math.min(reconnectTimeout * 2, 30000);
    };
}

// ============================================================
// Fetch Stats from API
// ============================================================
async function fetchStats() {
    try {
        const res = await fetch('/waf/api/stats');
        const data = await res.json();

        animateCounter('stat-total-reqs', data.total_requests || 0);
        animateCounter('stat-blocked-reqs', data.blocked_requests || 0);
        animateCounter('stat-active-rules', data.active_rules || 0);

        // Block percentage
        if (data.total_requests > 0) {
            const pct = data.block_rate || ((data.blocked_requests / data.total_requests) * 100).toFixed(1);
            document.getElementById('stat-blocked-pct').textContent = `${pct}%`;
        }

        // WAF status
        const wafDot = document.getElementById('waf-status-dot');
        const wafText = document.getElementById('waf-status-text');
        const modeBadge = document.getElementById('waf-mode-badge');

        if (data.status === 'active') {
            wafDot.className = 'dot pulse-green';
            wafText.textContent = 'ACTIVE';
        } else {
            wafDot.className = 'dot pulse-red';
            wafText.textContent = 'DISABLED';
        }

        if (data.mode) {
            modeBadge.textContent = data.mode.toUpperCase();
            modeBadge.className = data.mode === 'block' ? 'mode-badge badge-block' : 'mode-badge badge-monitor';
        }

        // Update charts from stats
        updateThreatChart(data.by_threat_type || {});
        updateIPChart(data.top_blocked_ips || {});

    } catch (err) {
        console.error('Failed to fetch stats:', err);
    }
}

// ============================================================
// Live Event Feed
// ============================================================
function addEvent(eventData) {
    events.unshift(eventData);
    if (events.length > MAX_EVENTS) {
        events.pop();
    }

    const tbody = document.getElementById('events-tbody');
    const tr = document.createElement('tr');

    const timestamp = formatTimestamp(eventData.timestamp);
    const threatColor = getThreatColor(eventData.threat_type);
    const actionBadge = getActionBadge(eventData.action);
    const payload = truncateText(eventData.payload || '-', 40);
    const ip = eventData.client_ip || eventData.ip || '-';

    tr.innerHTML = `
        <td>${timestamp}</td>
        <td>${ip}</td>
        <td>${eventData.method || '-'}</td>
        <td>${eventData.path || '-'}</td>
        <td><span class="badge" style="background: ${threatColor}20; color: ${threatColor};">${eventData.threat_type || 'Unknown'}</span></td>
        <td>${actionBadge}</td>
        <td title="${(eventData.payload || '').replace(/"/g, '&quot;')}">${payload}</td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);

    // Prune DOM to keep it performant
    while (tbody.children.length > MAX_EVENTS) {
        tbody.removeChild(tbody.lastChild);
    }

    // Update timeline
    updateTimeline(eventData);
}

// ============================================================
// Charts
// ============================================================
function initCharts() {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // Threat Distribution Doughnut
    const ctxThreat = document.getElementById('threatDistributionChart').getContext('2d');
    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
                borderWidth: 0,
                cutout: '70%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { padding: 15, usePointStyle: true } }
            }
        }
    });

    // Top Attacking IPs (Horizontal Bar)
    const ctxIPs = document.getElementById('topIPsChart').getContext('2d');
    topIpChart = new Chart(ctxIPs, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Blocked Requests',
                data: [],
                backgroundColor: 'rgba(0, 212, 255, 0.4)',
                borderColor: '#00d4ff',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { stepSize: 1 } },
                y: { grid: { display: false } }
            }
        }
    });

    // Attacks Timeline (Line)
    const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks/Min',
                data: [],
                borderColor: '#ff3b5c',
                backgroundColor: 'rgba(255, 59, 92, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 2,
                pointBackgroundColor: '#ff3b5c'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    });
}

function updateThreatChart(byType) {
    const labels = Object.keys(byType);
    const data = Object.values(byType);
    const colors = labels.map(l => getThreatColor(l));

    threatChart.data.labels = labels;
    threatChart.data.datasets[0].data = data;
    threatChart.data.datasets[0].backgroundColor = colors;
    threatChart.update('none');
}

function updateIPChart(topIps) {
    const sorted = Object.entries(topIps).sort((a, b) => b[1] - a[1]).slice(0, 10);
    topIpChart.data.labels = sorted.map(i => i[0]);
    topIpChart.data.datasets[0].data = sorted.map(i => i[1]);
    topIpChart.update('none');
}

function updateTimeline(eventData) {
    if (eventData.action !== 'block') return;

    const now = new Date();
    const minuteKey = `${now.getHours()}:${String(now.getMinutes()).padStart(2, '0')}`;

    timelineBuckets[minuteKey] = (timelineBuckets[minuteKey] || 0) + 1;

    // Keep last 30 minutes only
    const keys = Object.keys(timelineBuckets);
    if (keys.length > 30) {
        delete timelineBuckets[keys[0]];
    }

    const sortedKeys = Object.keys(timelineBuckets).sort();
    timelineChart.data.labels = sortedKeys;
    timelineChart.data.datasets[0].data = sortedKeys.map(k => timelineBuckets[k]);
    timelineChart.update('none');
}

// ============================================================
// Utilities
// ============================================================
function formatTimestamp(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function truncateText(text, maxLen) {
    if (!text) return '-';
    text = String(text);
    if (text.length <= maxLen) return text;
    return text.substring(0, maxLen) + '…';
}

function getThreatColor(type) {
    const colors = {
        'SQL_INJECTION': '#ff3b5c',
        'XSS_ATTACK': '#ffab00',
        'PATH_TRAVERSAL': '#b388ff',
        'COMMAND_INJECTION': '#ff5252',
        'LDAP_INJECTION': '#00b0ff',
        'HEADER_INJECTION': '#ff6e40',
        'RATE_LIMIT_EXCEEDED': '#ffd740',
        'BLACKLISTED_IP': '#ff1744',
        'BAD_BOTS': '#69f0ae',
        'SECURITY_SCANNER': '#e040fb'
    };
    return colors[type] || '#94a3b8';
}

function getActionBadge(action) {
    if (action === 'block') return '<span class="badge action-block">BLOCKED</span>';
    if (action === 'rate_limit') return '<span class="badge action-limit">RATE LIMITED</span>';
    if (action === 'monitor') return '<span class="badge action-allow">MONITORED</span>';
    return '<span class="badge action-allow">ALLOWED</span>';
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent.replace(/,/g, '')) || 0;

    if (current === target) return;

    const diff = target - current;
    const steps = 15;
    const step = Math.ceil(Math.abs(diff) / steps);
    let value = current;

    function tick() {
        if (value < target) {
            value = Math.min(value + step, target);
        } else {
            value = Math.max(value - step, target);
        }
        el.textContent = value.toLocaleString();
        if (value !== target) {
            requestAnimationFrame(tick);
        }
    }
    requestAnimationFrame(tick);
}

// ============================================================
// Export & Clear
// ============================================================
function exportCSV() {
    let csv = "Timestamp,IP,Method,Path,Threat Type,Action,Payload\n";
    events.forEach(e => {
        const row = [
            e.timestamp || '',
            e.client_ip || e.ip || '',
            e.method || '',
            e.path || '',
            e.threat_type || '',
            e.action || '',
            `"${(e.payload || '').replace(/"/g, '""')}"`
        ].join(',');
        csv += row + "\n";
    });

    downloadFile('waf_events.csv', csv, 'text/csv');
}

function exportJSON() {
    const jsonStr = JSON.stringify(events, null, 2);
    downloadFile('waf_events.json', jsonStr, 'application/json');
}

function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

async function clearEvents() {
    try {
        await fetch('/waf/api/events/clear', { method: 'POST' });
        events = [];
        timelineBuckets = {};
        document.getElementById('events-tbody').innerHTML = '';
        fetchStats();
    } catch (err) {
        console.error('Failed to clear events:', err);
    }
}
