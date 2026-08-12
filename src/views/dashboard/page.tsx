import type { FC } from "hono/jsx";

const DashboardPage: FC = () => {
	return (
		<html lang="en">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>PromptWall Dashboard & Security Audit</title>
				<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
				<link rel="stylesheet" href="/dashboard/tailwind.css" />
				<style
					// biome-ignore lint/security/noDangerouslySetInnerHtml: Custom CSS
					dangerouslySetInnerHTML={{
						__html: `
							:root {
								--color-accent: #b45309;
								--color-accent-hover: #92400e;
								--color-accent-light: #d97706;
								--color-accent-bg: #fef3c7;
								--color-accent-bg-subtle: #fffbeb;

								--color-bg-page: #fafaf9;
								--color-bg-surface: #ffffff;
								--color-bg-elevated: #f5f5f4;
								--color-border: #e7e5e4;
								--color-border-subtle: #f5f5f4;

								--color-text-primary: #1c1917;
								--color-text-secondary: #44403c;
								--color-text-muted: #57534e;
								--color-text-subtle: #78716c;

								--color-success: #16a34a;
								--color-success-bg: #dcfce7;
								--color-error: #dc2626;
								--color-error-bg: #fee2e2;
								--color-info: #2563eb;
								--color-info-bg: #dbeafe;
								--color-warning: #d97706;
								--color-warning-bg: #fef3c7;
								--color-teal: #0d9488;
								--color-anthropic: #d97706;

								--font-sans: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
								--font-mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace;
								--tracking-tight: -0.02em;

								--radius-sm: 6px;
								--radius-md: 8px;
								--radius-lg: 12px;
								--radius-xl: 16px;

								--shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
								--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -1px rgba(0, 0, 0, 0.04);
								--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -2px rgba(0, 0, 0, 0.04);

								--duration-fast: 150ms;
								--duration-normal: 200ms;
								--ease-out: cubic-bezier(0, 0, 0.2, 1);
							}

							* { box-sizing: border-box; }

							body {
								font-family: var(--font-sans);
								background: var(--color-bg-page);
								color: var(--color-text-primary);
								line-height: 1.6;
							}

							.font-mono { font-family: var(--font-mono); }

							.bg-page { background: var(--color-bg-page); }
							.bg-surface { background: var(--color-bg-surface); }
							.bg-elevated { background: var(--color-bg-elevated); }
							.bg-detail { background: var(--color-bg-page); }
							.bg-accent { background: var(--color-accent); }
							.bg-accent-bg { background: var(--color-accent-bg); }

							@keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
							.animate-pulse-dot { animation: pulse 2s ease-in-out infinite; }
							.animate-fade-in { animation: fadeIn 0.35s var(--ease-out) backwards; }

							.card-hover:hover {
								box-shadow: var(--shadow-md);
								transform: translateY(-2px);
								border-color: color-mix(in srgb, var(--color-accent) 40%, var(--color-border));
							}

							.tab-active {
								border-bottom: 2px solid var(--color-accent);
								color: var(--color-accent);
								font-weight: 600;
							}
						`,
					}}
				/>
			</head>
			<body class="bg-page text-text-primary min-h-screen font-sans antialiased leading-relaxed">
				<div class="max-w-[1320px] mx-auto p-8 px-6">
					<Header />
					<NavigationTabs />

					<div id="overview-tab-content">
						<StatsGrid />
						<Charts />
						<LogsSection />
					</div>

					<div id="audit-tab-content" class="hidden">
						<AuditStatsGrid />
						<AuditFilterBar />
						<AuditEventsSection />
					</div>
				</div>
				<ClientScript />
			</body>
		</html>
	);
};

const Header: FC = () => (
	<header class="flex justify-between items-center mb-6">
		<div class="flex items-center gap-3">
			<svg class="w-9 h-9" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
				<path d="M32 6C20 6 12 12 12 12v20c0 12 8 22 20 26 12-4 20-14 20-26V12s-8-6-20-6z" stroke="var(--color-accent)" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
				<rect x="22" y="24" width="20" height="4" rx="2" fill="var(--color-accent)"/>
				<rect x="22" y="32" width="14" height="4" rx="2" fill="var(--color-accent)" opacity="0.6"/>
				<rect x="22" y="40" width="17" height="4" rx="2" fill="var(--color-accent)" opacity="0.3"/>
			</svg>
			<div class="text-xl font-bold text-text-primary" style="letter-spacing: var(--tracking-tight)">
				Prompt<span class="text-accent">Wall</span> <span class="text-xs font-mono font-normal text-text-muted px-2 py-0.5 bg-elevated rounded-md border border-border-subtle">Enterprise Security</span>
			</div>
		</div>
		<div class="flex items-center gap-4">
			<span
				id="mode-badge"
				class="inline-flex items-center px-3 py-1.5 rounded-md font-mono text-[0.7rem] font-medium tracking-wide uppercase bg-elevated text-text-muted"
			>
				—
			</span>
			<div class="flex items-center gap-2 px-3 py-1.5 bg-surface border border-border rounded-full text-xs text-text-secondary shadow-sm">
				<div class="w-[7px] h-[7px] bg-success rounded-full animate-pulse-dot" />
				<span>Live</span>
			</div>
		</div>
	</header>
);

const NavigationTabs: FC = () => (
	<div class="flex gap-8 border-b border-border mb-8 text-sm">
		<button
			id="tab-overview"
			class="py-3 font-medium text-accent tab-active cursor-pointer"
			onclick="switchTab('overview')"
		>
			📊 Overview & Proxy Logs
		</button>
		<button
			id="tab-audit"
			class="py-3 font-medium text-text-muted hover:text-text-primary cursor-pointer"
			onclick="switchTab('audit')"
		>
			🛡️ Security Audit & Risk Logs
		</button>
	</div>
);

const StatsGrid: FC = () => (
	<div id="stats-grid" class="grid grid-cols-6 gap-4 mb-8">
		<StatCard label="Total Requests" valueId="total-requests" />
		<StatCard id="pii-card" label="Routed Local" labelId="pii-label" valueId="pii-requests" accent="accent" />
		<StatCard label="API Requests" valueId="api-requests" accent="accent" />
		<StatCard label="Extension" valueId="browser-extension-requests" accent="teal" />
		<StatCard label="Avg PII Scan" valueId="avg-scan" accent="teal" />
		<StatCard label="Requests/Hour" valueId="requests-hour" />
	</div>
);

const AuditStatsGrid: FC = () => (
	<div class="grid grid-cols-5 gap-4 mb-8">
		<StatCard label="Total Audit Events" valueId="audit-total-events" />
		<StatCard label="Blocked Threats" valueId="audit-blocked-threats" accent="accent" />
		<StatCard label="Masked Requests" valueId="audit-masked-requests" accent="teal" />
		<StatCard label="Critical/High Risk" valueId="audit-critical-risk" accent="accent" />
		<StatCard label="Avg Detection Latency" valueId="audit-avg-latency" accent="teal" />
	</div>
);

const StatCard: FC<{
	id?: string;
	label: string;
	labelId?: string;
	valueId: string;
	accent?: "accent" | "info" | "success" | "teal";
}> = ({ id, label, labelId, valueId, accent }) => {
	const accentClass = accent
		? {
				accent: "text-accent",
				info: "text-info",
				success: "text-success",
				teal: "text-teal",
			}[accent]
		: "";

	return (
		<div
			id={id}
			class="bg-surface border border-border-subtle rounded-xl p-5 shadow-sm transition-all card-hover animate-fade-in"
		>
			<div id={labelId} class="text-[0.7rem] font-medium uppercase tracking-widest text-text-muted mb-2">
				{label}
			</div>
			<div id={valueId} class={`text-3xl font-bold tabular-nums ${accentClass}`} style="letter-spacing: var(--tracking-tight)">
				—
			</div>
		</div>
	);
};

const Charts: FC = () => (
	<div class="grid grid-cols-1 gap-4 mb-8">
		<div id="entity-chart-card" class="bg-surface border border-border-subtle rounded-xl p-6 shadow-sm animate-fade-in">
			<div class="text-[0.8rem] font-semibold text-text-secondary mb-5 uppercase tracking-wide">
				Entity Types Detected
			</div>
			<div id="entity-chart" class="flex flex-col gap-2.5">
				<div class="text-sm text-text-muted py-4 text-center">Loading detection statistics...</div>
			</div>
		</div>
	</div>
);

const LogsSection: FC = () => (
	<>
		<div class="text-[0.8rem] font-semibold text-text-secondary mb-4 uppercase tracking-wide">
			Recent Requests
		</div>
		<div class="bg-surface border border-border-subtle rounded-xl shadow-sm overflow-hidden animate-fade-in">
			<div class="overflow-x-auto">
				<table class="w-full min-w-[700px] border-collapse">
					<thead>
						<tr>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Time</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Source</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Status</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Model</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">PII Entities</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Secrets</th>
							<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Scan Time</th>
						</tr>
					</thead>
					<tbody id="logs-body">
						<tr><td colSpan={7} class="p-8 text-center text-text-muted text-sm">Loading requests...</td></tr>
					</tbody>
				</table>
			</div>
		</div>
	</>
);

const AuditFilterBar: FC = () => (
	<div class="flex flex-wrap items-center justify-between gap-4 bg-surface border border-border-subtle p-4 rounded-xl shadow-sm mb-6">
		<div class="flex flex-wrap items-center gap-3">
			<select id="audit-filter-action" class="bg-elevated border border-border text-xs text-text-primary rounded-lg p-2 font-medium" onchange="fetchAuditEvents()">
				<option value="">All Actions</option>
				<option value="block">BLOCK</option>
				<option value="mask">MASK</option>
				<option value="allow">ALLOW</option>
			</select>

			<select id="audit-filter-risk" class="bg-elevated border border-border text-xs text-text-primary rounded-lg p-2 font-medium" onchange="fetchAuditEvents()">
				<option value="">All Risk Levels</option>
				<option value="critical">CRITICAL</option>
				<option value="high">HIGH</option>
				<option value="medium">MEDIUM</option>
				<option value="low">LOW</option>
			</select>

			<select id="audit-filter-timeframe" class="bg-elevated border border-border text-xs text-text-primary rounded-lg p-2 font-medium" onchange="fetchAuditAnalytics(); fetchAuditEvents();">
				<option value="24h">Last 24 Hours</option>
				<option value="7d">Last 7 Days</option>
				<option value="30d">Last 30 Days</option>
				<option value="all">All Time</option>
			</select>
		</div>

		<div class="flex items-center gap-2">
			<button class="bg-elevated hover:bg-border border border-border text-text-secondary text-xs px-3 py-2 rounded-lg font-medium cursor-pointer" onclick="downloadExport('json')">
				📥 Export JSON
			</button>
			<button class="bg-accent hover:bg-accent-hover text-white text-xs px-3 py-2 rounded-lg font-medium cursor-pointer" onclick="downloadExport('csv')">
				📥 Export CSV
			</button>
		</div>
	</div>
);

const AuditEventsSection: FC = () => (
	<div class="bg-surface border border-border-subtle rounded-xl shadow-sm overflow-hidden animate-fade-in">
		<div class="overflow-x-auto">
			<table class="w-full min-w-[900px] border-collapse">
				<thead>
					<tr>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Timestamp</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Request ID</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Provider / Model</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Action</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Risk Level & Score</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Detectors Triggered</th>
						<th class="bg-elevated font-mono text-[0.65rem] font-medium uppercase tracking-widest text-text-muted px-4 py-3.5 text-left border-b border-border">Latency</th>
					</tr>
				</thead>
				<tbody id="audit-events-body">
					<tr><td colSpan={7} class="p-8 text-center text-text-muted text-sm">Loading security audit events...</td></tr>
				</tbody>
			</table>
		</div>
	</div>
);

const ClientScript: FC = () => (
	<script
		// biome-ignore lint/security/noDangerouslySetInnerHtml: Client-side JS
		dangerouslySetInnerHTML={{
			__html: `
function switchTab(tab) {
  const overviewContent = document.getElementById('overview-tab-content');
  const auditContent = document.getElementById('audit-tab-content');
  const tabOverview = document.getElementById('tab-overview');
  const tabAudit = document.getElementById('tab-audit');

  if (tab === 'overview') {
    overviewContent.classList.remove('hidden');
    auditContent.classList.add('hidden');
    tabOverview.className = 'py-3 font-medium text-accent tab-active cursor-pointer';
    tabAudit.className = 'py-3 font-medium text-text-muted hover:text-text-primary cursor-pointer';
  } else {
    overviewContent.classList.add('hidden');
    auditContent.classList.remove('hidden');
    tabAudit.className = 'py-3 font-medium text-accent tab-active cursor-pointer';
    tabOverview.className = 'py-3 font-medium text-text-muted hover:text-text-primary cursor-pointer';
    fetchAuditAnalytics();
    fetchAuditEvents();
  }
}

async function fetchStats() {
  try {
    const res = await fetch('/dashboard/api/stats');
    const data = await res.json();
    document.getElementById('total-requests').textContent = (data.total_requests || 0).toLocaleString();
    document.getElementById('api-requests').textContent = (data.api_requests || 0).toLocaleString();
    document.getElementById('browser-extension-requests').textContent = (data.browser_extension_requests || 0).toLocaleString();
    document.getElementById('avg-scan').textContent = (data.avg_scan_time_ms || 0) + 'ms';
    document.getElementById('requests-hour').textContent = (data.requests_last_hour || 0).toLocaleString();
    const modeBadge = document.getElementById('mode-badge');
    modeBadge.textContent = (data.mode || 'mask').toUpperCase();
  } catch (err) {
    console.error('Failed to fetch stats:', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/dashboard/api/logs?limit=50');
    const data = await res.json();
    const tbody = document.getElementById('logs-body');
    if (!data.logs || data.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-8 text-text-muted text-sm">No proxy logs recorded yet</td></tr>';
      return;
    }
    tbody.innerHTML = data.logs.map(log => {
      const time = new Date(log.timestamp).toLocaleTimeString();
      return '<tr class="border-b border-border-subtle hover:bg-elevated text-xs">' +
        '<td class="px-4 py-3 font-mono text-text-secondary">' + time + '</td>' +
        '<td class="px-4 py-3 font-mono text-text-primary">' + log.source + '</td>' +
        '<td class="px-4 py-3 font-mono text-success font-semibold">' + (log.status_code || 200) + '</td>' +
        '<td class="px-4 py-3 font-mono text-text-secondary">' + log.model + '</td>' +
        '<td class="px-4 py-3 text-text-muted">' + (log.entities || '—') + '</td>' +
        '<td class="px-4 py-3 text-text-muted">' + (log.secrets_types || '—') + '</td>' +
        '<td class="px-4 py-3 font-mono text-teal">' + log.scan_time_ms + 'ms</td>' +
      '</tr>';
    }).join('');
  } catch (err) {
    console.error('Failed to fetch logs:', err);
  }
}

async function fetchAuditAnalytics() {
  try {
    const timeframe = document.getElementById('audit-filter-timeframe').value || '24h';
    const res = await fetch('/dashboard/api/audit/stats?timeframe=' + timeframe);
    const data = await res.json();
    const stats = data.stats;

    document.getElementById('audit-total-events').textContent = (stats.totalEvents || 0).toLocaleString();
    document.getElementById('audit-blocked-threats').textContent = (stats.actionBreakdown.block || 0) + ' (' + stats.actionBreakdown.blockPercentage + '%)';
    document.getElementById('audit-masked-requests').textContent = (stats.actionBreakdown.mask || 0) + ' (' + stats.actionBreakdown.maskPercentage + '%)';
    document.getElementById('audit-critical-risk').textContent = (stats.riskLevelDistribution.critical + stats.riskLevelDistribution.high || 0).toLocaleString();
    document.getElementById('audit-avg-latency').textContent = (stats.latencyMetrics.avg || 0) + 'ms';
  } catch (err) {
    console.error('Failed to fetch audit analytics:', err);
  }
}

async function fetchAuditEvents() {
  try {
    const action = document.getElementById('audit-filter-action').value;
    const riskLevel = document.getElementById('audit-filter-risk').value;
    let url = '/dashboard/api/audit/events?limit=50';
    if (action) url += '&action=' + action;
    if (riskLevel) url += '&riskLevel=' + riskLevel;

    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('audit-events-body');

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-8 text-text-muted text-sm">No security audit events matching query</td></tr>';
      return;
    }

    tbody.innerHTML = data.events.map(ev => {
      const time = new Date(ev.timestamp).toLocaleTimeString();
      const actionBadge = ev.action === 'block'
        ? '<span class="px-2 py-0.5 rounded text-[0.65rem] font-mono font-bold bg-error/10 text-error border border-error/20">BLOCK</span>'
        : ev.action === 'mask'
        ? '<span class="px-2 py-0.5 rounded text-[0.65rem] font-mono font-bold bg-amber-100 text-amber-700 border border-amber-300">MASK</span>'
        : '<span class="px-2 py-0.5 rounded text-[0.65rem] font-mono font-bold bg-success/10 text-success border border-success/20">ALLOW</span>';

      const riskBadge = ev.riskLevel === 'critical'
        ? '<span class="font-mono text-xs font-bold text-error">CRITICAL (' + ev.riskScore + ')</span>'
        : ev.riskLevel === 'high'
        ? '<span class="font-mono text-xs font-bold text-amber-600">HIGH (' + ev.riskScore + ')</span>'
        : ev.riskLevel === 'medium'
        ? '<span class="font-mono text-xs font-bold text-info">MEDIUM (' + ev.riskScore + ')</span>'
        : '<span class="font-mono text-xs text-text-muted">LOW (' + ev.riskScore + ')</span>';

      const detectors = ev.detectorsTriggered && ev.detectorsTriggered.length > 0
        ? ev.detectorsTriggered.map(d => '<span class="px-1.5 py-0.5 bg-elevated border border-border text-[0.6rem] font-mono rounded text-text-secondary mr-1">' + d + '</span>').join('')
        : '<span class="text-text-muted">—</span>';

      return '<tr class="border-b border-border-subtle hover:bg-elevated text-xs">' +
        '<td class="px-4 py-3 font-mono text-text-secondary">' + time + '</td>' +
        '<td class="px-4 py-3 font-mono text-text-primary text-[0.7rem]">' + ev.requestId.slice(0, 18) + '...</td>' +
        '<td class="px-4 py-3 font-mono text-text-secondary">' + ev.provider + ' / ' + ev.model + '</td>' +
        '<td class="px-4 py-3">' + actionBadge + '</td>' +
        '<td class="px-4 py-3">' + riskBadge + '</td>' +
        '<td class="px-4 py-3">' + detectors + '</td>' +
        '<td class="px-4 py-3 font-mono text-teal">' + ev.latencyMs + 'ms</td>' +
      '</tr>';
    }).join('');
  } catch (err) {
    console.error('Failed to fetch audit events:', err);
  }
}

function downloadExport(format) {
  const action = document.getElementById('audit-filter-action').value;
  const riskLevel = document.getElementById('audit-filter-risk').value;
  let url = '/dashboard/api/audit/export?format=' + format;
  if (action) url += '&action=' + action;
  if (riskLevel) url += '&riskLevel=' + riskLevel;
  window.open(url, '_blank');
}

fetchStats();
fetchLogs();
			`,
		}}
	/>
);

export default DashboardPage;
