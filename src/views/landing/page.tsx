import type { FC } from "hono/jsx";
import { DEMO_HEADER, DEMO_SECRET_HEADER } from "../../debug/types";

// ─── Types used client-side (inlined for JSX template) ───────────────────────

const LandingPage: FC = () => {
	return (
		<html lang="en">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>PromptWall – Enterprise AI Security Gateway</title>
				<meta
					name="description"
					content="Protect sensitive prompts before they reach any LLM. PromptWall detects and masks PII and secrets in real time."
				/>
				<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
				<link rel="preconnect" href="https://fonts.googleapis.com" />
				<link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
				<link
					href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
					rel="stylesheet"
				/>
				<style
					// biome-ignore lint/security/noDangerouslySetInnerHtml: Custom CSS for landing page
					dangerouslySetInnerHTML={{
						__html: `
/* ─── Reset & Base ─────────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  /* Brand */
  --amber:          #b45309;
  --amber-light:    #d97706;
  --amber-glow:     rgba(180, 83, 9, 0.35);
  --amber-subtle:   rgba(180, 83, 9, 0.12);
  --amber-border:   rgba(180, 83, 9, 0.30);

  /* Dark palette */
  --bg-base:        #070709;
  --bg-surface:     #0f0f13;
  --bg-card:        rgba(255,255,255,0.035);
  --bg-card-hover:  rgba(255,255,255,0.06);
  --bg-input:       rgba(255,255,255,0.04);
  --bg-badge:       rgba(255,255,255,0.07);

  /* Borders */
  --border:         rgba(255,255,255,0.08);
  --border-focus:   rgba(180,83,9,0.50);

  /* Text */
  --text-primary:   #f0ede8;
  --text-secondary: #9d9892;
  --text-muted:     #6b6762;

  /* Semantic */
  --green:          #22c55e;
  --green-subtle:   rgba(34,197,94,0.12);
  --green-border:   rgba(34,197,94,0.25);
  --red:            #ef4444;
  --red-subtle:     rgba(239,68,68,0.12);
  --red-border:     rgba(239,68,68,0.25);
  --blue:           #3b82f6;
  --blue-subtle:    rgba(59,130,246,0.12);

  /* Typography */
  --font:     'Inter', system-ui, -apple-system, sans-serif;
  --mono:     ui-monospace, 'SF Mono', Menlo, monospace;

  /* Motion */
  --ease:     cubic-bezier(0.16, 1, 0.3, 1);
  --fast:     150ms;
  --normal:   250ms;
}

html { scroll-behavior: smooth; }

body {
  font-family: var(--font);
  background: var(--bg-base);
  color: var(--text-primary);
  min-height: 100vh;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* ─── Scrollbar ─────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 3px; }

/* ─── Nav ─────────────────────────────────────────────────────────────────── */
.nav {
  position: sticky; top: 0; z-index: 50;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px; height: 60px;
  background: rgba(7,7,9,0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
}
.nav-logo {
  display: flex; align-items: center; gap: 10px;
  text-decoration: none; color: var(--text-primary);
}
.nav-logo-text {
  font-size: 1.05rem; font-weight: 700; letter-spacing: -0.02em;
}
.nav-logo-text span { color: var(--amber-light); }
.nav-right { display: flex; align-items: center; gap: 8px; }
.nav-link {
  padding: 6px 12px; border-radius: 6px;
  font-size: 0.8rem; font-weight: 500; color: var(--text-secondary);
  text-decoration: none; border: 1px solid transparent;
  cursor: pointer; background: transparent;
  transition: color var(--fast) var(--ease), background var(--fast) var(--ease),
              border-color var(--fast) var(--ease);
}
.nav-link:hover { color: var(--text-primary); background: var(--bg-badge); border-color: var(--border); }
.nav-link-primary {
  color: var(--text-primary); background: var(--bg-badge);
  border-color: var(--border);
}
.nav-link-primary:hover { border-color: var(--amber-border); }

.provider-select {
  appearance: none; padding: 6px 28px 6px 10px;
  background: var(--bg-badge) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%239d9892' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round' fill='none'/%3E%3C/svg%3E") no-repeat right 8px center;
  border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-primary); font-family: var(--font);
  font-size: 0.8rem; font-weight: 500; cursor: pointer;
  transition: border-color var(--fast) var(--ease);
}
.provider-select:hover { border-color: var(--amber-border); }
.provider-select:focus { outline: none; border-color: var(--amber-border); }
.provider-select option { background: #111115; }

/* ─── Hero ────────────────────────────────────────────────────────────────── */
.hero {
  display: flex; flex-direction: column; align-items: center;
  padding: 72px 24px 52px; text-align: center; max-width: 800px; margin: 0 auto;
}
.demo-badge {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 5px 14px; border-radius: 100px;
  border: 1px solid var(--amber-border);
  background: var(--amber-subtle);
  font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--amber-light);
  margin-bottom: 24px;
}
.demo-badge-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--amber-light);
  animation: pulse-dot 2s ease-in-out infinite;
}
.hero-title {
  font-size: clamp(2rem, 5vw, 3.2rem); font-weight: 800;
  letter-spacing: -0.04em; line-height: 1.12; margin-bottom: 16px;
}
.hero-title span {
  background: linear-gradient(135deg, var(--amber-light), var(--amber));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.hero-sub {
  font-size: 1.05rem; color: var(--text-secondary); line-height: 1.65;
  max-width: 540px; margin-bottom: 40px;
}

/* ─── Input Card ──────────────────────────────────────────────────────────── */
.input-card {
  width: 100%; max-width: 720px; margin: 0 auto;
  background: var(--bg-card);
  border: 1px solid var(--border); border-radius: 16px;
  padding: 4px;
  box-shadow: 0 0 0 1px rgba(255,255,255,0.03), 0 24px 64px rgba(0,0,0,0.5);
  transition: border-color var(--normal) var(--ease), box-shadow var(--normal) var(--ease);
}
.input-card:focus-within {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 1px rgba(180,83,9,0.15), 0 0 40px var(--amber-glow), 0 24px 64px rgba(0,0,0,0.5);
}
.prompt-textarea {
  width: 100%; min-height: 140px; padding: 16px 18px;
  background: transparent; border: none; resize: none;
  color: var(--text-primary); font-family: var(--font);
  font-size: 0.95rem; line-height: 1.65;
  caret-color: var(--amber-light);
}
.prompt-textarea::placeholder { color: var(--text-muted); }
.prompt-textarea:focus { outline: none; }

.input-footer {
  display: flex; justify-content: space-between; align-items: center;
  padding: 8px 14px 12px; gap: 12px;
}
.char-counter { font-size: 0.72rem; color: var(--text-muted); font-variant-numeric: tabular-nums; }

.send-btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 10px 22px; border-radius: 10px; cursor: pointer; border: none;
  background: linear-gradient(135deg, var(--amber-light), var(--amber));
  color: white; font-family: var(--font); font-size: 0.875rem; font-weight: 600;
  letter-spacing: -0.01em; white-space: nowrap;
  box-shadow: 0 2px 16px var(--amber-glow);
  transition: transform var(--fast) var(--ease), box-shadow var(--fast) var(--ease),
              opacity var(--fast) var(--ease);
}
.send-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 4px 24px var(--amber-glow); }
.send-btn:active:not(:disabled) { transform: translateY(0); }
.send-btn:disabled { opacity: 0.55; cursor: not-allowed; }

/* ─── Main layout ─────────────────────────────────────────────────────────── */
.main-layout {
  display: grid;
  grid-template-columns: 1fr 280px;
  gap: 24px; max-width: 1200px; margin: 0 auto;
  padding: 32px 24px 80px; align-items: start;
}
@media (max-width: 900px) { .main-layout { grid-template-columns: 1fr; } }

/* ─── Pipeline stages ─────────────────────────────────────────────────────── */
.stages { display: flex; flex-direction: column; gap: 12px; }

.stage-card {
  border: 1px solid var(--border); border-radius: 12px;
  background: var(--bg-card); overflow: hidden;
  opacity: 0; transform: translateY(10px);
  transition: opacity 0.4s var(--ease), transform 0.4s var(--ease),
              border-color var(--fast) var(--ease), background var(--fast) var(--ease);
}
.stage-card.visible { opacity: 1; transform: translateY(0); }
.stage-card:hover { background: var(--bg-card-hover); }

.stage-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px; cursor: pointer; user-select: none;
}
.stage-num {
  width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.65rem; font-weight: 700; font-variant-numeric: tabular-nums;
  border: 1px solid var(--border); color: var(--text-muted); background: var(--bg-badge);
  transition: background var(--fast) var(--ease), color var(--fast) var(--ease),
              border-color var(--fast) var(--ease);
}
.stage-card.complete .stage-num {
  background: var(--green-subtle); color: var(--green); border-color: var(--green-border);
}
.stage-title { font-size: 0.825rem; font-weight: 600; color: var(--text-secondary); flex: 1; }
.stage-card.complete .stage-title { color: var(--text-primary); }
.stage-chevron {
  color: var(--text-muted); font-size: 0.65rem;
  transition: transform var(--fast) var(--ease);
}
.stage-card.expanded .stage-chevron { transform: rotate(90deg); }

.stage-body { padding: 0 16px 14px; display: none; }
.stage-card.expanded .stage-body { display: block; }

/* Stage content pieces */
.prompt-pre {
  white-space: pre-wrap; word-break: break-word;
  font-family: var(--mono); font-size: 0.8rem; line-height: 1.7;
  color: var(--text-primary); padding: 12px; border-radius: 8px;
  background: rgba(0,0,0,0.25); border: 1px solid var(--border);
}
.placeholder-token {
  background: var(--amber-subtle); color: var(--amber-light);
  border: 1px solid var(--amber-border); border-radius: 4px;
  padding: 1px 5px; font-size: 0.75rem; font-weight: 600;
  font-family: var(--mono); display: inline;
}
.badge-list { display: flex; flex-wrap: wrap; gap: 6px; }
.badge {
  padding: 3px 10px; border-radius: 100px; font-size: 0.7rem; font-weight: 600;
  font-family: var(--mono); letter-spacing: 0.03em;
}
.badge-pii { background: var(--amber-subtle); color: var(--amber-light); border: 1px solid var(--amber-border); }
.badge-secret { background: var(--red-subtle); color: var(--red); border: 1px solid var(--red-border); }
.badge-none { background: var(--bg-badge); color: var(--text-muted); border: 1px solid var(--border); font-size: 0.7rem; }

.diff-row { display: grid; gap: 10px; margin-top: 4px; }
.diff-label {
  font-size: 0.65rem; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;
}
.diff-before .prompt-pre { border-color: rgba(239,68,68,0.15); }
.diff-after .prompt-pre { border-color: var(--amber-border); }

.copy-btn {
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 10px; padding: 6px 12px; border-radius: 7px; cursor: pointer;
  border: 1px solid var(--border); background: var(--bg-badge);
  color: var(--text-secondary); font-family: var(--font);
  font-size: 0.75rem; font-weight: 500;
  transition: color var(--fast) var(--ease), border-color var(--fast) var(--ease),
              background var(--fast) var(--ease);
}
.copy-btn:hover { color: var(--text-primary); border-color: var(--amber-border); background: var(--amber-subtle); }

/* Spinner */
.spinner {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid rgba(255,255,255,0.2); border-top-color: white;
  animation: spin 0.7s linear infinite;
}

/* Loading stage skeleton */
.loading-stage { display: flex; align-items: center; gap: 8px; }
.loading-bar {
  height: 4px; border-radius: 2px; background: var(--amber);
  animation: pulse-bar 1.2s ease-in-out infinite;
}

/* ─── Sidebar ─────────────────────────────────────────────────────────────── */
.sidebar { display: flex; flex-direction: column; gap: 14px; }

.sidebar-card {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px; overflow: hidden;
}
.sidebar-title {
  font-size: 0.68rem; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--text-muted); margin-bottom: 14px;
}
.meta-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
}
.meta-row:last-child { border-bottom: none; }
.meta-label { font-size: 0.75rem; color: var(--text-muted); }
.meta-value { font-size: 0.78rem; font-weight: 600; color: var(--text-primary); font-variant-numeric: tabular-nums; }
.meta-value.mono { font-family: var(--mono); font-size: 0.72rem; }
.meta-value.green { color: var(--green); }
.meta-value.red { color: var(--red); }
.meta-value.amber { color: var(--amber-light); }
.meta-value.muted { color: var(--text-muted); font-weight: 400; }

/* Pipeline checklist */
.checklist { display: flex; flex-direction: column; gap: 3px; }
.check-row { display: flex; align-items: center; gap: 8px; padding: 3px 0; }
.check-icon {
  width: 16px; height: 16px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.6rem; border: 1px solid var(--border); color: var(--text-muted);
  background: var(--bg-badge); transition: all var(--fast) var(--ease);
}
.check-icon.done { background: var(--green-subtle); color: var(--green); border-color: var(--green-border); }
.check-icon.active { background: var(--amber-subtle); color: var(--amber-light); border-color: var(--amber-border); }
.check-text { font-size: 0.75rem; color: var(--text-muted); transition: color var(--fast) var(--ease); }
.check-row.done .check-text { color: var(--text-secondary); }
.check-row.active .check-text { color: var(--text-primary); font-weight: 500; }
.check-time { font-family: var(--mono); font-size: 0.65rem; color: var(--text-muted); margin-left: auto; }

/* Request ID display */
.request-id-box {
  background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 10px; margin-top: 4px;
  font-family: var(--mono); font-size: 0.68rem; color: var(--amber-light);
  word-break: break-all; line-height: 1.5;
}

/* Status pill */
.status-pill {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 2px 8px; border-radius: 100px; font-size: 0.68rem; font-weight: 600;
}
.status-ok { background: var(--green-subtle); color: var(--green); border: 1px solid var(--green-border); }
.status-error { background: var(--red-subtle); color: var(--red); border: 1px solid var(--red-border); }
.status-idle { background: var(--bg-badge); color: var(--text-muted); border: 1px solid var(--border); }

/* ─── Animations ──────────────────────────────────────────────────────────── */
@keyframes pulse-dot {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(217,119,6,0.4); }
  50% { opacity: 0.7; box-shadow: 0 0 0 5px rgba(217,119,6,0); }
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes pulse-bar {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 1; }
}
@keyframes shimmer {
  from { background-position: -200% 0; }
  to { background-position: 200% 0; }
}
@keyframes fade-up {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

/* ─── Error card ──────────────────────────────────────────────────────────── */
.error-card {
  padding: 14px; border-radius: 10px;
  background: var(--red-subtle); border: 1px solid var(--red-border);
  color: var(--red); font-size: 0.82rem; line-height: 1.5;
}

/* ─── Empty state ─────────────────────────────────────────────────────────── */
.empty-state {
  text-align: center; padding: 48px 24px;
}
.empty-icon { font-size: 2.5rem; margin-bottom: 12px; opacity: 0.3; }
.empty-text { color: var(--text-muted); font-size: 0.875rem; }

/* ─── Timeline ────────────────────────────────────────────────────────────── */
.timeline { display: flex; flex-direction: column; gap: 0; }
.tl-row { display: flex; align-items: flex-start; gap: 10px; padding: 5px 0; }
.tl-dot {
  width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 6px;
  background: var(--border); border: 1px solid var(--border);
  transition: background var(--fast) var(--ease), border-color var(--fast) var(--ease);
}
.tl-dot.done { background: var(--amber); border-color: var(--amber); }
.tl-line {
  width: 1px; background: var(--border); margin: 0 3.5px;
  height: 14px; flex-shrink: 0;
  transition: background var(--fast) var(--ease);
}
.tl-line.done { background: var(--amber); }
.tl-content { flex: 1; }
.tl-label { font-size: 0.72rem; font-weight: 500; color: var(--text-secondary); }
.tl-time { font-family: var(--mono); font-size: 0.65rem; color: var(--amber-light); margin-left: 6px; }
`,
					}}
				/>
			</head>
			<body>
				{/* Navigation */}
				<nav class="nav">
					<a href="/" class="nav-logo" id="nav-logo">
						<svg width="28" height="28" viewBox="0 0 64 64" fill="none">
							<path
								d="M32 6C20 6 12 12 12 12v20c0 12 8 22 20 26 12-4 20-14 20-26V12s-8-6-20-6z"
								stroke="#b45309"
								stroke-width="3"
								fill="none"
								stroke-linecap="round"
								stroke-linejoin="round"
							/>
							<rect x="22" y="24" width="20" height="4" rx="2" fill="#b45309" />
							<rect x="22" y="32" width="14" height="4" rx="2" fill="#b45309" opacity="0.6" />
							<rect x="22" y="40" width="17" height="4" rx="2" fill="#b45309" opacity="0.3" />
						</svg>
						<span class="nav-logo-text">
							Prompt<span>Wall</span>
						</span>
					</a>
					<div class="nav-right">
						<a href="/dashboard" class="nav-link nav-link-primary" id="nav-dashboard">
							Dashboard ↗
						</a>
						<a href="#" class="nav-link" id="nav-docs">
							API Docs
						</a>
						<a href="#" class="nav-link" id="nav-github">
							GitHub
						</a>
						<select class="provider-select" id="provider-select">
						<option value="gemini" selected>Gemini (Google)</option>
						<option value="openai">OpenAI</option>
						<option value="anthropic">Anthropic</option>
					</select>
					</div>
				</nav>

				{/* Hero */}
				<section class="hero">
					<div class="demo-badge">
						<div class="demo-badge-dot" />
						Demo Mode · Visualizing PromptWall Security Pipeline
					</div>
					<h1 class="hero-title">
						Enterprise AI
						<br />
						<span>Security Gateway</span>
					</h1>
					<p class="hero-sub">
						Protect sensitive prompts before they reach any LLM. Watch PromptWall detect, mask, and
						restore data in real time.
					</p>
 
					{/* Input card */}
					<div class="input-card" id="input-card">
						<label for="prompt-input" class="sr-only">Enter prompt to test securely</label>
						<textarea
							class="prompt-textarea"
							id="prompt-input"
							placeholder="Try entering emails, phone numbers, passwords, API keys, or personal information..."
							maxlength={4000}
							// biome-ignore lint/a11y/noAutofocus: intentional focus for demo UX
							autofocus
						/>
						<div class="input-footer">
							<span class="char-counter">
								<span id="char-count">0</span> / 4000
							</span>
							<button type="button" class="send-btn" id="send-btn" disabled>
								<svg width="14" height="14" viewBox="0 0 16 16" fill="none">
									<path
										d="M8 2C5.5 2 4 3 4 3v6c0 3 2 5.5 4 6.5C10 14.5 12 12 12 9V3s-1.5-1-4-1z"
										stroke="white"
										stroke-width="1.5"
										fill="none"
										stroke-linecap="round"
									/>
									<path d="M6 7h4M6 9.5h3" stroke="white" stroke-width="1.2" stroke-linecap="round" />
								</svg>
								Send Securely
							</button>
						</div>
					</div>
				</section>
 
				{/* Main layout: pipeline stages + sidebar */}
				<div class="main-layout" id="main-layout" style="display:none">
					{/* ── Pipeline stages ── */}
					<div class="stages" id="stages">
						{/* Stage 1 – Original Prompt */}
						<div class="stage-card" id="stage-1">
							<div class="stage-header" data-stage="1">
								<div class="stage-num">1</div>
								<div class="stage-title">Original Prompt</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="prompt-pre" id="s1-content" />
							</div>
						</div>
 
						{/* Stage 2 – Detected PII */}
						<div class="stage-card" id="stage-2">
							<div class="stage-header" data-stage="2">
								<div class="stage-num">2</div>
								<div class="stage-title">Detected PII</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="badge-list" id="s2-content" />
							</div>
						</div>
 
						{/* Stage 3 – Detected Secrets */}
						<div class="stage-card" id="stage-3">
							<div class="stage-header" data-stage="3">
								<div class="stage-num">3</div>
								<div class="stage-title">Detected Secrets</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="badge-list" id="s3-content" />
							</div>
						</div>
 
						{/* Stage 4 – Protected Prompt */}
						<div class="stage-card" id="stage-4">
							<div class="stage-header" data-stage="4">
								<div class="stage-num">4</div>
								<div class="stage-title">Protected Prompt</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="diff-row" id="s4-content" />
								<button
									type="button"
									class="copy-btn"
									id="copy-masked-btn"
									style="display:none"
								>
									<svg width="12" height="12" viewBox="0 0 16 16" fill="none">
										<rect x="5" y="5" width="9" height="9" rx="2" stroke="currentColor" stroke-width="1.5" />
										<path
											d="M4 11H3a2 2 0 01-2-2V3a2 2 0 012-2h6a2 2 0 012 2v1"
											stroke="currentColor"
											stroke-width="1.5"
											stroke-linecap="round"
										/>
									</svg>
									Copy Protected Prompt
								</button>
							</div>
						</div>
 
						{/* Stage 5 – Provider Response (shown only when masking occurred) */}
						<div class="stage-card" id="stage-5" style="display:none">
							<div class="stage-header" data-stage="5">
								<div class="stage-num">5</div>
								<div class="stage-title">Provider Response (with placeholders)</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="prompt-pre" id="s5-content" />
							</div>
						</div>
 
						{/* Stage 6 – Final Response */}
						<div class="stage-card" id="stage-6">
							<div class="stage-header" data-stage="6">
								<div class="stage-num">6</div>
								<div class="stage-title">Final Response</div>
								<div class="stage-chevron">▶</div>
							</div>
							<div class="stage-body">
								<div class="prompt-pre" id="s6-content" />
							</div>
						</div>
					</div>
 
					{/* ── Sidebar ── */}
					<aside class="sidebar">
						{/* Request metadata */}
						<div class="sidebar-card">
							<div class="sidebar-title">Request Metadata</div>
							<div class="meta-row">
								<span class="meta-label">Status</span>
								<span class="status-pill status-idle" id="meta-status" aria-live="polite">Idle</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Provider</span>
								<span class="meta-value" id="meta-provider">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Policy</span>
								<span class="meta-value" id="meta-policy">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Mask Count</span>
								<span class="meta-value" id="meta-masks">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">PII Entities</span>
								<span class="meta-value amber" id="meta-pii">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Secrets</span>
								<span class="meta-value red" id="meta-secrets">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Scan Time</span>
								<span class="meta-value mono" id="meta-scan">—</span>
							</div>
							<div class="meta-row">
								<span class="meta-label">Response Time</span>
								<span class="meta-value mono" id="meta-resp">—</span>
							</div>
							<div class="meta-row" style="border-bottom:none;padding-bottom:0;align-items:flex-start;flex-direction:column;gap:4px">
								<span class="meta-label">Request ID</span>
								<div class="request-id-box" id="meta-reqid">—</div>
							</div>
						</div>
 
						{/* Pipeline checklist */}
						<div class="sidebar-card">
							<div class="sidebar-title">Pipeline Status</div>
							<div class="checklist" id="pipeline-checklist" aria-live="polite">
								<div class="check-row" id="chk-received">
									<div class="check-icon" id="chk-received-icon">○</div>
									<span class="check-text">Prompt Received</span>
								</div>
								<div class="check-row" id="chk-secrets">
									<div class="check-icon" id="chk-secrets-icon">○</div>
									<span class="check-text">Secret Detection</span>
									<span class="check-time" id="chk-secrets-time" />
								</div>
								<div class="check-row" id="chk-pii">
									<div class="check-icon" id="chk-pii-icon">○</div>
									<span class="check-text">PII Detection</span>
									<span class="check-time" id="chk-pii-time" />
								</div>
								<div class="check-row" id="chk-merge">
									<div class="check-icon" id="chk-merge-icon">○</div>
									<span class="check-text">Merge Results</span>
								</div>
								<div class="check-row" id="chk-mask">
									<div class="check-icon" id="chk-mask-icon">○</div>
									<span class="check-text">Placeholder Mapping</span>
								</div>
								<div class="check-row" id="chk-policy">
									<div class="check-icon" id="chk-policy-icon">○</div>
									<span class="check-text">Policy Evaluation</span>
								</div>
								<div class="check-row" id="chk-provider">
									<div class="check-icon" id="chk-provider-icon">○</div>
									<span class="check-text">Provider Routing</span>
									<span class="check-time" id="chk-provider-time" />
								</div>
								<div class="check-row" id="chk-restore">
									<div class="check-icon" id="chk-restore-icon">○</div>
									<span class="check-text">Response Restoration</span>
									<span class="check-time" id="chk-restore-time" />
								</div>
								<div class="check-row" id="chk-log">
									<div class="check-icon" id="chk-log-icon">○</div>
									<span class="check-text">Logging Complete</span>
								</div>
							</div>
						</div>
 
						{/* Timeline */}
						<div class="sidebar-card" id="timeline-card" style="display:none">
							<div class="sidebar-title">Timing Breakdown</div>
							<div class="timeline" id="timeline" />
						</div>
					</aside>
				</div>

				<script
					// biome-ignore lint/security/noDangerouslySetInnerHtml: Client-side JS
					dangerouslySetInnerHTML={{
						__html: `
// ─── State ───────────────────────────────────────────────────────────────────
let expandedStages = new Set();
let maskedPromptText = '';
let isSending = false;
 
// ─── Helpers ─────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
 
function highlightPlaceholders(text) {
  return esc(text).replace(
    /\\[\\[([A-Z0-9_]+_\\d+)\\]\\]/g,
    '<span class="placeholder-token">[[$1]]</span>'
  );
}
 
function formatMs(ms) {
  if (!ms && ms !== 0) return '—';
  return ms + ' ms';
}
 
// ─── Stage toggle ─────────────────────────────────────────────────────────────
function toggleStage(n) {
  const card = document.getElementById('stage-' + n);
  if (!card || !card.classList.contains('complete')) return;
  if (expandedStages.has(n)) {
    expandedStages.delete(n);
    card.classList.remove('expanded');
  } else {
    expandedStages.add(n);
    card.classList.add('expanded');
  }
}
 
// ─── Stage reveal (animation + expand) ───────────────────────────────────────
function revealStage(n, renderFn) {
  const card = document.getElementById('stage-' + n);
  if (!card) return;
  card.style.display = '';
  renderFn();
  card.classList.add('complete');
  setTimeout(() => {
    card.classList.add('visible');
    // Auto-expand if not already expanded
    if (!expandedStages.has(n)) {
      expandedStages.add(n);
      card.classList.add('expanded');
    }
  }, 60);
}
 
// ─── Checklist helpers ────────────────────────────────────────────────────────
function checkDone(id, timeText) {
  const row = document.getElementById(id);
  const icon = document.getElementById(id + '-icon');
  if (!row || !icon) return;
  row.classList.add('done');
  icon.classList.add('done');
  icon.textContent = '✓';
  const timeEl = document.getElementById(id + '-time');
  if (timeEl && timeText) timeEl.textContent = timeText;
}
function checkActive(id) {
  const row = document.getElementById(id);
  const icon = document.getElementById(id + '-icon');
  if (!row || !icon) return;
  row.classList.add('active');
  icon.classList.add('active');
  icon.textContent = '·';
}
function checkReset() {
  ['received','secrets','pii','merge','mask','policy','provider','restore','log']
    .forEach(id => {
      const row = document.getElementById('chk-' + id);
      const icon = document.getElementById('chk-' + id + '-icon');
      const time = document.getElementById('chk-' + id + '-time');
      if (row) row.className = 'check-row';
      if (icon) { icon.className = 'check-icon'; icon.textContent = '○'; }
      if (time) time.textContent = '';
    });
}
 
// ─── Meta sidebar updates ──────────────────────────────────────────────────────
function metaSet(id, value, cls) {
  const el = document.getElementById('meta-' + id);
  if (!el) return;
  el.textContent = value;
  if (cls) el.className = 'meta-value ' + cls;
}
function metaReset() {
  ['provider','policy','masks','pii','secrets','scan','resp','reqid']
    .forEach(id => metaSet(id, '—'));
  const st = document.getElementById('meta-status');
  if (st) { st.className = 'status-pill status-idle'; st.textContent = 'Idle'; }
}
 
// ─── Copy masked prompt ───────────────────────────────────────────────────────
function copyMasked() {
  if (!maskedPromptText) return;
  navigator.clipboard.writeText(maskedPromptText).then(() => {
    const btn = document.getElementById('copy-masked-btn');
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="2" stroke="currentColor" stroke-width="1.5"/><path d="M4 11H3a2 2 0 01-2-2V3a2 2 0 012-2h6a2 2 0 012 2v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> Copy Protected Prompt'; }, 2000); }
  }).catch(err => {
    console.error('Clipboard copy failed:', err);
  });
}
 
// ─── Main send function ───────────────────────────────────────────────────────
async function sendPrompt() {
  const prompt = document.getElementById('prompt-input').value.trim();
  if (!prompt || isSending) return;
 
  const provider = document.getElementById('provider-select').value;
  isSending = true;
 
  // Show layout
  document.getElementById('main-layout').style.display = '';
 
  // Reset everything
  for (let i = 1; i <= 6; i++) {
    const card = document.getElementById('stage-' + i);
    if (card) {
      card.style.display = (i === 5) ? 'none' : '';
      card.className = 'stage-card';
    }
  }
  expandedStages = new Set();
  maskedPromptText = '';
  checkReset();
  metaReset();
  document.getElementById('timeline-card').style.display = 'none';
  document.getElementById('copy-masked-btn').style.display = 'none';
 
  // Disable button, show spinner
  const btn = document.getElementById('send-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Processing...';
 
  // Update status
  const st = document.getElementById('meta-status');
  st.className = 'status-pill status-idle';
  st.textContent = 'Sending…';
 
  checkActive('chk-received');
 
  const startTs = performance.now();
 
  try {
    // Determine endpoint
    let endpoint = '/openai/v1/chat/completions';
    let body;
    if (provider === 'anthropic') {
      endpoint = '/anthropic/v1/messages';
      body = JSON.stringify({
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 1024,
        stream: false,
        messages: [{ role: 'user', content: prompt }],
      });
    } else if (provider === 'gemini') {
      // Gemini via the OpenAI-compatible proxy endpoint
      endpoint = '/openai/v1/chat/completions';
      body = JSON.stringify({
        provider: 'gemini',
        model: 'gemini-2.5-flash',
        stream: false,
        messages: [{ role: 'user', content: prompt }],
      });
    } else {
      body = JSON.stringify({
        provider: provider,
        model: 'gpt-4o',
        stream: false,
        messages: [{ role: 'user', content: prompt }],
      });
    }
 
    checkDone('chk-received');
    checkActive('chk-secrets');
 
    const demoSecret = "${process.env.PROMPTWALL_DEMO_SECRET || ""}";
    const headers = {
      'Content-Type': 'application/json',
      '${DEMO_HEADER}': 'true',
    };
    if (demoSecret) {
      headers['${DEMO_SECRET_HEADER}'] = demoSecret;
    }
 
    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body,
    });
 
    const elapsed = Math.round(performance.now() - startTs);
    const data = await res.json();
 
    // ── If the response has a debug envelope ──
    const debug = data.debug;
    const response = data.response || data; // fallback if envelope not present
 
    // Update checklist with timing
    checkDone('chk-secrets', debug?.timings?.secretsMs ? (debug.timings.secretsMs + ' ms') : '');
    checkDone('chk-pii', debug?.timings?.piiMs ? (debug.timings.piiMs + ' ms') : '');
    checkDone('chk-merge');
    checkDone('chk-mask');
    checkDone('chk-policy');
    checkDone('chk-provider', debug?.timings?.providerMs ? (debug.timings.providerMs + ' ms') : '');
    checkDone('chk-restore', debug?.timings?.restoreMs ? (debug.timings.restoreMs + ' ms') : '');
    checkDone('chk-log');
 
    if (!res.ok) {
      st.className = 'status-pill status-error';
      st.textContent = 'Error ' + res.status;
      metaSet('resp', elapsed + ' ms', 'mono');
      // Try to show error message
      const errMsg = data?.error?.message || data?.error?.error?.message || JSON.stringify(data);
      document.getElementById('stage-6').style.display = '';
      revealStage(6, () => {
        document.getElementById('s6-content').innerHTML =
          '<div class="error-card">⚠ ' + esc(errMsg) + '</div>';
      });
      return;
    }
 
    st.className = 'status-pill status-ok';
    st.textContent = 'OK ' + res.status;
 
    // ── Sidebar metadata ──
    metaSet('provider', debug?.provider || provider, 'mono');
    metaSet('policy', debug?.policyDecision || '—',
      debug?.policyDecision === 'ALLOWED' ? 'green' : debug?.policyDecision === 'BLOCKED' ? 'red' : '');
    metaSet('masks', debug?.maskCount ?? '—', debug?.maskCount > 0 ? 'amber' : '');
    metaSet('pii', (debug?.piiEntities?.length ?? '—') + (debug?.piiEntities?.length === 1 ? ' type' : debug?.piiEntities?.length > 1 ? ' types' : ''), debug?.piiEntities?.length > 0 ? 'amber' : '');
    metaSet('secrets', (debug?.secretTypes?.length ?? '—') + (debug?.secretTypes?.length === 1 ? ' type' : debug?.secretTypes?.length > 1 ? ' types' : ''), debug?.secretTypes?.length > 0 ? 'red' : '');
    metaSet('scan', formatMs(debug?.scanTimeMs), 'mono');
    metaSet('resp', elapsed + ' ms', 'mono');
    const reqidEl = document.getElementById('meta-reqid');
    if (reqidEl) reqidEl.textContent = debug?.requestId || '—';
 
    // ── Timeline ──
    if (debug?.timings) {
      buildTimeline(debug.timings);
    }
 
    // ── Extract final response text ──
    let finalText = '';
    try {
      if (provider === 'anthropic') {
        const content = response.content || [];
        finalText = content.filter(b => b.type === 'text').map(b => b.text).join(String.fromCharCode(10));
      } else {
        // gemini and openai both return OpenAI-compatible chat completion format
        finalText = response.choices?.[0]?.message?.content || '';
        if (Array.isArray(finalText)) {
          finalText = finalText.filter(p => p.type === 'text').map(p => p.text).join(String.fromCharCode(10));
        }
      }
    } catch(_) { finalText = JSON.stringify(response, null, 2); }
 
    // ── Stage 1: Original prompt ──
    revealStage(1, () => {
      document.getElementById('s1-content').textContent = debug?.originalPrompt || prompt;
    });
 
    // ── Stage 2: PII ──
    await delay(200);
    revealStage(2, () => {
      const entities = debug?.piiEntities || [];
      const el = document.getElementById('s2-content');
      if (entities.length === 0) {
        el.innerHTML = '<span class="badge badge-none">No PII detected</span>';
      } else {
        el.innerHTML = entities.map(e =>
          '<span class="badge badge-pii">' + esc(e) + '</span>'
        ).join('');
      }
    });
 
    // ── Stage 3: Secrets ──
    await delay(200);
    revealStage(3, () => {
      const secrets = debug?.secretTypes || [];
      const el = document.getElementById('s3-content');
      if (secrets.length === 0) {
        el.innerHTML = '<span class="badge badge-none">No secrets detected</span>';
      } else {
        el.innerHTML = secrets.map(s =>
          '<span class="badge badge-secret">' + esc(s) + '</span>'
        ).join('');
      }
    });
 
    // ── Stage 4: Protected prompt ──
    await delay(200);
    revealStage(4, () => {
      const orig = debug?.originalPrompt || prompt;
      const masked = debug?.maskedPrompt || prompt;
      maskedPromptText = masked;
      const el = document.getElementById('s4-content');
      const hasMasking = orig !== masked;
      if (hasMasking) {
        el.innerHTML =
          '<div class="diff-before"><div class="diff-label">Original</div>' +
          '<div class="prompt-pre">' + esc(orig) + '</div></div>' +
          '<div style="color:var(--text-muted);font-size:0.8rem;padding:4px 0;">↓ protected by PromptWall</div>' +
          '<div class="diff-after"><div class="diff-label">Protected</div>' +
          '<div class="prompt-pre">' + highlightPlaceholders(masked) + '</div></div>';
        document.getElementById('copy-masked-btn').style.display = 'inline-flex';
      } else {
        el.innerHTML =
          '<div class="prompt-pre">' + esc(orig) + '</div>' +
          '<div style="margin-top:8px;color:var(--text-muted);font-size:0.75rem">No masking required – prompt contained no sensitive data.</div>';
      }
    });
 
    // ── Stage 5: Provider response (only if masking occurred) ──
    await delay(200);
    if (debug?.maskCount > 0) {
      revealStage(5, () => {
        // We show the final text here since we don't have the pre-restore response
        // — the backend restores placeholders before returning the envelope.
        // Instead, we note what was restored.
        const el = document.getElementById('s5-content');
        el.innerHTML =
          '<div style="color:var(--text-muted);font-size:0.75rem;margin-bottom:8px">Response received from provider. PromptWall restored ' +
          (debug?.maskCount || 0) + ' placeholder(s) before returning to client.</div>' +
          esc(finalText || '(empty response)');
      });
    } else {
      document.getElementById('stage-5').style.display = 'none';
    }
 
    // ── Stage 6: Final response ──
    await delay(200);
    revealStage(6, () => {
      const el = document.getElementById('s6-content');
      el.textContent = finalText || '(empty response)';
    });
 
  } catch (err) {
    const elapsed = Math.round(performance.now() - startTs);
    st.className = 'status-pill status-error';
    st.textContent = 'Error';
    metaSet('resp', elapsed + ' ms', 'mono');
    document.getElementById('stage-6').style.display = '';
    revealStage(6, () => {
      document.getElementById('s6-content').innerHTML =
        '<div class="error-card">⚠ ' + esc(err.message || 'Network error') + '</div>';
    });
  } finally {
    isSending = false;
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 2C5.5 2 4 3 4 3v6c0 3 2 5.5 4 6.5C10 14.5 12 12 12 9V3s-1.5-1-4-1z" stroke="white" stroke-width="1.5" fill="none" stroke-linecap="round"/><path d="M6 7h4M6 9.5h3" stroke="white" stroke-width="1.2" stroke-linecap="round"/></svg> Send Securely';
  }
}
 
// ─── Timeline builder ─────────────────────────────────────────────────────────
function buildTimeline(timings) {
  const card = document.getElementById('timeline-card');
  const tl = document.getElementById('timeline');
  if (!card || !tl) return;
 
  const steps = [
    { label: 'Secret Detection', time: timings.secretsMs },
    { label: 'PII (GLiNER)',     time: timings.piiMs },
    { label: 'Provider',        time: timings.providerMs },
    { label: 'Restoration',     time: timings.restoreMs },
  ].filter(s => s.time > 0);
 
  if (steps.length === 0) return;
 
  tl.innerHTML = steps.map((s, i) => {
    const connector = i < steps.length - 1
      ? '<div class="tl-line done"></div>'
      : '';
    return (
      '<div class="tl-row">' +
        '<div style="display:flex;flex-direction:column;align-items:center">' +
          '<div class="tl-dot done"></div>' +
          connector +
        '</div>' +
        '<div class="tl-content">' +
          '<span class="tl-label">' + esc(s.label) + '</span>' +
          '<span class="tl-time">' + formatMs(s.time) + '</span>' +
        '</div>' +
      '</div>'
    );
  }).join('');
 
  card.style.display = '';
}
 
// ─── Delay helper ─────────────────────────────────────────────────────────────
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
 
// ─── Event bindings ───────────────────────────────────────────────────────────
const textarea = document.getElementById('prompt-input');
const sendBtn  = document.getElementById('send-btn');
const counter  = document.getElementById('char-count');
 
textarea.addEventListener('input', () => {
  const len = textarea.value.length;
  counter.textContent = len;
  sendBtn.disabled = len === 0 || isSending;
});
 
textarea.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    if (!sendBtn.disabled) sendPrompt();
  }
});
 
sendBtn.addEventListener('click', sendPrompt);
 
// Bind stage headers dynamically
document.querySelectorAll('.stage-header').forEach(header => {
  header.addEventListener('click', () => {
    const stageNum = parseInt(header.getAttribute('data-stage'));
    toggleStage(stageNum);
  });
});
 
// Bind copy button dynamically
const copyBtn = document.getElementById('copy-masked-btn');
if (copyBtn) {
  copyBtn.addEventListener('click', copyMasked);
}
 
// Pre-fill demo prompt
const DEMO_PROMPT =
  "Hi, I'm Sarah Johnson (sarah.j@acme-corp.com, +1-555-867-5309). " +
  "Please review this config: OPENAI_API_KEY=" + ["sk", "proj", "abc123xyz789"].join("-") + " " +
  "and my AWS secret: " + ["AKIA", "IOSFODNN7EXAMPLE"].join("") + ". My credit card on file is 4111-1111-1111-1111.";
 
textarea.value = DEMO_PROMPT;
counter.textContent = DEMO_PROMPT.length;
sendBtn.disabled = false;
`,
					}}
				/>
			</body>
		</html>
	);
};

export default LandingPage;
