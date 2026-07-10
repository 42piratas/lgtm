import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import pc from "picocolors";
import type { AuditReport, RunnerResult, Severity } from "./types.js";
import { gradeFor } from "./scoring.js";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: pc.magenta,
  high: pc.red,
  medium: pc.yellow,
  low: pc.blue,
  info: pc.dim,
};

// Severity → 42labs DS status chip (light theme): subtle bg + border + emphasis
// text. The DS ships success/error/warning/info; severities map onto them.
const SEV_CHIP: Record<Severity, { bg: string; border: string; text: string }> = {
  critical: { bg: "#FEF2F2", border: "#FECACA", text: "#991B1B" },
  high: { bg: "#FEF2F2", border: "#FECACA", text: "#DC2626" },
  medium: { bg: "#FEFCE8", border: "#FEF08A", text: "#854D0E" },
  low: { bg: "#EFF6FF", border: "#BFDBFE", text: "#2563EB" },
  info: { bg: "#F0FDF4", border: "#DCFCE7", text: "#166534" },
};

// Letter grade → solid chip colour (DS palette).
const GRADE_HEX: Record<string, string> = {
  A: "#16A34A", // emerald
  B: "#2563EB", // info blue
  C: "#B7791F", // amber-dark
  D: "#CC5D0A", // copper-dark
  F: "#DC2626", // red
  "—": "#B8AFA8", // mid-stone
  "?": "#B8AFA8",
};

/** Write JSON + HTML artifacts; return their paths. */
export function writeReports(report: AuditReport): { json: string; html: string } {
  const dir = reportDir(report);
  mkdirSync(dir, { recursive: true });
  const base = `${report.site}-${report.stamp}`;
  const jsonPath = join(dir, `${base}.json`);
  const htmlPath = join(dir, `${base}.html`);
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  writeFileSync(htmlPath, renderHtml(report));
  return { json: jsonPath, html: htmlPath };
}

function reportDir(report: AuditReport): string {
  return join(process.cwd(), "reports", report.site);
}

/** Console summary printed at the end of a run. */
export function consoleSummary(report: AuditReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(pc.bold(`  lgtm — ${report.site}  ${pc.dim(report.baseUrl)}`));
  lines.push(pc.dim(`  ${report.stamp}  ·  ${report.isLocalhost ? "localhost" : "remote"}${report.allowActive ? " · active" : ""}`));
  lines.push("");
  lines.push(pc.dim("  domain          grade  issues"));
  for (const r of report.results) {
    const n = r.findings.filter((f) => f.severity !== "info").length;
    const grade = gradeFor(r);
    const gcol =
      grade === "A" ? pc.green : grade === "F" || grade === "D" ? pc.red : grade === "—" || grade === "?" ? pc.dim : pc.yellow;
    const detail =
      r.status === "error"
        ? pc.red(`error${r.note ? ` — ${r.note}` : ""}`)
        : r.status === "skipped"
          ? pc.dim(`skipped${r.note ? ` — ${r.note}` : ""}`)
          : n > 0
            ? sevBreakdown(r)
            : pc.green("clean");
    lines.push(`  ${r.runnerId.padEnd(14)}  ${gcol(grade.padEnd(5))}  ${detail}`);
  }
  lines.push("");
  const t = report.totals;
  lines.push(
    `  totals: ${SEV_COLOR.critical(`${t.critical} critical`)} · ${SEV_COLOR.high(`${t.high} high`)} · ${SEV_COLOR.medium(`${t.medium} medium`)} · ${SEV_COLOR.low(`${t.low} low`)}`,
  );
  lines.push(
    report.passed
      ? pc.green(`  PASS `) + pc.dim(`(no findings ≥ ${report.failOn})`)
      : pc.red(`  FAIL `) + pc.dim(`(findings ≥ ${report.failOn} threshold)`),
  );
  lines.push("");
  return lines.join("\n");
}

function sevBreakdown(r: RunnerResult): string {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of r.findings) c[f.severity]++;
  const parts: string[] = [];
  (["critical", "high", "medium", "low"] as Severity[]).forEach((s) => {
    if (c[s]) parts.push(SEV_COLOR[s](`${c[s]}${s[0]}`));
  });
  return parts.join(" ");
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
}

// 42labs family favicon (the "42" star, icon.svg), embedded so reports stay
// self-contained — same mark used across every 42labs property.
const FAVICON =
  "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+Cjxzdmcgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgdmlld0JveD0iMCAwIDQwNyA0MDIiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIgeG1sbnM6c2VyaWY9Imh0dHA6Ly93d3cuc2VyaWYuY29tLyIgc3R5bGU9ImZpbGwtcnVsZTpldmVub2RkO2NsaXAtcnVsZTpldmVub2RkO3N0cm9rZS1saW5lam9pbjpyb3VuZDtzdHJva2UtbWl0ZXJsaW1pdDoyOyI+PHN0eWxlPnBhdGh7ZmlsbDojMDAwfUBtZWRpYSAocHJlZmVycy1jb2xvci1zY2hlbWU6ZGFyayl7cGF0aHtmaWxsOiNmZmZ9fTwvc3R5bGU+CiAgICA8ZyB0cmFuc2Zvcm09Im1hdHJpeCgxLDAsMCwxLC0xNjQ1LjgxLC02OTUuNDQyKSI+CiAgICAgICAgPGcgdHJhbnNmb3JtPSJtYXRyaXgoMSwwLDAsMSwxNjExLjY4LDY2Ni45MDgpIj4KICAgICAgICAgICAgPHBhdGggZD0iTTMwNy43MTksMjguNTM0TDM3Ni41MzYsNjcuNjk4TDI2Ny45OTUsMjEzLjE2NUw0NDAuODc3LDE5MC4yMjZMNDQwLjg3NywyNjcuOTk1TDI2Ny45OTUsMjQ3LjI5NEwyNjcuOTk1LDI0OS41MzJMMzc3LjY1NSwzODguMjg1TDMwNS40ODEsNDI4LjU2OUwyMzYuNjY0LDI2Ny45OTVMMjM0LjQyNiwyNjcuOTk1TDE2MC4wMTQsNDI5LjY4OEw5NS4xMTMsMzg4LjI4NUwyMDMuNjU0LDI0Ni4xNzVMMzQuMTI5LDI2Ny45OTVMMzQuMTI5LDE5MC4yMjZMMjAyLjUzNSwyMTIuMDQ2TDIwMi41MzUsMjA5LjgwOEw5NS4xMTMsNjguODE3TDE2NC40OSwyOS42NTNMMjM1LjU0NSwxODkuMTA3TDIzOC4zNDIsMTg5LjEwN0wzMDcuNzE5LDI4LjUzNFoiLz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPgo=";

function realCount(r: RunnerResult): number {
  return r.findings.filter((f) => f.severity !== "info").length;
}

// ── 42labs Design System — light theme HTML report ───────────────────────────

function renderMasthead(report: AuditReport): string {
  const mode = `${report.isLocalhost ? "localhost" : "remote"}${report.allowActive ? " · active scan" : ""}`;
  const ran = report.results.filter((r) => r.status !== "skipped").length;
  return `<div class="pagehead">
    <div class="eyebrow">lgtm · ${esc(report.site)} · ${mode}</div>
    <h1>${esc(report.label ?? report.site)} — security &amp; quality audit</h1>
    <p class="sub">${esc(report.baseUrl)}</p>
    <p class="meta">${esc(report.stamp)} · ${ran} runner${ran === 1 ? "" : "s"} · threshold ≥ ${report.failOn} · finished ${esc(report.finishedAt)}</p>
  </div>`;
}

function renderVerdict(report: AuditReport): string {
  const t = report.totals;
  const atOrAbove = countAtOrAbove(report);
  const cls = report.passed ? "pass" : "fail";
  const text = report.passed
    ? `PASS — no findings at or above <b>${report.failOn}</b>`
    : `FAIL — ${atOrAbove} finding${atOrAbove === 1 ? "" : "s"} at or above <b>${report.failOn}</b>`;
  return `<div class="verdict ${cls}"><span class="badge ${cls}">${report.passed ? "PASS" : "FAIL"}</span> ${text}
    <span class="vsum">${t.critical + t.high} high-severity · ${t.medium} medium · ${t.low} low</span></div>`;
}

function renderKpis(report: AuditReport): string {
  const t = report.totals;
  const tiles: Array<{ label: string; value: number; sev: Severity }> = [
    { label: "Critical", value: t.critical, sev: "critical" },
    { label: "High", value: t.high, sev: "high" },
    { label: "Medium", value: t.medium, sev: "medium" },
    { label: "Low", value: t.low, sev: "low" },
  ];
  const cells = tiles
    .map(
      (k) =>
        `<div class="kpi"><div class="l">${k.label}</div><div class="v" style="color:${k.value > 0 ? SEV_CHIP[k.sev].text : "var(--fg-muted)"}">${k.value}</div></div>`,
    )
    .join("");
  return `<div class="kpis">${cells}</div>`;
}

function renderOverview(report: AuditReport): string {
  const rows = report.results
    .map((r) => {
      const grade = gradeFor(r);
      const n = realCount(r);
      const status =
        r.status === "error"
          ? `<span class="tag err">error</span>`
          : r.status === "skipped"
            ? `<span class="tag muted">skipped</span>`
            : n > 0
              ? `<span class="tag warn">${n} finding${n === 1 ? "" : "s"}</span>`
              : `<span class="tag ok">clean</span>`;
      return `<tr>
        <td class="lbl"><a href="#r-${esc(r.runnerId)}">${esc(r.runnerId)}</a></td>
        <td>${esc(r.domain)}</td>
        <td><span class="grade" style="background:${GRADE_HEX[grade] ?? "#B8AFA8"}">${grade}</span></td>
        <td>${status}</td>
        <td class="num">${r.durationMs ? `${r.durationMs}ms` : "—"}</td>
      </tr>`;
    })
    .join("");
  return `<div class="secttl"><span class="n">00</span> Overview</div>
  <div class="card"><table class="overview">
    <thead><tr><th>runner</th><th>domain</th><th>grade</th><th>result</th><th class="num">time</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function renderRunnerSection(r: RunnerResult, index: number): string {
  const issues = r.findings.filter((f) => f.severity !== "info");
  const num = String(index + 1).padStart(2, "0");
  const grade = gradeFor(r);

  let body: string;
  if (r.status === "skipped") {
    body = `<p class="empty">Skipped${r.note ? ` — ${esc(r.note)}` : ""}.</p>`;
  } else if (r.status === "error") {
    body = `<p class="empty err">Errored${r.note ? ` — ${esc(r.note)}` : ""}.</p>`;
  } else if (issues.length === 0) {
    body = `<p class="empty ok">Clean${r.note ? ` — ${esc(r.note)}` : " — no findings"}.</p>`;
  } else {
    const rows = issues
      .map(
        (f) => `<tr>
        <td><span class="chip" style="background:${SEV_CHIP[f.severity].bg};border-color:${SEV_CHIP[f.severity].border};color:${SEV_CHIP[f.severity].text}">${f.severity}</span></td>
        <td class="find">${esc(f.title)}${f.standard ? `<div class="std">${esc(f.standard)}</div>` : ""}</td>
        <td class="loc">${f.location ? esc(f.location) : ""}</td>
        <td class="rem">${f.remediation ? esc(f.remediation) : ""}</td>
      </tr>`,
      )
      .join("");
    body = `<table class="findings">
      <thead><tr><th>severity</th><th>finding</th><th>location</th><th>remediation</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }

  return `<div class="secttl" id="r-${esc(r.runnerId)}"><span class="n">${num}</span> ${esc(r.runnerId)}
    <span class="grade sm" style="background:${GRADE_HEX[grade] ?? "#B8AFA8"}">${grade}</span>
    <span class="dm">${esc(r.domain)}${r.durationMs ? ` · ${r.durationMs}ms` : ""}</span></div>
  <div class="card">${body}</div>`;
}

function countAtOrAbove(report: AuditReport): number {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const idx = order.indexOf(report.failOn);
  return order
    .slice(0, idx + 1)
    .reduce((sum, s) => sum + report.totals[s], 0);
}

function renderHtml(report: AuditReport): string {
  const sections = report.results.map((r, i) => renderRunnerSection(r, i)).join("\n");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lgtm — ${esc(report.site)} — ${esc(report.stamp)}</title>
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Sans:wght@300;400;500;600&family=Geist+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
  /* 42labs Design System — light theme (semantic tokens) */
  :root{
    --bg:#FDFAF5;--surface:#FFFFFF;--surface-muted:#FEF3E2;--border:#E8E3DD;
    --fg:#1C1917;--fg-2:#433E3A;--fg-muted:#756D68;
    --accent:#E2711D;--accent-2:#CC5D0A;--accent-ink:#B45309;
    --r:14px;
    --font-head:'Space Grotesk',system-ui,sans-serif;
    --font-body:'IBM Plex Sans',system-ui,sans-serif;
    --font-mono:'Geist Mono',ui-monospace,monospace;
    color-scheme:light;
  }
  *{box-sizing:border-box}html,body{margin:0}
  body{background:var(--bg);color:var(--fg);font-family:var(--font-body);font-weight:300;
    font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;padding:40px 24px}
  .wrap{max-width:1080px;margin:0 auto}
  a{color:var(--accent-ink);text-decoration:none}a:hover{text-decoration:underline}

  .pagehead{padding:0 2px 14px;margin-bottom:16px;border-bottom:2px solid var(--fg)}
  .eyebrow{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent-2);font-weight:600}
  h1{font-family:var(--font-head);font-size:26px;font-weight:700;letter-spacing:-.01em;margin:7px 0 4px}
  .sub{font-size:13px;color:var(--fg-muted);margin:0;font-family:var(--font-mono)}
  .meta{font-family:var(--font-mono);font-size:11px;color:var(--fg-muted);margin-top:8px}

  .verdict{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:14px;color:var(--fg);
    background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);
    border-radius:8px;padding:12px 15px;margin:16px 0}
  .verdict.pass{border-left-color:#16A34A}.verdict.fail{border-left-color:#DC2626}
  .badge{font-family:var(--font-mono);font-weight:600;font-size:12px;letter-spacing:.06em;
    padding:3px 10px;border-radius:999px;color:#fff}
  .badge.pass{background:#16A34A}.badge.fail{background:#DC2626}
  .verdict b{font-weight:600}
  .vsum{font-family:var(--font-mono);font-size:11.5px;color:var(--fg-muted);margin-left:auto}

  .kpis{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 4px}
  .kpi{flex:1;min-width:120px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:11px 13px}
  .kpi .l{font-family:var(--font-mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--fg-muted)}
  .kpi .v{font-family:var(--font-head);font-size:24px;font-weight:700;margin-top:4px;font-variant-numeric:tabular-nums}

  .secttl{font-family:var(--font-head);font-size:14px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
    margin:28px 2px 6px;display:flex;align-items:center;gap:10px;scroll-margin-top:12px}
  .secttl .n{font-family:var(--font-mono);color:var(--accent);font-size:13px}
  .secttl .dm{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:0;
    text-transform:none;color:var(--fg-muted);margin-left:auto}

  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:6px 4px;
    box-shadow:0 1px 2px rgba(28,25,23,.04)}
  .empty{font-size:13px;color:var(--fg-muted);padding:14px 14px;margin:0;font-family:var(--font-mono)}
  .empty.ok{color:#166534}.empty.err{color:#991B1B}

  table{width:100%;border-collapse:collapse;font-size:12.5px}
  thead th{font-family:var(--font-mono);color:var(--accent-2);font-weight:600;font-size:9.5px;letter-spacing:.05em;
    text-transform:uppercase;text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);white-space:nowrap}
  tbody td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--fg-2)}
  tbody tr:last-child td{border-bottom:0}
  tbody tr:nth-child(even) td{background:#FCFBF9}
  .num{text-align:right;font-family:var(--font-mono);font-variant-numeric:tabular-nums}
  thead th.num{text-align:right}

  .overview .lbl a{font-family:var(--font-mono);font-weight:600;color:var(--fg)}
  .grade{display:inline-flex;width:22px;height:22px;align-items:center;justify-content:center;border-radius:6px;
    color:#fff;font-family:var(--font-head);font-weight:700;font-size:12px}
  .grade.sm{width:19px;height:19px;font-size:11px}
  .tag{font-family:var(--font-mono);font-size:11px;padding:2px 9px;border-radius:999px}
  .tag.ok{background:#F0FDF4;color:#166534}.tag.warn{background:#FEFCE8;color:#854D0E}
  .tag.err{background:#FEF2F2;color:#991B1B}.tag.muted{background:#F5F5F4;color:#756D68}

  .findings .chip{font-family:var(--font-mono);font-size:10px;text-transform:uppercase;letter-spacing:.04em;
    padding:2px 8px;border-radius:999px;border:1px solid;white-space:nowrap;font-weight:600}
  .find{font-family:var(--font-body);font-weight:400;color:var(--fg);max-width:360px}
  .std{font-family:var(--font-mono);color:var(--fg-muted);font-size:10.5px;margin-top:4px}
  .loc{font-family:var(--font-mono);font-size:11px;color:var(--fg-muted);word-break:break-all;max-width:240px}
  .rem{color:var(--fg-muted);max-width:300px}

  .foot{margin-top:26px;padding-top:12px;border-top:1px solid var(--border);font-size:11px;
    color:var(--fg-muted);font-family:var(--font-mono)}

  @page{size:A4 portrait;margin:12mm 11mm}
  @media print{html,body{background:#fff}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    body{padding:0;font-size:11px}.wrap{max-width:none}
    .card,.secttl,.kpi,table{break-inside:avoid;page-break-inside:avoid}.secttl{break-after:avoid}}
</style></head><body><div class="wrap">
  ${renderMasthead(report)}
  ${renderVerdict(report)}
  ${renderKpis(report)}
  ${renderOverview(report)}
  ${sections}
  <p class="foot">Generated by lgtm · ${esc(report.startedAt)} → ${esc(report.finishedAt)} · report follows the 42labs Design System</p>
</div></body></html>`;
}
