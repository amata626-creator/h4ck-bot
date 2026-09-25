/* H4CK-B0T frontend.
 *
 * Wires index.html to the FastAPI backend in backend/api/main.py.
 * Served from the same origin, so API_BASE is empty and all paths are
 * relative - no CORS, no config, no build step.
 *
 * Flow:
 *   1. On load, POST /api/assessments/run with a target.
 *   2. Poll /status every 1.5s while the run is "running".
 *   3. Poll /findings every 1.5s, re-render the table.
 *   4. Click a row -> fetch /findings/{id}, populate the detail panel.
 */

const API_BASE = "";                     // same-origin
const POLL_MS = 1500;
const DEFAULT_TARGET = "scanme.nmap.org";
const DEFAULT_MODULES = ["discovery", "misconfig", "web_api"];

// ── State ───────────────────────────────────────────────────────────
let assessmentId = null;
let findings = [];
let selectedFindingId = null;
let statusPoll = null;
let findingsPoll = null;

// ── Helpers ─────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function sevClass(sev) {
  const s = (sev || "").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(s) ? s : "low";
}

function statusClass(status) {
  const s = (status || "").toLowerCase();
  if (s === "validated") return "validated";
  if (s === "false_positive") return "false-positive";
  return "potential";
}

function statusLabel(status) {
  return {
    validated: "Validated",
    potential: "Potential",
    needs_review: "Needs review",
    false_positive: "False positive",
  }[status] || status;
}

// ── API ─────────────────────────────────────────────────────────────
async function startAssessment(target, modules, llmModel) {
  // /api/assessments/run is gated by the same admin token as the
  // proposal endpoints. The token is read from sessionStorage (set
  // when the user pastes it in the Propose form). If it's missing,
  // the server will return 401 and the caller will surface a
  // "paste your token" message.
  const token = sessionStorage.getItem("h4ck_admin_token") || "";
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const resp = await fetch(`${API_BASE}/api/assessments/run`, {
    method: "POST",
    headers,
    body: JSON.stringify({ target, modules, llm_model: llmModel }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`start failed: ${resp.status} ${text}`);
  }
  const { assessment_id } = await resp.json();
  return assessment_id;
}

async function getStatus(id) {
  const resp = await fetch(`${API_BASE}/api/assessments/${id}/status`);
  if (!resp.ok) throw new Error(`status ${resp.status}`);
  return resp.json();
}

async function getFindings(id) {
  const resp = await fetch(`${API_BASE}/api/assessments/${id}/findings`);
  if (!resp.ok) throw new Error(`findings ${resp.status}`);
  return resp.json();
}

async function getFinding(id, findingId) {
  const resp = await fetch(`${API_BASE}/api/assessments/${id}/findings/${findingId}`);
  if (!resp.ok) throw new Error(`finding ${resp.status}`);
  return resp.json();
}

// ── Rendering ───────────────────────────────────────────────────────
function renderStats() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, validated: 0, total: findings.length };
  for (const f of findings) {
    const sev = (f.severity || f.cvss?.severity || "").toLowerCase();
    if (sev in counts) counts[sev]++;
    if ((f.status || "").toLowerCase() === "validated") counts.validated++;
  }
  const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setText("stat-critical", counts.critical);
  setText("stat-high", counts.high);
  setText("stat-medium", counts.medium);
  setText("stat-validated", counts.validated);
  setText("stat-total", counts.total);
}

function renderFindingsTable() {
  const tbody = $("#findings-tbody");
  if (!tbody) return;

  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--text-3); padding:16px; text-align:center">
      No findings yet. Assessment ${assessmentId ? "running" : "not started"}.
    </td></tr>`;
    return;
  }

  tbody.innerHTML = findings.map((f) => {
    const sev = (f.severity || f.cvss?.severity || (function(s){
      if (s >= 9.0) return "critical";
      if (s >= 7.0) return "high";
      if (s >= 4.0) return "medium";
      if (s > 0.0)  return "low";
      return "info";
    })(f.cvss?.base_score ?? 0)).toLowerCase();
    const selected = f.finding_id === selectedFindingId ? " selected-row" : "";
    const phase = f.kill_chain_phase || "";
    return `
      <tr class="${selected}" data-finding-id="${escapeHtml(f.finding_id)}">
        <td>
          <div class="finding-title">${escapeHtml(f.title)}</div>
          <div class="finding-asset mono">${escapeHtml(f.asset?.name || "")}</div>
        </td>
        <td><span class="sev-pill ${sevClass(sev)}">${escapeHtml(sev.charAt(0).toUpperCase() + sev.slice(1))}</span></td>
        <td><span class="cvss-badge mono" style="color:var(--${sev === "info" ? "low" : sev})">${f.cvss?.base_score > 0 ? escapeHtml(String(f.cvss.base_score)) : "&mdash;"}</span></td>
        <td><span class="status-tag ${statusClass(f.status)}"><span class="sdot"></span>${escapeHtml(statusLabel(f.status))}</span></td>
        <td>${phase ? `<span class="kc-tag">${escapeHtml(phase.replace(/_/g, " "))}</span>` : ""}</td>
      </tr>`;
  }).join("");

  for (const row of tbody.querySelectorAll("tr[data-finding-id]")) {
    row.addEventListener("click", () => selectFinding(row.dataset.findingId));
  }
}

function renderDetail(f) {
  const panel = $("#detail-panel");
  if (!panel) return;
  if (!f) {
    panel.innerHTML = `<div style="color:var(--text-3); padding:20px; font-size:12px">
      Select a finding to view details.
    </div>`;
    return;
  }

  const sev = (f.severity || f.cvss?.severity || (function(s){
      if (s >= 9.0) return "critical";
      if (s >= 7.0) return "high";
      if (s >= 4.0) return "medium";
      if (s > 0.0)  return "low";
      return "info";
    })(f.cvss?.base_score ?? 0)).toLowerCase();
  const validation = f.validation || {};
  const layers = validation.layers || [];
  const applicable = layers.filter((l) => l.applicable !== false);
  const passed = applicable.filter((l) => l.passed).length;
  const conf = applicable.length
    ? Math.round((applicable.reduce((a, l) => a + (l.confidence || 0), 0) / applicable.length) * 100)
    : 0;

  const evidenceHtml = (f.evidence || []).map((e) => `
    <div class="evidence-shot">
      <div class="shot-canvas">${escapeHtml(e.evidence_type)} &middot; ${escapeHtml(e.description || "")}</div>
      <div class="shot-cap">
        <span>${escapeHtml((e.captured_at || "").slice(0, 19).replace("T", " "))} UTC</span>
        <span class="mono">sha256: ${escapeHtml((e.content_hash || "").slice(0, 8))}...</span>
      </div>
    </div>`).join("") || `<div style="color:var(--text-3); font-size:11.5px">No evidence attached.</div>`;

  const layersHtml = layers.map((l) => {
    const applicableFlag = l.applicable !== false;
    const icon = applicableFlag && l.passed ? "&#10003;" : (applicableFlag ? "&#10007;" : "&middot;");
    const statusText = applicableFlag
      ? `${l.passed ? "confirmed" : "failed"} (${Math.round((l.confidence || 0) * 100)}%)`
      : "not applicable";
    return `<div class="layer-item">
      <i>${icon}</i>
      <span class="layer-name">${escapeHtml(l.layer_name)}</span>
      <span class="layer-status">${escapeHtml(statusText)}</span>
    </div>`;
  }).join("");

  panel.innerHTML = `
    <div class="detail-top">
      <div>
        <div class="detail-title">${escapeHtml(f.title)}</div>
        <div class="detail-id mono">${escapeHtml(f.finding_id)} &middot; ${escapeHtml(f.asset?.name || "")}</div>
      </div>
      <span class="sev-pill ${sevClass(sev)}">${escapeHtml(sev.charAt(0).toUpperCase() + sev.slice(1))}</span>
    </div>

    <div class="detail-meta">
      <div class="meta-cell"><div class="l">CVSS</div><div class="v mono" style="color:var(--${sev === "info" ? "low" : sev})">${escapeHtml(f.cvss?.base_score ?? "")}</div></div>
      <div class="meta-cell"><div class="l">CWE</div><div class="v mono">${escapeHtml(f.cwe?.cwe_id || "")}</div></div>
      <div class="meta-cell"><div class="l">Source</div><div class="v mono">${escapeHtml(f.module_source || "")}</div></div>
      <div class="meta-cell"><div class="l">Status</div><div class="v">${escapeHtml(statusLabel(f.status))}</div></div>
    </div>

    <div class="section-label">Description</div>
    <div style="font-size:12px; color:var(--text-2); line-height:1.6">${escapeHtml(f.description || "")}</div>

    ${f.remediation ? `<div class="section-label">Remediation</div><div style="font-size:12px; color:var(--text-2); line-height:1.6">${escapeHtml(f.remediation)}</div>` : ""}

    <div class="section-label">Validation confidence</div>
    <div style="display:flex; align-items:baseline; justify-content:space-between;">
      <span style="font-size:12px; color:var(--text-2)">${passed} of ${applicable.length} applicable layers confirmed</span>
      <span class="mono" style="font-size:12px; color:var(--validated); font-weight:500">${conf}%</span>
    </div>
    <div class="confidence-bar-track"><div class="confidence-bar-fill" style="width:${conf}%"></div></div>

    <div class="section-label">Evidence</div>
    ${evidenceHtml}

    <div class="section-label">Validation layers</div>
    <div class="layers-list">${layersHtml}</div>
  `;
}

function selectFinding(findingId) {
  selectedFindingId = findingId;
  const f = findings.find((x) => x.finding_id === findingId);
  renderFindingsTable();
  renderDetail(f);
}

// ── Polling ─────────────────────────────────────────────────────────
function startPolling() {
  stopPolling();
  statusPoll = setInterval(async () => {
    try {
      const s = await getStatus(assessmentId);
      updateRunBadge(s.status, s.finding_count);
      if (s.status !== "running") {
        stopPolling();
        updateRunBadge(s.status === "complete" ? "complete" : "error", s.finding_count);
      }
    } catch (e) { console.warn("status poll failed", e); }
  }, POLL_MS);

  findingsPoll = setInterval(async () => {
    try {
      findings = await getFindings(assessmentId);
      renderStats();
      renderFindingsTable();
      if (selectedFindingId) {
        const f = findings.find((x) => x.finding_id === selectedFindingId);
        if (f) renderDetail(f);
      }
    } catch (e) { console.warn("findings poll failed", e); }
  }, POLL_MS);
}

function stopPolling() {
  if (statusPoll) { clearInterval(statusPoll); statusPoll = null; }
  if (findingsPoll) { clearInterval(findingsPoll); findingsPoll = null; }
}

function updateRunBadge(status, count) {
  const badge = $("#run-badge");
  if (!badge) return;
  let label, color;
  if (status === "running") {
    label = `Assessment running &middot; ${count} finding${count === 1 ? "" : "s"}`;
    color = "var(--validated)";
  } else if (status === "complete") {
    label = `Complete &middot; ${count} finding${count === 1 ? "" : "s"}`;
    color = "var(--text-3)";
  } else if (status === "error") {
    label = "Error";
    color = "var(--crit)";
  } else {
    label = "Idle";
    color = "var(--text-3)";
  }
  badge.innerHTML = `<span class="pulse" style="background:${color}"></span>${label}`;
}

// ── Scope + bootstrap ───────────────────────────────────────────────
async function getScope() {
  const resp = await fetch(`${API_BASE}/api/scope`);
  if (!resp.ok) throw new Error(`scope ${resp.status}`);
  return resp.json();
}

function populateTargetDropdown(scope) {
  const sel = $("#target-select");
  if (!sel) return;
  sel.innerHTML = scope.targets.map((t) =>
    `<option value="${escapeHtml(t.host)}">${escapeHtml(t.host)} — ${escapeHtml(t.note || "")}</option>`
  ).join("");
  // Show the authorization context next to the dropdown
  const authEl = $("#scope-auth");
  if (authEl) {
    authEl.textContent = scope.authorized_by
      ? `Authorized by: ${scope.authorized_by} (${scope.authorization_ref})`
      : "No scope loaded — see scope.yaml";
  }
}

// ── Scope proposals (Option 1: propose-only, admin promotes) ───────
function adminToken() {
  return sessionStorage.getItem("h4ck_admin_token") || "";
}

async function proposeTarget(host, note, authRef, activeTesting, destructive) {
  const token = adminToken();
  if (!token) throw new Error("admin token required - enter it above");
  const resp = await fetch(`${API_BASE}/api/scope/propose`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({
      host,
      note,
      authorization_ref: authRef,
      permitted_techniques: activeTesting
        ? ["passive_recon", "port_scan", "misconfig_check", "api_testing"]
        : ["passive_recon", "port_scan", "misconfig_check"],
      active_testing_permitted: activeTesting,
      destructive_actions_allowed: destructive,
    }),
  });
  if (!resp.ok) {
    let detail = `${resp.status}`;
    try { detail = (await resp.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  return resp.json();
}

async function listProposals() {
  const token = adminToken();
  if (!token) return null;
  const resp = await fetch(`${API_BASE}/api/scope/proposed`, {
    headers: { "Authorization": `Bearer ${token}` },
  });
  if (resp.status === 401) return { unauthorized: true, items: [] };
  if (!resp.ok) throw new Error(`${resp.status}`);
  return { unauthorized: false, items: await resp.json() };
}

function renderProposals(result) {
  const el = $("#proposals-list");
  if (!el) return;
  if (result === null) {
    el.innerHTML = "Enter admin token above to view pending proposals.";
    return;
  }
  if (result.unauthorized) {
    el.innerHTML = '<span style="color:var(--crit)">Token rejected by server.</span>';
    return;
  }
  if (!result.items.length) {
    el.innerHTML = "No pending proposals.";
    return;
  }
  el.innerHTML = result.items.map((p) => `
    <div style="border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px; color:var(--text-2);">
      <div style="font-family:'JetBrains Mono',monospace; color:var(--text-1);">${escapeHtml(p.host)}</div>
      <div style="font-size:11px; margin-top:3px;">${escapeHtml(p.note || "")}</div>
      <div style="font-size:11px; color:var(--text-3); margin-top:3px;">ref: ${escapeHtml(p.authorization_ref)} &middot; from ${escapeHtml(p.proposed_from_ip)}</div>
      <div style="font-size:10.5px; color:var(--text-3); margin-top:5px;">id: ${escapeHtml(p.proposal_id)}</div>
    </div>`).join("");
}

function wireProposalForm() {
  const toggle = $("#toggle-propose");
  const form = $("#propose-form");
  if (toggle && form) {
    toggle.addEventListener("click", () => {
      const open = form.style.display !== "none";
      form.style.display = open ? "none" : "block";
      toggle.textContent = open ? "Show" : "Hide";
    });
  }

  const tokenInput = $("#admin-token");
  if (tokenInput) {
    tokenInput.value = adminToken();
    tokenInput.addEventListener("change", async () => {
      sessionStorage.setItem("h4ck_admin_token", tokenInput.value);
      const result = await listProposals().catch(() => null);
      renderProposals(result);
    });
  }

  const submit = $("#submit-proposal");
  if (submit) {
    submit.addEventListener("click", async () => {
      const host = ($("#propose-host")?.value || "").trim();
      const note = ($("#propose-note")?.value || "").trim();
      const ref  = ($("#propose-ref")?.value || "").trim();
      const active = !!$("#propose-active")?.checked;
      const destructive = !!$("#propose-destructive")?.checked;
      const result = $("#propose-result");
      if (!host || !ref) {
        if (result) result.innerHTML = '<span style="color:var(--crit)">host and authorization reference are required</span>';
        return;
      }
      try {
        const r = await proposeTarget(host, note, ref, active, destructive);
        if (result) result.innerHTML = `<span style="color:var(--validated)">Proposed: ${escapeHtml(r.host)} (id ${escapeHtml(r.proposal_id.slice(0,8))}...)</span>`;
        const list = await listProposals().catch(() => null);
        renderProposals(list);
      } catch (e) {
        if (result) result.innerHTML = `<span style="color:var(--crit)">${escapeHtml(e.message)}</span>`;
      }
    });
  }

  const refresh = $("#refresh-proposals");
  if (refresh) {
    refresh.addEventListener("click", async () => {
      const list = await listProposals().catch(() => null);
      renderProposals(list);
    });
  }
}

async function boot() {
  renderDetail(null);
  renderFindingsTable();
  updateRunBadge("idle", 0);

  // Load scope for the summary line + the modal. Read-only.
  let scope = { targets: [], authorized_by: "", authorization_ref: "" };
  try {
    scope = await getScope();
    renderScopeSummary(scope);
  } catch (e) {
    const el = $("#scope-summary");
    if (el) el.textContent = `scope unavailable: ${e.message}`;
  }

  // Wire the View report button. It's enabled once an assessment
  // exists (checked in startPolling's status handler).
  const reportBtn = $("#view-report");
  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      if (!assessmentId) {
        alert("No assessment yet. Run a scan first.");
        return;
      }
      window.open(`${API_BASE}/api/assessments/${assessmentId}/report.html`, "_blank");
    });
  }

  // Wire both the topbar "Start scan" button and the header one.
  for (const id of ["start-scan", "start-scan-header"]) {
    const btn = document.getElementById(id);
    if (!btn) continue;
    btn.addEventListener("click", () => startScanFromForm());
  }

  // Enter in the target field also starts a scan.
  const targetInput = $("#target-input");
  if (targetInput) {
    targetInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") startScanFromForm();
    });
  }

  // Scope modal open/close.
  const showScope = $("#show-scope");
  if (showScope) showScope.addEventListener("click", async () => {
    renderScopeModal(scope);
    const list = await listProposals().catch(() => null);
    renderProposals(list);
  });
  const closeScope = $("#close-scope");
  if (closeScope) closeScope.addEventListener("click", () => {
    const m = $("#scope-modal"); if (m) m.style.display = "none";
  });
  const modal = $("#scope-modal");
  if (modal) modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.style.display = "none";
  });

  wireProposalForm();
}

async function startScanFromForm() {
  const target = ($("#target-input")?.value || "").trim();
  const llmModel = ($("#llm-model")?.value || "llama3.1").trim() || "llama3.1";

  if (!target) {
    alert("Enter a target hostname or IP.");
    $("#target-input")?.focus();
    return;
  }

  try {
    updateRunBadge("running", 0);
    const rpt = $("#view-report"); if (rpt) rpt.disabled = false;
    assessmentId = await startAssessment(target, DEFAULT_MODULES, llmModel);
    findings = [];
    selectedFindingId = null;
    renderStats();
    renderFindingsTable();
    startPolling();
  } catch (e) {
    // 403 => not in scope. Say so clearly, don't pretend it started.
    const msg = e.message || String(e);
    if (msg.includes("401") || msg.toLowerCase().includes("admin token")) {
      alert(
        `Admin token required.\n\n` +
        `Open "Authorized scope" and paste the token from ` +
        `/home/ubuntu/h4ck-bot/.env (the H4CK_BOT_ADMIN_TOKEN value) ` +
        `into the "Admin token" field, then try again.`
      );
      updateRunBadge("error", 0);
      return;
    }
    if (msg.includes("403")) {
      alert(
        `Target not authorized: ${target}\n\n` +
        `The server only scans targets listed in scope.yaml. ` +
        `Authorized targets: ${(window.__scope_targets || []).join(", ") || "(none loaded)"}.\n\n` +
        `To add one: edit scope.yaml on the server, then restart the API.`
      );
    } else {
      alert(`Failed to start scan: ${msg}`);
    }
    updateRunBadge("error", 0);
  }
}

function renderScopeSummary(scope) {
  window.__scope_targets = scope.targets.map((t) => t.host);
  const el = $("#scope-summary");
  if (!el) return;
  const n = scope.targets.length;
  el.textContent = n
    ? `${n} target${n === 1 ? "" : "s"} authorized`
    : "no targets authorized";
}

function renderScopeModal(scope) {
  const body = $("#scope-body");
  if (!body) return;
  const rows = scope.targets.map((t) => `
    <div style="border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px;">
      <div style="font-family:'JetBrains Mono',monospace; font-size:13px; color:var(--text-1);">${escapeHtml(t.host)}</div>
      <div style="color:var(--text-3); font-size:11.5px; margin-top:3px;">${escapeHtml(t.note || "")}</div>
      <div style="color:var(--text-2); font-size:11px; margin-top:6px;">
        techniques: ${escapeHtml((t.permitted_techniques || []).join(", "))} &middot;
        active: ${t.active_testing_permitted ? "yes" : "no"} &middot;
        destructive: ${t.destructive_actions_allowed ? "yes" : "no"}
      </div>
    </div>`).join("") || `<div style="color:var(--text-3);">No targets authorized. Add to scope.yaml and restart the API.</div>`;

  body.innerHTML = `
    <div style="color:var(--text-2); margin-bottom:10px;">
      <b>Authorized by:</b> ${escapeHtml(scope.authorized_by || "(unset)")}<br>
      <b>Reference:</b> ${escapeHtml(scope.authorization_ref || "(unset)")}
    </div>
    ${rows}
  `;
  const m = $("#scope-modal"); if (m) m.style.display = "flex";
}

document.addEventListener("DOMContentLoaded", boot);
