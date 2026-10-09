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

// Session gate: if any API call comes back 401 (session missing/expired),
// bounce to the login page, preserving where we were so login can return us.
(function installAuthRedirect() {
  const orig = window.fetch;
  window.fetch = async (...args) => {
    const resp = await orig(...args);
    if (resp.status === 401 && !location.pathname.startsWith("/login")) {
      location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
    }
    return resp;
  };
})();

// Log out: drop the session cookie and return to the login page.
async function h4ckLogout() {
  try { await window.fetch("/api/logout", { method: "POST" }); } catch (_) {}
  location.href = "/login";
}

// Top-bar account controls: a "Users" button (admins only) and "Log out",
// added once the DOM is ready and only when login is enabled on the server.
const _btnCss = "background:var(--bg-3);border:1px solid var(--border);color:var(--text-2);" +
  "font-size:12px;padding:5px 10px;border-radius:6px;cursor:pointer;font-family:inherit;";
const _inCss = "background:var(--bg-3);border:1px solid var(--border);color:var(--text-1);" +
  "font-size:13px;padding:8px 10px;border-radius:7px;font-family:inherit;outline:none;";

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const me = await (await window.fetch("/api/me")).json();
    if (!me || !me.login_enabled) return;
    if (me.role === "admin") buildUsersModal();
    installAccountMenu(me);
  } catch (_) {}
});

// Compact account menu anchored on the existing avatar (no extra top-bar
// width - the top bar is already dense). Avatar shows the user's initials;
// clicking it opens a dropdown with Users (admins) and Log out.
function installAccountMenu(me) {
  const avatar = document.querySelector(".avatar");
  if (!avatar) return;
  const initials = (me.user || "OP").replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "OP";
  avatar.textContent = initials;
  avatar.style.cursor = "pointer";
  avatar.title = (me.user || "") + (me.role ? " · " + me.role : "");

  const menu = document.createElement("div");
  menu.id = "acct-menu";
  menu.style.cssText = "position:fixed;top:46px;right:14px;min-width:180px;background:var(--bg-2);" +
    "border:1px solid var(--border-strong);border-radius:9px;padding:6px;z-index:1200;display:none;" +
    "box-shadow:0 12px 32px rgba(0,0,0,.5);";
  const head = document.createElement("div");
  head.style.cssText = "padding:7px 9px 9px;border-bottom:1px solid var(--border);margin-bottom:5px;";
  head.innerHTML = '<div style="font-weight:600;font-size:12.5px;">' + escapeHtml(me.user || "operator") + '</div>' +
    '<div style="font-size:11px;color:var(--text-3);margin-top:1px;">' + escapeHtml(me.role || "operator") + '</div>';
  menu.appendChild(head);

  const item = (label, fn) => {
    const el = document.createElement("div");
    el.textContent = label;
    el.style.cssText = "padding:8px 9px;border-radius:6px;font-size:12.5px;color:var(--text-2);cursor:pointer;";
    el.addEventListener("mouseenter", () => { el.style.background = "var(--bg-3)"; el.style.color = "var(--text-1)"; });
    el.addEventListener("mouseleave", () => { el.style.background = ""; el.style.color = "var(--text-2)"; });
    el.addEventListener("click", () => { menu.style.display = "none"; fn(); });
    menu.appendChild(el);
  };
  if (me.role === "admin") item("Manage users", openUsersModal);
  item("Log out", h4ckLogout);
  document.body.appendChild(menu);

  avatar.addEventListener("click", (e) => {
    e.stopPropagation();
    menu.style.display = menu.style.display === "none" ? "block" : "none";
  });
  document.addEventListener("click", (e) => {
    if (e.target !== avatar && !menu.contains(e.target)) menu.style.display = "none";
  });
}

// ── Admin Users panel (injected modal) ──────────────────────────────
function buildUsersModal() {
  if (document.getElementById("users-modal")) return;
  const m = document.createElement("div");
  m.id = "users-modal";
  m.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;" +
    "align-items:center;justify-content:center;z-index:1000;";
  m.innerHTML =
    '<div style="width:540px;max-width:92vw;max-height:86vh;overflow:auto;background:var(--bg-1);' +
    'border:1px solid var(--border);border-radius:12px;padding:20px 22px;">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">' +
        '<div style="font-weight:600;font-size:15px;">Users</div>' +
        '<button id="um-close" style="' + _btnCss + '">Close</button>' +
      '</div>' +
      '<div id="um-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:18px;"></div>' +
      '<div style="border-top:1px solid var(--border);padding-top:14px;">' +
        '<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-3);margin-bottom:9px;">Add user</div>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">' +
          '<input id="um-user" placeholder="username" style="' + _inCss + 'flex:1;min-width:120px;">' +
          '<input id="um-pass" type="password" placeholder="password (min 8)" style="' + _inCss + 'flex:1;min-width:120px;">' +
          '<select id="um-role" style="' + _inCss + '"><option value="operator">operator</option><option value="admin">admin</option></select>' +
          '<button id="um-add" style="background:linear-gradient(160deg,var(--validated),#2b8b81);color:#06201d;' +
            'font-weight:600;border:0;border-radius:7px;padding:9px 14px;cursor:pointer;font-family:inherit;">Add</button>' +
        '</div>' +
        '<div id="um-msg" style="margin-top:9px;font-size:12px;color:var(--text-2);min-height:16px;"></div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(m);
  m.addEventListener("click", (e) => { if (e.target === m) closeUsersModal(); });
  document.getElementById("um-close").addEventListener("click", closeUsersModal);
  document.getElementById("um-add").addEventListener("click", addUser);
}

function openUsersModal() {
  const m = document.getElementById("users-modal");
  if (m) { m.style.display = "flex"; loadUsers(); }
}
function closeUsersModal() {
  const m = document.getElementById("users-modal");
  if (m) m.style.display = "none";
}

async function loadUsers() {
  const list = document.getElementById("um-list");
  list.innerHTML = '<div style="color:var(--text-3);font-size:12px;">Loading…</div>';
  try {
    const data = await (await window.fetch("/api/users")).json();
    const users = (data && data.users) || [];
    list.innerHTML = "";
    users.forEach((u) => {
      const row = document.createElement("div");
      row.style.cssText = "display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--bg-2);" +
        "border:1px solid var(--border);border-radius:8px;";
      const badge = u.role === "admin"
        ? '<span style="font-size:10px;color:var(--validated);border:1px solid #2b8b81;border-radius:4px;padding:1px 6px;">admin</span>'
        : '<span style="font-size:10px;color:var(--text-3);border:1px solid var(--border-strong);border-radius:4px;padding:1px 6px;">operator</span>';
      row.innerHTML =
        '<span style="font-weight:500;">' + escapeHtml(u.username) + '</span>' + badge +
        '<span style="margin-left:auto;color:var(--text-3);font-size:11px;">' +
          (u.active ? "" : "disabled") + '</span>';
      const del = document.createElement("button");
      del.textContent = "Remove";
      del.style.cssText = "background:var(--crit-bg);border:1px solid #58242a;color:#f4a3a6;" +
        "font-size:11px;padding:4px 9px;border-radius:6px;cursor:pointer;font-family:inherit;";
      del.addEventListener("click", () => deleteUser(u.username));
      row.appendChild(del);
      list.appendChild(row);
    });
    if (!users.length) list.innerHTML = '<div style="color:var(--text-3);font-size:12px;">No users.</div>';
  } catch (_) {
    list.innerHTML = '<div style="color:#f4a3a6;font-size:12px;">Could not load users.</div>';
  }
}

async function addUser() {
  const msg = document.getElementById("um-msg");
  const username = document.getElementById("um-user").value.trim();
  const password = document.getElementById("um-pass").value;
  const role = document.getElementById("um-role").value;
  msg.style.color = "var(--text-2)"; msg.textContent = "Adding…";
  try {
    const resp = await window.fetch("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    if (resp.ok) {
      document.getElementById("um-user").value = "";
      document.getElementById("um-pass").value = "";
      msg.style.color = "var(--validated)"; msg.textContent = "User added.";
      loadUsers();
    } else {
      const e = await resp.json().catch(() => ({}));
      msg.style.color = "#f4a3a6"; msg.textContent = e.detail || ("Failed (" + resp.status + ")");
    }
  } catch (_) {
    msg.style.color = "#f4a3a6"; msg.textContent = "Request failed.";
  }
}

async function deleteUser(username) {
  if (!confirm("Remove user '" + username + "'?")) return;
  const msg = document.getElementById("um-msg");
  try {
    const resp = await window.fetch("/api/users/" + encodeURIComponent(username), { method: "DELETE" });
    if (resp.ok) { msg.style.color = "var(--text-2)"; msg.textContent = "Removed " + username + "."; loadUsers(); }
    else { const e = await resp.json().catch(() => ({})); msg.style.color = "#f4a3a6"; msg.textContent = e.detail || "Failed."; }
  } catch (_) { msg.style.color = "#f4a3a6"; msg.textContent = "Request failed."; }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const POLL_MS = 1500;
const DEFAULT_TARGET = "scanme.nmap.org";
const DEFAULT_MODULES = ["discovery", "misconfig", "nuclei"];  // nuclei runs when installed (no-op otherwise); red-team engine runs on top (full_engine)

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

function statusLabel(status, findingKind) {
  if ((findingKind || "").toLowerCase() === "informational") return "Recorded";
  return {
    validated: "Validated",
    potential: "Potential",
    needs_review: "Needs review",
    false_positive: "False positive",
  }[status] || status;
}

// ── API ─────────────────────────────────────────────────────────────
async function startAssessment(target, modules, llmModel, authCookie) {
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
    body: JSON.stringify({
      target, modules, llm_model: llmModel,
      ...(authCookie ? { auth_cookie: authCookie } : {}),
    }),
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
    // An informational finding (e.g. an open port) is shown as "Recorded",
    // not "Validated", so it must NOT be tallied in the Validated stat — the
    // tile has to match what the table shows, no inflation.
    const isInfo = (f.finding_kind || "").toLowerCase() === "informational";
    if (!isInfo && (f.status || "").toLowerCase() === "validated") counts.validated++;
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
        <td><span class="status-tag ${statusClass(f.status)}"><span class="sdot"></span>${escapeHtml(statusLabel(f.status, f.finding_kind))}</span></td>
        <td>${phase ? `<span class="kc-tag">${escapeHtml(phase.replace(/_/g, " "))}</span>` : ""}${f.owasp_category ? ` <span class="kc-tag" style="margin-left:4px;">${escapeHtml(f.owasp_category)}</span>` : ""}</td>
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

  const evidenceHtml = (f.evidence || []).map((e) => {
    const isScreenshot = e.evidence_type === "screenshot";
    const evUrl = `/api/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(f.finding_id)}/evidence/${encodeURIComponent(e.evidence_id)}`;
    const imgHtml = isScreenshot
      ? `<img src="${evUrl}" alt="${escapeHtml(e.description || "Screenshot evidence")}"
           style="max-width:100%; border-radius:6px; display:block; margin-bottom:6px; cursor:zoom-in; border:1px solid var(--border, #333);"
           onclick="window.open('${evUrl}', '_blank')" loading="lazy">`
      : "";
    return `
    <div class="evidence-shot">
      ${imgHtml}
      <div class="shot-canvas">${escapeHtml(e.evidence_type)} &middot; ${escapeHtml(e.description || "")}</div>
      <div class="shot-cap">
        <span>${escapeHtml((e.captured_at || "").slice(0, 19).replace("T", " "))} UTC</span>
        <span class="mono">sha256: ${escapeHtml((e.content_hash || "").slice(0, 8))}...</span>
      </div>
    </div>`;
  }).join("") || `<div style="color:var(--text-3); font-size:11.5px">No evidence attached.</div>`;

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
      <div class="meta-cell"><div class="l">Status</div><div class="v">${escapeHtml(statusLabel(f.status, f.finding_kind))}</div></div>
      ${f.owasp_category ? `<div class="meta-cell"><div class="l">OWASP Top 10</div><div class="v mono">${escapeHtml(f.owasp_category)}</div></div>` : ""}
    </div>

    <div class="section-label">Description</div>
    <div style="font-size:12px; color:var(--text-2); line-height:1.6">${escapeHtml(f.description || "")}</div>

    ${f.remediation ? `<div class="section-label">Remediation</div><div style="font-size:12px; color:var(--text-2); line-height:1.6">${escapeHtml(f.remediation)}</div>` : ""}

    ${(f.finding_kind || "").toLowerCase() === "informational" ? `
      <div class="section-label">Informational finding</div>
      <div style="font-size:12px; color:var(--text-2); line-height:1.6">
        This is a discovery result, not a vulnerability claim - it did not go through the validation pipeline.
      </div>
    ` : `
      <div class="section-label">Validation confidence</div>
      <div style="display:flex; align-items:baseline; justify-content:space-between;">
        <span style="font-size:12px; color:var(--text-2)">${passed} of ${applicable.length} applicable layers confirmed</span>
        <span class="mono" style="font-size:12px; color:var(--validated); font-weight:500">${conf}%</span>
      </div>
      <div class="confidence-bar-track"><div class="confidence-bar-fill" style="width:${conf}%"></div></div>

      <div class="section-label">Validation layers</div>
      <div class="layers-list">${layersHtml}</div>
    `}

    <div class="section-label">Evidence</div>
    ${evidenceHtml}
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

// ── Connection health ───────────────────────────────────────────────
async function checkConnection() {
  const dot = $("#conn-dot");
  const label = $("#conn-label");
  try {
    const resp = await fetch(`${API_BASE}/api/health`, { cache: "no-store" });
    if (resp.ok) {
      if (dot) dot.style.background = "var(--validated)";
      if (label) label.textContent = "connected";
      return true;
    }
    throw new Error(`status ${resp.status}`);
  } catch (e) {
    if (dot) dot.style.background = "var(--crit)";
    if (label) label.textContent = "disconnected";
    return false;
  }
}

// ── Past assessments ────────────────────────────────────────────────
async function loadPastAssessments() {
  const el = $("#past-assessments");
  if (!el) return;
  try {
    const resp = await fetch(`${API_BASE}/api/assessments?limit=20`);
    if (!resp.ok) throw new Error(`${resp.status}`);
    const items = await resp.json();
    if (!items.length) {
      el.innerHTML = '<em style="color:var(--text-3); font-size:11.5px;">(none yet)</em>';
      return;
    }
    el.innerHTML = items.map((a) => {
      const when = (a.started_at || "").replace("T", " ").slice(0, 16);
      const active = a.assessment_id === assessmentId ? ' style="background:var(--bg-3); color:var(--text-1);"' : '';
      return `
        <div class="asset-row" data-assessment-id="${escapeHtml(a.assessment_id)}"${active}
             style="font-size:11.5px; padding:5px 8px; border-radius:5px; cursor:pointer; margin-bottom:2px;">
          <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${escapeHtml(a.target)}
          </span>
          <span style="color:var(--text-3); font-size:10.5px; margin-left:6px;">
            ${escapeHtml(a.status).slice(0, 8)}
          </span>
        </div>`;
    }).join("");

    for (const row of el.querySelectorAll("[data-assessment-id]")) {
      row.addEventListener("click", () => {
        assessmentId = row.dataset.assessmentId;
        selectedFindingId = null;
        loadAssessment(assessmentId);
      });
    }
  } catch (e) {
    el.innerHTML = `<em style="color:var(--crit); font-size:11px;">error: ${escapeHtml(e.message)}</em>`;
  }
}

async function loadAssessment(id) {
  try {
    const s = await getStatus(id);
    updateRunBadge(s.status === "complete" ? "complete" : (s.status === "running" ? "running" : "error"), s.finding_count);
    findings = await getFindings(id);
    renderStats();
    renderFindingsTable();
    renderDetail(null);
    const rpt = $("#view-report"); if (rpt) rpt.disabled = false;
    setTimeout(loadPastAssessments, 500);   // refresh list after POST returns
    loadPastAssessments();
  } catch (e) {
    alert(`Failed to load assessment: ${e.message}`);
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

  // Mobile app scan: the button opens a file picker; selecting an
  // APK/IPA uploads it and runs the mobile static-analysis stage.
  const mobileBtn = $("#scan-mobile");
  const mobileFile = $("#mobile-file");
  if (mobileBtn && mobileFile) {
    mobileBtn.addEventListener("click", () => mobileFile.click());
    mobileFile.addEventListener("change", () => {
      const f = mobileFile.files && mobileFile.files[0];
      if (f) startMobileScan(f);
      mobileFile.value = "";  // allow re-selecting the same file
    });
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

  // Connection health: check every 5s.
  checkConnection();
  setInterval(checkConnection, 5000);

  // Past assessments: load on boot and refresh every 15s.
  loadPastAssessments();
  setInterval(loadPastAssessments, 15000);
}

async function uploadMobileApp(file) {
  // Admin-gated like /assessments/run; session users get a bearer injected
  // by the auth gate, otherwise the token in sessionStorage is used.
  const token = sessionStorage.getItem("h4ck_admin_token") || "";
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const fd = new FormData();
  fd.append("file", file, file.name);
  const resp = await fetch(`${API_BASE}/api/mobile/assess`, {
    method: "POST", headers, body: fd,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`upload failed: ${resp.status} ${text}`);
  }
  const { assessment_id } = await resp.json();
  return assessment_id;
}

async function startMobileScan(file) {
  const name = (file.name || "").toLowerCase();
  if (!(name.endsWith(".apk") || name.endsWith(".ipa"))) {
    alert("Please choose an Android .apk or iOS .ipa file.");
    return;
  }
  try {
    updateRunBadge("running", 0);
    const rpt = $("#view-report"); if (rpt) rpt.disabled = false;
    assessmentId = await uploadMobileApp(file);
    findings = [];
    selectedFindingId = null;
    renderStats();
    renderFindingsTable();
    startPolling();
  } catch (e) {
    updateRunBadge("error", 0);
    alert(`Mobile scan failed to start.\n\n${e.message || e}`);
  }
}

async function startScanFromForm() {
  const target = ($("#target-input")?.value || "").trim();
  const llmModel = ($("#llm-model")?.value || "qwen2.5:3b").trim() || "qwen2.5:3b";
  const authCookie = ($("#auth-cookie")?.value || "").trim();

  if (!target) {
    alert("Enter a target hostname or IP.");
    $("#target-input")?.focus();
    return;
  }

  try {
    updateRunBadge("running", 0);
    const rpt = $("#view-report"); if (rpt) rpt.disabled = false;
    assessmentId = await startAssessment(target, DEFAULT_MODULES, llmModel, authCookie);
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

  const roe = $("#roe-count");
  if (roe) roe.textContent = String(n);
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
