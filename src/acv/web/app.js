"use strict";

const state = {
  view: "overview",
  health: null,
  tasks: [],
  tools: [],
  task: null,
  candidate: null,
  codeTab: "vulnerable",
  verify: null,
  verifyError: null,
  scores: null,
  qualifyError: null,
  audit: null,
  auditError: null,
  review: null,
  reviewError: null,
  reviewTask: null,
  reviewCandidate: null,
  quickTask: null,
  quickCandidate: null,
  patchTask: null,
  patchDetail: null,
  patchCode: "",
  patchSource: "",
  patchDirty: false,
  patchResult: null,
  patchError: null,
  runs: [],
  taskFilter: "",
  busy: {},
  error: null,
};

const VIEW_META = {
  overview: { eyebrow: "workspace / dashboard", title: "Dashboard" },
  tasks: { eyebrow: "workspace / tasks", title: "Task explorer" },
  patch: { eyebrow: "workspace / patch lab", title: "Patch lab" },
  tools: { eyebrow: "evaluation / checkers", title: "Checker qualification" },
  audit: { eyebrow: "evaluation / audit", title: "Audit matrix" },
  review: { eyebrow: "review / model", title: "Model review" },
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[char];
  });
}

function pct(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${(number * 100).toFixed(1)}%` : "—";
}

function ratio(value) {
  return Number.isFinite(Number(value)) ? Number(value).toFixed(2) : "—";
}

function codeBlock(text) {
  const lines = String(text ?? "").replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  return `<div class="code">${lines
    .map(
      (line, index) =>
        `<span class="code-line"><span class="ln">${index + 1}</span><span class="src">${escapeHtml(
          line || " ",
        )}</span></span>`,
    )
    .join("")}</div>`;
}

function metricCard(label, value, note, extraClass = "") {
  return `<div class="card ${extraClass}">
    <div class="metric-label">${escapeHtml(label)}</div>
    <div class="metric">${escapeHtml(value)}</div>
    <div class="metric-note">${escapeHtml(note)}</div>
  </div>`;
}

function pill(text, tone = "") {
  return `<span class="pill ${tone}">${escapeHtml(text)}</span>`;
}

function verdictPill(accepted) {
  return `<span class="verdict ${accepted ? "accepted" : "rejected"}">${accepted ? "ACCEPT" : "REJECT"}</span>`;
}

function reviewTone(verdict) {
  if (verdict === "likely_fixed") return "green";
  if (verdict === "likely_vulnerable") return "red";
  if (verdict === "incomplete") return "amber";
  return "blue";
}

function iconButton(label, action, extra = "") {
  return `<button class="btn ${extra}" type="button" data-action="${escapeHtml(action)}">${escapeHtml(
    label,
  )}</button>`;
}

function spin(label) {
  return `<span class="spinner" aria-hidden="true"></span>${escapeHtml(label)}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!response.ok) {
    const detail = data && typeof data === "object" ? data.detail : data;
    throw new Error(
      typeof detail === "string" ? detail : `Request failed with HTTP ${response.status}`,
    );
  }
  return data;
}

function showToast(message, kind = "") {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast show ${kind}`.trim();
  window.clearTimeout(showToast._timer);
  showToast._timer = window.setTimeout(() => {
    toast.className = "toast";
  }, 4200);
}

function updateEnvironment() {
  const health = state.health;
  const candidates = state.tasks.reduce((total, task) => total + task.candidates.length, 0);
  const model = health?.model || "unknown model";
  $("#env-model").textContent = model;
  $("#env-key").textContent = health?.key_configured ? "configured" : "missing";
  $("#env-tasks").textContent = `${state.tasks.length} tasks`;
  $("#env-api").textContent = health?.ok ? "online" : "offline";
  $("#workspace-meta").textContent = `${state.tasks.length} fixtures · ${candidates} candidates`;
  if (health?.version) {
    $("#build-version").textContent = `v${health.version}`;
  }
  const status = $("#global-status");
  if (status) {
    status.textContent = health?.ok ? "API online" : "API offline";
    status.className = `status-pill ${health?.ok ? "online" : "offline"}`;
  }
}

function updateShell() {
  const meta = VIEW_META[state.view] || VIEW_META.overview;
  $("#view-title").textContent = meta.title;
  $("#view-eyebrow").textContent = meta.eyebrow;
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.view);
  });
}

function setView(view) {
  if (!VIEW_META[view]) return;
  state.view = view;
  if (view === "review") ensureReviewSelection();
  updateShell();
  if (view === "patch" && !state.patchDetail) {
    openPatchLab().catch((error) => showToast(error.message, "error"));
    return;
  }
  render();
}

function ensureReviewSelection() {
  if (!state.tasks.length) {
    state.reviewTask = null;
    state.reviewCandidate = null;
    return;
  }
  const task = state.tasks.find((item) => item.task_id === state.reviewTask) || state.tasks[0];
  state.reviewTask = task.task_id;
  const candidate =
    task.candidates.find((item) => item.name === state.reviewCandidate) || task.candidates[0];
  state.reviewCandidate = candidate?.name || null;
}

async function refreshCatalog() {
  const [health, tasks, tools] = await Promise.all([
    api("/api/health"),
    api("/api/tasks"),
    api("/api/tools"),
  ]);
  state.health = health;
  state.tasks = tasks;
  state.tools = tools;
  state.error = null;
  updateEnvironment();
}

async function init() {
  bindEvents();
  try {
    await refreshCatalog();
    render();
  } catch (error) {
    state.error = error.message;
    $("#view-root").innerHTML = `<div class="empty-panel">
      <strong>Could not reach the research API</strong>
      <span>${escapeHtml(error.message)}</span>
      <span class="small">Start the console with <code class="code-inline">uv run acv serve</code> and reload this page.</span>
    </div>`;
    const status = $("#global-status");
    if (status) {
      status.textContent = "API offline";
      status.className = "status-pill offline";
    }
  }
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const nav = event.target.closest("[data-view]");
    if (nav) {
      setView(nav.dataset.view);
      return;
    }

    const action = event.target.closest("[data-action]");
    if (!action) return;
    handleAction(action.dataset.action, action).catch((error) => {
      showToast(error.message, "error");
    });
  });

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (target.id === "candidate-select") {
      state.candidate = target.value;
      state.codeTab = "candidate";
      state.verify = null;
      state.verifyError = null;
      renderTaskDetail();
    }
    if (target.id === "quick-task") {
      state.quickTask = target.value;
      const task = state.tasks.find((item) => item.task_id === state.quickTask);
      state.quickCandidate = task?.candidates[0]?.name || null;
      renderOverview();
    }
    if (target.id === "quick-candidate") {
      state.quickCandidate = target.value;
    }
    if (target.id === "patch-task") {
      openPatchLab(target.value).catch((error) => showToast(error.message, "error"));
    }
    if (target.id === "review-task") {
      state.reviewTask = target.value;
      const task = state.tasks.find((item) => item.task_id === state.reviewTask);
      state.reviewCandidate = task?.candidates[0]?.name || null;
      state.review = null;
      state.reviewError = null;
      renderReview();
    }
    if (target.id === "review-candidate") {
      state.reviewCandidate = target.value;
      state.review = null;
      state.reviewError = null;
      renderReview();
    }
  });

  document.addEventListener("input", (event) => {
    if (event.target.id === "task-filter") {
      state.taskFilter = event.target.value;
      renderTaskList();
    }
    if (event.target.id === "patch-code") {
      state.patchCode = event.target.value;
      state.patchDirty = true;
      const count = $("#patch-count");
      if (count) count.textContent = codeStats(state.patchCode);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (
      event.target.id === "patch-code" &&
      (event.metaKey || event.ctrlKey) &&
      event.key === "Enter"
    ) {
      event.preventDefault();
      runPatch().catch((error) => showToast(error.message, "error"));
    }
  });

  $("#refresh-btn").addEventListener("click", async () => {
    const button = $("#refresh-btn");
    button.disabled = true;
    button.innerHTML = spin("Refreshing");
    try {
      await refreshCatalog();
      render();
      showToast("Catalog refreshed");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = "Refresh";
    }
  });
}

async function handleAction(action, element) {
  switch (action) {
    case "go-view":
      setView(element.dataset.target);
      break;
    case "open-task":
      await openTask(element.dataset.taskId);
      break;
    case "open-patch":
      await openPatchLab(element.dataset.taskId || state.task?.task_id);
      break;
    case "quick-verify":
      await quickVerify();
      break;
    case "patch-load":
      loadPatchSource($("#patch-source")?.value || "vulnerable");
      break;
    case "patch-run":
      await runPatch();
      break;
    case "code-tab":
      state.codeTab = element.dataset.tab || "vulnerable";
      renderTaskDetail();
      break;
    case "verify":
      await runVerify();
      break;
    case "qualify":
      await runQualify();
      break;
    case "audit":
      await runAudit();
      break;
    case "review":
      await runReview();
      break;
    case "switch-review":
      if (state.task) {
        state.reviewTask = state.task.task_id;
        state.reviewCandidate = state.candidate;
      }
      state.review = null;
      state.reviewError = null;
      setView("review");
      break;
    default:
      break;
  }
}

async function openTask(taskId) {
  state.view = "tasks";
  state.task = null;
  state.candidate = null;
  state.codeTab = "vulnerable";
  state.verify = null;
  state.verifyError = null;
  state.taskFilter = "";
  updateShell();
  $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading task source and candidates…</span></div>`;
  try {
    state.task = await api(`/api/tasks/${encodeURIComponent(taskId)}`);
    state.candidate = state.task.candidates[0]?.name || null;
    render();
  } catch (error) {
    state.error = error.message;
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>Could not load task</strong><span>${escapeHtml(
      error.message,
    )}</span></div>`;
  }
}

function render() {
  updateShell();
  if (state.error && !state.tasks.length) return;
  switch (state.view) {
    case "tasks":
      renderTasks();
      break;
    case "patch":
      renderPatchLab();
      break;
    case "tools":
      renderTools();
      break;
    case "audit":
      renderAudit();
      break;
    case "review":
      ensureReviewSelection();
      renderReview();
      break;
    default:
      renderOverview();
      break;
  }
}

function renderOverview() {
  const taskCount = state.tasks.length;
  const candidateCount = state.tasks.reduce((total, task) => total + task.candidates.length, 0);
  const cweCount = new Set(state.tasks.map((task) => task.cwe)).size;
  const availableCheckers = state.tools.filter((tool) => tool.available).length;
  const audit = state.audit?.summary;
  const best = state.scores?.find((score) => score.available);
  const demo = state.tasks.find((task) => task.task_id === "ssrf_redirect") || state.tasks[0];

  if (!state.quickTask || !state.tasks.some((task) => task.task_id === state.quickTask)) {
    state.quickTask = demo?.task_id || "";
  }
  const quickTask = state.tasks.find((task) => task.task_id === state.quickTask) || demo;
  if (
    quickTask &&
    !quickTask.candidates.some((candidate) => candidate.name === state.quickCandidate)
  ) {
    state.quickCandidate = quickTask.candidates[0]?.name || "";
  }

  const quickTaskOptions = state.tasks
    .map(
      (task) => `<option value="${escapeHtml(task.task_id)}" ${
        task.task_id === quickTask?.task_id ? "selected" : ""
      }>${escapeHtml(task.task_id)} · ${escapeHtml(task.cwe)}</option>`,
    )
    .join("");
  const quickCandidateOptions = (quickTask?.candidates || [])
    .map(
      (candidate) => `<option value="${escapeHtml(candidate.name)}" ${
        candidate.name === state.quickCandidate ? "selected" : ""
      }>${escapeHtml(candidate.name)} · ${escapeHtml(candidate.kind)}</option>`,
    )
    .join("");

  $("#view-root").innerHTML = `
    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Run a verification</h2>
            <p>Execute the exploit, the functional suite, and the checker gate against a labeled candidate.</p>
          </div>
          <span class="pill blue">deterministic</span>
        </div>
        <div class="quick-run">
          <div class="stack">
            <label class="metric-label" for="quick-task">Task</label>
            <select class="select" id="quick-task">${quickTaskOptions}</select>
          </div>
          <div class="stack">
            <label class="metric-label" for="quick-candidate">Candidate</label>
            <select class="select" id="quick-candidate">${quickCandidateOptions}</select>
          </div>
          <button class="btn primary" type="button" data-action="quick-verify" ${
            state.busy.verify ? "disabled" : ""
          }>${state.busy.verify ? spin("Running") : "Open & run gate"}</button>
        </div>
        <div class="row mt-12">
          <button class="btn ghost" type="button" data-action="open-patch" data-task-id="${escapeHtml(
            quickTask?.task_id || "",
          )}">Open patch lab</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="tasks">Browse tasks</button>
          <button class="btn ghost" type="button" data-action="audit" ${
            state.busy.audit ? "disabled" : ""
          }>${state.busy.audit ? spin("Running audit") : "Run full audit"}</button>
        </div>
        <div class="notice mt-12">
          A candidate is accepted only when the PoC exits cleanly, the functional suite passes, and
          the primary checker reports no blocking findings. The gate is authoritative.
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Corpus</h2>
          <span class="pill">${state.tasks.length ? "loaded" : "empty"}</span>
        </div>
        <div class="stat-list">
          <div class="stat-row"><span>Tasks</span><strong>${taskCount}</strong></div>
          <div class="stat-row"><span>CWE families</span><strong>${cweCount}</strong></div>
          <div class="stat-row"><span>Labeled candidates</span><strong>${candidateCount}</strong></div>
          <div class="stat-row"><span>Checkers installed</span><strong>${availableCheckers} / ${state.tools.length}</strong></div>
          <div class="stat-row"><span>Model reviewer</span><strong title="${escapeHtml(
            state.health?.model || "",
          )}">${escapeHtml(state.health?.model || "not checked")}</strong></div>
        </div>
        <div class="notice mt-12">
          ${
            state.health?.key_configured
              ? "Live model review is configured. Model output is advisory and never changes the gate verdict."
              : "No Groq key is configured. The deterministic gate and all local measurements still work."
          }
        </div>
      </section>
    </div>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Recent runs</h2>
            <p>Session history for catalog verifications and patch-lab runs.</p>
          </div>
          <span class="pill">${state.runs.length} run${state.runs.length === 1 ? "" : "s"}</span>
        </div>
        ${renderRecentRuns(6)}
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Last qualification</h2>
            <p>Measured checker quality on the labeled corpus.</p>
          </div>
          ${
            best
              ? `<span class="pill green">${escapeHtml(best.tool)}</span>`
              : `<span class="pill">not run</span>`
          }
        </div>
        ${
          best
            ? `<div class="stat-list">
                <div class="stat-row"><span>Precision</span><strong>${pct(best.precision)}</strong></div>
                <div class="stat-row"><span>Recall</span><strong>${pct(best.recall)}</strong></div>
                <div class="stat-row"><span>F1</span><strong>${pct(best.f1)}</strong></div>
                <div class="stat-row"><span>Runtime</span><strong>${best.runtime_ms} ms</strong></div>
                <div class="stat-row"><span>Samples</span><strong>${best.samples}</strong></div>
              </div>`
            : `<div class="notice">No qualification has run in this session. The harness scores every installed adapter over the same files.</div>`
        }
        <div class="row mt-12">
          <button class="btn ghost" type="button" data-action="go-view" data-target="tools">Open qualification</button>
          <button class="btn ghost" type="button" data-action="qualify" ${
            state.busy.qualify ? "disabled" : ""
          }>${state.busy.qualify ? spin("Qualifying") : "Run now"}</button>
        </div>
      </section>
    </div>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Last audit</h2>
            <p>Two-sided verdict matrix over gold, benign, and mutant candidates.</p>
          </div>
          <button class="btn ghost small" type="button" data-action="go-view" data-target="audit">Open audit</button>
        </div>
        ${
          audit
            ? `<div class="kv-grid">
                ${kv("Verdict accuracy", pct(audit.verdict_accuracy))}
                ${kv("Correct verdicts", `${audit.correct_verdicts}/${audit.candidates}`)}
                ${kv("False passes", String(audit.false_passes))}
                ${kv("False rejections", String(audit.false_rejections))}
                ${kv("Baseline", `${audit.baseline_ok}/${audit.tasks}`)}
                ${kv("Tasks", String(audit.tasks))}
              </div>`
            : `<div class="notice">No audit has run in this session. The full audit executes every task and reports false passes as well as false rejections.</div>`
        }
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Fixture note</h2>
            <p>${escapeHtml(demo?.title || "No fixture available")}</p>
          </div>
          ${demo ? `<span class="pill blue">${escapeHtml(demo.cwe)}</span>` : ""}
        </div>
        <p class="prose">
          The redirect-SSRF fixture is the useful hard case: a scanner can accept the redirect
          validation while the executable exploit still proves that the patch is incomplete.
        </p>
        <div class="row mt-12">
          ${
            demo
              ? `<button class="btn ghost" type="button" data-action="open-task" data-task-id="${escapeHtml(
                  demo.task_id,
                )}">Inspect task</button>
                 <button class="btn ghost" type="button" data-action="open-patch" data-task-id="${escapeHtml(
                   demo.task_id,
                 )}">Open in patch lab</button>`
              : ""
          }
        </div>
        <div class="notice mt-12">
          <strong>Scope.</strong> This is a calibration pack for verification mechanics, not a
          production benchmark and not evidence of universal detection quality.
        </div>
      </section>
    </div>
  `;
}

function formatRunTime(timestamp) {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function recordRun(entry) {
  state.runs.unshift({
    at: Date.now(),
    durationMs: 0,
    source: "catalog",
    ...entry,
  });
  state.runs = state.runs.slice(0, 12);
}

function renderRecentRuns(limit = 6) {
  const runs = state.runs.slice(0, limit);
  if (!runs.length) {
    return `<div class="notice">No gate runs in this browser session. Start with a candidate above or open the patch lab.</div>`;
  }
  return `<div class="run-list">
    ${runs
      .map(
        (run) => `<div class="run-row">
          <span class="run-time">${escapeHtml(formatRunTime(run.at))}</span>
          <span class="run-target"><strong>${escapeHtml(run.taskId)}</strong> <span>${escapeHtml(
            run.candidate,
          )}</span></span>
          <span>${run.accepted ? pill("accept", "green") : pill("reject", "red")}</span>
          <span class="run-duration">${escapeHtml(String(run.durationMs))} ms</span>
        </div>`,
      )
      .join("")}
  </div>`;
}

function codeStats(text) {
  const lines = String(text || "").split("\n").length;
  return `${lines} lines · ${String(text || "").length} chars`;
}

function renderTasks() {
  $("#view-root").innerHTML = `
    <div class="section-head">
      <div>
        <h2>Task explorer</h2>
        <p>Inspect the vulnerable source, the original exploit, the functional test, and the labeled candidates. Run any candidate through the deterministic gate.</p>
      </div>
      <div class="toolbar">
        <input id="task-filter" class="search" type="search" placeholder="Filter tasks…" value="${escapeHtml(
          state.taskFilter,
        )}" />
      </div>
    </div>
    <div class="task-layout">
      <aside class="task-sidebar">
        <div class="task-list" id="task-list"></div>
      </aside>
      <section class="task-detail" id="task-detail"></section>
    </div>
  `;
  renderTaskList();
  renderTaskDetail();
}

function renderTaskList() {
  const container = $("#task-list");
  if (!container) return;
  const needle = state.taskFilter.trim().toLowerCase();
  const tasks = state.tasks.filter((task) =>
    `${task.task_id} ${task.title} ${task.cwe}`.toLowerCase().includes(needle),
  );
  if (!tasks.length) {
    container.innerHTML = `<div class="empty-panel"><strong>No matching tasks</strong><span class="small">Clear the filter or refresh the catalog.</span></div>`;
    return;
  }
  container.innerHTML = tasks
    .map(
      (task) => `<button class="task-item ${
        state.task?.task_id === task.task_id ? "active" : ""
      }" type="button" data-action="open-task" data-task-id="${escapeHtml(task.task_id)}">
        <span class="task-id">${escapeHtml(task.task_id)}</span>
        <span class="task-title">${escapeHtml(task.title)}</span>
        <span class="task-meta">${escapeHtml(task.cwe)} · ${task.candidates.length} candidates</span>
      </button>`,
    )
    .join("");
}

function renderTaskDetail() {
  const container = $("#task-detail");
  if (!container) return;
  if (!state.task) {
    container.innerHTML = `<div class="empty-panel"><strong>Select a task</strong><span class="small">The vulnerable source, exploit, functional test, and candidate files will appear here.</span></div>`;
    return;
  }

  const task = state.task;
  const candidates = task.candidates || [];
  const candidate =
    candidates.find((item) => item.name === state.candidate) || candidates[0] || null;
  state.candidate = candidate?.name || null;

  const tabData = {
    vulnerable: {
      label: "Vulnerable",
      path: task.paths?.vulnerable,
      text: task.code?.vulnerable,
    },
    exploit: {
      label: "Exploit",
      path: task.paths?.poc,
      text: task.code?.exploit,
    },
    functional: {
      label: "Functional test",
      path: task.paths?.functional,
      text: task.code?.functional,
    },
    candidate: {
      label: candidate ? `Candidate · ${candidate.name}` : "Candidate",
      path: candidate?.path,
      text: candidate?.code,
    },
  };
  const activeTab = tabData[state.codeTab] ? state.codeTab : "vulnerable";
  const active = tabData[activeTab];

  const candidateOptions = candidates
    .map(
      (item) => `<option value="${escapeHtml(item.name)}" ${
        item.name === candidate?.name ? "selected" : ""
      }>${escapeHtml(item.name)} · ${escapeHtml(item.kind)} · ${
        item.expected_security ? "expected safe" : "expected vulnerable"
      }</option>`,
    )
    .join("");

  const tags = (task.tags || [])
    .map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`)
    .join("");

  container.innerHTML = `
    <div class="card task-head">
      <div>
        <div class="row">${pill(task.cwe, "blue")}${pill(task.task_id, "green")}</div>
        <h2>${escapeHtml(task.title)}</h2>
        <p>${escapeHtml(task.summary)}</p>
        <div class="task-tags">${tags}</div>
      </div>
      <div class="stack">
        <label class="metric-label" for="candidate-select">Candidate</label>
        <select class="select" id="candidate-select">${candidateOptions}</select>
        <div class="row">
          <button class="btn primary" type="button" data-action="verify" ${
            state.busy.verify ? "disabled" : ""
          }>${state.busy.verify ? spin("Running gate") : "Run gate"}</button>
          <button class="btn ghost" type="button" data-action="open-patch" data-task-id="${escapeHtml(
            task.task_id,
          )}">Open in patch lab</button>
          <button class="btn ghost" type="button" data-action="switch-review">Review candidate</button>
        </div>
      </div>
    </div>

    <div class="code-panel">
      <div class="code-head">
        <div class="code-tabs">
          ${Object.entries(tabData)
            .map(
              ([key, value]) =>
                `<button class="tab ${activeTab === key ? "active" : ""}" type="button" data-action="code-tab" data-tab="${escapeHtml(
                  key,
                )}">${escapeHtml(value.label)}</button>`,
            )
            .join("")}
        </div>
        <div class="code-path">${escapeHtml(active.path || "")}</div>
      </div>
      ${codeBlock(active.text)}
    </div>

    ${
      candidate
        ? `<div class="note">
            <strong>${escapeHtml(candidate.name)}</strong> is labeled <span class="code-inline">${escapeHtml(
              candidate.kind,
            )}</span>. Expected security: ${candidate.expected_security ? "safe" : "still vulnerable"}; expected behavior: ${
              candidate.expected_behavior ? "preserved" : "may change"
            }. ${escapeHtml(candidate.note || "")}
          </div>`
        : ""
    }

    ${state.verifyError ? `<div class="note warn">${escapeHtml(state.verifyError)}</div>` : ""}
    ${
      state.verify
        ? renderVerifyResult(state.verify)
        : `<div class="empty-panel"><strong>No gate result yet</strong><span class="small">Run the deterministic gate to execute the PoC, run the functional suite, and collect checker findings.</span></div>`
    }
  `;
}

function rejectedBy(result) {
  if (result.accepted) return "none";
  if (!result.security_pass) return "poc";
  if (!result.behavior_pass) return "behavior";
  if (!result.checker_pass) return "checker";
  return "unknown";
}

function findingsTable(findings) {
  if (!findings?.length) return "";
  return `<div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>CWE</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>
        ${findings
          .map(
            (finding) => `<tr>
              <td>${pill(finding.severity || "unknown", finding.severity === "high" ? "red" : "amber")}</td>
              <td class="mono">${escapeHtml(finding.rule_id || "—")}</td>
              <td class="mono">${escapeHtml(finding.cwe || "—")}</td>
              <td class="mono">${escapeHtml(finding.line ?? "—")}</td>
              <td class="wrap" title="${escapeHtml(finding.message || "")}">${escapeHtml(
                finding.message || "",
              )}</td>
            </tr>`,
          )
          .join("")}
      </tbody>
    </table>
  </div>`;
}

function checkerResultsTable(results) {
  const entries = Object.entries(results || {});
  if (!entries.length) return "";
  return `<details>
    <summary>Checker registry output</summary>
    <div class="table-wrap mt-12">
      <table>
        <thead><tr><th>Checker</th><th>Installed</th><th>Version</th><th class="num">Findings</th><th>Error</th></tr></thead>
        <tbody>
          ${entries
            .map(
              ([name, result]) => `<tr>
                <td class="mono">${escapeHtml(name)}</td>
                <td>${result.available ? pill("yes", "green") : pill("no", "red")}</td>
                <td class="mono">${escapeHtml(result.version || "—")}</td>
                <td class="num mono">${(result.findings || []).length}</td>
                <td class="wrap">${escapeHtml(result.error || "")}</td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  </details>`;
}

function renderVerifyResult(result) {
  const accepted = Boolean(result.accepted);
  const labeled = result.expected_accepted !== undefined && result.expected_accepted !== null;
  const correct = result.correct === true;
  const reasons = result.reasons || [];
  return `<div class="result ${accepted ? "accepted" : "rejected"}">
    <div class="result-top">
      <div class="result-title">
        ${verdictPill(accepted)}
        <strong>${escapeHtml(result.name || "custom")}</strong>
        ${
          labeled
            ? correct
              ? pill("matches label", "green")
              : pill("contradicts label", "red")
            : pill("unlabeled input", "blue")
        }
      </div>
      <div class="row">
        ${pill(`PoC exit ${result.poc_exit}`, result.poc_exit === 1 ? "green" : "red")}
        ${pill(`tests exit ${result.behavior_exit}`, result.behavior_exit === 0 ? "green" : "red")}
        ${pill(result.checker_tool || "checker", "blue")}
      </div>
    </div>

    <div class="kv-grid">
      ${
        labeled
          ? kv("Expected", result.expected_accepted ? "safe / fixed" : "still vulnerable")
          : kv("Source", "runtime input")
      }
      ${kv("Security", result.security_pass ? "pass" : "fail")}
      ${kv("Behavior", result.behavior_pass ? "pass" : "fail")}
      ${kv("Checker gate", result.checker_pass ? "pass" : "fail")}
      ${kv("Rejected by", rejectedBy(result))}
      ${kv("Verdict", accepted ? "accepted" : "rejected")}
      ${result.elapsed_ms !== undefined ? kv("Elapsed", `${result.elapsed_ms} ms`) : ""}
    </div>

    ${
      !labeled
        ? `<div class="notice">This source has no ground-truth label. Acceptance means the executable oracle and checker passed; it does not prove semantic equivalence with a reference repair.</div>`
        : ""
    }
    ${reasons.length ? `<ul class="reasons">${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
    ${findingsTable(result.findings)}

    <details>
      <summary>PoC output</summary>
      <div class="output">${escapeHtml(result.poc_output || "(no output)")}</div>
    </details>
    <details>
      <summary>Functional test output</summary>
      <div class="output">${escapeHtml(result.behavior_output || "(no output)")}</div>
    </details>
    ${checkerResultsTable(result.checker_results)}
  </div>`;
}

function kv(label, value) {
  return `<div class="kv"><div class="kv-label">${escapeHtml(label)}</div><div class="kv-value" title="${escapeHtml(
    value,
  )}">${escapeHtml(value)}</div></div>`;
}

async function runVerify() {
  if (!state.task || !state.candidate || state.busy.verify) return;
  state.busy.verify = true;
  state.verifyError = null;
  renderTaskDetail();
  const started = performance.now();
  try {
    state.verify = await api("/api/verify", {
      method: "POST",
      body: JSON.stringify({
        task_id: state.task.task_id,
        candidate: state.candidate,
        checker: "acv-rules",
      }),
    });
    recordRun({
      taskId: state.task.task_id,
      candidate: state.candidate,
      accepted: Boolean(state.verify.accepted),
      durationMs: Math.round(performance.now() - started),
      source: "catalog",
    });
    showToast(`Gate finished for ${state.candidate}`);
  } catch (error) {
    state.verify = null;
    state.verifyError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.verify = false;
    renderTaskDetail();
  }
}

async function quickVerify() {
  if (state.busy.verify || !state.quickTask || !state.quickCandidate) return;
  state.view = "tasks";
  updateShell();
  await openTask(state.quickTask);
  state.candidate = state.quickCandidate;
  state.codeTab = "candidate";
  state.verify = null;
  state.verifyError = null;
  renderTaskDetail();
  await runVerify();
}

function defaultPatchTask() {
  return (
    state.tasks.find((task) => task.task_id === "ssrf_redirect")?.task_id ||
    state.tasks[0]?.task_id ||
    null
  );
}

async function openPatchLab(taskId = state.patchTask || defaultPatchTask()) {
  state.view = "patch";
  updateShell();
  if (!taskId) {
    renderPatchLab();
    return;
  }
  if (state.patchDetail?.task_id === taskId) {
    renderPatchLab();
    return;
  }

  state.patchTask = taskId;
  state.patchDetail = null;
  state.patchCode = "";
  state.patchSource = "";
  state.patchDirty = false;
  state.patchResult = null;
  state.patchError = null;
  $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading task source and candidate templates…</span></div>`;

  try {
    const detail = await api(`/api/tasks/${encodeURIComponent(taskId)}`);
    if (!detail) return;
    state.patchDetail = detail;
    const preferred =
      detail.candidates.find((candidate) => candidate.name === "gold") || detail.candidates[0];
    state.patchCode = preferred?.code || detail.code?.vulnerable || "";
    state.patchSource = preferred?.name || "vulnerable";
    state.patchDirty = false;
    renderPatchLab();
  } catch (error) {
    state.patchError = error.message;
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>Could not load patch target</strong><span>${escapeHtml(
      error.message,
    )}</span></div>`;
  }
}

function patchSourceText(name) {
  const detail = state.patchDetail;
  if (!detail) return "";
  if (name === "vulnerable") return detail.code?.vulnerable || "";
  return detail.candidates.find((candidate) => candidate.name === name)?.code || "";
}

function loadPatchSource(name) {
  const text = patchSourceText(name);
  if (!text) {
    showToast(`No source template named ${name}`, "error");
    return;
  }
  state.patchCode = text;
  state.patchSource = name;
  state.patchDirty = false;
  state.patchResult = null;
  state.patchError = null;
  renderPatchLab();
}

async function runPatch() {
  if (!state.patchTask || !state.patchCode.trim() || state.busy.patch) return;
  state.busy.patch = true;
  state.patchError = null;
  renderPatchLab();
  const started = performance.now();
  try {
    const result = await api("/api/verify-code", {
      method: "POST",
      body: JSON.stringify({
        task_id: state.patchTask,
        code: state.patchCode,
        checker: "acv-rules",
      }),
    });
    state.patchResult = result;
    recordRun({
      taskId: state.patchTask,
      candidate: "custom source",
      accepted: Boolean(result.accepted),
      durationMs: result.elapsed_ms ?? Math.round(performance.now() - started),
      source: "patch",
    });
    showToast(`Patch gate finished: ${result.accepted ? "accepted" : "rejected"}`);
  } catch (error) {
    state.patchResult = null;
    state.patchError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.patch = false;
    renderPatchLab();
  }
}

function renderPatchLab() {
  if (!state.tasks.length) {
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>No tasks loaded</strong><span class="small">Start the API and refresh the catalog.</span></div>`;
    return;
  }
  if (!state.patchDetail) {
    $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading patch target…</span></div>`;
    return;
  }

  const detail = state.patchDetail;
  const taskOptions = state.tasks
    .map(
      (task) => `<option value="${escapeHtml(task.task_id)}" ${
        task.task_id === state.patchTask ? "selected" : ""
      }>${escapeHtml(task.task_id)} · ${escapeHtml(task.cwe)}</option>`,
    )
    .join("");
  const sourceOptions = [
    `<option value="vulnerable" ${
      state.patchSource === "vulnerable" ? "selected" : ""
    }>vulnerable source</option>`,
    ...detail.candidates.map(
      (candidate) => `<option value="${escapeHtml(candidate.name)}" ${
        state.patchSource === candidate.name ? "selected" : ""
      }>${escapeHtml(candidate.name)} · ${escapeHtml(candidate.kind)}</option>`,
    ),
  ].join("");
  const sourceLabel = state.patchSource
    ? `${state.patchSource}${state.patchDirty ? " · edited" : ""}`
    : "custom";

  $("#view-root").innerHTML = `
    <div class="section-head">
      <div>
        <h2>Patch lab</h2>
        <p>Paste a replacement <span class="code-inline">worker.py</span> for the selected task. The gate runs the original exploit, the functional suite, and the checker registry against the supplied source.</p>
      </div>
      <div class="toolbar">
        <select class="select" id="patch-task" aria-label="Patch target task">${taskOptions}</select>
        <select class="select" id="patch-source" aria-label="Source template">${sourceOptions}</select>
        <button class="btn ghost" type="button" data-action="patch-load">Load source</button>
        <button class="btn primary" type="button" data-action="patch-run" ${
          state.busy.patch ? "disabled" : ""
        }>${state.busy.patch ? spin("Running gate") : "Run gate"}</button>
      </div>
    </div>

    <div class="notice warning">
      <strong>Trusted input only.</strong> This endpoint writes the supplied module to a temporary
      directory and executes it on the host. There is no hardened sandbox yet; do not expose this
      console to untrusted users.
    </div>

    <div class="lab-layout mt-12">
      <section class="panel editor-panel">
        <div class="panel-head">
          <div>
            <h2>worker.py</h2>
            <p>${escapeHtml(detail.task_id)} · ${escapeHtml(detail.cwe)} · template ${escapeHtml(
              sourceLabel,
            )}</p>
          </div>
          <span class="pill blue">editable</span>
        </div>
        <textarea id="patch-code" class="editor" spellcheck="false" aria-label="Replacement worker source">${escapeHtml(
          state.patchCode,
        )}</textarea>
        <div class="editor-foot">
          <span id="patch-count">${codeStats(state.patchCode)}</span>
          <span>Ctrl/Cmd+Enter to run · full-file replacement</span>
        </div>
      </section>

      <section class="lab-result stack">
        ${
          state.patchError
            ? `<div class="notice warning">${escapeHtml(state.patchError)}</div>`
            : ""
        }
        ${
          state.patchResult
            ? renderVerifyResult(state.patchResult)
            : `<div class="empty-panel"><strong>No patch result yet</strong><span class="small">Load a template or paste your own replacement, then run the gate.</span></div>`
        }
        <div class="panel">
          <div class="panel-head">
            <h2>Target contract</h2>
            <span class="pill">${escapeHtml(detail.cwe)}</span>
          </div>
          <div class="stat-list">
            <div class="stat-row"><span>Task</span><strong>${escapeHtml(detail.task_id)}</strong></div>
            <div class="stat-row"><span>Vulnerable path</span><strong>${escapeHtml(
              detail.paths?.vulnerable || "worker.py",
            )}</strong></div>
            <div class="stat-row"><span>Exploit</span><strong>${escapeHtml(
              detail.paths?.poc || "poc.py",
            )}</strong></div>
            <div class="stat-row"><span>Functional test</span><strong>${escapeHtml(
              detail.paths?.functional || "test_worker.py",
            )}</strong></div>
            <div class="stat-row"><span>Labeled candidates</span><strong>${detail.candidates.length}</strong></div>
          </div>
          <p class="tiny faint mt-12">
            The replacement must expose the same module-level interface as the vulnerable worker.
            Patches are applied as full-file replacements in this build.
          </p>
        </div>
      </section>
    </div>
  `;
}

function renderTools() {
  const tools = state.tools || [];
  const scores = state.scores || [];
  const available = tools.filter((tool) => tool.available).length;

  $("#view-root").innerHTML = `
    <div class="section-head">
      <div>
        <h2>Checker qualification</h2>
        <p>Run every registered checker over the same labeled corpus, then compare true positives, false positives, false negatives, and runtime.</p>
      </div>
      <button class="btn primary" type="button" data-action="qualify" ${
        state.busy.qualify ? "disabled" : ""
      }>${state.busy.qualify ? spin("Qualifying") : "Run qualification"}</button>
    </div>

    <div class="cards">
      ${metricCard("Registered", String(tools.length), "checker adapters")}
      ${metricCard("Installed", String(available), "available in this environment")}
      ${metricCard(
        "Measured files",
        scores.length ? String(scores[0].samples) : "—",
        "the harness builds the corpus from every task",
      )}
      ${metricCard("Corpus", `${state.tasks.length} tasks`, "vulnerable, fixed, benign, mutant")}
    </div>

    <div class="table-wrap">
      <table>
        <thead><tr><th>Checker</th><th>Category</th><th>Languages</th><th>Installed</th><th>Version</th><th>Description</th></tr></thead>
        <tbody>
          ${tools
            .map(
              (tool) => `<tr>
                <td class="mono">${escapeHtml(tool.name)}</td>
                <td>${escapeHtml(tool.category)}</td>
                <td class="mono">${escapeHtml((tool.languages || []).join(", "))}</td>
                <td>${tool.available ? pill("yes", "green") : pill("no", "red")}</td>
                <td class="mono">${escapeHtml(tool.version || "—")}</td>
                <td class="wrap">${escapeHtml(tool.description || "")}</td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>

    <div class="note mt-12">
      The local <span class="code-inline">acv-rules</span> pack is intentionally tuned to this task family. Its score is useful for regression testing, not for claiming universal detection quality. Bandit is measured as an external baseline.
    </div>

    ${state.qualifyError ? `<div class="note warn mt-12">${escapeHtml(state.qualifyError)}</div>` : ""}
    ${scores.length ? renderScores(scores) : `<div class="empty-panel mt-18"><strong>No qualification run yet</strong><span class="small">Click “Run qualification” to execute the adapters and score the corpus.</span></div>`}
  `;
}

function renderScores(scores) {
  const available = scores.filter((score) => score.available);
  const misses = available.flatMap((score) =>
    (score.false_negatives || []).map((sample) => ({ tool: score.tool, sample })),
  );
  const falsePositives = available.flatMap((score) =>
    (score.false_positives || []).map((sample) => ({ tool: score.tool, sample })),
  );

  return `<div class="section-head">
      <div><h2>Leaderboard</h2><p>Scored on ${scores[0].samples} labeled files. Runtime includes process startup for subprocess checkers.</p></div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Tool</th><th>Available</th><th class="num">TP</th><th class="num">FP</th><th class="num">FN</th><th class="num">TN</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th><th class="num">Runtime</th></tr></thead>
        <tbody>
          ${scores
            .map(
              (score) => `<tr>
                <td class="mono">${escapeHtml(score.tool)}</td>
                <td>${score.available ? pill("yes", "green") : pill("no", "red")}</td>
                <td class="num mono">${score.available ? score.tp : "—"}</td>
                <td class="num mono">${score.available ? score.fp : "—"}</td>
                <td class="num mono">${score.available ? score.fn : "—"}</td>
                <td class="num mono">${score.available ? score.tn : "—"}</td>
                <td class="num mono">${score.available ? pct(score.precision) : "—"}</td>
                <td class="num mono">${score.available ? pct(score.recall) : "—"}</td>
                <td class="num mono">${score.available ? pct(score.f1) : "—"}</td>
                <td class="num mono">${score.available ? `${score.runtime_ms} ms` : "—"}</td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>

    <div class="split mt-18">
      <div class="card">
        <h2>False negatives</h2>
        <p class="muted small">Vulnerable files the checker missed.</p>
        <div class="miss-list mt-12">
          ${
            misses.length
              ? misses
                  .map(
                    (miss) =>
                      `<span class="miss">${escapeHtml(miss.tool)} · ${escapeHtml(miss.sample)}</span>`,
                  )
                  .join("")
              : `<span class="miss good">none in this corpus</span>`
          }
        </div>
      </div>
      <div class="card">
        <h2>False positives</h2>
        <p class="muted small">Safe files the checker flagged as blocking.</p>
        <div class="miss-list mt-12">
          ${
            falsePositives.length
              ? falsePositives
                  .map(
                    (miss) =>
                      `<span class="miss">${escapeHtml(miss.tool)} · ${escapeHtml(miss.sample)}</span>`,
                  )
                  .join("")
              : `<span class="miss good">none in this corpus</span>`
          }
        </div>
      </div>
    </div>

    ${renderCweRecall(available)}`;
}

function renderCweRecall(scores) {
  const rows = [];
  for (const score of scores) {
    for (const cwe of score.cwe || []) {
      rows.push({ tool: score.tool, ...cwe });
    }
  }
  if (!rows.length) return "";
  return `<details class="mt-18">
    <summary>CWE recall breakdown</summary>
    <div class="table-wrap mt-12">
      <table>
        <thead><tr><th>Tool</th><th>CWE</th><th class="num">Positives</th><th class="num">TP</th><th class="num">Recall</th></tr></thead>
        <tbody>
          ${rows
            .map(
              (row) => `<tr>
                <td class="mono">${escapeHtml(row.tool)}</td>
                <td class="mono">${escapeHtml(row.cwe)}</td>
                <td class="num mono">${row.positives}</td>
                <td class="num mono">${row.true_positives}</td>
                <td class="num mono">${pct(row.recall)}</td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  </details>`;
}

async function runQualify() {
  if (state.busy.qualify) return;
  if (state.view !== "tools") {
    state.view = "tools";
    updateShell();
  }
  state.busy.qualify = true;
  state.qualifyError = null;
  render();
  try {
    const data = await api("/api/qualify", {
      method: "POST",
      body: JSON.stringify({ checkers: null }),
    });
    state.scores = data.scores || [];
    showToast("Qualification finished");
  } catch (error) {
    state.qualifyError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.qualify = false;
    render();
  }
}

function renderAudit() {
  const audit = state.audit;
  const summary = audit?.summary;
  const busy = state.busy.audit;

  $("#view-root").innerHTML = `
    <div class="section-head">
      <div>
        <h2>Two-sided audit</h2>
        <p>Run every gold patch, safe variant, and known-bad mutant through the gate. The report counts both false passes and false rejections.</p>
      </div>
      <button class="btn primary" type="button" data-action="audit" ${
        busy ? "disabled" : ""
      }>${busy ? spin("Running audit") : "Run full audit"}</button>
    </div>

    ${state.auditError ? `<div class="note warn">${escapeHtml(state.auditError)}</div>` : ""}
    ${
      summary
        ? `<div class="cards">
            ${metricCard("Verdict accuracy", pct(summary.verdict_accuracy), `${summary.correct_verdicts}/${summary.candidates} correct`, "accent")}
            ${metricCard("False passes", String(summary.false_passes), "known-bad variants accepted")}
            ${metricCard("False rejections", String(summary.false_rejections), "gold or benign variants rejected")}
            ${metricCard("Baseline", `${summary.baseline_ok}/${summary.tasks}`, "vulnerable fails PoC, fixed passes tests")}
          </div>

          <div class="cards">
            ${metricCard("Tasks", String(summary.tasks), `${summary.cwe_families} CWE families`)}
            ${metricCard("Gold accepted", `${summary.gold_accepted}/${summary.gold}`, "fixed implementations")}
            ${metricCard("Safe accepted", `${summary.benign_accepted}/${summary.benign}`, "benign refactors")}
            ${metricCard("Mutants rejected", `${summary.mutants_rejected}/${summary.mutants}`, "known-bad repairs")}
          </div>

          <div class="section-head"><div><h2>Task matrix</h2><p>Click a task id to open its source and candidates.</p></div></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Task</th><th>CWE</th><th>Baseline</th><th class="num">Gold</th><th class="num">Safe</th><th class="num">Mutants</th><th class="num">False pass</th><th class="num">False reject</th></tr></thead>
              <tbody>
                ${(audit.tasks || []).map(renderAuditRow).join("")}
              </tbody>
            </table>
          </div>

          ${renderAuditCheckers(summary.checkers || [])}

          <div class="split mt-18">
            <div class="card">
              <h2>Residual false passes</h2>
              <p class="muted small">A known-bad candidate accepted by the gate.</p>
              <div class="miss-list mt-12">${
                summary.false_pass_ids?.length
                  ? summary.false_pass_ids
                      .map((id) => `<span class="miss">${escapeHtml(id)}</span>`)
                      .join("")
                  : `<span class="miss good">none</span>`
              }</div>
            </div>
            <div class="card">
              <h2>Residual false rejections</h2>
              <p class="muted small">A safe candidate rejected by the gate.</p>
              <div class="miss-list mt-12">${
                summary.false_rejection_ids?.length
                  ? summary.false_rejection_ids
                      .map((id) => `<span class="miss">${escapeHtml(id)}</span>`)
                      .join("")
                  : `<span class="miss good">none</span>`
              }</div>
            </div>
          </div>

          <div class="note mt-18">
            These numbers describe this calibration pack. They do not prove the verifier catches every real-world vulnerability or outperforms every SAST tool.
          </div>`
        : `<div class="empty-panel"><strong>No audit has run yet</strong><span class="small">The full audit executes the exploit and functional tests for every candidate across all ${state.tasks.length} tasks. It can take a little while.</span></div>`
    }
  `;
}

function renderAuditRow(task) {
  const candidates = task.candidates || [];
  const gold = candidates.filter((candidate) => candidate.kind === "gold");
  const safe = candidates.filter((candidate) => candidate.kind === "benign");
  const mutants = candidates.filter((candidate) => candidate.kind === "mutant");
  const falsePass = mutants.filter((candidate) => candidate.accepted).length;
  const falseReject = [...gold, ...safe].filter((candidate) => !candidate.accepted).length;
  return `<tr>
    <td><button class="btn small ghost" type="button" data-action="open-task" data-task-id="${escapeHtml(
      task.task_id,
    )}">${escapeHtml(task.task_id)}</button></td>
    <td class="mono">${escapeHtml(task.cwe)}</td>
    <td>${task.baseline_ok ? pill("ok", "green") : pill("failed", "red")}</td>
    <td class="num mono">${gold.filter((candidate) => candidate.accepted).length}/${gold.length}</td>
    <td class="num mono">${safe.filter((candidate) => candidate.accepted).length}/${safe.length}</td>
    <td class="num mono">${mutants.length - falsePass}/${mutants.length}</td>
    <td class="num mono">${falsePass}</td>
    <td class="num mono">${falseReject}</td>
  </tr>`;
}

function renderAuditCheckers(checkers) {
  const measured = checkers.filter((checker) => checker.available);
  if (!measured.length) return "";
  return `<div class="section-head"><div><h2>Checker comparison inside the audit</h2><p>Recall on vulnerable and mutant files, precision on fixed and benign files, and how often a checker misses a bad repair.</p></div></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Checker</th><th>Version</th><th>Available</th><th class="num">Recall</th><th class="num">Precision</th><th class="num">False repair</th></tr></thead>
        <tbody>
          ${measured
            .map(
              (checker) => `<tr>
                <td class="mono">${escapeHtml(checker.name)}</td>
                <td class="mono">${escapeHtml(checker.version || "—")}</td>
                <td>${pill("yes", "green")}</td>
                <td class="num mono">${checker.recall_hits}/${checker.recall_total} · ${pct(checker.recall)}</td>
                <td class="num mono">${checker.precision_hits}/${checker.precision_total} · ${pct(checker.precision)}</td>
                <td class="num mono">${checker.missed_mutants}/${checker.mutants} · ${pct(checker.false_repair)}</td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

async function runAudit() {
  if (state.busy.audit) return;
  if (state.view !== "audit") {
    state.view = "audit";
    updateShell();
  }
  state.busy.audit = true;
  state.auditError = null;
  render();
  try {
    state.audit = await api("/api/audit", { method: "POST" });
    showToast("Full audit finished");
  } catch (error) {
    state.auditError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.audit = false;
    render();
  }
}

function renderReview() {
  if (!state.tasks.length) {
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>No tasks available</strong><span class="small">The model reviewer needs the task pack.</span></div>`;
    return;
  }

  ensureReviewSelection();
  const task = state.tasks.find((item) => item.task_id === state.reviewTask) || state.tasks[0];
  const candidates = task?.candidates || [];
  const candidate =
    candidates.find((item) => item.name === state.reviewCandidate) || candidates[0] || null;
  state.reviewTask = task?.task_id || null;
  state.reviewCandidate = candidate?.name || null;

  const keyReady = Boolean(state.health?.key_configured);
  const review = state.review;
  const reviewData = review?.review;

  $("#view-root").innerHTML = `
    <div class="section-head">
      <div>
        <h2>Live model review</h2>
        <p>Ask the model to review the same candidate the deterministic gate just ran. The model is advisory; the gate remains authoritative.</p>
      </div>
      ${pill(keyReady ? "key configured" : "key missing", keyReady ? "green" : "red")}
    </div>

    <div class="card">
      <div class="form-row">
        <div class="stack">
          <label class="metric-label" for="review-task">Task</label>
          <select class="select" id="review-task">
            ${state.tasks
              .map(
                (item) => `<option value="${escapeHtml(item.task_id)}" ${
                  item.task_id === state.reviewTask ? "selected" : ""
                }>${escapeHtml(item.task_id)} · ${escapeHtml(item.cwe)}</option>`,
              )
              .join("")}
          </select>
        </div>
        <div class="stack">
          <label class="metric-label" for="review-candidate">Candidate</label>
          <select class="select" id="review-candidate">
            ${(task?.candidates || [])
              .map(
                (item) => `<option value="${escapeHtml(item.name)}" ${
                  item.name === state.reviewCandidate ? "selected" : ""
                }>${escapeHtml(item.name)} · ${escapeHtml(item.kind)}</option>`,
              )
              .join("")}
          </select>
        </div>
        <div class="stack">
          <span class="metric-label">&nbsp;</span>
          <button class="btn primary" type="button" data-action="review" ${
            state.busy.review || !keyReady ? "disabled" : ""
          }>${state.busy.review ? spin("Reviewing") : "Run live review"}</button>
        </div>
      </div>
      ${
        keyReady
          ? `<div class="note mt-12">The prompt sends the vulnerable source, exploit, functional test, and candidate to <span class="code-inline">${escapeHtml(
              state.health?.model || "the configured model",
            )}</span>. The key stays on the server.</div>`
          : `<div class="note warn mt-12">No Groq key is configured. Set <span class="code-inline">ACV_GROQ_API_KEY</span> in the server environment to enable live review. The deterministic gate works without it.</div>`
      }
      ${state.reviewError ? `<div class="note warn mt-12">${escapeHtml(state.reviewError)}</div>` : ""}
    </div>

    ${
      state.busy.review
        ? `<div class="loading-panel mt-18"><span class="spinner"></span><span>Waiting for the model and running the deterministic gate…</span></div>`
        : reviewData
          ? renderReviewResult(review)
          : `<div class="empty-panel mt-18"><strong>No model review yet</strong><span class="small">Select a task and candidate, then run the live reviewer. You will see the model verdict next to the executable gate verdict.</span></div>`
    }
  `;
}

function renderReviewResult(review) {
  const data = review.review;
  const deterministic = review.deterministic;
  const tone = reviewTone(data.verdict);
  const findings = data.findings || [];
  const testGaps = data.test_gaps || [];
  const gateAccepted = Boolean(deterministic.accepted);
  return `<div class="result ${gateAccepted ? "accepted" : "rejected"} mt-18">
    <div class="result-top">
      <div class="result-title">
        ${pill(data.verdict.replaceAll("_", " "), tone)}
        ${pill(`${Math.round((data.confidence || 0) * 100)}% confidence`, "blue")}
        ${pill(`${review.model}`, "green")}
      </div>
      <div class="row">
        ${pill(`latency ${review.latency_ms} ms`, "")}
        ${pill(`${review.usage?.total_tokens ?? 0} tokens`, "")}
      </div>
    </div>

    <div class="kv-grid">
      ${kv("Gate verdict", gateAccepted ? "accepted" : "rejected")}
      ${kv("Model verdict", data.verdict.replaceAll("_", " "))}
      ${kv("Matches gate", review.llm_matches_gate === null ? "uncertain" : review.llm_matches_gate ? "yes" : "no")}
      ${kv("Matches label", review.llm_matches_truth === null ? "uncertain" : review.llm_matches_truth ? "yes" : "no")}
      ${kv("Candidate", `${review.candidate} · ${review.candidate_kind}`)}
      ${kv("Code size", `${review.code_chars} chars`)}
    </div>

    <div class="prose">
      <p><strong>Model summary.</strong> ${escapeHtml(data.summary || "")}</p>
      ${
        data.attack_path
          ? `<p><strong>Attack path.</strong> ${escapeHtml(data.attack_path)}</p>`
          : ""
      }
      ${data.reasoning ? `<p><strong>Reasoning.</strong> ${escapeHtml(data.reasoning)}</p>` : ""}
    </div>

    ${
      findings.length
        ? `<div><div class="metric-label">Model findings</div><div class="findings mt-12">${findings
            .map(
              (finding) => `<div class="finding ${escapeHtml(finding.severity || "info")}">
                <div class="finding-head">
                  <span class="finding-title">${escapeHtml(finding.issue || "Finding")}</span>
                  <span class="row">${pill(finding.cwe || "CWE", "blue")}${pill(
                    finding.severity || "info",
                    finding.severity === "high" ? "red" : "amber",
                  )}${finding.line ? pill(`line ${finding.line}`, "") : ""}</span>
                </div>
                <p>${escapeHtml(finding.evidence || "")}</p>
                ${finding.recommendation ? `<p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>` : ""}
              </div>`,
            )
            .join("")}</div></div>`
        : ""
    }

    ${
      testGaps.length
        ? `<div><div class="metric-label">Test gaps</div><ul class="list mt-12">${testGaps
            .map((gap) => `<li>${escapeHtml(gap)}</li>`)
            .join("")}</ul></div>`
        : ""
    }

    <details>
      <summary>Deterministic gate view</summary>
      <div class="kv-grid mt-12">
        ${kv("Accepted", deterministic.accepted ? "yes" : "no")}
        ${kv("Expected", deterministic.expected_accepted ? "safe" : "vulnerable")}
        ${kv("Correct", deterministic.correct ? "yes" : "no")}
        ${kv("Security", deterministic.security_pass ? "pass" : "fail")}
        ${kv("Behavior", deterministic.behavior_pass ? "pass" : "fail")}
        ${kv("Checker", deterministic.checker_pass ? "pass" : "fail")}
      </div>
      ${
        deterministic.reasons?.length
          ? `<ul class="reasons mt-12">${deterministic.reasons
              .map((reason) => `<li>${escapeHtml(reason)}</li>`)
              .join("")}</ul>`
          : ""
      }
      ${findingsTable(deterministic.findings || [])}
    </details>
  </div>`;
}

async function runReview() {
  if (state.busy.review) return;
  if (!state.reviewTask || !state.reviewCandidate) return;
  if (!state.health?.key_configured) {
    showToast("No Groq key is configured on the server", "error");
    return;
  }
  state.busy.review = true;
  state.reviewError = null;
  state.review = null;
  renderReview();
  try {
    state.review = await api("/api/review", {
      method: "POST",
      body: JSON.stringify({
        task_id: state.reviewTask,
        candidate: state.reviewCandidate,
      }),
    });
    showToast("Model review finished");
  } catch (error) {
    state.reviewError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.review = false;
    renderReview();
  }
}

window.addEventListener("DOMContentLoaded", init);
