"use strict";

const state = {
  view: "overview",
  health: null,
  tasks: [],
  projects: [],
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
  patchMode: "source",
  patchCode: "",
  patchSource: "",
  patchDirty: false,
  patchResult: null,
  patchError: null,
  builderText: "",
  builderStatus: null,
  builderError: null,
  builderBusy: false,
  repairTask: null,
  repairResult: null,
  repairError: null,
  project: null,
  projectFile: null,
  projectCode: "",
  projectResult: null,
  projectError: null,
  projectRunLabel: "",
  projectUpload: {},
  projectUploadNote: "",
  projectJson: "",
  projectMeta: {},
  projectCriticality: "standard",
  projectAck: false,
  projectAdvanced: false,
  runs: [],
  taskFilter: "",
  busy: {},
  error: null,
};

const VIEW_META = {
  overview: { eyebrow: "start / overview", title: "Overview" },
  guide: { eyebrow: "start / learn", title: "Start here" },
  tasks: { eyebrow: "use / examples", title: "Example tasks" },
  projects: { eyebrow: "use / scale", title: "Project verifier" },
  patch: { eyebrow: "use / check a patch", title: "Check a patch" },
  builder: { eyebrow: "use / add a task", title: "Add a task" },
  tools: { eyebrow: "advanced / checker tests", title: "Checker tests" },
  audit: { eyebrow: "advanced / full audit", title: "Full audit" },
  review: { eyebrow: "optional / second opinion", title: "Ask a model" },
  repair: { eyebrow: "optional / generated fix", title: "Generate a fix" },
};

const CANDIDATE_KINDS = {
  gold: {
    title: "Reference fix",
    tone: "green",
    explanation:
      "A known-good repair. The attack should be blocked and the normal behaviour tests should keep passing.",
  },
  benign: {
    title: "Safe alternative",
    tone: "blue",
    explanation:
      "A different safe implementation. It should also pass, even if it is not the exact reference answer.",
  },
  mutant: {
    title: "Incomplete fix",
    tone: "amber",
    explanation:
      "A deliberately flawed repair. It is expected to leave the attack working or fail a blocking check.",
  },
};

function candidateKindInfo(kind) {
  return (
    CANDIDATE_KINDS[kind] || {
      title: kind ? `Other candidate (${kind})` : "Candidate",
      tone: "",
      explanation: "An implementation that will be tested by the same deterministic gate.",
    }
  );
}

function candidateKindLabel(kind) {
  const info = candidateKindInfo(kind);
  return kind ? `${info.title} (${kind})` : info.title;
}

function candidateOptionLabel(candidate) {
  const info = candidateKindInfo(candidate.kind);
  return `${info.title} — ${candidate.name}`;
}

function candidateExpectation(candidate) {
  if (candidate.expected_security !== undefined) {
    return candidate.expected_security
      ? "should block the attack and keep normal behaviour working"
      : "should stay vulnerable";
  }
  return candidate.kind === "mutant"
    ? "should stay vulnerable"
    : "should block the attack and keep normal behaviour working";
}

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

function codeBlock(text, maxLines = 0) {
  let lines = String(text ?? "").replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const total = lines.length;
  const clipped = maxLines > 0 && total > maxLines;
  if (clipped) lines = lines.slice(0, maxLines);
  return `<div class="code">${lines
    .map(
      (line, index) =>
        `<span class="code-line"><span class="ln">${index + 1}</span><span class="src">${escapeHtml(
          line || " ",
        )}</span></span>`,
    )
    .join("")}</div>${
    clipped
      ? `<div class="code-note">Showing the first ${maxLines.toLocaleString()} of ${total.toLocaleString()} lines. The gate judged the complete file.</div>`
      : ""
  }`;
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

function verdictPill(accepted, noun = "PATCH") {
  return `<span class="verdict ${accepted ? "accepted" : "rejected"}">${
    accepted ? `${noun} ACCEPTED` : `${noun} REJECTED`
  }</span>`;
}

function plainVerdict(result) {
  if (result.oracle_ok === false) {
    return {
      tone: "warn",
      title: "This result cannot be trusted yet: the fixture check failed.",
      body:
        "The original attack did not work on the vulnerable source. That means the exploit is not proving anything, so the gate cannot fairly judge the patch. Fix the attack script or the vulnerable fixture first.",
    };
  }
  if (!result.security_pass) {
    return {
      tone: "bad",
      title: "Rejected because the attack still works.",
      body:
        "The original attack script was run against the patched code and it still succeeded. The vulnerability is still reachable. Open the attack output, find the code path it reached, and close that path.",
    };
  }
  if (!result.behavior_pass) {
    return {
      tone: "warn",
      title: "Rejected because normal behaviour broke.",
      body:
        "The attack is blocked, but the normal behaviour tests failed. A useful fix must stop the attack and keep the expected functionality working.",
    };
  }
  if (!result.checker_pass) {
    return {
      tone: "warn",
      title: "Rejected because the static checker found a blocking issue.",
      body:
        "The attack is blocked and the behaviour tests pass, but the checker still reports a serious pattern. The checker is evidence, not the whole truth: inspect the finding, then decide whether the code or the check needs attention.",
    };
  }
  if (result.accepted && result.expected_accepted === false) {
    return {
      tone: "warn",
      title: "Accepted, but the label says this candidate should fail.",
      body:
        "The gate accepted this code while the task label says it is an incomplete fix. Treat that as a calibration finding: it may be a false pass, or the label may be wrong. Inspect the code and the attack before using this result as evidence.",
    };
  }
  if (result.expected_accepted === true) {
    return {
      tone: "good",
      title: "Accepted: this matches the known-good label.",
      body:
        "The attack is blocked, the normal behaviour tests pass, and the checker reports no blocking finding. This is a real pass inside this task. It is still not proof that the code is secure in every possible environment.",
    };
  }
  return {
    tone: "good",
    title: "Accepted by the deterministic gate.",
    body:
      "The attack is blocked, the normal behaviour tests pass, and the checker reports no blocking finding. For custom code, this means it passed these tests; it does not prove the code is safe everywhere.",
  };
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
  const projectCount = state.projects.length;
  const projectEl = $("#env-projects");
  const projectNoun = projectCount === 1 ? "project" : "projects";
  if (projectEl) projectEl.textContent = `${projectCount} ${projectNoun}`;
  $("#env-api").textContent = health?.ok ? "online" : "offline";
  $("#workspace-meta").textContent = `${state.tasks.length} examples · ${candidates} candidate files · ${projectCount} ${projectNoun}`;
  if (health?.version) {
    $("#build-version").textContent = `v${health.version}`;
  }
  const status = $("#global-status");
  if (status) {
    status.textContent = health?.ok ? "API online" : "API offline";
    status.className = `status-pill ${health?.ok ? "online" : "offline"}`;
  }
  applyFeatureFlags();
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
  if (view === "builder" && !featureEnabled("task_import")) {
    showToast("Add a task is disabled on this server", "error");
    return;
  }
  if (view === "repair" && !featureEnabled("repair")) {
    showToast("Generate a fix is disabled on this server", "error");
    return;
  }
  if (view === "guide" && !featureEnabled("guided_workflow")) {
    showToast("Workflow guide is disabled on this server", "error");
    return;
  }
  if (view === "projects" && !featureEnabled("project_verification")) {
    showToast("Project verification is disabled on this server", "error");
    return;
  }
  state.view = view;
  if (view === "review") ensureReviewSelection();
  if (view === "repair") ensureRepairSelection();
  updateShell();
  if (view === "patch" && !state.patchDetail) {
    openPatchLab().catch((error) => showToast(error.message, "error"));
    return;
  }
  if (view === "builder" && !state.builderText) {
    loadTaskTemplate().catch((error) => showToast(error.message, "error"));
    return;
  }
  if (view === "projects" && !state.project && state.projects.length) {
    openProject(state.projects[0].project_id).catch((error) => showToast(error.message, "error"));
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

function ensureRepairSelection() {
  if (!state.tasks.length) {
    state.repairTask = null;
    return;
  }
  if (!state.tasks.some((task) => task.task_id === state.repairTask)) {
    state.repairTask = state.tasks[0].task_id;
  }
}

function featureEnabled(name) {
  return state.health?.features?.[name] !== false;
}

function applyFeatureFlags() {
  $$("[data-feature]").forEach((element) => {
    if (!featureEnabled(element.dataset.feature)) {
      element.remove();
    }
  });
  if (
    (state.view === "builder" && !featureEnabled("task_import")) ||
    (state.view === "repair" && !featureEnabled("repair")) ||
    (state.view === "projects" && !featureEnabled("project_verification")) ||
    (state.view === "guide" && !featureEnabled("guided_workflow"))
  ) {
    state.view = "overview";
  }
}

async function refreshCatalog() {
  const [health, tasks, tools] = await Promise.all([
    api("/api/health"),
    api("/api/tasks"),
    api("/api/tools"),
  ]);
  let projects = [];
  if (health?.features?.project_verification !== false) {
    try {
      projects = await api("/api/projects");
    } catch {
      projects = [];
    }
  }
  state.health = health;
  state.tasks = tasks;
  state.projects = projects;
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

function closeHeaderMenus(except = null) {
  $$(".nav-menu-wrap[open], .system-menu[open]").forEach((menu) => {
    if (!except || !menu.contains(except)) menu.removeAttribute("open");
  });
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const nav = event.target.closest("[data-view]");
    if (nav) {
      closeHeaderMenus();
      setView(nav.dataset.view);
      return;
    }

    closeHeaderMenus(event.target);

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
    if (target.id === "project-select") {
      openProject(target.value).catch((error) => showToast(error.message, "error"));
    }
    if (target.id === "project-files") {
      readProjectFiles(target).catch((error) => showToast(error.message, "error"));
    }
    if (target.id === "project-criticality") {
      state.projectCriticality = target.value;
      if (state.view === "projects") render();
    }
    if (target.id === "project-ack") {
      state.projectAck = target.checked;
    }
    if (target.id === "patch-mode") {
      state.patchMode = target.value;
      state.patchCode = "";
      state.patchSource = "";
      state.patchDirty = false;
      state.patchResult = null;
      state.patchError = null;
      renderPatchLab();
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
    if (target.id === "repair-task") {
      state.repairTask = target.value;
      state.repairResult = null;
      state.repairError = null;
      renderRepair();
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
    if (event.target.id === "builder-json") {
      state.builderText = event.target.value;
      state.builderStatus = null;
      state.builderError = null;
      const count = $("#builder-count");
      if (count) count.textContent = codeStats(state.builderText);
    }
    if (event.target.id === "project-json") {
      state.projectJson = event.target.value;
      state.projectError = null;
    }
    if (event.target.dataset && event.target.dataset.projectField) {
      state.projectMeta = {
        ...(state.projectMeta || {}),
        [event.target.dataset.projectField]: event.target.value,
      };
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
      showToast("Task list refreshed");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = "Refresh tasks";
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
    case "project-file":
      await loadProjectFile(element.dataset.path);
      break;
    case "project-run-candidate":
      await runProjectCandidate(element.dataset.candidate);
      break;
    case "project-run-baseline":
      await runProjectBaseline();
      break;
    case "project-run-generated":
      await runProjectGenerated();
      break;
    case "project-clear-overlay":
      state.projectUpload = {};
      state.projectJson = "";
      state.projectError = null;
      render();
      break;
    case "project-toggle-intake":
      state.projectAdvanced = !state.projectAdvanced;
      render();
      break;
    case "project-retry":
      state.projectError = null;
      await openProject(state.projects[0]?.project_id);
      break;
    case "open-patch":
      await openPatchLab(element.dataset.taskId || state.task?.task_id);
      break;
    case "quick-verify":
      await quickVerify();
      break;
    case "demo-safe":
      await runDemo("safe");
      break;
    case "demo-bad":
      await runDemo("bad");
      break;
    case "patch-load":
      loadPatchSource($("#patch-source")?.value || "vulnerable");
      break;
    case "patch-run":
      await runPatch();
      break;
    case "builder-template":
      await loadTaskTemplate();
      break;
    case "builder-validate":
      await validateTaskBundle();
      break;
    case "builder-import":
      await importTaskBundle();
      break;
    case "use-result-source":
      await useResultSource(element.dataset.taskId || state.task?.task_id);
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
    case "repair":
      await runRepair();
      break;
    case "repair-to-patch":
      await useRepairInPatch();
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
  if (state.view === "patch" && !state.patchDetail && state.tasks.length) {
    openPatchLab().catch((error) => showToast(error.message, "error"));
    return;
  }
  switch (state.view) {
    case "guide":
      renderGuide();
      break;
    case "tasks":
      renderTasks();
      break;
    case "projects":
      renderProjects();
      break;
    case "patch":
      renderPatchLab();
      break;
    case "builder":
      renderBuilder();
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
    case "repair":
      ensureRepairSelection();
      renderRepair();
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
  const quickCandidate = quickTask?.candidates.find(
    (candidate) => candidate.name === state.quickCandidate,
  );
  const candidateInfo = quickCandidate ? candidateKindInfo(quickCandidate.kind) : null;

  const quickTaskOptions = state.tasks
    .map(
      (task) => `<option value="${escapeHtml(task.task_id)}" ${
        task.task_id === quickTask?.task_id ? "selected" : ""
      }>${escapeHtml(task.task_id)} — ${escapeHtml(task.title)}</option>`,
    )
    .join("");
  const quickCandidateOptions = (quickTask?.candidates || [])
    .map(
      (candidate) => `<option value="${escapeHtml(candidate.name)}" ${
        candidate.name === state.quickCandidate ? "selected" : ""
      }>${escapeHtml(candidateOptionLabel(candidate))}</option>`,
    )
    .join("");
  const lastRun = state.runs[0];

  $("#view-root").innerHTML = `
    <section class="panel accent hero-panel">
      <div class="hero-copy">
        <div class="row between">
          <span class="pill green">start here</span>
          <span class="pill ${lastRun ? (lastRun.accepted ? "green" : "red") : ""}">${
            lastRun
              ? `last run: ${lastRun.accepted ? "accepted" : "rejected"}`
              : "no run in this session"
          }</span>
        </div>
        <h2>This site checks whether a security fix actually works.</h2>
        <p class="hero-lede">
          It runs real evidence against the code you give it: the original attack script,
          the normal behaviour tests, and a static checker. A patch is accepted only when
          every required check passes. The decision comes from that gate, not from how clean
          the code looks and not from what an AI model says.
        </p>
        <div class="hero-actions">
          <button class="btn primary" type="button" data-action="demo-safe" ${
            state.busy.verify ? "disabled" : ""
          }>${state.busy.verify ? spin("Running") : "See a known-good fix pass"}</button>
          <button class="btn danger" type="button" data-action="demo-bad" ${
            state.busy.verify ? "disabled" : ""
          }>See an incomplete fix fail</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="guide">Learn the words</button>
        </div>
        <p class="help">
          The two demo buttons open a real example, run the real gate, and show a plain-language
          explanation of the result. Nothing is faked.
        </p>
      </div>
      <div class="hero-side">
        <div class="mini-step">
          <span class="step-num">1</span>
          <div><strong>Check the test itself</strong><p>Does the attack work on the original vulnerable code? If not, the fixture is broken.</p></div>
        </div>
        <div class="mini-step">
          <span class="step-num">2</span>
          <div><strong>Attack the patched code</strong><p>Does the same attack still work? If yes, the vulnerability is still reachable.</p></div>
        </div>
        <div class="mini-step">
          <span class="step-num">3</span>
          <div><strong>Run normal behaviour tests</strong><p>A fix must not break the functionality the code is supposed to provide.</p></div>
        </div>
        <div class="mini-step">
          <span class="step-num">4</span>
          <div><strong>Ask the static checker</strong><p>The checker adds evidence about risky patterns. It is not the final judge.</p></div>
        </div>
      </div>
    </section>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Try a candidate</h2>
            <p>Pick an example task and one prepared candidate, then run the same gate used everywhere else.</p>
          </div>
          <span class="pill blue">real execution</span>
        </div>
        <div class="quick-run">
          <div class="stack">
            <label class="metric-label" for="quick-task">Example task</label>
            <select class="select" id="quick-task">${quickTaskOptions}</select>
          </div>
          <div class="stack">
            <label class="metric-label" for="quick-candidate">Candidate code</label>
            <select class="select" id="quick-candidate">${quickCandidateOptions}</select>
          </div>
          <button class="btn primary" type="button" data-action="quick-verify" ${
            state.busy.verify ? "disabled" : ""
          }>${state.busy.verify ? spin("Running") : "Run the gate"}</button>
        </div>
        ${
          quickCandidate && candidateInfo
            ? `<div class="candidate-explain mt-12">
                <strong>${escapeHtml(candidateKindLabel(quickCandidate.kind))}</strong>
                <span>${escapeHtml(candidateInfo.explanation)} Expected result: this candidate ${escapeHtml(
                  candidateExpectation(quickCandidate),
                )}.</span>
              </div>`
            : ""
        }
        <div class="row mt-12">
          <button class="btn ghost" type="button" data-action="open-patch" data-task-id="${escapeHtml(
            quickTask?.task_id || "",
          )}">Paste my own patch</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="tasks">Read the example code</button>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>What is loaded</h2>
            <p>The built-in pack is small on purpose. It teaches the verification mechanics.</p>
          </div>
          <span class="pill">${state.tasks.length ? "ready" : "empty"}</span>
        </div>
        <div class="stat-list">
          <div class="stat-row"><span>Example tasks</span><strong>${taskCount}</strong></div>
          <div class="stat-row"><span>Weakness categories</span><strong>${cweCount}</strong></div>
          <div class="stat-row"><span>Prepared candidate files</span><strong>${candidateCount}</strong></div>
          <div class="stat-row"><span>Static checkers installed</span><strong>${availableCheckers} / ${state.tools.length}</strong></div>
          <div class="stat-row"><span>Optional model review</span><strong>${
            state.health?.key_configured ? "configured" : "not configured"
          }</strong></div>
          <div class="stat-row"><span>Add your own task</span><strong>${
            featureEnabled("task_import") ? "enabled" : "disabled"
          }</strong></div>
        </div>
        <div class="notice mt-12">
          <strong>Scope.</strong> The loaded tasks are a calibration set for the verifier. They are
          not a public benchmark and they do not prove that every real-world vulnerability will be found.
        </div>
      </section>
    </div>

    ${
      state.projects.length && featureEnabled("project_verification")
        ? `<div class="dashboard-grid two">
            <section class="panel accent">
              <div class="panel-head">
                <div>
                  <h2>Beyond a 5-line fixture: verify a whole project</h2>
                  <p>A complete multi-file tree with imports, a service layer, tests, and a trusted exploit. Generated code can be uploaded from any model; it cannot replace its own judge.</p>
                </div>
                <span class="pill green">multi-file</span>
              </div>
              <div class="stat-list">
                <div class="stat-row"><span>Project</span><strong>${escapeHtml(state.projects[0].title)}</strong></div>
                <div class="stat-row"><span>Source files</span><strong>${escapeHtml(String(state.projects[0].files))}</strong></div>
                <div class="stat-row"><span>Lines judged</span><strong>${escapeHtml(String(state.projects[0].lines))}</strong></div>
                <div class="stat-row"><span>Candidate overlays</span><strong>${escapeHtml(String(state.projects[0].candidates.length))}</strong></div>
              </div>
              <div class="row mt-12">
                <button class="btn primary" type="button" data-action="go-view" data-target="projects">Open Project verifier</button>
                <button class="btn ghost" type="button" data-action="go-view" data-target="patch">Compare with single-file intake</button>
              </div>
            </section>
            <section class="panel">
              <div class="panel-head">
                <div>
                  <h2>What changes when the code gets large</h2>
                  <p>The gate stays deterministic. The evidence handling and the trust boundary change.</p>
                </div>
              </div>
              <div class="term-list">
                <div class="term"><strong>Scope is declared</strong><span>The manifest names the checker scope and size limits. Findings carry a file path and line.</span></div>
                <div class="term"><strong>Evidence stays outside</strong><span>The exploit and functional tests live outside the base tree, so a generated overlay cannot edit the judge.</span></div>
                <div class="term"><strong>Model output is data</strong><span>Any studio or local runner can produce a path-to-text overlay. The verifier never calls the model and never treats its confidence as a verdict.</span></div>
                <div class="term"><strong>Isolation is still a boundary</strong><span>Project execution uses process limits only. Critical or untrusted code belongs in a VM or container.</span></div>
              </div>
            </section>
          </div>`
        : ""
    }

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Recent runs</h2>
            <p>Everything you ran in this browser session. Click “Start here” for a guided explanation.</p>
          </div>
          <span class="pill">${state.runs.length} run${state.runs.length === 1 ? "" : "s"}</span>
        </div>
        ${renderRecentRuns(6)}
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Words made simple</h2>
            <p>These are the five terms you will see most often.</p>
          </div>
          <button class="btn ghost small" type="button" data-action="go-view" data-target="guide">Full guide</button>
        </div>
        <div class="term-list">
          <div class="term"><strong>Attack script</strong><span>Code that proves the vulnerability is reachable. Also called a PoC (proof of concept).</span></div>
          <div class="term"><strong>Fixture check</strong><span>Run the attack on the original vulnerable code first. It must succeed, otherwise the test is broken. Also called the oracle.</span></div>
          <div class="term"><strong>Candidate</strong><span>The code we are judging. It can be a full file or a patch/diff.</span></div>
          <div class="term"><strong>Reference fix</strong><span>A known-good repair. The task label calls this <span class="code-inline">gold</span>.</span></div>
          <div class="term"><strong>Incomplete fix</strong><span>A deliberately flawed repair. The task label calls this <span class="code-inline">mutant</span>.</span></div>
        </div>
      </section>
    </div>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Optional and advanced</h2>
            <p>These pages measure the tooling itself, or ask a model for a second opinion.</p>
          </div>
        </div>
        <div class="row">
          <button class="btn ghost" type="button" data-action="go-view" data-target="tools">Test the checkers</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="audit">Run the full audit</button>
          ${
            featureEnabled("repair")
              ? `<button class="btn ghost" type="button" data-action="go-view" data-target="repair">Ask a model for a fix</button>`
              : ""
          }
          <button class="btn ghost" type="button" data-action="go-view" data-target="review">Ask a model to review</button>
        </div>
        <div class="notice mt-12">
          Model output is advisory. It can explain a weakness or propose code, but the executable
          gate still decides whether the code is accepted.
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Last measurements</h2>
            <p>Only filled in after you run the advanced checks.</p>
          </div>
        </div>
        ${
          audit || best
            ? `<div class="stat-list">
                ${
                  best
                    ? `<div class="stat-row"><span>Best checker F1 on this pack</span><strong>${pct(
                        best.f1,
                      )} · ${escapeHtml(best.tool)}</strong></div>`
                    : ""
                }
                ${
                  audit
                    ? `<div class="stat-row"><span>Audit verdict accuracy</span><strong>${pct(
                        audit.verdict_accuracy,
                      )}</strong></div>
                       <div class="stat-row"><span>False passes</span><strong>${audit.false_passes}</strong></div>
                       <div class="stat-row"><span>False rejections</span><strong>${audit.false_rejections}</strong></div>`
                    : ""
                }
              </div>`
            : `<div class="notice">No advanced measurement has run in this session. Start with the examples; the extra measurements are not required to use the verifier.</div>`
        }
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
    mode: "catalog",
    ...entry,
  });
  state.runs = state.runs.slice(0, 12);
}

function renderRecentRuns(limit = 6) {
  const runs = state.runs.slice(0, limit);
  if (!runs.length) {
    return `<div class="notice">No gate runs in this browser session. Start with a candidate above or open Check a patch.</div>`;
  }
  return `<div class="run-list">
    ${runs
      .map(
        (run) => `<div class="run-row">
          <span class="run-time">${escapeHtml(formatRunTime(run.at))}</span>
          <span class="run-target"><strong>${escapeHtml(run.taskId)}</strong> <span>${escapeHtml(
            run.candidate,
          )}</span> <span class="run-mode">${escapeHtml(run.mode || run.source)}</span></span>
          <span>${run.accepted ? pill("accepted", "green") : pill("rejected", "red")}</span>
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

function renderGuide() {
  const step = (number, title, body) => `<div class="workflow-step">
    <span class="step-num">${number}</span>
    <div>
      <strong>${title}</strong>
      <p>${body}</p>
    </div>
  </div>`;
  const importEnabled = featureEnabled("task_import");
  const repairEnabled = featureEnabled("repair");
  const keyReady = Boolean(state.health?.key_configured);
  $("#view-root").innerHTML = `
    <section class="panel accent hero-panel">
      <div class="hero-copy">
        <span class="pill green">plain-language guide</span>
        <h2>How this works, from start to finish</h2>
        <p class="hero-lede">
          This is a checking tool, not a code generator. You give it a piece of code that is
          supposed to fix a security weakness. It runs an attack, runs normal tests, and asks a
          static checker. Then it tells you whether the fix passed <em>this</em> evidence.
        </p>
        <div class="hero-actions">
          <button class="btn primary" type="button" data-action="demo-safe">Run a known-good example</button>
          <button class="btn danger" type="button" data-action="demo-bad">Run an incomplete example</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="tasks">Open the example code</button>
        </div>
      </div>
      <div class="hero-side">
        <div class="mini-step">
          <span class="step-num">A</span>
          <div><strong>One task = one weakness</strong><p>A task contains vulnerable code, an attack script, normal tests, and prepared candidates.</p></div>
        </div>
        <div class="mini-step">
          <span class="step-num">B</span>
          <div><strong>One gate = four checks</strong><p>Fixture, attack, behaviour, and checker. All required checks must pass.</p></div>
        </div>
        <div class="mini-step">
          <span class="step-num">C</span>
          <div><strong>One verdict = one reason</strong><p>When a patch is rejected, the result tells you which check failed first.</p></div>
        </div>
      </div>
    </section>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>The 60-second version</h2>
            <p>Read this first if you do not want the details yet.</p>
          </div>
          <span class="pill green">simple</span>
        </div>
        <div class="workflow">
          ${step(
            1,
            "Pick a real example",
            "Open Example tasks. Read the original vulnerable code, then the attack script, then the normal tests. The candidate is the code you are judging.",
          )}
          ${step(
            2,
            "Run a known result",
            "Run the reference fix. It should be accepted. Run the incomplete fix. It should be rejected. That tells you the example itself is working.",
          )}
          ${step(
            3,
            "Paste your own fix",
            "Open Check a patch. Use a full file or a unified diff. Run the gate. You do not need to know the internals to use this.",
          )}
          ${step(
            4,
            "Read the plain-language reason",
            "Accepted means every required check passed. Rejected means one check failed. The result explains the failing check in ordinary language and keeps the technical output below it.",
          )}
        </div>
        <div class="notice mt-12">
          <strong>The model is optional.</strong> You can use Ask a model for a second opinion or
          Generate a fix for a proposal. Neither one can change the gate verdict.
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>What each check means</h2>
            <p>The gate is a fixed rule. The order matters.</p>
          </div>
        </div>
        <div class="check-list">
          <div class="check-item good">
            <strong>1. Fixture check (oracle)</strong>
            <span>Run the attack against the original vulnerable code. It must succeed. If it does not, the test is broken and no patch can be judged fairly.</span>
          </div>
          <div class="check-item good">
            <strong>2. Attack check</strong>
            <span>Run the same attack against your candidate. It must fail. If it still succeeds, the vulnerability is still reachable.</span>
          </div>
          <div class="check-item blue">
            <strong>3. Behaviour check</strong>
            <span>Run the normal tests. They must pass. A fix that breaks the program is not a useful fix.</span>
          </div>
          <div class="check-item amber">
            <strong>4. Static checker</strong>
            <span>Look for risky code patterns. A blocking finding rejects the patch. The checker adds evidence; it is not the whole truth.</span>
          </div>
        </div>
        <div class="notice mt-12">
          <strong>Exact rule:</strong> accepted only when fixture check passes, attack is blocked,
          behaviour tests pass, and the checker has no blocking finding.
        </div>
      </section>
    </div>

    <div class="dashboard-grid one">
      <section class="panel accent">
        <div class="panel-head">
          <div>
            <h2>When the code is large, multi-file, or newly generated</h2>
            <p>The project verifier is the same gate with a complete tree instead of one worker file.</p>
          </div>
          <span class="pill green">project path</span>
        </div>
        <div class="workflow workflow-compact">
          ${step(
            1,
            "Open a project",
            "Project verifier loads a complete base tree. Read the file list and click a file to inspect the real source, not a summary.",
          )}
          ${step(
            2,
            "Run the known results",
            "Run the reference fix and the incomplete fix. The reference should pass; the incomplete one should fail. This proves the project evidence is alive.",
          )}
          ${step(
            3,
            "Bring generated files",
            "Upload files or paste a path-to-text JSON overlay from any model or studio. The verifier does not call the model and does not read its confidence.",
          )}
          ${step(
            4,
            "Read file-level evidence",
            "The result shows the four signals, the changed files, findings with file paths and line numbers, size limits, and the isolation warning.",
          )}
        </div>
        <div class="row mt-12">
          <button class="btn primary" type="button" data-action="go-view" data-target="projects">Open Project verifier</button>
          <span class="small">The exploit and functional tests live outside the base tree, so generated code cannot replace its own judge.</span>
        </div>
      </section>
    </div>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>A concrete example</h2>
            <p>This is the built-in redirect-SSRF task.</p>
          </div>
          <span class="pill blue">CWE-918</span>
        </div>
        <p class="prose">
          The vulnerable code checks the first URL against an allowlist, but it follows redirects
          without checking where they go. An attacker can start at an allowed host and redirect
          the server to an internal address.
        </p>
        <div class="example-grid mt-12">
          <div class="example-card good">
            <strong>Reference fix — should pass</strong>
            <span>The destination is checked again after redirects. The attack is blocked, normal requests still work, and the checker is clean.</span>
          </div>
          <div class="example-card bad">
            <strong>Incomplete fix — should fail</strong>
            <span>The first URL is checked, but redirects are still followed blindly. The attack succeeds, so the gate rejects it even if the code looks tidy.</span>
          </div>
        </div>
        <div class="row mt-12">
          <button class="btn ghost" type="button" data-action="demo-safe">Run the good one</button>
          <button class="btn ghost" type="button" data-action="demo-bad">Run the incomplete one</button>
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>Your first 10 minutes</h2>
            <p>Do this once and the rest of the site will make sense.</p>
          </div>
        </div>
        <ol class="prose guide-list">
          <li>Open <strong>Example tasks</strong> and read the original vulnerable code.</li>
          <li>Open the <strong>attack script</strong> tab. Follow what input it sends.</li>
          <li>Open the <strong>reference fix</strong> candidate and run the gate. You should see accepted.</li>
          <li>Switch to an <strong>incomplete fix</strong> and run the gate. You should see rejected.</li>
          <li>Read the plain-language rejection box. Find the check that failed.</li>
          <li>Open <strong>Check a patch</strong> and paste any small change. Run it.</li>
          <li>Run the <strong>full audit</strong> only when you want to measure the gate over the whole pack.</li>
        </ol>
        <div class="row mt-12">
          <button class="btn primary" type="button" data-action="go-view" data-target="tasks">Start with examples</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="patch">Go to Check a patch</button>
        </div>
      </section>
    </div>

    <section class="panel mt-12">
      <div class="panel-head">
        <div>
          <h2>Words used on this site</h2>
          <p>You can ignore the internal names once you know what they mean.</p>
        </div>
        <span class="pill">glossary</span>
      </div>
      <div class="glossary">
        ${glossaryRow("Task", "One vulnerability example: vulnerable code, attack script, normal tests, and labelled candidates.")}
        ${glossaryRow("Vulnerable source", "The original code that contains the weakness. It is the starting point, not the fix.")}
        ${glossaryRow("Attack script / PoC", "Short for proof of concept. Code that proves the weakness is reachable. It should succeed on vulnerable code and fail on a good fix.")}
        ${glossaryRow("Fixture check / oracle", "A check that the attack works on the vulnerable source. This stops us from trusting a broken test.")}
        ${glossaryRow("Behaviour test", "Normal tests that check the program still does its intended job.")}
        ${glossaryRow("Candidate", "The code being judged. It can be a full replacement or a unified diff.")}
        ${glossaryRow("Reference fix (gold)", "A known-good repair supplied with the task. Use it to check that the task works.")}
        ${glossaryRow("Safe alternative (benign)", "A different safe repair. It should also pass, even if it is not the reference answer.")}
        ${glossaryRow("Incomplete fix (mutant)", "A deliberately flawed repair. It is expected to be rejected.")}
        ${glossaryRow("Gate", "The fixed decision rule that combines fixture, attack, behaviour, and checker results.")}
        ${glossaryRow("Checker", "A static analysis tool that looks for risky code patterns. It is evidence, not the final judge.")}
        ${glossaryRow("CWE", "A standard category for a type of software weakness, such as CWE-78 command injection or CWE-918 SSRF.")}
        ${glossaryRow("False pass", "Bad code that the gate accepted. This is a serious calibration failure.")}
        ${glossaryRow("False rejection", "Good code that the gate rejected. This is also a calibration failure, but it does not mean the code is unsafe.")}
      </div>
    </section>

    <div class="dashboard-grid two">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>How we use it as a team</h2>
            <p>A practical handover without a long document.</p>
          </div>
        </div>
        <ol class="prose guide-list">
          <li><strong>One person prepares a task.</strong> The task needs a real vulnerability, an attack that proves it, normal behaviour tests, and at least one known-good fix.</li>
          <li><strong>Another person checks the fixture.</strong> Run the attack on vulnerable code. It must succeed. If it does not, fix the test before judging any patch.</li>
          <li><strong>Run the reference fix.</strong> It must be accepted. If not, the task or the checker is inconsistent.</li>
          <li><strong>Run an incomplete fix.</strong> It should be rejected. This proves the gate is not just accepting everything.</li>
          <li><strong>Then test the candidate.</strong> Record the task, candidate, verdict, and the first failing check. Do not record only “safe” or “unsafe”.</li>
          <li><strong>Use the model only as a note.</strong> If the model disagrees with the gate, record the disagreement; do not overwrite the verdict.</li>
          <li><strong>Add new tasks through Add a task.</strong> Keep the same shape: vulnerable, attack, behaviour tests, and candidates.</li>
        </ol>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div>
            <h2>What a result does and does not mean</h2>
            <p>Keep the claim narrow when you explain it to others.</p>
          </div>
          <span class="pill">scope</span>
        </div>
        <div class="example-grid">
          <div class="example-card good">
            <strong>It does mean</strong>
            <span>The candidate passed the attack, behaviour, and checker evidence for this task. The task fixture was valid when the run started.</span>
          </div>
          <div class="example-card bad">
            <strong>It does not mean</strong>
            <span>The code is secure in every environment, that all vulnerabilities were found, or that the candidate is semantically identical to the reference fix.</span>
          </div>
        </div>
        <ul class="prose guide-list mt-12">
          <li>It is not a universal vulnerability detector.</li>
          <li>It is not a production sandbox: process limits are active, but there is no network or filesystem jail.</li>
          <li>It is not a benchmark of real-world repositories yet. The built-in tasks are a calibration set.</li>
          <li>It does not let a model's confidence become a verdict.</li>
        </ul>
        <div class="notice mt-12">
          <strong>For the research work:</strong> report the task, model, quantization level,
          checker, and gate decision together. A CWE label from one tool is not the same thing as
          a proven vulnerability.
        </div>
      </section>
    </div>

    <section class="panel mt-12">
      <div class="panel-head">
        <div>
          <h2>Where to click next</h2>
          <p>Pick the question you are actually asking.</p>
        </div>
        <div class="row">
          <button class="btn primary" type="button" data-action="go-view" data-target="patch">Check a patch</button>
          <button class="btn ghost" type="button" data-action="go-view" data-target="tasks">Read examples</button>
        </div>
      </div>
      <div class="stat-list">
        <div class="stat-row"><span>Is this patch fixed?</span><strong>Check a patch</strong></div>
        <div class="stat-row"><span>What is the vulnerable code?</span><strong>Example tasks</strong></div>
        <div class="stat-row"><span>Can I add a new task?</span><strong>${importEnabled ? "Add a task" : "disabled"}</strong></div>
        <div class="stat-row"><span>Can a model propose a fix?</span><strong>${repairEnabled ? (keyReady ? "Generate a fix" : "key missing") : "disabled"}</strong></div>
        <div class="stat-row"><span>How good is the checker?</span><strong>Checker tests (advanced)</strong></div>
        <div class="stat-row"><span>How good is the gate?</span><strong>Full audit (advanced)</strong></div>
      </div>
    </section>
  `;
}

function glossaryRow(term, definition) {
  return `<div class="glossary-row"><strong>${escapeHtml(term)}</strong><span>${escapeHtml(
    definition,
  )}</span></div>`;
}

async function loadTaskTemplate() {
  state.builderBusy = true;
  state.builderError = null;
  if (state.view === "builder") renderBuilder();
  try {
    const bundle = await api("/api/tasks/template");
    state.builderText = JSON.stringify(bundle, null, 2);
    state.builderStatus = {
      kind: "info",
      message:
        "Loaded an editable example. Change the task id and the code before importing, or use it as a shape to copy.",
    };
  } catch (error) {
    state.builderError = error.message;
  } finally {
    state.builderBusy = false;
    if (state.view === "builder") renderBuilder();
  }
}

function parseBuilderBundle() {
  try {
    const bundle = JSON.parse(state.builderText);
    if (!bundle || typeof bundle !== "object" || !bundle.manifest || !bundle.files) {
      throw new Error("Bundle must contain a manifest object and a files object.");
    }
    return bundle;
  } catch (error) {
    throw new Error(`Invalid bundle JSON: ${error.message}`);
  }
}

async function validateTaskBundle() {
  if (!state.builderText.trim() || state.builderBusy) return;
  state.builderBusy = true;
  state.builderError = null;
  state.builderStatus = null;
  renderBuilder();
  try {
    const bundle = parseBuilderBundle();
    const result = await api("/api/tasks/validate", {
      method: "POST",
      body: JSON.stringify(bundle),
    });
    state.builderStatus = {
      kind: "success",
      message: `Bundle is valid: ${result.task_id} · ${result.files.length} files · ${result.candidates.length} candidates.`,
    };
  } catch (error) {
    state.builderError = error.message;
  } finally {
    state.builderBusy = false;
    renderBuilder();
  }
}

async function importTaskBundle() {
  if (!state.builderText.trim() || state.builderBusy) return;
  state.builderBusy = true;
  state.builderError = null;
  state.builderStatus = null;
  renderBuilder();
  try {
    const bundle = parseBuilderBundle();
    const result = await api("/api/tasks/import", {
      method: "POST",
      body: JSON.stringify(bundle),
    });
    await refreshCatalog();
    state.builderStatus = {
      kind: "success",
      message: `Added ${result.task.task_id}. It is now available under Example tasks and Check a patch.`,
    };
  } catch (error) {
    state.builderError = error.message;
  } finally {
    state.builderBusy = false;
    renderBuilder();
  }
}

function renderBuilder() {
  let parsed = null;
  let required = [];
  try {
    parsed = parseBuilderBundle();
    const manifest = parsed.manifest;
    required = [
      ...new Set(
        [
          manifest.vulnerable,
          manifest.fixed,
          manifest.poc,
          manifest.functional,
          ...(manifest.candidates || []).map((candidate) => candidate.path),
        ].filter(Boolean),
      ),
    ];
  } catch {
    parsed = null;
  }

  $("#view-root").innerHTML = `
    <div class="section-head intro-only">
      <div>
        <p>Add a new vulnerability example without editing the built-in pack. The bundle is checked as data, then written to your user pack. Importing does not execute the code.</p>
      </div>
      <div class="toolbar">
        <button class="btn ghost" type="button" data-action="builder-template" ${
          state.builderBusy ? "disabled" : ""
        }>${state.builderBusy ? spin("Loading") : "Load an example"}</button>
        <button class="btn ghost" type="button" data-action="builder-validate" ${
          state.builderBusy || !state.builderText.trim() ? "disabled" : ""
        }>Check the bundle</button>
        <button class="btn primary" type="button" data-action="builder-import" ${
          state.builderBusy || !state.builderText.trim() ? "disabled" : ""
        }>${state.builderBusy ? spin("Working") : "Add the task"}</button>
      </div>
    </div>

    <div class="notice">
      <strong>What a task needs.</strong> The bundle contains a
      <span class="code-inline">manifest</span> (the labels) and a
      <span class="code-inline">files</span> object (the code). Each task needs the original
      vulnerable file, an attack script, normal behaviour tests, and at least one known-good
      repair. <span class="code-inline">task.json</span> is generated automatically.
    </div>

    ${
      state.builderError
        ? `<div class="notice warning">${escapeHtml(state.builderError)}</div>`
        : ""
    }
    ${
      state.builderStatus
        ? `<div class="notice ${state.builderStatus.kind === "success" ? "" : "warning"}">${escapeHtml(
            state.builderStatus.message,
          )}</div>`
        : ""
    }

    <div class="lab-layout mt-12">
      <section class="panel editor-panel">
        <div class="panel-head">
          <div>
            <h2>Task bundle JSON</h2>
            <p>${parsed ? `${escapeHtml(parsed.manifest.id || "unnamed")} · ${required.length} required files` : "Edit or load an example bundle"}</p>
          </div>
          <span class="pill blue">data only</span>
        </div>
        <textarea id="builder-json" class="editor" spellcheck="false" aria-label="Task bundle JSON">${escapeHtml(
          state.builderText,
        )}</textarea>
        <div class="editor-foot">
          <span id="builder-count">${codeStats(state.builderText)}</span>
          <span>Use Validate or Import after editing</span>
        </div>
      </section>

      <section class="lab-result stack">
        <div class="panel">
          <div class="panel-head">
            <h2>Bundle map</h2>
            <span class="pill">${parsed ? "parsed" : "not parsed"}</span>
          </div>
          <div class="stat-list">
            <div class="stat-row"><span>Task id</span><strong>${escapeHtml(parsed?.manifest?.id || "—")}</strong></div>
            <div class="stat-row"><span>CWE</span><strong>${escapeHtml(parsed?.manifest?.cwe || "—")}</strong></div>
            <div class="stat-row"><span>Files</span><strong>${parsed ? Object.keys(parsed.files || {}).length : 0}</strong></div>
            <div class="stat-row"><span>Required</span><strong>${required.length}</strong></div>
          </div>
          ${
            required.length
              ? `<div class="stack mt-12">${required
                  .map(
                    (path) =>
                      `<div class="stat-row"><span>${escapeHtml(path)}</span><strong>${
                        parsed.files[path] !== undefined ? "present" : "missing"
                      }</strong></div>`,
                  )
                  .join("")}</div>`
              : ""
          }
        </div>

        <div class="panel">
          <div class="panel-head">
            <h2>After import</h2>
            <span class="pill green">reusable</span>
          </div>
          <ul class="prose guide-list">
            <li>The task appears under Example tasks and Check a patch.</li>
            <li>Its exploit and tests run through the same constrained gate.</li>
            <li>Imported tasks live in the user pack, not the built-in calibration pack.</li>
            <li>Validation checks structure and paths; it is not a security review.</li>
          </ul>
        </div>
      </section>
    </div>
  `;
}

function renderTasks() {
  $("#view-root").innerHTML = `
    <div class="section-head intro-only">
      <div>
        <p>Open one example to read the weakness, the attack that proves it, the normal behaviour test, and the prepared candidates. Run any candidate through the same gate.</p>
      </div>
      <div class="toolbar">
        <input id="task-filter" class="search" type="search" placeholder="Search examples…" value="${escapeHtml(
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
  if (!state.tasks.length && !state.error) {
    container.innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading examples…</span></div>`;
    return;
  }
  const needle = state.taskFilter.trim().toLowerCase();
  const tasks = state.tasks.filter((task) =>
    `${task.task_id} ${task.title} ${task.cwe}`.toLowerCase().includes(needle),
  );
  if (!tasks.length) {
    container.innerHTML = `<div class="empty-panel"><strong>No matching examples</strong><span class="small">Clear the search or refresh the list.</span></div>`;
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
      label: "1. Original vulnerable code",
      path: task.paths?.vulnerable,
      text: task.code?.vulnerable,
    },
    exploit: {
      label: "2. Attack script",
      path: task.paths?.poc,
      text: task.code?.exploit,
    },
    functional: {
      label: "3. Behaviour test",
      path: task.paths?.functional,
      text: task.code?.functional,
    },
    candidate: {
      label: candidate ? `4. Candidate: ${candidate.name}` : "4. Candidate",
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
      }>${escapeHtml(candidateOptionLabel(item))} — ${
        item.expected_security ? "expected to pass" : "expected to fail"
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
        <label class="metric-label" for="candidate-select">Candidate to test</label>
        <select class="select" id="candidate-select">${candidateOptions}</select>
        <div class="row">
          <button class="btn primary" type="button" data-action="verify" ${
            state.busy.verify ? "disabled" : ""
          }>${state.busy.verify ? spin("Running gate") : "Run the gate"}</button>
          <button class="btn ghost" type="button" data-action="open-patch" data-task-id="${escapeHtml(
            task.task_id,
          )}">Paste in Check a patch</button>
          <button class="btn ghost" type="button" data-action="switch-review">Ask a model</button>
        </div>
      </div>
    </div>

    <div class="notice">
      <strong>Read the tabs from left to right.</strong> Start with the original weakness, then
      see how the attack triggers it, then see what normal behaviour must keep working. The fourth
      tab is the code you are judging.
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
        ? `<div class="candidate-explain">
            <strong>${escapeHtml(candidateKindLabel(candidate.kind))}</strong>
            <span>${escapeHtml(candidateKindInfo(candidate.kind).explanation)} Expected result:
            this candidate ${escapeHtml(candidateExpectation(candidate))}.
            ${candidate.expected_behavior ? "Normal behaviour should stay the same." : "Normal behaviour may change."}
            ${escapeHtml(candidate.note || "")}</span>
          </div>`
        : ""
    }

    ${state.verifyError ? `<div class="note warn">${escapeHtml(state.verifyError)}</div>` : ""}
    ${
      state.verify
        ? renderVerifyResult(state.verify)
        : `<div class="empty-panel"><strong>No gate result yet</strong><span class="small">Run the gate to execute the attack script, run the normal behaviour tests, and collect checker findings.</span></div>`
    }
  `;
}

function rejectedBy(result) {
  if (result.accepted) return "none — accepted";
  if (result.oracle_ok === false) return "fixture check (oracle)";
  if (!result.security_pass) return "attack still works";
  if (!result.behavior_pass) return "normal behaviour tests";
  if (!result.checker_pass) return "static checker";
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
    <summary>All checker output (advanced)</summary>
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
  const explanation = plainVerdict(result);
  const inputMode =
    result.input_mode === "diff"
      ? "unified diff"
      : result.input_mode === "source"
        ? "full source file"
        : result.name && result.name !== "custom"
          ? "prepared candidate"
          : "submitted code";
  return `<div class="result ${accepted ? "accepted" : "rejected"}">
    <div class="result-top">
      <div class="result-title">
        ${verdictPill(accepted)}
        <strong>${escapeHtml(result.name || "custom code")}</strong>
        ${
          labeled
            ? correct
              ? pill("matches the label", "green")
              : pill("does not match the label", "red")
            : pill("no ground-truth label", "blue")
        }
      </div>
      <div class="row">
        ${pill(result.security_pass ? "attack blocked" : "attack still works", result.security_pass ? "green" : "red")}
        ${pill(result.behavior_pass ? "behaviour passes" : "behaviour fails", result.behavior_pass ? "green" : "red")}
        ${
          result.oracle_ok !== undefined
            ? pill(
                result.oracle_ok ? "fixture check passed" : "fixture check failed",
                result.oracle_ok ? "green" : "red",
              )
            : ""
        }
        ${pill(`checker: ${result.checker_tool || "default"}`, result.checker_pass ? "green" : "amber")}
      </div>
    </div>

    <div class="plain-verdict ${escapeHtml(explanation.tone)}">
      <strong>${escapeHtml(explanation.title)}</strong>
      <p>${escapeHtml(explanation.body)}</p>
    </div>

    <div class="kv-grid">
      ${
        labeled
          ? kv("Label says", result.expected_accepted ? "safe fix / should pass" : "still vulnerable / should fail")
          : kv("Label", "none — custom input")
      }
      ${
        result.oracle_ok !== undefined
          ? kv("Fixture check", result.oracle_ok ? "passed — attack works on original" : "failed — attack does not work on original")
          : ""
      }
      ${kv("Attack result", result.security_pass ? "blocked by the patch" : "still succeeds")}
      ${kv("Normal behaviour", result.behavior_pass ? "passes" : "fails")}
      ${kv("Static checker", result.checker_pass ? "no blocking finding" : "blocking finding")}
      ${kv("Deciding check", accepted ? "all required checks passed" : rejectedBy(result))}
      ${kv("Code supplied as", inputMode)}
      ${result.diff_applied !== undefined ? kv("Diff applied", result.diff_applied ? "yes" : "no") : ""}
      ${result.elapsed_ms !== undefined ? kv("Time", `${result.elapsed_ms} ms`) : ""}
    </div>

    ${
      result.candidate_code && state.view !== "patch"
        ? `<div class="row">
            <button class="btn ghost small" type="button" data-action="use-result-source" data-task-id="${escapeHtml(
              result.task_id,
            )}">Open the tested code in Check a patch</button>
          </div>`
        : ""
    }

    ${
      !labeled
        ? `<div class="notice"><strong>This code has no ground-truth label.</strong> Acceptance means it passed the fixture, attack, behaviour, and checker evidence for this task. It does not prove the code is semantically identical to a reference repair or secure in every environment.</div>`
        : ""
    }
    ${
      reasons.length
        ? `<details open>
            <summary>Technical gate messages</summary>
            <ul class="reasons mt-12">${reasons
              .map((reason) => `<li>${escapeHtml(reason)}</li>`)
              .join("")}</ul>
          </details>`
        : ""
    }
    ${findingsTable(result.findings)}

    <details>
      <summary>Code that was tested</summary>
      ${result.candidate_code ? codeBlock(result.candidate_code) : `<div class="output">(source not returned)</div>`}
    </details>
    <details>
      <summary>Patch that was applied</summary>
      <div class="output">${escapeHtml(result.applied_diff || "(no diff)")}</div>
    </details>
    <details>
      <summary>Attack output</summary>
      <div class="output">${escapeHtml(result.poc_output || "(no output)")}</div>
    </details>
    <details>
      <summary>Normal behaviour test output</summary>
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
      mode: "catalog",
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

async function runDemo(kind) {
  if (state.busy.verify || !state.tasks.length) return;
  const task =
    state.tasks.find((item) => item.task_id === "ssrf_redirect") || state.tasks[0] || null;
  if (!task) {
    showToast("No example task is available", "error");
    return;
  }
  const candidate =
    kind === "safe"
      ? task.candidates.find((item) => item.kind === "gold") || task.candidates[0]
      : task.candidates.find((item) => item.kind === "mutant") ||
        task.candidates.find((item) => !item.expected_security);
  if (!candidate) {
    showToast("This example task does not have that kind of candidate", "error");
    return;
  }
  state.quickTask = task.task_id;
  state.quickCandidate = candidate.name;
  showToast(
    kind === "safe"
      ? `Running the known-good fix: ${candidate.name}`
      : `Running an incomplete fix: ${candidate.name}`,
  );
  await quickVerify();
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
  state.patchMode = "source";
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
  if (state.patchMode !== "source") return;
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

function currentResultFor(taskId) {
  if (state.patchResult?.task_id === taskId && state.patchResult?.candidate_code) {
    return state.patchResult;
  }
  if (state.verify?.task_id === taskId && state.verify?.candidate_code) {
    return state.verify;
  }
  if (state.repairResult?.gate?.task_id === taskId && state.repairResult.gate?.candidate_code) {
    return state.repairResult.gate;
  }
  return null;
}

async function useResultSource(taskId) {
  const result = currentResultFor(taskId);
  if (!result?.candidate_code) {
    showToast("No evaluated source is available for this task", "error");
    return;
  }
  state.view = "patch";
  updateShell();
  await openPatchLab(taskId);
  state.patchMode = "source";
  state.patchCode = result.candidate_code;
  state.patchSource = "evaluated result";
  state.patchDirty = true;
  state.patchResult = result;
  state.patchError = null;
  renderPatchLab();
}

async function runPatch() {
  if (!state.patchTask || !state.patchCode.trim() || state.busy.patch) return;
  const useDiff = state.patchMode === "diff";
  state.busy.patch = true;
  state.patchError = null;
  renderPatchLab();
  const started = performance.now();
  try {
    const result = await api(useDiff ? "/api/verify-patch" : "/api/verify-code", {
      method: "POST",
      body: JSON.stringify(
        useDiff
          ? {
              task_id: state.patchTask,
              diff: state.patchCode,
              checker: "acv-rules",
            }
          : {
              task_id: state.patchTask,
              code: state.patchCode,
              checker: "acv-rules",
            },
      ),
    });
    state.patchResult = result;
    recordRun({
      taskId: state.patchTask,
      candidate: useDiff ? "custom diff" : "custom source",
      accepted: Boolean(result.accepted),
      durationMs: result.elapsed_ms ?? Math.round(performance.now() - started),
      source: "patch",
      mode: useDiff ? "diff" : "source",
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

function projectCandidateInfo(kind) {
  return candidateKindInfo(kind);
}

function byteLabel(value) {
  const number = Number(value) || 0;
  if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(1)} MB`;
  if (number >= 1_000) return `${(number / 1_000).toFixed(1)} kB`;
  return `${number} B`;
}

function projectSignal(label, ok, detail) {
  return `<div class="signal ${ok ? "good" : "bad"}">
    <span class="signal-dot" aria-hidden="true"></span>
    <div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(detail)}</span></div>
  </div>`;
}

function plainProjectVerdict(result) {
  if (result.oracle_ok === false) {
    return {
      tone: "warn",
      title: "The fixture check failed before the patch was judged.",
      body:
        "The exploit did not reproduce on the vulnerable project. A gate that cannot reproduce the original attack is not evidence, so this run is rejected regardless of what the patched code does.",
    };
  }
  if (!result.security_pass) {
    return {
      tone: "bad",
      title: "Rejected: the attack still works on the generated project.",
      body:
        "The trusted exploit ran against the complete project and still reached the dangerous path. The new code did not close the vulnerability. Open the attack output and follow the path it reached.",
    };
  }
  if (!result.behavior_pass) {
    return {
      tone: "warn",
      title: "Rejected: the normal behaviour suite broke.",
      body:
        "The attack is blocked, but the project no longer passes its functional tests. A useful project-level repair must preserve normal behaviour across the files that import and call it.",
    };
  }
  if (!result.checker_pass) {
    return {
      tone: "warn",
      title: "Rejected: the project checker is not clear.",
      body:
        "The exploit is blocked and the functional suite passes, but at least one source file still has a serious pattern, or the checker could not scan every file in its declared scope. Static findings are evidence, not authority: inspect the file, line, and surrounding code.",
    };
  }
  return {
    tone: "good",
    title: "Accepted inside this project and this evidence set.",
    body:
      "The exploit is blocked, the multi-file functional suite passes, and the checker found no blocking issue in the checked source files. This is a real deterministic pass, but it is still not proof that the whole project is secure in every environment.",
  };
}

function projectRunSummary(result) {
  const overlay = result.overlay_files?.length
    ? result.overlay_files.slice(0, 8).map((path) => `<code class="code-inline">${escapeHtml(path)}</code>`).join(" ")
    : "<span class=\"muted\">no files changed (baseline)</span>";
  return `<div class="project-run-summary">
    <div><span class="kv-label">input</span><strong>${escapeHtml(result.input_mode || "overlay")}</strong></div>
    <div><span class="kv-label">files judged</span><strong>${escapeHtml(String(result.total_files ?? "—"))}</strong></div>
    <div><span class="kv-label">lines judged</span><strong>${escapeHtml(String(result.total_lines ?? "—"))}</strong></div>
    <div><span class="kv-label">elapsed</span><strong>${escapeHtml(String(result.elapsed_ms ?? "—"))} ms</strong></div>
    <div class="wide"><span class="kv-label">changed by this run</span><span>${overlay}</span></div>
  </div>`;
}

function renderProjectResult(result) {
  const plain = plainProjectVerdict(result);
  const findings = (result.findings || []).slice(0, 80);
  const findingCount = (result.findings || []).length;
  const checkerRows = Object.entries(result.checker_results || {})
    .map(([name, score]) => `<div class="stat-row"><span>${escapeHtml(name)}</span><strong>${escapeHtml(
      score.available === false
        ? "unavailable"
        : `${score.files_scanned ?? 0} files · ${(score.findings || []).length} findings${score.coverage_complete === false ? " · coverage incomplete" : score.truncated ? " · capped" : ""}`,
    )}</strong></div>`)
    .join("");
  const coverageIncomplete = Object.values(result.checker_results || {}).some(
    (score) => score.available !== false && score.coverage_complete === false,
  );
  const provenance = result.provenance || {};
  const clipForDisplay = (value, limit = 20_000) => {
    const text = String(value ?? "");
    return text.length > limit ? `${text.slice(0, limit)}\n… [truncated in UI; the full value is in the run payload]` : text;
  };
  const provenanceRows = [
    ["model", provenance.model],
    ["provider", provenance.provider],
    ["backend", provenance.backend],
    ["quantization", provenance.quantization],
    ["temperature", provenance.temperature],
    ["seed", provenance.seed],
    ["criticality", provenance.criticality],
    ["isolation acknowledged", result.isolation_acknowledged ? "yes" : "no"],
    ["run id", result.run_id],
  ]
    .filter(([, value]) => value !== "" && value !== null && value !== undefined)
    .map(([label, value]) => `<div class="stat-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`)
    .join("");

  return `<div class="project-result">
    <div class="verdict-box ${plain.tone}">
      <div class="verdict-box-head">${verdictPill(result.accepted, "PROJECT")}<strong>${escapeHtml(plain.title)}</strong><span class="pill">${escapeHtml(state.projectRunLabel || result.input_mode || "run")}</span></div>
      <p>${escapeHtml(plain.body)}</p>
      ${result.rejected_by && result.rejected_by !== "none" ? `<p class="small">Rejected by: <strong>${escapeHtml(result.rejected_by)}</strong></p>` : ""}
    </div>

    <div class="panel">
      <div class="panel-head"><div><h2>Four independent signals</h2><p>All four must agree before the generated project is accepted.</p></div></div>
      <div class="signal-grid">
        ${projectSignal("Fixture reproduces", result.oracle_ok, result.oracle_ok ? `exploit exit ${result.oracle_exit} on vulnerable project` : `exploit exit ${result.oracle_exit}; oracle is not evidence`)}
        ${projectSignal("Attack blocked", result.security_pass, `PoC exit ${result.poc_exit} on candidate`)}
        ${projectSignal("Behaviour preserved", result.behavior_pass, `functional suite exit ${result.behavior_exit}`)}
        ${projectSignal("Checker clear", result.checker_pass, `${result.checker_tool || "checker"} · ${findingCount} finding${findingCount === 1 ? "" : "s"}${coverageIncomplete ? " · coverage incomplete" : ""}`)}
      </div>
    </div>

    ${projectRunSummary(result)}

    ${result.reasons?.length ? `<div class="notice warn"><strong>Why this verdict</strong><ul class="compact-list">${result.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul></div>` : ""}

    <div class="dashboard-grid two">
      <div class="panel">
        <div class="panel-head"><div><h2>Checker findings</h2><p>File-level evidence, capped for large projects.</p></div></div>
        ${
          findings.length
            ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>File</th><th>Line</th><th>Rule</th><th>CWE</th><th>Message</th></tr></thead><tbody>${findings
                .map(
                  (finding) => `<tr><td><code class="code-inline">${escapeHtml(finding.path || "—")}</code></td><td>${escapeHtml(finding.line ?? "—")}</td><td>${escapeHtml(finding.rule_id)}</td><td>${escapeHtml(finding.cwe)}</td><td>${escapeHtml(finding.message)}</td></tr>`,
                )
                .join("")}</tbody></table></div>${findingCount > findings.length ? `<p class="small">Showing ${findings.length} of ${findingCount} findings.</p>` : ""}`
            : `<p class="muted">No blocking finding in the checked scope.</p>`
        }
      </div>
      <div class="panel">
        <div class="panel-head"><div><h2>Checker coverage and provenance</h2><p>The gate is deterministic. These fields only describe where the code came from.</p></div></div>
        ${checkerRows || `<p class="muted">No checker result.</p>`}
        ${provenanceRows || `<p class="muted">No model provenance was supplied.</p>`}
        ${provenance.prompt ? `<details class="output-details"><summary>Prompt recorded with this run</summary><pre class="output-pre">${escapeHtml(clipForDisplay(provenance.prompt))}</pre></details>` : ""}
        ${provenance.raw_output ? `<details class="output-details"><summary>Raw model output recorded with this run</summary><pre class="output-pre">${escapeHtml(clipForDisplay(provenance.raw_output))}</pre></details>` : ""}
      </div>
    </div>

    <div class="notice isolation"><strong>Execution boundary.</strong> ${escapeHtml(result.isolation_warning || "Process limits only; no VM or container boundary.")}</div>

    <details class="output-details">
      <summary>Attack output</summary>
      <pre class="output-pre">${escapeHtml(result.poc_output || "(empty)")}</pre>
    </details>
    <details class="output-details">
      <summary>Functional test output</summary>
      <pre class="output-pre">${escapeHtml(result.behavior_output || "(empty)")}</pre>
    </details>
    <details class="output-details">
      <summary>Oracle output on the vulnerable project</summary>
      <pre class="output-pre">${escapeHtml(result.oracle_output || "(empty)")}</pre>
    </details>
  </div>`;
}

function projectFileRows(project, selected) {
  return (project.files || [])
    .map(
      (file) => `<button class="file-row ${file.path === selected ? "active" : ""}" type="button" data-action="project-file" data-path="${escapeHtml(file.path)}">
        <span class="file-path">${escapeHtml(file.path)}</span>
        <span class="file-meta">${escapeHtml(String(file.lines))} ln · ${byteLabel(file.bytes)}</span>
      </button>`,
    )
    .join("");
}

function projectProvenanceFields(meta) {
  return `<div class="provenance-grid">
    <label>Model<input class="input" id="project-model" data-project-field="model" value="${escapeHtml(meta.model || "")}" placeholder="e.g. qwen2.5-coder-32b" /></label>
    <label>Provider<input class="input" id="project-provider" data-project-field="provider" value="${escapeHtml(meta.provider || "")}" placeholder="ollama / vllm / studio" /></label>
    <label>Backend<input class="input" id="project-backend" data-project-field="backend" value="${escapeHtml(meta.backend || "")}" placeholder="local GPU, API, notebook" /></label>
    <label>Quantization<input class="input" id="project-quantization" data-project-field="quantization" value="${escapeHtml(meta.quantization || "")}" placeholder="FP16, Q8_0, AWQ..." /></label>
    <label>Temperature<input class="input" id="project-temperature" data-project-field="temperature" value="${escapeHtml(meta.temperature ?? "")}" placeholder="0" inputmode="decimal" /></label>
    <label>Seed<input class="input" id="project-seed" data-project-field="seed" value="${escapeHtml(meta.seed ?? "")}" placeholder="optional" inputmode="numeric" /></label>
    <label class="wide">Prompt / request note<textarea class="editor small" id="project-prompt" data-project-field="prompt" rows="3" placeholder="Paste the instruction or request id used to generate this project">${escapeHtml(meta.prompt || "")}</textarea></label>
    <label class="wide">Raw model output (optional)<textarea class="editor small" id="project-raw-output" data-project-field="raw_output" rows="3" placeholder="Optional: paste the raw response for provenance. It is not treated as evidence.">${escapeHtml(meta.raw_output || "")}</textarea></label>
  </div>`;
}

function renderProjects() {
  if (!state.projects.length) {
    $("#view-root").innerHTML = `<div class="empty-panel">
      <strong>No project tasks are configured</strong>
      <span>The single-file example pack is still available. Add a project under <code class="code-inline">project_workers/</code> or set <code class="code-inline">ACV_PROJECT_PACK</code>.</span>
    </div>`;
    return;
  }
  if (!state.project) {
    if (state.projectError) {
      $("#view-root").innerHTML = `<div class="empty-panel">
        <strong>Could not load the project</strong>
        <span>${escapeHtml(state.projectError)}</span>
        <button class="btn primary" type="button" data-action="project-retry">Try again</button>
      </div>`;
      return;
    }
    $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading the project browser…</span></div>`;
    openProject(state.projects[0].project_id).catch((error) => showToast(error.message, "error"));
    return;
  }

  const project = state.project;
  const selected = state.projectFile || project.files?.[0]?.path || "";
  const selectedInfo = project.files?.find((file) => file.path === selected);
  const meta = state.projectMeta || {};
  const candidates = project.candidates || [];
  const gold = candidates.find((item) => item.kind === "gold") || candidates[0];
  const mutant = candidates.find((item) => item.kind === "mutant");
  const uploadCount = Object.keys(state.projectUpload || {}).length;
  const uploadChars = Object.values(state.projectUpload || {}).reduce((total, text) => total + String(text).length, 0);
  const projectOptions = state.projects
    .map((item) => `<option value="${escapeHtml(item.project_id)}" ${item.project_id === project.project_id ? "selected" : ""}>${escapeHtml(item.title)} · ${escapeHtml(item.cwe)}</option>`)
    .join("");

  $("#view-root").innerHTML = `
    <div class="hero-panel project-hero">
      <div class="hero-copy">
        <div class="breadcrumb">multi-file project · ${escapeHtml(project.cwe)}</div>
        <h2>${escapeHtml(project.title)}</h2>
        <p class="hero-lede">${escapeHtml(project.summary)}</p>
        <div class="hero-actions">
          <button class="btn primary" type="button" data-action="project-run-candidate" data-candidate="${escapeHtml(gold?.name || "")}" ${gold ? "" : "disabled"}>Run reference fix</button>
          ${mutant ? `<button class="btn danger" type="button" data-action="project-run-candidate" data-candidate="${escapeHtml(mutant.name)}">Run incomplete fix</button>` : ""}
          <button class="btn ghost" type="button" data-action="project-run-baseline">Run vulnerable baseline</button>
        </div>
        <div class="task-tags">${(project.tags || []).map((tag) => pill(tag)).join("")}</div>
      </div>
      <div class="hero-stats">
        <div class="hero-stat"><span>files</span><strong>${escapeHtml(String(project.total_files))}</strong></div>
        <div class="hero-stat"><span>lines</span><strong>${escapeHtml(String(project.total_lines))}</strong></div>
        <div class="hero-stat"><span>project size</span><strong>${byteLabel(project.total_bytes)}</strong></div>
        <div class="hero-stat"><span>candidates</span><strong>${candidates.length}</strong></div>
      </div>
    </div>

    <div class="project-toolbar panel">
      <label class="inline-label">Project <select id="project-select">${projectOptions}</select></label>
      <span class="pill">checker scope: ${escapeHtml(String((project.checker_scope || []).length))} source files</span>
      <span class="pill">limits: ${project.limits.max_files} files · ${byteLabel(project.limits.max_total_bytes)}</span>
    </div>

    ${state.projectError ? `<div class="notice bad"><strong>Could not run this project.</strong> ${escapeHtml(state.projectError)}</div>` : ""}

    <div class="project-layout">
      <aside class="panel project-browser">
        <div class="panel-head"><div><h2>Project files</h2><p>Click a file to inspect the base project. Generated overlays are judged against this tree.</p></div></div>
        <div class="file-list">${projectFileRows(project, selected)}</div>
      </aside>

      <div class="project-main">
        <div class="code-panel">
          <div class="code-head">
            <div><span class="code-path">${escapeHtml(selected || "select a file")}</span>${selectedInfo ? `<span class="code-path">${escapeHtml(String(selectedInfo.lines))} lines · ${byteLabel(selectedInfo.bytes)}</span>` : ""}</div>
            <span class="pill">base project</span>
          </div>
          ${state.projectCode ? codeBlock(state.projectCode, 4000) : `<div class="empty-panel small">Select a file to inspect it.</div>`}
        </div>

        <div class="panel intake-panel">
          <div class="panel-head">
            <div><h2>Generated project intake</h2><p>Bring code from any model, studio, notebook, or local runner. The verifier does not call the model and does not trust its confidence.</p></div>
            <button class="btn ghost small" type="button" data-action="project-toggle-intake">${state.projectAdvanced ? "Hide provenance" : "Model provenance"}</button>
          </div>
          <div class="intake-grid">
            <div class="intake-main">
              <label class="inline-label">Upload generated files or a folder<input class="input file-input" id="project-files" type="file" multiple webkitdirectory /></label>
              <p class="small">${uploadCount ? `${uploadCount} file${uploadCount === 1 ? "" : "s"} loaded · ${uploadChars.toLocaleString()} characters.` : "No files loaded. You can also paste a JSON object of path → text below."}</p>
              <label class="inline-label">Or paste an overlay JSON<textarea class="editor" id="project-json" rows="10" placeholder='{ "portal/paths.py": "from pathlib import Path\\n..." }'>${escapeHtml(state.projectJson || "")}</textarea></label>
              <div class="intake-actions">
                <button class="btn primary" type="button" data-action="project-run-generated" ${state.projectBusy ? "disabled" : ""}>Verify generated overlay</button>
                <button class="btn ghost" type="button" data-action="project-clear-overlay">Clear</button>
                ${uploadCount ? `<span class="pill">${uploadCount} files ready</span>` : ""}
              </div>
            </div>
            <div class="intake-side">
              <div class="notice"><strong>What is judged.</strong> The exploit and functional test live outside the base tree. They are not taken from the generated code, and a generated overlay cannot replace them.</div>
              <div class="notice"><strong>Overlay limits.</strong> Up to 250 files, 1.5 MB total, 400 KB per file. Checker findings and output are capped explicitly; skipped or unscannable source files fail checker coverage instead of being ignored.</div>
              <label class="inline-label">Criticality<select id="project-criticality">
                <option value="standard" ${state.projectCriticality !== "critical" ? "selected" : ""}>standard / trusted local input</option>
                <option value="critical" ${state.projectCriticality === "critical" ? "selected" : ""}>critical code</option>
              </select></label>
              <label class="check-row"><input type="checkbox" id="project-ack" ${state.projectAck ? "checked" : ""} /> I understand the local runner is process limits only, not a VM or container.</label>
              <p class="small">For critical or untrusted code, move the verification to an isolated VM/container first. The checkbox records the boundary; it does not create isolation.</p>
              ${state.projectCriticality === "critical" ? `<div class="notice warn"><strong>Critical code selected.</strong> The built-in runner still executes on this host with process limits only. Do not treat an accepted result as safe for deployment until the same evidence has run inside an isolated VM or container.</div>` : ""}
              <button class="btn ghost small" type="button" data-action="project-toggle-intake">${state.projectAdvanced ? "Hide optional provenance" : "Add model provenance"}</button>
            </div>
          </div>
          ${state.projectAdvanced ? `<div class="provenance-panel"><div class="panel-head"><div><h2>Model provenance (optional, advisory only)</h2><p>Recorded in the result and the local run log. These fields never change the gate verdict.</p></div></div>${projectProvenanceFields(meta)}</div>` : ""}
        </div>

        ${state.projectResult ? renderProjectResult(state.projectResult) : `<div class="panel muted-panel"><strong>No run yet.</strong><p>Run the reference fix, the incomplete fix, or load your own generated files. The result will show the four signals and the file-level findings.</p></div>`}
      </div>
    </div>
  `;
}

async function openProject(projectId) {
  state.view = "projects";
  state.project = null;
  state.projectFile = null;
  state.projectCode = "";
  state.projectResult = null;
  state.projectError = null;
  state.projectUpload = {};
  state.projectUploadNote = "";
  state.projectJson = "";
  state.projectRunLabel = "";
  updateShell();
  $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading project files and evidence…</span></div>`;
  try {
    const project = await api(`/api/projects/${encodeURIComponent(projectId)}`);
    state.project = project;
    const preferred = project.files?.find((file) => file.path === "portal/paths.py") || project.files?.[0];
    if (preferred) {
      state.projectFile = preferred.path;
      const source = await api(`/api/projects/${encodeURIComponent(projectId)}/file?path=${encodeURIComponent(preferred.path)}`);
      state.projectCode = source.code || "";
    }
    render();
  } catch (error) {
    state.projectError = error.message;
    render();
  }
}

async function loadProjectFile(path) {
  if (!state.project) return;
  state.projectFile = path;
  state.projectCode = "";
  render();
  try {
    const source = await api(`/api/projects/${encodeURIComponent(state.project.project_id)}/file?path=${encodeURIComponent(path)}`);
    state.projectCode = source.code || "";
    render();
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function readProjectFiles(input) {
  const files = Array.from(input.files || []);
  if (!files.length) return;
  const entries = [];
  for (const file of files) {
    const text = await file.text();
    const raw = file.webkitRelativePath || file.name;
    entries.push({ path: raw, text });
  }
  const firstParts = new Set(entries.map((entry) => entry.path.split("/")[0]));
  const stripRoot = firstParts.size === 1 && entries.every((entry) => entry.path.includes("/"));
  const allowed = /\.(py|json|txt|md|html?|css|js|ya?ml|toml|sql|csv|ini|cfg|xml|j2|jinja|template)$/i;
  const overlay = {};
  for (const entry of entries) {
    let path = stripRoot ? entry.path.split("/").slice(1).join("/") : entry.path;
    if (!path || path.split("/").some((part) => part.startsWith(".") || part === "__pycache__")) continue;
    if (!allowed.test(path)) continue;
    overlay[path] = entry.text;
  }
  state.projectUpload = overlay;
  state.projectUploadNote = `${Object.keys(overlay).length} files loaded`;
  state.projectJson = "";
  render();
  showToast(`${Object.keys(overlay).length} files loaded from disk`);
}

function projectMetaFromState() {
  const meta = state.projectMeta || {};
  const numberOrNull = (value) => {
    if (value === "" || value === null || value === undefined) return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  };
  return {
    model: meta.model || "",
    provider: meta.provider || "",
    backend: meta.backend || "",
    quantization: meta.quantization || "",
    prompt: meta.prompt || "",
    temperature: numberOrNull(meta.temperature),
    seed: numberOrNull(meta.seed),
    raw_output: meta.raw_output || "",
    notes: meta.notes || "",
    criticality: state.projectCriticality === "critical" ? "critical" : "standard",
  };
}

function projectOverlayFromState() {
  if (Object.keys(state.projectUpload || {}).length) return state.projectUpload;
  const text = (state.projectJson || "").trim();
  if (!text) return null;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Overlay JSON is not valid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Overlay JSON must be an object of path → text.");
  }
  const files = parsed.files && typeof parsed.files === "object" ? parsed.files : parsed;
  if (parsed.files && typeof parsed.files !== "object") {
    throw new Error("Overlay 'files' must be an object of path → text.");
  }
  for (const [path, value] of Object.entries(files)) {
    if (typeof value !== "string") {
      throw new Error(`Overlay file ${path} must be text.`);
    }
  }
  return files;
}

async function runProjectCandidate(name) {
  if (!state.project) return;
  state.projectBusy = true;
  state.projectError = null;
  const candidate = (state.project.candidates || []).find((item) => item.name === name);
  state.projectRunLabel = candidate ? candidateOptionLabel(candidate) : name;
  render();
  try {
    const result = await api(`/api/projects/${encodeURIComponent(state.project.project_id)}/verify`, {
      method: "POST",
      body: JSON.stringify({
        candidate: name,
        checker: "acv-rules",
        provenance: projectMetaFromState(),
        isolation_acknowledged: Boolean(state.projectAck),
      }),
    });
    state.projectResult = result;
  } catch (error) {
    state.projectError = error.message;
  } finally {
    state.projectBusy = false;
    render();
  }
}

async function runProjectBaseline() {
  if (!state.project) return;
  state.projectBusy = true;
  state.projectError = null;
  state.projectRunLabel = "vulnerable baseline";
  render();
  try {
    const result = await api(`/api/projects/${encodeURIComponent(state.project.project_id)}/verify`, {
      method: "POST",
      body: JSON.stringify({
        files: {},
        checker: "acv-rules",
        provenance: projectMetaFromState(),
        isolation_acknowledged: Boolean(state.projectAck),
      }),
    });
    state.projectResult = result;
  } catch (error) {
    state.projectError = error.message;
  } finally {
    state.projectBusy = false;
    render();
  }
}

async function runProjectGenerated() {
  if (!state.project) return;
  let files;
  try {
    files = projectOverlayFromState();
  } catch (error) {
    state.projectError = error.message;
    render();
    return;
  }
  if (!files || !Object.keys(files).length) {
    state.projectError = "Load generated files or paste an overlay JSON object before running.";
    render();
    return;
  }
  state.projectBusy = true;
  state.projectError = null;
  state.projectRunLabel = "generated overlay";
  render();
  try {
    const result = await api(`/api/projects/${encodeURIComponent(state.project.project_id)}/verify`, {
      method: "POST",
      body: JSON.stringify({
        files,
        checker: "acv-rules",
        provenance: projectMetaFromState(),
        isolation_acknowledged: Boolean(state.projectAck),
      }),
    });
    state.projectResult = result;
  } catch (error) {
    state.projectError = error.message;
  } finally {
    state.projectBusy = false;
    render();
  }
}

function renderPatchLab() {
  if (!state.tasks.length) {
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>No examples loaded</strong><span class="small">Start the API and refresh the list.</span></div>`;
    return;
  }
  if (!state.patchDetail) {
    $("#view-root").innerHTML = `<div class="loading-panel"><span class="spinner"></span><span>Loading patch target…</span></div>`;
    return;
  }

  const detail = state.patchDetail;
  const mode = state.patchMode === "diff" ? "diff" : "source";
  const taskOptions = state.tasks
    .map(
      (task) => `<option value="${escapeHtml(task.task_id)}" ${
        task.task_id === state.patchTask ? "selected" : ""
      }>${escapeHtml(task.task_id)} — ${escapeHtml(task.title)}</option>`,
    )
    .join("");
  const sourceOptions = [
    `<option value="vulnerable" ${
      state.patchSource === "vulnerable" ? "selected" : ""
    }>Original vulnerable code — expected to fail</option>`,
    ...detail.candidates.map(
      (candidate) => `<option value="${escapeHtml(candidate.name)}" ${
        state.patchSource === candidate.name ? "selected" : ""
      }>${escapeHtml(candidateOptionLabel(candidate))} — ${
        candidate.expected_security ? "expected to pass" : "expected to fail"
      }</option>`,
    ),
  ].join("");
  let sourceLabel = "custom code";
  if (state.patchSource === "vulnerable") {
    sourceLabel = "original vulnerable code";
  } else if (state.patchSource) {
    const sourceCandidate = detail.candidates.find(
      (candidate) => candidate.name === state.patchSource,
    );
    sourceLabel = sourceCandidate
      ? candidateKindLabel(sourceCandidate.kind)
      : state.patchSource;
  }
  if (state.patchDirty) sourceLabel = `${sourceLabel} · edited`;
  const sourceControls =
    mode === "source"
      ? `<select class="select" id="patch-source" aria-label="Prepared candidate">${sourceOptions}</select>
         <button class="btn ghost" type="button" data-action="patch-load">Load prepared code</button>`
      : "";
  const editorTitle = mode === "diff" ? "Your patch (unified diff)" : "Your replacement code";
  const editorSubtitle =
    mode === "diff"
      ? `${escapeHtml(detail.task_id)} · ${escapeHtml(detail.cwe)} · diff against the original vulnerable file`
      : `${escapeHtml(detail.task_id)} · ${escapeHtml(detail.cwe)} · template: ${escapeHtml(
          sourceLabel,
        )}`;
  const editorNote =
    mode === "diff"
      ? "The diff must target worker.py. Paths are checked before the patch is applied."
      : "Ctrl/Cmd+Enter runs the gate · full-file replacement";

  $("#view-root").innerHTML = `
    <div class="section-head intro-only">
      <div>
        <p>Pick an example, then either load a prepared candidate or paste your own code. The gate runs the attack, the normal behaviour tests, and the checker against the result.</p>
      </div>
      <div class="toolbar">
        <select class="select" id="patch-task" aria-label="Example task">${taskOptions}</select>
        <select class="select" id="patch-mode" aria-label="How to supply the patch">
          <option value="source" ${mode === "source" ? "selected" : ""}>Full source file</option>
          <option value="diff" ${mode === "diff" ? "selected" : ""}>Unified diff</option>
        </select>
        ${sourceControls}
        <button class="btn primary" type="button" data-action="patch-run" ${
          state.busy.patch ? "disabled" : ""
        }>${state.busy.patch ? spin("Running gate") : "Run the gate"}</button>
      </div>
    </div>

    <div class="notice warning">
      <strong>Trusted input only.</strong> The gate executes the submitted Python module on this
      machine. Process limits are active, but there is no hardened network or filesystem sandbox.
      Do not expose this console to untrusted users.
    </div>

    <div class="lab-layout mt-12">
      <section class="panel editor-panel">
        <div class="panel-head">
          <div>
            <h2>${editorTitle}</h2>
            <p>${editorSubtitle}</p>
          </div>
          <span class="pill blue">editable</span>
        </div>
        <textarea id="patch-code" class="editor ${mode === "diff" ? "diff" : ""}" spellcheck="false" aria-label="${
          mode === "diff" ? "Unified diff" : "Replacement worker source"
        }">${escapeHtml(state.patchCode)}</textarea>
        <div class="editor-foot">
          <span id="patch-count">${codeStats(state.patchCode)}</span>
          <span>${editorNote}</span>
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
            : `<div class="empty-panel"><strong>No patch result yet</strong><span class="small">${
                mode === "diff"
                  ? "Paste a unified diff against the original vulnerable worker.py, then run the gate."
                  : "Load a prepared candidate from the menu or paste your own replacement, then run the gate."
              }</span><span class="small">A prepared reference fix is the quickest way to see a pass. An incomplete fix shows what a rejection looks like.</span></div>`
        }
        <div class="panel">
          <div class="panel-head">
            <div>
              <h2>What this patch must satisfy</h2>
              <p>The candidate has to keep the same module-level interface as the original worker.</p>
            </div>
            <span class="pill">${escapeHtml(detail.cwe)}</span>
          </div>
          <div class="stat-list">
            <div class="stat-row"><span>Example task</span><strong>${escapeHtml(detail.task_id)}</strong></div>
            <div class="stat-row"><span>Original vulnerable file</span><strong>${escapeHtml(
              detail.paths?.vulnerable || "worker.py",
            )}</strong></div>
            <div class="stat-row"><span>Attack script</span><strong>${escapeHtml(
              detail.paths?.poc || "poc.py",
            )}</strong></div>
            <div class="stat-row"><span>Normal behaviour test</span><strong>${escapeHtml(
              detail.paths?.functional || "test_worker.py",
            )}</strong></div>
            <div class="stat-row"><span>Prepared candidates</span><strong>${detail.candidates.length}</strong></div>
          </div>
          <p class="help mt-12">
            This build supports full-file replacement and a single-file unified diff for worker.py.
            The code is executed with process limits; it is not a hardened sandbox.
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
    <div class="section-head intro-only">
      <div>
        <p>Run every installed static checker over the same labelled files, then compare what it caught, what it missed, what it wrongly flagged, and how long it took. This measures the checker, not the model.</p>
      </div>
      <button class="btn primary" type="button" data-action="qualify" ${
        state.busy.qualify ? "disabled" : ""
      }>${state.busy.qualify ? spin("Testing checkers") : "Run checker tests"}</button>
    </div>

    <div class="cards">
      ${metricCard("Available checkers", String(tools.length), "static-analysis adapters")}
      ${metricCard("Installed", String(available), "ready in this environment")}
      ${metricCard(
        "Files measured",
        scores.length ? String(scores[0].samples) : "—",
        "built from every example task",
      )}
      ${metricCard("Example tasks", `${state.tasks.length}`, "vulnerable, fixed, safe, incomplete")}
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
      <strong>How to read this:</strong> precision means “when the checker flags something, how
      often is it right?”; recall means “of the weak files, how many did it catch?” The local
      <span class="code-inline">acv-rules</span> pack is intentionally tuned to this task family,
      so its score is useful for regression testing, not for claiming universal detection quality.
      Bandit is measured as an external baseline.
    </div>

    ${state.qualifyError ? `<div class="note warn mt-12">${escapeHtml(state.qualifyError)}</div>` : ""}
    ${scores.length ? renderScores(scores) : `<div class="empty-panel mt-18"><strong>No checker test has run yet</strong><span class="small">Click “Run checker tests” to measure each installed checker over the same labelled files.</span></div>`}
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
      <div><h2>Checker results</h2><p>Measured on ${scores[0].samples} labelled files. Runtime includes process startup for external checkers.</p></div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Checker</th><th>Installed</th><th class="num">Correct flags</th><th class="num">False alarms</th><th class="num">Missed weak code</th><th class="num">Correct clean</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th><th class="num">Runtime</th></tr></thead>
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
    showToast("Checker tests finished");
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
    <div class="section-head intro-only">
      <div>
        <p>Run every reference fix, safe alternative, and deliberately incomplete fix through the gate. The report counts both false passes and false rejections across the whole calibration pack.</p>
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
            ${metricCard("False rejections", String(summary.false_rejections), "known-good variants rejected")}
            ${metricCard("Fixture baseline", `${summary.baseline_ok}/${summary.tasks}`, "attack works on original, tests pass on fix")}
          </div>

          <div class="cards">
            ${metricCard("Example tasks", String(summary.tasks), `${summary.cwe_families} CWE categories`)}
            ${metricCard("Reference fixes accepted", `${summary.gold_accepted}/${summary.gold}`, "known-good repairs")}
            ${metricCard("Safe alternatives accepted", `${summary.benign_accepted}/${summary.benign}`, "different safe repairs")}
            ${metricCard("Incomplete fixes rejected", `${summary.mutants_rejected}/${summary.mutants}`, "known-bad repairs")}
          </div>

          <div class="section-head"><div><h2>Task matrix</h2><p>Click a task id to open its source and candidates.</p></div></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Task</th><th>CWE</th><th>Fixture</th><th class="num">Reference fix</th><th class="num">Safe alternative</th><th class="num">Incomplete fix</th><th class="num">False pass</th><th class="num">False reject</th></tr></thead>
              <tbody>
                ${(audit.tasks || []).map(renderAuditRow).join("")}
              </tbody>
            </table>
          </div>

          ${renderAuditCheckers(summary.checkers || [])}

          <div class="split mt-18">
            <div class="card">
              <h2>False passes to inspect</h2>
              <p class="muted small">Known-incomplete fixes that the gate accepted.</p>
              <div class="miss-list mt-12">${
                summary.false_pass_ids?.length
                  ? summary.false_pass_ids
                      .map((id) => `<span class="miss">${escapeHtml(id)}</span>`)
                      .join("")
                  : `<span class="miss good">none</span>`
              }</div>
            </div>
            <div class="card">
              <h2>False rejections to inspect</h2>
              <p class="muted small">Known-good fixes that the gate rejected.</p>
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
  return `<div class="section-head"><div><h2>Checker comparison inside the audit</h2><p>Recall on vulnerable and incomplete files, precision on fixed and safe files, and how often a checker misses a bad repair.</p></div></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Checker</th><th>Version</th><th>Installed</th><th class="num">Recall</th><th class="num">Precision</th><th class="num">Bad repairs missed</th></tr></thead>
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
    <div class="section-head intro-only">
      <div>
        <p>This optional page sends the same code to a model and runs the deterministic gate beside it. The model can explain and suggest; it cannot change the verdict.</p>
      </div>
      ${pill(keyReady ? "model configured" : "key missing", keyReady ? "green" : "red")}
    </div>

    <div class="card">
      <div class="form-row">
        <div class="stack">
          <label class="metric-label" for="review-task">Example task</label>
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
          <label class="metric-label" for="review-candidate">Code to review</label>
          <select class="select" id="review-candidate">
            ${(task?.candidates || [])
              .map(
                (item) => `<option value="${escapeHtml(item.name)}" ${
                  item.name === state.reviewCandidate ? "selected" : ""
                }>${escapeHtml(candidateOptionLabel(item))}</option>`,
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
      ${kv("Gate result", gateAccepted ? "accepted" : "rejected")}
      ${kv("Model's opinion", data.verdict.replaceAll("_", " "))}
      ${kv("Agrees with gate", review.llm_matches_gate === null ? "uncertain" : review.llm_matches_gate ? "yes" : "no")}
      ${kv("Matches task label", review.llm_matches_truth === null ? "uncertain" : review.llm_matches_truth ? "yes" : "no")}
      ${kv("Code reviewed", `${review.candidate} — ${candidateKindLabel(review.candidate_kind)}`)}
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
      <summary>What the deterministic gate actually found</summary>
      <div class="kv-grid mt-12">
        ${kv("Gate result", deterministic.accepted ? "accepted" : "rejected")}
        ${kv("Label says", deterministic.expected_accepted ? "safe fix" : "vulnerable")}
        ${kv("Matches label", deterministic.correct ? "yes" : "no")}
        ${kv("Attack", deterministic.security_pass ? "blocked" : "still works")}
        ${kv("Normal behaviour", deterministic.behavior_pass ? "passes" : "fails")}
        ${kv("Static checker", deterministic.checker_pass ? "passes" : "blocking finding")}
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
    showToast("Model second opinion finished");
  } catch (error) {
    state.reviewError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.review = false;
    renderReview();
  }
}

function renderRepair() {
  if (!state.tasks.length) {
    $("#view-root").innerHTML = `<div class="empty-panel"><strong>No tasks available</strong><span class="small">The repair lab needs the task pack.</span></div>`;
    return;
  }

  ensureRepairSelection();
  const task = state.tasks.find((item) => item.task_id === state.repairTask) || state.tasks[0];
  state.repairTask = task?.task_id || null;
  const keyReady = Boolean(state.health?.key_configured);
  const result = state.repairResult;

  $("#view-root").innerHTML = `
    <div class="section-head intro-only">
      <div>
        <p>The model proposes a repair, then the same deterministic gate runs the attack, normal behaviour tests, and checker against the generated code. The gate decides; the model does not.</p>
      </div>
      ${pill(keyReady ? "model configured" : "key missing", keyReady ? "green" : "red")}
    </div>

    <div class="card">
      <div class="form-row">
        <div class="stack">
          <label class="metric-label" for="repair-task">Example task</label>
          <select class="select" id="repair-task">
            ${state.tasks
              .map(
                (item) => `<option value="${escapeHtml(item.task_id)}" ${
                  item.task_id === state.repairTask ? "selected" : ""
                }>${escapeHtml(item.task_id)} — ${escapeHtml(item.title)}</option>`,
              )
              .join("")}
          </select>
        </div>
        <div class="stack">
          <span class="metric-label">&nbsp;</span>
          <button class="btn primary" type="button" data-action="repair" ${
            state.busy.repair || !keyReady ? "disabled" : ""
          }>${state.busy.repair ? spin("Generating") : "Generate and gate"}</button>
        </div>
      </div>
      <div class="${keyReady ? "note" : "note warn"} mt-12">
        ${
          keyReady
            ? `The model receives the vulnerable source, exploit, and normal behaviour test. The generated code is executed with the same process limits as Check a patch. Its confidence is not the verdict.`
            : `No Groq key is configured. Set <span class="code-inline">ACV_GROQ_API_KEY</span> on the server to enable generated fixes. Check a patch and the deterministic gate still work.`
        }
      </div>
      ${state.repairError ? `<div class="note warn mt-12">${escapeHtml(state.repairError)}</div>` : ""}
    </div>

    ${
      state.busy.repair
        ? `<div class="loading-panel mt-18"><span class="spinner"></span><span>Waiting for a repair proposal and running the deterministic gate…</span></div>`
        : result
          ? renderRepairResult(result)
          : `<div class="empty-panel mt-18"><strong>No repair proposal yet</strong><span class="small">Select a task and generate a proposal. You will see the model's rationale next to the executable gate verdict.</span></div>`
    }
  `;
}

function renderRepairResult(result) {
  const proposal = result.proposal || {};
  const gate = result.gate || {};
  const accepted = Boolean(gate.accepted);
  const assumptions = proposal.assumptions || [];
  const gaps = proposal.test_gaps || [];
  return `<div class="stack mt-18">
    <div class="panel">
      <div class="panel-head">
        <div>
          <h2>What the model proposed</h2>
          <p>Model text is advisory. The gate result below is the decision.</p>
        </div>
        <div class="row">
          ${pill(accepted ? "gate accepted" : "gate rejected", accepted ? "green" : "red")}
          ${pill(`${Math.round((proposal.confidence || 0) * 100)}% model confidence`, "blue")}
          ${pill(result.model || "model", "green")}
        </div>
      </div>
      <div class="prose">${escapeHtml(proposal.summary || "No summary returned.")}</div>
      <div class="kv-grid mt-12">
        ${kv("Gate result", accepted ? "accepted" : "rejected")}
        ${kv("Example task", result.task_id || "—")}
        ${kv("CWE", result.cwe || "—")}
        ${kv("Latency", `${result.latency_ms ?? 0} ms`)}
        ${kv("Tokens", String(result.usage?.total_tokens ?? 0))}
      </div>
      ${
        assumptions.length
          ? `<div class="mt-12"><strong class="metric-label">Assumptions</strong><ul class="reasons mt-8">${assumptions
              .map((item) => `<li>${escapeHtml(item)}</li>`)
              .join("")}</ul></div>`
          : ""
      }
      ${
        gaps.length
          ? `<div class="mt-12"><strong class="metric-label">Test gaps</strong><ul class="reasons mt-8">${gaps
              .map((item) => `<li>${escapeHtml(item)}</li>`)
              .join("")}</ul></div>`
          : ""
      }
      <div class="row mt-12">
        <button class="btn ghost" type="button" data-action="repair-to-patch">Open generated code in Check a patch</button>
      </div>
    </div>
    ${renderVerifyResult(gate)}
  </div>`;
}

async function runRepair() {
  if (state.busy.repair) return;
  if (!state.repairTask) return;
  if (!state.health?.key_configured) {
    showToast("No Groq key is configured on the server", "error");
    return;
  }
  state.busy.repair = true;
  state.repairError = null;
  state.repairResult = null;
  renderRepair();
  const started = performance.now();
  try {
    const result = await api("/api/repair", {
      method: "POST",
      body: JSON.stringify({ task_id: state.repairTask }),
    });
    state.repairResult = result;
    recordRun({
      taskId: result.task_id,
      candidate: "model repair",
      accepted: Boolean(result.gate?.accepted),
      durationMs: result.gate?.elapsed_ms ?? Math.round(performance.now() - started),
      source: "repair",
      mode: "repair",
    });
    showToast(result.gate?.accepted ? "Repair passed the gate" : "Repair rejected by the gate");
  } catch (error) {
    state.repairError = error.message;
    showToast(error.message, "error");
  } finally {
    state.busy.repair = false;
    renderRepair();
  }
}

async function useRepairInPatch() {
  const result = state.repairResult;
  if (!result?.proposal?.code || !result.task_id) {
    showToast("No generated repair is available", "error");
    return;
  }
  state.view = "patch";
  updateShell();
  await openPatchLab(result.task_id);
  state.patchMode = "source";
  state.patchCode = result.proposal.code;
  state.patchSource = "model proposal";
  state.patchDirty = true;
  state.patchResult = result.gate || null;
  state.patchError = null;
  renderPatchLab();
}

window.addEventListener("DOMContentLoaded", init);
