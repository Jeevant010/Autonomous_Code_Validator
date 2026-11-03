(() => {
  "use strict";

  const data = window.ACV_DATA;
  const summary = data && data.summary;
  const byId = (id) => document.getElementById(id);
  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (character) => {
      const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };
      return map[character];
    });
  const pct = (value) => `${(Number(value || 0) * 100).toFixed(1)}%`;
  const number = (value) => String(value ?? 0);
  const displayName = (name) => (name === "acv-rules" ? "ACV rules" : name === "bandit" ? "Bandit" : name);

  const explanations = {
    "cmd_runner/sh_c_filter": {
      reason:
        "The exploit is blocked because the candidate strips the separator, but the worker still hands input to a shell through sh -c. The rule pack does not model that wrapper.",
      context:
        "Security pass: true. Behavior pass: true. Checker pass: true. The gate accepted a known-bad variant. This is the residual false pass.",
    },
    "sql_lookup/benign": {
      reason:
        "The candidate removes single quotes before interpolation. The exploit is blocked and the functional suite passes, but the SQL rule is conservative and rejects the string-built query.",
      context:
        "Security pass: true. Behavior pass: true. Checker pass: false. The gate rejected a safe variant. This is the residual false rejection.",
    },
  };

  if (!data || !summary) {
    const main = document.querySelector("main");
    if (main) {
      main.innerHTML = `
        <section class="section">
          <div class="section-head">
            <p class="eyebrow">No audit data</p>
            <h2>Run the audit first.</h2>
            <p>The presentation reads <code>presentation/data.js</code>. Generate it locally, then reopen this file.</p>
          </div>
          <div class="terminal">
            <div class="terminal-bar"><span></span><span></span><span></span><em>bash</em></div>
            <pre><code><span class="prompt">$</span> uv sync --all-extras
<span class="prompt">$</span> uv run acv audit</code></pre>
          </div>
        </section>`;
    }
    return;
  }

  const tasks = Array.isArray(data.tasks) ? data.tasks : [];
  const allCandidates = tasks.flatMap((task) =>
    (task.candidates || []).map((candidate) => ({ ...candidate, task })),
  );
  const checkers = Array.isArray(summary.checkers) ? summary.checkers : [];

  const setText = (id, value) => {
    const element = byId(id);
    if (element) element.textContent = value;
  };

  setText("stat-accuracy", pct(summary.verdict_accuracy));
  setText("stat-tasks", number(summary.tasks));
  setText("stat-candidates", number(summary.candidates));
  setText("stat-cwes", number(summary.cwe_families));
  setText("stat-gold", `${number(summary.gold_accepted)}/${number(summary.gold)}`);
  setText("stat-mutants", `${number(summary.mutants_rejected)}/${number(summary.mutants)}`);
  setText("stat-fp", number(summary.false_passes));
  setText("stat-fr", number(summary.false_rejections));

  const matrix = summary.matrix || {};
  setText("matrix-ss", number(matrix.security_pass_behavior_pass));
  setText("matrix-sf", number(matrix.security_pass_behavior_fail));
  setText("matrix-fs", number(matrix.security_fail_behavior_pass));
  setText("matrix-ff", number(matrix.security_fail_behavior_fail));
  setText("matrix-correct", `${number(summary.correct_verdicts)} / ${number(summary.candidates)}`);
  setText("matrix-correct-sub", `of ${number(summary.candidates)} candidates`);

  setText("terminal-tasks", number(summary.tasks));
  setText("terminal-candidates", number(summary.candidates));
  setText("terminal-verdicts", `${number(summary.correct_verdicts)}/${number(summary.candidates)}`);
  setText("terminal-fp", number(summary.false_passes));
  setText("terminal-fr", number(summary.false_rejections));

  const generated = byId("generated");
  if (generated) {
    const stamp = String(data.generated_at || "").replace("T", " ").replace("+00:00", " UTC");
    generated.textContent = stamp ? `Generated ${stamp}` : "Generated locally";
  }

  const hasRisk = (task) =>
    (task.candidates || []).some(
      (candidate) =>
        (candidate.kind === "mutant" && candidate.accepted) ||
        ((candidate.kind === "gold" || candidate.kind === "benign") && !candidate.accepted),
    );

  const chipFor = (candidate) => {
    let className = "chip";
    let outcome = "checked";

    if (candidate.kind === "mutant") {
      className += candidate.accepted ? " chip-bad" : " chip-good";
      outcome = candidate.accepted ? "false pass" : "blocked";
    } else if (candidate.kind === "benign") {
      className += candidate.accepted ? " chip-good" : " chip-warn";
      outcome = candidate.accepted ? "safe" : "false reject";
    } else {
      className += candidate.accepted ? " chip-good" : " chip-bad";
      outcome = candidate.accepted ? "fix" : "rejected";
    }

    const detail = (candidate.reasons || []).join("; ");
    const title = `${candidate.kind} ${candidate.name}: ${outcome}${detail ? ` - ${detail}` : ""}`;

    return `<span class="${className}" title="${escapeHtml(title)}"><span class="chip-dot"></span><span>${escapeHtml(
      candidate.name,
    )}</span><span class="chip-outcome">${escapeHtml(outcome)}</span></span>`;
  };

  const taskCard = (task, index) => {
    const risk = hasRisk(task);
    const chips = (task.candidates || []).map(chipFor).join("");
    return `
      <article class="task-card${risk ? " is-risk" : ""}" data-risk="${risk}" style="animation-delay:${Math.min(
        index * 45,
        320,
      )}ms">
        <div class="task-top">
          <span class="cwe">${escapeHtml(task.cwe)}</span>
          <span class="baseline ${task.baseline_ok ? "is-ok" : "is-fail"}">baseline ${
            task.baseline_ok ? "ok" : "failed"
          }</span>
        </div>
        <h3>${escapeHtml(task.title)}</h3>
        <div class="task-id">${escapeHtml(task.task_id)}</div>
        <p class="task-summary">${escapeHtml(task.summary)}</p>
        <div class="candidate-row">${chips}</div>
      </article>`;
  };

  const taskGrid = byId("task-grid");
  if (taskGrid) taskGrid.innerHTML = tasks.map(taskCard).join("");

  const filters = Array.from(document.querySelectorAll(".filter"));
  const applyFilter = (filter) => {
    filters.forEach((button) => {
      const active = button.dataset.filter === filter;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    document.querySelectorAll(".task-card").forEach((card) => {
      const risk = card.dataset.risk === "true";
      const visible =
        filter === "all" || (filter === "risk" && risk) || (filter === "clean" && !risk);
      card.classList.toggle("is-hidden", !visible);
    });
  };
  filters.forEach((button) => {
    button.addEventListener("click", () => applyFilter(button.dataset.filter || "all"));
  });
  applyFilter("all");

  const meter = (label, value, detail, danger = false) => {
    const width = Math.max(0, Math.min(100, Number(value || 0) * 100)).toFixed(1);
    return `
      <div class="meter">
        <div class="meter-label"><span>${escapeHtml(label)}</span><strong>${pct(value)}</strong></div>
        <div class="bar${danger ? " is-danger" : ""}"><span style="width:${width}%"></span></div>
        <div class="meter-label"><span>${escapeHtml(detail)}</span></div>
      </div>`;
  };

  const checkerCard = (checker) => {
    const isDefault = checker.name === "acv-rules";
    const availability = checker.available ? "available" : "unavailable";
    return `
      <article class="checker-card">
        <div class="checker-head">
          <div>
            <h3>${escapeHtml(displayName(checker.name))}</h3>
            <div class="checker-version">v${escapeHtml(checker.version || "unknown")} / ${availability}</div>
          </div>
          <span class="badge${isDefault ? " is-default" : ""}">${isDefault ? "gate default" : "comparison"}</span>
        </div>
        <div class="meter-group">
          ${meter("Recall", checker.recall, `${number(checker.recall_hits)}/${number(checker.recall_total)} flagged`)}
          ${meter(
            "Precision",
            checker.precision,
            `${number(checker.precision_hits)}/${number(checker.precision_total)} clean`,
          )}
          ${meter(
            "False repair",
            checker.false_repair,
            `${number(checker.missed_mutants)}/${number(checker.mutants)} missed`,
            true,
          )}
        </div>
      </article>`;
  };

  const checkerGrid = byId("checker-grid");
  if (checkerGrid) checkerGrid.innerHTML = checkers.map(checkerCard).join("");

  const residual = allCandidates.filter(
    (candidate) =>
      (candidate.kind === "mutant" && candidate.accepted) ||
      ((candidate.kind === "gold" || candidate.kind === "benign") && !candidate.accepted),
  );

  const residualCard = (candidate) => {
    const falsePass = candidate.kind === "mutant" && candidate.accepted;
    const key = `${candidate.task_id}/${candidate.name}`;
    const explanation = explanations[key] || {};
    const reasons = (candidate.reasons || []).join("; ");
    const reason = explanation.reason || reasons || "The gate and ground truth disagree on this candidate.";
    const context =
      explanation.context ||
      `Security ${candidate.security_pass ? "pass" : "fail"}. Behavior ${
        candidate.behavior_pass ? "pass" : "fail"
      }. Checker ${candidate.checker_pass ? "pass" : "fail"}.`;
    return `
      <article class="residual-card${falsePass ? " is-false-pass" : ""}">
        <div class="residual-kicker">${falsePass ? "False pass" : "False rejection"}</div>
        <h3>${escapeHtml(candidate.task_title || candidate.task.title)}</h3>
        <div class="residual-id">${escapeHtml(key)}</div>
        <p class="residual-reason">${escapeHtml(reason)}</p>
        <p>${escapeHtml(context)}</p>
      </article>`;
  };

  const residualGrid = byId("residual-grid");
  if (residualGrid) {
    residualGrid.innerHTML = residual.length
      ? residual.map(residualCard).join("")
      : `<article class="residual-card"><div class="residual-kicker">No residual cases</div><h3>The gate and ground truth agreed on every candidate.</h3><p>Add a new mutant or a new checker to make the next gap visible.</p></article>`;
  }
})();
