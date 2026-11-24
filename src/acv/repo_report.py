"""HTML dashboard for the real-repository benchmark.

Design constraints come from the project's readability complaints: a 16px text
floor, no unexplained jargon, and a verdict explained in a sentence next to the
evidence. Self-contained, zero external asset dependencies, zero JS frameworks.
"""

from __future__ import annotations

import html
from typing import Any

CSS = """
:root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --border: #e2e8f0;
  --border-subtle: #edf2f7;
  --text: #0f172a;
  --muted: #64748b;
  --green: #0f766e;
  --green-bg: #f0fdfa;
  --green-border: #99f6e4;
  --red: #be123c;
  --red-bg: #fff1f2;
  --red-border: #fecdd3;
  --amber: #b45309;
  --amber-bg: #fffbeb;
  --amber-border: #fde68a;
  --blue: #1d4ed8;
  --blue-bg: #eff6ff;
  --blue-border: #bfdbfe;
  --purple: #6d28d9;
  --purple-bg: #f5f3ff;
  --purple-border: #ddd6fe;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 44px 24px 96px;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
.wrap { max-width: 1140px; margin: 0 auto; }
h1 { font-size: 34px; line-height: 1.25; margin: 0 0 8px; letter-spacing: -0.025em; font-weight: 800; }
h2 { font-size: 24px; margin: 44px 0 10px; letter-spacing: -0.015em; font-weight: 700; }
h3 { font-size: 18px; margin: 0 0 6px; font-weight: 600; }
.lede { font-size: 18px; color: var(--muted); margin: 0 0 24px; max-width: 820px; line-height: 1.6; }
.meta { color: var(--muted); font-size: 14.5px; margin-bottom: 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin: 24px 0 28px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
.card .k { font-size: 13.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-bottom: 6px; }
.card .v { font-size: 28px; font-weight: 800; letter-spacing: -0.03em; color: var(--text); }
.card.highlight { border-color: var(--green-border); background: var(--green-bg); }
.card.highlight .v { color: var(--green); }

.filter-bar { display: flex; gap: 8px; margin: 24px 0 16px; flex-wrap: wrap; }
.filter-btn { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 8px 16px; font-size: 14.5px; font-weight: 600; cursor: pointer; color: var(--muted); transition: all 0.15s ease; }
.filter-btn:hover { border-color: var(--muted); color: var(--text); }
.filter-btn.active { background: var(--text); color: #fff; border-color: var(--text); }

.guide-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px 28px; margin: 28px 0; }
.guide-panel h3 { font-size: 19px; margin-top: 0; margin-bottom: 12px; }
.guide-panel p { margin: 8px 0; color: var(--text); }
.guide-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-top: 16px; }
.guide-step { background: var(--bg); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 16px; font-size: 15px; }
.guide-step strong { display: block; margin-bottom: 6px; color: var(--text); }

table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; font-size: 15px; margin-top: 10px; }
th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: #f1f5f9; font-size: 13.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 700; }
tr:last-child td { border-bottom: none; }
tr:hover td { background-color: #fafbfc; }

code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13.5px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }
pre code { display: block; padding: 12px 16px; overflow-x: auto; background: #0f172a; color: #f8fafc; border-radius: 8px; line-height: 1.5; font-size: 13px; }

.pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 13px; font-weight: 700; white-space: nowrap; }
.ok { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
.bad { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
.warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-right: 8px; vertical-align: middle; }
.badge-cve { background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border); }
.badge-clean { background: var(--purple-bg); color: var(--purple); border: 1px solid var(--purple-border); }

.taskblock { margin: 28px 0; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 22px 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
.taskblock h2 { margin: 0 0 6px; font-size: 21px; display: flex; align-items: center; flex-wrap: wrap; }
.detail { color: var(--muted); font-size: 14.5px; margin: 4px 0 12px; }
.why { font-size: 14px; color: var(--muted); margin-top: 4px; }
footer { margin-top: 60px; color: var(--muted); font-size: 14.5px; border-top: 1px solid var(--border); padding-top: 24px; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def render_dashboard(payload: dict[str, Any]) -> str:
    totals = payload["totals"]
    rows = payload["tasks"]

    clean_count = sum(1 for r in rows if r.get("clean_baseline") or r.get("cwe") == "CWE-None")
    cve_count = len(rows) - clean_count

    cards = "".join(
        f'<div class="card { "highlight" if "agreements" in label or "accepts" in label else "" }">'
        f'<div class="k">{_esc(label)}</div>'
        f'<div class="v">{_esc(value)}</div></div>'
        for label, value in (
            ("Production Repositories", totals["tasks"]),
            ("CVE Vulnerability Tasks", cve_count),
            ("Clean Control Repositories", clean_count),
            ("Total Scenarios Judged", totals["cases"]),
            ("Verdicts Correct", f'{totals["agreements"]}/{totals["cases"]}'),
            ("False Accepts (Safety Gate)", totals["false_accepts"]),
        )
    )

    blocks: list[str] = []
    for row in rows:
        is_clean = bool(row.get("clean_baseline") or row.get("cwe") == "CWE-None")
        category = "clean" if is_clean else "cve"
        category_badge = (
            '<span class="badge badge-clean">Negative Control (Clean)</span>'
            if is_clean
            else '<span class="badge badge-cve">Vulnerability Benchmark</span>'
        )

        if "cases" not in row:
            blocks.append(
                f'<div class="taskblock" data-category="{category}">'
                f'<h2>{category_badge} {_esc(row.get("task"))}</h2>'
                f'<p class="why">This task could not run: {_esc(row.get("error"))}</p></div>'
            )
            continue

        live = row.get("live") or {}
        live_status = str(live.get("status", "") or "")
        live_note = str(live.get("detail", "") or "")
        if live_status:
            tone = {"unfixed": "bad", "fixed": "ok", "unknown": "warn"}.get(live_status, "")
            display_status = "CLEAN ON MAIN" if is_clean and live_status == "fixed" else live_status.upper()
            live_html = (
                f'<p class="detail">Live default branch '
                f'(<span class="mono">{_esc(live.get("branch", ""))}</span> @ '
                f'<span class="mono">{_esc(str(live.get("head_commit", ""))[:12])}</span>): '
                f'<span class="pill {tone}">{_esc(display_status)}</span> &middot; '
                f'<span class="why">{_esc(live_note)}</span></p>'
            )
        else:
            live_html = ""

        body = []
        for label, case in row["cases"].items():
            verdict = case.get("verdict", "?")
            matched = case.get("ok")
            css = "ok" if verdict == "ACCEPT" else "bad"
            expected = case.get("expected", "")
            mark = "matches expectation" if matched else "DOES NOT match expectation"
            why = _explain(case, is_clean=is_clean)
            behavior_label = "exit 0" if case.get("behavior_exit") == 0 else f"exit {case.get('behavior_exit')}"
            body.append(
                "<tr>"
                f"<td><strong>{_esc(label)}</strong></td>"
                f"<td><span class='pill {css}'>{_esc(verdict)}</span>"
                f"<div class='why'>expected {_esc(expected)} &middot; {_esc(mark)}</div></td>"
                f"<td>{_esc(case.get('rejected_by', 'none'))}<div class='why'>{why}</div></td>"
                f"<td>{_esc(case.get('oracle', ''))} / {_esc(case.get('poc', ''))} / pytest {_esc(behavior_label)}</td>"
                f"<td class='mono'>{_esc(', '.join(case.get('changed', [])) or 'no change')}</td>"
                f"<td class='mono'>{_esc(case.get('files', ''))} files<br>"
                f"{_esc(case.get('lines', ''))} lines</td>"
                "</tr>"
            )

        task_id = str(row["task"])
        repo_clean_url = str(row.get("repo_url", "")).replace("https://github.com/", "")
        blocks.append(
            f'<div class="taskblock" data-category="{category}">'
            f'<h2>{category_badge} {_esc(task_id)}</h2>'
            f'<p class="detail"><strong>{_esc(row.get("cwe"))}</strong> &middot; '
            f'<a href="{_esc(row.get("repo_url", ""))}" target="_blank" class="mono">{_esc(repo_clean_url)}</a>'
            f' &middot; pinned commit <span class="mono">{_esc(str(row.get("commit", ""))[:12])}</span></p>'
            f"{live_html}"
            f'<table><thead><tr><th>Scenario Case</th><th>Gate Verdict</th><th>Gate Reason</th>'
            f'<th>Evidence (Oracle / PoC / Tests)</th><th>Files Touched</th><th>Code Size</th>'
            f'</tr></thead><tbody>{"".join(body)}</tbody></table>'
            f"</div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Autonomous Code Validator - Repository Benchmark Dashboard</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Autonomous Code Validator: Real-World Multi-Repo Verification</h1>
  <p class="lede">
    Real-world repositories cloned live from GitHub, tested against deterministic security
    oracles, full unit test suites, and static AST containment gates. Evaluates both
    <strong>Vulnerable Repositories (CVE Benchmarks)</strong> and <strong>Clean Repositories (Negative Controls)</strong>
    to guarantee zero false accepts and zero false alarms on production codebases.
  </p>
  <p class="meta">Benchmark Report Generated: <strong>{_esc(payload["generated_at"])}</strong> &middot; Multi-Oracle Containment: Active</p>
  
  <div class="cards">{cards}</div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="setFilter('all', this)">All Repositories ({len(rows)})</button>
    <button class="filter-btn" onclick="setFilter('cve', this)">Vulnerable &amp; Repaired ({cve_count})</button>
    <button class="filter-btn" onclick="setFilter('clean', this)">Clean Negative Controls ({clean_count})</button>
  </div>

  <div class="guide-panel">
    <h3>Where to Put New Code &amp; How to Run Verification</h3>
    <p>ACV is completely decoupled from mock files: it evaluates real codebases in contained workspaces.</p>
    <div class="guide-grid">
      <div class="guide-step">
        <strong>1. Verify Candidate Code from CLI</strong>
        <p>Run deterministic gate against any task with your custom patch:</p>
        <pre><code>uv run acv repo-verify &lt;task_id&gt; --diff patch.diff</code></pre>
      </div>
      <div class="guide-step">
        <strong>2. Generate PR / Merge Request</strong>
        <p>Automatically create a local hardening branch with full test evidence:</p>
        <pre><code>uv run acv repo-harden &lt;task_id&gt; --diff patch.diff</code></pre>
      </div>
      <div class="guide-step">
        <strong>3. Intake New Repositories</strong>
        <p>Drop a new folder in <code>repo_tasks/&lt;new_task_id&gt;/</code> with <code>task.json</code>, <code>poc/exploit.py</code>, and <code>tests/test_functional.py</code>.</p>
      </div>
    </div>
  </div>

  {"".join(blocks)}

  <div class="guide-panel">
    <h3>Deterministic Oracle Contract &amp; Safety Boundary</h3>
    <p>
      A candidate patch is accepted if and only if:
      (1) The security attack is blocked (exit 1 without crash),
      (2) The repository's own test suite passes (exit 0),
      (3) No new blocking AST checker findings are introduced, and
      (4) Protected test files and oracle definitions are never modified.
    </p>
  </div>

  <footer>
    Autonomous Code Validator (ACV) &middot; Evaluated on live clones of GitPython, Jinja2, PyYAML, Requests, urllib3, sqlparse, and Click.
  </footer>
</div>

<script>
function setFilter(type, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.taskblock').forEach(block => {{
    if (type === 'all' || block.getAttribute('data-category') === type) {{
      block.style.display = 'block';
    }} else {{
      block.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>
"""


def _explain(case: dict[str, Any], *, is_clean: bool = False) -> str:
    verdict = case.get("verdict")
    if verdict == "ACCEPT":
        if is_clean:
            return "clean baseline verified: tests pass, 0 vulnerabilities"
        return "attack blocked, unit tests pass, no new AST findings"
    if verdict == "ERROR":
        return _esc(case.get("error", "the run could not complete"))
    by = case.get("rejected_by")
    if by == "poc":
        return "attack still succeeded (vulnerability active)"
    if by == "behavior":
        return "repository functional test suite failed (regression)"
    if by == "checker":
        return "patch introduced an unsafe AST rule finding or backdoor"
    if by == "oracle":
        return "attack did not reproduce on unpatched baseline"
    return "rejected by safety gate"
