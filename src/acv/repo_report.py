"""HTML dashboard for the real-repository benchmark.

Design constraints come from the project's readability complaints: a 16px text
floor, no unexplained jargon, and a verdict explained in a sentence next to the
evidence. No external assets, no build step, no JavaScript framework.
"""

from __future__ import annotations

import html
from typing import Any

CSS = """
:root {
  --bg: #f7f8fa;
  --surface: #ffffff;
  --border: #dfe3e8;
  --text: #14181f;
  --muted: #5b6472;
  --green: #0f7b4f;
  --green-bg: #e8f6ef;
  --red: #b3261e;
  --red-bg: #fdecea;
  --amber: #8a5a00;
  --amber-bg: #fdf3e0;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 40px 24px 80px;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
.wrap { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 34px; line-height: 1.2; margin: 0 0 8px; letter-spacing: -0.02em; }
h2 { font-size: 23px; margin: 40px 0 6px; letter-spacing: -0.01em; }
.lede { font-size: 18px; color: var(--muted); margin: 0 0 28px; max-width: 760px; }
.meta { color: var(--muted); font-size: 15px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin: 24px 0 8px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 18px 20px; }
.card .k { font-size: 15px; color: var(--muted); margin-bottom: 6px; }
.card .v { font-size: 30px; font-weight: 700; letter-spacing: -0.02em; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; font-size: 16px; }
th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: #f1f3f6; font-size: 15px; text-transform: none; color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 14.5px; }
.pill { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 14.5px; font-weight: 600; white-space: nowrap; }
.ok { background: var(--green-bg); color: var(--green); }
.bad { background: var(--red-bg); color: var(--red); }
.warn { background: var(--amber-bg); color: var(--amber); }
.taskblock { margin: 28px 0 12px; }
.detail { color: var(--muted); font-size: 15px; }
.why { font-size: 15px; color: var(--muted); margin-top: 4px; }
footer { margin-top: 48px; color: var(--muted); font-size: 15px; border-top: 1px solid var(--border); padding-top: 20px; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _cell(value: Any) -> str:
    return html.escape(str(value))


def render_dashboard(payload: dict[str, Any]) -> str:
    totals = payload["totals"]
    rows = payload["tasks"]

    cards = "".join(
        f'<div class="card"><div class="k">{_esc(label)}</div>'
        f'<div class="v">{_esc(value)}</div></div>'
        for label, value in (
            ("Real repositories", totals["tasks"]),
            ("Cases run", totals["cases"]),
            ("Verdicts correct", totals["agreements"]),
            ("False accepts", totals["false_accepts"]),
        )
    )

    blocks: list[str] = []
    for row in rows:
        if "cases" not in row:
            blocks.append(
                f'<div class="taskblock"><h2>{_esc(row.get("task"))}</h2>'
                f'<p class="why">This task could not run: {_esc(row.get("error"))}</p></div>'
            )
            continue

        live = row.get("live") or {}
        live_status = str(live.get("status", "") or "")
        live_note = str(live.get("detail", "") or "")
        if live_status:
            tone = {"unfixed": "bad", "fixed": "ok", "unknown": "warn"}.get(live_status, "")
            live_html = (
                f'<p class="detail">On the live default branch '
                f'(<span class="mono">{_esc(live.get("branch", ""))}</span> at '
                f'<span class="mono">{_esc(str(live.get("head_commit", ""))[:12])}</span>): '
                f'<span class="pill {tone}">{_esc(live_status)}</span> '
                f'<span class="why">{_esc(live_note)}</span></p>'
            )
        else:
            live_html = ""

        body = []
        for label, case in row["cases"].items():
            verdict = case.get("verdict", "?")
            matched = case.get("ok")
            # Colour by the verdict, not by whether the expectation matched:
            # a green pill on a rejected patch reads as "this code is fine".
            css = "ok" if verdict == "ACCEPT" else "bad"
            expected = case.get("expected", "")
            mark = "matches expectation" if matched else "DOES NOT match expectation"
            why = _explain(case)
            body.append(
                "<tr>"
                f"<td><strong>{_esc(label)}</strong></td>"
                f"<td><span class='pill {css}'>{_esc(verdict)}</span>"
                f"<div class='why'>expected {_esc(expected)} &middot; {_esc(mark)}</div></td>"
                f"<td>{_esc(case.get('rejected_by', ''))}<div class='why'>{why}</div></td>"
                f"<td>{_esc(case.get('oracle', ''))} / {_esc(case.get('poc', ''))} / "
                f"{_esc(case.get('behavior_exit', ''))}</td>"
                f"<td class='mono'>{_esc(', '.join(case.get('changed', [])) or 'no change')}</td>"
                f"<td class='mono'>{_esc(case.get('files', ''))} files<br>"
                f"{_esc(case.get('lines', ''))} lines</td>"
                "</tr>"
            )

        blocks.append(
            f'<div class="taskblock">'
            f'<h2>{_esc(row["task"])}</h2>'
            f'<p class="detail">{_esc(row.get("cwe"))} &middot; '
            f'<span class="mono">{_esc(row.get("repo_url", "").replace("https://github.com/", ""))}</span>'
            f' &middot; commit <span class="mono">{_esc(str(row.get("commit", ""))[:12])}</span></p>'
            f"{live_html}"
            f'<table><thead><tr><th>Case</th><th>Verdict</th><th>Stopped by</th>'
            f'<th>Attack / fix / tests</th><th>Files changed</th><th>Code judged</th>'
            f'</tr></thead><tbody>{"".join(body)}</tbody></table>'
            f"</div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Real repository verification</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Verifying fixes against real open-source repositories</h1>
  <p class="lede">
    Each repository is cloned from GitHub at a release commit, its own test suite is run,
    and a trusted attack script is executed against it. Three patches are judged per
    repository: no patch, the real upstream fix, and a half fix that looks plausible.
    A correct system rejects the first and third, and accepts the second.
  </p>
  <p class="meta">Generated {_esc(payload["generated_at"])}</p>
  <div class="cards">{cards}</div>

  <h2>How to read a row</h2>
  <p class="detail">
    <strong>Attack</strong> is the script that proves the weakness is reachable.
    <strong>Fix</strong> is the patch under test. <strong>Tests</strong> is the
    repository's own suite, which must keep passing. A patch is accepted only when
    the attack is blocked, the tests pass, and the patch introduces no new static
    finding. Pre-existing findings in untouched code never block a patch.
  </p>

  {"".join(blocks)}

  <footer>
    These are real CVEs in real repositories. Four repositories is a demonstration,
    not a benchmark: no statistical claim is made about model families, sizes, or
    quantisation from this table.
  </footer>
</div>
</body>
</html>
"""


def _explain(case: dict[str, Any]) -> str:
    verdict = case.get("verdict")
    if verdict == "ACCEPT":
        return "attack blocked, tests pass, no new finding"
    if verdict == "ERROR":
        return _esc(case.get("error", "the run could not complete"))
    by = case.get("rejected_by")
    if by == "poc":
        return "the attack still worked"
    if by == "behavior":
        return "the repository's own tests failed"
    if by == "checker":
        return "the patch added a static finding"
    if by == "oracle":
        return "the attack did not reproduce, so nothing was proven"
    return "rejected"
