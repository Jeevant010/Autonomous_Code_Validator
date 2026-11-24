# Autonomous Code Validator

A verifier for security patches and generated code. It checks four things at once:

1. Does the exploit reproduce on the vulnerable baseline?
2. Does the exploit stop working on the candidate?
3. Does the normal behaviour suite still pass?
4. Does a static checker still report a blocking pattern?

The deterministic gate is the decision. The optional live model is a second opinion, not the gate.

The built-in `security_workers/` pack is a calibration set: 11 small, deliberately vulnerable
workers. The newer `project_workers/` pack is a multi-file project set. Both are useful for
testing the verifier, but neither is a public real-world benchmark.

## Quick start

```bash
uv sync --all-extras
uv run acv list
uv run acv show cmd_runner
uv run acv verify cmd_runner semicolon_filter
uv run acv projects
uv run acv verify-project doc_portal --candidate gold
uv run acv verify-project gitpython_cve_2022_24439 --candidate gold
uv run acv verify-project gitpython_cve_2022_24439 --candidate clone_only
uv run pytest
uv run ruff check .
uv run mypy src
```

## Research console

The interactive UI is the fastest way to show the system without relying on terminal output:

```bash
uv run acv serve
```

Open `http://127.0.0.1:8000/`. The server also serves the OpenAPI docs at `/docs`.
If port 8000 is already in use, run `uv run acv serve --port 8017` and open the matching URL.

The console is a view over the real runner, not a static deck:

| Panel | What it does |
| :--- | :--- |
| Dashboard | Run one labeled candidate, see the four-step workflow, corpus status, session run history, last audit, and last qualification |
| How it works | Explains the gate in plain language: choose a target, supply a candidate, run evidence, read the verdict |
| Task explorer | Vulnerable source, exploit, functional test, every candidate, and a live deterministic gate run |
| Patch lab | Paste or load a replacement `worker.py`, or apply a unified diff, then run the same exploit, functional suite, and checker gate. The result includes the exact evaluated source and the applied diff |
| Project verifier | Inspect a complete multi-file project tree, run reference and incomplete fixes, or upload/paste an overlay produced by any model. The exploit and tests live outside the base tree, so generated code cannot replace its own judge |
| Task import | Validate and import a new vulnerability fixture as a JSON bundle into the user pack, without editing the built-in calibration pack |
| Checker qualification | Runs the qualification harness and shows precision, recall, F1, runtime, and exact misses |
| Audit matrix | Runs the full two-sided audit and shows false passes, false rejections, and the checker comparison |
| Model review | Runs one live model review and places it next to the executable gate verdict |
| Repair lab | Asks the model for a candidate repair, then runs the deterministic gate on the generated code. The proposal is advisory; the gate is the verdict |

The UI calls these endpoints: `/api/tasks`, `/api/tasks/{id}`, `/api/verify`,
`/api/verify-code`, `/api/verify-patch`, `/api/tasks/template`, `/api/tasks/validate`,
`/api/tasks/import`, `/api/projects`, `/api/projects/{id}`, `/api/projects/{id}/verify`,
`/api/projects/{id}/verify-patch`, `/api/tools`, `/api/qualify`, `/api/audit`, `/api/review`,
and `/api/repair`. The deterministic panels work without any model key.

The new console features are separately switchable with environment flags:

```bash
ACV_FEATURE_GUIDE=0
ACV_FEATURE_PATCH_PREVIEW=0
ACV_FEATURE_TASK_IMPORT=0
ACV_FEATURE_REPAIR=0
ACV_FEATURE_PROJECTS=0
ACV_FEATURE_PROJECT_LOG=0
uv run acv serve
```

The flags only control the optional console/API features. The deterministic gate is always
present, and the existing verification endpoints keep working.

## Patch lab: run source or a diff supplied by you

The patch lab is the first step toward dynamic intake. It accepts either a full replacement for
the task's `worker.py` or a unified diff against the vulnerable worker, then runs the same
executable gate:

- the original exploit must reproduce on the vulnerable source;
- the original exploit must stop succeeding on the candidate;
- the functional suite must still pass;
- the primary checker must not report a blocking finding.

The oracle check is deliberately separate from the candidate check. If the exploit no longer
works even on the vulnerable source, the run is marked `oracle_ok: false` and is rejected. That
prevents a broken exploit from being mistaken for a fixed patch.

```bash
curl -s http://127.0.0.1:8000/api/tasks/ssrf_redirect \
  | jq -r '.candidates[] | select(.name == "gold") | .code' > /tmp/worker.py

jq -n --rawfile code /tmp/worker.py \
  '{task_id: "ssrf_redirect", code: $code, checker: "acv-rules"}' \
  | curl -s -X POST http://127.0.0.1:8000/api/verify-code \
      -H 'Content-Type: application/json' -d @- | jq
```

For a diff, write a unified diff that targets `worker.py` and post it to `/api/verify-patch`:

```bash
jq -n --rawfile diff /tmp/worker.diff \
  '{task_id: "ssrf_redirect", diff: $diff, checker: "acv-rules"}' \
  | curl -s -X POST http://127.0.0.1:8000/api/verify-patch \
      -H 'Content-Type: application/json' -d @- | jq
```

The API rejects diffs that target anything other than `worker.py` or contain path escapes. The
response is a gate result, not a ground-truth label. `accepted: true` means the supplied source
passed the executable oracle and checker; it does not prove that the source is equivalent to a
reference repair.

**Security boundary.** These endpoints execute caller-supplied Python on the host. The runner
now applies process-level limits (wall-clock timeout, CPU seconds, address space, file size, open
files), starts each run in a fresh process group, and strips common secret-bearing environment
variables. That is containment, not isolation: there is no network namespace or filesystem jail.
Treat all input as trusted and do not expose the server to untrusted users. The next milestone is
a container or micro-VM sandbox with no network, a read-only base, and a writable workspace.


## Project verification: multi-file and generated code

The single-file pack answers "can this verifier catch a small mistake?" It does not answer "can it
judge a generated project with many files, imports, and tests?" The project path is for that second
question.

A project task lives under `project_workers/` and has this shape:

```text
project_workers/doc_portal/
  task.json
  vulnerable/          # complete base tree
    portal/...
  fixed/               # overlay: only files the reference fix changes
    portal/paths.py
  benign/              # a different safe implementation, as an overlay
  mutants/absolute_only/
  poc/exploit.py       # trusted evidence, outside the base tree
  tests/test_functional.py
  data/
```

The manifest names the base tree, evidence, checker scope, limits, and candidate overlays. The
runner copies the base tree to a temporary directory, applies the generated overlay or multi-file
diff, runs the exploit and the full functional suite, and scans every Python file in the declared
checker scope. Acceptance requires all four signals:

```text
oracle_ok && security_pass && behavior_pass && checker_pass
```

The exploit and functional test are not taken from the generated overlay. A generated file cannot
replace `poc/`, `tests/`, `conftest.py`, `pytest.ini`, or interpreter configuration such as
`sitecustomize.py`. This keeps the judge outside the code it is judging.

The included `doc_portal` project is deliberately larger than the single-file fixtures: roughly
18 files and 960 lines, with configuration, storage, search, rendering, authentication, a service
facade, an HTTP router, plugins, a CLI, an exploit, and a functional suite. It is still a
calibration example, not a claim about a real production repository. The GitPython task below is
the real-repository case.

### Real-repository case: GitPython CVE-2022-24439

The second project task is not a toy service. It uses the released **GitPython 3.1.29**
package and its `gitdb` / `smmap` dependencies, with the real CVE-2022-24439
remote-helper command-injection bug.

```text
project_workers/gitpython_cve_2022_24439/
  vulnerable/git/...              # real GitPython 3.1.29 code
  vulnerable/gitdb/...
  vulnerable/smmap/...
  fixed/git/...                   # upstream 3.1.30 fix files
  benign/git/...                  # central guard, different implementation
  mutants/clone_only/git/...      # fixes clone but leaves remote fetch open
  poc/exploit.py                  # two real attack paths
  tests/test_functional.py        # normal clone / fetch behaviour
```

The exploit tries both `Repo.clone_from("ext::sh ...")` and
`Remote.create(...)` followed by `Remote.fetch()`. The upstream fix blocks both;
the `clone_only` mutant blocks the first path and still loses to the second.
Normal local clone and fetch tests must keep passing.

```bash
uv run acv verify-project gitpython_cve_2022_24439 --candidate gold
uv run acv verify-project gitpython_cve_2022_24439 --candidate clone_only
```

Expected result:

| Candidate | Verdict | Evidence |
| :--- | :--- | :--- |
| vulnerable baseline | reject | remote-helper command executes |
| `gold` (upstream 3.1.30) | accept | both paths blocked, normal tests pass |
| `benign` (central guard) | accept | both paths blocked, normal tests pass |
| `clone_only` | reject | clone fixed, remote fetch still executes |

This is a known real vulnerability used to test the verifier. It is not a new
disclosure, and it does not prove that every GitPython code path is covered. The
project runner still uses process limits only; run untrusted code in a VM or
container.

### Bring code from any model

The verifier never calls a model. A studio, notebook, local runner, hosted API, or quantized
model can produce files; the verifier consumes a `path -> text` overlay and decides with the
deterministic gate. This keeps the model boundary explicit and makes the same workflow work with
any model or backend.

```bash
# Run a named reference candidate.
curl -s -X POST http://127.0.0.1:8017/api/projects/doc_portal/verify \
  -H 'Content-Type: application/json' \
  -d '{"candidate": "gold", "checker": "acv-rules"}' | jq '{accepted, rejected_by, reasons}'

# Run generated files, with optional provenance.
curl -s -X POST http://127.0.0.1:8017/api/projects/doc_portal/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "files": {"portal/paths.py": "from pathlib import Path\n...\n"},
    "provenance": {
      "model": "qwen2.5-coder-32b",
      "provider": "local",
      "backend": "vllm",
      "quantization": "AWQ",
      "temperature": 0,
      "seed": 7,
      "prompt": "fix the path traversal"
    }
  }' | jq '{accepted, rejected_by, total_files, total_lines, findings}'
```

The response includes the gate signals, file-level findings with paths and line numbers, an
inventory of the judged tree, the provenance record, an `isolation` warning, and a `run_id`.
Optional provenance is appended to `reports/project_runs.jsonl` when `ACV_FEATURE_PROJECT_LOG` is
enabled. Provenance is observability, not evidence: the gate does not read the model name or the
confidence. The project roots and log path are configurable:

```bash
ACV_PROJECT_PACK=/path/to/project_workers
ACV_USER_PROJECT_PACK=/path/to/user_project_workers
ACV_PROJECT_RUN_LOG=/path/to/project_runs.jsonl
```

### Large-code handling

The project path is bounded on purpose:

- 400 files and 2 MB per project by default, configurable in the manifest;
- 250 overlay files and 1.5 MB per generated overlay;
- 1 MB per checker file and 250 source files per checker run;
- 500 findings per checker, with an explicit `truncated` flag;
- output is clipped to the last 4,000 characters per stream;
- file contents are fetched one at a time by the UI instead of sending the whole tree in every
  response.

These limits make large-code behaviour predictable. They do not make the project path a
real-world benchmark or a replacement for a repository-aware test harness.

### Critical code and isolation

The local project runner uses process limits only: wall-clock timeout, CPU seconds, address
space, file size, open files, and a stripped environment. It has no network namespace, no
filesystem jail, and no container boundary. The API requires
`"criticality": "critical"` plus `"isolation_acknowledged": true` before it will run critical
input, and the result carries that warning. The acknowledgement records the boundary; it does not
create isolation. Critical or untrusted code should be moved to a VM or container with no network
and a disposable workspace before the gate is run.

## Task import: add a fixture without editing the built-in pack

The Task import view edits a single JSON bundle. A bundle contains the task manifest and the
files it references; `task.json` is generated from the manifest during import.

```json
{
  "manifest": {
    "id": "example_cmd_runner",
    "title": "Example command runner",
    "cwe": "CWE-78",
    "summary": "A deliberately vulnerable worker used as an import example.",
    "vulnerable": "vulnerable/worker.py",
    "fixed": "fixed/worker.py",
    "poc": "poc/exploit.py",
    "functional": "tests/test_functional.py",
    "data_dir": "data",
    "candidates": [
      {"name": "gold", "path": "fixed/worker.py", "kind": "gold", "expected_security": true}
    ]
  },
  "files": {
    "vulnerable/worker.py": "...",
    "fixed/worker.py": "...",
    "poc/exploit.py": "...",
    "tests/test_functional.py": "..."
  }
}
```

```bash
curl -s http://127.0.0.1:8017/api/tasks/template | jq > /tmp/task-bundle.json
curl -s -X POST http://127.0.0.1:8017/api/tasks/validate \
  -H 'Content-Type: application/json' -d @/tmp/task-bundle.json | jq
curl -s -X POST http://127.0.0.1:8017/api/tasks/import \
  -H 'Content-Type: application/json' -d @/tmp/task-bundle.json | jq
```

Imported tasks are written to `ACV_USER_PACK` (default `user_security_workers/`, which is
git-ignored). The path is separate from the built-in `security_workers/` calibration pack so
that the two can be developed and versioned independently. Import validates the manifest and
required paths; it does **not** execute the exploit or the candidate. Running an imported task
still goes through the same process-limited gate.

## Model-proposed repairs

`POST /api/repair` asks the configured model for a complete replacement `worker.py`, then runs
the deterministic gate on the generated code:

```bash
curl -s -X POST http://127.0.0.1:8017/api/repair \
  -H 'Content-Type: application/json' \
  -d '{"task_id": "cmd_runner"}' | jq
```

The response contains the model's summary, confidence, assumptions, test gaps, generated source,
and a separate `gate` result. The model never decides acceptance. A generated repair can still
fail because the exploit succeeds, the functional suite regresses, the checker blocks it, or the
generated code is invalid. The Repair lab shows the proposal next to that gate result and can
move the generated source into Patch lab for inspection.

This is a bounded proposal workflow, not a claim of guaranteed automatic repair. It does not
generate new tests, generate a new exploit, or prove semantic equivalence with a reference fix.

## Turning this into research

The current pack is a calibration set. The paper has to add a credible external evaluation, a
clear threat model, and a careful account of what the gate can and cannot prove. The concrete
plan, including dynamic patch intake, exploit adaptation, sandboxing, external benchmarks,
ablations, paper structure, and a one-month timeline, is in
[`docs/RESEARCH_PLAN.md`](docs/RESEARCH_PLAN.md).

## Five-minute demo

Run the failure case first, then the fixed case. That is the story.

```bash
uv run acv list
uv run acv tools
uv run acv qualify --checker acv-rules --checker bandit
uv run acv show ssrf_redirect --candidate initial_only
uv run acv verify ssrf_redirect initial_only
uv run acv verify ssrf_redirect gold
uv run acv audit
```

What each step proves:

| Step | What to say |
| :--- | :--- |
| `acv list` | The vulnerable targets are real files, not hidden behind a deck |
| `acv tools` | We know which checkers are installed and usable |
| `acv qualify` | We measured each checker instead of trusting it |
| `acv show` | The exploit, vulnerable code, and functional test are visible |
| `acv verify initial_only` | The static checker misses it, but the exploit catches it |
| `acv verify gold` | A real fix is accepted only when exploit, behavior, and checker agree |
| `acv audit` | The whole corpus is scored, including false passes and false rejections |

For the model review, add:

```bash
uv run acv review ssrf_redirect initial_only
uv run acv review ssrf_redirect gold
```

The deterministic demo needs no API key. The model path needs `GROQ_API_KEY` in `.env`.

## Adding a checker

Add a file under `src/acv/checkers/` that returns the common `CheckerResult` shape:

```python
from pathlib import Path

from ..models import CheckerResult, CheckFinding

def run_my_tool(path: Path) -> CheckerResult:
    # Run the real tool, parse its JSON, and normalize each finding.
    return CheckerResult(
        tool="my-tool",
        available=True,
        findings=[
            CheckFinding(
                rule_id="MY001",
                cwe="CWE-78",
                severity="high",
                message="command injection",
                line=12,
            )
        ],
    )
```

Register it in `src/acv/checkers/registry.py`:

```python
CheckerAdapter(
    name="my-tool",
    category="sast",
    languages=("python",),
    description="My checker",
    run=run_my_tool,
    available=shutil.which("my-tool") is not None,
)
```

Then it automatically appears in:

```bash
uv run acv tools
uv run acv qualify
uv run acv audit
```

The current adapter interface is **file-level**. Dependency scanners, IaC scanners, container scanners, CodeQL, and DAST need a project-level or service-level adapter; that is the next interface to add.

## Where the vulnerable code actually is

Every task lives in `security_workers/<task>/`:

```text
security_workers/cmd_runner/
├── task.json                 # task metadata and candidate list
├── vulnerable/worker.py      # the vulnerable implementation
├── fixed/worker.py           # the gold fix
├── benign/worker.py          # a different safe implementation
├── mutants/                  # plausible bad fixes
│   ├── semicolon_filter.py
│   └── sh_c_filter.py
├── poc/exploit.py            # executable attack
└── tests/test_functional.py  # behavior that must keep working
```

The vulnerable code is not in `src/acv/`. `src/acv/` is the verifier. The built-in targets are
under `security_workers/`. Imported tasks use the same layout under `user_security_workers/` and
are loaded alongside the built-in pack.

| Task | CWE | Vulnerable file |
| :--- | :--- | :--- |
| `cmd_runner` | CWE-78 | `security_workers/cmd_runner/vulnerable/worker.py` |
| `html_renderer` | CWE-79 | `security_workers/html_renderer/vulnerable/worker.py` |
| `open_redirect` | CWE-601 | `security_workers/open_redirect/vulnerable/worker.py` |
| `path_reader` | CWE-22 | `security_workers/path_reader/vulnerable/worker.py` |
| `pickle_loader` | CWE-502 | `security_workers/pickle_loader/vulnerable/worker.py` |
| `sql_lookup` | CWE-89 | `security_workers/sql_lookup/vulnerable/worker.py` |
| `ssrf_redirect` | CWE-918 | `security_workers/ssrf_redirect/vulnerable/worker.py` |
| `token_random` | CWE-338 | `security_workers/token_random/vulnerable/worker.py` |
| `token_signer` | CWE-798 | `security_workers/token_signer/vulnerable/worker.py` |
| `url_fetcher` | CWE-918 | `security_workers/url_fetcher/vulnerable/worker.py` |
| `yaml_loader` | CWE-94 | `security_workers/yaml_loader/vulnerable/worker.py` |

Example, `cmd_runner`:

```python
# security_workers/cmd_runner/vulnerable/worker.py:7
completed = subprocess.run(
    "echo " + value,
    shell=True,          # attacker input reaches a shell
    capture_output=True,
    text=True,
    check=False,
)
```

The attack is executable:

```python
# security_workers/cmd_runner/poc/exploit.py:12
run_echo("hello; touch ACV_CMD_PWNED")
```

The gold fix removes the shell:

```python
# security_workers/cmd_runner/fixed/worker.py:7
completed = subprocess.run(["echo", value], capture_output=True, text=True, check=False)
```

The behavior test says normal echo must still work:

```python
# security_workers/cmd_runner/tests/test_functional.py:4
assert run_echo("hello") == "hello\n"
```

## What the verifier files do

| File | Job |
| :--- | :--- |
| `src/acv/cli.py` | Commands: `list`, `show`, `verify`, `review`, `audit`, `tools`, `qualify`, `serve` |
| `src/acv/manifest.py` | Loads and validates `task.json`; rejects path escapes |
| `src/acv/models.py` | Typed records for tasks, candidates, findings, results |
| `src/acv/runner.py` | Copies a candidate to a temp dir, runs the exploit, pytest, and checkers |
| `src/acv/toolbench.py` | Scores checkers on the labeled pack: precision, recall, false misses, runtime |
| `src/acv/checkers/registry.py` | Registers every checker through one adapter interface |
| `src/acv/checkers/builtin.py` | Small deterministic rule pack; no network or external service |
| `src/acv/checkers/bandit_adapter.py` | Bandit adapter; reports unavailable if Bandit is absent |
| `src/acv/checkers/semgrep_adapter.py` | Optional Semgrep adapter with normalized JSON findings |
| `src/acv/review.py` | Builds the model prompt, calls the model, compares with the gate |
| `src/acv/repair.py` | Builds a repair prompt, validates the proposal, and runs the deterministic gate |
| `src/acv/task_import.py` | Validates task bundles and publishes them into the user pack |
| `src/acv/features.py` | Environment-driven feature flags for the guided view, patch preview, import, and repair |
| `src/acv/llm/groq.py` | Groq client, structured review schema, and generic JSON completion |
| `src/acv/server.py` | FastAPI research console and verification API |
| `src/acv/web/` | Vanilla HTML/CSS/JS console served by `acv serve`; no build step |
| `src/acv/report.py` | Writes `reports/results.json` and `reports/summary.md` |
| `tests/` | Tests for the verifier itself, not for the vulnerable workers |

`bandit_adapter.py` is not a fake checker. It runs the real `bandit` command when installed.
The built-in `acv-rules` checker is the offline fallback.

## Tool qualification: measure a checker before trusting it

The first step is not “use the best tool.” It is “prove a tool works on labeled data.”

```bash
uv run acv tools
uv run acv qualify
```

`acv tools` lists every registered adapter and whether it is installed. `acv qualify` runs each
checker over the labeled corpus:

- positives: the vulnerable implementation and known-bad mutants
- negatives: the gold fix and the benign safe implementation

It reports true positives, false positives, false negatives, true negatives, precision, recall,
F1, runtime, and the exact missed samples. It writes:

```text
reports/checkers.json
reports/checkers.md
```

On the current 11-task corpus:

| Tool | Available | TP | FP | FN | TN | Precision | Recall | F1 | Runtime |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `acv-rules` | yes | 28 | 1 | 5 | 21 | 96.6% | 84.8% | 90.3% | 42 ms |
| `bandit` | yes | 17 | 3 | 16 | 19 | 85.0% | 51.5% | 64.2% | 7,628 ms |
| `semgrep` | no | - | - | - | - | - | - | - | not installed |

This does **not** mean `acv-rules` is the best checker in the world. It is tuned to this corpus, so
the number is optimistic. The important result is the misses: `acv-rules` misses
`ssrf_redirect/initial_only`, `cmd_runner/sh_c_filter`, and three other known-bad variants. Bandit
misses many more. That is exactly why the dynamic exploit gate is still the authority.

The next qualification step is ensemble scoring: measure `union` (any tool flags) and
`intersection` (all tools agree) so we can see the recall/precision trade-off before adding more
tools.

## Commands

### Inspect the target

```bash
uv run acv list
uv run acv show cmd_runner
uv run acv show cmd_runner --candidate sh_c_filter
```

`show` prints the vulnerable implementation, exploit, functional test, and candidate list with
real file paths and line numbers.

### Run the deterministic gate

```bash
uv run acv verify cmd_runner semicolon_filter
uv run acv verify cmd_runner gold
uv run acv verify sql_lookup benign
uv run acv verify cmd_runner sh_c_filter --json   # known false pass, exits 1
```

`verify` does not call a model and does not need an API key. It exits non-zero when the gate
verdict disagrees with the task ground truth. `cmd_runner/sh_c_filter` is deliberately kept as a
known miss: the shell filter is too weak, but the gate cannot see it.

### Run the live model review

```bash
cp .env.example .env
# add GROQ_API_KEY to .env
uv run acv review cmd_runner sh_c_filter
uv run acv review cmd_runner sh_c_filter --json
```

The default model is `qwen/qwen3.8-27b`. To use the other Groq model:

```bash
ACV_LLM_MODEL=openai/gpt-oss-120b uv run acv review cmd_runner sh_c_filter
```

The `.env` file is git-ignored. The API key stays on the machine.

### Run the whole calibration set

```bash
uv run acv audit
```

This writes `reports/results.json` and `reports/summary.md`. The report keeps false passes and
false rejections in the denominator.

### Serve the research console

```bash
uv run acv serve
```

Open the console at `http://127.0.0.1:8000/`. OpenAPI docs are at
`http://127.0.0.1:8000/docs`. The server keeps the Groq key on the machine; the browser never sees
it. The console is bidirectional: it fetches real task data and can run the gate, qualification,
audit, and live review on demand.

The static assets live in `src/acv/web/` and are served at `/static`. There is no frontend build
step and no static deck to hide behind.

## The verification pipeline

For each candidate, `runner.py`:

1. Creates an isolated temporary directory.
2. Copies the candidate in as `worker.py`.
3. Runs `poc/exploit.py` against it.
4. Runs `tests/test_functional.py` against it.
5. Runs the built-in checker and every available registry adapter.
6. Accepts only when the exploit is blocked, behavior passes, and the checker is quiet.

The model review runs after the candidate source is loaded. It sees the vulnerable code, the
exploit, the functional test, and the candidate. It does not see the expected verdict.

## Repair mapping: from finding to verified fix

Detection is only half the system. The repair side needs a mapping with evidence, not a free-form
“here is a patch” answer.

For every finding, create a repair record:

```text
finding -> vulnerable file + line + CWE
        -> candidate fixes (gold, benign, model-generated)
        -> apply fix in a temporary worktree
        -> run functional tests
        -> run the exploit/PoC
        -> re-run the checkers
        -> run differential behavior checks
        -> accept only if every signal agrees
```

The repair gate is the same deterministic gate, with one addition: the fixer must not be allowed
to edit the tests or the exploit to make itself pass. Those files are part of the oracle, not the
candidate.

The repair loop should be:

1. **Locate** the source-to-sink path.
2. **Propose** the smallest fix.
3. **Apply** it to an isolated copy.
4. **Prove** the exploit is blocked.
5. **Prove** the functional tests still pass.
6. **Re-scan** to confirm the finding is gone.
7. **Reject** if the fix is only an input filter for the test case.

The Repair lab implements steps 2–7 as a single bounded proposal: the model suggests a fix, the
gate applies it in a fresh temporary directory, and the exploit, functional suite, and checker
decide whether it is accepted. There is still no CLI command for it, and there is no multi-step
repair loop that locates the sink, rewrites tests, or generates a new exploit. `acv verify
<task> <candidate>` remains the manual version of the deterministic gate.

## Hard network cases to add next

`url_fetcher` is intentionally simple: it has no host allowlist. `ssrf_redirect` is the first
harder case: the initial URL passes an allowlist, but `urlopen` follows a redirect to
`127.0.0.1`. A candidate that only fixes the first hop is still rejected by the exploit.

```bash
uv run acv show ssrf_redirect --candidate initial_only
uv run acv verify ssrf_redirect initial_only
```

Recommended next tasks:

| Task | Why it is hard |
| :--- | :--- |
| `dns_rebinding` | Hostname resolves to a public IP during validation, then a private IP at connect time |
| `request_smuggling` | Proxy and backend disagree on `Content-Length` / `Transfer-Encoding` |
| `jwt_confusion` | Public key is accepted as an HMAC secret; `alg` handling is wrong |
| `websocket_auth` | HTTP auth is checked, but the WebSocket upgrade path skips it |
| `path_symlink` | Path join looks safe, then a symlink escapes the sandbox |
| `race_file` | Check-then-open is vulnerable to a TOCTOU race |
| `tenant_idor` | Object lookup checks authentication but not tenant ownership |
| `graphql_authz` | Top-level resolver is guarded; nested fields are not |
| `template_injection` | User data reaches a template engine with expression evaluation |

No single case is guaranteed to defeat every model. Difficulty comes from hidden tests, runtime
state, protocol behavior, and cross-file context, not from obscurity.

## Reference repositories to calibrate against

Use these instead of presenting the 11 synthetic workers as a benchmark:

- **OWASP Benchmark** — SAST/DAST ground truth, 2,740 Java cases:
  https://github.com/OWASP-Benchmark/BenchmarkJava
- **Vul4J** — reproducible real Java vulnerabilities with failing/passing tests:
  https://github.com/tuhh-softsec/Vul4J
- **CVEfixes** — real CVE-fixing commits across languages:
  https://github.com/secureIT-project/CVEfixes
- **CVE-bench** — SWE-bench-style benchmark for repairing real CVEs:
  https://github.com/WhileBug/CVEBench
- **SWE-bench Verified** — real GitHub issue/patch evaluation, not security-specific:
  https://github.com/swe-bench/SWE-bench
- **VulnBench** — LLM security patch generation benchmark:
  https://github.com/vulnbench/vulnbench
- **OWASP Juice Shop**, **WebGoat**, **DVWA** — real vulnerable apps for demos:
  https://github.com/juice-shop/juice-shop
  https://github.com/WebGoat/WebGoat
  https://github.com/digininja/DVWA
- **Meta CyberSecEval / PurpleLlama** — LLM security evaluation:
  https://github.com/meta-llama/PurpleLlama

The right story is: this repo is the verifier; the external benchmark is the evidence. Do not call
the calibration pack a real-world benchmark.

## Current limits

- The task pack is synthetic and small.
- Checker scores are optimistic because the corpus is tuned to the built-in rules.
- There is no ensemble scoring yet (union/intersection of tools).
- Unified-diff intake is limited to a single `worker.py`; the project path supports multi-file
  overlays and multi-file diffs, but only for the Python projects configured under
  `project_workers/`.
- The project pack currently contains one calibration example. It demonstrates scale, file-level
  evidence, and model-agnostic intake; it is not an external benchmark.
- The project path does not install dependencies, resolve a Git URL, or import an arbitrary real
  repository. Those belong behind an isolated runner and an explicit dependency policy.
- Repair generation is a single model proposal followed by the gate. There is no multi-step
  repair loop, no generated test suite, and no proof that a generated patch is semantically
  equivalent to a reference fix.
- Imported tasks are validated structurally but not automatically audited; running them is still
  an explicit action.
- Execution has process-level limits but no network or filesystem isolation. It is not a
  hardened sandbox.
- There is no SARIF normalizer, PR comment, or CI gate yet.
- The model review is advisory and can be wrong.
- A model failing one hard case is not proof that all models fail it.

## Next implementation order

See `docs/RESEARCH_PLAN.md` for the prioritized build and evaluation plan. The short version is:
container sandbox, external benchmark importer, held-out repository evaluation, structured test
parsing, and artifact packaging.

5. Parse structured pytest JSON instead of text.
6. Run untrusted code in Docker or gVisor.
7. Add external benchmark adapters (OWASP Benchmark, Vul4J, CVE-bench).
8. Add a held-out repository set before calling the project path a real-world benchmark.
