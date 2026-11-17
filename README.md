# Autonomous Code Validator

A verifier for security patches. It checks three things at once:

1. Does the exploit still work?
2. Does the worker still behave correctly?
3. Does a static checker still flag the code?

The deterministic gate is the decision. The optional live model is a second opinion, not the gate.

The current `security_workers/` pack is a calibration set: 11 small, deliberately vulnerable
workers. It is useful for testing the verifier, but it is not a real-world benchmark.

## Quick start

```bash
uv sync --all-extras
uv run acv list
uv run acv show cmd_runner
uv run acv verify cmd_runner semicolon_filter
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
| Dashboard | Run one labeled candidate, see corpus status, session run history, last audit, and last qualification |
| Task explorer | Vulnerable source, exploit, functional test, every candidate, and a live deterministic gate run |
| Patch lab | Paste or load a replacement `worker.py` and run the same exploit, functional suite, and checker gate |
| Checker qualification | Runs the qualification harness and shows precision, recall, F1, runtime, and exact misses |
| Audit matrix | Runs the full two-sided audit and shows false passes, false rejections, and the checker comparison |
| Model review | Runs one live model review and places it next to the executable gate verdict |

The UI calls these endpoints: `/api/tasks`, `/api/tasks/{id}`, `/api/verify`,
`/api/verify-code`, `/api/tools`, `/api/qualify`, `/api/audit`, and `/api/review`. The
deterministic panels work without any model key.

## Patch lab: run source supplied by you

The patch lab is the first step toward dynamic intake. It accepts a full replacement for the
task's `worker.py`, writes it to a temporary directory, and runs the same executable gate:

- the original exploit must stop succeeding;
- the functional suite must still pass;
- the primary checker must not report a blocking finding.

```bash
curl -s http://127.0.0.1:8000/api/tasks/ssrf_redirect \
  | jq -r '.candidates[] | select(.name == "gold") | .code' > /tmp/worker.py

jq -n --rawfile code /tmp/worker.py \
  '{task_id: "ssrf_redirect", code: $code, checker: "acv-rules"}' \
  | curl -s -X POST http://127.0.0.1:8000/api/verify-code \
      -H 'Content-Type: application/json' -d @- | jq
```

The response is a gate result, not a ground-truth label. `accepted: true` means the supplied
source passed the executable oracle and checker; it does not prove that the source is equivalent
to a reference repair.

**Security boundary.** This endpoint executes caller-supplied Python on the host. It is intended
for local experiments with trusted code. There is no hardened sandbox in this build; do not expose
the server to untrusted users. The next milestone is a sandbox adapter with a writable work
directory, no network, a timeout, and a CPU/memory cap.

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

The vulnerable code is not in `src/acv/`. `src/acv/` is the verifier. The targets are under
`security_workers/`.

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
| `src/acv/llm/groq.py` | Groq client and structured review schema |
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

This is not implemented as a CLI command yet. `acv verify <task> <candidate>` is the manual version
of the same gate.

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
- There is no real Git patch input yet (`acv verify --patch`).
- There is no automated repair loop yet; repair mapping is documented, not implemented.
- There is no hardened sandbox; execution uses a temporary directory.
- There is no SARIF normalizer, PR comment, or CI gate yet.
- The model review is advisory and can be wrong.
- A model failing one hard case is not proof that all models fail it.

## Next implementation order

1. Add ensemble scoring: union/intersection recall and precision.
2. Add `acv repair --finding <id>` and `acv verify --patch change.diff`.
3. Add adapters for secrets, dependencies, IaC, containers, and DAST.
4. Add SARIF normalization and a CI gate.
5. Parse structured pytest JSON instead of text.
6. Run untrusted code in Docker or gVisor.
7. Add external benchmark adapters (OWASP Benchmark, Vul4J, CVE-bench).
