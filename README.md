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
| `src/acv/cli.py` | Commands: `list`, `show`, `verify`, `review`, `audit`, `serve` |
| `src/acv/manifest.py` | Loads and validates `task.json`; rejects path escapes |
| `src/acv/models.py` | Typed records for tasks, candidates, findings, results |
| `src/acv/runner.py` | Copies a candidate to a temp dir, runs the exploit, pytest, and checkers |
| `src/acv/checkers/builtin.py` | Small deterministic rule pack; no network or external service |
| `src/acv/checkers/bandit_adapter.py` | Optional Bandit adapter; reports unavailable if Bandit is absent |
| `src/acv/review.py` | Builds the model prompt, calls the model, compares with the gate |
| `src/acv/llm/groq.py` | Groq client and structured review schema |
| `src/acv/server.py` | JSON API only; no static presentation |
| `src/acv/report.py` | Writes `reports/results.json` and `reports/summary.md` |
| `tests/` | Tests for the verifier itself, not for the vulnerable workers |

`bandit_adapter.py` is not a fake checker. It runs the real `bandit` command when installed.
The built-in `acv-rules` checker is the offline fallback.

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

### Serve the JSON API

```bash
uv run acv serve
```

OpenAPI docs: `http://127.0.0.1:8000/docs`. There is no static deck to hide behind.

## The verification pipeline

For each candidate, `runner.py`:

1. Creates an isolated temporary directory.
2. Copies the candidate in as `worker.py`.
3. Runs `poc/exploit.py` against it.
4. Runs `tests/test_functional.py` against it.
5. Runs the built-in checker and, if available, Bandit.
6. Accepts only when the exploit is blocked, behavior passes, and the checker is quiet.

The model review runs after the candidate source is loaded. It sees the vulnerable code, the
exploit, the functional test, and the candidate. It does not see the expected verdict.

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
- There is no real Git patch input yet (`acv verify --patch`).
- There is no hardened sandbox; execution uses a temporary directory.
- There is no SARIF normalizer, PR comment, or CI gate yet.
- The model review is advisory and can be wrong.
- A model failing one hard case is not proof that all models fail it.

## Next implementation order

1. Add `acv verify --patch change.diff` for real diffs.
2. Add a Semgrep adapter and SARIF normalization.
3. Parse structured pytest JSON instead of text.
4. Run untrusted code in Docker or gVisor.
5. Add a CI gate and PR comment.
6. Add external benchmark adapters (OWASP Benchmark, Vul4J, CVE-bench).
