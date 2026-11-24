# Research plan: executable patch verification

Status: working plan, not a claim of completed results. Current date: 2026-11-19.

## 1. Working title

**Executable Patch Verification: Using Exploits and Behavior Tests as the Authority for
Security-Fix Validation**

Alternative titles:

- *Beyond the Scanner: An Executable Oracle for Security Patch Verification*
- *Gate the Patch, Not the Pattern: Deterministic Verification of Security Fixes*

## 2. One-sentence thesis

A security patch should be accepted only when an executable attack no longer succeeds **and**
the original behavior still works; static checkers and language models are useful evidence, but
they should not be the final decision.

This is a **verification** and **measurement** paper. It is not a claim that one can detect every
vulnerability, that static analysis is useless, or that this system is the best SAST tool.

## 3. What the current artifact already demonstrates

The repository currently contains:

- 11 small Python security workers spanning CWE-78, CWE-79, CWE-89, CWE-94, CWE-22, CWE-338,
  CWE-502, CWE-601, CWE-798, and CWE-918.
- 44 labeled candidates: vulnerable source, gold fixes, benign safe variants, and known-bad
  mutants.
- A deterministic gate that runs:
  1. the original exploit (PoC) against the candidate;
  2. the functional test suite against the candidate;
  3. the checker registry against the candidate.
- A checker qualification harness with real adapters for the built-in rule pack and Bandit, plus
  an optional Semgrep adapter.
- A two-sided audit that reports false passes and false rejections, not just a single accuracy
  number.
- A live model reviewer that is explicitly advisory.
- A local web console with a guided workflow, dashboard, task inspection, patch lab, task import,
  qualification, audit, model review, and repair views.
- `POST /api/verify-code`, which runs caller-supplied replacement source through the same gate.
- `POST /api/verify-patch`, which applies a single-file unified diff to the vulnerable worker and
  then runs the same gate.
- Patch results now include the exact evaluated source, the applied diff, and the input mode.
- A task-bundle importer (`GET /api/tasks/template`, `POST /api/tasks/validate`,
  `POST /api/tasks/import`) that publishes validated user tasks into a separate user pack.
- A bounded model repair endpoint (`POST /api/repair`) that proposes a complete replacement
  `worker.py` and then runs the deterministic gate on the proposal.
- A multi-file project pack (`project_workers/`) with a complete base tree, trusted exploit and
  functional test outside that tree, checker scope, size limits, and overlay candidates.
- A real-repository case (`gitpython_cve_2022_24439`) built from released GitPython 3.1.29 and
  its dependencies, with the real CVE-2022-24439 remote-helper command injection, the upstream
  3.1.30 fix, an independent benign fix, and a clone-only partial fix.
- `POST /api/projects/{id}/verify` for a generated path-to-text overlay from any model, and
  `POST /api/projects/{id}/verify-patch` for a validated multi-file diff.
- Model provenance fields (model, provider, backend, quantization, prompt, temperature, seed,
  raw output) recorded with a project run. These are observability, not evidence.
- A local JSONL run log for project provenance and reproducibility.
- Environment-controlled feature flags for the guided view, patch preview, task import, repair,
  project verification, and project logging so these additions can be removed or deployed
  independently.

Current measured facts from the local calibration pack:

| Measurement | Result |
| :--- | :--- |
| Audit verdict accuracy | 42/44 correct (95.5%) |
| False pass | `cmd_runner/sh_c_filter` |
| False rejection | `sql_lookup/benign` |
| `acv-rules` qualification | TP 28, FP 1, FN 5, TN 21; P 96.6%, R 84.8%, F1 90.3% |
| `bandit` qualification | TP 17, FP 3, FN 16, TN 19; P 85.0%, R 51.5%, F1 64.2% |
| `semgrep` | not installed in the current environment |
| Redirect-SSRF demo | `initial_only` accepted by the checker but rejected by the exploit gate |
| Project calibration | `doc_portal` gold and benign accepted; `absolute_only` rejected by the exploit even when the checker is clear |
| Project scale | 18 source files and 963 lines in the base tree, plus a trusted exploit and functional suite |
| Real repository case | GitPython 3.1.29: upstream 3.1.30 fix accepted, central-guard benign accepted, clone-only partial fix rejected by the remote-fetch attack path |
| Real repository scale | 74 judged files and ~22,700 lines, including vendored `gitdb` and `smmap` dependencies |

These are calibration results. They are useful for debugging the verifier and for showing the
failure mode, but they are not a real-world benchmark.

## 4. Research questions

**RQ1. Does an executable oracle catch bad patches that static checkers accept?**
Measure false passes on labeled mutants, especially mutants that preserve the syntactic pattern
but leave an attack path open. The redirect-SSRF fixture is the motivating example.

**RQ2. Does the gate reject legitimate safe patches?**
Measure false rejections on gold and benign variants. This is the cost of a strict gate and must
be reported, not hidden.

**RQ3. How much does each component contribute?**
Run ablations: exploit only, behavior only, checker only, exploit + behavior, full gate, and
model-only. Report false-pass and false-reject changes, runtime, and disagreement.

**RQ4. Can the system intake new code and new patches without hand-editing the harness?**
Evaluate full-file replacement, unified-diff application, and repository-level patch application.
Measure how often the oracle remains valid after a patch changes imports, call signatures, or
control flow.

**RQ5. How reliable is a model as an advisory reviewer?**
Measure agreement with the gate and with labels, confidence calibration, and failure modes. The
model is not allowed to override the gate.

## 5. System model

```text
task manifest
  ├── vulnerable source
  ├── gold / benign / mutant candidates
  ├── exploit (PoC)
  ├── functional tests
  └── metadata (CWE, tags, expected labels)

candidate source (catalog, pasted file, diff, or repository)
        │
        ▼
isolated work directory
        │
        ├── run exploit ───────────────► pass only if attack is blocked
        ├── run functional suite ──────► pass only if behavior is preserved
        └── run checker registry ──────► blocking findings? 
                                             │
                                             ▼
                                  deterministic gate verdict
                                             │
                              ┌──────────────┴──────────────┐
                              ▼                             ▼
                     accept / reject record          model review (advisory)
```

Gate rule for this build:

```text
accept(candidate) =
    exploit_exit == CLEAN
    and functional_exit == 0
    and primary_checker has no blocking findings
```

Important distinction: a candidate can fail because the exploit still succeeds (security
failure), because the tests fail (behavior regression), because the checker blocks it, or because
the oracle itself is broken (import error, timeout, missing dependency). The last case must be
reported separately, not silently treated as a security result.

## 6. Dynamic code and dynamic evidence

### 6.1 What is implemented now

- Full-file replacement of `worker.py` through `POST /api/verify-code`.
- Single-file unified-diff intake through `POST /api/verify-patch`. The diff is validated to
  target only `worker.py`, applied to a fresh copy of the vulnerable source with `git apply
  --check` and then `git apply`.
- The supplied source or patched source is executed in a fresh temporary directory with
  process-level containment: wall-clock timeout, CPU limit, address-space limit, file-size limit,
  open-file limit, and a separate process group for cleanup.
- The runner strips common secret-bearing environment variables before execution.
- The same task exploit and functional suite are used.
- The exploit is also run against the vulnerable source as an oracle-sensitivity check. If it
  fails there, the result is marked `oracle_ok: false` and rejected.
- The result is unlabeled: it says whether the gate passed, not whether the source is the
  reference fix.
- The result returns the evaluated `candidate_code`, a generated `applied_diff`, and the
  `input_mode`, so the UI can show what actually ran rather than only a verdict.
- The UI exposes this as **Patch lab** with a full-source mode, a unified-diff mode, source
  templates, editing, and a run button.
- **Task import** accepts a manifest plus file map, validates paths and required files, then
  publishes the task under `ACV_USER_PACK` (default `user_security_workers/`). Built-in and user
  tasks are discovered together. Import does not execute the bundle.
- **Repair lab** asks the configured model for a complete replacement `worker.py`, validates the
  proposal schema, and runs the same gate on the generated code. The response keeps the proposal
  and the gate result separate; model confidence is not the verdict.

- **Project verification** (`src/acv/projects.py`) loads a configured multi-file project task,
  copies the base tree into a temporary workspace, applies a generated overlay or validated
  multi-file diff, runs the trusted exploit and functional suite, and scans the declared checker
  scope. Findings carry a relative file path. The exploit and tests live outside the base tree,
  so generated code cannot replace its own judge.
- Project overlays are bounded (250 files, 1.5 MB, 400 KB per file) and the project is bounded
  (400 files, 2 MB by default). Checker runs cap files and findings and set explicit truncation
  flags. The UI fetches one file at a time instead of sending the whole tree in every response.
- Project provenance accepts model, provider, backend, quantization, prompt, temperature, seed,
  and raw output. The verifier never calls a model and never reads those fields as evidence.
- Critical input requires an explicit `isolation_acknowledged` flag, but that records the
  boundary; it does not create isolation.

This is enough to try arbitrary trusted Python code, a single-file patch, or a generated overlay
on a project-shaped tree, add new fixtures at runtime, and test a bounded model repair proposal.
The process limits are not a sandbox: there is still no network namespace or filesystem jail.
The project path is limited to configured Python projects; it does not clone a Git URL, install
dependencies, or run an arbitrary real repository. Imported tasks are structurally validated but
not automatically audited. Repair generation does not create new tests or a new exploit, so it
cannot by itself prove semantic equivalence with a reference fix.

### 6.2 Next dynamic intake layers

**Layer 1: full-file replacement (implemented).**
Useful for research prototypes and trusted local experiments. Weakness: the candidate must expose
the exact same interface; it avoids the hard problem of applying a patch to a real repository.

**Layer 2: single-file unified diff (implemented).**
The API accepts a patch such as `git diff` or `---/+++`, applies it to a fresh copy of the
vulnerable `worker.py` with `git apply --check` and then `git apply`, and rejects path escapes or
any target other than `worker.py`.

**Layer 3: repository-level candidates (partially implemented).**
The `project_workers/` path implements repository-shaped tasks: a complete base tree, package
layout, trusted evidence outside the tree, checker scope, and generated overlays or multi-file
diffs. `gitpython_cve_2022_24439` is a real third-party package with a documented CVE and upstream
fix, so this is no longer only a synthetic service. The next step is arbitrary repository intake:
a Git URL and commit, a declared environment, dependency installation, and a held-out test
command. One real case is a validity check, not an external benchmark.

**Layer 4: sandboxed execution.**
The current runner has process-level limits and a timeout, but it is not isolation. The next
version must run candidate code in a container or micro-VM:

- fresh writable workspace, read-only base image;
- no network by default;
- CPU, memory, process, file-size, and wall-clock limits;
- drop capabilities, no-new-privileges, seccomp/AppArmor;
- a timeout that distinguishes "attack did not finish" from "attack blocked";
- separate stdout/stderr and an artifact directory.

Docker is acceptable for a paper prototype; gVisor or Firecracker is stronger. The paper must
state which isolation was used and what it does not protect against.

**Layer 5: exploit adaptation.**
A patch can make the original exploit fail for the wrong reason: a renamed function, a changed
import, or a new precondition. The system needs an **oracle sensitivity check**:

1. Run the exploit against the vulnerable source and require it to succeed.
2. Run the same exploit against the candidate.
3. Run a control probe against the candidate to prove the target is reachable.
4. Distinguish "attack blocked" from "target unreachable" and "oracle broken".
5. If the patch changes the interface, use a declared adapter or a task-specific harness update;
   do not silently count a broken exploit as a fix.

For exploit generation, the honest design is **bounded synthesis**: templates plus optional model
suggestions, all validated against the vulnerable source, the gold fix, and at least one benign
variant. A generated exploit is admitted only if it succeeds on the vulnerable source and fails
on the gold fix. This prevents the paper from claiming "the model generates exploits" without
evidence.

### 6.3 What "dynamic to static" should mean in the paper

Do not claim that a static analyzer becomes dynamic. Instead:

- static analysis is one evidence source;
- the executable oracle is the authority;
- candidate intake is dynamic (code, diff, repository);
- task generation can be semi-automated, but labels and exploits are validated;
- the evaluation measures where static evidence helps and where it misses.

## 7. Evaluation design

### 7.1 Internal calibration set

Use the current 11 tasks and 44 candidates for:

- gate mechanics;
- ablation studies;
- failure-mode analysis;
- UI and API artifact demonstration;
- regression tests.

Do not use it as the main external validity claim. It was designed by the same people who wrote
the checker, so it is vulnerable to construction bias.

### 7.2 External evaluation

The paper needs a held-out set that was not used to tune `acv-rules`. Candidate sources:

1. **SecurityEval** (Python security code generation benchmark). Useful for a broad set of
   CWE-labeled Python snippets. It is not a patch benchmark, so the harness must be adapted.
2. **CVEfixes** Python subset. Real vulnerability-fixing commits with CVE metadata. Many lack
   runnable PoCs and tests; select a subset where a minimal reproduction can be written and
   validated.
3. **OWASP Benchmark** for checker comparison. It is Java-oriented, so use it to compare
   checkers, not as a direct gate benchmark.
4. **Hand-built real-world fixtures** from small Python libraries with public advisories
   (for example unsafe YAML loading, pickle deserialization, path traversal, SSRF). Keep the
   reproduction minimal and document the advisory.

A realistic target for a one-month paper is **25-40 external tasks** with executable evidence.
Quality matters more than count. For each task record:

- source repository and commit;
- CVE or advisory;
- vulnerable and fixed code;
- exploit;
- functional tests;
- label and expected behavior;
- whether the exploit was validated on vulnerable and fixed versions;
- provenance and license.

### 7.3 Baselines

- `acv-rules` only;
- Bandit;
- Semgrep (if installed);
- CodeQL if a project-level adapter can be built in time;
- model-only review;
- exploit only;
- exploit + functional tests;
- full gate.

Use the same candidates and the same labels. Report runtime and setup cost.

### 7.4 Metrics

- False-pass rate on known-bad candidates.
- False-reject rate on gold and benign candidates.
- Verdict accuracy with raw counts and Wilson confidence intervals.
- Baseline reproduction rate: vulnerable fails the exploit, fixed passes the tests.
- Oracle sensitivity: how often the exploit still succeeds on the vulnerable source.
- Checker precision, recall, F1, and per-CWE recall.
- Runtime: median and tail, including process startup.
- Model agreement with gate and labels, plus confidence calibration.
- Ablation deltas with paired tests (McNemar for binary comparisons; bootstrap intervals for
  small samples).

Do not report a single accuracy without raw counts and confidence intervals. With 44 candidates,
a 95.5% result has a wide interval; the paper should say so.

### 7.5 Threats to validity

- **Construct validity:** an exploit tests one attack path, not all attacks.
- **Label noise:** a "gold" fix can still be vulnerable in a way the PoC does not cover.
- **Oracle breakage:** a patch may make the exploit fail for the wrong reason.
- **Benchmark contamination:** public CVEs may be in model training data.
- **Circularity:** the built-in checker is tuned to the calibration corpus.
- **Selection bias:** tasks with easy reproductions are overrepresented.
- **Sandbox limitations:** host execution with process limits is not a security boundary.
- **Model leakage:** the review model may have seen the CVE or the fix.
- **Generalization:** small Python workers are not representative of large services.

## 8. Paper structure

1. **Abstract** — one failure mode, one mechanism, one measured result, explicit scope.
2. **Introduction** — static checkers can accept incomplete patches; executable evidence is a
   stronger authority; contributions.
3. **Background and related work** — SAST, patch correctness, vulnerability reproduction,
   LLM code review, benchmark limitations.
4. **Threat model and problem statement** — what a patch is, what "fixed" means, what the gate
   can and cannot prove.
5. **System design** — task contract, oracle, functional tests, checker registry, gate, sandbox.
6. **Dynamic intake** — full-file replacement, diff application, repository candidates,
   exploit sensitivity checks.
7. **Evaluation** — internal calibration, external set, baselines, ablations, error analysis.
8. **Discussion** — when executable evidence is worth the cost; when it is not; human workflow.
9. **Limitations and ethics** — sandbox, dual use, disclosure, benchmark bias.
10. **Artifact appendix** — commands, manifests, expected outputs, environment.

Venue strategy:

- **Full paper:** USENIX Security, ACM CCS, NDSS, IEEE S&P, ICSE, ASE, or ISSTA.
- **One-month realistic target:** a workshop paper, a short paper, or an arXiv preprint plus a
  strong artifact. Do not submit a full-conference claim without the external evaluation.
- **Artifact:** the console, CLI, task pack, reports, and reproduction scripts are already a
  useful artifact; package them after the sandbox and external set exist.

## 9. One-month timeline

### Week 1: freeze the claim and build the safety boundary

- Write the claims/non-claims section and the threat model.
- Add process-level containment and a container sandbox (Docker first): no network, resource
  limits, timeout, read-only base.
- Add unified-diff intake and patch-application errors.
- Add oracle sensitivity checks: vulnerable must fail, fixed must pass, control probe must work.
- Freeze the internal calibration results and record exact commands.

### Week 2: external corpus and exploit adaptation

- Select 25-40 real Python tasks from CVEfixes/SecurityEval/advisories.
- Write or adapt exploits and functional tests.
- Validate every task on vulnerable and fixed versions.
- Add provenance fields to manifests.
- Measure how often the original exploit survives patch application and interface changes.

### Week 3: evaluation and ablations

- Run all baselines and ablations.
- Compute confidence intervals and paired tests.
- Do a full error analysis of false passes and false rejections.
- Run the model review on the external set and measure agreement/calibration.
- Package reports and reproduction scripts.

### Week 4: writing and artifact

- Draft the paper around the measured results, not the UI.
- Internal review: every claim traceable to a table or a command.
- Reproducibility check on a clean machine.
- Artifact README, license/provenance audit, and submission package.

If the external set is not ready by the end of Week 2, change the target to a workshop paper or
an arXiv preprint. Do not fill the gap with calibration-pack numbers presented as external
evidence.

## 10. Concrete next implementation tasks

Priority order:

1. **Sandbox runner** (`src/acv/sandbox.py`): process limits and timeouts are implemented.
   Container/gVisor execution with no network and a read-only base remains the next step.
2. **Single-file diff intake** (`POST /api/verify-patch`): implemented. It validates the diff,
   applies it to a fresh copy of `worker.py`, and returns patch-application errors separately
   from gate failures.
3. **Oracle sensitivity** (`src/acv/runner.py`): implemented for the vulnerable-source check
   (`oracle_ok`). The candidate-side control probe still needs a task-specific reachability
   signal so "target unreachable" is distinct from "attack blocked".
4. **Task import** (`src/acv/task_import.py`): implemented for a manifest-plus-files bundle and a
   separate user pack. Next: provenance fields, overwrite policy, and a post-import baseline run.
5. **Bounded model repair** (`src/acv/repair.py`): implemented for one proposal followed by the
   deterministic gate. Next: generated tests, exploit adaptation, and a measured repair success
   rate against external tasks. Do not call a single proposal a repair loop.
6. **Feature isolation** (`src/acv/features.py`): implemented environment flags for the guided
   view, patch preview, task import, and repair. Keep the deterministic gate independent of these
   flags.
7. **Repository task format** (`src/acv/projects.py`): implemented for a configured project
   tree, trusted evidence, checker scope, overlays, and multi-file diffs. Next: Git URL/commit
   intake, dependency policy, environment spec, and a held-out repository set.
8. **External benchmark adapter** (`scripts/import_*`): import SecurityEval/CVEfixes tasks with
   provenance and license metadata.
9. **Evaluation script** (`scripts/evaluate.py`): emit CSV/JSON with raw counts, CIs, and
   per-CWE breakdowns.
10. **Artifact packaging**: Dockerfile, seed data, expected outputs, and a one-command smoke test.

## 11. What not to claim

- Do not claim "detects all vulnerabilities."
- Do not claim "outperforms all SAST tools."
- Do not present the 11-task calibration pack as a real-world benchmark.
- Do not present the one multi-file calibration project as a real-world benchmark.
- Do not call the project runner a sandbox; it still uses process limits only.
- Do not present model agreement as proof that the model is correct.
- Do not treat a failed exploit as proof of a fix without checking oracle sensitivity.
- Do not hide false passes or false rejections; they are the most interesting part of the result.
- Do not expose caller-supplied code execution to an untrusted network before a real sandbox
  lands. Process limits are not network or filesystem isolation.

## 12. How to use the current platform today

```bash
cd Autonomous_Code_Validator
uv sync --all-extras
uv run acv serve --host 127.0.0.1 --port 8017
```

Open `http://127.0.0.1:8017/`.

Recommended demo path:

1. **How it works** — show the four-step gate and the difference between evidence and verdict.
2. **Dashboard** — run `ssrf_redirect/gold`; the gate accepts it.
3. **Patch lab** — load `ssrf_redirect/initial_only`; the checker gate passes but the exploit
   still succeeds, so the overall verdict is reject. Open the result's evaluated source and
   applied diff.
4. **Task explorer** — inspect the vulnerable source, exploit, functional test, and candidate
   labels.
5. **Task import** — load the example bundle, validate it, and show the separate user pack. Use a
   changed task id for a real import.
6. **Checker qualification** — measure `acv-rules` and Bandit; show the misses.
7. **Audit matrix** — run the full pack; show the false pass and false rejection.
8. **Model review** — run the advisory model on the same candidate and compare it with the gate.
9. **Repair lab** — request a proposal, then show the proposal next to the independent gate
   verdict. If the key is unavailable, show that the deterministic path still works.

For a paper, replace steps 7-9 with the external evaluation, repair-success measurement, and
ablations described above. Do not present the calibration-pack UI as the result.
