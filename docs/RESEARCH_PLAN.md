# Research plan: executable patch verification

Status: working plan, not a claim of completed results. Current date: 2026-11-16.

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
- A local web console with task inspection, patch lab, qualification, audit, and review views.
- `POST /api/verify-code`, which runs caller-supplied replacement source through the same gate.

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
- The supplied source is written to a temporary directory and executed on the host.
- The same task exploit and functional suite are used.
- The result is unlabeled: it says whether the gate passed, not whether the source is the
  reference fix.
- The UI exposes this as **Patch lab** with source templates, editing, and a run button.

This is enough to try arbitrary trusted Python code against a known fixture. It is not yet a
sandbox and it does not apply diffs.

### 6.2 Next dynamic intake layers

**Layer 1: full-file replacement (current).**
Useful for research prototypes and trusted local experiments. Weakness: the candidate must expose
the exact same interface; it avoids the hard problem of applying a patch to a real repository.

**Layer 2: unified diff application.**
Accept a patch such as `git diff` or `---/+++`. Apply it to a fresh copy of the task repository
with `git apply --check` and then `git apply`. If it fails, report a patch-application error.
This is still bounded and reproducible.

**Layer 3: repository-level candidates.**
Each task becomes a small repository with a real package layout. The candidate is a commit or
working tree. The gate runs the exploit and tests in the repository's own environment. This is
the layer needed for external benchmarks.

**Layer 4: sandboxed execution.**
Run candidate code in a container or micro-VM:

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
- **Sandbox limitations:** host execution is not a security boundary.
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
- Add a sandbox adapter (Docker first): no network, resource limits, timeout, read-only base.
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

1. **Sandbox runner** (`src/acv/runner.py` or a new `src/acv/sandbox.py`): Docker/gVisor
   execution, no network, timeouts, resource limits, explicit error classes.
2. **Diff intake** (`POST /api/verify-patch`): accept a unified diff, apply to a fresh copy,
   return patch-application errors separately from gate failures.
3. **Oracle sensitivity** (`src/acv/runner.py`): run the exploit against vulnerable source and a
   control probe against the candidate; record `oracle_ok` and `target_reachable`.
4. **Repository task format** (`manifest.py`): support a task repository and environment spec,
   not only a single `worker.py`.
5. **External benchmark adapter** (`scripts/import_*`): import SecurityEval/CVEfixes tasks with
   provenance and license metadata.
6. **Evaluation script** (`scripts/evaluate.py`): emit CSV/JSON with raw counts, CIs, and
   per-CWE breakdowns.
7. **Artifact packaging**: Dockerfile, seed data, expected outputs, and a one-command smoke test.

## 11. What not to claim

- Do not claim "detects all vulnerabilities."
- Do not claim "outperforms all SAST tools."
- Do not present the 11-task calibration pack as a real-world benchmark.
- Do not present model agreement as proof that the model is correct.
- Do not treat a failed exploit as proof of a fix without checking oracle sensitivity.
- Do not hide false passes or false rejections; they are the most interesting part of the result.
- Do not expose caller-supplied code execution to an untrusted network before the sandbox lands.

## 12. How to use the current platform today

```bash
cd Autonomous_Code_Validator
uv sync --all-extras
uv run acv serve --host 127.0.0.1 --port 8017
```

Open `http://127.0.0.1:8017/`.

Recommended demo path:

1. **Dashboard** — run `ssrf_redirect/gold`; the gate accepts it.
2. **Patch lab** — load `ssrf_redirect/initial_only`; the checker gate passes but the exploit
   still succeeds, so the overall verdict is reject.
3. **Task explorer** — inspect the vulnerable source, exploit, functional test, and candidate
   labels.
4. **Checker qualification** — measure `acv-rules` and Bandit; show the misses.
5. **Audit matrix** — run the full pack; show the false pass and false rejection.
6. **Model review** — run the advisory model on the same candidate and compare it with the gate.

For a paper, replace step 5-6 with the external evaluation and ablations described above.
