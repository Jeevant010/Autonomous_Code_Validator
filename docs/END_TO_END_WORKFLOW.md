# End-to-End System Manual: Autonomous Code Verification & Repository Hardening

> **Complete operational guide for the Autonomous Code Validator (ACV) and Autonomous Adversarial Verifier Synthesis (AAVS) pipeline.**  
> Covers live data intake from SWE-bench/GitHub, process-isolated reproduction, automated patch generation, multi-oracle deterministic gating, clean baseline negative controls, and automated Merge Request / Pull Request branch synthesis.

---

## 1. System Architecture & Core Philosophy

Most AI coding pipelines commit a fatal error: **they allow the AI model to grade its own work, or they rely on superficial unit tests that never check adversarial edge cases.**

Our architecture completely decouples **Generation** from **Verification**:

```
                       [Data Intake Layer]
            Hugging Face SWE-bench / GitHub Repositories
                                │
                                ▼
                     [Target Codebase & PoC]
          (Real Multi-File Repositories Cloned Live)
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
[Candidate Generation (The Edge)]         [Adversarial Mutation (The Attacker)]
  • Human Patch / Unified Git Diff          • Injects 8 AST mutation families
  • LLM Repair (Groq / Qwen / Ollama)       • Injects backdoors & half-fixes
  • Upstream Official Security Patches      • Discovers verifier blind spots
        │                                               │
        └───────────────────────┬───────────────────────┘
                                ▼
        ┌───────────────────────────────────────────────┐
        │         Autonomous Deterministic Gate         │
        │   (Linux Kernel Process Resource Isolation)   │
        │                                               │
        │  1. Oracle Baseline: Attack triggers? (PoC)   │
        │  2. Security Oracle: Attack blocked? (exit 1) │
        │  3. Behavior Oracle: Pytest passes? (exit 0)  │
        │  4. Static SAST: No new blocking AST rules?   │
        │  5. Scope Guard: Protected files untouched?   │
        └───────────────────────┬───────────────────────┘
                                │
                                ▼
                    [Final Executable Verdict]
            ACCEPTED (Green)   or   REJECTED (Red)
                                │
                                ▼
             [Automated Merge Request Synthesis]
        • Local Git Branch: acv/harden-<task_id>
        • Verified Evidence Pull Request: pull_request.md
```

### The Iron Rule:
> **The AI model proposes a candidate at the edge. The deterministic gate decides the verdict.**  
> The model's self-assessed confidence has **zero authority**. Only process-isolated execution against the attack and test suite determines acceptance.

---

## 2. Multi-Repo Benchmark Suite (7 Real Codebases, 20 Scenarios)

The system is tested against **7 production codebases** across **20 live scenarios**:
- **6 Real Vulnerable Repositories (CVE Benchmarks)**: Verifies that real-world security vulnerabilities reproduce on baseline, are repaired by sound patches, and are rejected when incomplete or mutated.
- **1 Clean Production Repository (Negative Control)**: Verifies that healthy repositories with no vulnerabilities pass the gate without false alarms (`ACCEPT`), while malicious mutants (e.g. backdoors) are immediately blocked (`REJECT`).

| Repository | GitHub Target | CWE Category | Files / Lines | Scenarios Tested | Gate Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GitPython** | `gitpython-developers/GitPython` | **CWE-78** (Command Injection) | 74 files / ~25,280 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **Jinja2** | `pallets/jinja` | **CWE-79** (HTML Attribute Injection) | 61 files / ~22,370 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **PyYAML** | `yaml/pyyaml` | **CWE-502** (Unsafe Deserialization) | 79 files / ~17,080 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **Requests** | `psf/requests` | **CWE-522** (Credential Leakage) | 35 files / ~10,730 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **urllib3** | `urllib3/urllib3` | **CWE-201** (Cookie Exposure) | 75 files / ~27,800 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **sqlparse** | `andialbrecht/sqlparse` | **CWE-674** (Uncontrolled Recursion) | 28 files / ~8,450 LOC | Baseline, Fix, Half-Fix | **3/3 (100%)** |
| **Click (Clean)** | `pallets/click` | **CWE-None** (Negative Control) | 22 files / ~7,900 LOC | Clean Baseline, Backdoor Mutant | **2/2 (100%)** |
| **TOTAL** | **7 Repositories** | **6 Weakness Classes** | **374 files / ~119,610 LOC** | **20 Executable Scenarios** | **20/20 (100%)** |

**Zero False Accepts (0)**: No malicious or half-fix patch ever bypassed the gate.  
**Zero False Rejects (0)**: No clean production repository was falsely rejected.

---

## 3. Terminal CLI Commands (Run Everything Live)

All operations run directly from your terminal using the `acv` CLI.

### 1. List All Configured Real Repositories
```bash
cd /home/jeevant/Desktop/RLVR/Autonomous_Code_Validator
uv run acv repo-list
```
Prints the catalog of real-world repositories, their assigned CWEs, GitHub URLs, and pinned commit SHAs.

### 2. Verify a Real Repository Baseline (Proves Vulnerability Reproduces)
```bash
uv run acv repo-verify jinja_cve_2024_22195
```
Clones `pallets/jinja` from GitHub, installs isolated dependencies, and runs the security oracle.  
* **Output:** `Verdict: REJECT (rejected by poc)` — proving the attack reproduces on unpatched code.

### 3. Verify a Candidate Fix Patch Against a Repository
```bash
uv run acv repo-verify gitpython_cve_2022_24439 --diff my_candidate_fix.diff
```
Applies the patch inside the clone and tests all 4 gates.  
* **Accepted:** `Verdict: ACCEPT (rejected by none)` if PoC is blocked and pytest passes.  
* **Rejected:** `Verdict: REJECT` with explicit explanation (e.g., `rejected by behavior` if unit tests broke, or `rejected by checker` if an unsafe call was added).

### 4. Probe Live Default Branches (Upstream Status)
```bash
uv run acv repo-stale
```
Clones the current `main`/`master` HEAD of each upstream project and probes whether the vulnerability is still present today or already fixed upstream.

### 5. Run the Full Multi-Repository Benchmark Suite
```bash
uv run python scripts/benchmark_repos.py
```
Executes all 20 scenarios across the 7 repositories and regenerates:
* `reports/repo_benchmark.json` (Machine-readable JSON record)
* `reports/repo_dashboard.html` (Interactive web dashboard with category filters)

---

## 4. Where to Put New Code & Intake New Repositories

ACV is designed for seamless extension. You can intake new code and repositories in three distinct ways:

### Method A: Supply a Patch to an Existing Task (`--diff`)
If you have written a fix for an existing task:
1. Save your unified git diff to a file, e.g. `my_fix.diff`.
2. Run the gate:
   ```bash
   uv run acv repo-verify sqlparse_cve_2024_4340 --diff my_fix.diff
   ```
3. If it passes, turn it into a Merge Request (see Section 5).

### Method B: Add a Custom Repository Task (`repo_tasks/`)
To add ANY new GitHub repository to ACV:
1. Create a directory: `repo_tasks/<task_id>/`
2. Add `task.json`:
   ```json
   {
     "id": "my_new_cve_task",
     "title": "Short title describing the fix",
     "cwe": "CWE-78",
     "summary": "Detailed weakness summary.",
     "repo_url": "https://github.com/owner/repo.git",
     "commit": "<vulnerable_commit_sha>",
     "fix_commit": "<upstream_fix_commit_sha>",
     "diff_paths": ["path/to/vulnerable_file.py"],
     "poc": "poc/exploit.py",
     "functional": "tests/test_functional.py",
     "memory_mb": 768,
     "poc_timeout": 60,
     "test_timeout": 120
   }
   ```
3. Create `poc/exploit.py`:
   - Must exit `0` when vulnerable (baseline).
   - Must exit `1` when safe/blocked (candidate fix).
   - Must exit `2` on environment crash.
4. Create `tests/test_functional.py`:
   - Standard `pytest` test suite verifying expected library behavior.
5. ACV will automatically discover the task in `uv run acv repo-list`!

### Method C: Add a Clean Repository (Negative Control)
To verify that a repository is clean and has no vulnerabilities:
In `task.json`, add:
```json
"clean_baseline": true,
"cwe": "CWE-None"
```
The baseline will expect `ACCEPT`, and any corrupted mutant will expect `REJECT`.

---

## 5. Automated Merge Request & Pull Request Workflow

When a candidate patch successfully passes all verification gates, you can generate a **clean, production-ready Git branch and PR description**:

```bash
uv run acv repo-harden <task_id> --diff my_fix.diff
```

### What `repo-harden` does automatically:
1. Clones the live default branch (`main`) in an isolated directory.
2. Applies the candidate patch and re-runs the full 4-signal verification gate.
3. If the vulnerability is already fixed upstream, it refuses with an informative message (preventing noisy spam PRs).
4. If verified, it creates a local git branch:
   `acv/harden-<task_id>`
5. Commits the changes with a clean, conventional commit message:
   `security: harden against <CWE_ID> (<task_id>)`
6. Writes a complete, maintainer-ready **`pull_request.md`** containing:
   - Reproduction evidence and exact stdout of the attack before the patch.
   - Exact list of modified source files.
   - Proof that the attack was blocked.
   - Proof that the test suite passed with `exit 0`.
   - Proof that static AST checks showed 0 new findings.

### How to push and open the Merge Request:
```bash
# In the clone directory created by repo-harden:
git push origin acv/harden-<task_id>
# Or push to your own fork:
git remote add myfork git@github.com:<your_username>/<repo_name>.git
git push myfork acv/harden-<task_id>
```
Then copy and paste the contents of the generated `pull_request.md` into GitHub or GitLab!

---

## 6. Interactive Web Console

Start the live web console:
```bash
uv run acv serve --port 8017
```
Open **`http://127.0.0.1:8017`** in your browser to access:
* **Patch Lab:** Test arbitrary code diffs against any repository.
* **Autonomous LLM Repair:** Prompt Groq / Qwen to generate fixes tested live against deterministic gates.
* **Audit Dashboard:** View false-pass and false-reject metrics across all workers.
* **Checker Benchmarks:** Inspect precision, recall, and runtime comparing AST rules against Bandit and Semgrep.

---

## 7. Oral Defense Guide (Answering Friends, Teachers & Reviewers)

### Q: "How do I know this is real and not mock data or fake test runs?"
> *"Look at the benchmark logs and git history: the system invokes real Linux tools via subprocess — `git clone`, `pytest`, `resource.setrlimit()`, and Python AST parsers. It evaluates 374 real open-source Python files totaling ~120,000 lines of production code from GitPython, Jinja2, PyYAML, Requests, urllib3, sqlparse, and Click."*

### Q: "Does your system only reject things? What happens on a clean repository?"
> *"No. We specifically include clean negative control repositories (such as `pallets/click`). On clean code, the gate verifies that the attack probe fails, unit tests pass, and AST checks are clear, producing an immediate `ACCEPT`. If a malicious backdoor or defect is injected, it immediately flips to `REJECT`. This proves the gate is selective and produces zero false alarms."*

### Q: "Why don't you just trust the AI's confidence score?"
> *"LLMs frequently suffer from sycophancy and hallucinations: they write flawed code with high confidence. In our evaluation, half-fixes (such as escaping only specific attributes or catching ValueError instead of RecursionError) look completely plausible to an LLM, but still allow exploits to succeed. Only deterministic execution against executable oracles can be trusted."*

### Q: "How does this prevent breaking other parts of the repository?"
> *"Every patch must pass the repository's functional unit tests via `pytest` (`exit 0`). If an AI tries to 'fix' a vulnerability by deleting code, returning early, or breaking API contracts, the functional test oracle fails and the patch is instantly rejected with `rejected by behavior`."*
