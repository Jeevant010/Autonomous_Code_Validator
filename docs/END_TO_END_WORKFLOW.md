# End-to-End System Manual: Autonomous Code Verification & Repository Hardening

> **Complete operational guide for the Autonomous Code Validator (ACV) and Autonomous Adversarial Verifier Synthesis (AAVS) pipeline.**  
> Covers live data intake from SWE-bench/GitHub, process-isolated reproduction, automated patch generation, multi-oracle deterministic gating, and verifier hardening.

---

## 1. System Architecture & Core Philosophy

Most AI coding pipelines commit a fatal error: **they allow the AI model to grade its own work, or they rely on unit tests that never check adversarial edge cases.**

Our architecture decouples **Generation** from **Verification**:

```
                       [Data Intake Layer]
            Hugging Face SWE-bench / GitHub Repositories
                               │
                               ▼
                    [Target Codebase & PoC]
                   (Real Repo / Multi-File PR)
                               │
        ┌──────────────────────┴──────────────────────┐
        ▼                                             ▼
[Candidate Generation (The Edge)]        [Adversarial Mutation (The Attacker)]
  • LLM Repair (Groq / Qwen / Ollama)       • Injects 8 AST mutation families
  • Unified Git Diff / Human Patch          • Identifies test suite blind spots (SMR)
        │                                             │
        └──────────────────────┬──────────────────────┘
                               ▼
        ┌─────────────────────────────────────────────┐
        │        Autonomous Deterministic Gate        │
        │  (Operating System Process Containment)     │
        │                                             │
        │  1. Oracle Baseline: Attack triggers?       │
        │  2. Security Oracle: Attack blocked? (exit 1)│
        │  3. Behavior Oracle: Pytest passes? (exit 0) │
        │  4. Static SAST: No blocking AST findings?  │
        └──────────────────────┬──────────────────────┘
                               │
                               ▼
                  [Final Executable Verdict]
           ACCEPTED (Green)  or  REJECTED (Red)
```

### The Iron Rule:
> **The AI model proposes a candidate at the edge. The deterministic gate decides the verdict.**  
> The model's self-assessed confidence has **zero authority**. Only process-isolated execution against the attack and test suite determines acceptance.

---

## 2. Phase 1: Dynamic Data Intake (Zero Hardcoded Data)

To prove that the pipeline is not hardcoded, tasks can be pulled dynamically from two primary sources.

### Option A: Stream Tasks Live from Princeton's SWE-bench (Hugging Face)
Extract real-world software engineering issues directly from the official benchmark:

```bash
cd /home/jeevant/Desktop/RLVR/Agent_to_Agent
.venv/bin/python scripts/download_subset.py --dataset princeton-nlp/SWE-bench_Lite --count 5
```
* **What happens:** The script streams `princeton-nlp/SWE-bench_Lite`, parses task problem statements, commits, and golden patches, and saves them to `data/curated_tasks.json`.
* **Filter by repository:**
  ```bash
  .venv/bin/python scripts/download_subset.py --repo requests --count 2
  ```

### Option B: Clone Real Repositories Live via Git
Clone any supported GitHub repository at a vulnerable release commit:

```bash
cd /home/jeevant/Desktop/RLVR/Autonomous_Code_Validator
uv run acv repo-verify jinja_cve_2024_22195
```
* **What happens:** The engine clones `pallets/jinja.git` at commit `b08cd4bc`, builds the sandbox, and executes the exploit against 61 files (22,371 lines).

---

## 3. Phase 2: Vulnerability Reproduction (Baseline Oracle)

Before evaluating any patch, the gate enforces **Step 0: The Baseline Oracle Sanity Check**:
* The attack script (Proof of Concept / PoC) **must successfully compromise the unpatched code** (`exit 0`).
* If the attack fails against vulnerable code, the test harness itself is broken or invalid. The system rejects the run with `oracle_ok: false`.

### Sandboxing & Resource Containment:
Every test executes under Linux kernel constraints via `resource.setrlimit()`:
* **Address Space (RAM):** Max 512 MB (`RLIMIT_AS`)
* **CPU Execution Time:** Max 30 seconds (`RLIMIT_CPU`)
* **File Output Size:** Max 16 MB (`RLIMIT_FSIZE`)
* **Open File Descriptors:** Max 64 (`RLIMIT_NOFILE`)
* **Process Management:** Isolated process group (`start_new_session=True`); runaway trees are terminated via `os.killpg(proc.pid, signal.SIGKILL)`.

---

## 4. Phase 3: Patch Generation (AI at the Edge)

Patches can be generated through the built-in LLM repair engine or supplied externally.

### In-Console Autonomous Repair (Groq / Qwen 2.5 Coder)
The system formats an untrusted prompt containing:
1. The vulnerable implementation
2. The exploit script
3. The functional test suite
4. A strict JSON schema requiring complete Python source

Run via API:
```bash
curl -s -X POST http://127.0.0.1:8017/api/repair \
  -H "Content-Type: application/json" \
  -d '{"task_id": "cmd_runner", "checker": "acv-rules"}' | jq
```

### External Model / Studio Diff Integration
If code is generated in Ollama, LM Studio, or Cursor, feed the replacement code or unified diff directly to the verifier:

```bash
# Verify raw source code
curl -s -X POST http://127.0.0.1:8017/api/verify-code \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "cmd_runner",
    "code": "import shlex, subprocess\ndef run_echo(val): return subprocess.run([\"echo\", val], capture_output=True, text=True).stdout\n",
    "checker": "acv-rules"
  }' | jq

# Verify a unified git diff
curl -s -X POST http://127.0.0.1:8017/api/verify-patch \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "ssrf_redirect",
    "diff": "--- a/worker.py\n+++ b/worker.py\n...",
    "checker": "acv-rules"
  }' | jq
```

---

## 5. Phase 4: Deterministic Multi-Oracle Gating

When code enters the gate, it must satisfy all three independent oracles simultaneously:

| Oracle | Tool | Condition for PASS | Why It Is Mandatory |
| :--- | :--- | :--- | :--- |
| **Security Oracle** | Real Exploit PoC | `exit 1` (Blocked) | Proves the vulnerability cannot be exploited. |
| **Behavior Oracle** | Pytest Test Suite | `exit 0` (All Passed) | Prevents the model from "fixing" bugs by disabling features or returning empty strings. |
| **Static Pattern Oracle** | Bandit / Semgrep / AST | No blocking findings | Prevents models from using insecure anti-patterns (e.g. `shell=True` or `eval`). |

### Live CLI Verification of a Real Multi-File Codebase (GitPython)

#### 1. Test the sound fix (ACCEPTED):
```bash
cd /home/jeevant/Desktop/RLVR/Autonomous_Code_Validator
uv run acv verify-project gitpython_cve_2022_24439 --candidate gold
```
* **Result:** `Verdict: ACCEPT` across 74 files and 22,741 lines of code.

#### 2. Test a mutant / incomplete fix (REJECTED):
```bash
uv run acv verify-project gitpython_cve_2022_24439 --candidate clone_only
```
* **Result:** `Verdict: REJECT` — `Reasons: PoC still succeeds`.

---

## 6. Phase 5: Adversarial Verifier Synthesis (AAVS)

When existing repository test suites are too weak, the AAVS engine hardens them:

1. **Attacker:** Injects 8 semantic AST mutation families into the PR diff lines:
   * Comparison flips (`<` to `<=`, `==` to `!=`)
   * Boolean flips (`True` to `False`)
   * Return nullification (`return None`)
   * Arithmetic inversion (`+` to `-`, `*` to `/`)
   * Logic swaps (`and` to `or`)
   * Exception swallowing (`try: ... except Exception: pass`)
2. **Blind-Spot Detector:** Runs the original test suite on each mutant. If a mutant passes, it is flagged as a **Surviving Mutant (SMR)**.
3. **Defender:** Prompts an LLM to write a targeted unit test to catch the survivor.
4. **Judge:** Evaluates the new test under dual constraints:
   * **Soundness:** Must PASS on original unmutated code (`exit 0`).
   * **Completeness:** Must FAIL on mutated code (`exit 1`).

### Run the local audit live:
```bash
cd /home/jeevant/Desktop/RLVR/Agent_to_Agent
.venv/bin/python scripts/run_local_audit.py --audit-only
```

---

## 7. Interactive Research Console

Start the web UI:
```bash
cd /home/jeevant/Desktop/RLVR/Autonomous_Code_Validator
uv run acv serve --port 8017
```
Open **`http://127.0.0.1:8017`** in your browser to access:
* **Check a patch:** Interactive code & unified diff editor with live sandboxed evaluation.
* **Generate a fix:** Live LLM code generation tested against the deterministic gate.
* **Full audit:** 44-candidate audit matrix reporting false passes and false rejections.
* **Checker tests:** Precision, recall, and F1 benchmarks comparing ACV rules, Bandit, and Semgrep.

---

## 8. Oral Defense Guide (Answering Professor Questions)

### Q: "Did you just hardcode these 4 examples?"
> *"No. Our data layer uses a streaming adapter (`scripts/download_subset.py`) connected to Princeton's official Hugging Face SWE-bench Lite and Verified datasets. Furthermore, our Patch Lab accepts arbitrary Python code and unified diffs via REST API and executes them dynamically in Linux process sandboxes."*

### Q: "Why not just use Semgrep or Bandit?"
> *"Static scanners analyze syntax without execution. In our qualification benchmarks, standard SAST tools produced false-alarm rejections on safe sanitizers (`sql_lookup/benign`) and completely missed shell command execution via `sh -c` (`cmd_runner/sh_c_filter`). Dynamic execution of real exploit scripts combined with pytest behavior suites is required for ground-truth verification."*

### Q: "How do you know the AI patch didn't break other features?"
> *"A security fix is rejected if it fails the functional test suite. If an AI tries to 'fix' a command injection bug by making the function return an empty string or crash, the security oracle passes, but the behavior oracle instantly rejects the patch."*

### Q: "What prevents malicious patches from damaging the host?"
> *"All candidate execution is bounded by Linux kernel limits (`setrlimit`), restricting memory to 512 MB, CPU time to 30 seconds, file output to 16 MB, running inside dedicated process groups, and stripping secret-bearing environment variables."*
