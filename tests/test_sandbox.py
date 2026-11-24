from __future__ import annotations

import sys
from pathlib import Path

from acv.sandbox import SandboxPolicy, constrained_environment, run


def test_constrained_environment_strips_secrets(tmp_path: Path) -> None:
    env = constrained_environment(
        {
            "PATH": "/usr/bin",
            "GROQ_API_KEY": "do-not-pass",
            "HOME": "/root",
            "ACV_TASK_ID": "cmd_runner",
        },
        tmp_path,
    )
    assert env["PATH"] == "/usr/bin"
    assert env["ACV_TASK_ID"] == "cmd_runner"
    assert "GROQ_API_KEY" not in env
    assert env["HOME"] == str(tmp_path / "home")
    assert env["TMPDIR"] == str(tmp_path / "tmp")
    assert env["PYTHONNOUSERSITE"] == "1"


def test_run_returns_output_and_exit_code(tmp_path: Path) -> None:
    code, output = run(
        [sys.executable, "-c", "print('sandbox-ok')"],
        cwd=tmp_path,
        env={"PATH": "/usr/bin"},
        policy=SandboxPolicy(timeout=5, memory_mb=256),
    )
    assert code == 0
    assert "sandbox-ok" in output


def test_run_times_out_and_kills_the_process(tmp_path: Path) -> None:
    code, output = run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        env={"PATH": "/usr/bin"},
        policy=SandboxPolicy(timeout=0.4, cpu_seconds=5, memory_mb=256),
    )
    assert code == 124
    assert "timeout" in output.lower()


def test_run_applies_a_memory_limit(tmp_path: Path) -> None:
    code, _ = run(
        [
            sys.executable,
            "-c",
            "x = bytearray(128 * 1024 * 1024); print(len(x))",
        ],
        cwd=tmp_path,
        env={"PATH": "/usr/bin"},
        policy=SandboxPolicy(timeout=5, cpu_seconds=5, memory_mb=48),
    )
    assert code != 0
