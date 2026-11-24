"""Best-effort process containment for executable evidence.

This module is intentionally not a claim of strong isolation. It limits CPU,
address space, file size, open files, and wall-clock time, and it strips common
secret-bearing environment variables before executing a candidate. There is no
network namespace or filesystem jail; the caller is still responsible for
running the service on a trusted machine.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

_SAFE_ENV_KEYS = {
    "ACV_DATA_DIR",
    "ACV_TASK_ID",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_PROXY",
    "PATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONPATH",
    "PYTHONNOUSERSITE",
    "no_proxy",
}


@dataclass(frozen=True)
class SandboxPolicy:
    """Limits applied to one candidate execution."""

    timeout: float = 30.0
    memory_mb: int = 512
    cpu_seconds: int = 30
    file_size_mb: int = 16
    nofile: int = 64
    max_output_bytes: int = 1_000_000


def constrained_environment(
    source: dict[str, str],
    workdir: Path,
    scratch_dir: Path | None = None,
) -> dict[str, str]:
    """Keep only the variables the runner needs, plus private HOME/TMPDIR."""

    env = {key: value for key, value in source.items() if key in _SAFE_ENV_KEYS}
    scratch = scratch_dir or workdir
    home = scratch / "home"
    tmp = scratch / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home)
    env["TMPDIR"] = str(tmp)
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _output_text(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    policy: SandboxPolicy | None = None,
    scratch_dir: Path | None = None,
) -> tuple[int, str]:
    """Run a command with process limits and a wall-clock timeout.

    Returns ``(exit_code, combined_output)``. A timeout is reported as exit 124,
    matching the common coreutils convention.
    """

    policy = policy or SandboxPolicy()
    wrapper = Path(__file__).with_name("_sandbox_exec.py")
    limited_command = [
        sys.executable,
        str(wrapper),
        str(policy.memory_mb * 1024 * 1024),
        str(policy.cpu_seconds),
        str(policy.file_size_mb * 1024 * 1024),
        str(policy.nofile),
        "--",
        *command,
    ]
    clean_env = constrained_environment(env, cwd, scratch_dir)

    try:
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(
                limited_command,
                cwd=cwd,
                env=clean_env,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=policy.timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                with suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()

            output.seek(0)
            raw = output.read(policy.max_output_bytes + 1)

        text = _output_text(raw)
        if len(raw) > policy.max_output_bytes:
            text += "\n[output truncated]"
        if timed_out:
            text += f"\n[timeout after {policy.timeout:g}s]"
            return 124, text
        returncode = proc.returncode if proc.returncode is not None else 125
        if returncode < 0:
            returncode = 128 + abs(returncode)
        return returncode, text
    except OSError as exc:
        return 126, f"could not start constrained command: {exc}"
