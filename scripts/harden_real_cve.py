"""Fix and verify a real open-source vulnerability: GitPython CVE-2022-24439.

This script is the evidence artifact for the claim "the verifier is useful
because it can harden real code", not just judge a fixture.

It runs four stages against the *published* GitPython 3.1.29 wheel from PyPI,
not against any vendored copy in this repository:

  1. download   fetch GitPython 3.1.29 and its real dependencies from PyPI
  2. reproduce  run both attack paths and show the command actually executes
  3. fix        apply the transport-allowlist patch in place
  4. verify     re-run the attacks (must be blocked) and normal git (must work)

Exit code 0 means the vulnerability reproduced on the unpatched package and
was closed by the patch, with normal behaviour preserved.

Usage:
    python scripts/harden_real_cve.py [--workdir /tmp/acv_cve] [--keep]

The verifier itself is not required for stages 1-4; this script proves the
patch purely with the upstream package. Stage 5 (optional) hands the same
files to the ACV project gate.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ATTACK_SNIPPET = '''
import sys, tempfile
sys.path.insert(0, {path!r})
from pathlib import Path
import git
from git import Repo

marker = Path(tempfile.mkdtemp()) / "PWNED"
results = {{}}

try:
    Repo.clone_from(
        f"ext::sh -c touch% {{marker}}",
        tempfile.mkdtemp() + "/clone",
        multi_options=["-c protocol.ext.allow=always"],
    )
    results["clone_from"] = "no exception"
except Exception as exc:
    results["clone_from"] = type(exc).__name__

try:
    repo = Repo.init(tempfile.mkdtemp() + "/fetch")
    remote = repo.create_remote("evil", f"ext::sh -c touch% {{marker}}")
    repo.git.config("protocol.ext.allow", "always")
    remote.fetch()
    results["remote_fetch"] = "no exception"
except Exception as exc:
    results["remote_fetch"] = type(exc).__name__

results["executed"] = marker.exists()
results["version"] = git.__version__
print(results)
'''

BEHAVIOUR_SNIPPET = '''
import sys, tempfile
sys.path.insert(0, {path!r})
from pathlib import Path
from git import Repo, Git

base = Path(tempfile.mkdtemp())
source = base / "source"
repo = Repo.init(source)
Path(source, "readme.txt").write_text("hello")
repo.index.add(["readme.txt"])
repo.index.commit("initial")

clone = base / "clone"
cloned = Repo.clone_from(str(source), str(clone))

other = Repo.init(base / "other")
remote = other.create_remote("origin", str(source))
other.git.config("protocol.file.allow", "always")
remote.fetch()

print({{
    "clone_ok": (clone / "readme.txt").exists(),
    "fetch_ok": len(other.remotes) == 1,
    "commit": cloned.head.commit.message.strip(),
    "git": Git().version(),
}})
'''


def run_python(code: str) -> dict[str, object]:
    process = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=600
    )
    if process.returncode != 0:
        print(process.stdout)
        print(process.stderr, file=sys.stderr)
        raise SystemExit(f"stage failed with exit {process.returncode}")
    return eval(process.stdout.strip())


def download(workdir: Path) -> Path:
    target = workdir / "real"
    if target.exists():
        return target
    print("  installing GitPython 3.1.29, gitdb, smmap from PyPI into a scratch dir ...")
    target.mkdir(parents=True, exist_ok=True)
    base = [
        "install",
        "--target",
        str(target),
        "--no-deps",
        "--quiet",
        "gitpython==3.1.29",
        "gitdb",
        "smmap",
    ]
    attempts = []
    if shutil.which("uv"):
        attempts.append(["uv", "pip", *base])
    attempts.append([sys.executable, "-m", "pip", *base])

    errors = []
    for command in attempts:
        process = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if process.returncode == 0:
            break
        detail = (process.stderr or process.stdout).strip()[:400]
        errors.append(f"{' '.join(command[:3])}: {detail}")
    else:
        raise SystemExit(
            "could not fetch the package from PyPI.\n"
            + "\n".join(errors)
            + "\nInstall pip, or run this script with `uv run python scripts/harden_real_cve.py`."
        )
    return target


def apply_fix(tree: Path) -> list[str]:
    exc_path = tree / "git" / "exc.py"
    cmd_path = tree / "git" / "cmd.py"
    changed: list[str] = []

    exc_source = exc_path.read_text(encoding="utf-8")
    if "class UnsafeProtocolError" not in exc_source:
        anchor = "class CommandError(GitError):"
        if anchor not in exc_source:
            raise SystemExit("unexpected exc.py layout")
        exc_source = exc_source.replace(
            anchor,
            "class UnsafeProtocolError(GitError):\n"
            '    """Raised when a command would use a remote-helper protocol '
            'that runs code."""\n\n\n' + anchor,
            1,
        )
        exc_path.write_text(exc_source, encoding="utf-8")
        changed.append("git/exc.py")

    cmd_source = cmd_path.read_text(encoding="utf-8")
    if "UnsafeProtocolError" not in cmd_source:
        import_anchor = "from .exc import GitCommandError, GitCommandNotFound"
        if import_anchor not in cmd_source:
            raise SystemExit("unexpected cmd.py import layout")
        cmd_source = cmd_source.replace(
            import_anchor,
            import_anchor + ", UnsafeProtocolError",
            1,
        )

        old = (
            "        # Remove password for the command if present\n"
            "        redacted_command = remove_password_if_present(command)\n"
        )
        if old not in cmd_source:
            raise SystemExit("unexpected cmd.py guard layout")
        guard = (
            "        # Remove password for the command if present\n"
            "        redacted_command = remove_password_if_present(command)\n"
            '        # Remote-helper URLs of the form "<transport>::<address>" let a\n'
            "        # caller pick the transport, and \"ext\" runs a shell command.\n"
            "        # Allow only the transports that ship with git so an unknown\n"
            "        # helper cannot execute a local command.\n"
            '        allowed_helpers = {"file", "git", "http", "https", "ssh"}\n'
            "        parts = [command] if isinstance(command, str) else [str(p) for p in command]\n"
            "        for part in parts:\n"
            '            separator = part.find("::")\n'
            '            # The separator must precede any "/", otherwise a bracketed\n'
            "            # IPv6 host such as http://[::1]/repo.git is misread.\n"
            '            if separator == -1 or "/" in part[:separator]:\n'
            "                continue\n"
            '            helper = part[:separator].split("+", 1)[0]\n'
            "            if helper not in allowed_helpers:\n"
            "                raise UnsafeProtocolError(\n"
            '                    f"remote-helper transport {helper!r} is not allowed; "\n'
            '                    f"allowed transports: {\', \'.join(sorted(allowed_helpers))}"\n'
            "                )\n"
        )
        cmd_source = cmd_source.replace(old, guard, 1)
        cmd_path.write_text(cmd_source, encoding="utf-8")
        changed.append("git/cmd.py")

    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, default=None)
    parser.add_argument("--keep", action="store_true", help="keep the scratch tree")
    args = parser.parse_args()

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="acv-cve-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"workdir: {workdir}")

    print("\n[1/4] download published GitPython 3.1.29 from PyPI")
    tree = download(workdir)
    print(f"  extracted to {tree}")

    print("\n[2/4] reproduce the vulnerability on the unpatched package")
    before = run_python(ATTACK_SNIPPET.format(path=str(tree)))
    print(f"  version {before['version']}, clone_from={before['clone_from']}, "
          f"remote_fetch={before['remote_fetch']}, executed={before['executed']}")
    if not before["executed"]:
        print("  the attack did not reproduce; the environment may differ")
        return 2

    print("\n[3/4] apply the transport-allowlist patch")
    changed = apply_fix(tree)
    print(f"  patched: {', '.join(changed) if changed else 'already patched'}")

    print("\n[4/4] verify the fix")
    after = run_python(ATTACK_SNIPPET.format(path=str(tree)))
    behaviour = run_python(BEHAVIOUR_SNIPPET.format(path=str(tree)))
    print(f"  clone_from={after['clone_from']}, remote_fetch={after['remote_fetch']}, "
          f"executed={after['executed']}")
    print(f"  normal clone={behaviour['clone_ok']}, normal fetch={behaviour['fetch_ok']}, "
          f"commit={behaviour['commit']!r}")

    blocked = not after["executed"]
    working = bool(behaviour["clone_ok"] and behaviour["fetch_ok"])

    print("\n" + "=" * 72)
    print(f"  reproduced before fix : {before['executed']}")
    print(f"  blocked after fix     : {blocked}")
    print(f"  normal git preserved  : {working}")
    print("=" * 72)

    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)

    if blocked and working:
        print("\nPASS: a real published package was hardened and still works.")
        return 0
    print("\nFAIL: the patch did not close the vulnerability or broke git.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
