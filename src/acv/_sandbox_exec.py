"""Apply resource limits and then exec a command.

This helper runs as a separate process so the parent does not use
``preexec_fn`` in a potentially threaded server process.
"""

from __future__ import annotations

import os
import resource
import sys


def _set(limit: int, value: int) -> None:
    _soft, hard = resource.getrlimit(limit)
    if hard != resource.RLIM_INFINITY:
        value = min(value, hard)
    resource.setrlimit(limit, (value, value))


def main() -> None:
    args = sys.argv[1:]
    try:
        marker = args.index("--")
    except ValueError:
        raise SystemExit("usage: _sandbox_exec LIMITS -- COMMAND ...") from None
    limits = args[:marker]
    command = args[marker + 1 :]
    if len(limits) != 4 or not command:
        raise SystemExit("usage: _sandbox_exec MEMORY CPU FSIZE NOFILE -- COMMAND ...")

    memory, cpu, fsize, nofile = (int(value) for value in limits)
    _set(resource.RLIMIT_CORE, 0)
    _set(resource.RLIMIT_AS, memory)
    _set(resource.RLIMIT_FSIZE, fsize)
    _set(resource.RLIMIT_NOFILE, nofile)
    _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    cpu = min(cpu, hard) if hard != resource.RLIM_INFINITY else cpu
    hard_cpu = cpu + 1
    if hard != resource.RLIM_INFINITY:
        hard_cpu = min(hard_cpu, hard)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, hard_cpu))
    os.umask(0o077)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
