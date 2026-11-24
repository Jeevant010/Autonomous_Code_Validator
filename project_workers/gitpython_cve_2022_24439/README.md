# GitPython CVE-2022-24439 project case

This is the real-repository calibration case for the project verifier.

## What is real here

- **Package:** GitPython 3.1.29, the released vulnerable version.
- **CVE:** CVE-2022-24439, remote-helper command injection.
- **Upstream fix:** GitPython 3.1.30 / PR #1521.
- **Vulnerable behaviour:** a caller-controlled clone or remote URL can use
  Git's `ext::` remote helper to execute a shell command.
- **Fixed behaviour:** unsafe protocols and clone/fetch/push options are rejected
  before Git is invoked.

The base tree is the released `git/` package plus its `gitdb` and `smmap`
dependencies, copied from the PyPI distributions. It is not a rewritten toy
version of GitPython. The functional tests and the exploit live outside the base
tree, so a generated overlay cannot replace its own evidence.

## Gate evidence

- `poc/exploit.py` tries two real attack paths:
  1. `Repo.clone_from("ext::sh ...")`
  2. `Remote.create(...)` followed by `Remote.fetch()`
- `tests/test_functional.py` exercises normal local clone and fetch.
- `fixed/` is the upstream 3.1.30 fix overlay.
- `benign/` is a different implementation: one central guard in
  `Git.execute` rejects every `transport::address` URL.
- `mutants/clone_only/` repairs only the clone path and leaves remote fetch
  vulnerable.

## Expected verdicts

| Candidate | Expected | Why |
| :--- | :--- | :--- |
| vulnerable baseline | reject | the exploit runs a command |
| `gold` | accept | upstream fix blocks both paths, normal tests pass |
| `benign` | accept | central guard blocks both paths, normal tests pass |
| `clone_only` | reject | clone is fixed but remote fetch still executes |

## What not to claim

This case validates the verifier against a known real vulnerability. It is not a
new vulnerability disclosure and it is not an external benchmark of every
GitPython code path. The project still runs with process limits only; use an
isolated VM or container for untrusted code.
