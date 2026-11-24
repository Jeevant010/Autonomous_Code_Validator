"""Normal GitPython behaviour used as the functional side of the gate."""

from __future__ import annotations

from pathlib import Path

from git import Repo


def _make_source(path: Path) -> Repo:
    repo = Repo.init(path)
    with repo.config_writer() as config:
        config.set_value("user", "name", "ACV Fixture")
        config.set_value("user", "email", "acv@example.invalid")
    (path / "README.md").write_text("normal repository\n", encoding="utf-8")
    repo.index.add(["README.md"])
    repo.index.commit("initial")
    return repo


def test_normal_local_clone(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _make_source(source)
    clone = Repo.clone_from(str(source), tmp_path / "clone")
    assert (Path(clone.working_dir) / "README.md").read_text() == "normal repository\n"


def test_normal_remote_fetch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _make_source(source)
    target = Repo.init(tmp_path / "target")
    remote = target.create_remote("origin", str(source))
    remote.fetch()
    assert remote.url == str(source)
    assert any(ref.remote_head == "master" for ref in remote.refs) or any(
        ref.remote_head == "main" for ref in remote.refs
    )


def test_git_version_is_available(tmp_path: Path) -> None:
    version = Repo.init(tmp_path / "version-check").git.version()
    assert "git version" in version


def test_repository_reports_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    repo = _make_source(source)
    assert "README.md" in repo.git.ls_files().splitlines()
    assert repo.head.commit.message == "initial"
