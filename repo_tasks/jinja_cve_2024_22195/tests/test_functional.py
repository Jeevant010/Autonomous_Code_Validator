"""Behaviour that must keep working after the CVE-2024-22195 fix.

This is the trusted functional signal. It exercises the same public surface the
patch touches, so a patch that "fixes" the CVE by breaking ``xmlattr`` is
rejected. Every assertion here passes on unpatched Jinja 3.1.2, which is what
makes it a valid behaviour check rather than a wish list.
"""

from __future__ import annotations

import pytest
from jinja2 import Environment, Undefined


@pytest.fixture()
def env() -> Environment:
    return Environment(autoescape=True)


def test_xmlattr_renders_normal_keys(env: Environment) -> None:
    template = env.from_string("{{ attrs|xmlattr }}")
    out = template.render(attrs={"class": "card", "id": "main"})

    assert 'class="card"' in out
    assert 'id="main"' in out


def test_xmlattr_skips_none_and_undefined(env: Environment) -> None:
    template = env.from_string("{{ attrs|xmlattr }}")
    out = template.render(attrs={"a": None, "b": env.undefined("missing"), "c": "keep"})

    parts = out.split()
    assert len(parts) == 1
    assert parts[0] == 'c="keep"'


def test_xmlattr_still_escapes_values(env: Environment) -> None:
    template = env.from_string("{{ attrs|xmlattr }}")
    out = template.render(attrs={"title": 'x" onclick="alert(1)'})

    assert "onclick" not in out or 'title="' in out
    # The quote inside the value must be escaped, not emitted raw.
    assert 'x" onclick="alert(1)' not in out
    assert "&#34;" in out or "&quot;" in out


def test_xmlattr_escapes_markup_in_values(env: Environment) -> None:
    template = env.from_string("{{ attrs|xmlattr }}")
    out = template.render(attrs={"data": "<script>"})

    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_xmlattr_autospace_off(env: Environment) -> None:
    template = env.from_string("<p{{ attrs|xmlattr(false) }}>")
    out = template.render(attrs={"a": "1"})

    assert out == '<pa="1">'


def test_xmlattr_nested_key(env: Environment) -> None:
    template = env.from_string("{{ attrs|xmlattr }}")
    out = template.render(attrs={"blub:blub": "<?>"})

    assert 'blub:blub="&lt;?&gt;"' in out
