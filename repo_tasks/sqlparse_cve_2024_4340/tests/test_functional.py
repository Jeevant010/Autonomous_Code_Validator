"""Functional test suite for sqlparse task.

Verifies that standard SQL parsing, splitting, and formatting work correctly.
"""

import sqlparse
from sqlparse import tokens as T


def test_simple_select():
    sql = "SELECT * FROM users WHERE id = 1;"
    parsed = sqlparse.parse(sql)
    assert len(parsed) == 1
    stmt = parsed[0]
    assert stmt.get_type() == "SELECT"


def test_split_statements():
    sql = "SELECT 1; SELECT 2; SELECT 3;"
    stmts = sqlparse.split(sql)
    assert len(stmts) == 3


def test_format_sql():
    sql = "select a, b, c from foo where id = 1"
    formatted = sqlparse.format(sql, reindent=True, keyword_case="upper")
    assert "SELECT" in formatted
    assert "FROM" in formatted
    assert "WHERE" in formatted


def test_tokens_flatten():
    sql = "SELECT count(*) FROM (SELECT 1 AS col);"
    parsed = sqlparse.parse(sql)[0]
    tokens = list(parsed.flatten())
    assert any(t.value == "SELECT" for t in tokens)
    assert any(t.value == "FROM" for t in tokens)
