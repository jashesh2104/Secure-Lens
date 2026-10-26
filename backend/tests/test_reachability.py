"""Tests for codebase-aware reachability analysis.

These are fully deterministic: we write small repos to a tmp dir, run the static
analyzer, and assert the reach verdict for specific finding locations. No LLM,
network, or scanner binary is involved.
"""

from __future__ import annotations

from app.services import reachability

WEBAPP = """\
from flask import Flask, request

app = Flask(__name__)


def run_query(uid):
    cur = get_cursor()
    cur.execute("SELECT * FROM u WHERE id = '" + uid + "'")


@app.route("/user")
def get_user():
    return run_query(request.args["id"])


def orphan():
    eval(request.args["x"])
"""


def _line(src: str, needle: str) -> int:
    for i, line in enumerate(src.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle not found: {needle}")


def _write(tmp_path, name: str, content: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_reachable_from_web_route_via_call_path(tmp_path):
    _write(tmp_path, "webapp.py", WEBAPP)
    graph = reachability.analyze_repo(str(tmp_path))
    line = _line(WEBAPP, "cur.execute(")

    result = reachability.reachability_for(graph, "webapp.py", line)

    assert result.reachable is True
    assert result.entry_point_kind == "web_route"
    assert result.enclosing_symbol == "run_query"
    # Path threads from the route handler down to the vulnerable helper.
    assert result.call_path == ["get_user", "run_query"]
    assert result.confidence == "high"


def test_dead_code_is_not_reachable(tmp_path):
    _write(tmp_path, "webapp.py", WEBAPP)
    graph = reachability.analyze_repo(str(tmp_path))
    line = _line(WEBAPP, "eval(request.args")

    result = reachability.reachability_for(graph, "webapp.py", line)

    assert result.reachable is False
    assert result.enclosing_symbol == "orphan"


def test_module_level_code_is_reachable(tmp_path):
    _write(tmp_path, "webapp.py", WEBAPP)
    graph = reachability.analyze_repo(str(tmp_path))
    line = _line(WEBAPP, "app = Flask(")

    result = reachability.reachability_for(graph, "webapp.py", line)

    assert result.reachable is True
    assert result.entry_point_kind == "module_top_level"
    assert result.enclosing_symbol is None


def test_test_code_is_flagged_not_reachable(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_thing.py").write_text(
        "def test_x():\n    eval('1+1')\n", encoding="utf-8"
    )
    graph = reachability.analyze_repo(str(tmp_path))

    result = reachability.reachability_for(graph, "tests/test_thing.py", 2)

    assert result.reachable is False
    assert "test code" in result.reason.lower()


def test_no_entry_points_treats_public_function_as_reachable(tmp_path):
    # A standalone library-style module with no routes/main/top-level calls.
    src = "def ping(host):\n    import os\n    os.system('ping ' + host)\n"
    _write(tmp_path, "lib.py", src)
    graph = reachability.analyze_repo(str(tmp_path))

    result = reachability.reachability_for(graph, "lib.py", 3)

    assert result.reachable is True
    assert result.confidence == "low"
    assert result.entry_point_kind == "public_function"
