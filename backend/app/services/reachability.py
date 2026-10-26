"""Codebase-aware reachability analysis (SecureLens's core differentiator).

A plain scanner tells you *where* a vulnerable pattern is. SecureLens tells you
whether that code is actually **reachable** from a real entry point in *this*
repository — an HTTP route, a CLI ``main``, or top-level module code that runs
on import. That single fact is what turns a wall of findings into a ranked
worklist: a SQL injection on a public, unauthenticated route is urgent; the same
pattern in dead code or a test fixture is noise.

The analysis is pure static Python (the :mod:`ast` module) so it is fully
deterministic, needs no API key, and runs at scan time. It builds a call graph
keyed by function name, detects entry points from web-framework decorators /
``main`` / module-level code, then does a BFS from those entry points to decide
reach and the shortest call path for each finding.

Name-based resolution is intentionally biased toward *reachable*: declaring code
unreachable uses only ``medium`` confidence, because dynamic dispatch and
framework callbacks can hide real edges. We would rather keep a real finding
than wrongly silence it.
"""

from __future__ import annotations

import ast
import logging
import os
from collections import deque
from dataclasses import dataclass, field

from app.schemas.reachability import EntryPointKind, ReachabilityResult

logger = logging.getLogger("securelens.reachability")

# Directories that are vendored, generated, or otherwise not first-party source.
_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", "__pycache__", ".git", "chroma",
    "dist", "build", "site-packages", ".mypy_cache", ".pytest_cache", ".tox",
    ".idea", ".vscode", "migrations", "alembic",
}

# Decorator attribute names that mark a function as a web entry point, mapped to
# whether they carry an HTTP method in the attribute itself.
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "websocket"}
_ROUTE_DECORATORS = _HTTP_METHODS | {"route", "api_route", "endpoint", "middleware"}
# CLI frameworks (click/typer) expose commands as entry points too.
_CLI_DECORATORS = {"command", "callback"}
# Function names that are conventionally program entry points.
_ENTRY_NAMES = {"main", "handler", "handle", "lambda_handler", "run"}

_MAX_PY_FILE_BYTES = 1_000_000  # skip pathological/generated files


@dataclass
class FuncDef:
    """One function/method definition discovered in the repo."""

    name: str
    qualname: str
    file: str  # repo-relative, forward-slash
    lineno: int
    end_lineno: int
    is_entry: bool = False
    entry_kind: EntryPointKind = "unknown"
    entry_label: str | None = None


@dataclass
class RepoGraph:
    """The analyzed repo: function definitions, call edges, and entry points."""

    # Callee names invoked from each caller name (simple, last-segment names).
    edges: dict[str, set[str]] = field(default_factory=lambda: {})
    # All function definitions, grouped by file for enclosing-symbol lookup.
    defs_by_file: dict[str, list[FuncDef]] = field(default_factory=lambda: {})
    # Seed entry callee names -> (kind, label), from decorators/main/top-level.
    seeds: dict[str, tuple[EntryPointKind, str]] = field(default_factory=lambda: {})
    has_entry_points: bool = False
    # name -> (distance, path, kind, label) once reachability is computed.
    reachable: dict[str, tuple[int, list[str], EntryPointKind, str]] = field(
        default_factory=lambda: {}
    )


def is_test_path(path: str) -> bool:
    """True if a repo-relative path looks like test code (not production risk)."""
    p = path.replace("\\", "/").lower()
    parts = p.split("/")
    base = parts[-1]
    return (
        "tests" in parts
        or "test" in parts
        or base.startswith("test_")
        or base == "conftest.py"
    )


def _rel(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace("\\", "/")


def _iter_python_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def _callee_name(node: ast.AST) -> str | None:
    """Best-effort last-segment name of a call target (``os.system`` -> system)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _decorator_entry(dec: ast.expr) -> tuple[EntryPointKind, str] | None:
    """Classify a decorator as a web/CLI entry point, returning (kind, label)."""
    call = dec.value if isinstance(dec, ast.Expr) else dec
    args: list[ast.expr] = []
    if isinstance(call, ast.Call):
        args = list(call.args)
        target = call.func
    else:
        target = call
    attr = target.attr if isinstance(target, ast.Attribute) else (
        target.id if isinstance(target, ast.Name) else None
    )
    if attr is None:
        return None
    attr_l = attr.lower()
    if attr_l in _ROUTE_DECORATORS:
        method = attr_l.upper() if attr_l in _HTTP_METHODS else "ANY"
        path = ""
        if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            path = args[0].value
        label = f"{method} {path}".strip()
        return ("web_route", label or "web route")
    if attr_l in _CLI_DECORATORS:
        return ("cli_main", "CLI command")
    return None


class _ModuleVisitor(ast.NodeVisitor):
    """Collects function defs, call edges, and entry seeds for one module."""

    def __init__(self, graph: RepoGraph, rel_path: str) -> None:
        self.graph = graph
        self.rel = rel_path
        self._func_stack: list[str] = []
        self._in_main_guard = False

    # --- helpers ---------------------------------------------------------
    def _current_caller(self) -> str:
        return self._func_stack[-1] if self._func_stack else "__module__"

    def _add_edge(self, caller: str, callee: str) -> None:
        self.graph.edges.setdefault(caller, set()).add(callee)

    # --- visitors --------------------------------------------------------
    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qual = ".".join(self._func_stack + [node.name])
        fd = FuncDef(
            name=node.name,
            qualname=qual,
            file=self.rel,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno) or node.lineno,
        )
        for dec in node.decorator_list:
            hit = _decorator_entry(dec)
            if hit:
                fd.is_entry = True
                fd.entry_kind, fd.entry_label = hit
                break
        if not fd.is_entry and node.name in _ENTRY_NAMES:
            fd.is_entry = True
            fd.entry_kind = "cli_main"
            fd.entry_label = f"{node.name}()"
        if fd.is_entry:
            self.graph.seeds[node.name] = (fd.entry_kind, fd.entry_label or node.name)
            self.graph.has_entry_points = True

        self.graph.defs_by_file.setdefault(self.rel, []).append(fd)
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _callee_name(node.func)
        if callee:
            caller = self._current_caller()
            self._add_edge(caller, callee)
            # Calls made at module top level (or in __main__) are program entry
            # points: whatever they invoke is reachable when the module runs.
            if caller == "__module__" or self._in_main_guard:
                kind: EntryPointKind = (
                    "cli_main" if self._in_main_guard else "module_top_level"
                )
                self.graph.seeds.setdefault(callee, (kind, "module __main__" if self._in_main_guard else "module top-level"))
                self.graph.has_entry_points = True
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if self._is_main_guard(node.test):
            prev = self._in_main_guard
            self._in_main_guard = True
            for child in node.body:
                self.visit(child)
            self._in_main_guard = prev
            for child in node.orelse:
                self.visit(child)
        else:
            self.generic_visit(node)

    @staticmethod
    def _is_main_guard(test: ast.expr) -> bool:
        """Detect ``if __name__ == "__main__":``."""
        return (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and any(
                isinstance(c, ast.Constant) and c.value == "__main__"
                for c in test.comparators
            )
        )


def analyze_repo(repo_path: str) -> RepoGraph:
    """Parse every first-party ``.py`` file and build the reachability graph."""
    graph = RepoGraph()
    root = os.path.abspath(repo_path)
    for file in _iter_python_files(root):
        try:
            if os.path.getsize(file) > _MAX_PY_FILE_BYTES:
                continue
            with open(file, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
            tree = ast.parse(source)
        except (SyntaxError, OSError) as exc:  # unparseable file: skip, don't crash
            logger.debug("reachability skip %s: %s", file, exc)
            continue
        _ModuleVisitor(graph, _rel(file, root)).visit(tree)
    _compute_reachable(graph)
    return graph


def _compute_reachable(graph: RepoGraph) -> None:
    """BFS from every entry seed to fill graph.reachable with shortest paths."""
    queue: deque[tuple[str, int, list[str], EntryPointKind, str]] = deque()
    for name, (kind, label) in graph.seeds.items():
        queue.append((name, 0, [name], kind, label))
    while queue:
        name, dist, path, kind, label = queue.popleft()
        existing = graph.reachable.get(name)
        if existing is not None and existing[0] <= dist:
            continue
        graph.reachable[name] = (dist, path, kind, label)
        for callee in graph.edges.get(name, ()):  # expand neighbors
            if callee not in graph.reachable:
                queue.append((callee, dist + 1, path + [callee], kind, label))


def _enclosing_symbol(graph: RepoGraph, file: str, line: int | None) -> FuncDef | None:
    """Return the innermost function containing (file, line), or None."""
    candidates = [
        fd for fd in graph.defs_by_file.get(file, [])
        if line is not None and fd.lineno <= line <= fd.end_lineno
    ]
    if not candidates:
        return None
    # Innermost == smallest line span.
    return min(candidates, key=lambda fd: fd.end_lineno - fd.lineno)


def reachability_for(
    graph: RepoGraph, file: str, line: int | None
) -> ReachabilityResult:
    """Compute the reachability verdict for one finding location."""
    file = (file or "").replace("\\", "/")

    if is_test_path(file):
        return ReachabilityResult(
            reachable=False, confidence="medium", entry_point_kind="unknown",
            reason="Finding is in test code, not a production entry point.",
        )

    enclosing = _enclosing_symbol(graph, file, line)

    if enclosing is None:
        # Not inside any function: this is module-level code that executes on
        # import, so it is always reachable when the module is loaded.
        return ReachabilityResult(
            reachable=True, confidence="high", entry_point_kind="module_top_level",
            entry_point="module top-level (runs on import)",
            enclosing_symbol=None, distance=0,
            reason="Module-level code executes whenever the module is imported.",
        )

    sym = enclosing.name

    if enclosing.is_entry:
        return ReachabilityResult(
            reachable=True, confidence="high", entry_point_kind=enclosing.entry_kind,
            entry_point=enclosing.entry_label or sym, call_path=[sym],
            enclosing_symbol=sym, distance=0,
            reason=f"'{sym}' is itself an entry point ({enclosing.entry_label}).",
        )

    hit = graph.reachable.get(sym)
    if hit is not None:
        dist, path, kind, label = hit
        return ReachabilityResult(
            reachable=True, confidence="high", entry_point_kind=kind,
            entry_point=label, call_path=path, enclosing_symbol=sym, distance=dist,
            reason=f"Reachable from entry point '{label}' via {' -> '.join(path)}.",
        )

    if graph.has_entry_points:
        # We found entry points and this symbol is not among the reachable set.
        # Use medium confidence: name-based call graphs can miss dynamic edges.
        return ReachabilityResult(
            reachable=False, confidence="medium", entry_point_kind="unknown",
            enclosing_symbol=sym,
            reason=(
                f"'{sym}' is not reachable from any detected entry point "
                "(likely dead code, a helper, or invoked dynamically)."
            ),
        )

    # No entry points anywhere (e.g. a library or a standalone sample): we
    # cannot prove reach, so treat public functions as potentially reachable
    # rather than silently suppressing a real vulnerability.
    is_public = not sym.startswith("_")
    kind_pub: EntryPointKind = "public_function" if is_public else "unknown"
    return ReachabilityResult(
        reachable=is_public, confidence="low", entry_point_kind=kind_pub,
        enclosing_symbol=sym,
        reason=(
            "No entry points detected in this repo; "
            + ("public function treated as potentially reachable."
               if is_public else "private helper, reachability unknown.")
        ),
    )
