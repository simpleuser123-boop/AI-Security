"""Static guard for high-risk ORM reads that must be tenant scoped.

The scanner is intentionally conservative and focused on core business models.
It catches direct ``db.session.query(Model)`` calls that omit a tenant predicate
and direct ``session.get(Model, ...)`` calls where ``tenant_get`` should be used.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable, List, Sequence


TENANT_SCOPED_MODELS = {
    "Alert",
    "AlertHistory",
    "APIKey",
    "AuditEvent",
    "BannedIp",
    "IOC",
    "LicenseKey",
    "ModelVersion",
    "Organization",
    "Quota",
    "ResponseAction",
    "ResponseApproval",
    "ResponseDrill",
    "ResponseProviderConfig",
    "ResponseScheduleTask",
    "ResponseWhitelistEntry",
    "Rule",
    "Setting",
    "Subscription",
    "UsageMeter",
}

GLOBAL_OR_CONTROL_PLANE_MODELS = {
    "Membership",
    "Role",
    "Tenant",
    "User",
    "Plan",
}

DEFAULT_PATHS = ("web", "src", "tests/test_tenant_isolation_c1.py")


class Finding:
    def __init__(
        self,
        path: str,
        line: int,
        model: str,
        reason: str,
        suggestion: str,
        category: str,
        access: str,
        *,
        exempt: bool = False,
        exemption_reason: str = "",
    ) -> None:
        self.path = path
        self.line = line
        self.model = model
        self.reason = reason
        self.suggestion = suggestion
        self.category = category
        self.access = access
        self.exempt = exempt
        self.exemption_reason = exemption_reason

    def format(self) -> str:
        status = "EXEMPT" if self.exempt else "ERROR"
        detail = f" reason={self.reason}"
        if self.exemption_reason:
            detail += f" exemption={self.exemption_reason}"
        return (
            f"{status} {self.path}:{self.line}: model={self.model} "
            f"category={self.category} access={self.access}{detail} "
            f"suggestion={self.suggestion}"
        )


class ScanResult:
    def __init__(self, findings: List[Finding], exemptions: List[Finding]) -> None:
        self.findings = findings
        self.exemptions = exemptions

    @property
    def ok(self) -> bool:
        return not self.findings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _model_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _model_name(node.func)
    return ""


def _source_segment(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ""


def _category(path: Path) -> str:
    parts = path.parts
    if parts and parts[0] == "tests":
        return "test-only"
    if parts and parts[0] == "scripts":
        return "production-script"
    return "production"


def _query_suggestion(model: str) -> str:
    return (
        f"use tenant_query(db.session.query({model}), {model}) or add an explicit "
        f"{model}.tenant_id predicate with a server-resolved tenant id"
    )


def _get_suggestion(model: str) -> str:
    return (
        f"use tenant_get(session, {model}, ident) or replace with a query filtered by "
        f"{model}.tenant_id"
    )


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: Path, source: str) -> None:
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: List[Finding] = []
        self.exemptions: List[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name.endswith(".query") and node.args:
            for model in self._tenant_models(node.args):
                self._record_query_access(node, model)
        if name.endswith(".get") and node.args:
            model = _model_name(node.args[0])
            if model in TENANT_SCOPED_MODELS and model not in GLOBAL_OR_CONTROL_PLANE_MODELS:
                self._record_get_access(node, model)
        self.generic_visit(node)

    def _tenant_models(self, args: Sequence[ast.AST]) -> List[str]:
        found: set[str] = set()
        for arg in args:
            model = _model_name(arg)
            if model in TENANT_SCOPED_MODELS and model not in GLOBAL_OR_CONTROL_PLANE_MODELS:
                found.add(model)
        return sorted(found)

    def _record_query_access(self, node: ast.Call, model: str) -> None:
        stmt = self._enclosing_stmt_source(node)
        allow = self._allow_reason(stmt, node.lineno)
        if allow:
            self.exemptions.append(
                Finding(
                    str(self.path),
                    node.lineno,
                    model,
                    "query direct access is explicitly exempted",
                    _query_suggestion(model),
                    _category(self.path),
                    "query",
                    exempt=True,
                    exemption_reason=allow,
                )
            )
            return
        if "tenant_query(" in stmt or f"{model}.tenant_id" in stmt or "tenant_id=" in stmt:
            return
        self.findings.append(
            Finding(
                str(self.path),
                node.lineno,
                model,
                "query lacks tenant_query(...) or explicit tenant_id predicate",
                _query_suggestion(model),
                _category(self.path),
                "query",
            )
        )

    def _record_get_access(self, node: ast.Call, model: str) -> None:
        stmt = self._enclosing_stmt_source(node)
        allow = self._allow_reason(stmt, node.lineno)
        if allow:
            self.exemptions.append(
                Finding(
                    str(self.path),
                    node.lineno,
                    model,
                    "direct session.get is explicitly exempted",
                    _get_suggestion(model),
                    _category(self.path),
                    "get",
                    exempt=True,
                    exemption_reason=allow,
                )
            )
            return
        if "tenant_get(" in stmt:
            return
        self.findings.append(
            Finding(
                str(self.path),
                node.lineno,
                model,
                "direct session.get on tenant-scoped model",
                _get_suggestion(model),
                _category(self.path),
                "get",
            )
        )

    def _enclosing_stmt_source(self, node: ast.AST) -> str:
        root = getattr(node, "_parent_stmt", node)
        return _source_segment(self.source, root)

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    def _allow_reason(self, stmt: str, lineno: int) -> str:
        candidates = [stmt, self._line_text(lineno), self._line_text(lineno - 1), self._line_text(lineno - 2)]
        for line in candidates:
            if "tenant-scan: allow" in line:
                return line.split("tenant-scan: allow", 1)[1].strip(" .#")
        return ""


def _attach_parent_stmt(tree: ast.AST) -> None:
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.stmt):
            for child in ast.walk(stmt):
                setattr(child, "_parent_stmt", stmt)


def scan_file(path: Path, *, root: Path | None = None) -> List[Finding]:
    return scan_file_report(path, root=root).findings


def scan_file_report(path: Path, *, root: Path | None = None) -> ScanResult:
    text = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(text, filename=str(path))
    _attach_parent_stmt(tree)
    try:
        rel = path.relative_to(root) if root else path
    except ValueError:
        rel = path
    scanner = _Scanner(rel, text)
    scanner.visit(tree)
    return ScanResult(scanner.findings, scanner.exemptions)


def scan_paths(paths: Iterable[Path], *, root: Path | None = None) -> List[Finding]:
    return scan_paths_report(paths, root=root).findings


def scan_paths_report(paths: Iterable[Path], *, root: Path | None = None) -> ScanResult:
    out: List[Finding] = []
    exemptions: List[Finding] = []
    for base in paths:
        if base.is_file() and base.suffix == ".py":
            result = scan_file_report(base, root=root)
            out.extend(result.findings)
            exemptions.extend(result.exemptions)
        elif base.is_dir():
            for path in base.rglob("*.py"):
                if "__pycache__" not in path.parts:
                    result = scan_file_report(path, root=root)
                    out.extend(result.findings)
                    exemptions.extend(result.exemptions)
    return ScanResult(out, exemptions)


def main(argv: list[str]) -> int:
    root = Path.cwd()
    paths = [root / p for p in (argv or list(DEFAULT_PATHS))]
    result = scan_paths_report(paths, root=root)
    for f in result.findings:
        print(f.format())
    for f in result.exemptions:
        print(f.format())
    path_label = ",".join(str(p.relative_to(root)) if p.is_relative_to(root) else str(p) for p in paths)
    print(f"tenant_query_scan summary: errors={len(result.findings)} exemptions={len(result.exemptions)} paths={path_label}")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
