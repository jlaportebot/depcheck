"""One-shot refactor: split depcheck/cli.py into a depcheck/commands/ package.

The script parses the current CLI module, extracts every command function
(decorators included) into its own module, and prints the module list. It is
deterministic: after running it, the registered command set must be identical
in names and options.

Usage:
    python scripts/split_cli.py
"""

from __future__ import annotations

import ast
from pathlib import Path

CLI = Path("depcheck/cli.py")
OUT = Path("depcheck/commands")

#: When set, the source CLI module is read from this path instead of ``CLI``.
SOURCE_OVERRIDE: Path | None = None

TITLES = {
    "scan": "Scan a project for dependency health issues.",
    "tree": "Render the dependency tree with health status.",
    "diff": "Compare dependency files or detect lockfile drift.",
    "export": "Export a Software Bill of Materials (SBOM).",
    "license": "Check dependency license compliance.",
    "outdated": "Report outdated dependencies with upgrade paths.",
    "audit": "Audit dependencies for supply-chain risk.",
    "watch": "Watch dependency files and re-scan on change.",
    "why": "Explain why a dependency is present.",
    "check": "Check a project against dependency best practices.",
    "lockfile": "Inspect, diff and audit lockfiles.",
    "explain": "Explain the dependencies of a project.",
    "size": "Measure installed dependency sizes.",
    "suggest": "Suggest healthier alternative dependencies.",
    "history": "Report dependency changes across git history.",
    "bundle": "Bundle a project into a reproducible artifact set.",
    "doctor": "Diagnose dependency tooling and CI setup.",
    "budget": "Enforce dependency budgets.",
    "risks": "Assess dependency risk levels.",
    "advisories": "List security advisories affecting dependencies.",
    "graph": "Build an interactive dependency graph.",
    "policy": "Evaluate a project against a dependency policy.",
    "update": "Generate a prioritized dependency update plan.",
    "isolate": "Analyze dependency isolation boundaries.",
    "unused": "Detect unused dependencies via AST analysis.",
    "sizescore": "Score dependencies by install footprint.",
    "depdrift": "Track dependency drift across git history.",
    "compat": "Check Python version compatibility.",
}

#: Names that must resolve to a module-level import when used by a command.
MODULE_IMPORTS: dict[str, str] = {
    "render_json": "from depcheck.output import render_json",
    "render_table": "from depcheck.output import render_table",
    "determine_exit_code": "from depcheck.output import determine_exit_code",
    "render_github_annotations": "from depcheck.output import render_github_annotations",
    "LicenseCategory": "from depcheck.licenses import LicenseCategory",
}

#: Every command resolves the scanner through the shared indirection.
SCAN_IMPORT = "from depcheck.commands import _common"

HEADER = '''"""{title}"""

from __future__ import annotations

{imports}
'''


def collect_commands(tree: ast.Module) -> list[ast.FunctionDef]:
    """Return every command function registered on the CLI group."""
    commands = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if any("main.command" in ast.unparse(d) for d in node.decorator_list):
            commands.append(node)
    return commands


def bound_names(node: ast.AST) -> set[str]:
    """Return every name bound inside the command function."""
    names: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Store):
            names.add(inner.id)
        elif isinstance(inner, ast.Import):
            for alias in inner.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(inner, ast.ImportFrom):
            for alias in inner.names:
                names.add(alias.asname or alias.name)
        elif isinstance(inner, ast.arg):
            names.add(inner.arg)
        elif isinstance(inner, ast.ExceptHandler) and inner.name:
            names.add(inner.name)
        elif isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(inner.name)
    return names


def loaded_names(node: ast.AST) -> set[str]:
    """Return every name the command body reads."""
    return {
        inner.id
        for inner in ast.walk(node)
        if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load)
    }


def command_imports(body: str) -> list[str]:
    """Determine the module-level imports a command function needs."""
    tree = ast.parse(body)
    node = tree.body[0]
    bound = bound_names(node)
    used = loaded_names(node) - bound
    imports: list[str] = []
    if "click" in used:
        imports.append("import click")
    if "Console" in used:
        imports.append("from rich.console import Console")
    if "jsonout" in used:
        imports.append("from depcheck import jsonout")
    if "sys" in used:
        imports.append("import sys")
    if "Path" in used:
        imports.append("from pathlib import Path")
    for name, statement in MODULE_IMPORTS.items():
        if name in used:
            imports.append(statement)
    if "_common.scan_project" in body:
        imports.append(SCAN_IMPORT)
    return imports


def extract(node: ast.FunctionDef, lines: list[str]) -> str:
    """Return the source of a command function with its decorators."""
    start = min(d.lineno for d in node.decorator_list) - 1
    body = "\n".join(lines[start : node.end_lineno])
    body = body.replace(
        "@main.command()",
        f'@click.command(name="{node.name}")',
        1,
    )
    body = body.replace(
        "@main.command(name=",
        "@click.command(name=",
        1,
    )
    body = body.replace(f"def {node.name}(", "def command(", 1)
    body = body.replace("    from depcheck.scanner import scan_project\n", "")
    body = body.replace("scan_project(", "_common.scan_project(")
    body = body.replace("__common.scan_project(", "_common.scan_project(")
    return body


def main() -> None:
    """Extract each command into its own module and print the module list."""
    source_path = SOURCE_OVERRIDE or CLI
    source = source_path.read_text()
    lines = source.splitlines()
    tree = ast.parse(source)
    commands = collect_commands(tree)

    OUT.mkdir(parents=True, exist_ok=True)
    module_names = []
    for node in commands:
        body = extract(node, lines)
        imports = command_imports(body)
        header = HEADER.format(
            title=TITLES.get(node.name, f"depcheck {node.name} command."),
            imports="\n".join(imports),
        )
        (OUT / f"{node.name}.py").write_text(f"{header}\n\n{body}\n")
        module_names.append(node.name)

    print("extracted:", ", ".join(module_names))


if __name__ == "__main__":
    main()
