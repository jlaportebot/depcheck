# Workspace/Monorepo Support Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add `depcheck workspace` command to scan and analyze Python monorepos with multiple projects, detecting workspace configurations (uv, poetry, hatch, pdm, setuptools), discovering member projects, and performing cross-project dependency analysis.

**Architecture:** New `depcheck/workspace.py` module for workspace detection and analysis, `depcheck/workspace_report.py` for reporting, CLI command in `cli.py`. Integrates with existing `scan_project`, `render_table`, `render_json` infrastructure.

**Tech Stack:** Python 3.11+, click, rich, httpx, packaging, pyproject.toml parsing via tomllib/tomli.

---

## Task 1: Create Workspace Config Models

**Objective:** Define data structures for workspace configuration and member projects.

**Files:**
- Create: `depcheck/workspace.py` (new module)
- Modify: `depcheck/__init__.py` (export new types)

**Step 1: Write failing test**

```python
# tests/test_workspace.py
def test_workspace_config_detection_uv():
    from depcheck.workspace import detect_workspace_config, WorkspaceType
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "my-workspace"
            [tool.uv.workspace]
            members = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)
        (root / "packages" / "pkg2").mkdir()
        (root / "packages" / "pkg2" / "pyproject.toml").write_text("""
            [project]
            name = "pkg2"
            dependencies = ["httpx"]
        """)
        
        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.UV
        assert len(config.members) == 2
```

**Step 2: Run test to verify failure**

```bash
pytest tests/test_workspace.py::test_workspace_config_detection_uv -v
```

**Step 3: Write minimal implementation**

```python
# depcheck/workspace.py
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
import tomllib

class WorkspaceType(Enum):
    UV = "uv"
    POETRY = "poetry"
    HATCH = "hatch"
    PDM = "pdm"
    SETUPTOOLS = "setuptools"
    UNKNOWN = "unknown"

@dataclass
class WorkspaceConfig:
    workspace_type: WorkspaceType
    root_path: Path
    members: list[Path]
    config_path: Path

def detect_workspace_config(root: Path) -> Optional[WorkspaceConfig]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return None
    
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    
    # Check uv workspace
    if "tool" in data and "uv" in data["tool"] and "workspace" in data["tool"]["uv"]:
        ws = data["tool"]["uv"]["workspace"]
        members = ws.get("members", [])
        member_paths = _expand_globs(root, members)
        return WorkspaceConfig(
            workspace_type=WorkspaceType.UV,
            root_path=root,
            members=member_paths,
            config_path=pyproject,
        )
    
    return None

def _expand_globs(root: Path, patterns: list[str]) -> list[Path]:
    results = []
    for pattern in patterns:
        for match in root.glob(pattern):
            if match.is_dir() and (match / "pyproject.toml").exists():
                results.append(match)
    return sorted(results)
```

**Step 4: Run test to verify pass**

```bash
pytest tests/test_workspace.py::test_workspace_config_detection_uv -v
```

**Step 5: Commit**

```bash
git add depcheck/workspace.py tests/test_workspace.py
git commit -m "feat(workspace): add workspace config detection for uv"
```

---

## Task 2: Add Poetry Workspace Detection

**Objective:** Support Poetry's workspace configuration.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_workspace_config_detection_poetry():
    from depcheck.workspace import detect_workspace_config, WorkspaceType
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [tool.poetry.workspace]
            mode = "explicit"
            packages = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [tool.poetry]
            name = "pkg1"
            dependencies = { requests = "^2.28" }
        """)
        
        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.POETRY
        assert len(config.members) == 1
```

**Step 2-5:** Same TDD cycle.

---

## Task 3: Add Hatch Workspace Detection

**Objective:** Support Hatch's workspace configuration.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_workspace_config_detection_hatch():
    from depcheck.workspace import detect_workspace_config, WorkspaceType
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [tool.hatch.build.targets.wheel]
            packages = ["src"]
            [tool.hatch.envs.default]
            [tool.hatch.workspace]
            packages = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)
        
        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.HATCH
```

---

## Task 4: Add PDM Workspace Detection

**Objective:** Support PDM's workspace configuration.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

---

## Task 5: Add Setuptools Workspace Detection (pyproject.toml [project.workspace])

**Objective:** Support PEP 621 / setuptools workspace configuration.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

---

## Task 6: Create Workspace Member Project Model

**Objective:** Data structure for scanned member projects with health info.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_workspace_member_model():
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult
    from depcheck.models import ScanResult
    from pathlib import Path
    
    member = WorkspaceMember(
        name="pkg1",
        path=Path("/tmp/workspace/packages/pkg1"),
        scan_result=None,  # Will be filled after scan
    )
    assert member.name == "pkg1"
    assert member.relative_path == Path("packages/pkg1")
```

---

## Task 7: Implement Workspace Scanning Logic

**Objective:** Scan all member projects and aggregate results.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_scan_workspace():
    from depcheck.workspace import scan_workspace, WorkspaceScanResult
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "my-workspace"
            [tool.uv.workspace]
            members = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests>=2.28"]
        """)
        (root / "packages" / "pkg2").mkdir()
        (root / "packages" / "pkg2" / "pyproject.toml").write_text("""
            [project]
            name = "pkg2"
            dependencies = ["httpx>=0.24"]
        """)
        
        result = scan_workspace(root, check_vulnerabilities=False)
        assert isinstance(result, WorkspaceScanResult)
        assert len(result.members) == 2
        assert result.total_packages >= 2
```

**Step 2-5:** Implementation using existing `scan_project` from `depcheck.scanner`.

---

## Task 8: Cross-Project Dependency Analysis

**Objective:** Analyze shared dependencies, version conflicts, and duplication across workspace members.

**Files:**
- Create: `depcheck/workspace_analysis.py` (new module)
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_cross_project_analysis():
    from depcheck.workspace_analysis import analyze_workspace_dependencies
    from depcheck.workspace import WorkspaceScanResult, WorkspaceMember
    from depcheck.models import PackageInfo, PackageStatus
    from pathlib import Path
    
    # Create mock scan results with overlapping dependencies
    pkg1_result = create_mock_scan_result([
        PackageInfo(name="requests", installed_version="2.28.0", latest_version="2.31.0", status=PackageStatus.OUTDATED),
        PackageInfo(name="urllib3", installed_version="1.26.15", latest_version="2.0.0", status=PackageStatus.OUTDATED),
    ])
    pkg2_result = create_mock_scan_result([
        PackageInfo(name="requests", installed_version="2.28.0", latest_version="2.31.0", status=PackageStatus.OUTDATED),
        PackageInfo(name="certifi", installed_version="2023.01.01", latest_version="2023.07.22", status=PackageStatus.OUTDATED),
    ])
    
    members = [
        WorkspaceMember(name="pkg1", path=Path("packages/pkg1"), scan_result=pkg1_result),
        WorkspaceMember(name="pkg2", path=Path("packages/pkg2"), scan_result=pkg2_result),
    ]
    workspace_result = WorkspaceScanResult(root=Path("/tmp"), members=members, workspace_type=WorkspaceType.UV)
    
    analysis = analyze_workspace_dependencies(workspace_result)
    
    # Should detect shared dependency
    assert "requests" in analysis.shared_dependencies
    assert len(analysis.shared_dependencies["requests"]) == 2
    
    # Should detect version conflict (both same version in this case - no conflict)
    # But if versions differed, should flag
```

---

## Task 9: Version Conflict Detection

**Objective:** Detect when workspace members depend on different versions of the same package.

**Files:**
- Modify: `depcheck/workspace_analysis.py`
- Modify: `tests/test_workspace.py`

---

## Task 10: Duplicate Dependency Consolidation Suggestions

**Objective:** Suggest moving shared dependencies to workspace root or consolidating versions.

**Files:**
- Modify: `depcheck/workspace_analysis.py`
- Modify: `tests/test_workspace.py`

---

## Task 11: Workspace Health Score Calculation

**Objective:** Compute overall workspace health score from member scores.

**Files:**
- Modify: `depcheck/workspace.py`
- Modify: `tests/test_workspace.py`

---

## Task 12: Workspace Report Rendering (Table)

**Objective:** Rich table output for workspace scan results.

**Files:**
- Create: `depcheck/workspace_report.py` (new module)
- Modify: `tests/test_workspace.py`

**Step 1: Write failing test**

```python
def test_render_workspace_table():
    from depcheck.workspace_report import render_workspace_table
    from depcheck.workspace import WorkspaceScanResult, WorkspaceMember, WorkspaceType
    from depcheck.models import ScanResult
    from pathlib import Path
    from rich.console import Console
    from io import StringIO
    
    # Create mock workspace result
    result = WorkspaceScanResult(...)
    
    console = Console(file=StringIO(), force_terminal=False, no_color=True)
    render_workspace_table(result, console=console)
    
    output = console.file.getvalue()
    assert "pkg1" in output
    assert "pkg2" in output
    assert "Workspace Health" in output
```

---

## Task 13: Workspace Report Rendering (JSON)

**Objective:** JSON output for CI/CD integration.

**Files:**
- Modify: `depcheck/workspace_report.py`
- Modify: `tests/test_workspace.py`

---

## Task 14: Add `depcheck workspace` CLI Command

**Objective:** Wire up the CLI command with all options.

**Files:**
- Modify: `depcheck/cli.py`
- Modify: `tests/test_cli.py` (or create)

**Step 1: Write failing test**

```python
def test_workspace_cli_command():
    from click.testing import CliRunner
    from depcheck.cli import main
    import tempfile
    from pathlib import Path
    
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "my-workspace"
            [tool.uv.workspace]
            members = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)
        
        result = runner.invoke(main, ["workspace", str(root), "--no-vuln-check"])
        assert result.exit_code == 0
        assert "pkg1" in result.output
```

---

## Task 15: Add CLI Options for Workspace Command

**Objective:** Add options: `--json`, `--fail-on`, `--check-licenses`, `--no-vuln-check`, `--output`, `--format`.

**Files:**
- Modify: `depcheck/cli.py`
- Modify: `tests/test_cli.py`

---

## Task 16: Workspace HTML Report Generation

**Objective:** Generate interactive HTML dashboard for workspace (similar to `graph` command).

**Files:**
- Modify: `depcheck/workspace_report.py`
- Modify: `tests/test_workspace.py`

---

## Task 17: Integration Tests with Real Project

**Objective:** Test workspace command against a real monorepo structure.

**Files:**
- Create: `tests/fixtures/workspace_sample/` (test fixture)
- Modify: `tests/test_workspace_integration.py`

---

## Task 18: Update Documentation

**Objective:** Update README.md with workspace command usage.

**Files:**
- Modify: `README.md`

---

## Task 19: Run Full Test Suite and Fix Issues

**Objective:** Ensure all tests pass and coverage >= 75%.

```bash
pytest tests/ -v --cov=depcheck --cov-fail-under=75
ruff check --fix .
ruff format .
ty check depcheck/
```

---

## Task 20: Final Commit and PR

**Objective:** Push branch, create PR.

```bash
git add -A
git commit -m "feat(workspace): add monorepo/workspace support with cross-project analysis"
git push -u origin feat/workspace-monorepo-support
gh pr create --title "feat: add workspace/monorepo support" --body "..." --label enhancement
```

---

## Implementation Notes

### Workspace Configuration Patterns to Support

| Tool | Config Location | Member Spec |
|------|----------------|-------------|
| uv | `[tool.uv.workspace]` members | glob patterns |
| Poetry | `[tool.poetry.workspace]` packages | glob patterns |
| Hatch | `[tool.hatch.workspace]` packages | glob patterns |
| PDM | `[tool.pdm.workspace]` packages | glob patterns |
| Setuptools | `[project.workspace]` members | glob patterns |

### Cross-Project Analysis Features

1. **Shared Dependencies** - Packages used by multiple members
2. **Version Conflicts** - Same package, different versions across members
3. **Duplicate Dependencies** - Dependencies that could be hoisted to workspace root
4. **Transitive Overlap** - Shared transitive dependencies
5. **License Conflicts** - Incompatible licenses across members
6. **Vulnerability Propagation** - If shared dep is vulnerable, all members affected

### Output Formats

- Table (default) - Rich formatted table with health grades
- JSON - For CI/CD pipelines
- HTML - Interactive dashboard (stretch goal)

### Exit Codes

- 0: Success, workspace healthy
- 1: Workspace has issues (configurable with `--fail-on`)
- 2: Error (no workspace found, scan failed)

---

## Dependencies Between Tasks

```
Task 1 (UV config) → Task 2 (Poetry) → Task 3 (Hatch) → Task 4 (PDM) → Task 5 (Setuptools)
                                                                    ↓
Task 6 (Member model) → Task 7 (Scan logic) → Task 8 (Cross-project analysis)
                                                                    ↓
                                                         Task 9 (Version conflicts) → Task 10 (Consolidation)
                                                                    ↓
                                                         Task 11 (Health score) → Task 12 (Table report)
                                                                    ↓
                                                         Task 13 (JSON report) → Task 14 (CLI command)
                                                                    ↓
                                                         Task 15 (CLI options) → Task 16 (HTML report)
                                                                    ↓
                                                         Task 17 (Integration tests) → Task 18 (Docs)
                                                                    ↓
                                                         Task 19 (Full test suite) → Task 20 (PR)
```

---

## Success Criteria

- [ ] `depcheck workspace` detects uv, poetry, hatch, pdm, setuptools workspaces
- [ ] Scans all member projects in parallel (or sequentially with progress)
- [ ] Reports shared dependencies, version conflicts, consolidation opportunities
- [ ] Outputs table, JSON, and optionally HTML
- [ ] Exit codes work for CI/CD
- [ ] All tests pass (1636+ new tests)
- [ ] Coverage >= 75% for new code
- [ ] Ruff, ty, mypy clean
- [ ] Documentation updated