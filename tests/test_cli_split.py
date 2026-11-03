"""Tests for the command package structure.

The CLI group is a thin registrar over :mod:`depcheck.commands`. These tests
lock that structure in place so a command can never silently disappear from
the group or lose its exported command object.
"""

from __future__ import annotations

import importlib
import pkgutil

import click
import pytest

from depcheck import commands
from depcheck.cli import main

#: Every command module in :mod:`depcheck.commands` and the CLI name it uses.
EXPECTED_COMMANDS = {
    "advisories": "advisories",
    "audit": "audit",
    "budget": "budget",
    "bundle": "bundle",
    "check": "check",
    "compat": "compat",
    "depdrift": "depdrift",
    "diff": "diff",
    "doctor": "doctor",
    "explain": "explain",
    "export": "export",
    "graph": "graph",
    "history": "history",
    "isolate": "isolate",
    "license": "license",
    "lockfile": "lockfile",
    "outdated": "outdated",
    "policy": "policy",
    "risks": "risks",
    "scan": "scan",
    "size": "size",
    "sizescore": "sizescore",
    "suggest": "suggest",
    "tree": "tree",
    "unused": "unused",
    "update": "update",
    "watch": "watch",
    "why": "why",
}


def command_module_names() -> list[str]:
    """Return the names of every command module in the package."""
    names = []
    for info in pkgutil.iter_modules(commands.__path__):
        if not info.name.startswith("_"):
            names.append(info.name)
    return sorted(names)


class TestCommandPackage:
    """Structural tests for the command package."""

    def test_package_exposes_every_expected_module(self):
        assert command_module_names() == sorted(EXPECTED_COMMANDS)

    @pytest.mark.parametrize("module_name", sorted(EXPECTED_COMMANDS))
    def test_module_exports_click_command(self, module_name):
        module = importlib.import_module(f"depcheck.commands.{module_name}")
        assert isinstance(module.command, click.Command)

    @pytest.mark.parametrize("module_name", sorted(EXPECTED_COMMANDS))
    def test_module_command_uses_expected_name(self, module_name):
        module = importlib.import_module(f"depcheck.commands.{module_name}")
        assert module.command.name == EXPECTED_COMMANDS[module_name]

    @pytest.mark.parametrize("module_name", sorted(EXPECTED_COMMANDS))
    def test_module_command_has_help_text(self, module_name):
        module = importlib.import_module(f"depcheck.commands.{module_name}")
        assert module.command.help


class TestCliRegistrar:
    """Tests for the CLI group that registers the commands."""

    def test_group_registers_every_command(self):
        registered = set(main.commands)
        expected = set(EXPECTED_COMMANDS.values())
        assert registered == expected

    def test_group_exposes_scan_project_binding(self):
        from depcheck import cli

        assert callable(cli.scan_project)

    def test_every_command_help_renders(self):
        from click.testing import CliRunner

        runner = CliRunner()
        for name in sorted(main.commands):
            result = runner.invoke(main, [name, "--help"])
            assert result.exit_code == 0, f"{name} --help failed: {result.output}"

    def test_group_help_lists_commands(self):
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        for name in sorted(EXPECTED_COMMANDS.values()):
            assert name in result.output


class TestScannerIndirection:
    """Tests for the shared scanner binding used by the command modules."""

    def test_common_scan_project_delegates_to_cli_binding(self, monkeypatch):
        from depcheck import cli
        from depcheck.commands import _common

        calls = []

        def fake_scan(*args, **kwargs):
            calls.append((args, kwargs))
            return "scanned"

        monkeypatch.setattr(cli, "scan_project", fake_scan)
        assert _common.scan_project("path", check_vulnerabilities=False) == "scanned"
        assert calls == [(("path",), {"check_vulnerabilities": False})]
