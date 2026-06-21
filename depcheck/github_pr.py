"""GitHub PR automation client for depcheck remediation.

Provides async GitHub API interactions for creating branches, PRs,
adding labels, requesting reviewers, and enabling auto-merge.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

from depcheck.remediate import RemediationGroup, RemediationPlan


@dataclass
class PRConfig:
    """Configuration for PR creation behavior."""

    base_branch: str = "main"
    auto_merge: bool = False
    draft: bool = False
    labels: Optional[list[str]] = None
    reviewers: Optional[list[str]] = None
    assignees: Optional[list[str]] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = ["automated", "dependencies"]
        if self.reviewers is None:
            self.reviewers = []
        if self.assignees is None:
            self.assignees = []


@dataclass
class PRDescription:
    """Generates PR description markdown from a remediation group."""

    group: RemediationGroup
    repository: str
    base_branch: str = "main"

    def generate(self) -> str:
        """Generate the PR description as markdown."""
        lines = [
            f"# {self.group.title}",
            "",
            f"This PR automates **{self.group.priority.upper()}** priority dependency updates "
            f"for [{self.repository}](https://github.com/{self.repository}).",
            "",
            "## Changes",
            "",
        ]

        for detail in self.group.step_details:
            name = detail["name"]
            current = detail["current"]
            target = detail["target"]
            rationale = detail.get("rationale", "update available")
            changelog = detail.get("changelog_url")
            risk = detail.get("risk", "unknown").upper()
            upgrade = detail.get("upgrade_level", "unknown").upper()
            is_vuln = detail.get("is_vulnerable", False)

            vuln_badge = " 🔴 **VULNERABLE**" if is_vuln else ""
            lines.extend(
                [
                    f"### `{name}`: `{current}` → `{target}`{vuln_badge}",
                    "",
                    f"- **Upgrade Level**: {upgrade}",
                    f"- **Risk Assessment**: {risk}",
                    f"- **Rationale**: {rationale}",
                ]
            )

            cmd = detail.get("command", f"pip install --upgrade {name}=={target}")
            lines.append(f"- **Command**: `{cmd}`")

            if changelog:
                lines.append(f"- **Changelog**: [{changelog}]({changelog})")

            if detail.get("days_behind"):
                lines.append(f"- **Days Behind**: {detail['days_behind']}")

            if detail.get("breaking_change_risk"):
                lines.append(
                    f"- **Breaking Change Risk**: {detail['breaking_change_risk'].upper()}"
                )

            lines.append("")

        lines.extend(
            [
                "## Test Plan",
                "",
                "After merging, run the following to verify:",
                "",
                "```bash",
                "# Update dependencies",
            ]
        )

        for detail in self.group.step_details:
            default_cmd = f"pip install --upgrade {detail['name']}=={detail['target']}"
            cmd = detail.get("command", default_cmd)
            lines.append(cmd)

        lines.extend(
            [
                "",
                "# Run project tests",
                "pytest  # or your test command",
                "",
                "# Verify dependency health",
                "depcheck scan .",
                "```",
                "",
                "## Rollback",
                "",
                "If issues arise, revert this PR or run:",
                "",
                "```bash",
            ]
        )

        for detail in self.group.step_details:
            lines.append(f"pip install {detail['name']}=={detail['current']}")

        lines.extend(
            [
                "```",
                "",
                "---",
                "",
                "*This PR was generated automatically by "
                "[depcheck](https://github.com/jlaportebot/depcheck). "
                "Review the changes and test thoroughly before merging.*",
            ]
        )

        return "\n".join(lines)


class GitHubPRClient:
    """Async GitHub API client for PR operations.

    Uses `gh` CLI for authenticated API calls.
    """

    def __init__(self, repo: str, token: str | None = None):
        """Initialize the client.

        Args:
            repo: Repository in 'owner/repo' format.
            token: GitHub token. If None, uses gh CLI auth.
        """
        self.repo = repo
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self._use_gh_cli = token is None

    async def _gh_api(self, endpoint: str, method: str = "GET", data: dict | None = None) -> Any:
        """Make a GitHub API call via gh CLI."""
        args = ["gh", "api", f"/repos/{self.repo}{endpoint}", "--method", method]
        if data:
            args.extend(["--input", "-"])
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(input=json.dumps(data).encode())
        else:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"gh api failed: {stderr.decode()}")

        return json.loads(stdout.decode()) if stdout else {}

    async def _gh_cli(self, *args: str) -> Any:
        """Run a gh CLI command and parse JSON output."""
        cmd = ["gh", *args, "--json", "number,html_url,title,state,headRefName,baseRefName"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"gh cli failed: {stderr.decode()}")

        return json.loads(stdout.decode()) if stdout else {}

    async def get_default_branch(self) -> str:
        """Get the default branch of the repository."""
        result = await self._gh_api("/repo", "GET")
        return result.get("default_branch", "main")

    async def get_base_sha(self, branch: str) -> str:
        """Get the latest commit SHA for a branch."""
        result = await self._gh_api(f"/git/ref/heads/{branch}", "GET")
        return result.get("object", {}).get("sha", "")

    async def create_branch(self, new_branch: str, from_branch: str) -> str:
        """Create a new branch from an existing branch.

        Args:
            new_branch: Name of the new branch.
            from_branch: Source branch name.

        Returns:
            The full ref of the created branch.
        """
        sha = await self.get_base_sha(from_branch)
        if not sha:
            raise RuntimeError(f"Could not get SHA for branch {from_branch}")

        result = await self._gh_api(
            "/git/refs",
            "POST",
            {"ref": f"refs/heads/{new_branch}", "sha": sha},
        )
        return result.get("ref", f"refs/heads/{new_branch}")

    async def create_pr(
        self,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool = False,
    ) -> dict[str, Any]:
        """Create a pull request.

        Args:
            title: PR title.
            body: PR description body.
            head: Head branch name.
            base: Base branch name.
            draft: Whether to create as draft.

        Returns:
            PR info dict with number, html_url, etc.
        """
        data = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "draft": draft,
        }
        result = await self._gh_api("/pulls", "POST", data)
        return result

    async def add_labels(self, pr_number: int, labels: list[str]) -> list[dict]:
        """Add labels to a PR."""
        result = await self._gh_api(
            f"/issues/{pr_number}/labels",
            "POST",
            {"labels": labels},
        )
        return result

    async def request_reviewers(self, pr_number: int, reviewers: list[str]) -> dict:
        """Request reviewers for a PR."""
        result = await self._gh_api(
            f"/pulls/{pr_number}/requested_reviewers",
            "POST",
            {"reviewers": reviewers},
        )
        return result

    async def add_assignees(self, pr_number: int, assignees: list[str]) -> dict:
        """Add assignees to a PR."""
        result = await self._gh_api(
            f"/issues/{pr_number}/assignees",
            "POST",
            {"assignees": assignees},
        )
        return result

    async def enable_auto_merge(self, pr_number: int, merge_method: str = "squash") -> dict:
        """Enable auto-merge on a PR."""
        result = await self._gh_api(
            f"/pulls/{pr_number}/auto-merge",
            "PUT",
            {"merge_method": merge_method},
        )
        return result

    async def check_workflow_status(self, pr_number: int) -> dict:
        """Check the workflow/check status for a PR."""
        result = await self._gh_api(f"/pulls/{pr_number}/checks", "GET")
        return result

    async def create_remediation_prs(
        self,
        remediation_plan: RemediationPlan,
        config: PRConfig | None = None,
    ) -> list[dict[str, Any]]:
        """Create PRs for all groups in a remediation plan.

        Args:
            remediation_plan: The RemediationPlan with grouped updates.
            config: PR creation configuration.

        Returns:
            List of created PR info dicts.
        """
        config = config or PRConfig()
        created_prs = []

        for group in remediation_plan.groups:
            branch_name = f"remediate/{group.name}"

            # Create branch
            base_branch = config.base_branch
            try:
                await self.create_branch(branch_name, base_branch)
            except RuntimeError as e:
                if "Reference already exists" in str(e):
                    # Branch exists, continue
                    pass
                else:
                    raise

            # Generate PR description
            desc = PRDescription(group, self.repo, base_branch)
            body = desc.generate()
            title = f"{group.title} ({group.priority.title()})"

            # Create PR
            pr = await self.create_pr(
                title=title,
                body=body,
                head=branch_name,
                base=base_branch,
                draft=config.draft,
            )

            # Add labels
            all_labels = (config.labels or []) + group.labels
            await self.add_labels(pr["number"], all_labels)

            # Request reviewers
            if config.reviewers:
                await self.request_reviewers(pr["number"], config.reviewers)

            # Add assignees
            if config.assignees:
                await self.add_assignees(pr["number"], config.assignees)

            # Enable auto-merge if configured
            if config.auto_merge:
                await self.enable_auto_merge(pr["number"])

            created_prs.append(
                {
                    "group": group.name,
                    "priority": group.priority,
                    "pr_number": pr["number"],
                    "pr_url": pr["html_url"],
                    "title": pr["title"],
                    "branch": branch_name,
                }
            )

        return created_prs
