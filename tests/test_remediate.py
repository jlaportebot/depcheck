"""Tests for the remediate command and PR automation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depcheck.github_pr import GitHubPRClient, PRConfig, PRDescription
from depcheck.remediate import (
    RemediationGroup,
    build_remediation_plan,
    group_by_priority,
)


class TestRemediationGroup:
    """Tests for RemediationGroup dataclass."""

    def test_create_group(self):
        group = RemediationGroup(
            name="security-fixes",
            title="Security Fixes",
            priority="critical",
            packages=["requests", "urllib3"],
            labels=["security", "automated"],
        )
        assert group.name == "security-fixes"
        assert group.priority == "critical"
        assert len(group.packages) == 2

    def test_to_dict(self):
        group = RemediationGroup(
            name="minor-updates",
            title="Minor Updates",
            priority="medium",
            packages=["click"],
            labels=["dependencies"],
        )
        d = group.to_dict()
        assert d["name"] == "minor-updates"
        assert d["priority"] == "medium"
        assert d["packages"] == ["click"]


class TestPRConfig:
    """Tests for PRConfig dataclass."""

    def test_default_config(self):
        config = PRConfig()
        assert config.base_branch == "main"
        assert config.auto_merge is False
        assert config.draft is False
        assert "automated" in config.labels
        assert "dependencies" in config.labels

    def test_custom_config(self):
        config = PRConfig(
            base_branch="develop",
            auto_merge=True,
            draft=True,
            labels=["custom", "bot"],
            reviewers=["user1", "user2"],
            assignees=["bot"],
        )
        assert config.base_branch == "develop"
        assert config.auto_merge is True
        assert config.draft is True
        assert config.labels == ["custom", "bot"]
        assert config.reviewers == ["user1", "user2"]
        assert config.assignees == ["bot"]


class TestGroupByPriority:
    """Tests for grouping update steps by priority."""

    def test_groups_critical_first(self):
        steps = [
            MagicMock(priority="critical", name="pkg1"),
            MagicMock(priority="high", name="pkg2"),
            MagicMock(priority="medium", name="pkg3"),
            MagicMock(priority="low", name="pkg4"),
            MagicMock(priority="deferred", name="pkg5"),
        ]
        groups = group_by_priority(steps)
        assert len(groups) == 5
        assert groups[0].priority == "critical"
        assert groups[1].priority == "high"
        assert groups[2].priority == "medium"
        assert groups[3].priority == "low"
        assert groups[4].priority == "deferred"

    def test_empty_list(self):
        assert group_by_priority([]) == []

    def test_single_priority(self):
        steps = [
            MagicMock(priority="low", name="a"),
            MagicMock(priority="low", name="b"),
        ]
        groups = group_by_priority(steps)
        assert len(groups) == 1
        assert groups[0].priority == "low"
        assert len(groups[0].packages) == 2


class TestBuildRemediationPlan:
    """Tests for building remediation plan from update plan."""

    def _make_update_plan(self, steps_data: list[dict]):
        from depcheck.outdated import RiskLevel, UpgradeLevel
        from depcheck.update import (
            UpdatePlan,
            UpdatePriority,
            UpdateStep,
            UpdateStrategy,
        )

        plan = UpdatePlan()
        for sd in steps_data:
            step = UpdateStep(
                name=sd["name"],
                current_version=sd["current"],
                target_version=sd["target"],
                priority=sd.get("priority", UpdatePriority.LOW),
                strategy=sd.get("strategy", UpdateStrategy.DIRECT),
                risk=sd.get("risk", RiskLevel.LOW),
                upgrade_level=sd.get("upgrade", UpgradeLevel.PATCH),
                command=sd.get("command", ""),
                rationale=sd.get("rationale", ""),
                changelog_url=sd.get("changelog"),
                days_behind=sd.get("days"),
                is_vulnerable=sd.get("vuln", False),
            )
            plan.steps.append(step)
            plan.needs_update_count += 1
            if step.priority == UpdatePriority.CRITICAL:
                plan.critical_count += 1
            elif step.priority == UpdatePriority.HIGH:
                plan.high_count += 1
            elif step.priority == UpdatePriority.MEDIUM:
                plan.medium_count += 1
            elif step.priority == UpdatePriority.LOW:
                plan.low_count += 1
            else:
                plan.deferred_count += 1
        return plan

    def test_build_plan_from_update_plan(self):
        update_plan = self._make_update_plan(
            [
                {
                    "name": "requests",
                    "current": "2.28.0",
                    "target": "2.31.0",
                    "priority": "critical",
                    "vuln": True,
                },
                {
                    "name": "click",
                    "current": "8.0.0",
                    "target": "8.1.0",
                    "priority": "medium",
                },
            ]
        )
        remediation = build_remediation_plan(update_plan, "test/repo")
        assert remediation.repository == "test/repo"
        assert len(remediation.groups) == 2
        assert remediation.groups[0].priority == "critical"
        assert "requests" in remediation.groups[0].packages
        assert remediation.groups[1].priority == "medium"
        assert "click" in remediation.groups[1].packages

    def test_plan_to_dict(self):
        update_plan = self._make_update_plan(
            [
                {
                    "name": "requests",
                    "current": "2.28.0",
                    "target": "2.31.0",
                    "priority": "critical",
                    "vuln": True,
                },
            ]
        )
        remediation = build_remediation_plan(update_plan, "owner/repo")
        d = remediation.to_dict()
        assert d["repository"] == "owner/repo"
        assert len(d["groups"]) == 1
        assert d["groups"][0]["name"] == "security-fixes"


class TestPRDescription:
    """Tests for PR description generation."""

    def test_generate_description(self):
        group = RemediationGroup(
            name="security-fixes",
            title="Critical Security Fixes",
            priority="critical",
            packages=["requests", "urllib3"],
            labels=["security", "automated", "dependencies"],
            step_details=[
                {
                    "name": "requests",
                    "current": "2.28.0",
                    "target": "2.31.0",
                    "command": "pip install --upgrade requests==2.31.0",
                    "rationale": "has known vulnerabilities; minor version upgrade",
                    "changelog_url": "https://github.com/psf/requests/releases",
                    "risk": "high",
                    "upgrade_level": "minor",
                    "days_behind": 180,
                    "is_vulnerable": True,
                },
                {
                    "name": "urllib3",
                    "current": "1.26.0",
                    "target": "2.0.0",
                    "command": "pip install --upgrade urllib3==2.0.0",
                    "rationale": "major version upgrade",
                    "changelog_url": "https://github.com/urllib3/urllib3/releases",
                    "risk": "high",
                    "upgrade_level": "major",
                    "days_behind": 365,
                    "is_vulnerable": False,
                },
            ],
        )
        desc = PRDescription(group, "owner/repo", "main")
        markdown = desc.generate()
        assert "Critical Security Fixes" in markdown
        assert "requests" in markdown
        assert "urllib3" in markdown
        assert "automates" in markdown.lower()  # "This PR automates..."
        assert "vulnerable" in markdown.lower()

    def test_description_includes_commands(self):
        group = RemediationGroup(
            name="minor-updates",
            title="Minor Updates",
            priority="medium",
            packages=["click"],
            labels=["dependencies"],
        )
        # Add step details
        group.step_details = [
            {
                "name": "click",
                "current": "8.0.0",
                "target": "8.1.0",
                "command": "pip install --upgrade click==8.1.0",
                "rationale": "minor version upgrade",
                "changelog_url": "https://example.com/changelog",
                "risk": "low",
            }
        ]
        desc = PRDescription(group, "owner/repo", "main")
        markdown = desc.generate()
        assert "click" in markdown
        assert "8.0.0" in markdown
        assert "8.1.0" in markdown
        assert "pip install" in markdown


class TestGitHubPRClient:
    """Tests for GitHub PR client."""

    @pytest.mark.asyncio
    async def test_create_branch(self):
        client = GitHubPRClient("token", "owner/repo")
        with patch.object(client, "_gh_api", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {
                "ref": "refs/heads/remediate/security-fixes",
                "object": {"sha": "abc123"},
            }
            ref = await client.create_branch("remediate/security-fixes", "main")
            assert ref == "refs/heads/remediate/security-fixes"

    @pytest.mark.asyncio
    async def test_create_pr(self):
        client = GitHubPRClient("token", "owner/repo")
        with patch.object(client, "_gh_api", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {
                "number": 42,
                "html_url": "https://github.com/owner/repo/pull/42",
                "title": "Security Fixes",
            }
            pr = await client.create_pr(
                title="Security Fixes",
                body="Description",
                head="remediate/security-fixes",
                base="main",
                draft=False,
            )
            assert pr["number"] == 42
            assert pr["html_url"] == "https://github.com/owner/repo/pull/42"

    @pytest.mark.asyncio
    async def test_add_labels(self):
        client = GitHubPRClient("token", "owner/repo")
        with patch.object(client, "_gh_api", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = [{"name": "security"}]
            labels = await client.add_labels(42, ["security", "automated"])
            assert len(labels) == 1

    @pytest.mark.asyncio
    async def test_request_reviewers(self):
        client = GitHubPRClient("token", "owner/repo")
        with patch.object(client, "_gh_api", new_callable=AsyncMock) as mock_api:
            mock_api.return_value = {}
            await client.request_reviewers(42, ["user1", "user2"])
            mock_api.assert_called()


class TestRemediationPlanIntegration:
    """Integration tests for remediation plan."""

    def test_full_plan_serialization(self):
        from depcheck.outdated import RiskLevel, UpgradeLevel
        from depcheck.update import (
            UpdatePlan,
            UpdatePriority,
            UpdateStep,
            UpdateStrategy,
        )

        plan = UpdatePlan(total_packages=5)
        step = UpdateStep(
            name="requests",
            current_version="2.28.0",
            target_version="2.31.0",
            priority=UpdatePriority.CRITICAL,
            strategy=UpdateStrategy.DIRECT,
            risk=RiskLevel.HIGH,
            upgrade_level=UpgradeLevel.MINOR,
            command="pip install --upgrade requests==2.31.0",
            rationale="has known vulnerabilities; minor version upgrade",
            changelog_url="https://github.com/psf/requests/releases",
            days_behind=180,
            is_vulnerable=True,
        )
        plan.steps = [step]
        plan.needs_update_count = 1
        plan.critical_count = 1

        remediation = build_remediation_plan(plan, "jlaportebot/depcheck")
        d = remediation.to_dict()

        assert d["repository"] == "jlaportebot/depcheck"
        assert len(d["groups"]) == 1
        group = d["groups"][0]
        assert group["name"] == "security-fixes"
        assert group["priority"] == "critical"
        assert "requests" in group["packages"]
        assert "changelog_url" in group["step_details"][0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
