"""The release workflow's order: both platforms built and checked before anything is pushed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "release.yml"
PLATFORMS = ("amd64", "arm64")


@pytest.fixture(scope="module")
def steps() -> list[dict[str, Any]]:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = workflow["jobs"]["release"]["steps"]
    return found


def index(steps: list[dict[str, Any]], name: str) -> int:
    [position] = [i for i, s in enumerate(steps) if s.get("name") == name]
    return position


def test_each_platform_is_built_alone_and_loaded(steps: list[dict[str, Any]]) -> None:
    for arch in PLATFORMS:
        build = steps[index(steps, f"Build the gateway image ({arch})")]["with"]
        assert build["platforms"] == f"linux/{arch}"
        assert build["load"] is True
        assert build["push"] is False
        assert build["tags"].endswith(f"-{arch}")


def test_every_image_is_checked_before_the_registry_is_touched(
    steps: list[dict[str, Any]],
) -> None:
    check = index(steps, "Check both images")
    builds = [index(steps, f"Build the gateway image ({arch})") for arch in PLATFORMS]
    login = index(steps, "Log in to ghcr.io")
    push = index(steps, "Push")

    assert max(builds) < check < login < push
    script = steps[check]["run"]
    assert "for arch in amd64 arm64" in script
    for check_for in ("acp.mocks", "10001", "acp.__version__", ".Architecture"):
        assert check_for in script


def test_the_published_tags_join_the_checked_images(steps: list[dict[str, Any]]) -> None:
    script = steps[index(steps, "Push")]["run"]

    assert "imagetools create" in script
    for arch in PLATFORMS:
        assert f'docker push "${{IMAGE}}:${{VERSION}}-{arch}"' in script
    assert "buildx build" not in script, "a rebuild would publish an unchecked image"
    confirm = index(steps, "Confirm the published tag serves both platforms")
    assert confirm > index(steps, "Push")
