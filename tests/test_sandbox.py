"""Sandbox isolation. Skipped unless Docker and the sandbox image are present.

Builds nothing. When they are present, asserts the image runs and that a
``--network none`` container cannot reach the network.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from redforge.config import settings
from redforge.sandbox import SandboxRunner

pytestmark = pytest.mark.sandbox

_DOCKER_TIMEOUT_S = 20
_CURL_NETWORK_ERRORS = (
    "Could not resolve host",
    "Couldn't resolve host",
    "Failed to connect",
    "Couldn't connect to server",
    "Network is unreachable",
    "Network unreachable",
    "Operation timed out",
)


def _unavailable_reason() -> str | None:
    if shutil.which("docker") is None:
        return "docker CLI not on PATH"
    try:
        info = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "docker daemon not available"
    if info.returncode != 0:
        return "docker daemon not available"
    image = settings.sandbox_image
    try:
        inspect = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return f"could not inspect sandbox image {image}"
    if inspect.returncode != 0:
        return f"sandbox image {image} not present (this test does not build it)"
    return None


@pytest.fixture(autouse=True)
def _require_sandbox() -> None:
    reason = _unavailable_reason()
    if reason is not None:
        pytest.skip(reason)


def test_self_check_when_docker_present() -> None:
    assert SandboxRunner().self_check() is True


def test_network_none_cannot_reach_example_com() -> None:
    runner = SandboxRunner(network="none")
    with tempfile.TemporaryDirectory() as ro, tempfile.TemporaryDirectory() as rw:
        res = runner.run("curl -m 3 -fsS https://example.com", Path(ro), Path(rw))
    output = res.stdout + res.stderr
    assert not res.timed_out
    assert res.exit_code not in (0, 127)
    assert "Example Domain" not in output
    assert any(msg in output for msg in _CURL_NETWORK_ERRORS)
