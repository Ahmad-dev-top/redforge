"""Clone a target repository safely.

We shallow-clone into a per-run work directory. The clone happens on the host
(git is trusted); ALL execution of the cloned code happens later inside the
sandbox. We validate the URL is a plausible git host and never clone
submodules automatically (a hostile repo could point a submodule anywhere).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from redforge.config import settings
from redforge.logging_conf import get_logger

log = get_logger("cloner")

_ALLOWED_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")
_URL_RE = re.compile(r"^https://([^/]+)/[\w.\-]+/[\w.\-]+(?:\.git)?/?$")


class RepoCloneError(RuntimeError):
    pass


def validate_url(url: str) -> str:
    m = _URL_RE.match(url.strip())
    if not m:
        raise RepoCloneError(f"URL not accepted: {url!r}")
    host = m.group(1)
    if host not in _ALLOWED_HOSTS:
        raise RepoCloneError(f"host not allowed: {host}")
    return url.strip()


def clone_repo(url: str, run_id: str) -> Path:
    url = validate_url(url)
    dest = settings.work_root / run_id / "repo"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        log.info("repo already cloned at %s", dest)
        return dest
    log.info("cloning %s -> %s", url, dest)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--no-recurse-submodules", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.CalledProcessError as exc:
        raise RepoCloneError(exc.stderr.strip() or "git clone failed") from exc
    return dest
