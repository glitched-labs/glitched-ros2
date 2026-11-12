"""Shared local storage paths; no ROS dependency."""

import os
from pathlib import Path


def state_directory(value=None):
    """Resolve an explicit directory, or the XDG state directory."""
    if value:
        return Path(value).expanduser().resolve()
    base = Path(os.environ.get("XDG_STATE_HOME", "~/.local/state")).expanduser()
    return (base / "glitched").resolve()
