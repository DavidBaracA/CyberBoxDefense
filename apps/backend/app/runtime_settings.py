"""Small repo-local runtime settings loader for backend defaults.

Environment variables still take precedence, but this lets local development
use a checked-in JSON config file instead of requiring repeated shell exports.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "runtime_settings.json"


@lru_cache(maxsize=1)
def load_runtime_settings() -> dict[str, Any]:
    """Load runtime settings from the backend config file if it exists."""

    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def get_runtime_setting(name: str, default: Any) -> Any:
    """Return one runtime setting, preferring env vars over config file."""

    env_value = os.getenv(name)
    if env_value is not None:
        return env_value
    return load_runtime_settings().get(name, default)


def get_runtime_bool(name: str, default: bool) -> bool:
    """Return one boolean runtime setting from env/config/default."""

    value = get_runtime_setting(name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def get_runtime_float(name: str, default: float) -> float:
    """Return one float runtime setting from env/config/default."""

    value = get_runtime_setting(name, default)
    return float(value)
