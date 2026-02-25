"""Auto-discover and load the BlueSPY Python API.

Resolution order:
1. BLUESPY_API_PATH env var (explicit directory containing bluespy.py)
2. Platform-specific BlueSPY application install paths
3. Direct import (already on PYTHONPATH)
4. Bundled fallback (_vendor/bluespy.py)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import platform
import sys
from pathlib import Path
from types import ModuleType

logger = logging.getLogger(__name__)

_PLATFORM_PATHS: dict[str, list[str]] = {
    "Darwin": [
        "/Applications/blueSPY.app/Contents/Resources",
        "/Applications/blueSPY.app/Contents/Resources/python",
    ],
    "Windows": [
        r"C:\Program Files\blueSPY\python",
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "blueSPY", "python"),
    ],
    "Linux": [
        "/opt/bluespy/python",
        os.path.expanduser("~/.local/share/bluespy/python"),
    ],
}

# Cache the loaded module
_bluespy_module: ModuleType | None = None
_load_attempted: bool = False


def _load_module_from_path(directory: str | Path) -> ModuleType | None:
    """Load bluespy.py from a specific directory."""
    bluespy_file = Path(directory) / "bluespy.py"
    if not bluespy_file.is_file():
        return None

    spec = importlib.util.spec_from_file_location("bluespy", str(bluespy_file))
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    except (FileNotFoundError, OSError) as e:
        logger.debug(f"Found bluespy.py at {bluespy_file} but failed to load: {e}")
        return None


def _try_env_path() -> ModuleType | None:
    """Try BLUESPY_API_PATH environment variable."""
    env_path = os.environ.get("BLUESPY_API_PATH")
    if not env_path:
        return None

    logger.debug(f"Trying BLUESPY_API_PATH: {env_path}")
    module = _load_module_from_path(env_path)
    if module:
        logger.info(f"Loaded BlueSPY API from BLUESPY_API_PATH: {env_path}")
    return module


def _try_platform_paths() -> ModuleType | None:
    """Try platform-specific install paths."""
    system = platform.system()
    paths = _PLATFORM_PATHS.get(system, [])

    for search_path in paths:
        if not search_path:  # Skip empty paths (e.g., missing LOCALAPPDATA)
            continue
        logger.debug(f"Trying platform path: {search_path}")
        module = _load_module_from_path(search_path)
        if module:
            logger.info(f"Loaded BlueSPY API from platform path: {search_path}")
            return module
    return None


def _try_direct_import() -> ModuleType | None:
    """Try importing bluespy directly (already on PYTHONPATH)."""
    try:
        import bluespy
        logger.info("Loaded BlueSPY API from PYTHONPATH")
        return bluespy
    except (ImportError, FileNotFoundError, OSError):
        return None


def _try_vendor() -> ModuleType | None:
    """Try the bundled fallback in _vendor/."""
    vendor_dir = Path(__file__).parent / "_vendor"
    logger.debug(f"Trying bundled vendor: {vendor_dir}")
    module = _load_module_from_path(vendor_dir)
    if module:
        logger.warning(
            "Loaded BlueSPY API from bundled fallback. "
            "This may be outdated — install the BlueSPY application for the latest API."
        )
    return module


def discover_bluespy() -> ModuleType | None:
    """Discover and load the BlueSPY Python API.

    Tries multiple sources in priority order. Returns the loaded module
    or None if BlueSPY is not available.

    The result is cached — subsequent calls return the same module.
    """
    global _bluespy_module, _load_attempted

    if _load_attempted:
        return _bluespy_module

    _load_attempted = True

    for loader in [_try_env_path, _try_platform_paths, _try_direct_import, _try_vendor]:
        module = loader()
        if module is not None:
            _bluespy_module = module
            return module

    logger.warning(
        "BlueSPY API not found. Install the BlueSPY application from rfcreations.com "
        "or set BLUESPY_API_PATH to the directory containing bluespy.py"
    )
    return None


def get_bluespy() -> ModuleType:
    """Get the BlueSPY module, raising ImportError if unavailable.

    Use this in code that requires BlueSPY to function.
    """
    module = discover_bluespy()
    if module is None:
        raise ImportError(
            "BlueSPY library not available. Install the BlueSPY application "
            "from rfcreations.com and ensure BLUESPY_LIBRARY_PATH is set to "
            "the libblueSPY dylib/so/dll path."
        )
    return module


def reset_cache() -> None:
    """Reset the cached module (for testing)."""
    global _bluespy_module, _load_attempted
    _bluespy_module = None
    _load_attempted = False
