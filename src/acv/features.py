"""Feature switches for independently deployable parts of the console."""

from __future__ import annotations

import os


def _enabled(env_name: str, default: bool = True) -> bool:
    value = os.environ.get(env_name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def feature_flags() -> dict[str, bool]:
    """Return the features this process is allowed to expose.

    The flags are intentionally small and environment-driven so the UI and API
    can be deployed or tested without the guided view, task import, or repair
    module. The deterministic gate is not a feature flag; it is always present.
    """

    return {
        "guided_workflow": _enabled("ACV_FEATURE_GUIDE", True),
        "patch_preview": _enabled("ACV_FEATURE_PATCH_PREVIEW", True),
        "task_import": _enabled("ACV_FEATURE_TASK_IMPORT", True),
        "repair": _enabled("ACV_FEATURE_REPAIR", True),
        "project_verification": _enabled("ACV_FEATURE_PROJECTS", True),
        "project_run_log": _enabled("ACV_FEATURE_PROJECT_LOG", True),
    }
