from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.safe_load(payload)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
