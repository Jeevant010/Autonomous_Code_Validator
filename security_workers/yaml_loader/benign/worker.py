from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.load(payload, Loader=yaml.SafeLoader)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
