from __future__ import annotations

import pickle


def load_profile(payload: bytes) -> dict:
    if len(payload) > 4096:
        raise ValueError("profile too large")
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
