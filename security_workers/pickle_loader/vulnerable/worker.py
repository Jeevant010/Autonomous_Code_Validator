from __future__ import annotations

import pickle


def load_profile(payload: bytes) -> dict:
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
