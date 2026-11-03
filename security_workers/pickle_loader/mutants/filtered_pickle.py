from __future__ import annotations

import pickle
import re


def load_profile(payload: bytes) -> dict:
    if re.search(rb"os|system|subprocess", payload):
        raise ValueError("blocked")
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
