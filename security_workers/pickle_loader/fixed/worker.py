from __future__ import annotations

import io
import pickle

ALLOWED = {
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "str"),
    ("builtins", "int"),
}


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if (module, name) in ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked class: {module}.{name}")


def load_profile(payload: bytes) -> dict:
    data = SafeUnpickler(io.BytesIO(payload)).load()
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
