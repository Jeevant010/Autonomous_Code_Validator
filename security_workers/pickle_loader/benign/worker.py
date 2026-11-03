from __future__ import annotations

import io
import pickle

_ALLOWED = frozenset(
    {
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "str"),
        ("builtins", "int"),
    }
)


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if (module, name) not in _ALLOWED:
            raise pickle.UnpicklingError(f"blocked class: {module}.{name}")
        return super().find_class(module, name)


def load_profile(payload: bytes) -> dict:
    data = RestrictedUnpickler(io.BytesIO(payload)).load()
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
