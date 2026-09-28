"""NumPy 1.x / 2.x pickle compatibility for model artifacts.

Model bundles (``*.pkl``) trained under NumPy 2.x reference the
``numpy._core`` module path, which does not exist under NumPy 1.x. A plain
``joblib.load`` then fails with ``ModuleNotFoundError: No module named
'numpy._core'``.

We deliberately do NOT alias ``sys.modules['numpy._core']``: injecting that
alias under NumPy 1.x corrupts the import state that scikit-learn's compiled
extensions rely on and segfaults the interpreter. Redirecting at unpickle
time via ``NumpyUnpickler.find_class`` is sufficient and safe.

Import this module (or call :func:`ensure_numpy2_pickle_compat`) from any
code path that unpickles model artifacts with joblib.
"""

from __future__ import annotations

import numpy


def ensure_numpy2_pickle_compat() -> bool:
    """Patch joblib's unpickler to resolve ``numpy._core`` on NumPy 1.x.

    Returns True if the patch was applied, False if not needed / unavailable.
    Idempotent: safe to call multiple times.
    """
    if not numpy.__version__.startswith("1."):
        return False
    try:
        import joblib.numpy_pickle
    except Exception:
        return False
    unpickler_cls = getattr(joblib.numpy_pickle, "NumpyUnpickler", None)
    if unpickler_cls is None:
        return False
    if getattr(unpickler_cls.find_class, "__numpy_compat_patched__", False):
        return True

    orig_find_class = unpickler_cls.find_class

    def _patched_find_class(self, module, name):
        if module and module.startswith("numpy._core"):
            module = module.replace("numpy._core", "numpy.core", 1)
        return orig_find_class(self, module, name)

    _patched_find_class.__numpy_compat_patched__ = True
    unpickler_cls.find_class = _patched_find_class
    return True


# Apply on import so every joblib.load in this process benefits.
ensure_numpy2_pickle_compat()
