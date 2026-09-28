import warnings

import numpy
import pytest

# Compatibility shim for loading model pickles that were created under NumPy 2.x
# (whose pickles reference ``numpy._core``) while running under NumPy 1.x.
#
# NOTE: We deliberately do NOT alias ``sys.modules['numpy._core']``. Injecting
# that alias under NumPy 1.x corrupts the import state that scikit-learn's
# compiled extensions rely on and segfaults the interpreter. Redirecting at
# unpickle time via ``find_class`` is sufficient and safe.
if numpy.__version__.startswith("1."):
    try:
        import joblib.numpy_pickle

        if hasattr(joblib.numpy_pickle, "NumpyUnpickler"):
            _orig_find_class = joblib.numpy_pickle.NumpyUnpickler.find_class

            def _patched_find_class(self, module, name):
                if module and module.startswith("numpy._core"):
                    module = module.replace("numpy._core", "numpy.core", 1)
                return _orig_find_class(self, module, name)

            joblib.numpy_pickle.NumpyUnpickler.find_class = _patched_find_class
    except Exception:
        # The shim is best-effort; model loading must never break test collection.
        pass


def pytest_configure(config):
    # Suppress scikit-learn version unpickling warnings for legacy model bundles
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
    # Suppress pandas upcoming pyarrow requirement warning
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="pandas")
