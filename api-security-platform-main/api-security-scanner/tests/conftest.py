import warnings

import pytest

# Compatibility shim for loading model pickles that were created under NumPy 2.x
# (whose pickles reference ``numpy._core``) while running under NumPy 1.x.
# Lives in detection/numpy_compat.py so production code gets it too, not just tests.
from detection.numpy_compat import ensure_numpy2_pickle_compat

ensure_numpy2_pickle_compat()


def pytest_configure(config):
    # Suppress scikit-learn version unpickling warnings for legacy model bundles
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
    # Suppress pandas upcoming pyarrow requirement warning
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="pandas")
