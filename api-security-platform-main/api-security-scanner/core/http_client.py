"""Shared httpx client construction for the scanner.

Centralises the workaround for malformed ambient proxy configuration so every
network-touching component (request engine, endpoint discovery, ...) degrades
gracefully instead of turning all requests into silent ``status_code: 0``
failures.
"""
from typing import Any, Dict

import httpx

from config.logging_config import logger


def build_client(client_cls=httpx.Client, **kwargs):
    """
    Build an httpx client that degrades gracefully when the ambient proxy
    configuration is malformed.

    httpx reads proxy settings from the environment by default (trust_env=True).
    A malformed entry (e.g. a bare IPv6 address in ``no_proxy``) makes client
    construction raise, which would otherwise turn *every* scan request into a
    failure that is indistinguishable from a dead target. In that case we fall
    back to ignoring the environment's proxy config and log a clear warning
    instead of failing silently.

    Pass ``trust_env=False`` explicitly to always skip environment proxies.
    """
    try:
        return client_cls(**kwargs)
    except Exception as exc:  # noqa: BLE001 - proxy env parsing can raise many types
        logger.warning(
            "Ignoring malformed proxy environment configuration (%s); "
            "continuing with direct connections.",
            exc,
        )
        kwargs["trust_env"] = False
        return client_cls(**kwargs)


def client_kwargs(timeout: float, follow_redirects: bool = True, trust_env: bool = True) -> Dict[str, Any]:
    """Standard keyword arguments for scanner HTTP clients."""
    return {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        "trust_env": trust_env,
    }
