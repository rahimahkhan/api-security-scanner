"""Target URL validation + SSRF guard.

Moved here from main.py so both the scan entry points (main.py,
dashboard/routes.py) and the request engine (core/request_engine.py —
which must re-validate every redirect target server-side) share one
implementation. There is exactly one definition of the SSRF policy.
"""

import os
import re
import urllib.parse
from typing import Any

from config.logging_config import logger


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def private_targets_allowed() -> bool:
    """Lab-mode override: ALLOW_PRIVATE_SCAN_TARGETS=1 permits private hosts.

    Same semantics everywhere the SSRF policy is enforced — never enabled on
    the deployed service.
    """
    return os.getenv("ALLOW_PRIVATE_SCAN_TARGETS", "0").lower() in {"1", "true", "yes", "on"}


def _host_resolves_to_public_ip(host: str) -> bool:
    """SSRF guard: reject targets pointing at private/internal networks.

    Scans run server-side, so a target like http://169.254.169.254/ (cloud
    instance metadata) or http://localhost/ would turn the scanner into a
    proxy into the host's private network. Literal IPs are checked directly;
    hostnames are resolved and every resolved address must be public.
    A DNS failure is not treated as private (the request itself will fail
    naturally); only positively-private addresses are rejected.
    """
    import ipaddress
    import socket

    def _is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified

    # Literal IP literal (brackets already stripped by urlparse's hostname).
    try:
        ipaddress.ip_address(host)
        return not _is_private_ip(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return True
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return True
    return not any(_is_private_ip(addr) for addr in addresses)


def validate_target_url(target_url: Any) -> "tuple[bool, str]":
    """Validate a scan target. Returns (True, normalized_url) or (False, reason).

    Rejects payload-looking junk (e.g. "<script>alert(1)</script>",
    "; cat /etc/passwd") that previously created garbage scan sessions.
    """
    if not isinstance(target_url, str):
        return False, "target URL must be a string"
    candidate = target_url.strip()
    if not candidate:
        return False, "target URL is empty"
    if len(candidate) > 2048:
        return False, "target URL is too long"
    if any(ch in candidate for ch in "<>\"' \t\r\n\\"):
        return False, "target URL contains illegal characters"
    try:
        parsed = urllib.parse.urlparse(candidate)
    except ValueError as exc:
        return False, f"target URL could not be parsed: {exc}"
    if parsed.scheme not in ("http", "https"):
        return False, "target URL must start with http:// or https://"
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "target URL must include a host name"
    is_ipv6 = host.startswith("[") or ":" in host
    if not (is_ipv6 or _IPV4_RE.match(host) or _HOSTNAME_RE.match(host)):
        return False, "target URL host name looks invalid"
    if _IPV4_RE.match(host) and not all(0 <= int(o) <= 255 for o in host.split(".")):
        return False, "target URL IPv4 address is invalid"
    # Env override for local lab testing (e.g. scanning a localhost target
    # from the CLI). Never set this on the deployed service.
    if not private_targets_allowed():
        if not _host_resolves_to_public_ip(host):
            return False, "target URL resolves to a private or internal address; only public targets can be scanned"
    return True, candidate


def validate_redirect_target(current_url: str, location: str) -> "tuple[bool, str, str]":
    """Resolve a redirect Location against the current URL and SSRF-validate it.

    Returns (ok, target_url, reason): (True, absolute_url, "") when the
    redirect is safe to follow, (False, attempted_url, reason) when it must
    be refused (private/internal target, bad scheme, unparsable, ...).
    """
    from urllib.parse import urljoin

    if not location:
        return False, "", "empty redirect location"
    try:
        next_url = urljoin(current_url, location)
    except Exception:
        return False, location, "unparseable redirect location"
    valid, normalized_or_reason = validate_target_url(next_url)
    if not valid:
        logger.warning(
            "SSRF guard: refusing to follow redirect %r -> %r: %s",
            current_url, next_url, normalized_or_reason,
        )
        return False, next_url, normalized_or_reason
    return True, normalized_or_reason, ""
