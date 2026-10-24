"""Outbound network policy for server-side probes.

The scanner accepts user-controlled targets, so URL scope checks alone are not
enough: a public-looking hostname can resolve to loopback, RFC1918, link-local,
or cloud metadata addresses.  Every direct network client calls this module
immediately before opening a socket.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit


class NetworkSafetyError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    parsed: SplitResult
    host: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class HTTPResult:
    status: int
    body: bytes
    headers: dict[str, str]


def _private_targets_allowed() -> bool:
    """Explicit local-runtime escape hatch; never enabled by default."""
    return (os.environ.get("VIBE_AGENT_ALLOW_PRIVATE_TARGETS") or "").strip().lower() in {
        "1", "true", "yes",
    }


def _canonical_host(host: str) -> str:
    value = (host or "").strip().rstrip(".")
    if not value or "%" in value:
        raise NetworkSafetyError("invalid target hostname")
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NetworkSafetyError("invalid target hostname") from exc


def _resolved_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise NetworkSafetyError("target hostname could not be resolved") from exc
        values = sorted({row[4][0].split("%", 1)[0] for row in rows if row[4]})
        if not values:
            raise NetworkSafetyError("target hostname resolved to no addresses")
        return tuple(values)
    return (str(literal),)


def validate_outbound_url(
    url: str,
    *,
    expected_host: str | None = None,
    require_https: bool = False,
) -> ValidatedURL:
    """Validate scheme, authority, exact host, and resolved address class."""
    try:
        parsed = urlsplit((url or "").strip())
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise NetworkSafetyError("invalid target URL") from exc

    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise NetworkSafetyError("target URL must use HTTP or HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise NetworkSafetyError("target URL must have a hostname and no embedded credentials")

    host = _canonical_host(parsed.hostname)
    if expected_host and host != _canonical_host(expected_host):
        raise NetworkSafetyError("redirect or request escaped the exact authorized hostname")

    resolved = _resolved_addresses(host, port or (443 if parsed.scheme.lower() == "https" else 80))
    if not _private_targets_allowed():
        for raw in resolved:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise NetworkSafetyError("target resolved to an invalid address") from exc
            if not address.is_global:
                raise NetworkSafetyError("private, loopback, link-local, reserved, and metadata targets are blocked")

    return ValidatedURL(url=url, parsed=parsed, host=host, addresses=resolved)


def request_url(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    timeout: float = 12,
    max_bytes: int = 200_000,
    expected_host: str | None = None,
    require_https: bool = False,
) -> HTTPResult:
    """Request a URL through a socket pinned to a validated DNS answer."""
    method = (method or "GET").upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise NetworkSafetyError("outbound method is not permitted")
    if max_bytes < 0 or max_bytes > 10 * 1024 * 1024:
        raise NetworkSafetyError("invalid outbound response limit")

    checked = validate_outbound_url(
        url,
        expected_host=expected_host,
        require_https=require_https,
    )
    parsed = checked.parsed
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))

    host_header = f"[{checked.host}]" if ":" in checked.host else checked.host
    if port != (443 if scheme == "https" else 80):
        host_header += f":{port}"
    request_headers = {
        key: str(value)
        for key, value in (headers or {}).items()
        if key.lower() not in {"host", "connection"}
    }
    request_headers["Host"] = host_header
    request_headers["Connection"] = "close"

    last_error: Exception | None = None
    for address in checked.addresses:
        raw_sock = None
        conn = None
        try:
            raw_sock = socket.create_connection((address, port), timeout=timeout)
            sock = raw_sock
            if scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(raw_sock, server_hostname=checked.host)
                raw_sock = None

            conn = http.client.HTTPConnection(checked.host, port=port, timeout=timeout)
            conn.sock = sock
            conn.request(method, path, headers=request_headers)
            response = conn.getresponse()
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise NetworkSafetyError("target response exceeded the configured limit")
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            return HTTPResult(status=response.status, body=body, headers=response_headers)
        except NetworkSafetyError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if conn is not None:
                conn.close()
            elif raw_sock is not None:
                raw_sock.close()

    raise NetworkSafetyError("target could not be reached") from last_error
