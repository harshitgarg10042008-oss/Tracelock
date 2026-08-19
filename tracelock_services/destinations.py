"""Phase 4 destination registration and safe URL validation."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit


@dataclass(frozen=True, slots=True)
class RegisteredDestination:
    """Destination identity and transport constraints approved by an operator."""

    destination_id: str
    environment: str
    scheme: str
    host: str
    port: int
    allowed_paths: tuple[str, ...]
    require_tls: bool = True
    allow_redirects: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "destination_id": self.destination_id,
            "environment": self.environment,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "allowed_paths": list(self.allowed_paths),
            "require_tls": self.require_tls,
            "allow_redirects": self.allow_redirects,
        }


@dataclass(frozen=True, slots=True)
class DestinationValidation:
    """Privacy-safe result of validating a requested destination URL."""

    valid: bool
    reason_code: str
    destination_id: str | None = None
    canonical_url: str | None = None
    resolved_addresses: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason_code": self.reason_code,
            "destination_id": self.destination_id,
            "canonical_url": self.canonical_url,
            "resolved_addresses": list(self.resolved_addresses),
        }


Resolver = Callable[[str, int], list[str]]


class DestinationRegistry:
    """Validate outbound URLs against explicitly registered destinations."""

    def __init__(self, destinations: tuple[RegisteredDestination, ...] = ()) -> None:
        self._destinations = {item.destination_id: item for item in destinations}

    def register(self, destination: RegisteredDestination) -> None:
        self._destinations[destination.destination_id] = destination

    def get(self, destination_id: str) -> RegisteredDestination | None:
        return self._destinations.get(destination_id)

    def all(self) -> list[RegisteredDestination]:
        return list(self._destinations.values())

    def validate(
        self,
        *,
        destination_id: str,
        requested_url: str,
        resolver: Resolver | None = None,
    ) -> DestinationValidation:
        destination = self._destinations.get(destination_id)
        if destination is None:
            return DestinationValidation(False, "unregistered_destination")

        try:
            parsed = urlsplit(requested_url)
            structural_error = self._validate_structure(parsed, destination)
        except ValueError:
            return DestinationValidation(False, "malformed_destination_url", destination_id)
        if structural_error is not None:
            return DestinationValidation(False, structural_error, destination_id)

        resolve = resolver or self._resolve
        try:
            addresses = tuple(resolve(parsed.hostname or "", destination.port))
        except OSError:
            return DestinationValidation(False, "destination_resolution_failed", destination_id)

        if not addresses:
            return DestinationValidation(False, "destination_resolution_empty", destination_id)
        if any(self._is_private_or_special(address) for address in addresses):
            return DestinationValidation(False, "private_or_special_address", destination_id)

        canonical = self._canonical_url(parsed, destination)
        return DestinationValidation(True, "validated", destination_id, canonical, addresses)

    @staticmethod
    def _validate_structure(
        parsed: SplitResult,
        destination: RegisteredDestination,
    ) -> str | None:
        if parsed.scheme.lower() != destination.scheme.lower():
            return "scheme_mismatch"
        if destination.require_tls and parsed.scheme.lower() != "https":
            return "tls_required"
        if parsed.username or parsed.password:
            return "userinfo_not_allowed"
        if parsed.hostname is None:
            return "missing_host"
        if parsed.hostname.lower().rstrip(".") != destination.host.lower().rstrip("."):
            return "host_mismatch"
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        if (parsed.port or default_port) != destination.port:
            return "port_mismatch"
        if parsed.query or parsed.fragment:
            return "query_or_fragment_not_allowed"
        if parsed.path not in destination.allowed_paths:
            return "path_not_registered"
        return None

    @staticmethod
    def _canonical_url(parsed: SplitResult, destination: RegisteredDestination) -> str:
        return f"{parsed.scheme.lower()}://{destination.host.lower()}:{destination.port}{parsed.path}"

    @staticmethod
    def _resolve(host: str, port: int) -> list[str]:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(item[4][0]) for item in addresses})

    @staticmethod
    def _is_private_or_special(address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return True
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )
