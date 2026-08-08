"""Filters used by the homelab edge collection."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ansible.errors import AnsibleFilterError

PORT_RANGE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _ports(value: Any, service_name: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise AnsibleFilterError(f"{service_name}: listen.ports must be a non-empty list")
    result: list[int] = []
    for item in value:
        if isinstance(item, int):
            start = end = item
        elif isinstance(item, str) and (match := PORT_RANGE.fullmatch(item)):
            start, end = (int(match.group(1)), int(match.group(2)))
        else:
            raise AnsibleFilterError(f"{service_name}: invalid port or range {item!r}")
        if start < 1 or end > 65535 or start > end:
            raise AnsibleFilterError(f"{service_name}: invalid port range {item!r}")
        if end - start > 1023:
            raise AnsibleFilterError(f"{service_name}: port ranges are limited to 1024 ports")
        result.extend(range(start, end + 1))
    return sorted(set(result))


def normalize_services(services: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(services, dict):
        raise AnsibleFilterError("edge_services must be a mapping")
    normalized: dict[str, dict[str, Any]] = {}
    used_hosts: set[str] = set()
    raw_listeners: dict[tuple[str, int], str] = {}
    https_ports: set[int] = set()
    https_port_policies: dict[int, tuple[str, ...]] = {}
    for name, raw in services.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise AnsibleFilterError(f"invalid service name {name!r}")
        if not isinstance(raw, dict):
            raise AnsibleFilterError(f"{name}: service definition must be a mapping")
        exposure = raw.get("exposure")
        if exposure not in {"https", "tcp", "udp"}:
            raise AnsibleFilterError(f"{name}: exposure must be https, tcp or udp")
        listen = raw.get("listen", {})
        ports = _ports(listen.get("ports"), name)
        destination = raw.get("destination", {})
        host = destination.get("host")
        port = destination.get("port")
        if not isinstance(host, str) or not host:
            raise AnsibleFilterError(f"{name}: destination.host is required")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AnsibleFilterError(f"{name}: destination.port must be between 1 and 65535")
        protocol = destination.get("protocol", "http" if exposure == "https" else exposure)
        allowed_protocols = {"http", "https"} if exposure == "https" else {exposure}
        if protocol not in allowed_protocols:
            raise AnsibleFilterError(f"{name}: destination protocol is incompatible with {exposure}")
        hostname = raw.get("hostname")
        if exposure == "https":
            if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
                raise AnsibleFilterError(f"{name}: a valid hostname is required for HTTPS")
            hostname = hostname.lower()
            if hostname in used_hosts:
                raise AnsibleFilterError(f"{name}: duplicate HTTPS hostname {hostname}")
            used_hosts.add(hostname)
        elif hostname is not None:
            raise AnsibleFilterError(f"{name}: hostname is only valid for HTTPS services")
        source_cidrs = listen.get("source_cidrs", [])
        if not isinstance(source_cidrs, list):
            raise AnsibleFilterError(f"{name}: listen.source_cidrs must be a list")
        try:
            source_cidrs = [str(ipaddress.ip_network(cidr, strict=False)) for cidr in source_cidrs]
        except (TypeError, ValueError) as exc:
            raise AnsibleFilterError(f"{name}: invalid source CIDR: {exc}") from exc
        listener_protocol = "udp" if exposure == "udp" else "tcp"
        if exposure == "https":
            https_ports.update(ports)
            policy = tuple(sorted(source_cidrs))
            for public_port in ports:
                previous_policy = https_port_policies.setdefault(public_port, policy)
                if previous_policy != policy:
                    raise AnsibleFilterError(
                        f"{name}: HTTPS services sharing tcp/{public_port} must use identical source CIDRs"
                    )
        else:
            for public_port in ports:
                key = (listener_protocol, public_port)
                if key in raw_listeners:
                    raise AnsibleFilterError(
                        f"{name}: listener {listener_protocol}/{public_port} conflicts with "
                        f"{raw_listeners[key]}"
                    )
                raw_listeners[key] = name
        normalized[name] = {
            "exposure": exposure,
            "hostname": hostname,
            "ports": ports,
            "source_cidrs": source_cidrs,
            "destination": {"host": host, "port": port, "protocol": protocol},
        }
    for public_port in https_ports:
        conflict = raw_listeners.get(("tcp", public_port))
        if conflict:
            raise AnsibleFilterError(
                f"HTTPS listener tcp/{public_port} conflicts with raw TCP service {conflict}"
            )
    return normalized


class FilterModule:
    """Ansible filter registration."""

    def filters(self) -> dict[str, Any]:
        return {"normalize_services": normalize_services}
