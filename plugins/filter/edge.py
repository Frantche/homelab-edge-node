"""Filters used by the homelab edge collection."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ansible.errors import AnsibleFilterError

PORT_RANGE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
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


def _service_dns(value: Any, service_name: str, destination_host: str, mode: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not value:
        raise AnsibleFilterError(f"{service_name}: dns must be a non-empty mapping")
    unknown = set(value) - {"local", "cloudflare"}
    if unknown:
        raise AnsibleFilterError(f"{service_name}: unsupported dns provider settings: {sorted(unknown)}")

    normalized: dict[str, Any] = {}
    local = value.get("local")
    if local is not None:
        if not isinstance(local, dict):
            raise AnsibleFilterError(f"{service_name}: dns.local must be a mapping")
        unknown = set(local) - {"enabled", "address"}
        if unknown:
            raise AnsibleFilterError(f"{service_name}: unsupported dns.local settings: {sorted(unknown)}")
        enabled = local.get("enabled")
        if not isinstance(enabled, bool):
            raise AnsibleFilterError(f"{service_name}: dns.local.enabled must be a boolean")
        record: dict[str, Any] = {"enabled": enabled}
        address = local.get("address")
        if enabled:
            address = destination_host if address is None else address
            if not isinstance(address, str):
                raise AnsibleFilterError(f"{service_name}: dns.local.address must be an IP address string")
            try:
                ip = ipaddress.ip_address(address)
            except (TypeError, ValueError) as exc:
                raise AnsibleFilterError(f"{service_name}: dns.local.address must be an IP address") from exc
            if not ip.is_private:
                raise AnsibleFilterError(f"{service_name}: dns.local.address must be a private IP address")
            record["address"] = str(ip)
        elif address is not None:
            raise AnsibleFilterError(f"{service_name}: dns.local.address requires dns.local.enabled=true")
        normalized["local"] = record

    cloudflare = value.get("cloudflare")
    if cloudflare is not None:
        if not isinstance(cloudflare, dict):
            raise AnsibleFilterError(f"{service_name}: dns.cloudflare must be a mapping")
        unknown = set(cloudflare) - {"enabled", "ipv4", "ipv6", "adopt_existing"}
        if unknown:
            raise AnsibleFilterError(f"{service_name}: unsupported dns.cloudflare settings: {sorted(unknown)}")
        if mode == "cloudflare-tunnel":
            raise AnsibleFilterError(f"{service_name}: dns.cloudflare is only valid for direct routes")
        enabled = cloudflare.get("enabled")
        if not isinstance(enabled, bool):
            raise AnsibleFilterError(f"{service_name}: dns.cloudflare.enabled must be a boolean")
        record = {"enabled": enabled}
        for family in ("ipv4", "ipv6"):
            address = cloudflare.get(family)
            if address is None:
                continue
            if not isinstance(address, str):
                raise AnsibleFilterError(f"{service_name}: dns.cloudflare.{family} must be an IP address string")
            try:
                ip = ipaddress.ip_address(address)
            except (TypeError, ValueError) as exc:
                raise AnsibleFilterError(f"{service_name}: dns.cloudflare.{family} must be an IP address") from exc
            if (family == "ipv4") != (ip.version == 4):
                raise AnsibleFilterError(f"{service_name}: dns.cloudflare.{family} has the wrong IP version")
            if not enabled:
                raise AnsibleFilterError(
                    f"{service_name}: dns.cloudflare.{family} requires dns.cloudflare.enabled=true"
                )
            record[family] = str(ip)
        adopt_existing = cloudflare.get("adopt_existing", False)
        if not isinstance(adopt_existing, bool):
            raise AnsibleFilterError(f"{service_name}: dns.cloudflare.adopt_existing must be a boolean")
        if adopt_existing and not enabled:
            raise AnsibleFilterError(
                f"{service_name}: dns.cloudflare.adopt_existing requires dns.cloudflare.enabled=true"
            )
        record["adoptExisting"] = adopt_existing
        normalized["cloudflare"] = record

    if not normalized:
        raise AnsibleFilterError(f"{service_name}: dns must define local or cloudflare settings")
    return normalized


def normalize_services(services: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(services, dict):
        raise AnsibleFilterError("edge_services must be a mapping")
    normalized: dict[str, dict[str, Any]] = {}
    used_hosts: set[str] = set()
    raw_listeners: dict[tuple[str, int], str] = {}
    http_ports: set[int] = set()
    http_port_policies: dict[int, tuple[str, ...]] = {}
    for name, raw in services.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,49}", name):
            raise AnsibleFilterError(f"invalid service name {name!r}")
        if not isinstance(raw, dict):
            raise AnsibleFilterError(f"{name}: service definition must be a mapping")
        exposure = raw.get("exposure")
        if exposure not in {"http", "https", "tcp", "tls-passthrough"}:
            raise AnsibleFilterError(f"{name}: exposure must be http, https, tcp or tls-passthrough")
        mode = raw.get("mode", "direct")
        if mode not in {"direct", "cloudflare-tunnel"}:
            raise AnsibleFilterError(f"{name}: mode must be direct or cloudflare-tunnel")
        listen = raw.get("listen", {})
        ports = _ports(listen.get("ports"), name)
        if exposure == "tcp" and mode != "direct":
            raise AnsibleFilterError(f"{name}: TCP services support direct exposure only")
        if exposure == "tls-passthrough" and mode != "direct":
            raise AnsibleFilterError(f"{name}: TLS passthrough services support direct exposure only")
        if exposure == "tcp" and 443 in ports:
            raise AnsibleFilterError(f"{name}: TCP exposure on port 443 is not supported")
        if mode == "cloudflare-tunnel" and ports != [443]:
            raise AnsibleFilterError(f"{name}: Cloudflare Tunnel HTTP services must use public port 443")
        destination = raw.get("destination", {})
        host = destination.get("host")
        port = destination.get("port")
        if not isinstance(host, str) or not host:
            raise AnsibleFilterError(f"{name}: destination.host is required")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AnsibleFilterError(f"{name}: destination.port must be between 1 and 65535")
        protocol = destination.get(
            "protocol",
            "http" if exposure in {"http", "https"} else "tcp" if exposure == "tls-passthrough" else exposure,
        )
        allowed_protocols = (
            {"http", "https"}
            if exposure in {"http", "https"}
            else {"tcp"}
            if exposure == "tls-passthrough"
            else {exposure}
        )
        if protocol not in allowed_protocols:
            raise AnsibleFilterError(f"{name}: destination protocol is incompatible with {exposure}")
        proxy_protocol_version = destination.get("proxy_protocol_version")
        if proxy_protocol_version is not None:
            if (
                exposure != "tcp"
                or isinstance(proxy_protocol_version, bool)
                or not isinstance(proxy_protocol_version, int)
                or proxy_protocol_version not in {1, 2}
            ):
                raise AnsibleFilterError(
                    f"{name}: destination.proxy_protocol_version is only valid for TCP services "
                    "and must be 1 or 2"
                )
        hostname = raw.get("hostname")
        if exposure in {"http", "https", "tls-passthrough"}:
            if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
                raise AnsibleFilterError(f"{name}: a valid hostname is required for HTTP and TLS services")
            hostname = hostname.lower()
            if hostname in used_hosts:
                raise AnsibleFilterError(f"{name}: duplicate hostname {hostname}")
            used_hosts.add(hostname)
        dns = _service_dns(raw.get("dns"), name, host, mode)
        if exposure == "tcp":
            dns_enabled = any(settings["enabled"] for settings in (dns or {}).values())
            if hostname is None and dns_enabled:
                raise AnsibleFilterError(f"{name}: hostname is required when DNS publication is enabled")
            if hostname is not None:
                if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname) or hostname.startswith("*."):
                    raise AnsibleFilterError(f"{name}: a valid non-wildcard hostname is required for TCP DNS")
                if not dns_enabled:
                    raise AnsibleFilterError(f"{name}: TCP hostname requires an enabled DNS provider")
                hostname = hostname.lower()
                if hostname in used_hosts:
                    raise AnsibleFilterError(f"{name}: duplicate hostname {hostname}")
                used_hosts.add(hostname)
        source_cidrs = listen.get("source_cidrs", [])
        if not isinstance(source_cidrs, list):
            raise AnsibleFilterError(f"{name}: listen.source_cidrs must be a list")
        try:
            source_cidrs = [str(ipaddress.ip_network(cidr, strict=False)) for cidr in source_cidrs]
        except (TypeError, ValueError) as exc:
            raise AnsibleFilterError(f"{name}: invalid source CIDR: {exc}") from exc
        if mode == "cloudflare-tunnel" and source_cidrs:
            raise AnsibleFilterError(f"{name}: listen.source_cidrs are supported only for direct routes")
        listener_protocol = "tcp"
        if exposure in {"http", "https", "tls-passthrough"}:
            if mode == "direct":
                http_ports.update(ports)
                policy = tuple(sorted(source_cidrs))
                for public_port in ports:
                    previous_policy = http_port_policies.setdefault(public_port, policy)
                    if previous_policy != policy:
                        raise AnsibleFilterError(
                            f"{name}: HTTP services sharing tcp/{public_port} must use identical source CIDRs"
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
            "mode": mode,
            "hostname": hostname,
            "ports": ports,
            "source_cidrs": source_cidrs,
            "dns": dns,
            "destination": {
                "host": host,
                "port": port,
                "protocol": protocol,
                "proxy_protocol_version": proxy_protocol_version,
            },
        }
    for public_port in http_ports:
        conflict = raw_listeners.get(("tcp", public_port))
        if conflict:
            raise AnsibleFilterError(
                f"HTTP or TLS listener tcp/{public_port} conflicts with raw TCP service {conflict}"
            )
    return normalized


def fixed_snapshot(services: Any) -> dict[str, Any]:
    exposures = []
    for name, service in normalize_services(services).items():
        for port in service["ports"]:
            exposure = {
                "id": f"{name}-{port}",
                "protocol": (
                    "http"
                    if service["exposure"] in {"http", "https"}
                    else "tls"
                    if service["exposure"] == "tls-passthrough"
                    else "tcp"
                ),
                "mode": service["mode"],
                "listenPort": port,
                "targetHost": service["destination"]["host"],
                "targetPort": service["destination"]["port"],
                "sourceCIDRs": service["source_cidrs"],
            }
            if service["hostname"] is not None:
                exposure["hostname"] = service["hostname"]
            if service["dns"] is not None:
                exposure["dns"] = service["dns"]
            if service["exposure"] == "https" and service["mode"] == "direct":
                exposure["tls"] = True
            if service["destination"]["protocol"] == "https":
                exposure["targetTLS"] = True
            if service["destination"]["proxy_protocol_version"] is not None:
                exposure["proxyProtocolVersion"] = service["destination"]["proxy_protocol_version"]
            exposures.append(exposure)
    return {"generation": 1, "exposures": exposures}


class FilterModule:
    """Ansible filter registration."""

    def filters(self) -> dict[str, Any]:
        return {"normalize_services": normalize_services, "fixed_snapshot": fixed_snapshot}
