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


def _normalize_listener(service_name: str, raw: Any, mode: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AnsibleFilterError(f"{service_name}: listener definition must be a mapping")
    exposure = raw.get("exposure")
    if exposure not in {"http", "https", "tcp", "tls-passthrough"}:
        raise AnsibleFilterError(f"{service_name}: exposure must be http, https, tcp or tls-passthrough")
    listen = raw.get("listen", {})
    if not isinstance(listen, dict):
        raise AnsibleFilterError(f"{service_name}: listen must be a mapping")
    ports = _ports(listen.get("ports"), service_name)
    if exposure == "tcp" and mode != "direct":
        raise AnsibleFilterError(f"{service_name}: TCP services support direct exposure only")
    if exposure == "tls-passthrough" and mode != "direct":
        raise AnsibleFilterError(f"{service_name}: TLS passthrough services support direct exposure only")
    if exposure == "tcp" and 443 in ports:
        raise AnsibleFilterError(f"{service_name}: TCP exposure on port 443 is not supported")
    if mode == "cloudflare-tunnel" and ports != [443]:
        raise AnsibleFilterError(f"{service_name}: Cloudflare Tunnel HTTP services must use public port 443")
    destination = raw.get("destination", {})
    if not isinstance(destination, dict):
        raise AnsibleFilterError(f"{service_name}: destination must be a mapping")
    host = destination.get("host")
    port = destination.get("port")
    if not isinstance(host, str) or not host:
        raise AnsibleFilterError(f"{service_name}: destination.host is required")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise AnsibleFilterError(f"{service_name}: destination.port must be between 1 and 65535")
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
        raise AnsibleFilterError(f"{service_name}: destination protocol is incompatible with {exposure}")
    proxy_protocol_version = destination.get("proxy_protocol_version")
    if proxy_protocol_version is not None and (
        exposure != "tcp"
        or isinstance(proxy_protocol_version, bool)
        or not isinstance(proxy_protocol_version, int)
        or proxy_protocol_version not in {1, 2}
    ):
        raise AnsibleFilterError(
            f"{service_name}: destination.proxy_protocol_version is only valid for TCP services and must be 1 or 2"
        )
    source_cidrs = listen.get("source_cidrs", [])
    if not isinstance(source_cidrs, list):
        raise AnsibleFilterError(f"{service_name}: listen.source_cidrs must be a list")
    try:
        source_cidrs = [str(ipaddress.ip_network(cidr, strict=False)) for cidr in source_cidrs]
    except (TypeError, ValueError) as exc:
        raise AnsibleFilterError(f"{service_name}: invalid source CIDR: {exc}") from exc
    if mode == "cloudflare-tunnel" and source_cidrs:
        raise AnsibleFilterError(f"{service_name}: listen.source_cidrs are supported only for direct routes")
    return {
        "exposure": exposure,
        "mode": mode,
        "ports": ports,
        "source_cidrs": source_cidrs,
        "destination": {
            "host": host,
            "port": port,
            "protocol": protocol,
            "proxy_protocol_version": proxy_protocol_version,
        },
    }


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
        multi_listener = "listeners" in raw
        if multi_listener:
            unknown = set(raw) - {"hostname", "mode", "dns", "listeners"}
            if unknown:
                raise AnsibleFilterError(
                    f"{name}: use either listeners or the single-listener fields, not both; unknown fields: "
                    f"{sorted(unknown)}"
                )
            listener_specs = raw.get("listeners")
            if not isinstance(listener_specs, list) or not listener_specs:
                raise AnsibleFilterError(f"{name}: listeners must be a non-empty list")
            for listener in listener_specs:
                if isinstance(listener, dict):
                    unknown_listener_fields = set(listener) - {"exposure", "listen", "destination"}
                    if unknown_listener_fields:
                        raise AnsibleFilterError(
                            f"{name}: hostname, mode and dns belong on the service, not on each listener; "
                            f"unsupported listener fields: {sorted(unknown_listener_fields)}"
                        )
        else:
            listener_specs = [raw]
        mode = raw.get("mode", "direct")
        if mode not in {"direct", "cloudflare-tunnel"}:
            raise AnsibleFilterError(f"{name}: mode must be direct or cloudflare-tunnel")
        listeners = [_normalize_listener(name, listener, mode) for listener in listener_specs]
        hostname = raw.get("hostname")
        dns_raw = raw.get("dns")
        hostname_listener_indexes = [
            index
            for index, listener in enumerate(listeners)
            if listener["exposure"] in {"http", "https", "tls-passthrough"}
        ]
        if multi_listener and len(hostname_listener_indexes) > 1:
            raise AnsibleFilterError(
                f"{name}: a shared hostname can have only one HTTP or TLS listener; use separate hostnames"
            )
        if hostname_listener_indexes:
            if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
                raise AnsibleFilterError(f"{name}: a valid hostname is required for HTTP and TLS services")
            hostname = hostname.lower()
        elif hostname is not None:
            if (
                not isinstance(hostname, str)
                or not HOSTNAME.fullmatch(hostname)
                or hostname.startswith("*.")
            ):
                raise AnsibleFilterError(f"{name}: a valid non-wildcard hostname is required for TCP DNS")
            hostname = hostname.lower()

        dns_listener_index = hostname_listener_indexes[0] if hostname_listener_indexes else 0
        dns = _service_dns(
            dns_raw,
            name,
            listeners[dns_listener_index]["destination"]["host"],
            mode,
        )
        dns_enabled = any(settings["enabled"] for settings in (dns or {}).values())
        if dns_enabled and hostname is None:
            raise AnsibleFilterError(f"{name}: hostname is required when DNS publication is enabled")
        if not hostname_listener_indexes and hostname is not None and not dns_enabled:
            raise AnsibleFilterError(f"{name}: TCP hostname requires an enabled DNS provider")
        if hostname is not None and (hostname_listener_indexes or dns_enabled):
            if hostname in used_hosts:
                raise AnsibleFilterError(f"{name}: duplicate hostname {hostname}")
            used_hosts.add(hostname)

        for listener in listeners:
            exposure = listener["exposure"]
            ports = listener["ports"]
            source_cidrs = listener["source_cidrs"]
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
                    key = ("tcp", public_port)
                    if key in raw_listeners:
                        raise AnsibleFilterError(
                            f"{name}: listener tcp/{public_port} conflicts with {raw_listeners[key]}"
                        )
                    raw_listeners[key] = name

        normalized[name] = {
            "mode": mode,
            "hostname": hostname,
            "dns": dns,
            "listeners": listeners,
            "multi_listener": multi_listener,
            "dns_listener_index": dns_listener_index,
        }
        if not multi_listener:
            normalized[name].update(listeners[0])
            normalized[name]["hostname"] = hostname
            normalized[name]["dns"] = dns

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
        listeners = service["listeners"]
        metadata_listener = service["dns_listener_index"]
        hostname_listener = next(
            (
                index
                for index, listener in enumerate(listeners)
                if listener["exposure"] in {"http", "https", "tls-passthrough"}
            ),
            metadata_listener,
        )
        for index, listener in enumerate(listeners):
            for port in listener["ports"]:
                exposure = {
                    "id": f"{name}-{port}",
                    "protocol": (
                        "http"
                        if listener["exposure"] in {"http", "https"}
                        else "tls"
                        if listener["exposure"] == "tls-passthrough"
                        else "tcp"
                    ),
                    "mode": listener["mode"],
                    "listenPort": port,
                    "targetHost": listener["destination"]["host"],
                    "targetPort": listener["destination"]["port"],
                    "sourceCIDRs": listener["source_cidrs"],
                }
                if service["hostname"] is not None and index == hostname_listener:
                    exposure["hostname"] = service["hostname"]
                if service["dns"] is not None and index == metadata_listener:
                    exposure["dns"] = service["dns"]
                if listener["exposure"] == "https" and listener["mode"] == "direct":
                    exposure["tls"] = True
                if listener["destination"]["protocol"] == "https":
                    exposure["targetTLS"] = True
                if listener["destination"]["proxy_protocol_version"] is not None:
                    exposure["proxyProtocolVersion"] = listener["destination"]["proxy_protocol_version"]
                exposures.append(exposure)
    return {"generation": 1, "exposures": exposures}


class FilterModule:
    """Ansible filter registration."""

    def filters(self) -> dict[str, Any]:
        return {"normalize_services": normalize_services, "fixed_snapshot": fixed_snapshot}
