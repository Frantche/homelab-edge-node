from pathlib import Path
import importlib.util

import pytest
from ansible.errors import AnsibleFilterError

MODULE_PATH = Path(__file__).parents[1] / "plugins/filter/edge.py"
SPEC = importlib.util.spec_from_file_location("edge_filter", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def service(exposure="https", ports=None, **extra):
    value = {
        "exposure": exposure,
        "listen": {"ports": ports or [443]},
        "destination": {
            "host": "192.0.2.10",
            "port": 8080,
            "protocol": "http" if exposure == "https" else exposure,
        },
    }
    if exposure in {"http", "https"}:
        value["hostname"] = extra.pop("hostname", "app.example.test")
    value.update(extra)
    return value


def test_normalizes_ranges_and_cidrs():
    raw = service("tcp", ["50000-50002"])
    raw["listen"]["source_cidrs"] = ["192.0.2.8/24"]
    result = MODULE.normalize_services({"game": raw})
    assert result["game"]["ports"] == [50000, 50001, 50002]
    assert result["game"]["source_cidrs"] == ["192.0.2.0/24"]


@pytest.mark.parametrize(
    "services",
    [
        {"bad_name": service()},
        {"a": service("udp", [2456])},
        {"a": {**service("tcp", [6690]), "mode": "cloudflare-tunnel"}},
        {"a": service("tcp", [443])},
        {"a": {**service("http", [80]), "mode": "cloudflare-tunnel"}},
        {
            "a": {
                **service("http", [443]),
                "mode": "cloudflare-tunnel",
                "listen": {"ports": [443], "source_cidrs": ["192.0.2.0/24"]},
            }
        },
        {"a": service(ports=[0])},
        {"a": service(ports=["10-1"])},
        {"a": service(hostname="not-a-host")},
        {"a": service(), "b": service()},
        {"a": service("tcp", [6690]), "b": service("tcp", [6690])},
        {
            "a": service(hostname="a.example.test"),
            "b": {
                **service(hostname="b.example.test"),
                "listen": {"ports": [443], "source_cidrs": ["192.0.2.0/24"]},
            },
        },
    ],
)
def test_rejects_invalid_services(services):
    with pytest.raises(AnsibleFilterError):
        MODULE.normalize_services(services)


def test_fixed_snapshot_converts_http_https_and_tcp_to_route_api_contract():
    tunnel = service("https", [443], hostname="tunnel.example.test")
    tunnel["mode"] = "cloudflare-tunnel"
    result = MODULE.fixed_snapshot(
        {
            "secure": service("https", [443], hostname="secure.example.test"),
            "plain": service("http", [8080], hostname="plain.example.test"),
            "database": service("tcp", [6690]),
            "tunnel": tunnel,
        }
    )
    assert result["generation"] == 1
    assert [route["protocol"] for route in result["exposures"]] == ["http", "http", "tcp", "http"]
    assert result["exposures"][0]["tls"] is True
    assert "tls" not in result["exposures"][1]
    assert "hostname" not in result["exposures"][2]
    assert result["exposures"][3]["mode"] == "cloudflare-tunnel"
    assert "tls" not in result["exposures"][3]


def test_accepts_wildcard_http_hostname():
    raw = service(hostname="*.apps.example.test")
    assert MODULE.normalize_services({"wildcard": raw})["wildcard"]["hostname"] == "*.apps.example.test"
