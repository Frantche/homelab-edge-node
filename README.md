# homelab-edge-node

`homelab-edge-node` turns a dedicated Arch Linux host into a declarative Internet
edge gateway. A single `edge_services` mapping generates Traefik v3 HTTP, TCP and
UDP routes together with the nftables input policy that permits them.

The public repository contains the reusable Ansible collection. Real domains,
addresses and SOPS-encrypted secrets belong in the private
`homelab-edge-node-config` repository.

## Safety properties

- no public port without a declared backend;
- strict Host/SNI handling and no Traefik dashboard;
- atomic configuration validation and last-known-good rollback;
- Docker host networking so traffic cannot bypass the host input policy;
- ACME DNS-01 through Cloudflare DNS without requiring the Cloudflare proxy;
- full Arch upgrades only, followed by a controlled reboot when the running
  kernel no longer has installed modules.
- optional OpenTelemetry host and Traefik telemetry without Docker API access,
  with OTLP ingestion restricted to host loopback.

See [`examples/group_vars.yml`](examples/group_vars.yml) for the public variable
contract. Port ranges are expanded to individual Traefik entrypoints and are
limited to 1024 ports per declaration.

## Bootstrap

1. Install Arch Linux on the dedicated host.
2. Place the private age identity and GitHub deploy key under
   `/etc/homelab-edge-node/` as documented by the config repository.
3. Run:

```bash
sudo EDGE_CONFIG_REPO_URL=git@github.com:Frantche/homelab-edge-node-config.git \
  ./scripts/bootstrap.sh
```

The CI runs this lifecycle in a fresh official Arch cloud image under QEMU and
tests HTTPS, raw TCP, UDP, nftables, idempotence and container hardening.

## OpenTelemetry observability

Set `edge_observability.enabled` to deploy a pinned OpenTelemetry Collector
Contrib container. It exports host CPU, memory, load, network, paging, disk I/O
and process-count metrics, native Traefik OTLP metrics, and structured Traefik
general and access logs. Metrics and logs use separate OTLP/HTTP endpoints so
VictoriaMetrics and VictoriaLogs can remain independent.

Production endpoints must use HTTPS. Optional exporter headers belong in the
SOPS-encrypted private configuration, never in this repository. Access logs
retain client IP and request path for diagnostics, while query strings,
credentials and all request/response headers are excluded. The Collector has
no Docker socket, runs as UID/GID 10001 with all capabilities dropped, and only
mounts `/proc`, `/sys`, its bounded state directory and the Traefik log
directory. Filesystem-capacity metrics are intentionally omitted to avoid a
read-only mount of the complete host root filesystem.

See [`examples/group_vars.yml`](examples/group_vars.yml) for the full variable
shape. A Victoria backend outage does not stop Traefik; telemetry remains a
best-effort, bounded pipeline.
