# Changelog

## 0.2.0

- Add an optional hardened OpenTelemetry Collector without Docker API access.
- Export host and native Traefik metrics to VictoriaMetrics over OTLP/HTTP.
- Export privacy-filtered Traefik general and access logs to VictoriaLogs.
- Validate telemetry isolation, payload privacy and backend-failure behavior in
  the Arch Linux QEMU bootstrap journey.

## 0.1.1

- Recreate Traefik after an activated configuration change so removed TCP and
  UDP entrypoints stop listening immediately.
- Harden the QEMU bootstrap journey and candidate configuration validation.

## 0.1.0

- Initial Arch Linux edge gateway collection.
- Declarative Traefik HTTP, TCP and UDP routes with nftables synchronization.
- QEMU bootstrap integration journey for GitHub Actions.
