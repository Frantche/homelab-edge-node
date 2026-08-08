# Changelog

## 0.1.1

- Recreate Traefik after an activated configuration change so removed TCP and
  UDP entrypoints stop listening immediately.
- Harden the QEMU bootstrap journey and candidate configuration validation.

## 0.1.0

- Initial Arch Linux edge gateway collection.
- Declarative Traefik HTTP, TCP and UDP routes with nftables synchronization.
- QEMU bootstrap integration journey for GitHub Actions.
