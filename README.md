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

