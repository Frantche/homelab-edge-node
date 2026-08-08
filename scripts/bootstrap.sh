#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this bootstrap as root" >&2
  exit 1
fi
: "${EDGE_CONFIG_REPO_URL:?Set EDGE_CONFIG_REPO_URL to the private configuration repository}"
install -d -m 0700 /etc/homelab-edge-node/keys /etc/homelab-edge-node/secrets
pacman --sync --refresh --sysupgrade --noconfirm
pacman --sync --needed --noconfirm ansible git openssh sops age
ansible-pull --url "$EDGE_CONFIG_REPO_URL" --checkout main \
  --directory /var/lib/homelab-edge-node/config-checkout \
  --inventory inventory/hosts.yml playbook.yml

