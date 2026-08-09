#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 .ci/build .ci/collections
ansible-galaxy collection install --force --collections-path .ci/collections -r requirements.yml
ansible-galaxy collection build --force --output-path .ci/build
archive="$(find .ci/build -maxdepth 1 -type f -name 'frantche-homelab_edge_node-*.tar.gz' -print | sort -V | tail -1)"
[[ -n "$archive" ]]
ansible-galaxy collection install --force --collections-path .ci/collections "$archive"
install -d -m 0755 .ci/otel-logs .ci/otel-state
ANSIBLE_COLLECTIONS_PATH="$PWD/.ci/collections" \
  ansible-playbook --syntax-check -i localhost, ci/playbooks/syntax.yml
ANSIBLE_COLLECTIONS_PATH="$PWD/.ci/collections" \
  ansible-playbook -i localhost, ci/playbooks/render.yml
docker compose -f .ci/rendered-compose.yml config --quiet
docker run --rm --network none \
  -v "$PWD/.ci/rendered-otel-collector.yml:/etc/otelcol/config.yml:ro" \
  -v "/proc:/hostfs/proc:ro" \
  -v "/sys:/hostfs/sys:ro" \
  -v "$PWD/.ci/otel-logs:/var/log/traefik:ro" \
  -v "$PWD/.ci/otel-state:/var/lib/otelcol" \
  otel/opentelemetry-collector-contrib:0.157.0@sha256:4eb842091c796156d4d3c994eb22ba793590f5723719dbf6b8436cb4dfc17f48 \
  validate --config=/etc/otelcol/config.yml
