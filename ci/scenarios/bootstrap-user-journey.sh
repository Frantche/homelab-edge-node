#!/usr/bin/env bash
set -euo pipefail

repo=/opt/homelab-edge-node
config=/tmp/edge-ci-config

install -d -m 0755 "$config/inventory" "$config/group_vars"
install -m 0755 "$repo/ci/mock-backends.py" /usr/local/bin/edge-ci-backends
cat >/etc/systemd/system/edge-ci-backends.service <<'EOF'
[Unit]
Description=CI protocol echo backends
After=network.target
[Service]
ExecStart=/usr/local/bin/edge-ci-backends
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now edge-ci-backends.service

cat >"$config/inventory/hosts.yml" <<'EOF'
---
all:
  hosts:
    localhost:
      ansible_connection: local
EOF
cat >"$config/playbook.yml" <<'EOF'
---
- name: Configure CI edge
  hosts: all
  become: true
  vars_files:
    - group_vars/all.yml
  roles:
    - frantche.homelab_edge_node.edge
EOF
cat >"$config/group_vars/all.yml" <<'EOF'
---
edge_ci_mode: true
edge_acme_enabled: false
edge_management_cidrs: [10.0.2.0/24]
edge_observability:
  enabled: true
  metrics_endpoint: http://otel-mock-backend:43190/v1/metrics
  logs_endpoint: http://otel-mock-backend:43190/v1/logs
  compression: none
  collection_interval: 5s
  traefik_metrics_interval: 5s
  queue_size: 32
edge_services:
  web:
    exposure: https
    hostname: edge.example.test
    listen: {ports: [443]}
    destination: {host: 127.0.0.1, port: 18080, protocol: http}
  drive:
    exposure: tcp
    listen: {ports: [6690]}
    destination: {host: 127.0.0.1, port: 19001, protocol: tcp}
  game:
    exposure: udp
    listen: {ports: [2456]}
    destination: {host: 127.0.0.1, port: 19002, protocol: udp}
EOF

cd "$config"
ansible-playbook -i inventory/hosts.yml playbook.yml
ansible-playbook -i inventory/hosts.yml playbook.yml | tee /tmp/edge-second-converge.log
grep -Eq 'changed=0 +unreachable=0 +failed=0' /tmp/edge-second-converge.log

systemctl is-active --quiet docker sshd edge-ci-backends
systemctl cat edge-converge.service edge-converge.timer edge-upgrade.service edge-upgrade.timer >/dev/null
docker ps --filter name='^edge-traefik$' --filter status=running --format '{{.Names}}' | grep -qx edge-traefik
docker ps --filter name='^edge-otel-collector$' --filter status=running --format '{{.Names}}' | grep -qx edge-otel-collector
curl --fail --silent --insecure --resolve edge.example.test:443:127.0.0.1 \
  https://edge.example.test/ | grep -qx edge-http-ok
curl --fail --silent --insecure --resolve edge.example.test:443:127.0.0.1 \
  -H "Authori""zation: bearer-ci-value" -H 'X-CI-Sentinel: header-ci-value' \
  'https://edge.example.test/observability-check?token=query-ci-secret' | grep -qx edge-http-ok
if curl --fail --silent --insecure --resolve unknown.example.test:443:127.0.0.1 \
  https://unknown.example.test/; then
  echo "Unknown SNI was unexpectedly accepted" >&2
  exit 1
fi

python - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 6690), timeout=5) as sock:
    sock.sendall(b"hello")
    assert sock.recv(1024) == b"tcp:hello"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.sendto(b"hello", ("127.0.0.1", 2456))
    assert sock.recv(1024) == b"udp:hello"
PY

nft list table inet homelab_edge | grep -q 'tcp dport 443'
nft list table inet homelab_edge | grep -q 'tcp dport 6690'
nft list table inet homelab_edge | grep -q 'udp dport 2456'
if ss -H -lnt | grep -q ':4444 '; then
  echo "Unexpected listener on tcp/4444" >&2
  exit 1
fi

read_only="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' edge-traefik)"
[[ "$read_only" == true ]]
cap_drop="$(docker inspect -f '{{json .HostConfig.CapDrop}}' edge-traefik)"
grep -q 'ALL' <<<"$cap_drop"
docker inspect -f '{{json .HostConfig.SecurityOpt}}' edge-traefik | grep -q no-new-privileges

collector_read_only="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' edge-otel-collector)"
[[ "$collector_read_only" == true ]]
[[ "$(docker inspect -f '{{.Config.User}}' edge-otel-collector)" == '10001:10001' ]]
docker inspect -f '{{json .HostConfig.CapDrop}}' edge-otel-collector | grep -q 'ALL'
docker inspect -f '{{json .HostConfig.SecurityOpt}}' edge-otel-collector | grep -q no-new-privileges
if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' edge-otel-collector | grep -q docker.sock; then
  echo "Collector unexpectedly has access to the Docker socket" >&2
  exit 1
fi
docker port edge-otel-collector 4318/tcp | grep -qx '127.0.0.1:4318'
if ss -H -lnt | grep ':4318 ' | grep -vq '^LISTEN .*127\.0\.0\.1:4318 '; then
  echo "OTLP receiver is not restricted to loopback" >&2
  exit 1
fi

for attempt in $(seq 1 30); do
  metrics=/tmp/edge-otel-mock/metrics.received
  logs=/tmp/edge-otel-mock/logs.received
  if [[ -s "$metrics" && -s "$logs" ]] && \
     grep -aq 'system.cpu' "$metrics" && grep -aq 'traefik_' "$metrics" && \
     grep -aq 'observability-check' "$logs"; then
    break
  fi
  if [[ "$attempt" == 30 ]]; then
    echo "Expected host metrics, Traefik metrics and logs were not exported" >&2
    exit 1
  fi
  sleep 2
done
grep -aq 'ClientHost' /tmp/edge-otel-mock/logs.received
grep -aq 'observability-check' /tmp/edge-otel-mock/logs.received
for secret in query-ci-secret bearer-ci-value header-ci-value; do
  if grep -aq "$secret" /tmp/edge-otel-mock/logs.received; then
    echo "Sensitive access-log value was exported: $secret" >&2
    exit 1
  fi
done

logrotate --debug /etc/logrotate.d/homelab-edge-node >/dev/null
docker restart edge-otel-collector >/dev/null
for attempt in $(seq 1 30); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' edge-otel-collector)" == healthy ]] && break
  [[ "$attempt" == 30 ]] && { echo "Collector did not recover after restart" >&2; exit 1; }
  sleep 2
done
curl --fail --silent --insecure --resolve edge.example.test:443:127.0.0.1 \
  https://edge.example.test/after-collector-restart | grep -qx edge-http-ok

docker stop edge-otel-mock-backend >/dev/null
curl --fail --silent --insecure --resolve edge.example.test:443:127.0.0.1 \
  https://edge.example.test/backend-outage | grep -qx edge-http-ok
docker start edge-otel-mock-backend >/dev/null

# Removing a declaration must remove both the listener and firewall permission.
python - <<'PY'
from pathlib import Path
import yaml

path = Path("group_vars/all.yml")
data = yaml.safe_load(path.read_text())
del data["edge_services"]["drive"]
path.write_text(yaml.safe_dump(data, sort_keys=False))
PY
ansible-playbook -i inventory/hosts.yml playbook.yml
if ss -H -lnt | grep -q ':6690 '; then
  echo "Removed TCP service is still listening" >&2
  exit 1
fi
if nft list table inet homelab_edge | grep -q '6690'; then
  echo "Removed TCP service is still allowed by nftables" >&2
  exit 1
fi

echo "bootstrap user journey passed"
