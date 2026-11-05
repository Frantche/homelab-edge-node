#!/usr/bin/env bash
set -euo pipefail

repo=/opt/homelab-edge-node
config=/tmp/edge-ci-config
mtls=/tmp/edge-ci-mtls

install -d -m 0755 "$config/inventory" "$config/group_vars"
install -d -m 0700 "$mtls"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$mtls/ca.key" -out "$mtls/ca.crt" \
  -days 1 -subj /CN=edge-ci-mtls-ca \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
cat >"$mtls/server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:otel.example.test
EOF
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$mtls/server.key" -out "$mtls/server.csr" \
  -subj /CN=otel.example.test >/dev/null 2>&1
openssl x509 -req -in "$mtls/server.csr" \
  -CA "$mtls/ca.crt" -CAkey "$mtls/ca.key" -CAcreateserial \
  -out "$mtls/server.crt" -days 1 -sha256 -extfile "$mtls/server.ext" >/dev/null 2>&1
cat >"$mtls/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$mtls/client.key" -out "$mtls/client.csr" \
  -subj /CN=edge-ci-client >/dev/null 2>&1
openssl x509 -req -in "$mtls/client.csr" \
  -CA "$mtls/ca.crt" -CAkey "$mtls/ca.key" -CAcreateserial \
  -out "$mtls/client.crt" -days 1 -sha256 -extfile "$mtls/client.ext" >/dev/null 2>&1
install -m 0755 "$repo/ci/mock-backends.py" /usr/local/bin/edge-ci-backends
cat >/etc/systemd/system/edge-ci-backends.service <<'EOF'
[Unit]
Description=CI protocol echo backends
After=network.target
[Service]
Environment=EDGE_CI_MTLS_DIR=/tmp/edge-ci-mtls
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
edge_allowed_http_ports: [80, 443]
edge_allowed_tcp_ports: [6690, 6691]
edge_publication_sources: [ci-kubernetes]
edge_publication_api_cidrs: [10.0.2.0/24]
edge_publication_api_server_name: edge-api.example.test
edge_publication_server_sans: [DNS:edge-api.example.test, IP:127.0.0.1]
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
  telemetry:
    exposure: tls-passthrough
    hostname: otel.example.test
    listen: {ports: [443]}
    destination: {host: 127.0.0.1, port: 19443, protocol: tcp}
EOF

cd "$config"
ansible-playbook -i inventory/hosts.yml playbook.yml
ansible-playbook -i inventory/hosts.yml playbook.yml | tee /tmp/edge-second-converge.log
grep -Eq 'changed=0 +unreachable=0 +failed=0' /tmp/edge-second-converge.log

assert_http_ok() {
  local body
  body="$(curl --fail --silent --show-error "$@")"
  if [[ "$body" != edge-http-ok ]]; then
    printf 'Unexpected HTTP response body: %q\n' "$body" >&2
    return 1
  fi
}

echo "Checking required systemd services"
for service in docker sshd edge-ci-backends; do
  systemctl is-active --quiet "$service"
done
systemctl cat edge-converge.service edge-converge.timer edge-upgrade.service edge-upgrade.timer >/dev/null
echo "Checking edge containers"
docker ps --filter name='^edge-traefik$' --filter status=running --format '{{.Names}}' | grep -Fx edge-traefik >/dev/null
docker ps --filter name='^edge-otel-collector$' --filter status=running --format '{{.Names}}' | grep -Fx edge-otel-collector >/dev/null
echo "Checking direct HTTP backend"
assert_http_ok http://127.0.0.1:18080/
echo "Checking HTTPS route"
assert_http_ok --insecure --resolve edge.example.test:443:127.0.0.1 https://edge.example.test/
assert_http_ok --insecure --resolve edge.example.test:443:127.0.0.1 \
  -H "Authori""zation: bearer-ci-value" -H 'X-CI-Sentinel: header-ci-value' \
  'https://edge.example.test/observability-check?token=query-ci-secret'
if curl --fail --silent --show-error --insecure --resolve unknown.example.test:443:127.0.0.1 \
  https://unknown.example.test/; then
  echo "Unknown SNI was unexpectedly accepted" >&2
  exit 1
fi

echo "Checking SNI routing and end-to-end mTLS passthrough"
python - "$mtls" <<'PY'
import socket
import ssl
import sys

root = sys.argv[1]
server_context = ssl.create_default_context(cafile=f"{root}/ca.crt")
try:
    with socket.create_connection(("127.0.0.1", 443), timeout=5) as connection:
        with server_context.wrap_socket(connection, server_hostname="otel.example.test") as tls:
            tls.sendall(b"probe")
            if tls.recv(1):
                raise RuntimeError("TLS passthrough accepted a client without a certificate")
except (ssl.SSLError, ConnectionError, OSError):
    pass
else:
    print("TLS endpoint rejected the client without a certificate")

client_context = ssl.create_default_context(cafile=f"{root}/ca.crt")
client_context.load_cert_chain(f"{root}/client.crt", f"{root}/client.key")
with socket.create_connection(("127.0.0.1", 443), timeout=5) as connection:
    with client_context.wrap_socket(connection, server_hostname="otel.example.test") as tls:
        tls.sendall(b"hello")
        response = tls.recv(1024)
if response != b"tcp:hello":
    raise RuntimeError(f"mTLS backend returned {response!r}")
PY

echo "Checking fixed TCP route"
python - <<'PY'
import socket
import sys

def exchange(port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"hello")
        return sock.recv(1024)

try:
    backend_response = exchange(19001)
    if backend_response != b"tcp:hello":
        raise RuntimeError(f"direct TCP backend returned {backend_response!r}")
    route_response = exchange(6690)
    if route_response != b"tcp:hello":
        raise RuntimeError(f"fixed TCP route returned {route_response!r}")
except Exception as error:
    print(f"Fixed TCP route probe failed: {error!r}", file=sys.stderr, flush=True)
    print("Manager status:", file=sys.stderr, flush=True)
    try:
        print(open("/var/lib/homelab-edge-node/manager/status.json").read(), file=sys.stderr, flush=True)
    except OSError as status_error:
        print(repr(status_error), file=sys.stderr, flush=True)
    print("Dynamic routes:", file=sys.stderr, flush=True)
    try:
        print(open("/var/lib/homelab-edge-node/runtime/routes.yml").read(), file=sys.stderr, flush=True)
    except OSError as routes_error:
        print(repr(routes_error), file=sys.stderr, flush=True)
    raise
PY

nft list table inet homelab_edge | grep -F 'tcp dport 443' >/dev/null
nft list table inet homelab_edge | grep -F 'tcp dport 6690' >/dev/null
nft list table inet homelab_edge | grep -F 'tcp dport 9443' >/dev/null
nft list table inet homelab_edge | grep -F 'iifname "docker0" ct state established,related,new accept' >/dev/null
nft list table inet homelab_edge | grep -F 'iifname "br-*" ct state established,related,new accept' >/dev/null
if ss -H -lnt | grep -F ':4444 ' >/dev/null; then
  echo "Unexpected listener on tcp/4444" >&2
  exit 1
fi

# Publish and withdraw an allow-listed TCP route through the real mTLS API.
python - <<'PY'
import json
import socket
import ssl
import time
from urllib.request import Request, urlopen

pki = "/etc/homelab-edge-node/secrets/pki"
context = ssl.create_default_context(cafile=f"{pki}/ca.crt")
context.load_cert_chain(f"{pki}/client-ci-kubernetes.crt", f"{pki}/client-ci-kubernetes.key")
url = "https://127.0.0.1:9443/v1/sources/ci-kubernetes/exposures"

def publish(generation, exposures):
    body = json.dumps({"generation": generation, "exposures": exposures}).encode()
    request = Request(url, data=body, method="PUT", headers={"Content-Type": "application/json"})
    with urlopen(request, context=context, timeout=5) as response:
        assert response.status == 202

route = {
    "id": "k8s-direct-tcp",
    "protocol": "tcp",
    "mode": "direct",
    "listenPort": 6691,
    "targetHost": "127.0.0.1",
    "targetPort": 19001,
}
publish(1, [route])
for attempt in range(30):
    try:
        with socket.create_connection(("127.0.0.1", 6691), timeout=1) as sock:
            sock.sendall(b"hello")
            if sock.recv(1024) == b"tcp:hello":
                break
    except OSError:
        pass
    if attempt == 29:
        raise RuntimeError("mTLS-published TCP route did not become active")
    time.sleep(1)
publish(2, [])
for attempt in range(30):
    try:
        with open("/var/lib/homelab-edge-node/manager/status.json", encoding="utf-8") as status_file:
            status = json.load(status_file)
        if status["state"] == "applied" and status["exposureCount"] == 3:
            break
    except (OSError, ValueError, KeyError):
        pass
    if attempt == 29:
        raise RuntimeError("edge manager did not reconcile the removed dynamic route")
    time.sleep(1)
PY
if nft list table inet homelab_edge | grep -F 'tcp dport 6691' >/dev/null; then
  echo "Removed dynamic TCP route is still allowed by nftables" >&2
  exit 1
fi

echo "Checking container security and loopback receiver"
read_only="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' edge-traefik)"
[[ "$read_only" == true ]]
cap_drop="$(docker inspect -f '{{json .HostConfig.CapDrop}}' edge-traefik)"
grep -q 'ALL' <<<"$cap_drop"
docker inspect -f '{{json .HostConfig.SecurityOpt}}' edge-traefik | grep -F no-new-privileges >/dev/null

collector_read_only="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' edge-otel-collector)"
[[ "$collector_read_only" == true ]]
[[ "$(docker inspect -f '{{.Config.User}}' edge-otel-collector)" == '10001:10001' ]]
docker inspect -f '{{json .HostConfig.CapDrop}}' edge-otel-collector | grep -F 'ALL' >/dev/null
docker inspect -f '{{json .HostConfig.SecurityOpt}}' edge-otel-collector | grep -F no-new-privileges >/dev/null
if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' edge-otel-collector | grep -F docker.sock >/dev/null; then
  echo "Collector unexpectedly has access to the Docker socket" >&2
  exit 1
fi
docker port edge-otel-collector 4318/tcp | grep -Fx '127.0.0.1:4318' >/dev/null
if ss -H -lnt | grep ':4318 ' | grep -v '^LISTEN .*127\.0\.0\.1:4318 ' >/dev/null; then
  echo "OTLP receiver is not restricted to loopback" >&2
  exit 1
fi

echo "Checking observability export and redaction"
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

echo "Checking collector restart and backend outage behavior"
logrotate --debug /etc/logrotate.d/homelab-edge-node >/dev/null
docker restart edge-otel-collector >/dev/null
for attempt in $(seq 1 30); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' edge-otel-collector)" == healthy ]] && break
  [[ "$attempt" == 30 ]] && { echo "Collector did not recover after restart" >&2; exit 1; }
  sleep 2
done
assert_http_ok --insecure --resolve edge.example.test:443:127.0.0.1 \
  https://edge.example.test/after-collector-restart

docker stop edge-otel-mock-backend >/dev/null
assert_http_ok --insecure --resolve edge.example.test:443:127.0.0.1 \
  https://edge.example.test/backend-outage
docker start edge-otel-mock-backend >/dev/null

# Removing a declaration must remove its firewall permission.
echo "Checking firewall cleanup after config removal"
python - <<'PY'
from pathlib import Path
import yaml

path = Path("group_vars/all.yml")
data = yaml.safe_load(path.read_text())
del data["edge_services"]["drive"]
path.write_text(yaml.safe_dump(data, sort_keys=False))
PY
ansible-playbook -i inventory/hosts.yml playbook.yml
if nft list table inet homelab_edge | grep -F '6690' >/dev/null; then
  echo "Removed TCP service is still allowed by nftables" >&2
  exit 1
fi

echo "bootstrap user journey passed"
