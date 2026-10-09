#!/usr/bin/env bash
set -euo pipefail

cluster_name="edge-controller-ci-${GITHUB_RUN_ID:-local}-$$"
namespace=homelab-edge-system
kind_image=homelab-edge-node:ci
gateway_api_version=v1.6.1
temporary_directory=$(mktemp -d)
port_forward_pid=

cleanup() {
  result=$?
  trap - EXIT
  if [[ $result -ne 0 ]]; then
    kubectl get pods,services,deployments -A -o wide || true
    kubectl -n "$namespace" logs deployment/edge-manager --all-containers=true || true
    kubectl -n "$namespace" logs deployment/edge-kubernetes-controller --all-containers=true || true
  fi
  if [[ -n ${port_forward_pid:-} ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
  fi
  if kind get clusters 2>/dev/null | grep -Fxq "$cluster_name"; then
    kind delete cluster --name "$cluster_name" || true
  fi
  rm -rf "$temporary_directory"
  exit "$result"
}
trap cleanup EXIT

openssl_run() {
  if ! openssl "$@" >"$temporary_directory/openssl.log" 2>&1; then
    cat "$temporary_directory/openssl.log" >&2
    return 1
  fi
}

kind create cluster --name "$cluster_name" --wait 180s
kind load docker-image "$kind_image" --name "$cluster_name"
for crd in gatewayclasses gateways httproutes tcproutes; do
  kubectl apply --server-side -f \
    "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/${gateway_api_version}/config/crd/standard/gateway.networking.k8s.io_${crd}.yaml"
done
for crd in gatewayclasses.gateway.networking.k8s.io gateways.gateway.networking.k8s.io \
  httproutes.gateway.networking.k8s.io tcproutes.gateway.networking.k8s.io; do
  kubectl wait --for=condition=Established "crd/$crd" --timeout=180s
done
if kubectl get crd udproutes.gateway.networking.k8s.io >/dev/null 2>&1; then
  echo 'the Kind fixture unexpectedly installed the UDPRoute CRD' >&2
  exit 1
fi

openssl_run req -x509 -newkey rsa:2048 -nodes \
  -keyout "$temporary_directory/ca.key" -out "$temporary_directory/ca.crt" \
  -days 1 -subj /CN=homelab-edge-kind-ci-ca \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
cat >"$temporary_directory/server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:edge-manager.homelab-edge-system.svc,DNS:edge-manager.homelab-edge-system.svc.cluster.local
EOF
openssl_run req -new -newkey rsa:2048 -nodes \
  -keyout "$temporary_directory/server.key" -out "$temporary_directory/server.csr" \
  -subj /CN=edge-manager.homelab-edge-system.svc
openssl_run x509 -req -in "$temporary_directory/server.csr" \
  -CA "$temporary_directory/ca.crt" -CAkey "$temporary_directory/ca.key" \
  -CAcreateserial -out "$temporary_directory/server.crt" -days 1 -sha256 \
  -extfile "$temporary_directory/server.ext"
cat >"$temporary_directory/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl_run req -new -newkey rsa:2048 -nodes \
  -keyout "$temporary_directory/client.key" -out "$temporary_directory/client.csr" \
  -subj /CN=ci-kubernetes
openssl_run x509 -req -in "$temporary_directory/client.csr" \
  -CA "$temporary_directory/ca.crt" -CAkey "$temporary_directory/ca.key" \
  -CAcreateserial -out "$temporary_directory/client.crt" -days 1 -sha256 \
  -extfile "$temporary_directory/client.ext"

kubectl apply -f deploy/kubernetes/namespace.yaml
cat >"$temporary_directory/manager.yml" <<'EOF'
api:
  listenAddress: ":9443"
  serverCertFile: /run/edge-pki/server.crt
  serverKeyFile: /run/edge-pki/server.key
  clientCAFile: /run/edge-pki/ca.crt
  sources: [ci-kubernetes]
runtime:
  fixedSnapshotFile: /etc/homelab-edge-node/fixed-exposures.json
  dynamicFile: /var/lib/homelab-edge-node/runtime/routes.yml
  statusFile: /var/lib/homelab-edge-node/manager/status.json
  sourceTTLSeconds: 300
  reconcileIntervalSeconds: 1
  allowedPorts:
    http:
      443: {}
    tcp:
      33060: {}
EOF
printf '%s\n' '{"generation":1,"exposures":[]}' >"$temporary_directory/fixed-exposures.json"
kubectl -n "$namespace" create configmap edge-manager-config \
  --from-file=manager.yml="$temporary_directory/manager.yml" \
  --from-file=fixed-exposures.json="$temporary_directory/fixed-exposures.json"
kubectl -n "$namespace" create secret generic edge-manager-server-tls \
  --from-file=server.crt="$temporary_directory/server.crt" \
  --from-file=server.key="$temporary_directory/server.key" \
  --from-file=ca.crt="$temporary_directory/ca.crt"
kubectl -n "$namespace" create secret generic edge-publication-client-tls \
  --from-file=tls.crt="$temporary_directory/client.crt" \
  --from-file=tls.key="$temporary_directory/client.key" \
  --from-file=ca.crt="$temporary_directory/ca.crt"

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge-manager
  namespace: homelab-edge-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: edge-manager
  template:
    metadata:
      labels:
        app: edge-manager
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: manager
          image: homelab-edge-node:ci
          imagePullPolicy: IfNotPresent
          command: [/edge-manager]
          args: [-config, /etc/homelab-edge-node/manager.yml]
          ports:
            - name: api
              containerPort: 9443
          volumeMounts:
            - name: config
              mountPath: /etc/homelab-edge-node
              readOnly: true
            - name: tls
              mountPath: /run/edge-pki
              readOnly: true
            - name: runtime
              mountPath: /var/lib/homelab-edge-node
      volumes:
        - name: config
          configMap:
            name: edge-manager-config
        - name: tls
          secret:
            secretName: edge-manager-server-tls
            defaultMode: 288
        - name: runtime
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: edge-manager
  namespace: homelab-edge-system
spec:
  selector:
    app: edge-manager
  ports:
    - name: api
      port: 9443
      targetPort: api
      protocol: TCP
EOF
kubectl -n "$namespace" rollout status deployment/edge-manager --timeout=180s

cat >"$temporary_directory/controller.yml" <<'EOF'
source: ci-kubernetes
edgeURL: https://edge-manager.homelab-edge-system.svc:9443
edgeCACertFile: /var/run/edge-publication/ca.crt
edgeClientCertFile: /var/run/edge-publication/tls.crt
edgeClientKeyFile: /var/run/edge-publication/tls.key
defaultMode: direct
defaultHTTPPort: 443
gatewayAPIEnabled: true
tcpRouteEnabled: true
pollIntervalSeconds: 5
ingressTargets:
  kind-ci-ingress:
    address: ingress-backend.apps.svc.cluster.local
    port: 8080
gatewayTargets:
  kind-ci-gateway:
    address: gateway-backend.apps.svc.cluster.local
    port: 8080
EOF
kubectl -n "$namespace" create configmap edge-kubernetes-controller \
  --from-file=controller.yml="$temporary_directory/controller.yml"
kubectl apply -f deploy/kubernetes/rbac.yaml
sed "s#^          image: .*#          image: $kind_image#" deploy/kubernetes/deployment.yaml \
  | kubectl apply -f -
kubectl -n "$namespace" rollout status deployment/edge-kubernetes-controller --timeout=180s

controller_identity="system:serviceaccount:${namespace}:edge-kubernetes-controller"
for resource in ingresses.networking.k8s.io gateways.gateway.networking.k8s.io \
  httproutes.gateway.networking.k8s.io tcproutes.gateway.networking.k8s.io; do
  if ! kubectl auth can-i list "$resource" --as="$controller_identity" --quiet -n apps; then
    echo "controller service account cannot list $resource" >&2
    exit 1
  fi
done
for verb in get list create update patch delete; do
  if kubectl auth can-i "$verb" secrets --as="$controller_identity" --quiet -n apps; then
    echo "controller service account can unexpectedly $verb Secrets" >&2
    exit 1
  fi
done
for verb in create update patch delete; do
  if kubectl auth can-i "$verb" ingresses.networking.k8s.io \
    --as="$controller_identity" --quiet -n apps; then
    echo "controller service account can unexpectedly $verb Ingress resources" >&2
    exit 1
  fi
done

cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: apps
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: kind-ci-ingress
spec:
  controller: ci.example.com/ingress-controller
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-backend
  namespace: apps
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
  selector:
    app: ingress-backend
---
apiVersion: v1
kind: Service
metadata:
  name: gateway-backend
  namespace: apps
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: database
      port: 33060
      targetPort: 33060
  selector:
    app: gateway-backend
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: private-website
  namespace: apps
spec:
  ingressClassName: kind-ci-ingress
  rules:
    - host: private.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ingress-backend
                port:
                  number: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: website
  namespace: apps
  annotations:
    edge.homelab-edge-node.io/expose: "true"
    edge.homelab-edge-node.io/tls: "true"
spec:
  ingressClassName: kind-ci-ingress
  rules:
    - host: ingress.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ingress-backend
                port:
                  number: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: kind-ci-gateway
spec:
  controllerName: ci.example.com/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public
  namespace: apps
spec:
  gatewayClassName: kind-ci-gateway
  listeners:
    - name: web
      hostname: gateway.example.test
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: All
    - name: database
      port: 33060
      protocol: TCP
      allowedRoutes:
        namespaces:
          from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: website
  namespace: apps
  annotations:
    edge.homelab-edge-node.io/expose: "true"
spec:
  parentRefs:
    - name: public
      sectionName: web
  hostnames:
    - gateway.example.test
  rules:
    - backendRefs:
        - name: gateway-backend
          port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: database
  namespace: apps
  annotations:
    edge.homelab-edge-node.io/expose: "true"
spec:
  parentRefs:
    - name: public
      sectionName: database
  rules:
    - backendRefs:
        - name: gateway-backend
          port: 33060
EOF

kubectl -n "$namespace" port-forward service/edge-manager 19443:9443 >"$temporary_directory/port-forward.log" 2>&1 &
port_forward_pid=$!
for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --output /dev/null \
    --cacert "$temporary_directory/ca.crt" \
    --cert "$temporary_directory/client.crt" --key "$temporary_directory/client.key" \
    --resolve edge-manager.homelab-edge-system.svc:19443:127.0.0.1 \
    https://edge-manager.homelab-edge-system.svc:19443/healthz 2>/dev/null; then
    break
  fi
  if [[ $attempt -eq 30 ]]; then
    cat "$temporary_directory/port-forward.log" >&2
    echo 'edge manager API did not become reachable through port-forward' >&2
    exit 1
  fi
  sleep 1
done

snapshot_url=https://edge-manager.homelab-edge-system.svc:19443/v1/sources/ci-kubernetes/exposures
read_snapshot() {
  curl --fail --silent --show-error \
    --cacert "$temporary_directory/ca.crt" \
    --cert "$temporary_directory/client.crt" --key "$temporary_directory/client.key" \
    --resolve edge-manager.homelab-edge-system.svc:19443:127.0.0.1 "$snapshot_url"
}
wait_for_snapshot() {
  expected_count=$1
  for attempt in $(seq 1 60); do
    if read_snapshot >"$temporary_directory/snapshot.json" 2>/dev/null \
      && python3 - "$temporary_directory/snapshot.json" "$expected_count" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as snapshot_file:
    snapshot = json.load(snapshot_file)
raise SystemExit(0 if len(snapshot.get("exposures", [])) == int(sys.argv[2]) else 1)
PY
    then
      return 0
    fi
    sleep 2
  done
  read_snapshot || true
  kubectl -n "$namespace" logs deployment/edge-kubernetes-controller --all-containers=true || true
  echo "timed out waiting for $expected_count published exposures" >&2
  return 1
}

wait_for_snapshot 1
kubectl patch gatewayclass kind-ci-gateway --subresource=status --type=merge \
  -p '{"status":{"conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"}]}}'
kubectl -n apps patch gateway public --subresource=status --type=merge \
  -p '{"status":{"conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"},{"type":"Programmed","status":"True","reason":"Programmed","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"}]}}'
kubectl -n apps patch httproute website --subresource=status --type=merge \
  -p '{"status":{"parents":[{"parentRef":{"name":"public","sectionName":"web"},"controllerName":"ci.example.com/gateway-controller","conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"},{"type":"ResolvedRefs","status":"True","reason":"ResolvedRefs","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"}]}]}}'
kubectl -n apps patch tcproute database --subresource=status --type=merge \
  -p '{"status":{"parents":[{"parentRef":{"name":"public","sectionName":"database"},"controllerName":"ci.example.com/gateway-controller","conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"},{"type":"ResolvedRefs","status":"True","reason":"ResolvedRefs","message":"Kind integration fixture","observedGeneration":1,"lastTransitionTime":"2026-01-01T00:00:00Z"}]}]}}'
wait_for_snapshot 3
python3 - "$temporary_directory/snapshot.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as snapshot_file:
    exposures = json.load(snapshot_file)["exposures"]
by_host = {exposure.get("hostname"): exposure for exposure in exposures if exposure.get("hostname")}
assert set(by_host) == {"ingress.example.test", "gateway.example.test"}, by_host
assert by_host["ingress.example.test"]["targetHost"] == "ingress-backend.apps.svc.cluster.local"
assert by_host["ingress.example.test"]["listenPort"] == 443
assert by_host["ingress.example.test"]["tls"] is True
assert by_host["gateway.example.test"]["targetHost"] == "gateway-backend.apps.svc.cluster.local"
tcp_routes = [exposure for exposure in exposures if exposure["protocol"] == "tcp"]
assert len(tcp_routes) == 1, tcp_routes
assert tcp_routes[0]["listenPort"] == 33060, tcp_routes[0]
assert tcp_routes[0]["targetPort"] == 33060, tcp_routes[0]
assert tcp_routes[0]["mode"] == "direct", tcp_routes[0]
print("Kind controller published Ingress, HTTPRoute, and TCPRoute snapshots over mTLS")
PY

kubectl -n apps delete ingress/website ingress/private-website httproute/website tcproute/database
wait_for_snapshot 0
echo 'Kind controller removed deleted Kubernetes routes from the edge snapshot'
