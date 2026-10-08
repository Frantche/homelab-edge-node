# homelab-edge-node

`homelab-edge-node` turns a dedicated Arch Linux host into the reverse proxy for
a homelab. It combines fixed Ansible routes with dynamic routes published by a
small controller running inside Kubernetes. It can publish HTTP services
through a router port forward or a Cloudflare Tunnel, and TCP services through
a direct router port forward.

The edge host does not receive Kubernetes credentials and does not read the
Kubernetes API. The controller reads route resources in the cluster and pushes
a complete, replaceable route snapshot to the edge over mutually authenticated
HTTPS. UDP is not supported.

## Exposure model

| Route | Internet path | Domain and DNS | Cleanup |
| --- | --- | --- | --- |
| HTTP, direct | Router forwards the chosen TCP port to the edge | HTTP host required; optional Cloudflare A/AAAA records are DNS-only | Removing the route removes its manager-owned Cloudflare records |
| HTTP, Cloudflare Tunnel | `cloudflared` to a loopback-only Traefik entrypoint | HTTP host required; manager-owned proxied CNAME and Tunnel ingress rule | Removing the route removes the CNAME and Tunnel ingress rule |
| TCP, direct | Router forwards a pre-authorized TCP port to the edge | No domain is carried by TCP; callers use the edge host and port | Removing the route removes its firewall allowance |
| UDP | Unsupported | — | — |

HTTP listener ports and direct TCP ports are pre-authorized by Ansible. A
Kubernetes route cannot open a new port by itself. The manager only permits
active direct routes in nftables. Cloudflare Tunnel is for HTTP and always uses
public port 443; TCP is direct only.

## Fixed routes with Ansible

Set `edge_allowed_http_ports` and `edge_allowed_tcp_ports` to the ports the edge
may serve, then declare fixed routes in `edge_services`:

```yaml
edge_allowed_http_ports: [80, 443]
edge_allowed_tcp_ports: [6690]

edge_services:
  jellyfin:
    exposure: https
    hostname: jellyfin.example.net
    listen:
      ports: [443]
    destination:
      host: 192.168.10.50
      port: 8096
      protocol: http
  synology-drive:
    exposure: tcp
    listen:
      ports: [6690]
    destination:
      host: 192.168.10.10
      port: 6690
      protocol: tcp
```

`http` and `https` routes require `hostname`; `tcp` routes do not accept one.
HTTP services may set `mode: cloudflare-tunnel`; this requires Cloudflare
publication, uses public port 443 and does not accept source CIDRs. The mode
defaults to `direct`. Port ranges are expanded to individual ports and are
limited to 1024 ports per declaration. The role rejects UDP, conflicting
listeners and routes on direct ports that have not been pre-authorized.

## Kubernetes publication

The controller supports Kubernetes `Ingress`, Gateway API `HTTPRoute`, and
Gateway API `TCPRoute`. A route is published only when it has the opt-in
annotation `edge.homelab-edge-node.io/expose: "true"`. Ingress and Gateway API
routes are resolved to an address and port for the in-cluster Ingress or
Gateway listener; the edge then proxies to that address. `TCPRoute` requires
the Gateway API TCPRoute CRD and is direct only. TCP cannot use port 443.

### Prepare the edge

In the private Ansible inventory, allow the ports and one publication source.
Use the source name `edge-kubernetes` to match the sample manifests:

```yaml
edge_allowed_http_ports: [80, 443]
edge_allowed_tcp_ports: [33060]
edge_publication_sources: [edge-kubernetes]
edge_publication_api_port: 9443
edge_publication_api_cidrs:
  - 10.42.0.0/16 # Replace with the source CIDR seen by the edge
edge_publication_api_server_name: edge-api.example.net
edge_publication_server_sans:
  - DNS:edge-api.example.net
  - IP:192.168.10.20 # Include this only if clients use the IP in edgeURL
```

`edge_publication_api_cidrs` is separate from `edge_management_cidrs`: adding
the cluster network opens only the mTLS API port, not SSH. Choose the source
CIDR that the edge actually sees after any cluster egress NAT. The edge role
creates a local CA and one client certificate per authorized source under
`/etc/homelab-edge-node/secrets/pki/`. It keeps `ca.key` on the edge and mounts
only the API server certificate, server key and CA certificate into the
manager.

Securely transfer `client-edge-kubernetes.crt`,
`client-edge-kubernetes.key`, and `ca.crt` from the edge to the operator
workstation. Create the Kubernetes Secret there; the command pipes the
generated manifest straight to the API and does not print key material:

```sh
kubectl -n homelab-edge-system create secret generic edge-publication-client-tls \
  --from-file=tls.crt=client-edge-kubernetes.crt \
  --from-file=tls.key=client-edge-kubernetes.key \
  --from-file=ca.crt=ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
```

Treat the client key as a credential. Removing a source from
`edge_publication_sources` immediately removes its stored snapshot when the
manager restarts and rejects its certificate. Re-running Ansible also removes
the corresponding client key and certificate from the edge. Client
certificates and the local CA are valid for ten years and are not silently
rotated, because the cluster Secret is managed separately. Rotate a client
certificate by removing that source's `client-<source>.key`, `.csr`, and `.crt`
from the edge PKI directory, converging Ansible to issue a new pair, then
securely transferring the new certificate and key and updating the Kubernetes
Secret. Rotate the CA only when all controller Secrets and the API server trust
bundle can be updated together.

### Install the cluster controller

The repository provides a read-only ClusterRole and a single Deployment in
[`deploy/kubernetes`](deploy/kubernetes). The ClusterRole can list Ingress,
Gateway, HTTPRoute and TCPRoute objects; it cannot change them or read Secrets.
The controller reads the projected Kubernetes service-account token and
refreshes it as Kubernetes rotates the token.

Edit `deploy/kubernetes/configmap.yaml` before applying it:

- set `edgeURL` to the edge API hostname and port; its name/IP must match the
  API server certificate SAN;
- set `gatewayAPIEnabled: true` after installing the standard Gateway API CRDs;
- set `tcpRouteEnabled: true` only after installing the TCPRoute CRD;
- configure `ingressTargets` by `IngressClass` name and `gatewayTargets` by
  `GatewayClass` name when resource status does not contain a reachable
  address.

The target profile shape is `{address, port, tls}`. `tls` describes whether the
edge should use HTTPS to reach that in-cluster listener. For an Ingress without
a configured target, the controller uses its `status.loadBalancer` address and
port 80. For a Gateway without a configured target, it uses the Gateway status
address and the matching HTTP/HTTPS listener.

The release workflow publishes a multi-architecture image when a `vX.Y.Z` tag
is pushed. After publishing the `v0.3.0` release, make the GHCR package public
or add an `imagePullSecret` to the Deployment if the package is private, then
apply the manifests:

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
```

### Opt in routes

Example Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: photos
  namespace: apps
  annotations:
    edge.homelab-edge-node.io/expose: "true"
    edge.homelab-edge-node.io/mode: direct
    edge.homelab-edge-node.io/listen-port: "443"
    edge.homelab-edge-node.io/tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: photos.example.net
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: photos
                port:
                  number: 8080
```

For Gateway API, annotate the `HTTPRoute` the same way; its hostnames and
accepted parent Gateway determine the edge route. Set `mode:
cloudflare-tunnel` to use the Cloudflare path. A Tunnel route uses public port
443, plain HTTP from `cloudflared` to Traefik, and a manager-owned Cloudflare
Tunnel hostname rule. Omit `tls` for Tunnel routes.

For an experimental `TCPRoute`, use `expose: "true"`, an accepted parent
Gateway with a TCP listener, and optionally `listen-port` to choose a different
pre-authorized edge port. The controller forwards to the Gateway listener
port. TCP has no hostname, cannot use a Tunnel, cannot use port 443, and only
works when its port has been listed under `edge_allowed_tcp_ports`.

The controller polls the Kubernetes API every 30 seconds by default. It sends
an empty snapshot when opted-in routes are removed, so the edge removes the
route and its external state. A full Kubernetes API read must succeed before a
snapshot is published; transient API failures never publish a partial route
set.

## Cloudflare DNS and Tunnel

When `edge_cloudflare_publication_enabled` is enabled, the edge manager
reconciles Cloudflare DNS for both Ansible and Kubernetes HTTP routes. Direct
routes create unproxied A and/or AAAA records using
`edge_cloudflare_public_ipv4` and `edge_cloudflare_public_ipv6`. Set the
router's port forward to the edge. The Cloudflare token file must have DNS edit
permission for the configured zone.

For HTTP Tunnel routes, also set `edge_cloudflare_tunnel_enabled`,
`edge_cloudflare_tunnel_id`, `edge_cloudflare_account_id`, and the
`edge_cloudflare_tunnel_token_file`. The token used by the manager needs zone
DNS edit and Tunnel configuration write permissions. The edge runs
`cloudflared`; the manager creates proxied CNAME records and updates the
Tunnel's ingress configuration. Existing Tunnel routes and global origin
settings are preserved; an overlapping hostname owned by another route causes
reconciliation to fail before the Tunnel configuration is changed. TCP cannot
use this mode.

Only Cloudflare records marked `managed-by=homelab-edge-node` are modified or
deleted. Existing unowned conflicting records cause reconciliation to fail
without overwriting them. Keep Cloudflare publication enabled and retain the
Tunnel account and ID while removing routes so the manager can delete its old
records and Tunnel rules.

Dynamic snapshots have a lease controlled by
`edge_publication_source_ttl_seconds` (24 hours by default). The controller
refreshes its snapshot during each poll. If it disappears without publishing
an empty snapshot, the lease expires and the edge withdraws its routes, DNS
records and Tunnel rules at the next reconciliation. Fixed Ansible routes are
removed when `edge_services` changes and Ansible converges.

## CrowdSec

`edge_crowdsec_enabled` adds the CrowdSec Traefik plugin to HTTP routes. It uses
the key file at `edge_crowdsec_traefik_key_file`. For direct TCP exposure,
`edge_crowdsec_firewall_enabled` installs the pinned CrowdSec firewall bouncer
and uses a separate key file at `edge_crowdsec_firewall_key_file`. Create
separate bouncer credentials for the plugin and firewall bouncer. The firewall
bouncer owns its `crowdsec` and `crowdsec6` nftables tables; the edge manager
only replaces `inet homelab_edge`.

## Observability and bootstrap

Set `edge_observability.enabled` to deploy a pinned OpenTelemetry Collector
without Docker API access. It exports host and Traefik metrics and structured
logs over separate OTLP/HTTP endpoints. Production endpoints must use HTTPS;
optional exporter headers belong in the SOPS-encrypted private configuration.

The collection supports Arch Linux and uses the existing bootstrap script:

```sh
sudo EDGE_CONFIG_REPO_URL=git@github.com:Frantche/homelab-edge-node-config.git \
  ./scripts/bootstrap.sh
```

## Tests

`make quality` runs Python filter tests, Go unit and API tests, Go vet/build,
the container build, YAML and Ansible linting, shellcheck, collection rendering
and container configuration validation. The GitHub Actions bootstrap job
starts a fresh Arch Linux VM and tests fixed HTTPS/TCP routes, mTLS dynamic TCP
publication and cleanup, nftables synchronization, observability, idempotent
Ansible convergence and container hardening. Cloudflare calls use a mocked API
in the Go tests; no live Cloudflare zone is required for CI.
