package kubecontroller

import (
	"testing"

	"github.com/Frantche/homelab-edge-node/internal/edge"
)

func TestBuildSnapshotPublishesIngressGatewayHTTPAndDirectTCP(t *testing.T) {
	config := Config{Source: "cluster-a", DefaultMode: edge.Direct, GatewayAPIEnabled: true, TCPRouteEnabled: true,
		IngressTargets: map[string]TargetProfile{"traefik": {Address: "192.0.2.10", Port: 80}},
		GatewayTargets: map[string]TargetProfile{"edge-gateway": {Address: "192.0.2.20", Port: 8080}}}
	var ingress Ingress
	ingress.Metadata = Metadata{Name: "web", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true", AnnotationSourceCIDRs: "192.0.2.8/24"}}
	ingress.Spec.IngressClassName = "traefik"
	ingress.Spec.Rules = append(ingress.Spec.Rules, struct {
		Host string `json:"host"`
	}{Host: "web.example.test"})

	var gateway Gateway
	gateway.Metadata = Metadata{Name: "public", Namespace: "apps"}
	gateway.Spec.GatewayClassName = "edge-gateway"
	gateway.Spec.Listeners = append(gateway.Spec.Listeners,
		struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hostname string `json:"hostname"`
		}{Name: "web", Port: 80, Protocol: "HTTP"},
		struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hostname string `json:"hostname"`
		}{Name: "db", Port: 5432, Protocol: "TCP"},
	)
	gateway.Status.Conditions = []Condition{{Type: "Accepted", Status: "True"}, {Type: "Programmed", Status: "True"}}
	gateway.Status.Addresses = append(gateway.Status.Addresses, struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}{Type: "IPAddress", Value: "192.0.2.20"})

	parent := ParentRef{Name: "public"}
	httpRoute := HTTPRoute{Metadata: Metadata{Name: "site", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true", AnnotationMode: "cloudflare-tunnel"}}}
	httpRoute.Spec.ParentRefs = []ParentRef{parent}
	httpRoute.Spec.Hostnames = []string{"site.example.test"}
	httpRoute.Status.Parents = []ParentStatus{{ParentRef: parent, Conditions: []Condition{{Type: "Accepted", Status: "True"}, {Type: "ResolvedRefs", Status: "True"}}}}
	tcpRoute := TCPRoute{Metadata: Metadata{Name: "database", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true"}}}
	tcpRoute.Spec.ParentRefs = []ParentRef{{Name: "public", SectionName: stringPointer("db")}}
	tcpRoute.Status.Parents = []ParentStatus{{ParentRef: tcpRoute.Spec.ParentRefs[0], Conditions: []Condition{{Type: "Accepted", Status: "True"}, {Type: "ResolvedRefs", Status: "True"}}}}

	snapshot, err := BuildSnapshot(config, []Ingress{ingress}, []Gateway{gateway}, []HTTPRoute{httpRoute}, []TCPRoute{tcpRoute})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Exposures) != 3 {
		t.Fatalf("exposures = %#v, want Ingress, HTTPRoute and TCPRoute", snapshot.Exposures)
	}
	byProtocol := map[edge.Protocol][]edge.Exposure{}
	for _, exposure := range snapshot.Exposures {
		byProtocol[exposure.Protocol] = append(byProtocol[exposure.Protocol], exposure)
	}
	if got := byProtocol[edge.HTTP]; len(got) != 2 {
		t.Fatalf("HTTP exposures = %#v", got)
	}
	var tunnel, ingressExposure *edge.Exposure
	for i := range byProtocol[edge.HTTP] {
		if byProtocol[edge.HTTP][i].Mode == edge.Tunnel {
			tunnel = &byProtocol[edge.HTTP][i]
		} else {
			ingressExposure = &byProtocol[edge.HTTP][i]
		}
	}
	if tunnel == nil || tunnel.TLS || tunnel.ListenPort != 443 || tunnel.Hostname != "site.example.test" {
		t.Fatalf("Tunnel HTTP exposure = %#v", tunnel)
	}
	if ingressExposure == nil || ingressExposure.TargetHost != "192.0.2.10" || ingressExposure.SourceCIDRs[0] != "192.0.2.0/24" || !ingressExposure.TLS {
		t.Fatalf("Ingress exposure = %#v", ingressExposure)
	}
	tcp := byProtocol[edge.TCP][0]
	if tcp.Hostname != "" || tcp.Mode != edge.Direct || tcp.ListenPort != 5432 || tcp.TargetPort != 5432 {
		t.Fatalf("TCP exposure = %#v", tcp)
	}
}

func TestBuildSnapshotDoesNotPublishUnadmittedRoutes(t *testing.T) {
	config := Config{Source: "cluster-a", GatewayAPIEnabled: true}
	route := HTTPRoute{Metadata: Metadata{Name: "site", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true"}}}
	route.Spec.ParentRefs = []ParentRef{{Name: "gateway"}}
	route.Spec.Hostnames = []string{"site.example.test"}
	snapshot, err := BuildSnapshot(config, nil, nil, []HTTPRoute{route}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Exposures) != 0 {
		t.Fatalf("unadmitted route exposures = %#v", snapshot.Exposures)
	}
}

func TestBuildSnapshotSupportsLocalOnlyIngressWithoutOpeningEdgePort(t *testing.T) {
	var ingress Ingress
	ingress.Metadata = Metadata{Name: "private", Namespace: "apps", Annotations: map[string]string{AnnotationLocal: "true"}}
	ingress.Spec.IngressClassName = "private-ingress"
	ingress.Spec.Rules = append(ingress.Spec.Rules, struct {
		Host string `json:"host"`
	}{Host: "private.example.test"})
	config := Config{Source: "cluster-a", DefaultMode: edge.Tunnel, IngressTargets: map[string]TargetProfile{"private-ingress": {Address: "192.168.1.40", Port: 443}}}
	snapshot, err := BuildSnapshot(config, []Ingress{ingress}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Exposures) != 1 {
		t.Fatalf("exposures = %#v", snapshot.Exposures)
	}
	got := snapshot.Exposures[0]
	if !got.LocalDNS || !got.LocalOnly || got.Mode != edge.Direct || got.Hostname != "private.example.test" || got.TargetHost != "192.168.1.40" {
		t.Fatalf("local-only exposure = %#v", got)
	}
}

func TestBuildSnapshotRequiresResolvedRefsBeforePublishingHTTPRoute(t *testing.T) {
	config := Config{Source: "cluster-a", GatewayAPIEnabled: true}
	gateway := testGateway()
	route := testHTTPRoute()
	route.Status.Parents[0].Conditions = []Condition{{Type: "Accepted", Status: "True"}}
	snapshot, err := BuildSnapshot(config, nil, []Gateway{gateway}, []HTTPRoute{route}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Exposures) != 0 {
		t.Fatalf("HTTPRoute with unresolved references was published: %#v", snapshot.Exposures)
	}
}

func TestBuildSnapshotRejectsOptedInIngressWithoutTarget(t *testing.T) {
	ingress := Ingress{Metadata: Metadata{Name: "web", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true"}}}
	ingress.Spec.Rules = append(ingress.Spec.Rules, struct {
		Host string `json:"host"`
	}{Host: "web.example.test"})
	if _, err := BuildSnapshot(Config{Source: "cluster-a"}, []Ingress{ingress}, nil, nil, nil); err == nil {
		t.Fatal("Ingress without a configured target or status address was accepted")
	}
}

func TestBuildSnapshotRejectsTunnelModeForTCPRoute(t *testing.T) {
	parent := ParentRef{Name: "public", SectionName: stringPointer("sql")}
	route := TCPRoute{Metadata: Metadata{Name: "database", Namespace: "apps", Annotations: map[string]string{
		AnnotationExpose: "true",
		AnnotationMode:   string(edge.Tunnel),
	}}}
	route.Spec.ParentRefs = []ParentRef{parent}
	route.Status.Parents = []ParentStatus{{ParentRef: parent, Conditions: []Condition{{Type: "Accepted", Status: "True"}, {Type: "ResolvedRefs", Status: "True"}}}}
	if _, err := BuildSnapshot(Config{Source: "cluster-a", GatewayAPIEnabled: true, TCPRouteEnabled: true}, nil, []Gateway{testGateway()}, nil, []TCPRoute{route}); err == nil {
		t.Fatal("TCPRoute with Cloudflare Tunnel mode was accepted")
	}
}

func stringPointer(value string) *string { return &value }

func testGateway() Gateway {
	var gateway Gateway
	gateway.Metadata = Metadata{Name: "public", Namespace: "apps"}
	gateway.Spec.GatewayClassName = "edge-gateway"
	gateway.Spec.Listeners = append(gateway.Spec.Listeners,
		struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hostname string `json:"hostname"`
		}{Name: "web", Port: 80, Protocol: "HTTP"},
		struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hostname string `json:"hostname"`
		}{Name: "sql", Port: 5432, Protocol: "TCP"},
	)
	gateway.Status.Conditions = []Condition{{Type: "Accepted", Status: "True"}, {Type: "Programmed", Status: "True"}}
	gateway.Status.Addresses = append(gateway.Status.Addresses, struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}{Type: "IPAddress", Value: "192.0.2.20"})
	return gateway
}

func testHTTPRoute() HTTPRoute {
	parent := ParentRef{Name: "public"}
	route := HTTPRoute{Metadata: Metadata{Name: "site", Namespace: "apps", Annotations: map[string]string{AnnotationExpose: "true"}}}
	route.Spec.ParentRefs = []ParentRef{parent}
	route.Spec.Hostnames = []string{"site.example.test"}
	route.Status.Parents = []ParentStatus{{ParentRef: parent, Conditions: []Condition{{Type: "Accepted", Status: "True"}, {Type: "ResolvedRefs", Status: "True"}}}}
	return route
}
