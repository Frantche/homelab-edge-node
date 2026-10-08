package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRenderTraefikCombinesDirectHTTPTunnelAndTCP(t *testing.T) {
	owned := []OwnedExposure{
		{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TLS: true, TargetHost: "192.0.2.10", TargetPort: 8080}},
		{Source: "cluster-a", Exposure: Exposure{ID: "tunnel", Hostname: "private.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.11", TargetPort: 8080}},
		{Source: "ansible", Exposure: Exposure{ID: "drive", Protocol: TCP, Mode: Direct, ListenPort: 6690, TargetHost: "2001:db8::1", TargetPort: 6690}},
	}
	content, err := RenderTraefik(owned, RuntimeConfig{ACMEEnabled: true, TunnelEntryPoint: "tunnel-http"})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := yaml.Unmarshal(content, &result); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, content)
	}
	httpConfig := result["http"].(map[string]any)
	routers := httpConfig["routers"].(map[string]any)
	direct := routers[routeName("cluster-a", "site")].(map[string]any)
	if direct["entryPoints"].([]any)[0] != "http-443" || direct["rule"] != "Host(`app.example.test`)" {
		t.Fatalf("direct HTTP router = %#v", direct)
	}
	if direct["tls"].(map[string]any)["certResolver"] != "cloudflare" {
		t.Fatalf("TLS resolver = %#v", direct["tls"])
	}
	tunnel := routers[routeName("cluster-a", "tunnel")].(map[string]any)
	if tunnel["entryPoints"].([]any)[0] != "tunnel-http" {
		t.Fatalf("tunnel router = %#v", tunnel)
	}
	tcp := result["tcp"].(map[string]any)["routers"].(map[string]any)[routeName("ansible", "drive")].(map[string]any)
	if tcp["rule"] != "HostSNI(`*`)" {
		t.Fatalf("TCP router = %#v", tcp)
	}
}

func TestRenderTraefikAddsCrowdSecMiddlewareForHTTP(t *testing.T) {
	content, err := RenderTraefik([]OwnedExposure{{Source: "cluster-a", Exposure: Exposure{
		ID: "web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct,
		ListenPort: 443, TLS: true, TargetHost: "192.0.2.10", TargetPort: 8080,
	}}}, RuntimeConfig{ACMEEnabled: true, CrowdSec: &CrowdSecMiddleware{
		LAPIURL: "http://crowdsec.internal:8080", APIKeyFile: "/run/secrets/crowdsec-key",
		Mode: "stream", UpdateInterval: 10, PluginVersion: "v1.7.1",
		TrustedProxies: []string{"127.0.0.1/32"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := yaml.Unmarshal(content, &result); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, content)
	}
	httpConfig := result["http"].(map[string]any)
	middleware := httpConfig["middlewares"].(map[string]any)["crowdsec"].(map[string]any)
	plugin := middleware["plugin"].(map[string]any)["bouncer"].(map[string]any)
	if plugin["crowdsecLapiHost"] != "http://crowdsec.internal:8080" || plugin["crowdsecLapiKeyFile"] != "/run/secrets/crowdsec-key" || plugin["crowdsecMode"] != "stream" {
		t.Fatalf("CrowdSec middleware config = %#v", plugin)
	}
	if plugin["updateIntervalSeconds"] != 10 || plugin["forwardedHeadersTrustedIPs"].([]any)[0] != "127.0.0.1/32" {
		t.Fatalf("CrowdSec middleware options = %#v", plugin)
	}
}

func TestGlobalValidationRejectsCrossSourceConflicts(t *testing.T) {
	one := OwnedExposure{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "same.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 80}}
	conflicts := []OwnedExposure{
		one,
		{Source: "cluster-b", Exposure: Exposure{ID: "site", Hostname: "same.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.11", TargetPort: 80}},
	}
	if err := ValidateGlobalExposures(conflicts); err == nil {
		t.Fatal("duplicate hostname across owners was accepted")
	}
	tcp := OwnedExposure{Source: "cluster-b", Exposure: Exposure{ID: "raw", Protocol: TCP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.11", TargetPort: 443}}
	if err := ValidateGlobalExposures([]OwnedExposure{one, tcp}); err == nil {
		t.Fatal("HTTP and raw TCP listener conflict was accepted")
	}
}

func TestRenderNFTablesOpensOnlyActiveDirectPortsAndKeepsCrowdSecTableSeparate(t *testing.T) {
	content, err := RenderNFTables([]OwnedExposure{
		{Source: "cluster-a", Exposure: Exposure{ID: "web", Protocol: HTTP, Mode: Direct, ListenPort: 443}},
		{Source: "cluster-a", Exposure: Exposure{ID: "db", Protocol: TCP, Mode: Direct, ListenPort: 6690, SourceCIDRs: []string{"192.0.2.0/24"}}},
		{Source: "cluster-a", Exposure: Exposure{ID: "tunnel", Hostname: "t.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443}},
	}, []string{"192.0.2.0/24"}, []int{22}, []string{"10.10.0.0/16"}, 9443)
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	for _, expected := range []string{"tcp dport 443 ct state new accept", "ip saddr 192.0.2.0/24 tcp dport 6690 ct state new accept", "tcp dport 22 ct state new accept", "ip saddr 10.10.0.0/16 tcp dport 9443 ct state new accept", "table inet homelab_edge"} {
		if !strings.Contains(script, expected) {
			t.Errorf("nft script missing %q", expected)
		}
	}
	if strings.Contains(script, "tcp dport 18080") || strings.Contains(script, "2456") {
		t.Fatalf("unexpected tunnel or UDP listener in nft script:\n%s", script)
	}
	if strings.Contains(script, "destroy table inet crowdsec") || strings.Contains(script, "table inet crowdsec") {
		t.Fatal("route reconciler touched CrowdSec-owned nftables state")
	}
}

func TestReconcileKeepsLastGoodRoutesWhenFirewallValidationFails(t *testing.T) {
	root := t.TempDir()
	fixedPath := filepath.Join(root, "fixed.json")
	if err := os.WriteFile(fixedPath, []byte(`{"generation":1,"exposures":[{"id":"web","hostname":"app.example.test","protocol":"http","mode":"direct","listenPort":443,"targetHost":"192.0.2.10","targetPort":80}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	dynamicPath := filepath.Join(root, "runtime.yml")
	if err := os.WriteFile(dynamicPath, []byte("old-config"), 0600); err != nil {
		t.Fatal(err)
	}
	failingNFT := filepath.Join(root, "nft-fail")
	if err := os.WriteFile(failingNFT, []byte("#!/bin/sh\necho invalid policy >&2\nexit 1\n"), 0750); err != nil {
		t.Fatal(err)
	}
	reconciler := Reconciler{Store: NewSnapshotStore(filepath.Join(root, "sources"), AllowedPorts{HTTP: {443: {}}, TCP: {6690: {}}}), Config: RuntimeConfig{FixedSnapshotFile: fixedPath, DynamicFile: dynamicPath, NFTBinary: failingNFT, AllowedPorts: AllowedPorts{HTTP: {443: {}}, TCP: {6690: {}}}, TunnelEntryPoint: "tunnel-http"}}
	if err := reconciler.Reconcile(t.Context()); err == nil {
		t.Fatal("expected nftables validation to fail")
	}
	content, err := os.ReadFile(dynamicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old-config" {
		t.Fatalf("last good config changed to %q", content)
	}
}

func TestReconcileRejectsTunnelRoutesBeforeActivatingWithoutCloudflare(t *testing.T) {
	root := t.TempDir()
	fixedPath := filepath.Join(root, "fixed.json")
	content := `{"generation":1,"exposures":[{"id":"web","hostname":"app.example.test","protocol":"http","mode":"cloudflare-tunnel","listenPort":443,"targetHost":"192.0.2.10","targetPort":80}]}`
	if err := os.WriteFile(fixedPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	dynamicPath := filepath.Join(root, "runtime.yml")
	if err := os.WriteFile(dynamicPath, []byte("last-good"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed := AllowedPorts{HTTP: {443: {}}, TCP: {}}
	reconciler := Reconciler{Store: NewSnapshotStore(filepath.Join(root, "sources"), allowed), Config: RuntimeConfig{
		FixedSnapshotFile: fixedPath,
		DynamicFile:       dynamicPath,
		AllowedPorts:      allowed,
		TunnelEntryPoint:  "",
	}}
	if err := reconciler.Reconcile(t.Context()); err == nil || !strings.Contains(err.Error(), "requires enabled DNS/Tunnel publication") {
		t.Fatalf("Reconcile error = %v, want Cloudflare Tunnel preflight failure", err)
	}
	actual, err := os.ReadFile(dynamicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "last-good" {
		t.Fatalf("dynamic config changed before Cloudflare preflight: %q", actual)
	}
}

func TestReconcileRejectsDirectCloudflareRouteWithoutPublicAddress(t *testing.T) {
	root := t.TempDir()
	fixedPath := filepath.Join(root, "fixed.json")
	content := `{"generation":1,"exposures":[{"id":"web","hostname":"app.example.test","protocol":"http","mode":"direct","listenPort":443,"tls":true,"targetHost":"192.0.2.10","targetPort":80}]}`
	if err := os.WriteFile(fixedPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	dynamicPath := filepath.Join(root, "runtime.yml")
	if err := os.WriteFile(dynamicPath, []byte("last-good"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed := AllowedPorts{HTTP: {443: {}}, TCP: {}}
	reconciler := Reconciler{Store: NewSnapshotStore(filepath.Join(root, "sources"), allowed), Config: RuntimeConfig{
		FixedSnapshotFile: fixedPath,
		DynamicFile:       dynamicPath,
		AllowedPorts:      allowed,
		Cloudflare:        &CloudflareConfig{Enabled: true, ZoneID: "zone", TokenFile: "/unused"},
	}}
	if err := reconciler.Reconcile(t.Context()); err == nil || !strings.Contains(err.Error(), "requires a Cloudflare public IPv4 or IPv6") {
		t.Fatalf("Reconcile error = %v, want missing-public-address preflight failure", err)
	}
	actual, err := os.ReadFile(dynamicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "last-good" {
		t.Fatalf("dynamic config changed before Cloudflare preflight: %q", actual)
	}
}
