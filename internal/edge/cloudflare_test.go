package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudflareReconcileCreatesIdempotentlyAndDeletesOnlyOwnedRecords(t *testing.T) {
	records := []cloudflareDNSRecord{}
	created, deleted := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Cloudflare Authorization header was not set")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone/dns_records":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": records, "result_info": map[string]any{"total_pages": 1}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone/dns_records":
			var record cloudflareDNSRecord
			if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
				t.Errorf("decode create body: %v", err)
			}
			record.ID = fmt.Sprintf("record-%d", created+1)
			records = append(records, record)
			created++
			writeCloudflareResult(w, record)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone/dns_records/")
			filtered := records[:0]
			for _, record := range records {
				if record.ID != id {
					filtered = append(filtered, record)
				}
			}
			records = filtered
			deleted++
			writeCloudflareResult(w, map[string]string{"id": id})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := testCloudflareClient(t, server.URL)
	client.Config.PublicIPv6 = "2001:db8::10"
	owned := []OwnedExposure{
		{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.20", TargetPort: 8080, LocalDNS: true}},
		{Source: "cluster-a", Exposure: Exposure{ID: "local-only", Hostname: "local.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.40", TargetPort: 443, LocalDNS: true, LocalOnly: true}},
	}
	if err := client.Reconcile(context.Background(), owned); err != nil {
		t.Fatal(err)
	}
	if err := client.Reconcile(context.Background(), owned); err != nil {
		t.Fatal(err)
	}
	if created != 2 || len(records) != 2 {
		t.Fatalf("created=%d records=%d, want idempotent A and AAAA records", created, len(records))
	}
	if records[0].Type != "A" || records[0].Content != "198.51.100.10" || records[0].Proxied || records[0].Comment != cloudflareManagedComment {
		t.Fatalf("direct A record = %#v", records[0])
	}
	if records[1].Type != "AAAA" || records[1].Content != "2001:db8::10" || records[1].Proxied {
		t.Fatalf("direct AAAA record = %#v", records[1])
	}
	if err := client.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if deleted != 2 || len(records) != 0 {
		t.Fatalf("deleted=%d records=%d, want owned A and AAAA records removed", deleted, len(records))
	}
}

func TestCloudflareRefusesToOverwriteUnownedRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeCloudflareEnvelope(w, []cloudflareDNSRecord{{ID: "human", Type: "A", Name: "app.example.test", Content: "203.0.113.7"}})
			return
		}
		t.Errorf("unexpected mutation request %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := testCloudflareClient(t, server.URL)
	err := client.Reconcile(context.Background(), []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 80}}})
	if err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("error = %v, want an ownership conflict", err)
	}
}

func TestCloudflareTunnelConfigurationAndDNS(t *testing.T) {
	tunnelConfig := map[string]any{"config": map[string]any{
		"ingress": []any{
			map[string]any{"hostname": "legacy.example.test", "service": "http://192.0.2.50"},
			map[string]any{"service": "http_status:410"},
		},
		"originRequest": map[string]any{"connectTimeout": 30},
	}}
	records := []cloudflareDNSRecord{}
	deleted := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/accounts/account/cfd_tunnel/tunnel/configurations":
			writeCloudflareResult(w, tunnelConfig)
		case r.Method == http.MethodPut && r.URL.Path == "/accounts/account/cfd_tunnel/tunnel/configurations":
			if err := json.NewDecoder(r.Body).Decode(&tunnelConfig); err != nil {
				t.Errorf("decode tunnel config: %v", err)
			}
			writeCloudflareResult(w, tunnelConfig)
		case r.Method == http.MethodGet:
			writeCloudflareEnvelope(w, records)
		case r.Method == http.MethodPost:
			var record cloudflareDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&record)
			if record.Type != "CNAME" || record.Content != "tunnel.cfargotunnel.com" || !record.Proxied {
				t.Errorf("tunnel DNS record = %#v", record)
			}
			record.ID = "tunnel-record"
			records = append(records, record)
			writeCloudflareResult(w, record)
		case r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone/dns_records/")
			filtered := records[:0]
			for _, record := range records {
				if record.ID != id {
					filtered = append(filtered, record)
				}
			}
			records = filtered
			deleted++
			writeCloudflareResult(w, map[string]string{"id": id})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := testCloudflareClient(t, server.URL)
	client.Config.AccountID = "account"
	client.Config.TunnelID = "tunnel"
	client.Config.TunnelOriginPort = 18080
	owned := []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 8080}}}
	if err := client.Reconcile(context.Background(), owned); err != nil {
		t.Fatal(err)
	}
	config := tunnelConfig["config"].(map[string]any)
	ingress := config["ingress"].([]any)
	first := ingress[0].(map[string]any)
	if first["hostname"] != "legacy.example.test" || first["service"] != "http://192.0.2.50" {
		t.Fatalf("pre-existing tunnel ingress rule was not preserved: %#v", first)
	}
	second := ingress[1].(map[string]any)
	if second["hostname"] != "app.example.test" || second["service"] != "http://127.0.0.1:18080" {
		t.Fatalf("tunnel ingress rule = %#v", second)
	}
	if ingress[len(ingress)-1].(map[string]any)["service"] != "http_status:410" {
		t.Fatal("pre-existing Tunnel catch-all rule must remain last")
	}
	if config["originRequest"].(map[string]any)["connectTimeout"] != float64(30) {
		t.Fatalf("pre-existing tunnel originRequest settings were not preserved: %#v", config["originRequest"])
	}
	if err := client.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	config = tunnelConfig["config"].(map[string]any)
	ingress = config["ingress"].([]any)
	if len(ingress) != 2 || ingress[0].(map[string]any)["hostname"] != "legacy.example.test" || ingress[1].(map[string]any)["service"] != "http_status:410" {
		t.Fatalf("cleanup did not retain pre-existing tunnel rules: %#v", ingress)
	}
	if deleted != 1 || len(records) != 0 {
		t.Fatalf("tunnel cleanup deleted=%d records=%d, want one owned CNAME removed", deleted, len(records))
	}
}

func TestCloudflareTunnelRefusesUnownedDNSConflictBeforeUpdatingTunnel(t *testing.T) {
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones/"):
			writeCloudflareEnvelope(w, []cloudflareDNSRecord{{ID: "human", Type: "A", Name: "app.example.test", Content: "203.0.113.7"}})
		case r.Method == http.MethodPut:
			puts++
			t.Errorf("unexpected Tunnel mutation before DNS conflict was rejected")
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := testCloudflareClient(t, server.URL)
	client.Config.AccountID = "account"
	client.Config.TunnelID = "tunnel"
	client.Config.TunnelOriginPort = 18080
	err := client.Reconcile(context.Background(), []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 80}}})
	if err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("error = %v, want an ownership conflict", err)
	}
	if puts != 0 {
		t.Fatalf("tunnel updates = %d, want none", puts)
	}
}

func TestCloudflareTunnelRefusesUnownedIngressHostnameConflict(t *testing.T) {
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones/"):
			writeCloudflareEnvelope(w, []cloudflareDNSRecord{})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/accounts/"):
			writeCloudflareResult(w, map[string]any{"config": map[string]any{"ingress": []any{
				map[string]any{"hostname": "app.example.test", "service": "http://192.0.2.20"},
				map[string]any{"service": "http_status:404"},
			}}})
		case r.Method == http.MethodPut:
			puts++
			t.Errorf("unexpected Tunnel mutation over an unowned hostname")
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := testCloudflareClient(t, server.URL)
	client.Config.AccountID = "account"
	client.Config.TunnelID = "tunnel"
	client.Config.TunnelOriginPort = 18080
	err := client.Reconcile(context.Background(), []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "app.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 80}}})
	if err == nil || !strings.Contains(err.Error(), "not managed by this edge") {
		t.Fatalf("error = %v, want an unowned Tunnel hostname conflict", err)
	}
	if puts != 0 {
		t.Fatalf("tunnel updates = %d, want none", puts)
	}
}

func testCloudflareClient(t *testing.T, baseURL string) *CloudflareClient {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "cf-token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	return &CloudflareClient{Config: CloudflareConfig{TokenFile: tokenFile, ZoneID: "zone", PublicIPv4: "198.51.100.10", APIBaseURL: baseURL}, HTTP: http.DefaultClient}
}

func writeCloudflareResult(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}

func writeCloudflareEnvelope(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]any{"total_pages": 1}})
}
