package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalDNSReconcilesRecordsAndPreservesUnmanagedEntries(t *testing.T) {
	for _, provider := range []string{"adguard", "pihole"} {
		t.Run(provider, func(t *testing.T) {
			records := map[string]string{"manual.example.test": "192.168.1.10"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if provider == "adguard" {
					user, pass, ok := r.BasicAuth()
					if !ok || user != "admin" || pass != "password" {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					switch r.URL.Path {
					case "/control/rewrite/list":
						list := make([]map[string]string, 0, len(records))
						for host, ip := range records {
							list = append(list, map[string]string{"domain": host, "answer": ip})
						}
						_ = json.NewEncoder(w).Encode(list)
					case "/control/rewrite/add", "/control/rewrite/delete":
						var record struct {
							Domain string `json:"domain"`
							Answer string `json:"answer"`
						}
						_ = json.NewDecoder(r.Body).Decode(&record)
						if r.URL.Path == "/control/rewrite/add" {
							records[record.Domain] = record.Answer
						} else {
							delete(records, record.Domain)
						}
						w.WriteHeader(http.StatusOK)
					default:
						http.NotFound(w, r)
					}
					return
				}
				if r.URL.Path == "/api/auth" {
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if body["password"] != "password" {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]string{"sid": "session"}})
					return
				}
				if r.Header.Get("X-FTL-SID") != "session" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/config":
					hosts := make([]string, 0, len(records))
					for host, ip := range records {
						hosts = append(hosts, ip+" "+host)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": hosts}}})
				case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(r.URL.Path, "/api/config/dns/hosts/"):
					entry := strings.TrimPrefix(r.URL.Path, "/api/config/dns/hosts/")
					fields := strings.Fields(entry)
					if len(fields) >= 2 {
						if r.Method == http.MethodPut {
							records[fields[1]] = fields[0]
						} else {
							delete(records, fields[1])
						}
					}
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			root := t.TempDir()
			passwordFile := filepath.Join(root, "password")
			if err := os.WriteFile(passwordFile, []byte("password"), 0600); err != nil {
				t.Fatal(err)
			}
			client := LocalDNSClient{Config: LocalDNSConfig{Provider: provider, BaseURL: server.URL, Username: "admin", PasswordFile: passwordFile, StateFile: filepath.Join(root, "state.json")}}
			owned := []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "site.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.20", TargetPort: 443, LocalDNS: true}}}
			if err := client.Reconcile(t.Context(), owned); err != nil {
				t.Fatal(err)
			}
			if records["site.example.test"] != "192.168.1.20" {
				t.Fatalf("record after create = %#v", records)
			}
			owned[0].Exposure.TargetHost = "192.168.1.21"
			if err := client.Reconcile(t.Context(), owned); err != nil {
				t.Fatal(err)
			}
			if records["site.example.test"] != "192.168.1.21" {
				t.Fatalf("record after update = %#v", records)
			}
			if err := client.Reconcile(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			if _, exists := records["site.example.test"]; exists {
				t.Fatalf("managed record was not removed: %#v", records)
			}
			if records["manual.example.test"] != "192.168.1.10" {
				t.Fatalf("unmanaged record changed: %#v", records)
			}
		})
	}
}

func TestLocalDNSRejectsUnmanagedHostnameConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"domain":"site.example.test","answer":"192.168.1.30"}]`))
	}))
	defer server.Close()
	root := t.TempDir()
	passwordFile := filepath.Join(root, "password")
	if err := os.WriteFile(passwordFile, []byte("password"), 0600); err != nil {
		t.Fatal(err)
	}
	client := LocalDNSClient{Config: LocalDNSConfig{Provider: "adguard", BaseURL: server.URL, Username: "admin", PasswordFile: passwordFile, StateFile: filepath.Join(root, "state.json")}}
	owned := []OwnedExposure{{Source: "cluster-a", Exposure: Exposure{ID: "site", Hostname: "site.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.20", TargetPort: 443, LocalDNS: true}}}
	// The handler returns an existing rewrite with the requested hostname.
	client.HTTP = server.Client()
	if err := client.Reconcile(t.Context(), owned); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("Reconcile() error = %v, want unmanaged-record conflict", err)
	}
}
