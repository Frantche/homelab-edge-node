package edge

import "testing"

func TestValidateExposureModeAndPortPolicy(t *testing.T) {
	ports := AllowedPorts{HTTP: {80: {}, 443: {}}, TCP: {6690: {}}}
	cases := []struct {
		name     string
		exposure Exposure
		wantErr  bool
	}{
		{"direct HTTPS", Exposure{ID: "web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.1", TargetPort: 8080}, false},
		{"local-only does not need a pre-authorized edge port", Exposure{ID: "local-web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.20", TargetPort: 8080, LocalDNS: true, LocalOnly: true}, false},
		{"local-only requires local DNS", Exposure{ID: "local-web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.168.1.20", TargetPort: 8080, LocalOnly: true}, true},
		{"local DNS rejects public target", Exposure{ID: "local-web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "8.8.8.8", TargetPort: 8080, LocalDNS: true, LocalOnly: true}, true},
		{"tunnel HTTPS", Exposure{ID: "web", Hostname: "app.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.1", TargetPort: 8080}, false},
		{"Tunnel source CIDRs rejected", Exposure{ID: "web", Hostname: "app.example.test", Protocol: HTTP, Mode: Tunnel, ListenPort: 443, TargetHost: "192.0.2.1", TargetPort: 8080, SourceCIDRs: []string{"192.0.2.0/24"}}, true},
		{"direct TCP", Exposure{ID: "db", Protocol: TCP, Mode: Direct, ListenPort: 6690, TargetHost: "db.example.test", TargetPort: 6690}, false},
		{"TCP port 443 refused", Exposure{ID: "db", Protocol: TCP, Mode: Direct, ListenPort: 443, TargetHost: "db.example.test", TargetPort: 443}, true},
		{"TCP tunnel refused", Exposure{ID: "db", Protocol: TCP, Mode: Tunnel, ListenPort: 6690, TargetHost: "db.example.test", TargetPort: 6690}, true},
		{"UDP removed", Exposure{ID: "game", Protocol: "udp", Mode: Direct, ListenPort: 2456, TargetHost: "192.0.2.1", TargetPort: 2456}, true},
		{"new port refused", Exposure{ID: "other", Protocol: TCP, Mode: Direct, ListenPort: 8443, TargetHost: "192.0.2.1", TargetPort: 8443}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateExposure(tc.exposure, ports); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateExposure() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateSnapshotRejectsDuplicateHostsAndTCPPorts(t *testing.T) {
	base := Exposure{ID: "one", Protocol: HTTP, Mode: Direct, Hostname: "app.example.test", ListenPort: 443, TargetHost: "192.0.2.1", TargetPort: 8080}
	for name, snapshot := range map[string]Snapshot{
		"host":                  {Generation: 1, Exposures: []Exposure{base, {ID: "two", Protocol: HTTP, Mode: Direct, Hostname: "APP.example.test", ListenPort: 443, TargetHost: "192.0.2.2", TargetPort: 8080}}},
		"wildcard host overlap": {Generation: 1, Exposures: []Exposure{{ID: "wildcard", Protocol: HTTP, Mode: Direct, Hostname: "*.example.test", ListenPort: 443, TargetHost: "192.0.2.1", TargetPort: 8080}, {ID: "exact", Protocol: HTTP, Mode: Direct, Hostname: "app.example.test", ListenPort: 443, TargetHost: "192.0.2.2", TargetPort: 8080}}},
		"port":                  {Generation: 1, Exposures: []Exposure{{ID: "one", Protocol: TCP, Mode: Direct, ListenPort: 6690, TargetHost: "192.0.2.1", TargetPort: 1}, {ID: "two", Protocol: TCP, Mode: Direct, ListenPort: 6690, TargetHost: "192.0.2.2", TargetPort: 2}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSnapshot(snapshot, AllowedPorts{HTTP: {443: {}}, TCP: {6690: {}}}); err == nil {
				t.Fatal("expected conflicting snapshot to fail")
			}
		})
	}
}
