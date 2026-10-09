package edge

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIRequiresMatchingClientIdentityAndAppliesMonotonicSnapshots(t *testing.T) {
	store := NewSnapshotStore(filepath.Join(t.TempDir(), "sources"), AllowedPorts{HTTP: {443: {}}, TCP: {6690: {}}})
	api := &API{Store: store, AllowedPorts: map[Protocol][]int{HTTP: {443}, TCP: {6690}}, AllowedSources: map[string]struct{}{"cluster-a": {}}}
	handler := api.Handler()
	snapshot := Snapshot{Generation: 1, Exposures: []Exposure{{ID: "web", Hostname: "app.example.test", Protocol: HTTP, Mode: Direct, ListenPort: 443, TargetHost: "192.0.2.10", TargetPort: 8080}}}
	body, _ := json.Marshal(snapshot)

	request := httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(string(body)))
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthenticated.Code)
	}

	request = httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-b/exposures", strings.NewReader(string(body)))
	request.TLS = peerCertificate("cluster-b")
	wrongSource := httptest.NewRecorder()
	handler.ServeHTTP(wrongSource, request)
	if wrongSource.Code != http.StatusForbidden {
		t.Fatalf("unauthorized source status = %d, want 403", wrongSource.Code)
	}

	request = httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(string(body)))
	request.TLS = peerCertificate("cluster-a")
	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, request)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("accepted snapshot status = %d, want 202: %s", accepted.Code, accepted.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(string(body)))
	request.TLS = peerCertificate("cluster-a")
	heartbeat := httptest.NewRecorder()
	handler.ServeHTTP(heartbeat, request)
	if heartbeat.Code != http.StatusAccepted {
		t.Fatalf("same-generation heartbeat status = %d, want 202", heartbeat.Code)
	}

	snapshot.Generation = 2
	body, _ = json.Marshal(snapshot)
	request = httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(string(body)))
	request.TLS = peerCertificate("cluster-a")
	advanced := httptest.NewRecorder()
	handler.ServeHTTP(advanced, request)
	if advanced.Code != http.StatusAccepted {
		t.Fatalf("advanced snapshot status = %d, want 202", advanced.Code)
	}
	snapshot.Generation = 1
	body, _ = json.Marshal(snapshot)
	request = httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(string(body)))
	request.TLS = peerCertificate("cluster-a")
	stale := httptest.NewRecorder()
	handler.ServeHTTP(stale, request)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale snapshot status = %d, want 409", stale.Code)
	}
}

func TestAPIRejectsUnknownFieldsAndUnapprovedPorts(t *testing.T) {
	api := &API{Store: NewSnapshotStore(filepath.Join(t.TempDir(), "sources"), AllowedPorts{HTTP: {443: {}}}), AllowedSources: map[string]struct{}{"cluster-a": {}}}
	cases := []struct{ name, body string }{
		{"unknown field", `{"generation":1,"exposures":[],"ignorePolicy":true}`},
		{"unapproved port", `{"generation":1,"exposures":[{"id":"web","hostname":"app.example.test","protocol":"http","mode":"direct","listenPort":8443,"targetHost":"192.0.2.10","targetPort":80}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/v1/sources/cluster-a/exposures", strings.NewReader(tc.body))
			request.TLS = peerCertificate("cluster-a")
			recorder := httptest.NewRecorder()
			api.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 400 or 422: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func peerCertificate(commonName string) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: commonName}}}}
}
