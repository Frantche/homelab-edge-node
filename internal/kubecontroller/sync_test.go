package kubecontroller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListResourcesFollowsContinuationTokens(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "500" {
			t.Errorf("list limit = %q, want 500", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "page-2" {
			_ = json.NewEncoder(w).Encode(ListEnvelope[item]{Items: []item{{Name: "second"}}})
			return
		}
		var envelope ListEnvelope[item]
		envelope.Items = []item{{Name: "first"}}
		envelope.Metadata.Continue = "page-2"
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	items, err := listResources[item](context.Background(), &HTTPJSONClient{BaseURL: server.URL, HTTP: server.Client()}, "/apis/example/v1/items")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "first" || items[1].Name != "second" {
		t.Fatalf("items = %#v, want both pages", items)
	}
}

func TestListResourcesRejectsRepeatedContinuationTokenWithoutPartialItems(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		var envelope ListEnvelope[item]
		envelope.Items = []item{{Name: "partial"}}
		envelope.Metadata.Continue = "same-token"
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	items, err := listResources[item](context.Background(), &HTTPJSONClient{BaseURL: server.URL, HTTP: server.Client()}, "/apis/example/v1/items")
	if err == nil || items != nil {
		t.Fatalf("items=%#v error=%v, want a failed list with no partial snapshot", items, err)
	}
	if calls != 2 {
		t.Fatalf("list calls = %d, want to detect the repeated continuation", calls)
	}
}
