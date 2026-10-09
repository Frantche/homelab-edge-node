package edge

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotStorePersistsAndRejectsStaleGeneration(t *testing.T) {
	store := NewSnapshotStore(filepath.Join(t.TempDir(), "sources"), AllowedPorts{HTTP: {443: {}}})
	snapshot := Snapshot{Generation: 1, Exposures: []Exposure{{ID: "web", Protocol: HTTP, Mode: Direct, Hostname: "app.example.test", ListenPort: 443, TargetHost: "192.0.2.5", TargetPort: 8080}}}
	if err := store.Replace("cluster-a", snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace("cluster-a", snapshot); err != nil {
		t.Fatalf("same-generation heartbeat failed: %v", err)
	}
	changedWithoutGeneration := snapshot
	changedWithoutGeneration.Exposures = append([]Exposure(nil), snapshot.Exposures...)
	changedWithoutGeneration.Exposures[0].TargetPort++
	if err := store.Replace("cluster-a", changedWithoutGeneration); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("same-generation mutation error = %v", err)
	}
	loaded, err := store.Get("cluster-a")
	if err != nil || loaded.Generation != 1 || loaded.Exposures[0].ID != "web" {
		t.Fatalf("loaded snapshot = %#v, error = %v", loaded, err)
	}
}

func TestSnapshotStoreRemovesUnauthorizedAndExpiredSources(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sources")
	store := NewSnapshotStore(root, AllowedPorts{HTTP: {443: {}}})
	snapshot := Snapshot{Generation: 1, Exposures: []Exposure{{ID: "web", Protocol: HTTP, Mode: Direct, Hostname: "app.example.test", ListenPort: 443, TargetHost: "192.0.2.5", TargetPort: 8080}}}
	if err := store.Replace("authorized", snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace("removed", snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveUnauthorized(map[string]struct{}{"authorized": {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("removed"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed source snapshot error = %v", err)
	}
	path := filepath.Join(root, "authorized.json")
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	active, err := store.AllActive(time.Hour, time.Now())
	if err != nil || len(active) != 0 {
		t.Fatalf("active snapshots = %#v, error = %v", active, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired snapshot was not removed: %v", err)
	}
}

func TestSnapshotStoreRejectsUnauthorizedPortWithoutWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sources")
	store := NewSnapshotStore(root, AllowedPorts{HTTP: {443: {}}})
	snapshot := Snapshot{Generation: 1, Exposures: []Exposure{{ID: "tcp", Protocol: TCP, Mode: Direct, ListenPort: 6690, TargetHost: "192.0.2.5", TargetPort: 6690}}}
	if err := store.Replace("cluster-a", snapshot); err == nil {
		t.Fatal("expected unapproved port to be rejected")
	}
	if _, err := store.Get("cluster-a"); err == nil {
		t.Fatal("rejected snapshot was written")
	}
}
