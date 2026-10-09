package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrStaleGeneration = errors.New("snapshot generation is not newer than the stored generation")

type SnapshotStore struct {
	root        string
	allowedPort AllowedPorts
	mu          sync.Mutex
}

func NewSnapshotStore(root string, allowedPorts AllowedPorts) *SnapshotStore {
	allowed := AllowedPorts{}
	for protocol, ports := range allowedPorts {
		allowed[protocol] = make(map[int]struct{}, len(ports))
		for port := range ports {
			allowed[protocol][port] = struct{}{}
		}
	}
	return &SnapshotStore{root: root, allowedPort: allowed}
}

func (store *SnapshotStore) Replace(source string, snapshot Snapshot) error {
	if !ValidIdentifier(source) {
		return fmt.Errorf("invalid source id %q", source)
	}
	if err := ValidateSnapshot(snapshot, store.allowedPort); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := filepath.Join(store.root, source+".json")
	if current, err := readSnapshot(path); err == nil {
		if snapshot.Generation < current.Generation || (snapshot.Generation == current.Generation && !reflect.DeepEqual(snapshot, current)) {
			return ErrStaleGeneration
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read stored snapshot: %w", err)
	}
	return writeJSONAtomic(path, snapshot)
}

// AllActive returns snapshots whose most recent PUT/heartbeat is within ttl.
// Expired snapshots are removed so a deleted or abandoned source cannot keep
// DNS records and listeners alive indefinitely.
func (store *SnapshotStore) AllActive(ttl time.Duration, now time.Time) (map[string]Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := map[string]Snapshot{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		source := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidIdentifier(source) {
			return nil, fmt.Errorf("invalid snapshot file %q", entry.Name())
		}
		path := filepath.Join(store.root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat source %s: %w", source, err)
		}
		if ttl > 0 && now.Sub(info.ModTime()) > ttl {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove expired source %s: %w", source, err)
			}
			continue
		}
		snapshot, err := readSnapshot(path)
		if err != nil {
			return nil, fmt.Errorf("read source %s: %w", source, err)
		}
		result[source] = snapshot
	}
	return result, nil
}

// RemoveUnauthorized immediately drops snapshots for sources removed from the
// manager allow-list. Their routes and owned DNS records are then withdrawn by
// the next reconciliation instead of waiting for the lease to expire.
func (store *SnapshotStore) RemoveUnauthorized(allowed map[string]struct{}) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		source := strings.TrimSuffix(entry.Name(), ".json")
		if _, ok := allowed[source]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(store.root, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove unauthorized source %s: %w", source, err)
		}
	}
	return nil
}

func (store *SnapshotStore) Get(source string) (Snapshot, error) {
	if !ValidIdentifier(source) {
		return Snapshot{}, fmt.Errorf("invalid source id %q", source)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return readSnapshot(filepath.Join(store.root, source+".json"))
}

func (store *SnapshotStore) All() (map[string]Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entries, err := os.ReadDir(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := map[string]Snapshot{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		source := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidIdentifier(source) {
			return nil, fmt.Errorf("invalid snapshot file %q", entry.Name())
		}
		snapshot, err := readSnapshot(filepath.Join(store.root, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read source %s: %w", source, err)
		}
		result[source] = snapshot
	}
	return result, nil
}

func (store *SnapshotStore) Sources() ([]string, error) {
	snapshots, err := store.All()
	if err != nil {
		return nil, err
	}
	sources := make([]string, 0, len(snapshots))
	for source := range snapshots {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources, nil
}

func readSnapshot(path string) (Snapshot, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(content, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
