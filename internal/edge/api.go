package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

type API struct {
	Store          *SnapshotStore
	AllowedPorts   map[Protocol][]int
	AllowedSources map[string]struct{}
	StatusFile     string
	Wake           chan<- struct{}
}

func (api *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/capabilities", api.capabilities)
	mux.HandleFunc("GET /v1/status", api.status)
	mux.HandleFunc("PUT /v1/sources/{source}/exposures", api.replaceSnapshot)
	mux.HandleFunc("GET /v1/sources/{source}/exposures", api.getSnapshot)
	return mux
}

func (api *API) capabilities(w http.ResponseWriter, request *http.Request) {
	if _, ok := api.authorizedIdentity(w, request, ""); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocols":   []Protocol{HTTP, TCP},
		"modes":       []Mode{Direct, Tunnel},
		"directPorts": api.AllowedPorts,
	})
}

func (api *API) status(w http.ResponseWriter, request *http.Request) {
	if _, ok := api.authorizedIdentity(w, request, ""); !ok {
		return
	}
	content, err := os.ReadFile(api.StatusFile)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ReconcileStatus{State: "starting"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (api *API) replaceSnapshot(w http.ResponseWriter, request *http.Request) {
	source := request.PathValue("source")
	if _, ok := api.authorizedIdentity(w, request, source); !ok {
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		http.Error(w, "invalid snapshot: "+err.Error(), http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "request body must contain one JSON value", http.StatusBadRequest)
		return
	}
	if err := ValidateSnapshot(snapshot, api.Store.allowedPort); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := api.Store.Replace(source, snapshot); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrStaleGeneration) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if api.Wake != nil {
		select {
		case api.Wake <- struct{}{}:
		default:
		}
	}
	w.Header().Set("ETag", strconv.Quote(fmt.Sprint(snapshot.Generation)))
	writeJSON(w, http.StatusAccepted, map[string]any{"source": source, "generation": snapshot.Generation, "state": "accepted"})
}

func (api *API) getSnapshot(w http.ResponseWriter, request *http.Request) {
	source := request.PathValue("source")
	if _, ok := api.authorizedIdentity(w, request, source); !ok {
		return
	}
	snapshot, err := api.Store.Get(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, request)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", strconv.Quote(fmt.Sprint(snapshot.Generation)))
	writeJSON(w, http.StatusOK, snapshot)
}

func (api *API) authorizedIdentity(w http.ResponseWriter, request *http.Request, expectedSource string) (string, bool) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate is required", http.StatusUnauthorized)
		return "", false
	}
	identity := request.TLS.PeerCertificates[0].Subject.CommonName
	if !ValidIdentifier(identity) {
		http.Error(w, "invalid client identity", http.StatusForbidden)
		return "", false
	}
	if api.AllowedSources != nil {
		if _, allowed := api.AllowedSources[identity]; !allowed {
			http.Error(w, "source is not authorized", http.StatusForbidden)
			return "", false
		}
	}
	if expectedSource != "" && identity != expectedSource {
		http.Error(w, "client certificate does not match source", http.StatusForbidden)
		return "", false
	}
	return identity, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
