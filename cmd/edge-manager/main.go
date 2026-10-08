package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/Frantche/homelab-edge-node/internal/edge"
	"go.yaml.in/yaml/v3"
)

type apiConfig struct {
	ListenAddress string   `yaml:"listenAddress"`
	ServerCert    string   `yaml:"serverCertFile"`
	ServerKey     string   `yaml:"serverKeyFile"`
	ClientCA      string   `yaml:"clientCAFile"`
	Sources       []string `yaml:"sources"`
}

type managerConfig struct {
	Runtime edge.RuntimeConfig `yaml:"runtime"`
	API     apiConfig          `yaml:"api"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck(os.Args[2:])
		return
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("edge-manager", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/homelab-edge-node/manager.yml", "manager configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	content, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read manager config: %w", err)
	}
	var config managerConfig
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("parse manager config: %w", err)
	}
	if config.API.ListenAddress == "" || config.API.ServerCert == "" || config.API.ServerKey == "" || config.API.ClientCA == "" {
		return fmt.Errorf("api.listenAddress, serverCertFile, serverKeyFile and clientCAFile are required")
	}
	allowed := map[string]struct{}{}
	for _, source := range config.API.Sources {
		if !edge.ValidIdentifier(source) {
			return fmt.Errorf("invalid source id or client certificate CN in api.sources: %q", source)
		}
		allowed[source] = struct{}{}
	}
	if config.Runtime.FixedSnapshotFile == "" || config.Runtime.DynamicFile == "" || config.Runtime.StatusFile == "" {
		return fmt.Errorf("runtime.fixedSnapshotFile, dynamicFile and statusFile are required")
	}
	if config.Runtime.SourceTTLSeconds <= 0 {
		return fmt.Errorf("runtime.sourceTTLSeconds must be positive")
	}
	store := edge.NewSnapshotStore(filepath.Join(filepath.Dir(config.Runtime.StatusFile), "sources"), config.Runtime.AllowedPorts)
	if err := store.RemoveUnauthorized(allowed); err != nil {
		return fmt.Errorf("remove snapshots for unauthorized sources: %w", err)
	}
	var publisher edge.ExternalPublisher
	if config.Runtime.Cloudflare != nil && config.Runtime.Cloudflare.Enabled {
		publisher = &edge.CloudflareClient{Config: *config.Runtime.Cloudflare}
	}
	reconciler := &edge.Reconciler{Config: config.Runtime, Store: store, Publisher: publisher}
	wake := make(chan struct{}, 1)
	portLists := make(map[edge.Protocol][]int, len(config.Runtime.AllowedPorts))
	for protocol, ports := range config.Runtime.AllowedPorts {
		for port := range ports {
			portLists[protocol] = append(portLists[protocol], port)
		}
		sort.Ints(portLists[protocol])
	}
	api := &edge.API{Store: store, AllowedPorts: portLists, AllowedSources: allowed, StatusFile: config.Runtime.StatusFile, Wake: wake}

	caPEM, err := os.ReadFile(config.API.ClientCA)
	if err != nil {
		return fmt.Errorf("read API client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("API client CA file contains no certificates")
	}
	serverCert, err := tls.LoadX509KeyPair(config.API.ServerCert, config.API.ServerKey)
	if err != nil {
		return fmt.Errorf("load API server certificate: %w", err)
	}
	tlsConfig := &tls.Config{ //nolint:gosec -- this is a TLS-only mTLS API.
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	listener, err := net.Listen("tcp", config.API.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on edge API: %w", err)
	}
	server := &http.Server{Addr: config.API.ListenAddress, Handler: api.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go reconcileLoop(ctx, reconciler, wake, time.Duration(config.Runtime.ReconcileIntervalSeconds)*time.Second)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("edge publication API listening on %s with %d authorized sources", config.API.ListenAddress, len(allowed))
	if err := server.Serve(tls.NewListener(listener, tlsConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve edge API: %w", err)
	}
	return nil
}

func reconcileLoop(ctx context.Context, reconciler *edge.Reconciler, wake <-chan struct{}, interval time.Duration) {
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := reconciler.Reconcile(ctx); err != nil {
			log.Printf("route reconciliation failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-ticker.C:
		}
	}
}

func healthcheck(args []string) {
	flags := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	statusFile := flags.String("status-file", "/var/lib/homelab-edge-node/status.json", "reconcile status path")
	_ = flags.Parse(args)
	content, err := os.ReadFile(*statusFile)
	var status edge.ReconcileStatus
	if err != nil || json.Unmarshal(content, &status) != nil || (status.State != "applied" && status.State != "applied-with-pending-cloudflare") {
		os.Exit(1)
	}
}
