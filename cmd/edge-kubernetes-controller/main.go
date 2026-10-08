package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Frantche/homelab-edge-node/internal/kubecontroller"
	"go.yaml.in/yaml/v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("edge-kubernetes-controller", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/homelab-edge-node/controller.yml", "controller configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	content, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read controller config: %w", err)
	}
	var config kubecontroller.ControllerConfig
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("parse controller config: %w", err)
	}
	if err := kubecontroller.ValidateEndpoint(config.EdgeURL); err != nil {
		return fmt.Errorf("controller edgeURL: %w", err)
	}
	if config.TCPRouteEnabled && !config.GatewayAPIEnabled {
		return fmt.Errorf("tcpRouteEnabled requires gatewayAPIEnabled")
	}
	kube, err := kubecontroller.NewKubernetesClient(config.KubeAPIServer, config.KubeTokenFile, config.KubeCAFile)
	if err != nil {
		return err
	}
	edgeClient, err := kubecontroller.NewEdgeClient(config.EdgeURL, config.EdgeCAFile, config.EdgeClientCertFile, config.EdgeClientKeyFile)
	if err != nil {
		return err
	}
	controller := &kubecontroller.RouteController{Config: config, Kube: kube, Edge: edgeClient}
	interval := time.Duration(config.PollIntervalSeconds) * time.Second
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}
	var synced atomic.Bool
	health := http.NewServeMux()
	health.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	health.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !synced.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "route snapshot is not synchronized")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	healthServer := &http.Server{Addr: ":8080", Handler: health, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdown)
	}()
	log.Printf("watching opted-in Ingress, HTTPRoute and TCPRoute resources for source %s", config.Source)
	for {
		if err := controller.SyncOnce(ctx); err != nil {
			synced.Store(false)
			log.Printf("route publication failed: %v", err)
		} else {
			synced.Store(true)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
