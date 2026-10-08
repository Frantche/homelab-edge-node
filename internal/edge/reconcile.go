package edge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type RuntimeConfig struct {
	FixedSnapshotFile        string              `json:"fixedSnapshotFile" yaml:"fixedSnapshotFile"`
	DynamicFile              string              `json:"dynamicFile" yaml:"dynamicFile"`
	NFTBinary                string              `json:"nftBinary" yaml:"nftBinary"`
	ManagementCIDRs          []string            `json:"managementCIDRs" yaml:"managementCIDRs"`
	ManagementTCP            []int               `json:"managementTCPPorts" yaml:"managementTCPPorts"`
	PublicationAPICIDRs      []string            `json:"publicationAPICIDRs" yaml:"publicationAPICIDRs"`
	PublicationAPIPort       int                 `json:"publicationAPIPort" yaml:"publicationAPIPort"`
	AllowedPorts             AllowedPorts        `json:"allowedPorts" yaml:"allowedPorts"`
	SourceTTLSeconds         int                 `json:"sourceTTLSeconds" yaml:"sourceTTLSeconds"`
	ReconcileIntervalSeconds int                 `json:"reconcileIntervalSeconds" yaml:"reconcileIntervalSeconds"`
	ACMEEnabled              bool                `json:"acmeEnabled" yaml:"acmeEnabled"`
	TunnelEntryPoint         string              `json:"tunnelEntryPoint" yaml:"tunnelEntryPoint"`
	CrowdSec                 *CrowdSecMiddleware `json:"crowdsec,omitempty" yaml:"crowdsec,omitempty"`
	Cloudflare               *CloudflareConfig   `json:"cloudflare,omitempty" yaml:"cloudflare,omitempty"`
	StatusFile               string              `json:"statusFile" yaml:"statusFile"`
}

type CrowdSecMiddleware struct {
	LAPIURL        string   `json:"lapiURL" yaml:"lapiURL"`
	APIKeyFile     string   `json:"apiKeyFile" yaml:"apiKeyFile"`
	Mode           string   `json:"mode" yaml:"mode"`
	UpdateInterval int      `json:"updateIntervalSeconds" yaml:"updateIntervalSeconds"`
	PluginVersion  string   `json:"pluginVersion" yaml:"pluginVersion"`
	TrustedProxies []string `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
}

type Reconciler struct {
	Config    RuntimeConfig
	Store     *SnapshotStore
	Publisher ExternalPublisher
	Now       func() time.Time
}

type ExternalPublisher interface {
	Reconcile(context.Context, []OwnedExposure) error
}

type OwnedExposure struct {
	Source   string
	Exposure Exposure
}

func (reconciler *Reconciler) Reconcile(ctx context.Context) error {
	if reconciler.Now == nil {
		reconciler.Now = time.Now
	}
	writeStatus := func(status ReconcileStatus) {
		status.UpdatedAt = reconciler.Now().UTC().Format(time.RFC3339)
		if reconciler.Config.StatusFile != "" {
			_ = writeJSONAtomic(reconciler.Config.StatusFile, status)
		}
	}
	fail := func(err error) error {
		writeStatus(ReconcileStatus{State: "error", Error: err.Error()})
		return err
	}
	fixed, err := readSnapshot(reconciler.Config.FixedSnapshotFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("read fixed exposure declarations: %w", err))
	}
	if errors.Is(err, os.ErrNotExist) {
		fixed = Snapshot{Generation: 1, Exposures: []Exposure{}}
	}
	if fixed.Generation < 1 {
		return fail(fmt.Errorf("fixed snapshot generation must be positive"))
	}
	if err := ValidateSnapshot(fixed, reconciler.Config.AllowedPorts); err != nil {
		return fail(fmt.Errorf("fixed exposures: %w", err))
	}
	sourceTTL := time.Duration(reconciler.Config.SourceTTLSeconds) * time.Second
	sources, err := reconciler.Store.AllActive(sourceTTL, reconciler.Now())
	if err != nil {
		return fail(fmt.Errorf("read source snapshots: %w", err))
	}
	owned := make([]OwnedExposure, 0, len(fixed.Exposures))
	for _, exposure := range fixed.Exposures {
		owned = append(owned, OwnedExposure{Source: "ansible", Exposure: exposure})
	}
	for source, snapshot := range sources {
		if err := ValidateSnapshot(snapshot, reconciler.Config.AllowedPorts); err != nil {
			return fail(fmt.Errorf("source %s: %w", source, err))
		}
		for _, exposure := range snapshot.Exposures {
			owned = append(owned, OwnedExposure{Source: source, Exposure: exposure})
		}
	}
	if err := ValidateGlobalExposures(owned); err != nil {
		return fail(err)
	}
	for _, item := range owned {
		if reconciler.Config.Cloudflare != nil && reconciler.Config.Cloudflare.Enabled && item.Exposure.Protocol == HTTP && item.Exposure.Mode == Direct && reconciler.Config.Cloudflare.PublicIPv4 == "" && reconciler.Config.Cloudflare.PublicIPv6 == "" {
			return fail(fmt.Errorf("direct HTTP exposure %s/%s requires a Cloudflare public IPv4 or IPv6 address", item.Source, item.Exposure.ID))
		}
		if item.Exposure.Mode != Tunnel {
			continue
		}
		cloudflare := reconciler.Config.Cloudflare
		if cloudflare == nil || !cloudflare.Enabled || reconciler.Publisher == nil || cloudflare.TunnelID == "" || cloudflare.AccountID == "" {
			return fail(fmt.Errorf("Cloudflare Tunnel exposure %s/%s requires enabled DNS/Tunnel publication and a configured tunnel", item.Source, item.Exposure.ID))
		}
		if reconciler.Config.TunnelEntryPoint == "" || cloudflare.TunnelOriginPort < 1 {
			return fail(fmt.Errorf("Cloudflare Tunnel exposure %s/%s requires a local Tunnel origin entrypoint", item.Source, item.Exposure.ID))
		}
	}
	dynamic, err := RenderTraefik(owned, reconciler.Config)
	if err != nil {
		return fail(err)
	}
	nft, err := RenderNFTables(owned, reconciler.Config.ManagementCIDRs, reconciler.Config.ManagementTCP, reconciler.Config.PublicationAPICIDRs, reconciler.Config.PublicationAPIPort)
	if err != nil {
		return fail(err)
	}
	if reconciler.Config.NFTBinary != "" {
		if err := validateAndApplyNFT(ctx, reconciler.Config.NFTBinary, nft); err != nil {
			return fail(fmt.Errorf("apply nftables policy: %w", err))
		}
	}
	if err := writeFileAtomic(reconciler.Config.DynamicFile, dynamic, 0640); err != nil {
		return fail(fmt.Errorf("activate Traefik routes: %w", err))
	}
	if reconciler.Publisher != nil {
		if err := reconciler.Publisher.Reconcile(ctx, owned); err != nil {
			writeStatus(ReconcileStatus{State: "applied-with-pending-cloudflare", Error: err.Error(), ExposureCount: len(owned)})
			return err
		}
	}
	writeStatus(ReconcileStatus{State: "applied", ExposureCount: len(owned)})
	return nil
}

type ReconcileStatus struct {
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
	ExposureCount int    `json:"exposureCount"`
	UpdatedAt     string `json:"updatedAt"`
}

func ValidateGlobalExposures(owned []OwnedExposure) error {
	hostOwners, listenerOwners := map[string]string{}, map[string]string{}
	portPolicies := map[int]string{}
	for _, item := range owned {
		exposure := item.Exposure
		owner := item.Source + "/" + exposure.ID
		if exposure.Hostname != "" {
			host := strings.ToLower(exposure.Hostname)
			for existing, previous := range hostOwners {
				if hostnamesOverlap(existing, host) && previous != owner {
					return fmt.Errorf("hostname %q overlaps %q, already owned by %s", host, existing, previous)
				}
			}
			hostOwners[host] = owner
		}
		if exposure.Mode != Direct {
			continue
		}
		listener := fmt.Sprintf("tcp/%d", exposure.ListenPort)
		if previous, exists := listenerOwners[listener]; exists && (exposure.Protocol == TCP || strings.Contains(previous, ":tcp")) {
			return fmt.Errorf("listener %s conflicts with %s", listener, previous)
		}
		if exposure.Protocol == TCP {
			if previous, exists := listenerOwners[listener]; exists {
				return fmt.Errorf("listener %s conflicts with %s", listener, previous)
			}
			listenerOwners[listener] = owner + ":tcp"
		} else {
			listenerOwners[listener] = owner + ":http"
		}
		policy := strings.Join(exposure.SourceCIDRs, ",")
		if previous, exists := portPolicies[exposure.ListenPort]; exists && previous != policy {
			return fmt.Errorf("services sharing tcp/%d must use identical source CIDRs", exposure.ListenPort)
		}
		portPolicies[exposure.ListenPort] = policy
	}
	return nil
}

func RenderTraefik(owned []OwnedExposure, config RuntimeConfig) ([]byte, error) {
	httpRouters, httpServices, tcpRouters, tcpServices := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
	for _, item := range owned {
		exposure := item.Exposure
		name := routeName(item.Source, exposure.ID)
		if exposure.Protocol == HTTP {
			entryPoint := "http-" + fmt.Sprint(exposure.ListenPort)
			if exposure.Mode == Tunnel {
				entryPoint = config.TunnelEntryPoint
			}
			serviceName := name
			router := map[string]any{
				"entryPoints": []string{entryPoint},
				"rule":        hostRule(exposure.Hostname),
				"service":     serviceName,
			}
			if exposure.TLS {
				tls := map[string]any{}
				if config.ACMEEnabled && exposure.Mode == Direct {
					tls["certResolver"] = "cloudflare"
				}
				router["tls"] = tls
			}
			if config.CrowdSec != nil {
				router["middlewares"] = []string{"crowdsec"}
			}
			httpRouters[name] = router
			scheme := "http"
			if exposure.TargetTLS {
				scheme = "https"
			}
			address := net.JoinHostPort(exposure.TargetHost, fmt.Sprint(exposure.TargetPort))
			httpServices[serviceName] = map[string]any{"loadBalancer": map[string]any{"servers": []map[string]string{{"url": scheme + "://" + address}}}}
			continue
		}
		tcpRouters[name] = map[string]any{
			"entryPoints": []string{"tcp-" + fmt.Sprint(exposure.ListenPort)},
			"rule":        "HostSNI(`*`)",
			"service":     name,
		}
		address := net.JoinHostPort(exposure.TargetHost, fmt.Sprint(exposure.TargetPort))
		tcpServices[name] = map[string]any{"loadBalancer": map[string]any{"servers": []map[string]string{{"address": address}}}}
	}
	rendered := map[string]any{}
	if len(httpRouters) > 0 {
		renderedHTTP := map[string]any{"routers": httpRouters, "services": httpServices}
		if config.CrowdSec != nil {
			if config.CrowdSec.LAPIURL == "" || config.CrowdSec.APIKeyFile == "" || config.CrowdSec.PluginVersion == "" {
				return nil, fmt.Errorf("CrowdSec requires lapiURL, apiKeyFile and pluginVersion")
			}
			plugin := map[string]any{
				"enabled":             true,
				"crowdsecLapiHost":    config.CrowdSec.LAPIURL,
				"crowdsecLapiKeyFile": config.CrowdSec.APIKeyFile,
				"crowdsecMode":        config.CrowdSec.Mode,
			}
			if config.CrowdSec.UpdateInterval > 0 {
				plugin["updateIntervalSeconds"] = config.CrowdSec.UpdateInterval
			}
			if len(config.CrowdSec.TrustedProxies) > 0 {
				plugin["forwardedHeadersTrustedIPs"] = config.CrowdSec.TrustedProxies
			}
			renderedHTTP["middlewares"] = map[string]any{"crowdsec": map[string]any{"plugin": map[string]any{"bouncer": plugin}}}
		}
		rendered["http"] = renderedHTTP
	}
	if len(tcpRouters) > 0 {
		rendered["tcp"] = map[string]any{"routers": tcpRouters, "services": tcpServices}
	}
	return yaml.Marshal(rendered)
}

func routeName(source, exposureID string) string {
	digest := sha256.Sum256([]byte(source + "/" + exposureID))
	return fmt.Sprintf("edge-%x", digest[:10])
}

func hostRule(hostname string) string {
	hostname = strings.ToLower(hostname)
	if strings.HasPrefix(hostname, "*.") {
		base := regexp.QuoteMeta(strings.TrimPrefix(hostname, "*."))
		return "HostRegexp(`^[a-z0-9-]+\\." + base + "$`)"
	}
	return "Host(`" + hostname + "`)"
}

func RenderNFTables(owned []OwnedExposure, managementCIDRs []string, managementPorts []int, apiCIDRs []string, apiPort int) ([]byte, error) {
	var output strings.Builder
	output.WriteString("destroy table inet homelab_edge\ntable inet homelab_edge {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    ct state established,related accept\n    ct state invalid drop\n    iifname \"lo\" accept\n    ip protocol icmp accept\n    ip6 nexthdr ipv6-icmp accept\n")
	for _, cidr := range managementCIDRs {
		parsed, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid management CIDR %q", cidr)
		}
		family := "ip"
		if parsed.To4() == nil {
			family = "ip6"
		}
		for _, port := range managementPorts {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid management TCP port %d", port)
			}
			fmt.Fprintf(&output, "    %s saddr %s tcp dport %d ct state new accept\n", family, cidr, port)
		}
	}
	if len(apiCIDRs) > 0 && (apiPort < 1 || apiPort > 65535) {
		return nil, fmt.Errorf("invalid publication API TCP port %d", apiPort)
	}
	for _, cidr := range apiCIDRs {
		parsed, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid publication API CIDR %q", cidr)
		}
		family := "ip"
		if parsed.To4() == nil {
			family = "ip6"
		}
		fmt.Fprintf(&output, "    %s saddr %s tcp dport %d ct state new accept\n", family, cidr, apiPort)
	}
	for _, item := range owned {
		exposure := item.Exposure
		if exposure.Mode != Direct {
			continue
		}
		familyProtocol := "tcp"
		if exposure.Protocol == HTTP || exposure.Protocol == TCP {
			familyProtocol = "tcp"
		}
		if len(exposure.SourceCIDRs) == 0 {
			fmt.Fprintf(&output, "    %s dport %d ct state new accept\n", familyProtocol, exposure.ListenPort)
			continue
		}
		for _, cidr := range exposure.SourceCIDRs {
			parsed, _, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid source CIDR %q", cidr)
			}
			family := "ip"
			if parsed.To4() == nil {
				family = "ip6"
			}
			fmt.Fprintf(&output, "    %s saddr %s %s dport %d ct state new accept\n", family, cidr, familyProtocol, exposure.ListenPort)
		}
	}
	output.WriteString("  }\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n    iifname \"docker0\" ct state new,established,related accept\n    oifname \"docker0\" ct state established,related accept\n    iifname \"br-*\" ct state new,established,related accept\n    oifname \"br-*\" ct state established,related accept\n  }\n  chain output { type filter hook output priority filter; policy accept; }\n}\n")
	return []byte(output.String()), nil
}

func validateAndApplyNFT(ctx context.Context, binary string, script []byte) error {
	check := exec.CommandContext(ctx, binary, "--check", "--file", "-")
	check.Stdin = strings.NewReader(string(script))
	if output, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("nft validation failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	apply := exec.CommandContext(ctx, binary, "--file", "-")
	apply.Stdin = strings.NewReader(string(script))
	if output, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".edge-dynamic-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
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

func exposureList(owned []OwnedExposure) []Exposure {
	result := make([]Exposure, 0, len(owned))
	for _, item := range owned {
		result = append(result, item.Exposure)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func writeStatusFile(path string, status ReconcileStatus) error {
	return writeJSONAtomic(path, status)
}

func loadRuntimeConfig(path string) (RuntimeConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	var config RuntimeConfig
	if err := json.Unmarshal(content, &config); err == nil && config.FixedSnapshotFile != "" {
		return config, nil
	}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return RuntimeConfig{}, err
	}
	return config, nil
}

func LoadRuntimeConfig(path string) (RuntimeConfig, error) { return loadRuntimeConfig(path) }
