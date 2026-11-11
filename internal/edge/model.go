package edge

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type Protocol string

const (
	HTTP           Protocol = "http"
	TCP            Protocol = "tcp"
	TLSPassthrough Protocol = "tls"
)

type Mode string

const (
	Direct Mode = "direct"
	Tunnel Mode = "cloudflare-tunnel"
)

type Exposure struct {
	ID                   string       `json:"id" yaml:"id"`
	Hostname             string       `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Protocol             Protocol     `json:"protocol" yaml:"protocol"`
	Mode                 Mode         `json:"mode" yaml:"mode"`
	ListenPort           int          `json:"listenPort" yaml:"listenPort"`
	TLS                  bool         `json:"tls,omitempty" yaml:"tls,omitempty"`
	TargetHost           string       `json:"targetHost" yaml:"targetHost"`
	TargetPort           int          `json:"targetPort" yaml:"targetPort"`
	TargetTLS            bool         `json:"targetTLS,omitempty" yaml:"targetTLS,omitempty"`
	ProxyProtocolVersion int          `json:"proxyProtocolVersion,omitempty" yaml:"proxyProtocolVersion,omitempty"`
	SourceCIDRs          []string     `json:"sourceCIDRs,omitempty" yaml:"sourceCIDRs,omitempty"`
	LocalDNS             bool         `json:"localDNS,omitempty" yaml:"localDNS,omitempty"`
	LocalOnly            bool         `json:"localOnly,omitempty" yaml:"localOnly,omitempty"`
	DNS                  *ExposureDNS `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// ExposureDNS carries provider settings for one canonical Exposure.Hostname.
// It deliberately contains no hostname field so DNS names cannot drift apart.
type ExposureDNS struct {
	Local      *ExposureLocalDNS      `json:"local,omitempty" yaml:"local,omitempty"`
	Cloudflare *ExposureCloudflareDNS `json:"cloudflare,omitempty" yaml:"cloudflare,omitempty"`
}

type ExposureLocalDNS struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Address string `json:"address,omitempty" yaml:"address,omitempty"`
}

type ExposureCloudflareDNS struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	IPv4          string `json:"ipv4,omitempty" yaml:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty" yaml:"ipv6,omitempty"`
	AdoptExisting bool   `json:"adoptExisting,omitempty" yaml:"adoptExisting,omitempty"`
}

type Snapshot struct {
	Generation int64      `json:"generation"`
	Exposures  []Exposure `json:"exposures"`
}

type AllowedPorts map[Protocol]map[int]struct{}

var (
	identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostLabel  = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

func ValidIdentifier(value string) bool { return identifier.MatchString(value) }

func ValidateExposure(exposure Exposure, allowedPorts AllowedPorts) error {
	if !ValidIdentifier(exposure.ID) {
		return fmt.Errorf("exposure id %q must be a DNS label", exposure.ID)
	}
	if exposure.Protocol != HTTP && exposure.Protocol != TCP && exposure.Protocol != TLSPassthrough {
		return fmt.Errorf("%s: protocol must be http, tcp or tls", exposure.ID)
	}
	if exposure.ProxyProtocolVersion != 0 {
		if exposure.Protocol != TCP {
			return fmt.Errorf("%s: PROXY protocol is only valid for TCP", exposure.ID)
		}
		if exposure.ProxyProtocolVersion != 1 && exposure.ProxyProtocolVersion != 2 {
			return fmt.Errorf("%s: PROXY protocol version must be 1 or 2", exposure.ID)
		}
	}
	if exposure.Mode != Direct && exposure.Mode != Tunnel {
		return fmt.Errorf("%s: mode must be direct or cloudflare-tunnel", exposure.ID)
	}
	if (exposure.Protocol == TCP || exposure.Protocol == TLSPassthrough) && exposure.Mode != Direct {
		return fmt.Errorf("%s: TCP and TLS passthrough support direct exposure only", exposure.ID)
	}
	if exposure.Protocol == TCP && exposure.ListenPort == 443 {
		return fmt.Errorf("%s: TCP exposure on port 443 is not supported", exposure.ID)
	}
	if exposure.Mode == Tunnel && len(exposure.SourceCIDRs) > 0 {
		return fmt.Errorf("%s: sourceCIDRs are supported only for direct routes", exposure.ID)
	}
	if exposure.DNS != nil && exposure.DNS.Local == nil && exposure.DNS.Cloudflare == nil {
		return fmt.Errorf("%s: dns must define local or cloudflare settings", exposure.ID)
	}
	if exposure.DNS != nil && exposure.Mode == Tunnel && exposure.DNS.Cloudflare != nil {
		return fmt.Errorf("%s: per-service dns.cloudflare settings are only valid for direct routes", exposure.ID)
	}
	if exposure.DNS != nil && exposure.DNS.Local != nil {
		local := exposure.DNS.Local
		if !local.Enabled && local.Address != "" {
			return fmt.Errorf("%s: dns.local.address requires dns.local.enabled", exposure.ID)
		}
		if local.Enabled {
			if exposure.Hostname == "" || strings.HasPrefix(exposure.Hostname, "*.") || !ValidHostname(exposure.Hostname) {
				return fmt.Errorf("%s: enabled local DNS requires a non-wildcard hostname", exposure.ID)
			}
			if local.Address != "" {
				ip := net.ParseIP(local.Address)
				if ip == nil || !ip.IsPrivate() {
					return fmt.Errorf("%s: dns.local.address must be a private IP address", exposure.ID)
				}
			}
		}
	}
	if exposure.DNS != nil && exposure.DNS.Cloudflare != nil {
		cloudflare := exposure.DNS.Cloudflare
		if exposure.Hostname == "" || strings.HasPrefix(exposure.Hostname, "*.") || !ValidHostname(exposure.Hostname) {
			return fmt.Errorf("%s: dns.cloudflare requires a non-wildcard hostname", exposure.ID)
		}
		if !cloudflare.Enabled && (cloudflare.IPv4 != "" || cloudflare.IPv6 != "" || cloudflare.AdoptExisting) {
			return fmt.Errorf("%s: dns.cloudflare address and adoption options require dns.cloudflare.enabled", exposure.ID)
		}
		if cloudflare.IPv4 != "" {
			ip := net.ParseIP(cloudflare.IPv4)
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("%s: dns.cloudflare.ipv4 must be an IPv4 address", exposure.ID)
			}
		}
		if cloudflare.IPv6 != "" {
			ip := net.ParseIP(cloudflare.IPv6)
			if ip == nil || ip.To4() != nil {
				return fmt.Errorf("%s: dns.cloudflare.ipv6 must be an IPv6 address", exposure.ID)
			}
		}
	}
	if exposure.Protocol == TCP && exposure.Hostname != "" {
		if !ValidHostname(exposure.Hostname) || strings.HasPrefix(exposure.Hostname, "*.") {
			return fmt.Errorf("%s: TCP DNS hostname must be a valid non-wildcard hostname", exposure.ID)
		}
		localDNS := exposure.DNS != nil && exposure.DNS.Local != nil && exposure.DNS.Local.Enabled
		cloudflareDNS := exposure.DNS != nil && exposure.DNS.Cloudflare != nil && exposure.DNS.Cloudflare.Enabled
		if !localDNS && !cloudflareDNS {
			return fmt.Errorf("%s: TCP hostname requires an enabled DNS provider", exposure.ID)
		}
	}
	if exposure.Protocol == TCP && exposure.Hostname == "" && exposure.DNS != nil {
		localDNS := exposure.DNS.Local != nil && exposure.DNS.Local.Enabled
		cloudflareDNS := exposure.DNS.Cloudflare != nil && exposure.DNS.Cloudflare.Enabled
		if localDNS || cloudflareDNS {
			return fmt.Errorf("%s: hostname is required when DNS publication is enabled", exposure.ID)
		}
	}
	if (exposure.Protocol == HTTP || exposure.Protocol == TLSPassthrough) && !ValidHostname(exposure.Hostname) {
		return fmt.Errorf("%s: a valid hostname is required for HTTP and TLS routes", exposure.ID)
	}
	if exposure.LocalDNS && (exposure.Protocol != HTTP || strings.HasPrefix(exposure.Hostname, "*.")) {
		return fmt.Errorf("%s: local DNS requires an HTTP route with a non-wildcard hostname", exposure.ID)
	}
	if exposure.LocalDNS {
		ip := net.ParseIP(exposure.TargetHost)
		if ip == nil || !ip.IsPrivate() {
			return fmt.Errorf("%s: local DNS targetHost must be a private IP address", exposure.ID)
		}
	}
	if exposure.DNS != nil && exposure.DNS.Local != nil && exposure.DNS.Local.Enabled {
		address := exposure.DNS.Local.Address
		if address == "" {
			address = exposure.TargetHost
		}
		ip := net.ParseIP(address)
		if ip == nil || !ip.IsPrivate() {
			return fmt.Errorf("%s: local DNS address must be a private IP address", exposure.ID)
		}
	}
	if exposure.LocalOnly && !exposure.LocalDNS {
		return fmt.Errorf("%s: localOnly requires localDNS", exposure.ID)
	}
	if exposure.LocalOnly && exposure.Mode != Direct {
		return fmt.Errorf("%s: local-only routes must use direct mode", exposure.ID)
	}
	if exposure.ListenPort < 1 || exposure.ListenPort > 65535 {
		return fmt.Errorf("%s: listenPort must be between 1 and 65535", exposure.ID)
	}
	if exposure.Mode == Direct && !exposure.LocalOnly {
		if _, ok := allowedPorts[exposure.Protocol][exposure.ListenPort]; !ok {
			return fmt.Errorf("%s: direct %s port %d is not pre-authorized on the edge", exposure.ID, exposure.Protocol, exposure.ListenPort)
		}
	}
	if exposure.TargetHost == "" || strings.ContainsAny(exposure.TargetHost, "\r\n\x00 `") {
		return fmt.Errorf("%s: targetHost is required and must not contain whitespace or configuration syntax", exposure.ID)
	}
	if net.ParseIP(exposure.TargetHost) == nil && !ValidHostname(exposure.TargetHost) {
		return fmt.Errorf("%s: targetHost is not a valid hostname or IP address", exposure.ID)
	}
	if exposure.TargetPort < 1 || exposure.TargetPort > 65535 {
		return fmt.Errorf("%s: targetPort must be between 1 and 65535", exposure.ID)
	}
	if exposure.Protocol != HTTP && exposure.TargetTLS {
		return fmt.Errorf("%s: targetTLS is only valid for HTTP", exposure.ID)
	}
	if exposure.Protocol != HTTP && exposure.TLS {
		return fmt.Errorf("%s: TLS is only valid for HTTP", exposure.ID)
	}
	if exposure.Protocol == HTTP && exposure.Mode == Tunnel && exposure.ListenPort != 443 {
		return fmt.Errorf("%s: Cloudflare Tunnel HTTP publications use public port 443", exposure.ID)
	}
	if exposure.Protocol == HTTP && exposure.Mode == Tunnel && exposure.TLS {
		return fmt.Errorf("%s: Cloudflare Tunnel origin routes use plain HTTP", exposure.ID)
	}
	for _, cidr := range exposure.SourceCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("%s: invalid source CIDR %q", exposure.ID, cidr)
		}
	}
	return nil
}

func ValidHostname(hostname string) bool {
	if strings.HasPrefix(hostname, "*.") {
		hostname = strings.TrimPrefix(hostname, "*.")
	}
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func (exposure Exposure) wantsLocalDNS() bool {
	return exposure.LocalDNS || (exposure.DNS != nil && exposure.DNS.Local != nil && exposure.DNS.Local.Enabled)
}

// wantsCloudflareDNS preserves the legacy global behavior for HTTP and TLS
// routes. TCP DNS is opt-in because a raw TCP route has no routing hostname.
func (exposure Exposure) wantsCloudflareDNS() bool {
	if exposure.Mode == Tunnel {
		return true
	}
	if exposure.DNS != nil && exposure.DNS.Cloudflare != nil {
		return exposure.DNS.Cloudflare.Enabled
	}
	return exposure.Protocol == HTTP || exposure.Protocol == TLSPassthrough
}

func (exposure Exposure) cloudflareIPv4(fallback string) string {
	if exposure.DNS != nil && exposure.DNS.Cloudflare != nil && exposure.DNS.Cloudflare.IPv4 != "" {
		return exposure.DNS.Cloudflare.IPv4
	}
	return fallback
}

func (exposure Exposure) cloudflareIPv6(fallback string) string {
	if exposure.DNS != nil && exposure.DNS.Cloudflare != nil && exposure.DNS.Cloudflare.IPv6 != "" {
		return exposure.DNS.Cloudflare.IPv6
	}
	return fallback
}

func hostnamesOverlap(left, right string) bool {
	left, right = strings.ToLower(left), strings.ToLower(right)
	return hostnamePatternMatches(left, right) || hostnamePatternMatches(right, left)
}

func hostnamePatternMatches(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*")
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}
	label := strings.TrimSuffix(hostname, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func ValidateSnapshot(snapshot Snapshot, allowedPorts AllowedPorts) error {
	if snapshot.Generation < 1 {
		return fmt.Errorf("generation must be positive")
	}
	seenIDs, seenHosts, seenPorts := map[string]bool{}, map[string]string{}, map[string]string{}
	for _, exposure := range snapshot.Exposures {
		if err := ValidateExposure(exposure, allowedPorts); err != nil {
			return err
		}
		if seenIDs[exposure.ID] {
			return fmt.Errorf("duplicate exposure id %q", exposure.ID)
		}
		seenIDs[exposure.ID] = true
		if exposure.Hostname != "" {
			host := strings.ToLower(exposure.Hostname)
			for existing, previous := range seenHosts {
				if hostnamesOverlap(existing, host) && previous != exposure.ID {
					return fmt.Errorf("hostname %q overlaps route %q declared by %q", host, existing, previous)
				}
			}
			seenHosts[host] = exposure.ID
		}
		if exposure.Protocol == TCP {
			key := fmt.Sprintf("tcp/%d", exposure.ListenPort)
			if previous, exists := seenPorts[key]; exists {
				return fmt.Errorf("listener %s conflicts between %q and %q", key, previous, exposure.ID)
			}
			seenPorts[key] = exposure.ID
		}
	}
	return nil
}
