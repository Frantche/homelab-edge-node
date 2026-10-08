package edge

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type Protocol string

const (
	HTTP Protocol = "http"
	TCP  Protocol = "tcp"
)

type Mode string

const (
	Direct Mode = "direct"
	Tunnel Mode = "cloudflare-tunnel"
)

type Exposure struct {
	ID          string   `json:"id" yaml:"id"`
	Hostname    string   `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Protocol    Protocol `json:"protocol" yaml:"protocol"`
	Mode        Mode     `json:"mode" yaml:"mode"`
	ListenPort  int      `json:"listenPort" yaml:"listenPort"`
	TLS         bool     `json:"tls,omitempty" yaml:"tls,omitempty"`
	TargetHost  string   `json:"targetHost" yaml:"targetHost"`
	TargetPort  int      `json:"targetPort" yaml:"targetPort"`
	TargetTLS   bool     `json:"targetTLS,omitempty" yaml:"targetTLS,omitempty"`
	SourceCIDRs []string `json:"sourceCIDRs,omitempty" yaml:"sourceCIDRs,omitempty"`
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
	if exposure.Protocol != HTTP && exposure.Protocol != TCP {
		return fmt.Errorf("%s: protocol must be http or tcp", exposure.ID)
	}
	if exposure.Mode != Direct && exposure.Mode != Tunnel {
		return fmt.Errorf("%s: mode must be direct or cloudflare-tunnel", exposure.ID)
	}
	if exposure.Protocol == TCP && exposure.Mode != Direct {
		return fmt.Errorf("%s: TCP supports direct exposure only", exposure.ID)
	}
	if exposure.Protocol == TCP && exposure.ListenPort == 443 {
		return fmt.Errorf("%s: TCP exposure on port 443 is not supported", exposure.ID)
	}
	if exposure.Mode == Tunnel && len(exposure.SourceCIDRs) > 0 {
		return fmt.Errorf("%s: sourceCIDRs are supported only for direct routes", exposure.ID)
	}
	if exposure.Protocol == TCP && exposure.Hostname != "" {
		return fmt.Errorf("%s: TCP routes do not carry a hostname", exposure.ID)
	}
	if exposure.Protocol == HTTP && !ValidHostname(exposure.Hostname) {
		return fmt.Errorf("%s: a valid hostname is required for HTTP", exposure.ID)
	}
	if exposure.ListenPort < 1 || exposure.ListenPort > 65535 {
		return fmt.Errorf("%s: listenPort must be between 1 and 65535", exposure.ID)
	}
	if exposure.Mode == Direct {
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
	if exposure.Protocol == TCP && exposure.TargetTLS {
		return fmt.Errorf("%s: targetTLS is only valid for HTTP", exposure.ID)
	}
	if exposure.Protocol == TCP && exposure.TLS {
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
	return strings.HasSuffix(hostname, suffix) && hostname != strings.TrimPrefix(suffix, ".")
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
