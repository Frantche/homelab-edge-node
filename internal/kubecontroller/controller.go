package kubecontroller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Frantche/homelab-edge-node/internal/edge"
)

const (
	AnnotationExpose      = "edge.homelab-edge-node.io/expose"
	AnnotationMode        = "edge.homelab-edge-node.io/mode"
	AnnotationListenPort  = "edge.homelab-edge-node.io/listen-port"
	AnnotationTLS         = "edge.homelab-edge-node.io/tls"
	AnnotationSourceCIDRs = "edge.homelab-edge-node.io/source-cidrs"
)

type TargetProfile struct {
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	TLS     bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
}

type Config struct {
	Source            string                   `yaml:"source"`
	DefaultMode       edge.Mode                `yaml:"defaultMode"`
	DefaultHTTPPort   int                      `yaml:"defaultHTTPPort"`
	GatewayAPIEnabled bool                     `yaml:"gatewayAPIEnabled"`
	TCPRouteEnabled   bool                     `yaml:"tcpRouteEnabled"`
	IngressTargets    map[string]TargetProfile `yaml:"ingressTargets"`
	GatewayTargets    map[string]TargetProfile `yaml:"gatewayTargets"`
}

type Metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
}

type Ingress struct {
	Metadata Metadata `json:"metadata"`
	Spec     struct {
		IngressClassName string `json:"ingressClassName"`
		Rules            []struct {
			Host string `json:"host"`
		} `json:"rules"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type Gateway struct {
	Metadata Metadata `json:"metadata"`
	Spec     struct {
		GatewayClassName string `json:"gatewayClassName"`
		Listeners        []struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hostname string `json:"hostname"`
		} `json:"listeners"`
	} `json:"spec"`
	Status struct {
		Addresses []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"addresses"`
		Conditions []Condition `json:"conditions"`
	} `json:"status"`
}

type Condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type ParentRef struct {
	Name        string  `json:"name"`
	Namespace   *string `json:"namespace"`
	SectionName *string `json:"sectionName"`
}

type ParentStatus struct {
	ParentRef  ParentRef   `json:"parentRef"`
	Conditions []Condition `json:"conditions"`
}

type HTTPRoute struct {
	Metadata Metadata `json:"metadata"`
	Spec     struct {
		ParentRefs []ParentRef `json:"parentRefs"`
		Hostnames  []string    `json:"hostnames"`
	} `json:"spec"`
	Status struct {
		Parents []ParentStatus `json:"parents"`
	} `json:"status"`
}

type TCPRoute struct {
	Metadata Metadata `json:"metadata"`
	Spec     struct {
		ParentRefs []ParentRef `json:"parentRefs"`
	} `json:"spec"`
	Status struct {
		Parents []ParentStatus `json:"parents"`
	} `json:"status"`
}

func BuildSnapshot(config Config, ingresses []Ingress, gateways []Gateway, httpRoutes []HTTPRoute, tcpRoutes []TCPRoute) (edge.Snapshot, error) {
	if !edge.ValidIdentifier(config.Source) {
		return edge.Snapshot{}, fmt.Errorf("source must be a DNS label")
	}
	mode := config.DefaultMode
	if mode == "" {
		mode = edge.Direct
	}
	if mode != edge.Direct && mode != edge.Tunnel {
		return edge.Snapshot{}, fmt.Errorf("defaultMode must be direct or cloudflare-tunnel")
	}
	defaultHTTPPort := config.DefaultHTTPPort
	if defaultHTTPPort == 0 {
		defaultHTTPPort = 443
	}
	exposures := make([]edge.Exposure, 0)
	for _, ingress := range ingresses {
		if !optedIn(ingress.Metadata.Annotations) {
			continue
		}
		profile, exists := config.IngressTargets[ingress.Spec.IngressClassName]
		if !exists {
			profile = TargetProfile{Port: 80}
			if address := ingressAddress(ingress.Status.LoadBalancer.Ingress); address != "" {
				profile.Address = address
			}
		}
		if profile.Address == "" {
			return edge.Snapshot{}, fmt.Errorf("Ingress %s/%s has no configured target or load balancer address", ingress.Metadata.Namespace, ingress.Metadata.Name)
		}
		if profile.Port == 0 {
			profile.Port = 80
		}
		routeMode, tls, listenPort, cidrs, err := httpPolicy(ingress.Metadata.Annotations, mode, defaultHTTPPort)
		if err != nil {
			return edge.Snapshot{}, fmt.Errorf("Ingress %s/%s: %w", ingress.Metadata.Namespace, ingress.Metadata.Name, err)
		}
		hosts := ingressHosts(ingress.Spec.Rules)
		if len(hosts) == 0 {
			return edge.Snapshot{}, fmt.Errorf("Ingress %s/%s is opted in but has no host rules", ingress.Metadata.Namespace, ingress.Metadata.Name)
		}
		for _, host := range hosts {
			exposures = append(exposures, edge.Exposure{ID: resourceID("ing", ingress.Metadata.Namespace, ingress.Metadata.Name, host), Hostname: host, Protocol: edge.HTTP, Mode: routeMode, ListenPort: listenPort, TLS: tls, TargetHost: profile.Address, TargetPort: profile.Port, TargetTLS: profile.TLS, SourceCIDRs: cidrs})
		}
	}
	if config.GatewayAPIEnabled {
		gatewaysByKey := make(map[string]Gateway, len(gateways))
		for _, gateway := range gateways {
			gatewaysByKey[gateway.Metadata.Namespace+"/"+gateway.Metadata.Name] = gateway
		}
		for _, route := range httpRoutes {
			if !optedIn(route.Metadata.Annotations) {
				continue
			}
			if len(route.Spec.Hostnames) == 0 {
				return edge.Snapshot{}, fmt.Errorf("HTTPRoute %s/%s is opted in but has no hostnames", route.Metadata.Namespace, route.Metadata.Name)
			}
			routeMode, tls, listenPort, cidrs, err := httpPolicy(route.Metadata.Annotations, mode, defaultHTTPPort)
			if err != nil {
				return edge.Snapshot{}, fmt.Errorf("HTTPRoute %s/%s: %w", route.Metadata.Namespace, route.Metadata.Name, err)
			}
			for _, parent := range route.Spec.ParentRefs {
				if !parentAccepted(route.Status.Parents, parent, route.Metadata.Namespace) {
					continue
				}
				gateway, ok := gatewaysByKey[parentNamespace(parent, route.Metadata.Namespace)+"/"+parent.Name]
				if !ok || !conditionIsTrue(gateway.Status.Conditions, "Programmed") || !conditionIsTrue(gateway.Status.Conditions, "Accepted") {
					continue
				}
				profile, profileExists := config.GatewayTargets[gateway.Spec.GatewayClassName]
				target, err := gatewayHTTPProfile(gateway, parent.SectionName, profile, profileExists, route.Spec.Hostnames)
				if err != nil {
					return edge.Snapshot{}, fmt.Errorf("HTTPRoute %s/%s: %w", route.Metadata.Namespace, route.Metadata.Name, err)
				}
				for _, host := range route.Spec.Hostnames {
					exposures = append(exposures, edge.Exposure{ID: resourceID("http", route.Metadata.Namespace, route.Metadata.Name, host), Hostname: host, Protocol: edge.HTTP, Mode: routeMode, ListenPort: listenPort, TLS: tls, TargetHost: target.Address, TargetPort: target.Port, TargetTLS: target.TLS, SourceCIDRs: cidrs})
				}
			}
		}
		if config.TCPRouteEnabled {
			for _, route := range tcpRoutes {
				if !optedIn(route.Metadata.Annotations) {
					continue
				}
				if requestedMode := route.Metadata.Annotations[AnnotationMode]; requestedMode != "" && edge.Mode(requestedMode) != edge.Direct {
					return edge.Snapshot{}, fmt.Errorf("TCPRoute %s/%s supports direct mode only", route.Metadata.Namespace, route.Metadata.Name)
				}
				cidrs, err := sourceCIDRs(route.Metadata.Annotations[AnnotationSourceCIDRs])
				if err != nil {
					return edge.Snapshot{}, fmt.Errorf("TCPRoute %s/%s: %w", route.Metadata.Namespace, route.Metadata.Name, err)
				}
				for _, parent := range route.Spec.ParentRefs {
					if !parentAccepted(route.Status.Parents, parent, route.Metadata.Namespace) {
						continue
					}
					gateway, ok := gatewaysByKey[parentNamespace(parent, route.Metadata.Namespace)+"/"+parent.Name]
					if !ok || !conditionIsTrue(gateway.Status.Conditions, "Programmed") || !conditionIsTrue(gateway.Status.Conditions, "Accepted") {
						continue
					}
					profile := config.GatewayTargets[gateway.Spec.GatewayClassName]
					targetHost := profile.Address
					if targetHost == "" {
						targetHost = gatewayAddress(gateway.Status.Addresses)
					}
					if targetHost == "" {
						return edge.Snapshot{}, fmt.Errorf("Gateway %s/%s has no configured target or status address", gateway.Metadata.Namespace, gateway.Metadata.Name)
					}
					listeners := matchingTCPListeners(gateway.Spec.Listeners, parent.SectionName)
					for _, listener := range listeners {
						listenPort, err := annotatedPort(route.Metadata.Annotations, listener.Port)
						if err != nil {
							return edge.Snapshot{}, fmt.Errorf("TCPRoute %s/%s: %w", route.Metadata.Namespace, route.Metadata.Name, err)
						}
						targetPort := listener.Port
						exposures = append(exposures, edge.Exposure{ID: resourceID("tcp", route.Metadata.Namespace, route.Metadata.Name, strconv.Itoa(listenPort)), Protocol: edge.TCP, Mode: edge.Direct, ListenPort: listenPort, TargetHost: targetHost, TargetPort: targetPort, SourceCIDRs: cidrs})
					}
				}
			}
		}
	}
	sort.Slice(exposures, func(i, j int) bool { return exposures[i].ID < exposures[j].ID })
	snapshot := edge.Snapshot{Generation: 1, Exposures: exposures}
	allowed := edge.AllowedPorts{edge.HTTP: {}, edge.TCP: {}}
	for _, exposure := range exposures {
		if allowed[exposure.Protocol] == nil {
			allowed[exposure.Protocol] = map[int]struct{}{}
		}
		allowed[exposure.Protocol][exposure.ListenPort] = struct{}{}
	}
	if err := edge.ValidateSnapshot(snapshot, allowed); err != nil {
		return edge.Snapshot{}, fmt.Errorf("build exposure snapshot: %w", err)
	}
	return snapshot, nil
}

func optedIn(annotations map[string]string) bool { return annotations[AnnotationExpose] == "true" }

func httpPolicy(annotations map[string]string, defaultMode edge.Mode, defaultPort int) (edge.Mode, bool, int, []string, error) {
	mode := defaultMode
	if raw := annotations[AnnotationMode]; raw != "" {
		mode = edge.Mode(raw)
	}
	if mode != edge.Direct && mode != edge.Tunnel {
		return "", false, 0, nil, fmt.Errorf("mode must be direct or cloudflare-tunnel")
	}
	port, err := annotatedPort(annotations, defaultPort)
	if err != nil {
		return "", false, 0, nil, err
	}
	tls := mode == edge.Direct
	if raw := annotations[AnnotationTLS]; raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return "", false, 0, nil, fmt.Errorf("tls must be true or false")
		}
		tls = parsed
	}
	cidrs, err := sourceCIDRs(annotations[AnnotationSourceCIDRs])
	return mode, tls, port, cidrs, err
}

func annotatedPort(annotations map[string]string, defaultPort int) (int, error) {
	if raw := annotations[AnnotationListenPort]; raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return 0, fmt.Errorf("listen-port must be between 1 and 65535")
		}
		return port, nil
	}
	return defaultPort, nil
}

func sourceCIDRs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	values := strings.Split(raw, ",")
	result := make([]string, 0, len(values))
	for _, value := range values {
		_, parsed, err := net.ParseCIDR(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid source-cidrs value %q", value)
		}
		result = append(result, parsed.String())
	}
	sort.Strings(result)
	return result, nil
}

func ingressHosts(rules []struct {
	Host string `json:"host"`
}) []string {
	hosts := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Host != "" {
			hosts = append(hosts, strings.ToLower(rule.Host))
		}
	}
	sort.Strings(hosts)
	return unique(hosts)
}

func ingressAddress(addresses []struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}) string {
	for _, address := range addresses {
		if address.IP != "" {
			return address.IP
		}
		if address.Hostname != "" {
			return address.Hostname
		}
	}
	return ""
}

func gatewayAddress(addresses []struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}) string {
	for _, address := range addresses {
		if address.Value != "" && (address.Type == "" || address.Type == "IPAddress" || address.Type == "Hostname") {
			return address.Value
		}
	}
	return ""
}

func gatewayHTTPProfile(gateway Gateway, sectionName *string, configured TargetProfile, configuredOK bool, routeHosts []string) (TargetProfile, error) {
	if configuredOK && configured.Address != "" {
		if configured.Port < 1 || configured.Port > 65535 {
			return TargetProfile{}, fmt.Errorf("GatewayClass %q target port must be between 1 and 65535", gateway.Spec.GatewayClassName)
		}
		return configured, nil
	}
	address := gatewayAddress(gateway.Status.Addresses)
	if address == "" {
		return TargetProfile{}, fmt.Errorf("Gateway %s/%s has no configured target or status address", gateway.Metadata.Namespace, gateway.Metadata.Name)
	}
	for _, preferredProtocol := range []string{"HTTP", "HTTPS"} {
		for _, listener := range gateway.Spec.Listeners {
			if sectionName != nil && listener.Name != *sectionName {
				continue
			}
			if listener.Protocol != preferredProtocol || !listenerMatchesHosts(listener.Hostname, routeHosts) {
				continue
			}
			return TargetProfile{Address: address, Port: listener.Port, TLS: listener.Protocol == "HTTPS"}, nil
		}
	}
	return TargetProfile{}, fmt.Errorf("Gateway %s/%s has no HTTP or HTTPS listener matching the route hostnames", gateway.Metadata.Namespace, gateway.Metadata.Name)
}

func listenerMatchesHosts(listenerHost string, routeHosts []string) bool {
	if listenerHost == "" {
		return true
	}
	for _, host := range routeHosts {
		if strings.EqualFold(listenerHost, host) || (strings.HasPrefix(listenerHost, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(listenerHost[1:]))) {
			return true
		}
	}
	return false
}

func matchingTCPListeners(listeners []struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
}, sectionName *string) []struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
} {
	result := make([]struct {
		Name     string `json:"name"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Hostname string `json:"hostname"`
	}, 0)
	for _, listener := range listeners {
		if listener.Protocol == "TCP" && (sectionName == nil || listener.Name == *sectionName) {
			result = append(result, listener)
		}
	}
	return result
}

func parentAccepted(statuses []ParentStatus, wanted ParentRef, routeNamespace string) bool {
	for _, status := range statuses {
		if status.ParentRef.Name != wanted.Name || parentNamespace(status.ParentRef, routeNamespace) != parentNamespace(wanted, routeNamespace) {
			continue
		}
		if wanted.SectionName != nil && (status.ParentRef.SectionName == nil || *wanted.SectionName != *status.ParentRef.SectionName) {
			continue
		}
		accepted, resolved := false, false
		for _, condition := range status.Conditions {
			switch condition.Type {
			case "Accepted":
				accepted = condition.Status == "True"
			case "ResolvedRefs":
				resolved = condition.Status == "True"
			}
		}
		return accepted && resolved
	}
	return false
}

func conditionIsTrue(conditions []Condition, wanted string) bool {
	for _, condition := range conditions {
		if condition.Type == wanted {
			return condition.Status == "True"
		}
	}
	return false
}

func parentNamespace(parent ParentRef, fallback string) string {
	if parent.Namespace != nil && *parent.Namespace != "" {
		return *parent.Namespace
	}
	return fallback
}

func resourceID(kind, namespace, name, discriminator string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{kind, namespace, name, discriminator}, "/")))
	return kind + "-" + hex.EncodeToString(digest[:10])
}

func unique(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func ValidateEndpoint(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("endpoint must be an absolute HTTP or HTTPS URL")
	}
	return nil
}
