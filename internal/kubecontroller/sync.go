package kubecontroller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Frantche/homelab-edge-node/internal/edge"
)

type ControllerConfig struct {
	Config              `yaml:",inline"`
	EdgeURL             string `yaml:"edgeURL"`
	EdgeCAFile          string `yaml:"edgeCACertFile"`
	EdgeClientCertFile  string `yaml:"edgeClientCertFile"`
	EdgeClientKeyFile   string `yaml:"edgeClientKeyFile"`
	KubeAPIServer       string `yaml:"kubeAPIServer"`
	KubeTokenFile       string `yaml:"kubeTokenFile"`
	KubeCAFile          string `yaml:"kubeCAFile"`
	PollIntervalSeconds int    `yaml:"pollIntervalSeconds"`
}

type ListEnvelope[T any] struct {
	Items    []T `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

type HTTPJSONClient struct {
	BaseURL   string
	Token     string
	TokenFile string
	HTTP      *http.Client
}

func NewKubernetesClient(baseURL, tokenFile, caFile string) (*HTTPJSONClient, error) {
	if baseURL == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, fmt.Errorf("kubeAPIServer is required outside a Kubernetes pod")
		}
		baseURL = "https://" + netJoinHostPort(host, port)
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("Kubernetes API URL must use HTTPS")
	}
	if tokenFile == "" {
		tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	if caFile == "" {
		caFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes service CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("Kubernetes service CA contains no certificates")
	}
	return &HTTPJSONClient{BaseURL: strings.TrimRight(baseURL, "/"), TokenFile: tokenFile, HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}}, nil
}

func NewEdgeClient(baseURL, caFile, certFile, keyFile string) (*HTTPJSONClient, error) {
	if err := ValidateEndpoint(baseURL); err != nil || !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("edgeURL must be an absolute HTTPS URL")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read edge server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("edge server CA contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load edge API client certificate: %w", err)
	}
	return &HTTPJSONClient{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}}}, nil
}

func (client *HTTPJSONClient) get(ctx context.Context, endpoint string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.BaseURL+endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	token, err := client.bearerToken()
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.HTTP.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return body, response.StatusCode, err
}

func (client *HTTPJSONClient) bearerToken() (string, error) {
	if client.TokenFile == "" {
		return client.Token, nil
	}
	token, err := os.ReadFile(client.TokenFile)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes service account token: %w", err)
	}
	return strings.TrimSpace(string(token)), nil
}

func (client *HTTPJSONClient) put(ctx context.Context, endpoint string, value any) ([]byte, int, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, client.BaseURL+endpoint, bytes.NewReader(content))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.HTTP.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return body, response.StatusCode, err
}

type RouteController struct {
	Config ControllerConfig
	Kube   *HTTPJSONClient
	Edge   *HTTPJSONClient
}

func (controller *RouteController) SyncOnce(ctx context.Context) error {
	ingresses, err := listResources[Ingress](ctx, controller.Kube, "/apis/networking.k8s.io/v1/ingresses")
	if err != nil {
		return fmt.Errorf("list Ingress resources: %w", err)
	}
	var gateways []Gateway
	var httpRoutes []HTTPRoute
	var tcpRoutes []TCPRoute
	if controller.Config.GatewayAPIEnabled {
		gateways, err = listResources[Gateway](ctx, controller.Kube, "/apis/gateway.networking.k8s.io/v1/gateways")
		if err != nil {
			return fmt.Errorf("list Gateway resources: %w", err)
		}
		httpRoutes, err = listResources[HTTPRoute](ctx, controller.Kube, "/apis/gateway.networking.k8s.io/v1/httproutes")
		if err != nil {
			return fmt.Errorf("list HTTPRoute resources: %w", err)
		}
		if controller.Config.TCPRouteEnabled {
			tcpRoutes, err = listResources[TCPRoute](ctx, controller.Kube, "/apis/gateway.networking.k8s.io/v1/tcproutes")
			if isNotFound(err) {
				tcpRoutes, err = listResources[TCPRoute](ctx, controller.Kube, "/apis/gateway.networking.k8s.io/v1alpha2/tcproutes")
			}
			if err != nil {
				return fmt.Errorf("list TCPRoute resources (install the experimental Gateway API CRD): %w", err)
			}
		}
	}
	snapshot, err := BuildSnapshot(controller.Config.Config, ingresses, gateways, httpRoutes, tcpRoutes)
	if err != nil {
		return err
	}
	return controller.publish(ctx, snapshot)
}

func listResources[T any](ctx context.Context, client *HTTPJSONClient, endpoint string) ([]T, error) {
	items := make([]T, 0)
	continuation := ""
	seenContinuations := map[string]struct{}{}
	for page := 0; page < 10000; page++ {
		query := url.Values{"limit": []string{"500"}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		body, status, err := client.get(ctx, endpoint+"?"+query.Encode())
		if err != nil {
			return nil, err
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("Kubernetes API returned HTTP %d: %s", status, strings.TrimSpace(string(body)))
		}
		var envelope ListEnvelope[T]
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("decode Kubernetes list response: %w", err)
		}
		items = append(items, envelope.Items...)
		next := envelope.Metadata.Continue
		if next == "" {
			return items, nil
		}
		if _, repeated := seenContinuations[next]; repeated {
			return nil, fmt.Errorf("Kubernetes API repeated a pagination continuation token")
		}
		seenContinuations[next] = struct{}{}
		continuation = next
	}
	return nil, fmt.Errorf("Kubernetes API list exceeded the 10000 page safety limit")
}

func (controller *RouteController) publish(ctx context.Context, desired edge.Snapshot) error {
	endpoint := "/v1/sources/" + url.PathEscape(controller.Config.Source) + "/exposures"
	body, status, err := controller.Edge.get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("read current edge snapshot: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("edge API returned HTTP %d while reading snapshot: %s", status, strings.TrimSpace(string(body)))
	}
	if status == http.StatusNotFound {
		desired.Generation = 1
	} else {
		var current edge.Snapshot
		if err := json.Unmarshal(body, &current); err != nil {
			return fmt.Errorf("decode current edge snapshot: %w", err)
		}
		currentExposures := sortedExposures(current.Exposures)
		desiredExposures := sortedExposures(desired.Exposures)
		desired.Generation = current.Generation
		if !sameExposures(currentExposures, desiredExposures) {
			desired.Generation++
		}
	}
	body, status, err = controller.Edge.put(ctx, endpoint, desired)
	if err != nil {
		return fmt.Errorf("publish edge snapshot: %w", err)
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("edge API returned HTTP %d while publishing snapshot: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

func sortedExposures(exposures []edge.Exposure) []edge.Exposure {
	result := append([]edge.Exposure(nil), exposures...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func sameExposures(left, right []edge.Exposure) bool {
	if len(left) != len(right) {
		return false
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func isNotFound(err error) bool { return err != nil && strings.Contains(err.Error(), "HTTP 404") }

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func APIPath(base, suffix string) string { return path.Join(strings.TrimRight(base, "/"), suffix) }
