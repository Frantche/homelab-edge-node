package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

const cloudflareManagedComment = "managed-by=homelab-edge-node"

type CloudflareConfig struct {
	Enabled          bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	TokenFile        string `json:"tokenFile" yaml:"tokenFile"`
	ZoneID           string `json:"zoneID" yaml:"zoneID"`
	AccountID        string `json:"accountID" yaml:"accountID"`
	TunnelID         string `json:"tunnelID" yaml:"tunnelID"`
	TunnelOriginPort int    `json:"tunnelOriginPort" yaml:"tunnelOriginPort"`
	PublicIPv4       string `json:"publicIPv4,omitempty" yaml:"publicIPv4,omitempty"`
	PublicIPv6       string `json:"publicIPv6,omitempty" yaml:"publicIPv6,omitempty"`
	APIBaseURL       string `json:"apiBaseURL,omitempty" yaml:"apiBaseURL,omitempty"`
	TTL              int    `json:"ttl,omitempty" yaml:"ttl,omitempty"`
}

type CloudflareClient struct {
	Config CloudflareConfig
	HTTP   *http.Client
}

type cloudflareEnvelope struct {
	Success    bool              `json:"success"`
	Errors     []cloudflareError `json:"errors"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type cloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

type managedDNSRecord struct {
	Type    string
	Name    string
	Content string
	Proxied bool
}

func (client *CloudflareClient) Reconcile(ctx context.Context, owned []OwnedExposure) error {
	if client.HTTP == nil {
		client.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if client.Config.ZoneID == "" || client.Config.TokenFile == "" {
		return fmt.Errorf("Cloudflare DNS zone and API token file are required when publications have hostnames")
	}
	token, err := os.ReadFile(client.Config.TokenFile)
	if err != nil {
		return fmt.Errorf("read Cloudflare API token file: %w", err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return fmt.Errorf("Cloudflare API token file is empty")
	}
	base := strings.TrimRight(client.Config.APIBaseURL, "/")
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return fmt.Errorf("invalid Cloudflare API base URL")
	}

	tunnelIngress := make([]map[string]any, 0)
	desiredDNS := map[string]managedDNSRecord{}
	hasTunnel := false
	for _, item := range owned {
		exposure := item.Exposure
		if exposure.Hostname == "" {
			continue
		}
		name := strings.ToLower(exposure.Hostname)
		if exposure.Mode == Tunnel {
			hasTunnel = true
			tunnelIngress = append(tunnelIngress, map[string]any{"hostname": name, "service": fmt.Sprintf("http://127.0.0.1:%d", client.Config.TunnelOriginPort)})
			desiredDNS[name+"/CNAME"] = managedDNSRecord{Type: "CNAME", Name: name, Content: client.Config.TunnelID + ".cfargotunnel.com", Proxied: true}
			continue
		}
		if client.Config.PublicIPv4 != "" {
			if ip := net.ParseIP(client.Config.PublicIPv4); ip == nil || ip.To4() == nil {
				return fmt.Errorf("configured Cloudflare public IPv4 is invalid")
			}
			desiredDNS[name+"/A"] = managedDNSRecord{Type: "A", Name: name, Content: client.Config.PublicIPv4}
		}
		if client.Config.PublicIPv6 != "" {
			if ip := net.ParseIP(client.Config.PublicIPv6); ip == nil || ip.To4() != nil {
				return fmt.Errorf("configured Cloudflare public IPv6 is invalid")
			}
			desiredDNS[name+"/AAAA"] = managedDNSRecord{Type: "AAAA", Name: name, Content: client.Config.PublicIPv6}
		}
		if client.Config.PublicIPv4 == "" && client.Config.PublicIPv6 == "" {
			return fmt.Errorf("a public IP address is required to create direct DNS records")
		}
	}
	if hasTunnel && client.Config.TunnelID == "" {
		return fmt.Errorf("Cloudflare Tunnel ID and account ID are required for Tunnel publications")
	}
	if client.Config.TunnelID != "" && client.Config.AccountID == "" {
		return fmt.Errorf("Cloudflare Tunnel account ID is required")
	}
	if hasTunnel && client.Config.TunnelOriginPort < 1 {
		return fmt.Errorf("Cloudflare Tunnel origin port is required")
	}
	tokenValue := strings.TrimSpace(string(token))
	existingDNS, err := client.listDNS(ctx, base, tokenValue)
	if err != nil {
		return err
	}
	if err := validateDNSConflicts(existingDNS, desiredDNS); err != nil {
		return err
	}
	if client.Config.TunnelID != "" {
		if err := client.reconcileTunnel(ctx, base, tokenValue, existingDNS, tunnelIngress); err != nil {
			return err
		}
	}
	return client.reconcileDNSRecords(ctx, base, tokenValue, existingDNS, desiredDNS)
}

func validateDNSConflicts(existing []cloudflareDNSRecord, desired map[string]managedDNSRecord) error {
	for _, want := range desired {
		for _, record := range existing {
			if !strings.EqualFold(record.Name, want.Name) || strings.Contains(record.Comment, cloudflareManagedComment) {
				continue
			}
			conflict := want.Type == "CNAME" || record.Type == "CNAME" || record.Type == want.Type
			if conflict {
				return fmt.Errorf("Cloudflare record %s %s already exists and is not managed by this edge", record.Type, record.Name)
			}
		}
	}
	return nil
}

func (client *CloudflareClient) reconcileTunnel(ctx context.Context, base, token string, existingDNS []cloudflareDNSRecord, desired []map[string]any) error {
	path := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", url.PathEscape(client.Config.AccountID), url.PathEscape(client.Config.TunnelID))
	var current struct {
		Config map[string]any `json:"config"`
	}
	if _, err := client.request(ctx, base, token, http.MethodGet, path, nil, &current); err != nil {
		return fmt.Errorf("read Cloudflare Tunnel routes: %w", err)
	}
	if current.Config == nil {
		current.Config = map[string]any{}
	}
	currentIngress, err := decodeTunnelIngress(current.Config["ingress"])
	if err != nil {
		return fmt.Errorf("decode Cloudflare Tunnel ingress rules: %w", err)
	}
	current.Config["ingress"] = currentIngress
	sort.Slice(desired, func(i, j int) bool {
		left, _ := desired[i]["hostname"].(string)
		right, _ := desired[j]["hostname"].(string)
		return left < right
	})

	ownedHosts := map[string]struct{}{}
	for _, record := range existingDNS {
		if strings.Contains(record.Comment, cloudflareManagedComment) {
			ownedHosts[strings.ToLower(record.Name)] = struct{}{}
		}
	}

	foreignIngress := make([]map[string]any, 0, len(currentIngress))
	catchAll := make([]map[string]any, 0, 1)
	for _, rule := range currentIngress {
		hostname, _ := rule["hostname"].(string)
		if hostname == "" {
			catchAll = append(catchAll, rule)
			continue
		}
		if _, isOwned := ownedHosts[strings.ToLower(hostname)]; isOwned {
			continue
		}
		for _, route := range desired {
			desiredHost, _ := route["hostname"].(string)
			if hostnamesOverlap(hostname, desiredHost) {
				return fmt.Errorf("Cloudflare Tunnel hostname %q conflicts with an ingress rule not managed by this edge", hostname)
			}
		}
		foreignIngress = append(foreignIngress, rule)
	}
	mergedIngress := append(foreignIngress, desired...)
	if len(catchAll) == 0 {
		catchAll = append(catchAll, map[string]any{"service": "http_status:404"})
	}
	mergedIngress = append(mergedIngress, catchAll...)
	mergedConfig := make(map[string]any, len(current.Config)+1)
	for key, value := range current.Config {
		mergedConfig[key] = value
	}
	mergedConfig["ingress"] = mergedIngress
	if reflect.DeepEqual(current.Config, mergedConfig) {
		return nil
	}
	body := map[string]any{"config": mergedConfig}
	if _, err := client.request(ctx, base, token, http.MethodPut, path, body, nil); err != nil {
		return fmt.Errorf("update Cloudflare Tunnel routes: %w", err)
	}
	return nil
}

func decodeTunnelIngress(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var ingress []map[string]any
	if err := json.Unmarshal(encoded, &ingress); err != nil {
		return nil, err
	}
	return ingress, nil
}

func (client *CloudflareClient) reconcileDNSRecords(ctx context.Context, base, token string, existing []cloudflareDNSRecord, desired map[string]managedDNSRecord) error {
	managedByKey := map[string]cloudflareDNSRecord{}
	for _, record := range existing {
		if strings.Contains(record.Comment, cloudflareManagedComment) {
			managedByKey[record.Name+"/"+record.Type] = record
		}
	}
	// Remove obsolete edge-owned records first so changing A/AAAA to CNAME never
	// collides with Cloudflare's CNAME coexistence rules.
	staleKeys := make([]string, 0, len(managedByKey))
	for key := range managedByKey {
		if _, stillDesired := desired[key]; !stillDesired {
			staleKeys = append(staleKeys, key)
		}
	}
	sort.Strings(staleKeys)
	for _, key := range staleKeys {
		record := managedByKey[key]
		path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(client.Config.ZoneID), url.PathEscape(record.ID))
		if _, err := client.request(ctx, base, token, http.MethodDelete, path, nil, nil); err != nil {
			return fmt.Errorf("delete stale Cloudflare record %s: %w", record.Name, err)
		}
		delete(managedByKey, key)
	}
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := desired[key]
		var current *cloudflareDNSRecord
		for _, record := range existing {
			if _, stale := containsString(staleKeys, record.Name+"/"+record.Type); stale {
				continue
			}
			if strings.EqualFold(record.Name, want.Name) && record.Type == want.Type {
				copy := record
				current = &copy
			}
		}
		body := map[string]any{"type": want.Type, "name": want.Name, "content": want.Content, "ttl": client.Config.TTL, "proxied": want.Proxied, "comment": cloudflareManagedComment}
		if body["ttl"] == 0 {
			body["ttl"] = 1
		}
		if current == nil {
			path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(client.Config.ZoneID))
			var created cloudflareDNSRecord
			if _, err := client.request(ctx, base, token, http.MethodPost, path, body, &created); err != nil {
				return fmt.Errorf("create Cloudflare record %s: %w", want.Name, err)
			}
			continue
		}
		delete(managedByKey, key)
		if current.Content == want.Content && current.Proxied == want.Proxied && current.Comment == cloudflareManagedComment {
			continue
		}
		path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(client.Config.ZoneID), url.PathEscape(current.ID))
		if _, err := client.request(ctx, base, token, http.MethodPatch, path, body, nil); err != nil {
			return fmt.Errorf("update Cloudflare record %s: %w", want.Name, err)
		}
	}
	return nil
}

func containsString(values []string, wanted string) (int, bool) {
	for i, value := range values {
		if value == wanted {
			return i, true
		}
	}
	return 0, false
}

func (client *CloudflareClient) listDNS(ctx context.Context, base, token string) ([]cloudflareDNSRecord, error) {
	var result []cloudflareDNSRecord
	for page := 1; page <= 100; page++ {
		path := fmt.Sprintf("/zones/%s/dns_records?per_page=500&page=%d", url.PathEscape(client.Config.ZoneID), page)
		var pageRecords []cloudflareDNSRecord
		envelope, err := client.request(ctx, base, token, http.MethodGet, path, nil, &pageRecords)
		if err != nil {
			return nil, fmt.Errorf("list Cloudflare DNS records: %w", err)
		}
		result = append(result, pageRecords...)
		if envelope.ResultInfo.TotalPages <= page || envelope.ResultInfo.TotalPages == 0 {
			break
		}
		if page == 100 {
			return nil, fmt.Errorf("Cloudflare DNS list exceeded the 100-page safety limit")
		}
	}
	return result, nil
}

func (client *CloudflareClient) request(ctx context.Context, base, token, method, path string, body any, out any) (cloudflareEnvelope, error) {
	var encoded io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return cloudflareEnvelope{}, err
		}
		encoded = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, base+path, encoded)
	if err != nil {
		return cloudflareEnvelope{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.HTTP.Do(request)
	if err != nil {
		return cloudflareEnvelope{}, err
	}
	defer response.Body.Close()
	var envelope cloudflareEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope); err != nil {
		return cloudflareEnvelope{}, fmt.Errorf("decode Cloudflare response (%d): %w", response.StatusCode, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		messages := make([]string, 0, len(envelope.Errors))
		for _, item := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d: %s", item.Code, item.Message))
		}
		return envelope, fmt.Errorf("Cloudflare API returned HTTP %d: %s", response.StatusCode, strings.Join(messages, "; "))
	}
	if out != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return envelope, fmt.Errorf("decode Cloudflare result: %w", err)
		}
	}
	return envelope, nil
}
