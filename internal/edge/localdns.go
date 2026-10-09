package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

type LocalDNSConfig struct {
	Provider     string `json:"provider" yaml:"provider"`
	BaseURL      string `json:"baseURL" yaml:"baseURL"`
	PasswordFile string `json:"passwordFile" yaml:"passwordFile"`
	Username     string `json:"username,omitempty" yaml:"username,omitempty"`
	StateFile    string `json:"stateFile" yaml:"stateFile"`
}

type LocalDNSClient struct {
	Config LocalDNSConfig
	HTTP   *http.Client
}

func (client *LocalDNSClient) Reconcile(ctx context.Context, owned []OwnedExposure) error {
	if client.Config.Provider != "pihole" && client.Config.Provider != "adguard" {
		return fmt.Errorf("local DNS provider must be pihole or adguard")
	}
	base, err := url.Parse(client.Config.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return fmt.Errorf("local DNS baseURL must be an absolute HTTP(S) URL")
	}
	if client.Config.PasswordFile == "" || client.Config.StateFile == "" {
		return fmt.Errorf("local DNS passwordFile and stateFile are required")
	}
	if client.Config.Provider == "adguard" && client.Config.Username == "" {
		return fmt.Errorf("AdGuard Home local DNS username is required")
	}
	password, err := os.ReadFile(client.Config.PasswordFile)
	if err != nil {
		return fmt.Errorf("read local DNS password file: %w", err)
	}
	if strings.TrimSpace(string(password)) == "" {
		return fmt.Errorf("local DNS password file is empty")
	}
	if client.HTTP == nil {
		client.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	desired := map[string]string{}
	for _, item := range owned {
		exposure := item.Exposure
		if !exposure.LocalDNS {
			continue
		}
		ip := net.ParseIP(exposure.TargetHost)
		if ip == nil || !ip.IsPrivate() {
			return fmt.Errorf("local DNS exposure %s/%s must target a private IP address", item.Source, exposure.ID)
		}
		host := strings.ToLower(strings.TrimSuffix(exposure.Hostname, "."))
		if !ValidHostname(host) || strings.HasPrefix(host, "*.") {
			return fmt.Errorf("local DNS exposure %s/%s has an invalid hostname", item.Source, exposure.ID)
		}
		if previous, exists := desired[host]; exists && previous != ip.String() {
			return fmt.Errorf("local DNS hostname %s has conflicting target addresses", host)
		}
		desired[host] = ip.String()
	}
	previous, err := client.readState()
	if err != nil {
		return err
	}
	if len(desired) == 0 && len(previous) == 0 {
		return nil
	}
	existing, err := client.list(ctx, base, string(password))
	if err != nil {
		return err
	}
	for host, address := range desired {
		if current, found := existing[host]; found {
			old, managed := previous[host]
			if !managed {
				return fmt.Errorf("local DNS record %s already exists and is not managed by this edge", host)
			}
			if current != old && current != address {
				return fmt.Errorf("local DNS record %s was changed outside this edge; refusing to overwrite it", host)
			}
		}
	}
	for host, old := range previous {
		if _, keep := desired[host]; keep {
			continue
		}
		if current, found := existing[host]; found {
			if current != old {
				return fmt.Errorf("local DNS record %s was changed outside this edge; refusing to delete it", host)
			}
			if err := client.delete(ctx, base, string(password), host, old); err != nil {
				return err
			}
			delete(previous, host)
			if err := client.writeState(previous); err != nil {
				return err
			}
		}
	}
	hosts := make([]string, 0, len(desired))
	for host := range desired {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if existing[host] == desired[host] {
			continue
		}
		if current, found := existing[host]; found {
			if err := client.delete(ctx, base, string(password), host, current); err != nil {
				return err
			}
		}
		if err := client.addOrUpdate(ctx, base, string(password), host, desired[host]); err != nil {
			return err
		}
		previous[host] = desired[host]
		if err := client.writeState(previous); err != nil {
			return err
		}
	}
	return client.writeState(desired)
}

func (client *LocalDNSClient) readState() (map[string]string, error) {
	content, err := os.ReadFile(client.Config.StateFile)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local DNS ownership state: %w", err)
	}
	state := map[string]string{}
	if err := json.Unmarshal(content, &state); err != nil {
		return nil, fmt.Errorf("decode local DNS ownership state: %w", err)
	}
	return state, nil
}

func (client *LocalDNSClient) writeState(state map[string]string) error {
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path.Dir(client.Config.StateFile), 0750); err != nil {
		return err
	}
	return writeFileAtomic(client.Config.StateFile, content, 0600)
}

func (client *LocalDNSClient) list(ctx context.Context, base *url.URL, password string) (map[string]string, error) {
	result := map[string]string{}
	switch client.Config.Provider {
	case "adguard":
		var records []struct {
			Domain string `json:"domain"`
			Answer string `json:"answer"`
		}
		if err := client.request(ctx, base, password, http.MethodGet, "/control/rewrite/list", nil, &records); err != nil {
			return nil, err
		}
		for _, record := range records {
			host := strings.ToLower(strings.TrimSuffix(record.Domain, "."))
			answer := strings.TrimSpace(record.Answer)
			if ip := net.ParseIP(answer); ip != nil {
				answer = ip.String()
			}
			if previous, exists := result[host]; exists && previous != answer {
				return nil, fmt.Errorf("local DNS provider has multiple different rewrites for %s", host)
			}
			result[host] = answer
		}
	case "pihole":
		var response struct {
			Config struct {
				DNS struct {
					Hosts        []string `json:"hosts"`
					CNAMERecords []string `json:"cnameRecords"`
				} `json:"dns"`
			} `json:"config"`
		}
		if err := client.piholeRequest(ctx, base, password, http.MethodGet, "/api/config", nil, &response); err != nil {
			return nil, err
		}
		for _, line := range response.Config.DNS.Hosts {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip := net.ParseIP(fields[0])
			if ip == nil {
				continue
			}
			for _, host := range fields[1:] {
				result[strings.ToLower(strings.TrimSuffix(host, "."))] = ip.String()
			}
		}
		for _, line := range response.Config.DNS.CNAMERecords {
			fields := strings.Split(line, ",")
			if len(fields) < 2 {
				continue
			}
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fields[0]), "."))
			if previous, exists := result[host]; exists && previous != "cname:"+strings.TrimSpace(fields[1]) {
				return nil, fmt.Errorf("local DNS provider has multiple different records for %s", host)
			}
			result[host] = "cname:" + strings.TrimSpace(fields[1])
		}
	}
	return result, nil
}

func (client *LocalDNSClient) addOrUpdate(ctx context.Context, base *url.URL, password, host, address string) error {
	if client.Config.Provider == "adguard" {
		return client.request(ctx, base, password, http.MethodPost, "/control/rewrite/add", map[string]string{"domain": host, "answer": address}, nil)
	}
	return client.piholeRequest(ctx, base, password, http.MethodPut, "/api/config/dns/hosts/"+url.PathEscape(address+" "+host), nil, nil)
}

func (client *LocalDNSClient) delete(ctx context.Context, base *url.URL, password, host, address string) error {
	if client.Config.Provider == "adguard" {
		return client.request(ctx, base, password, http.MethodPost, "/control/rewrite/delete", map[string]string{"domain": host, "answer": address}, nil)
	}
	return client.piholeRequest(ctx, base, password, http.MethodDelete, "/api/config/dns/hosts/"+url.PathEscape(address+" "+host), nil, nil)
}

func (client *LocalDNSClient) request(ctx context.Context, base *url.URL, password, method, endpoint string, body any, out any) error {
	return client.doRequest(ctx, base, password, method, endpoint, body, out, false)
}

func (client *LocalDNSClient) piholeRequest(ctx context.Context, base *url.URL, password, method, endpoint string, body any, out any) error {
	if endpoint == "/api/auth" {
		return client.doRequest(ctx, base, password, method, endpoint, body, out, true)
	}
	var auth struct {
		Session struct {
			SID string `json:"sid"`
		} `json:"session"`
	}
	if err := client.doRequest(ctx, base, password, http.MethodPost, "/api/auth", map[string]string{"password": strings.TrimSpace(password)}, &auth, true); err != nil {
		return err
	}
	return client.doRequest(ctx, base, auth.Session.SID, method, endpoint, body, out, true)
}

func (client *LocalDNSClient) doRequest(ctx context.Context, base *url.URL, credential, method, endpoint string, body any, out any, pihole bool) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base.String(), "/")+endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if pihole {
		if endpoint != "/api/auth" {
			req.Header.Set("X-FTL-SID", credential)
		}
	} else {
		req.SetBasicAuth(client.Config.Username, strings.TrimSpace(credential))
	}
	resp, err := client.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("local DNS API %s %s returned HTTP %d: %s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("decode local DNS API response: %w", err)
		}
	}
	return nil
}
