package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultConfigPath = "config.yaml"

type Config struct {
	Listen          string         `yaml:"listen"`
	RoutePrefix     string         `yaml:"route_prefix"`
	MaxSubIDLen     int            `yaml:"max_sub_id_len"`
	UpstreamTimeout string         `yaml:"upstream_timeout"`
	ValidPrefixes   []string       `yaml:"valid_prefixes"`
	Upstreams       []string       `yaml:"upstreams"`
	StaticInject    []StaticInject `yaml:"static_inject,omitempty"`
}

// StaticInject — статичный конфиг, прибавляется к ответу подписки.
// Если SubIDs пуст — попадает всем; иначе только перечисленным subId.
type StaticInject struct {
	URL    string   `yaml:"url"`
	Name   string   `yaml:"name,omitempty"`
	SubIDs []string `yaml:"sub_ids,omitempty"`
}

var (
	listenAddr    string
	routePrefix   string
	maxSubIDLen   int
	upstreamTO    time.Duration
	validPrefixes []string
	upstreams     []string
	staticInject  []StaticInject
	client        *http.Client
)

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		return fmt.Errorf("listen is empty")
	}
	if cfg.RoutePrefix == "" {
		return fmt.Errorf("route_prefix is empty")
	}
	if strings.ContainsAny(cfg.RoutePrefix, "/") {
		return fmt.Errorf("route_prefix must not contain slashes: %q", cfg.RoutePrefix)
	}
	if cfg.MaxSubIDLen <= 0 {
		return fmt.Errorf("max_sub_id_len must be > 0")
	}
	to, err := time.ParseDuration(cfg.UpstreamTimeout)
	if err != nil {
		return fmt.Errorf("upstream_timeout %q: %w", cfg.UpstreamTimeout, err)
	}
	if to <= 0 {
		return fmt.Errorf("upstream_timeout must be > 0")
	}
	if len(cfg.ValidPrefixes) == 0 {
		return fmt.Errorf("valid_prefixes is empty")
	}
	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("upstreams is empty")
	}
	for i, u := range cfg.Upstreams {
		if !strings.Contains(u, "%s") {
			return fmt.Errorf("upstreams[%d] missing %%s placeholder: %s", i, u)
		}
	}
	for i, si := range cfg.StaticInject {
		if si.URL == "" {
			return fmt.Errorf("static_inject[%d]: url is empty", i)
		}
		ok := false
		for _, p := range cfg.ValidPrefixes {
			if strings.HasPrefix(si.URL, p) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("static_inject[%d]: url prefix not in valid_prefixes", i)
		}
		for j, id := range si.SubIDs {
			if !validSubIDStr(id, cfg.MaxSubIDLen) {
				return fmt.Errorf("static_inject[%d].sub_ids[%d]: invalid subId", i, j)
			}
		}
	}

	listenAddr = cfg.Listen
	routePrefix = cfg.RoutePrefix
	maxSubIDLen = cfg.MaxSubIDLen
	upstreamTO = to
	validPrefixes = cfg.ValidPrefixes
	upstreams = cfg.Upstreams
	staticInject = cfg.StaticInject
	client = &http.Client{Timeout: upstreamTO}
	return nil
}

// validSubIDStr — то же что validSubID, но принимает свой maxLen
// (нужно чтобы валидировать sub_ids в loadConfig до того как глобальный maxSubIDLen установлен).
func validSubIDStr(s string, maxLen int) bool {
	if len(s) == 0 || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func fetchUpstream(url string) []string {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("build request: %v", err)
		return nil
	}
	req.Header.Set("User-Agent", "microsubsproxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("upstream fail: %v", err)
		return nil
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("upstream read fail: %v", err)
		return nil
	}
	text := strings.TrimSpace(string(raw))

	// 3x-ui may return base64 or plain; try base64 first
	if dec, err := base64.StdEncoding.DecodeString(text); err == nil {
		text = string(dec)
	}

	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		for _, p := range validPrefixes {
			if strings.HasPrefix(ln, p) {
				lines = append(lines, ln)
				break
			}
		}
	}
	return lines
}

func validSubID(s string) bool {
	return validSubIDStr(s, maxSubIDLen)
}

func subIDInList(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != routePrefix {
		http.Error(w, fmt.Sprintf("use /%s/<subId>", routePrefix), http.StatusNotFound)
		return
	}
	subID := parts[1]
	if !validSubID(subID) {
		http.Error(w, "bad subId", http.StatusBadRequest)
		return
	}

	// Log without subId — it's a secret
	log.Printf("%s - aggregate", r.RemoteAddr)

	// Parallel fetch, preserve upstream order in output
	results := make([][]string, len(upstreams))
	var wg sync.WaitGroup
	for i, tmpl := range upstreams {
		wg.Add(1)
		go func(i int, tmpl string) {
			defer wg.Done()
			results[i] = fetchUpstream(fmt.Sprintf(tmpl, subID))
		}(i, tmpl)
	}
	wg.Wait()

	var lines []string
	for _, chunk := range results {
		lines = append(lines, chunk...)
	}

	// Append static_inject entries for matching subId.
	// Empty SubIDs list = inject for all subIds.
	for _, si := range staticInject {
		if len(si.SubIDs) == 0 || subIDInList(si.SubIDs, subID) {
			lines = append(lines, si.URL)
		}
	}

	if len(lines) == 0 {
		http.Error(w, "all upstreams failed", http.StatusBadGateway)
		return
	}

	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", "upload=0; download=0; total=0")
	w.Header().Set("Profile-Update-Interval", "24")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func main() {
	cfgPath := defaultConfigPath
	if v := os.Getenv("CONFIG"); v != "" {
		cfgPath = v
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	if err := loadConfig(cfgPath); err != nil {
		log.Fatalf("config %s: %v", cfgPath, err)
	}

	addr := listenAddr
	if v := os.Getenv("LISTEN"); v != "" {
		addr = v
	}

	log.Printf("loaded %d upstreams from %s (route /%s/, timeout %s)",
		len(upstreams), cfgPath, routePrefix, upstreamTO)
	log.Printf("microsubsproxy listening on %s", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
