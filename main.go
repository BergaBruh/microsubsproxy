package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"microsubsproxy/internal/fetch"
	"microsubsproxy/internal/proxy"
	"microsubsproxy/internal/render"

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
	// ForceFingerprint rewrites URI-level TLS client fingerprints (fp=...)
	// before rendering. Empty means pass upstream values through unchanged.
	ForceFingerprint string `yaml:"force_fingerprint,omitempty"`
	// ForceQueryParams rewrites selected client URI query parameters before
	// rendering. It is intended for TLS-like share links generated upstream.
	ForceQueryParams ForceQueryParams `yaml:"force_query_params,omitempty"`
	// Optional path to a YAML file with Mihomo base config (dns, tun,
	// rule-providers, rules, proxy-groups, etc). Merged into clash output;
	// `proxies` is always overwritten. When empty, a minimal output with a
	// PROXY select group and MATCH,PROXY rule is generated.
	ClashExtra string `yaml:"clash_extra,omitempty"`
}

// StaticInject — статичный конфиг, прибавляется к ответу подписки.
// Если SubIDs пуст — попадает всем; иначе только перечисленным subId.
type StaticInject struct {
	URL    string   `yaml:"url"`
	Name   string   `yaml:"name,omitempty"`
	SubIDs []string `yaml:"sub_ids,omitempty"`
}

type ForceQueryParams struct {
	Fingerprint   string `yaml:"fingerprint,omitempty"`
	ALPN          string `yaml:"alpn,omitempty"`
	AllowInsecure *bool  `yaml:"allow_insecure,omitempty"`
}

var (
	listenAddr   string
	routePrefix  string
	maxSubIDLen  int
	staticInject []StaticInject
	forceParams  ForceQueryParams
	fetcher      *fetch.Client
	clashExtra   map[string]any // loaded once at startup, nil if not configured
)

// clashUARegex matches User-Agents used by Mihomo-compatible clients.
//
// We require the canonical "Name/" (or "Name /") pattern that real Clash-family
// clients emit (e.g. "Clash/v1.18.0", "mihomo/1.18.10", "Mihomo Party/1.2.3").
// Using word-boundary matching (\b…\b) was too broad: it matched strings like
// "compatible; verge bot" or "MyApp Stash Module/1.0" and caused false positives
// that silently flipped v2ray clients to the Clash render path.
//
// The pattern anchors on: optional preceding whitespace/separator, then the
// client name, then an optional space, then a literal "/".  This never matches
// unless the slash follows directly.
//
// Keep this conservative — false positives flip the format and break v2ray-only clients.
var clashUARegex = regexp.MustCompile(`(?i)(^|[\s(;])((clash([\s-]?(for[\s]?windows|x|meta|verge))?)|mihomo([\s-]?party)?|stash|flclash|verge)\s*/`)

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

	// Load clash_extra base YAML if configured. Validated by attempting to
	// unmarshal — a syntax error here is a hard config failure.
	var extra map[string]any
	if cfg.ClashExtra != "" {
		raw, err := os.ReadFile(cfg.ClashExtra)
		if err != nil {
			return fmt.Errorf("read clash_extra %s: %w", cfg.ClashExtra, err)
		}
		if err := yaml.Unmarshal(raw, &extra); err != nil {
			return fmt.Errorf("parse clash_extra %s: %w", cfg.ClashExtra, err)
		}
		// Refuse to silently override our generated proxies — if the user put
		// `proxies:` in their base, they're confused.
		if _, has := extra["proxies"]; has {
			return fmt.Errorf("clash_extra %s contains 'proxies' — that key is generated, remove it", cfg.ClashExtra)
		}
	}

	listenAddr = cfg.Listen
	routePrefix = cfg.RoutePrefix
	maxSubIDLen = cfg.MaxSubIDLen
	staticInject = cfg.StaticInject
	forceParams = cfg.ForceQueryParams.normalized()
	// Backward compatibility for the older single-field override.
	if forceParams.Fingerprint == "" {
		forceParams.Fingerprint = strings.TrimSpace(cfg.ForceFingerprint)
	}
	clashExtra = extra
	fetcher = &fetch.Client{
		HTTP:          &http.Client{Timeout: to},
		Upstreams:     cfg.Upstreams,
		ValidPrefixes: cfg.ValidPrefixes,
	}
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

func (p ForceQueryParams) normalized() ForceQueryParams {
	p.Fingerprint = strings.TrimSpace(p.Fingerprint)
	p.ALPN = normalizeCommaList(p.ALPN)
	return p
}

func normalizeCommaList(raw string) string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, ",")
}

func (p ForceQueryParams) empty() bool {
	return p.Fingerprint == "" && p.ALPN == "" && p.AllowInsecure == nil
}

func forceQueryParamsURI(uri string, params ForceQueryParams) string {
	params = params.normalized()
	if params.empty() {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	scheme := strings.ToLower(u.Scheme)
	security := strings.ToLower(q.Get("security"))
	switch scheme {
	case "vless":
		if security != "tls" && security != "reality" {
			return uri
		}
	case "trojan", "hysteria2", "hy2", "tuic":
		// These schemes use TLS in normal clients and understand fp=.
	default:
		return uri
	}
	if params.Fingerprint != "" {
		q.Set("fp", params.Fingerprint)
	}
	if params.ALPN != "" {
		q.Set("alpn", params.ALPN)
	}
	if params.AllowInsecure != nil {
		value := "0"
		if *params.AllowInsecure {
			value = "1"
		}
		// v2rayNG accepts all three spellings; emitting them keeps older and
		// patched clients aligned when they differ on the preferred key.
		q.Set("insecure", value)
		q.Set("allowInsecure", value)
		q.Set("allow_insecure", value)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func forceQueryParamsURIs(uris []string, params ForceQueryParams) []string {
	params = params.normalized()
	if params.empty() {
		return uris
	}
	out := make([]string, len(uris))
	for i, uri := range uris {
		out[i] = forceQueryParamsURI(uri, params)
	}
	return out
}

// detectFormat resolves the output format from query param (priority 1) and
// User-Agent (priority 2). Default is "v2ray" to preserve existing client behavior.
func detectFormat(r *http.Request) string {
	switch strings.ToLower(r.URL.Query().Get("type")) {
	case "clash", "mihomo":
		return "clash"
	case "v2ray":
		return "v2ray"
	}
	if clashUARegex.MatchString(r.Header.Get("User-Agent")) {
		return "clash"
	}
	return "v2ray"
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

	format := detectFormat(r)

	// Log without subId — it's a secret.
	log.Printf("%s - aggregate format=%s", r.RemoteAddr, format)

	uris := fetcher.Aggregate(subID)
	for _, si := range staticInject {
		if len(si.SubIDs) == 0 || subIDInList(si.SubIDs, subID) {
			uris = append(uris, si.URL)
		}
	}
	uris = forceQueryParamsURIs(uris, forceParams)

	if len(uris) == 0 {
		http.Error(w, "all upstreams failed", http.StatusBadGateway)
		return
	}

	var body []byte
	var contentType string
	switch format {
	case "clash":
		proxies, dropped := proxy.ParseAll(uris)
		if dropped > 0 {
			log.Printf("clash render: parsed %d/%d URIs, dropped %d", len(proxies), len(uris), dropped)
		}
		out, err := render.Clash(proxies, clashExtra)
		if err != nil {
			log.Printf("render clash: %v", err)
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		body = out
		contentType = "text/yaml; charset=utf-8"
	default:
		body = render.V2Ray(uris)
		contentType = "text/plain; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	// Do NOT emit Subscription-Userinfo when we don't know the real usage —
	// asserting "upload=0; download=0; total=0" triggers a "subscription exhausted"
	// warning in some Clash clients.
	w.Header().Set("Profile-Update-Interval", "24")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
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
		len(fetcher.Upstreams), cfgPath, routePrefix, fetcher.HTTP.Timeout)
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
