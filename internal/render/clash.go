// Package render converts []proxy.Proxy into subscription output formats.
// Currently only Mihomo (Clash Meta) YAML is implemented.
package render

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"microsubsproxy/internal/proxy"
)

// ---- shared sub-option structs ----

type realityOptsYAML struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type wsOptsYAML struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type grpcOptsYAML struct {
	ServiceName string `yaml:"grpc-service-name,omitempty"`
}

type xhttpOptsYAML struct {
	Mode string `yaml:"mode,omitempty"`
	Path string `yaml:"path,omitempty"`
	Host string `yaml:"host,omitempty"`
}

// h2OptsYAML matches Mihomo's h2-opts block.
// Path is a scalar string (not a list) per the Mihomo schema.
type h2OptsYAML struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

// httpOptsYAML matches Mihomo's http-opts block (TCP+HTTP obfuscation header).
// method defaults to GET; path and Host header are lists.
type httpOptsYAML struct {
	Method  string              `yaml:"method,omitempty"`
	Path    []string            `yaml:"path,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty"`
}

// ---- per-protocol proxy structs ----

type vlessYAML struct {
	Name              string           `yaml:"name"`
	Type              string           `yaml:"type"`
	Server            string           `yaml:"server"`
	Port              uint16           `yaml:"port"`
	UUID              string           `yaml:"uuid"`
	Encryption        string           `yaml:"encryption,omitempty"` // VLESS post-quantum encryption; omitted when none
	Network           string           `yaml:"network,omitempty"`    // omitted when tcp (Mihomo default)
	Flow              string           `yaml:"flow,omitempty"`
	TLS               bool             `yaml:"tls,omitempty"`
	UDP               bool             `yaml:"udp"`
	Servername        string           `yaml:"servername,omitempty"`
	ALPN              []string         `yaml:"alpn,omitempty"`
	ClientFingerprint string           `yaml:"client-fingerprint,omitempty"`
	SkipCertVerify    bool             `yaml:"skip-cert-verify,omitempty"`
	RealityOpts       *realityOptsYAML `yaml:"reality-opts,omitempty"`
	WSOpts            *wsOptsYAML      `yaml:"ws-opts,omitempty"`
	GRPCOpts          *grpcOptsYAML    `yaml:"grpc-opts,omitempty"`
	XHTTPOpts         *xhttpOptsYAML   `yaml:"xhttp-opts,omitempty"`
}

type vmessYAML struct {
	Name              string        `yaml:"name"`
	Type              string        `yaml:"type"`
	Server            string        `yaml:"server"`
	Port              uint16        `yaml:"port"`
	UUID              string        `yaml:"uuid"`
	AlterID           int           `yaml:"alterId"`
	Cipher            string        `yaml:"cipher"`
	Network           string        `yaml:"network,omitempty"`
	TLS               bool          `yaml:"tls,omitempty"`
	UDP               bool          `yaml:"udp"`
	Servername        string        `yaml:"servername,omitempty"`
	ALPN              []string      `yaml:"alpn,omitempty"`
	ClientFingerprint string        `yaml:"client-fingerprint,omitempty"`
	SkipCertVerify    bool          `yaml:"skip-cert-verify,omitempty"`
	WSOpts            *wsOptsYAML   `yaml:"ws-opts,omitempty"`
	GRPCOpts          *grpcOptsYAML `yaml:"grpc-opts,omitempty"`
	H2Opts            *h2OptsYAML   `yaml:"h2-opts,omitempty"`
	HTTPOpts          *httpOptsYAML `yaml:"http-opts,omitempty"`
}

// trojanYAML: Mihomo treats TLS as implicit for trojan; do not emit tls:true.
// Trojan uses `sni` (not `servername`) — Mihomo quirk.
type trojanYAML struct {
	Name              string        `yaml:"name"`
	Type              string        `yaml:"type"`
	Server            string        `yaml:"server"`
	Port              uint16        `yaml:"port"`
	Password          string        `yaml:"password"`
	Network           string        `yaml:"network,omitempty"`
	UDP               bool          `yaml:"udp"`
	SNI               string        `yaml:"sni,omitempty"`
	ALPN              []string      `yaml:"alpn,omitempty"`
	ClientFingerprint string        `yaml:"client-fingerprint,omitempty"`
	SkipCertVerify    bool          `yaml:"skip-cert-verify,omitempty"`
	WSOpts            *wsOptsYAML   `yaml:"ws-opts,omitempty"`
	GRPCOpts          *grpcOptsYAML `yaml:"grpc-opts,omitempty"`
}

type ssYAML struct {
	Name       string            `yaml:"name"`
	Type       string            `yaml:"type"`
	Server     string            `yaml:"server"`
	Port       uint16            `yaml:"port"`
	Cipher     string            `yaml:"cipher"`
	Password   string            `yaml:"password"`
	UDP        bool              `yaml:"udp"`
	Plugin     string            `yaml:"plugin,omitempty"`
	PluginOpts *ssPluginOptsYAML `yaml:"plugin-opts,omitempty"`
}

// ssPluginOptsYAML is the union of plugin-opt fields across known plugins
// (obfs, v2ray-plugin, shadow-tls). Irrelevant fields are omitempty per-plugin.
type ssPluginOptsYAML struct {
	Mode           string `yaml:"mode,omitempty"`             // obfs: "tls"|"http"; v2ray-plugin: "websocket"
	Host           string `yaml:"host,omitempty"`             // all
	Path           string `yaml:"path,omitempty"`             // v2ray-plugin
	TLS            bool   `yaml:"tls,omitempty"`              // v2ray-plugin
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"` // v2ray-plugin
	Mux            bool   `yaml:"mux,omitempty"`              // v2ray-plugin
	Password       string `yaml:"password,omitempty"`         // shadow-tls
	Version        int    `yaml:"version,omitempty"`          // shadow-tls
}

// hysteria2YAML — Mihomo treats TLS as implicit; no `tls:` field.
// `obfs` is the only Hy2 obfs, paired with `obfs-password`.
type hysteria2YAML struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Server         string   `yaml:"server"`
	Port           uint16   `yaml:"port"`
	Password       string   `yaml:"password"`
	Obfs           string   `yaml:"obfs,omitempty"`
	ObfsPassword   string   `yaml:"obfs-password,omitempty"`
	SNI            string   `yaml:"sni,omitempty"`
	ALPN           []string `yaml:"alpn,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty"`
	Up             int      `yaml:"up,omitempty"`
	Down           int      `yaml:"down,omitempty"`
	UDP            bool     `yaml:"udp"`
}

// tuicYAML — TUIC v5. Field names use hyphens: congestion-controller, udp-relay-mode.
type tuicYAML struct {
	Name                 string   `yaml:"name"`
	Type                 string   `yaml:"type"`
	Server               string   `yaml:"server"`
	Port                 uint16   `yaml:"port"`
	UUID                 string   `yaml:"uuid"`
	Password             string   `yaml:"password"`
	CongestionController string   `yaml:"congestion-controller,omitempty"`
	UDPRelayMode         string   `yaml:"udp-relay-mode,omitempty"`
	ReduceRTT            bool     `yaml:"reduce-rtt,omitempty"`
	DisableSNI           bool     `yaml:"disable-sni,omitempty"`
	SNI                  string   `yaml:"sni,omitempty"`
	ALPN                 []string `yaml:"alpn,omitempty"`
	SkipCertVerify       bool     `yaml:"skip-cert-verify,omitempty"`
	UDP                  bool     `yaml:"udp"`
}

// wireguardYAML — WireGuard. No TLS; own crypto via curve25519 keys.
// Mihomo uses `pre-shared-key` (hyphenated), `ip` and `ipv6` for addresses.
type wireguardYAML struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	Server       string   `yaml:"server"`
	Port         uint16   `yaml:"port"`
	PrivateKey   string   `yaml:"private-key"`
	PublicKey    string   `yaml:"public-key"`
	PresharedKey string   `yaml:"pre-shared-key,omitempty"`
	IP           string   `yaml:"ip,omitempty"`
	IPv6         string   `yaml:"ipv6,omitempty"`
	MTU          int      `yaml:"mtu,omitempty"`
	AllowedIPs   []string `yaml:"allowed-ips,omitempty"`
	Reserved     []int    `yaml:"reserved,omitempty"`
	UDP          bool     `yaml:"udp"`
}

// ssrYAML — ShadowsocksR (legacy). Hyphenated obfs-param, protocol-param.
type ssrYAML struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	Server        string `yaml:"server"`
	Port          uint16 `yaml:"port"`
	Cipher        string `yaml:"cipher"`
	Password      string `yaml:"password"`
	Protocol      string `yaml:"protocol"`
	ProtocolParam string `yaml:"protocol-param,omitempty"`
	Obfs          string `yaml:"obfs"`
	ObfsParam     string `yaml:"obfs-param,omitempty"`
	UDP           bool   `yaml:"udp"`
}

// ---- top-level document structs ----

type proxyGroupYAML struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

// Clash renders proxies into a Mihomo (Clash Meta) YAML subscription.
//
// When extra is nil, emits a minimal valid Mihomo config: proxies, a PROXY
// select group containing all proxies, and a single MATCH,PROXY rule.
//
// When extra is non-nil, it is treated as a user-provided base YAML (loaded
// from clash_extra config path). Merge semantics:
//   - `proxies` is ALWAYS overwritten with the generated list.
//   - `proxy-groups`, `rules`, `dns`, `tun`, `rule-providers`, etc. are taken
//     from extra as-is. The user references our proxies via Mihomo's
//     `include-all-proxies: true` (or similar) in their groups.
//   - If extra has no `proxy-groups`, the default PROXY select group is added.
//   - If extra has no `rules`, the default MATCH,PROXY rule is added.
//
// Duplicate proxy names: the second occurrence is renamed "name-2", third
// "name-3", etc. This happens before proxy-group name collection so group
// membership stays consistent.
func Clash(proxies []proxy.Proxy, extra map[string]any) ([]byte, error) {
	names := make([]string, 0, len(proxies))
	// seen tracks how many times each base name has appeared so far.
	seen := make(map[string]int, len(proxies))
	// used tracks every name already emitted to detect suffix collisions.
	// For example, if the input contains both "node-2" (explicit) and a
	// duplicate "node", the suffix generator bumps the counter until it
	// finds a candidate not yet in used, avoiding silent duplicates.
	used := make(map[string]struct{}, len(proxies))

	for _, p := range proxies {
		base := p.Name
		if base == "" {
			base = fmt.Sprintf("%s-%s-%d", p.Type, p.Server, p.Port)
		}
		count := seen[base]
		seen[base]++
		if count == 0 {
			names = append(names, base)
			used[base] = struct{}{}
		} else {
			// Bump counter until the candidate is not already taken.
			n := count + 1
			for {
				candidate := fmt.Sprintf("%s-%d", base, n)
				if _, taken := used[candidate]; !taken {
					names = append(names, candidate)
					used[candidate] = struct{}{}
					break
				}
				n++
			}
		}
	}

	yamlProxies := make([]any, 0, len(proxies))
	for i, p := range proxies {
		name := names[i]
		entry, err := buildProxyEntry(p, name)
		if err != nil {
			return nil, fmt.Errorf("proxy %q: %w", name, err)
		}
		yamlProxies = append(yamlProxies, entry)
	}

	// Build output as a map so user-provided top-level keys (dns, tun, etc)
	// are preserved. yaml.v3 emits map keys in alphabetical order, which is
	// stable and acceptable for Mihomo (key order has no functional meaning).
	out := make(map[string]any, len(extra)+3)
	for k, v := range extra {
		out[k] = v
	}
	out["proxies"] = yamlProxies

	if _, has := out["proxy-groups"]; !has {
		out["proxy-groups"] = []proxyGroupYAML{
			{Name: "PROXY", Type: "select", Proxies: names},
		}
	}
	if _, has := out["rules"]; !has {
		out["rules"] = []string{"MATCH,PROXY"}
	}

	return yaml.Marshal(out)
}

// buildProxyEntry converts a single Proxy into the appropriate typed YAML struct.
func buildProxyEntry(p proxy.Proxy, name string) (any, error) {
	switch p.Type {
	case "vless":
		return buildVless(p, name), nil
	case "vmess":
		return buildVmess(p, name), nil
	case "trojan":
		return buildTrojan(p, name), nil
	case "ss":
		return buildSS(p, name), nil
	case "hysteria2":
		return buildHysteria2(p, name), nil
	case "tuic":
		return buildTUIC(p, name), nil
	case "wireguard":
		return buildWireGuard(p, name), nil
	case "ssr":
		return buildSSR(p, name), nil
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", p.Type)
	}
}

func buildVless(p proxy.Proxy, name string) vlessYAML {
	v := vlessYAML{
		Name:       name,
		Type:       "vless",
		Server:     p.Server,
		Port:       p.Port,
		UUID:       p.UUID,
		UDP:        true,
		Flow:       p.Flow,
		Encryption: p.Encryption,
	}

	// omit network field for tcp (Mihomo default)
	if p.Network != "" && p.Network != "tcp" {
		v.Network = p.Network
	}

	if p.TLS != nil && p.TLS.Enabled {
		v.TLS = true
		v.Servername = p.TLS.SNI
		v.ALPN = p.TLS.ALPN
		v.ClientFingerprint = p.TLS.Fingerprint
		if p.TLS.SkipVerify {
			v.SkipCertVerify = true
		}
	}

	if p.Reality != nil {
		v.RealityOpts = &realityOptsYAML{
			PublicKey: p.Reality.PublicKey,
			ShortID:   p.Reality.ShortID,
		}
	}

	v.WSOpts = buildWSopts(p)
	v.GRPCOpts = buildGRPCopts(p)
	v.XHTTPOpts = buildXHTTPopts(p)

	return v
}

func buildVmess(p proxy.Proxy, name string) vmessYAML {
	cipher := p.Cipher
	if cipher == "" {
		cipher = "auto"
	}

	v := vmessYAML{
		Name:    name,
		Type:    "vmess",
		Server:  p.Server,
		Port:    p.Port,
		UUID:    p.UUID,
		AlterID: p.AlterID,
		Cipher:  cipher,
		UDP:     true,
	}

	// Determine the effective network for Mihomo output.
	//
	// VMess "tcp with HTTP obfuscation header" is parsed as Network=tcp with
	// p.HTTP populated. Mihomo does NOT support a tcp+http-opts combination;
	// the correct representation is network: http with http-opts. We rewrite
	// tcp→http here when HTTPConfig is present so Mihomo accepts the config.
	effectiveNetwork := p.Network
	if effectiveNetwork == "tcp" && p.HTTP != nil {
		effectiveNetwork = "http"
	}

	if effectiveNetwork != "" && effectiveNetwork != "tcp" {
		v.Network = effectiveNetwork
	}

	if p.TLS != nil && p.TLS.Enabled {
		v.TLS = true
		v.Servername = p.TLS.SNI
		v.ALPN = p.TLS.ALPN
		v.ClientFingerprint = p.TLS.Fingerprint
		if p.TLS.SkipVerify {
			v.SkipCertVerify = true
		}
	}

	v.WSOpts = buildWSopts(p)
	v.GRPCOpts = buildGRPCopts(p)
	v.H2Opts = buildH2opts(p)
	v.HTTPOpts = buildHTTPopts(p)

	return v
}

func buildTrojan(p proxy.Proxy, name string) trojanYAML {
	t := trojanYAML{
		Name:     name,
		Type:     "trojan",
		Server:   p.Server,
		Port:     p.Port,
		Password: p.Password,
		UDP:      true,
	}

	if p.Network != "" && p.Network != "tcp" {
		t.Network = p.Network
	}

	// Trojan uses `sni` NOT `servername` — Mihomo quirk.
	// TLS is implicit for trojan; do not emit tls: true.
	if p.TLS != nil {
		t.SNI = p.TLS.SNI
		t.ALPN = p.TLS.ALPN
		t.ClientFingerprint = p.TLS.Fingerprint
		if p.TLS.SkipVerify {
			t.SkipCertVerify = true
		}
	}

	t.WSOpts = buildWSopts(p)
	t.GRPCOpts = buildGRPCopts(p)

	return t
}

func buildSS(p proxy.Proxy, name string) ssYAML {
	s := ssYAML{
		Name:     name,
		Type:     "ss",
		Server:   p.Server,
		Port:     p.Port,
		Cipher:   p.Cipher,
		Password: p.Password,
		UDP:      true,
	}
	if p.SSPlugin != nil && p.SSPlugin.Name != "" {
		s.Plugin = p.SSPlugin.Name
		s.PluginOpts = &ssPluginOptsYAML{
			Mode:           p.SSPlugin.Mode,
			Host:           p.SSPlugin.Host,
			Path:           p.SSPlugin.Path,
			TLS:            p.SSPlugin.TLS,
			SkipCertVerify: p.SSPlugin.SkipCertVerify,
			Mux:            p.SSPlugin.Mux,
			Password:       p.SSPlugin.Password,
			Version:        p.SSPlugin.Version,
		}
	}
	return s
}

func buildHysteria2(p proxy.Proxy, name string) hysteria2YAML {
	h := hysteria2YAML{
		Name:     name,
		Type:     "hysteria2",
		Server:   p.Server,
		Port:     p.Port,
		Password: p.Password,
		UDP:      true,
	}
	if p.TLS != nil {
		h.SNI = p.TLS.SNI
		h.ALPN = p.TLS.ALPN
		if p.TLS.SkipVerify {
			h.SkipCertVerify = true
		}
	}
	if p.Hysteria2 != nil {
		h.Obfs = p.Hysteria2.ObfsType
		h.ObfsPassword = p.Hysteria2.ObfsPassword
		h.Up = p.Hysteria2.Up
		h.Down = p.Hysteria2.Down
	}
	return h
}

func buildTUIC(p proxy.Proxy, name string) tuicYAML {
	t := tuicYAML{
		Name:     name,
		Type:     "tuic",
		Server:   p.Server,
		Port:     p.Port,
		UUID:     p.UUID,
		Password: p.Password,
		UDP:      true,
	}
	if p.TLS != nil {
		t.SNI = p.TLS.SNI
		t.ALPN = p.TLS.ALPN
		if p.TLS.SkipVerify {
			t.SkipCertVerify = true
		}
	}
	if p.TUIC != nil {
		t.CongestionController = p.TUIC.CongestionController
		t.UDPRelayMode = p.TUIC.UDPRelayMode
		t.ReduceRTT = p.TUIC.ReduceRTT
		t.DisableSNI = p.TUIC.DisableSNI
	}
	return t
}

func buildWireGuard(p proxy.Proxy, name string) wireguardYAML {
	w := wireguardYAML{
		Name:   name,
		Type:   "wireguard",
		Server: p.Server,
		Port:   p.Port,
		UDP:    true,
	}
	if p.WireGuard != nil {
		w.PrivateKey = p.WireGuard.PrivateKey
		w.PublicKey = p.WireGuard.PublicKey
		w.PresharedKey = p.WireGuard.PresharedKey
		w.IP = p.WireGuard.IP
		w.IPv6 = p.WireGuard.IPv6
		w.MTU = p.WireGuard.MTU
		w.AllowedIPs = p.WireGuard.AllowedIPs
		w.Reserved = p.WireGuard.Reserved
	}
	return w
}

func buildSSR(p proxy.Proxy, name string) ssrYAML {
	s := ssrYAML{
		Name:     name,
		Type:     "ssr",
		Server:   p.Server,
		Port:     p.Port,
		Cipher:   p.Cipher,
		Password: p.Password,
		UDP:      true,
	}
	if p.SSR != nil {
		s.Protocol = p.SSR.Protocol
		s.ProtocolParam = p.SSR.ProtocolParam
		s.Obfs = p.SSR.Obfs
		s.ObfsParam = p.SSR.ObfsParam
	}
	return s
}

// buildWSopts returns ws-opts if the proxy uses WebSocket transport, else nil.
func buildWSopts(p proxy.Proxy) *wsOptsYAML {
	if p.Network != "ws" || p.WS == nil {
		return nil
	}
	opts := &wsOptsYAML{
		Path: p.WS.Path,
	}
	if len(p.WS.Headers) > 0 {
		opts.Headers = p.WS.Headers
	}
	return opts
}

// buildGRPCopts returns grpc-opts if the proxy uses gRPC transport, else nil.
func buildGRPCopts(p proxy.Proxy) *grpcOptsYAML {
	if p.Network != "grpc" || p.GRPC == nil {
		return nil
	}
	return &grpcOptsYAML{
		ServiceName: p.GRPC.ServiceName,
	}
}

// buildXHTTPopts returns xhttp-opts if the proxy uses xhttp transport, else nil.
func buildXHTTPopts(p proxy.Proxy) *xhttpOptsYAML {
	if p.Network != "xhttp" || p.XHTTP == nil {
		return nil
	}
	return &xhttpOptsYAML{
		Mode: p.XHTTP.Mode,
		Path: p.XHTTP.Path,
		Host: p.XHTTP.Host,
	}
}

// buildH2opts returns h2-opts if the proxy uses h2 transport, else nil.
func buildH2opts(p proxy.Proxy) *h2OptsYAML {
	if p.Network != "h2" || p.HTTP == nil {
		return nil
	}
	opts := &h2OptsYAML{
		Host: p.HTTP.Host,
	}
	if len(p.HTTP.Path) > 0 {
		opts.Path = p.HTTP.Path[0]
	}
	return opts
}

// buildHTTPopts returns http-opts for VMess TCP+HTTP obfuscation (network=http
// after the tcp→http rewrite in buildVmess). Returns nil unless the original
// network was tcp with p.HTTP populated, which we detect by checking that
// p.Network is either "tcp" or "http" and p.HTTP is set.
func buildHTTPopts(p proxy.Proxy) *httpOptsYAML {
	if p.HTTP == nil {
		return nil
	}
	// Only emit http-opts for the HTTP-obfuscation case (original network=tcp
	// rewritten to http, or explicitly network=http). h2 is handled separately.
	if p.Network != "tcp" && p.Network != "http" {
		return nil
	}
	method := p.HTTP.Method
	if method == "" {
		method = "GET"
	}
	opts := &httpOptsYAML{
		Method: method,
		Path:   p.HTTP.Path,
	}
	if len(p.HTTP.Host) > 0 {
		opts.Headers = map[string][]string{
			"Host": p.HTTP.Host,
		}
	}
	return opts
}
