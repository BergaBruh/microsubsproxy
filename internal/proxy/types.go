// Package proxy defines the internal Proxy model and URI parsers.
//
// Parsers convert vless://, vmess://, trojan://, ss:// URIs into a unified
// Proxy struct. Renderers (in sibling internal/render package) consume []Proxy
// and produce subscription output in either V2Ray base64 list or Mihomo YAML.
package proxy

// Proxy is the unified representation of a single proxy node, independent of
// source URI scheme. Renderers use it to emit format-specific output.
//
// Raw holds the original URI string. V2Ray-style output is pass-through and
// emits Raw verbatim, so URIs that parse partially (or not at all) can still
// reach the V2Ray renderer if kept in a separate slice. Clash/Mihomo output
// uses only the parsed fields.
type Proxy struct {
	Raw  string
	Type string // "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "tuic" | "wireguard" | "ssr"
	Name string // from #fragment, may be empty

	Server string
	Port   uint16

	UUID     string // vless, vmess, tuic
	Password string // trojan, ss, hysteria2, tuic, ssr
	Cipher   string // ss method, ssr method, or vmess security (aes-128-gcm, chacha20-poly1305, auto, none, zero)
	AlterID  int    // vmess only

	Network string // tcp | ws | grpc | xhttp | httpupgrade | h2
	Flow    string // vless: xtls-rprx-vision (or empty)

	// Encryption holds the VLESS encryption value (post-quantum, e.g.
	// "mlkem768x25519plus.native.0rtt.<base64...>"). Empty means no encryption —
	// the parser normalizes the legacy "none" value to empty so the renderer
	// omits the field (Mihomo treats absent/empty as no encryption).
	Encryption string // vless only

	TLS       *TLSConfig
	Reality   *RealityConfig
	WS        *WSConfig
	GRPC      *GRPCConfig
	HTTP      *HTTPConfig
	XHTTP     *XHTTPConfig
	Hysteria2 *Hysteria2Config
	TUIC      *TUICConfig
	WireGuard *WireGuardConfig
	SSR       *SSRConfig
	SSPlugin  *SSPluginConfig
}

type TLSConfig struct {
	Enabled     bool
	SNI         string
	ALPN        []string
	Fingerprint string // client fingerprint: chrome, firefox, safari, ios, android, edge, 360, qq, random
	SkipVerify  bool
}

type RealityConfig struct {
	PublicKey string
	ShortID   string
	SpiderX   string
}

type WSConfig struct {
	Path    string
	Headers map[string]string // typically just {"Host": "..."}
}

type GRPCConfig struct {
	ServiceName string
	Mode        string // "gun" | "multi"
}

type HTTPConfig struct {
	Method string
	Path   []string
	Host   []string
}

type XHTTPConfig struct {
	Mode string // "packet-up" | "stream-up" | "stream-one"
	Path string
	Host string
}

// Hysteria2Config holds protocol-specific Hysteria2 fields. TLS lives in
// Proxy.TLS (Hysteria2 always uses TLS over QUIC).
type Hysteria2Config struct {
	ObfsType     string // "salamander" or empty
	ObfsPassword string
	// Up/Down speed hints (Mbps). 0 = unset.
	Up   int
	Down int
}

// TUICConfig holds TUIC v5 protocol fields. Auth uses Proxy.UUID + Password.
// TLS lives in Proxy.TLS (TUIC always uses TLS over QUIC).
type TUICConfig struct {
	CongestionController string // "bbr" | "cubic" | "new_reno"
	UDPRelayMode         string // "native" | "quic"
	DisableSNI           bool
	ReduceRTT            bool
}

// WireGuardConfig holds all WireGuard fields. WireGuard has its own crypto;
// Proxy.TLS, UUID, Password are unused for this type.
type WireGuardConfig struct {
	PrivateKey   string
	PublicKey    string // peer public key
	PresharedKey string
	IP           string // assigned IPv4 (e.g. "10.0.0.2/32")
	IPv6         string // assigned IPv6
	MTU          int
	AllowedIPs   []string
	Reserved     []int // 3-byte reserved field (used by Cloudflare WARP)
}

// SSRConfig holds ShadowsocksR-specific fields. Cipher and Password live on
// Proxy. SSR has no TLS layer — protocol/obfs are its own obfuscation.
type SSRConfig struct {
	Protocol      string // e.g. "auth_chain_a", "auth_aes128_md5", "origin"
	ProtocolParam string
	Obfs          string // e.g. "tls1.2_ticket_auth", "http_simple", "plain"
	ObfsParam     string
}

// SSPluginConfig describes a Shadowsocks plugin (SIP003) attached to an SS
// proxy. Common plugins: obfs-local/simple-obfs (alias to mihomo's "obfs"),
// v2ray-plugin (ws transport), shadow-tls.
//
// Mihomo renders plugin opts under a single "plugin-opts" map; fields not
// applicable to the chosen plugin remain empty and are omitted by the renderer.
type SSPluginConfig struct {
	// Name as recognized by mihomo: "obfs" | "v2ray-plugin" | "shadow-tls".
	// The parser normalizes "obfs-local" and "simple-obfs" to "obfs".
	Name string

	// obfs (simple-obfs) opts
	Mode string // "tls" | "http" for obfs; "websocket" for v2ray-plugin
	Host string

	// v2ray-plugin opts
	Path           string
	TLS            bool
	SkipCertVerify bool
	Mux            bool

	// shadow-tls opts
	Password string
	Version  int
}
