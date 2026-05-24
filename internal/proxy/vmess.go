package proxy

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// vmessJSON is the V2RayN-style decoded payload.
// Ports and AlterID arrive as either string or number depending on the panel,
// so we capture them as json.RawMessage and convert in intOrString helpers.
type vmessJSON struct {
	V    string          `json:"v"`
	PS   string          `json:"ps"`
	Add  string          `json:"add"`
	Port json.RawMessage `json:"port"`
	ID   string          `json:"id"`
	Aid  json.RawMessage `json:"aid"`
	// cipher: "scy" is the canonical field; "security" is an alias used by
	// some panels (e.g. v2rayN forks).
	Scy      string `json:"scy"`
	Security string `json:"security"`
	Net      string `json:"net"`
	Type     string `json:"type"` // header type for tcp / grpc mode, NOT the same as net
	Host     string `json:"host"`
	Path     string `json:"path"`
	TLS      string `json:"tls"`
	SNI      string `json:"sni"`
	ALPN     string `json:"alpn"`
	FP       string `json:"fp"`
	// TLS verification skip — different panels use different key names.
	// skip_cert_verify=true or allowInsecure=true → skip.
	// verify_hostname=false → skip (inverted semantics).
	SkipCertVerify json.RawMessage `json:"skip_cert_verify"`
	AllowInsecure  json.RawMessage `json:"allowInsecure"`
	VerifyHostname json.RawMessage `json:"verify_hostname"`
}

// rawToInt converts a json.RawMessage that is either a JSON number or a
// quoted string (e.g. "443" or 443) into an int. Returns 0 on failure.
func rawToInt(r json.RawMessage) int {
	if len(r) == 0 {
		return 0
	}
	// Try unquoted number first.
	var n int
	if err := json.Unmarshal(r, &n); err == nil {
		return n
	}
	// Try quoted string.
	var s string
	if err := json.Unmarshal(r, &s); err == nil {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return 0
}

// rawToBool converts a json.RawMessage that may be a JSON bool, a quoted
// string ("true"/"1"/"false"/"0"), or a number (1/0) into a Go bool.
// Returns false on any parse failure or empty input.
func rawToBool(r json.RawMessage) bool {
	if len(r) == 0 {
		return false
	}
	// Try JSON bool first.
	var b bool
	if err := json.Unmarshal(r, &b); err == nil {
		return b
	}
	// Try quoted string.
	var s string
	if err := json.Unmarshal(r, &s); err == nil {
		sl := strings.ToLower(strings.TrimSpace(s))
		return sl == "true" || sl == "1"
	}
	// Try number (1 = true, 0 = false).
	var n int
	if err := json.Unmarshal(r, &n); err == nil {
		return n != 0
	}
	return false
}

// b64Encodings lists every base64 variant we attempt in order.
// Many panels produce standard-padded output; V2RayN itself uses standard
// encoding; some web converters emit URL-safe or raw (no-padding) variants.
var b64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// parseVMess parses a vmess:// URI (base64-encoded JSON payload) into a Proxy.
func parseVMess(uri string) (*Proxy, bool) {
	const prefix = "vmess://"
	if !strings.HasPrefix(uri, prefix) {
		return nil, false
	}
	payload := uri[len(prefix):]
	// Some URIs have a trailing newline or whitespace.
	payload = strings.TrimSpace(payload)

	// Try each base64 variant until one yields valid JSON.
	var v vmessJSON
	decoded := false
	for _, enc := range b64Encodings {
		data, err := enc.DecodeString(payload)
		if err != nil {
			continue
		}
		if err = json.Unmarshal(data, &v); err != nil {
			continue
		}
		decoded = true
		break
	}
	if !decoded {
		return nil, false
	}

	// Required fields.
	server := strings.TrimSpace(v.Add)
	if server == "" {
		return nil, false
	}
	uuid := strings.TrimSpace(v.ID)
	if uuid == "" {
		return nil, false
	}
	port := rawToInt(v.Port)
	if port <= 0 || port > 65535 {
		return nil, false
	}

	// Cipher: prefer "scy", fall back to "security" alias.
	cipher := v.Scy
	if cipher == "" {
		cipher = v.Security
	}

	alterID := rawToInt(v.Aid)

	// Name.
	name := strings.TrimSpace(v.PS)
	if name == "" {
		name = fallbackName("vmess", server, uint16(port))
	}

	// Network defaults to tcp.
	network := v.Net
	if network == "" {
		network = "tcp"
	}

	p := &Proxy{
		Raw:     uri,
		Type:    "vmess",
		Name:    name,
		Server:  server,
		Port:    uint16(port),
		UUID:    uuid,
		Cipher:  cipher,
		AlterID: alterID,
		Network: network,
	}

	// TLS.
	if strings.EqualFold(v.TLS, "tls") {
		var alpn []string
		if v.ALPN != "" {
			for _, a := range strings.Split(v.ALPN, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					alpn = append(alpn, a)
				}
			}
		}
		// skip_cert_verify=true OR allowInsecure=true OR verify_hostname=false
		// → SkipVerify=true. Only evaluated when TLS is active.
		skipVerify := rawToBool(v.SkipCertVerify) ||
			rawToBool(v.AllowInsecure) ||
			(len(v.VerifyHostname) > 0 && !rawToBool(v.VerifyHostname))
		p.TLS = &TLSConfig{
			Enabled:     true,
			SNI:         v.SNI,
			ALPN:        alpn,
			Fingerprint: v.FP,
			SkipVerify:  skipVerify,
		}
	}

	// Transport-specific config.
	switch network {
	case "ws":
		ws := &WSConfig{Path: v.Path}
		if v.Host != "" {
			ws.Headers = map[string]string{"Host": v.Host}
		}
		p.WS = ws

	case "grpc":
		// V2RayN reuses the "path" field as the gRPC service name.
		mode := "gun"
		if strings.EqualFold(v.Type, "multi") {
			mode = "multi"
		}
		p.GRPC = &GRPCConfig{
			ServiceName: v.Path,
			Mode:        mode,
		}

	case "h2", "http":
		hc := &HTTPConfig{}
		if v.Path != "" {
			hc.Path = []string{v.Path}
		}
		if v.Host != "" {
			hc.Host = []string{v.Host}
		}
		p.HTTP = hc

	case "tcp":
		// TCP with HTTP obfuscation header (rare but valid).
		if strings.EqualFold(v.Type, "http") {
			hc := &HTTPConfig{}
			if v.Path != "" {
				hc.Path = []string{v.Path}
			}
			if v.Host != "" {
				hc.Host = []string{v.Host}
			}
			p.HTTP = hc
		}
	}

	return p, true
}
