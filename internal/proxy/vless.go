package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseVLESS parses a vless:// URI into a Proxy.
// Format: vless://<uuid>@<host>:<port>?<params>#<name>
func parseVLESS(uri string) (*Proxy, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, false
	}
	if u.Scheme != "vless" {
		return nil, false
	}

	// UUID is the userinfo (no password in vless)
	uuid := u.User.Username()
	if uuid == "" {
		return nil, false
	}

	// Host and port
	host := u.Hostname()
	if host == "" {
		return nil, false
	}
	portStr := u.Port()
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, false
	}
	port := uint16(portNum)

	// Query params
	q := u.Query()

	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}

	security := q.Get("security")
	flow := q.Get("flow")
	sni := q.Get("sni")

	// VLESS encryption (post-quantum, e.g. mlkem768x25519plus...). Legacy/empty
	// "none" means no encryption — normalize to empty so the renderer omits it.
	encryption := q.Get("encryption")
	if encryption == "none" {
		encryption = ""
	}

	// Parse ALPN — may be URL-encoded commas (e.g. h2%2Chttp%2F1.1)
	var alpn []string
	if alpnRaw := q.Get("alpn"); alpnRaw != "" {
		for _, a := range strings.Split(alpnRaw, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpn = append(alpn, a)
			}
		}
	}

	fp := q.Get("fp")

	// Name
	name := u.Fragment
	if name == "" {
		name = fallbackName("vless", host, port)
	}

	p := &Proxy{
		Raw:        uri,
		Type:       "vless",
		Name:       name,
		Server:     host,
		Port:       port,
		UUID:       uuid,
		Network:    network,
		Flow:       flow,
		Encryption: encryption,
	}

	// allowInsecure: accept both "allowInsecure" and "insecure" query params.
	// Values "1" or "true" (case-insensitive) map to SkipVerify=true.
	aiRaw := q.Get("allowInsecure")
	if aiRaw == "" {
		aiRaw = q.Get("insecure")
	}
	skipVerify := aiRaw == "1" || strings.EqualFold(aiRaw, "true")

	// TLS / Reality
	if security == "tls" || security == "reality" {
		// For Reality, default fingerprint to "chrome" when not specified so
		// Mihomo has a valid client-fingerprint and doesn't fail the handshake.
		if security == "reality" && fp == "" {
			fp = "chrome"
		}
		p.TLS = &TLSConfig{
			Enabled:     true,
			SNI:         sni,
			ALPN:        alpn,
			Fingerprint: fp,
			SkipVerify:  skipVerify,
		}
		if security == "reality" {
			p.Reality = &RealityConfig{
				PublicKey: q.Get("pbk"),
				ShortID:   q.Get("sid"),
				SpiderX:   q.Get("spx"),
			}
		}
	}

	// Transport-specific config
	switch network {
	case "ws", "httpupgrade":
		wsPath := q.Get("path")
		wsHost := q.Get("host")
		ws := &WSConfig{
			Path: wsPath,
		}
		if wsHost != "" {
			ws.Headers = map[string]string{"Host": wsHost}
		}
		p.WS = ws

	case "grpc":
		serviceName := q.Get("serviceName")
		mode := q.Get("mode")
		// Only allocate if there's something meaningful to store
		if serviceName != "" || mode != "" {
			p.GRPC = &GRPCConfig{
				ServiceName: serviceName,
				Mode:        mode,
			}
		}

	case "xhttp":
		mode := q.Get("mode")
		xPath := q.Get("path")
		xHost := q.Get("host")
		if mode != "" || xPath != "" || xHost != "" {
			p.XHTTP = &XHTTPConfig{
				Mode: mode,
				Path: xPath,
				Host: xHost,
			}
		}
	}

	return p, true
}
