package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseTrojan parses a trojan:// URI into a Proxy.
// Format: trojan://<password>@<host>:<port>?<params>#<name>
// Trojan always uses TLS — no plain-text mode exists.
func parseTrojan(uri string) (*Proxy, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, false
	}
	if u.Scheme != "trojan" {
		return nil, false
	}

	// Password is in userinfo; url.Parse percent-decodes it.
	password, _ := u.User.Password()
	if password == "" {
		// Some clients encode the password as the username with no ":" separator.
		// Fall back to username when no colon is present.
		password = u.User.Username()
	}
	if password == "" {
		return nil, false
	}

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

	q := u.Query()

	// Transport type — default tcp
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}

	// TLS params — always enabled for Trojan
	sni := q.Get("sni")
	fp := q.Get("fp")

	var alpn []string
	if alpnRaw := q.Get("alpn"); alpnRaw != "" {
		for _, a := range strings.Split(alpnRaw, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpn = append(alpn, a)
			}
		}
	}

	allowInsecure := q.Get("allowInsecure")
	skipVerify := allowInsecure == "1" || strings.EqualFold(allowInsecure, "true")

	// Name from fragment; url.Parse already percent-decodes it.
	name := u.Fragment
	if name == "" {
		name = fallbackName("trojan", host, port)
	}

	p := &Proxy{
		Raw:      uri,
		Type:     "trojan",
		Name:     name,
		Server:   host,
		Port:     port,
		Password: password,
		Network:  network,
		TLS: &TLSConfig{
			Enabled:     true,
			SNI:         sni,
			ALPN:        alpn,
			Fingerprint: fp,
			SkipVerify:  skipVerify,
		},
	}

	// Transport-specific config
	switch network {
	case "ws":
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
		if serviceName != "" || mode != "" {
			p.GRPC = &GRPCConfig{
				ServiceName: serviceName,
				Mode:        mode,
			}
		}
	}

	return p, true
}
