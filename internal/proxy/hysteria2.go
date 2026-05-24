package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseHysteria2 parses a hysteria2:// or hy2:// URI into a Proxy.
// Format: hysteria2://<password>@<host>:<port>/?<params>#<name>
// Both schemes are treated identically; the type field is always "hysteria2".
func parseHysteria2(uri string) (*Proxy, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return nil, false
	}

	// Password lives entirely in the userinfo username field (no colon separator).
	// url.Parse percent-decodes User.Username() automatically.
	password := u.User.Username()
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

	// Name from fragment; url.Parse percent-decodes it.
	name := u.Fragment
	if name == "" {
		name = fallbackName("hysteria2", host, port)
	}

	// TLS — Hysteria2 always uses TLS over QUIC; always allocate.
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

	insecureRaw := q.Get("insecure")
	skipVerify := insecureRaw == "1" || strings.EqualFold(insecureRaw, "true")

	tls := &TLSConfig{
		Enabled:     true,
		SNI:         sni,
		ALPN:        alpn,
		Fingerprint: fp,
		SkipVerify:  skipVerify,
	}

	// Hysteria2-specific config — allocate only when obfs or speed hints present.
	obfsType := q.Get("obfs")
	// Accept both "obfs-password" (hyphen) and "obfs_password" (underscore).
	obfsPassword := q.Get("obfs-password")
	if obfsPassword == "" {
		obfsPassword = q.Get("obfs_password")
	}
	upRaw := q.Get("up")
	downRaw := q.Get("down")

	var hy2cfg *Hysteria2Config
	if obfsType != "" || obfsPassword != "" || upRaw != "" || downRaw != "" {
		up, _ := strconv.Atoi(upRaw)
		down, _ := strconv.Atoi(downRaw)
		hy2cfg = &Hysteria2Config{
			ObfsType:     obfsType,
			ObfsPassword: obfsPassword,
			Up:           up,
			Down:         down,
		}
	}

	p := &Proxy{
		Raw:       uri,
		Type:      "hysteria2",
		Name:      name,
		Server:    host,
		Port:      port,
		Password:  password,
		TLS:       tls,
		Hysteria2: hy2cfg,
	}

	return p, true
}
