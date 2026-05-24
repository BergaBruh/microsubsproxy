package proxy

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// parseSS parses an ss:// URI (SIP002 or legacy base64) into a Proxy.
//
// Three real-world variants are handled:
//
//	Variant A — SIP002 with base64 userinfo:
//	  ss://<base64(method:password)>@<host>:<port>[?plugin=...]#<name>
//
//	Variant B — SIP002 with plaintext userinfo:
//	  ss://method:password@host:port#name
//
//	Variant C — legacy (whole body is base64):
//	  ss://<base64(method:password@host:port)>#<name>
func parseSS(uri string) (*Proxy, bool) {
	if !strings.HasPrefix(uri, "ss://") {
		return nil, false
	}

	// Strip scheme.
	body := uri[len("ss://"):]

	// Peel off the trailing #fragment before any other processing so that
	// base64 padding characters ("=") are not confused with query separators.
	name := ""
	if idx := strings.Index(body, "#"); idx != -1 {
		rawFrag := body[idx+1:]
		body = body[:idx]
		// Percent-decode the fragment (best-effort; ignore errors).
		if decoded, err := url.PathUnescape(rawFrag); err == nil {
			name = decoded
		} else {
			name = rawFrag
		}
	}

	var method, password, host, portStr, rawQuery string

	if strings.Contains(body, "@") {
		// ---- SIP002 (variant A or B) ----
		//
		// Split on the LAST "@" so that passwords containing "@" (percent-encoded
		// in Variant B, embedded literally after base64 decoding in Variant A) are
		// handled correctly. The host:port portion never contains "@".
		atIdx := strings.LastIndex(body, "@")
		userinfo := body[:atIdx]
		hostport := body[atIdx+1:]

		// Peel off ?plugin=... query for later parsing.
		if qIdx := strings.Index(hostport, "?"); qIdx != -1 {
			rawQuery = hostport[qIdx+1:]
			hostport = hostport[:qIdx]
		}

		// Split host:port.
		colonIdx := strings.LastIndex(hostport, ":")
		if colonIdx == -1 {
			return nil, false
		}
		host = hostport[:colonIdx]
		portStr = hostport[colonIdx+1:]

		// Try to base64-decode the userinfo (Variant A).
		// Accept both standard and URL-safe encodings with or without padding.
		decoded, err := tryBase64Decode(userinfo)
		if err == nil && strings.Count(decoded, ":") >= 1 {
			// Decoded successfully and looks like "method:password".
			// Split only on the FIRST colon — method never contains colons,
			// but passwords might (though unusual when base64-encoded).
			colonPos := strings.Index(decoded, ":")
			method = decoded[:colonPos]
			password = decoded[colonPos+1:]
		} else {
			// Variant B — userinfo is URL-encoded plaintext "method:password".
			plain, decErr := url.PathUnescape(userinfo)
			if decErr != nil {
				plain = userinfo
			}
			colonPos := strings.Index(plain, ":")
			if colonPos == -1 {
				return nil, false
			}
			method = plain[:colonPos]
			password = plain[colonPos+1:]
		}
	} else {
		// ---- Legacy (Variant C) ----
		// The entire body (before #) is base64(method:password@host:port).
		decoded, err := tryBase64Decode(body)
		if err != nil {
			return nil, false
		}
		// Expected format after decoding: "method:password@host:port"
		atIdx := strings.LastIndex(decoded, "@")
		if atIdx == -1 {
			return nil, false
		}
		credPart := decoded[:atIdx]
		hostport := decoded[atIdx+1:]

		colonIdx := strings.Index(credPart, ":")
		if colonIdx == -1 {
			return nil, false
		}
		method = credPart[:colonIdx]
		password = credPart[colonIdx+1:]

		colonIdx2 := strings.LastIndex(hostport, ":")
		if colonIdx2 == -1 {
			return nil, false
		}
		host = hostport[:colonIdx2]
		portStr = hostport[colonIdx2+1:]
	}

	// Normalize.
	method = strings.ToLower(strings.TrimSpace(method))
	password = strings.TrimSpace(password)
	host = strings.Trim(strings.TrimSpace(host), "[]") // strip IPv6 brackets if present

	// Validate.
	if method == "" || password == "" || host == "" {
		return nil, false
	}

	portNum, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil || portNum == 0 {
		return nil, false
	}
	port := uint16(portNum)

	if name == "" {
		name = fallbackName("ss", host, port)
	}

	p := &Proxy{
		Raw:      uri,
		Type:     "ss",
		Name:     name,
		Server:   host,
		Port:     port,
		Password: password,
		Cipher:   method,
		Network:  "tcp",
	}

	if rawQuery != "" {
		if plugin := parseSSPluginQuery(rawQuery); plugin != nil {
			p.SSPlugin = plugin
		}
	}

	return p, true
}

// parseSSPluginQuery extracts an SS plugin spec from a SIP002 query string.
// Returns nil if no plugin field is present or the spec can't be parsed.
//
// Input is the raw query (already URL-encoded), e.g.
//
//	plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.com
//
// Plugin string format after url-decoding:
//
//	<plugin-name>;<key>=<value>;<key>=<value>;...
//
// Standalone tokens (e.g. "tls" in v2ray-plugin) are treated as boolean flags
// set to true.
func parseSSPluginQuery(rawQuery string) *SSPluginConfig {
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	spec := strings.TrimSpace(vals.Get("plugin"))
	if spec == "" {
		return nil
	}

	parts := strings.Split(spec, ";")
	rawName := strings.TrimSpace(parts[0])
	if rawName == "" {
		return nil
	}

	// Normalize plugin names to mihomo's vocabulary.
	name := rawName
	switch rawName {
	case "obfs-local", "simple-obfs":
		name = "obfs"
	}

	cfg := &SSPluginConfig{Name: name}

	for _, kv := range parts[1:] {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		var key, val string
		if eq := strings.Index(kv, "="); eq != -1 {
			key = strings.TrimSpace(kv[:eq])
			val = strings.TrimSpace(kv[eq+1:])
		} else {
			// bare flag token
			key = kv
			val = "true"
		}

		switch key {
		// obfs (simple-obfs) opts
		case "obfs":
			cfg.Mode = val // "tls" | "http"
		case "obfs-host":
			cfg.Host = val

		// v2ray-plugin opts — see https://github.com/shadowsocks/v2ray-plugin
		case "mode":
			cfg.Mode = val // "websocket"
		case "host":
			cfg.Host = val
		case "path":
			cfg.Path = val
		case "tls":
			cfg.TLS = boolish(val)
		case "skip-cert-verify", "insecure":
			cfg.SkipCertVerify = boolish(val)
		case "mux":
			cfg.Mux = boolish(val)

		// shadow-tls opts
		case "password":
			cfg.Password = val
		case "version":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.Version = n
			}
		}
	}

	return cfg
}

func boolish(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// tryBase64Decode attempts to decode s using standard, URL-safe, and
// unpadded variants of base64.  Returns the decoded string and nil on the
// first successful decode, or a non-nil error if all attempts fail.
func tryBase64Decode(s string) (string, error) {
	// Normalise: replace URL-safe characters so we only need two paths.
	stdForm := strings.NewReplacer("-", "+", "_", "/").Replace(s)

	// 1. Standard with padding (as-is).
	if b, err := base64.StdEncoding.DecodeString(stdForm); err == nil {
		return string(b), nil
	}

	// 2. Standard without padding (RawStdEncoding).
	if b, err := base64.RawStdEncoding.DecodeString(stdForm); err == nil {
		return string(b), nil
	}

	// 3. URL-safe with padding.
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}

	// 4. URL-safe without padding (RawURLEncoding).
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}

	return "", base64.CorruptInputError(0)
}
