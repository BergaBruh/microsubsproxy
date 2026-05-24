package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseSSR parses an ssr:// URI (legacy ShadowsocksR base64-encoded format) into a Proxy.
//
// SSR URI format:
//
//	ssr://<base64url(host:port:protocol:method:obfs:base64url(password)/?<params>)>
//
// After stripping "ssr://" the remainder is URL-safe base64 (no padding typical) of:
//
//	<host>:<port>:<protocol>:<method>:<obfs>:<b64password>/?<params>
//
// Each query-param value in <params> is itself URL-safe base64-encoded.
// Known params: obfsparam, protoparam, remarks, group (group is ignored).
func parseSSR(uri string) (*Proxy, bool) {
	if !strings.HasPrefix(uri, "ssr://") {
		return nil, false
	}

	// Strip scheme.
	encoded := uri[len("ssr://"):]
	if encoded == "" {
		return nil, false
	}

	// Decode the outer base64 blob.
	decoded, err := tryBase64Decode(encoded)
	if err != nil {
		return nil, false
	}

	// Split at the first "/?" to separate main fields from query params.
	var main, rawParams string
	if idx := strings.Index(decoded, "/?"); idx != -1 {
		main = decoded[:idx]
		rawParams = decoded[idx+2:]
	} else {
		main = decoded
		rawParams = ""
	}

	// Split main into exactly 6 colon-separated fields:
	// host:port:protocol:method:obfs:b64password
	parts := strings.SplitN(main, ":", 6)
	if len(parts) != 6 {
		return nil, false
	}
	host := strings.TrimSpace(parts[0])
	portStr := strings.TrimSpace(parts[1])
	protocol := strings.TrimSpace(parts[2])
	method := strings.TrimSpace(parts[3])
	obfs := strings.TrimSpace(parts[4])
	b64password := strings.TrimSpace(parts[5])

	if host == "" {
		return nil, false
	}

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, false
	}
	port := uint16(portNum)

	password, err := tryBase64Decode(b64password)
	if err != nil || password == "" {
		return nil, false
	}

	// Parse query parameters; each value is itself base64-encoded.
	var obfsParam, protoParam, remarks string
	if rawParams != "" {
		qvals, qerr := url.ParseQuery(rawParams)
		if qerr == nil {
			if v := qvals.Get("obfsparam"); v != "" {
				if dec, decErr := tryBase64Decode(v); decErr == nil {
					obfsParam = dec
				}
			}
			if v := qvals.Get("protoparam"); v != "" {
				if dec, decErr := tryBase64Decode(v); decErr == nil {
					protoParam = dec
				}
			}
			if v := qvals.Get("remarks"); v != "" {
				if dec, decErr := tryBase64Decode(v); decErr == nil {
					remarks = dec
				}
			}
			// "group" is parsed but intentionally ignored.
		}
	}

	// Apply defaults for protocol and obfs.
	if protocol == "" {
		protocol = "origin"
	}
	if obfs == "" {
		obfs = "plain"
	}

	// Determine name.
	name := remarks
	if name == "" {
		name = fallbackName("ssr", host, port)
	}

	return &Proxy{
		Raw:      uri,
		Type:     "ssr",
		Name:     name,
		Server:   host,
		Port:     port,
		Cipher:   strings.ToLower(method),
		Password: password,
		Network:  "tcp",
		SSR: &SSRConfig{
			Protocol:      protocol,
			ProtocolParam: protoParam,
			Obfs:          obfs,
			ObfsParam:     obfsParam,
		},
	}, true
}
