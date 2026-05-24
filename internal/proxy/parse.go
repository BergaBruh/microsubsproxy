package proxy

import (
	"fmt"
	"strings"
)

// Parse dispatches a single URI string to the appropriate parser by scheme.
// Returns (nil, false) when the URI scheme is unsupported. Unsupported URIs
// are skipped silently by callers — this matches the existing valid_prefixes
// filter behavior in fetch logic.
func Parse(uri string) (*Proxy, bool) {
	uri = strings.TrimSpace(uri)
	switch {
	case strings.HasPrefix(uri, "vless://"):
		return parseVLESS(uri)
	case strings.HasPrefix(uri, "vmess://"):
		return parseVMess(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojan(uri)
	case strings.HasPrefix(uri, "ssr://"):
		// Must come BEFORE ss:// — strings.HasPrefix("ssr://", "ss://") is true.
		return parseSSR(uri)
	case strings.HasPrefix(uri, "ss://"):
		return parseSS(uri)
	case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
		return parseHysteria2(uri)
	case strings.HasPrefix(uri, "tuic://"):
		return parseTUIC(uri)
	case strings.HasPrefix(uri, "wireguard://"), strings.HasPrefix(uri, "wg://"):
		return parseWireGuard(uri)
	}
	return nil, false
}

// ParseAll parses many URIs. Unparseable URIs are dropped without error.
// Returns parsed Proxies in input order and a count of URIs that could not be
// parsed. Callers should log the dropped count when > 0 to aid debugging —
// do NOT log the URIs themselves as they may contain credentials.
func ParseAll(uris []string) (parsed []Proxy, dropped int) {
	out := make([]Proxy, 0, len(uris))
	for _, u := range uris {
		if p, ok := Parse(u); ok {
			out = append(out, *p)
		} else {
			dropped++
		}
	}
	return out, dropped
}

// fallbackName generates a stable name when the URI fragment is empty.
func fallbackName(typ, server string, port uint16) string {
	return fmt.Sprintf("%s-%s-%d", typ, server, port)
}
