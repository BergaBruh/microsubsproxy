package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseWireGuard parses a wireguard:// or wg:// URI into a Proxy.
//
// De facto format (Mihomo/sing-box converters):
//
//	wireguard://<privatekey>@<host>:<port>/?<params>#<name>
//	wg://<privatekey>@<host>:<port>/?<params>#<name>
//
// The userinfo username is the local private key (base64, URL-encoded or not).
// Required query params: publickey (or public-key / peer_publickey).
// Optional: address/ip, presharedkey/preshared-key/psk, allowed_ips/allowedips/allowed-ips,
// mtu, reserved.
func parseWireGuard(uri string) (*Proxy, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, false
	}
	if u.Scheme != "wireguard" && u.Scheme != "wg" {
		return nil, false
	}

	// Private key lives in the userinfo username field.
	// url.Parse percent-decodes User.Username() automatically.
	privateKey := u.User.Username()
	if privateKey == "" {
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

	// Peer public key — required. Try several aliases in order.
	publicKey := q.Get("publickey")
	if publicKey == "" {
		publicKey = q.Get("public-key")
	}
	if publicKey == "" {
		publicKey = q.Get("peer_publickey")
	}
	if publicKey == "" {
		return nil, false
	}

	// Preshared key — optional; try aliases.
	presharedKey := q.Get("presharedkey")
	if presharedKey == "" {
		presharedKey = q.Get("preshared-key")
	}
	if presharedKey == "" {
		presharedKey = q.Get("psk")
	}

	// Address / assigned IP — optional; may be comma-separated "v4,v6".
	var ipv4, ipv6 string
	addrRaw := q.Get("address")
	if addrRaw == "" {
		addrRaw = q.Get("ip")
	}
	if addrRaw != "" {
		for _, part := range strings.Split(addrRaw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// Quick heuristic: colon present → IPv6, otherwise IPv4.
			if strings.Contains(part, ":") {
				if ipv6 == "" {
					ipv6 = part
				}
			} else {
				if ipv4 == "" {
					ipv4 = part
				}
			}
		}
	}

	// Allowed IPs — optional; comma-separated CIDRs. Try several aliases.
	var allowedIPs []string
	allowedRaw := q.Get("allowed_ips")
	if allowedRaw == "" {
		allowedRaw = q.Get("allowedips")
	}
	if allowedRaw == "" {
		allowedRaw = q.Get("allowed-ips")
	}
	if allowedRaw != "" {
		for _, cidr := range strings.Split(allowedRaw, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				allowedIPs = append(allowedIPs, cidr)
			}
		}
	}

	// MTU — optional integer; 0 if unset.
	mtu, _ := strconv.Atoi(q.Get("mtu"))

	// Reserved — three comma-separated ints (Cloudflare WARP).
	var reserved []int
	if reservedRaw := q.Get("reserved"); reservedRaw != "" {
		parts := strings.Split(reservedRaw, ",")
		ok := true
		tmp := make([]int, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				ok = false
				break
			}
			tmp = append(tmp, n)
		}
		if ok {
			reserved = tmp
		}
	}

	// Name from fragment; url.Parse already percent-decodes it.
	name := u.Fragment
	if name == "" {
		name = fallbackName("wireguard", host, port)
	}

	p := &Proxy{
		Raw:    uri,
		Type:   "wireguard",
		Name:   name,
		Server: host,
		Port:   port,
		// UUID, Password, Cipher, Network intentionally left empty for WireGuard.
		WireGuard: &WireGuardConfig{
			PrivateKey:   privateKey,
			PublicKey:    publicKey,
			PresharedKey: presharedKey,
			IP:           ipv4,
			IPv6:         ipv6,
			MTU:          mtu,
			AllowedIPs:   allowedIPs,
			Reserved:     reserved,
		},
	}

	return p, true
}
