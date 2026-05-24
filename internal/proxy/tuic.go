package proxy

import (
	"net/url"
	"strconv"
	"strings"
)

// parseTUIC parses a tuic:// URI (TUIC v5) into a Proxy.
// Format: tuic://<uuid>:<password>@<host>:<port>/?<params>#<name>
// TUIC always uses TLS over QUIC — TLS is unconditionally allocated.
func parseTUIC(uri string) (*Proxy, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, false
	}
	if u.Scheme != "tuic" {
		return nil, false
	}

	// Userinfo: uuid:password — both required.
	uuid := u.User.Username()
	if uuid == "" {
		return nil, false
	}
	password, hasPassword := u.User.Password()
	if !hasPassword || password == "" {
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

	// TLS params — TUIC always runs TLS over QUIC.
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

	// accept allow_insecure=1|true or insecure=1|true
	allowInsecure := q.Get("allow_insecure")
	if allowInsecure == "" {
		allowInsecure = q.Get("insecure")
	}
	skipVerify := allowInsecure == "1" || strings.EqualFold(allowInsecure, "true")

	// Name from fragment; url.Parse already percent-decodes it.
	name := u.Fragment
	if name == "" {
		name = fallbackName("tuic", host, port)
	}

	p := &Proxy{
		Raw:      uri,
		Type:     "tuic",
		Name:     name,
		Server:   host,
		Port:     port,
		UUID:     uuid,
		Password: password,
		TLS: &TLSConfig{
			Enabled:     true,
			SNI:         sni,
			ALPN:        alpn,
			Fingerprint: fp,
			SkipVerify:  skipVerify,
		},
	}

	// TUIC-specific params — accept both underscore and hyphen variants.
	congestion := q.Get("congestion_control")
	if congestion == "" {
		congestion = q.Get("congestion-control")
	}
	udpRelay := q.Get("udp_relay_mode")
	if udpRelay == "" {
		udpRelay = q.Get("udp-relay-mode")
	}
	disableSNIRaw := q.Get("disable_sni")
	reducRTTRaw := q.Get("reduce_rtt")

	disableSNI := disableSNIRaw == "1" || strings.EqualFold(disableSNIRaw, "true")
	reduceRTT := reducRTTRaw == "1" || strings.EqualFold(reducRTTRaw, "true")

	// Allocate TUICConfig only when at least one TUIC-specific param is present.
	if congestion != "" || udpRelay != "" || disableSNI || reduceRTT {
		p.TUIC = &TUICConfig{
			CongestionController: congestion,
			UDPRelayMode:         udpRelay,
			DisableSNI:           disableSNI,
			ReduceRTT:            reduceRTT,
		}
	}

	return p, true
}
