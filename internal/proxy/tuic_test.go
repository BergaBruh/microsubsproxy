package proxy

import (
	"testing"
)

func TestParseTUIC(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		wantOk bool
		check  func(t *testing.T, p *Proxy)
	}{
		{
			name:   "plain with sni and alpn fragment",
			uri:    "tuic://uuid-1:secret@example.com:443/?sni=example.com&alpn=h3#tuicnode",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Type != "tuic" {
					t.Errorf("Type=%q, want tuic", p.Type)
				}
				if p.UUID != "uuid-1" {
					t.Errorf("UUID=%q, want uuid-1", p.UUID)
				}
				if p.Password != "secret" {
					t.Errorf("Password=%q, want secret", p.Password)
				}
				if p.Server != "example.com" {
					t.Errorf("Server=%q, want example.com", p.Server)
				}
				if p.Port != 443 {
					t.Errorf("Port=%d, want 443", p.Port)
				}
				if p.Name != "tuicnode" {
					t.Errorf("Name=%q, want tuicnode", p.Name)
				}
				if p.Raw == "" {
					t.Error("Raw should not be empty")
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil, want non-nil")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled=false, want true")
				}
				if p.TLS.SNI != "example.com" {
					t.Errorf("TLS.SNI=%q, want example.com", p.TLS.SNI)
				}
				if len(p.TLS.ALPN) != 1 || p.TLS.ALPN[0] != "h3" {
					t.Errorf("TLS.ALPN=%v, want [h3]", p.TLS.ALPN)
				}
				if p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=true, want false")
				}
				if p.TUIC != nil {
					t.Error("TUIC should be nil when no TUIC-specific params present")
				}
			},
		},
		{
			name:   "full params underscore variants",
			uri:    "tuic://u:p@h:443/?sni=h&alpn=h3&congestion_control=bbr&udp_relay_mode=native&reduce_rtt=1&disable_sni=0#full",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.UUID != "u" {
					t.Errorf("UUID=%q, want u", p.UUID)
				}
				if p.Password != "p" {
					t.Errorf("Password=%q, want p", p.Password)
				}
				if p.Name != "full" {
					t.Errorf("Name=%q, want full", p.Name)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.SNI != "h" {
					t.Errorf("TLS.SNI=%q, want h", p.TLS.SNI)
				}
				if p.TUIC == nil {
					t.Fatal("TUIC is nil, want non-nil")
				}
				if p.TUIC.CongestionController != "bbr" {
					t.Errorf("CongestionController=%q, want bbr", p.TUIC.CongestionController)
				}
				if p.TUIC.UDPRelayMode != "native" {
					t.Errorf("UDPRelayMode=%q, want native", p.TUIC.UDPRelayMode)
				}
				if !p.TUIC.ReduceRTT {
					t.Error("ReduceRTT=false, want true")
				}
				if p.TUIC.DisableSNI {
					t.Error("DisableSNI=true, want false (disable_sni=0)")
				}
			},
		},
		{
			name:   "hyphen variants congestion-control and udp-relay-mode",
			uri:    "tuic://u:p@h:443/?congestion-control=cubic&udp-relay-mode=quic",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TUIC == nil {
					t.Fatal("TUIC is nil, want non-nil")
				}
				if p.TUIC.CongestionController != "cubic" {
					t.Errorf("CongestionController=%q, want cubic", p.TUIC.CongestionController)
				}
				if p.TUIC.UDPRelayMode != "quic" {
					t.Errorf("UDPRelayMode=%q, want quic", p.TUIC.UDPRelayMode)
				}
			},
		},
		{
			name:   "allow_insecure=1 sets SkipVerify",
			uri:    "tuic://u:p@h:443/?allow_insecure=1",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true (allow_insecure=1)")
				}
			},
		},
		{
			name:   "insecure=1 alternate name sets SkipVerify",
			uri:    "tuic://u:p@h:443/?insecure=1",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true (insecure=1)")
				}
			},
		},
		{
			name:   "allow_insecure=true sets SkipVerify",
			uri:    "tuic://u:p@h:443/?allow_insecure=true",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true (allow_insecure=true)")
				}
			},
		},
		{
			name:   "ALPN comma list h3,h2",
			uri:    "tuic://u:p@h:443/?alpn=h3,h2",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if len(p.TLS.ALPN) != 2 {
					t.Fatalf("ALPN len=%d, want 2; got %v", len(p.TLS.ALPN), p.TLS.ALPN)
				}
				if p.TLS.ALPN[0] != "h3" || p.TLS.ALPN[1] != "h2" {
					t.Errorf("ALPN=%v, want [h3 h2]", p.TLS.ALPN)
				}
			},
		},
		{
			name:   "URL-encoded password containing colon",
			uri:    "tuic://myuuid:pass%3Aword@h:443/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.UUID != "myuuid" {
					t.Errorf("UUID=%q, want myuuid", p.UUID)
				}
				if p.Password != "pass:word" {
					t.Errorf("Password=%q, want pass:word", p.Password)
				}
			},
		},
		{
			name:   "URL-encoded password containing @",
			uri:    "tuic://myuuid:pass%40word@h:443/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Password != "pass@word" {
					t.Errorf("Password=%q, want pass@word", p.Password)
				}
			},
		},
		{
			name:   "empty fragment falls back to generated name",
			uri:    "tuic://u:p@myhost:9000/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				want := fallbackName("tuic", "myhost", 9000)
				if p.Name != want {
					t.Errorf("Name=%q, want %q", p.Name, want)
				}
			},
		},
		{
			name:   "TLS always allocated even with no params",
			uri:    "tuic://u:p@h:443/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil, want non-nil (TUIC always TLS)")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled=false, want true")
				}
				if p.TUIC != nil {
					t.Error("TUIC should be nil when no TUIC-specific params present")
				}
			},
		},
		{
			name:   "fp fingerprint stored in TLS",
			uri:    "tuic://u:p@h:443/?fp=chrome",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.Fingerprint != "chrome" {
					t.Errorf("TLS.Fingerprint=%q, want chrome", p.TLS.Fingerprint)
				}
			},
		},
		{
			name:   "disable_sni=1 allocates TUIC with DisableSNI true",
			uri:    "tuic://u:p@h:443/?disable_sni=1",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TUIC == nil {
					t.Fatal("TUIC is nil, want non-nil")
				}
				if !p.TUIC.DisableSNI {
					t.Error("DisableSNI=false, want true")
				}
			},
		},
		// --- Invalid cases ---
		{
			name:   "missing password",
			uri:    "tuic://uuid-only@example.com:443/",
			wantOk: false,
		},
		{
			name:   "empty username (uuid)",
			uri:    "tuic://:password@example.com:443/",
			wantOk: false,
		},
		{
			name:   "bad port (non-numeric)",
			uri:    "tuic://u:p@h:abc/",
			wantOk: false,
		},
		{
			name:   "port zero",
			uri:    "tuic://u:p@h:0/",
			wantOk: false,
		},
		{
			name:   "wrong scheme",
			uri:    "trojan://u:p@h:443/",
			wantOk: false,
		},
		{
			name:   "empty host",
			uri:    "tuic://u:p@:443/",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := parseTUIC(tc.uri)
			if ok != tc.wantOk {
				t.Fatalf("ok=%v, want %v", ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if p == nil {
				t.Fatal("p is nil, want non-nil")
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
