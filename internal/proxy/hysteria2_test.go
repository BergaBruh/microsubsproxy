package proxy

import (
	"testing"
)

func TestParseHysteria2(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		wantOk bool
		check  func(t *testing.T, p *Proxy)
	}{
		{
			name:   "plain hysteria2 scheme",
			uri:    "hysteria2://mypass@example.com:443/?sni=example.com&insecure=0#hy2node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Type != "hysteria2" {
					t.Errorf("Type = %q; want hysteria2", p.Type)
				}
				if p.Name != "hy2node" {
					t.Errorf("Name = %q; want hy2node", p.Name)
				}
				if p.Server != "example.com" {
					t.Errorf("Server = %q; want example.com", p.Server)
				}
				if p.Port != 443 {
					t.Errorf("Port = %d; want 443", p.Port)
				}
				if p.Password != "mypass" {
					t.Errorf("Password = %q; want mypass", p.Password)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil; want allocated")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled = false; want true")
				}
				if p.TLS.SNI != "example.com" {
					t.Errorf("TLS.SNI = %q; want example.com", p.TLS.SNI)
				}
				if p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify = true; want false (insecure=0)")
				}
				if p.Hysteria2 != nil {
					t.Error("Hysteria2 should be nil when no obfs/speed params")
				}
			},
		},
		{
			name:   "hy2 alias scheme",
			uri:    "hy2://mypass@1.2.3.4:443/?sni=example.com#hy2alias",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Type != "hysteria2" {
					t.Errorf("Type = %q; want hysteria2", p.Type)
				}
				if p.Name != "hy2alias" {
					t.Errorf("Name = %q; want hy2alias", p.Name)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server = %q; want 1.2.3.4", p.Server)
				}
				if p.Port != 443 {
					t.Errorf("Port = %d; want 443", p.Port)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil; want allocated")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled = false; want true")
				}
			},
		},
		{
			name:   "salamander obfs with hyphen key",
			uri:    "hysteria2://mypass@h:443/?sni=h&obfs=salamander&obfs-password=obfspw#obfs",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Hysteria2 == nil {
					t.Fatal("Hysteria2 is nil; want allocated for obfs")
				}
				if p.Hysteria2.ObfsType != "salamander" {
					t.Errorf("ObfsType = %q; want salamander", p.Hysteria2.ObfsType)
				}
				if p.Hysteria2.ObfsPassword != "obfspw" {
					t.Errorf("ObfsPassword = %q; want obfspw", p.Hysteria2.ObfsPassword)
				}
			},
		},
		{
			name:   "obfs_password underscore alias",
			uri:    "hysteria2://mypass@h:443/?sni=h&obfs=salamander&obfs_password=obfspw#obfs",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Hysteria2 == nil {
					t.Fatal("Hysteria2 is nil; want allocated for obfs")
				}
				if p.Hysteria2.ObfsPassword != "obfspw" {
					t.Errorf("ObfsPassword = %q; want obfspw (underscore key)", p.Hysteria2.ObfsPassword)
				}
			},
		},
		{
			name:   "insecure=1 sets SkipVerify",
			uri:    "hysteria2://mypass@host:443/?sni=host&insecure=1#insecure",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify = false; want true (insecure=1)")
				}
			},
		},
		{
			name:   "ALPN comma split",
			uri:    "hysteria2://mypass@host:443/?alpn=h3,h2&sni=host#alpn",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if len(p.TLS.ALPN) != 2 {
					t.Fatalf("ALPN len = %d; want 2: %v", len(p.TLS.ALPN), p.TLS.ALPN)
				}
				if p.TLS.ALPN[0] != "h3" || p.TLS.ALPN[1] != "h2" {
					t.Errorf("ALPN = %v; want [h3 h2]", p.TLS.ALPN)
				}
			},
		},
		{
			name:   "up and down speed hints",
			uri:    "hysteria2://mypass@host:443/?up=100&down=200&sni=host#speed",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Hysteria2 == nil {
					t.Fatal("Hysteria2 is nil; want allocated for speed hints")
				}
				if p.Hysteria2.Up != 100 {
					t.Errorf("Up = %d; want 100", p.Hysteria2.Up)
				}
				if p.Hysteria2.Down != 200 {
					t.Errorf("Down = %d; want 200", p.Hysteria2.Down)
				}
			},
		},
		{
			name:   "URL-encoded password with exclamation",
			uri:    "hysteria2://p%21ass@host:443/#encoded",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Password != "p!ass" {
					t.Errorf("Password = %q; want p!ass (percent-decoded)", p.Password)
				}
			},
		},
		{
			name:   "URL-encoded password with colon",
			uri:    "hysteria2://pass%3Aword@host:443/#colon",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Password != "pass:word" {
					t.Errorf("Password = %q; want pass:word (percent-decoded)", p.Password)
				}
			},
		},
		{
			name:   "empty fragment uses fallback name",
			uri:    "hysteria2://mypass@example.com:443/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				want := fallbackName("hysteria2", "example.com", 443)
				if p.Name != want {
					t.Errorf("Name = %q; want fallback %q", p.Name, want)
				}
			},
		},
		{
			name:   "TLS always allocated even with no TLS params",
			uri:    "hysteria2://mypass@host:443/",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil; Hysteria2 always requires TLS")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled = false; want true")
				}
			},
		},
		{
			name:   "fp fingerprint stored in TLS",
			uri:    "hysteria2://mypass@host:443/?fp=chrome&sni=host#fp",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.Fingerprint != "chrome" {
					t.Errorf("Fingerprint = %q; want chrome", p.TLS.Fingerprint)
				}
			},
		},
		{
			name:   "invalid: no port",
			uri:    "hysteria2://mypass@host/",
			wantOk: false,
		},
		{
			name:   "invalid: port zero",
			uri:    "hysteria2://mypass@host:0/",
			wantOk: false,
		},
		{
			name:   "invalid: no password",
			uri:    "hysteria2://@host:443/",
			wantOk: false,
		},
		{
			name:   "invalid: no host",
			uri:    "hysteria2://mypass@:443/",
			wantOk: false,
		},
		{
			name:   "invalid: malformed URI",
			uri:    "hysteria2://",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := parseHysteria2(tc.uri)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v; want %v", ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if p == nil {
				t.Fatal("proxy is nil but ok=true")
			}
			// Raw must be preserved verbatim.
			if p.Raw != tc.uri {
				t.Errorf("Raw = %q; want %q", p.Raw, tc.uri)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
