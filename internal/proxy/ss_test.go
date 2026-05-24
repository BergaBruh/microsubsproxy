package proxy

import (
	"encoding/base64"
	"testing"
)

// encodeB64 is a test helper that returns standard base64 with padding.
func encodeB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// encodeB64URL is a test helper that returns URL-safe base64 without padding.
func encodeB64URL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestParseSS(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		wantOk bool
		check  func(t *testing.T, p *Proxy)
	}{
		// -----------------------------------------------------------------
		// Variant A: SIP002 with standard base64 userinfo
		// -----------------------------------------------------------------
		{
			name: "SIP002 base64 userinfo standard padding",
			// base64("aes-256-gcm:password") = "YWVzLTI1Ni1nY206cGFzc3dvcmQ="
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#node1",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Type != "ss" {
					t.Errorf("Type=%q, want ss", p.Type)
				}
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm", p.Cipher)
				}
				if p.Password != "password" {
					t.Errorf("Password=%q, want password", p.Password)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 8388 {
					t.Errorf("Port=%d, want 8388", p.Port)
				}
				if p.Name != "node1" {
					t.Errorf("Name=%q, want node1", p.Name)
				}
				if p.Network != "tcp" {
					t.Errorf("Network=%q, want tcp", p.Network)
				}
				if p.TLS != nil {
					t.Error("TLS should be nil for ss")
				}
				if p.Raw == "" {
					t.Error("Raw should not be empty")
				}
			},
		},
		// -----------------------------------------------------------------
		// Variant A: SIP002 with URL-safe base64 userinfo (no padding)
		// -----------------------------------------------------------------
		{
			name: "SIP002 URL-safe base64 no padding",
			// base64url(no-pad) of "aes-256-gcm:password" = "YWVzLTI1Ni1nY206cGFzc3dvcmQ"
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#node_urlsafe",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm", p.Cipher)
				}
				if p.Password != "password" {
					t.Errorf("Password=%q, want password", p.Password)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 8388 {
					t.Errorf("Port=%d, want 8388", p.Port)
				}
				if p.Name != "node_urlsafe" {
					t.Errorf("Name=%q, want node_urlsafe", p.Name)
				}
			},
		},
		// -----------------------------------------------------------------
		// Variant B: SIP002 plaintext userinfo (not base64)
		// -----------------------------------------------------------------
		{
			name:   "SIP002 plaintext userinfo",
			uri:    "ss://aes-256-gcm:password@1.2.3.4:8388#node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm", p.Cipher)
				}
				if p.Password != "password" {
					t.Errorf("Password=%q, want password", p.Password)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 8388 {
					t.Errorf("Port=%d, want 8388", p.Port)
				}
				if p.Name != "node" {
					t.Errorf("Name=%q, want node", p.Name)
				}
			},
		},
		// -----------------------------------------------------------------
		// Variant C: Legacy — entire body is base64
		// -----------------------------------------------------------------
		{
			name: "Legacy base64 whole body",
			// base64("aes-256-gcm:password@1.2.3.4:8388") = "YWVzLTI1Ni1nY206cGFzc3dvcmRAMS4yLjMuNDo4Mzg4"
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMS4yLjMuNDo4Mzg4#legacy",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm", p.Cipher)
				}
				if p.Password != "password" {
					t.Errorf("Password=%q, want password", p.Password)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 8388 {
					t.Errorf("Port=%d, want 8388", p.Port)
				}
				if p.Name != "legacy" {
					t.Errorf("Name=%q, want legacy", p.Name)
				}
			},
		},
		// -----------------------------------------------------------------
		// Plugin present — parse normally, plugin ignored (not in Proxy)
		// -----------------------------------------------------------------
		{
			name:   "SIP002 with plugin query string — plugin ignored",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dtls#obfsnode",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm", p.Cipher)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 8388 {
					t.Errorf("Port=%d, want 8388", p.Port)
				}
				if p.Name != "obfsnode" {
					t.Errorf("Name=%q, want obfsnode", p.Name)
				}
			},
		},
		// -----------------------------------------------------------------
		// URL-encoded password containing special characters
		// -----------------------------------------------------------------
		{
			name: "SIP002 plaintext URL-encoded password with colon and at",
			// Password is "p@ss:word" — percent-encoded as "p%40ss%3Aword"
			uri:    "ss://chacha20-ietf-poly1305:p%40ss%3Aword@10.0.0.1:1080#special",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "chacha20-ietf-poly1305" {
					t.Errorf("Cipher=%q, want chacha20-ietf-poly1305", p.Cipher)
				}
				if p.Password != "p@ss:word" {
					t.Errorf("Password=%q, want p@ss:word", p.Password)
				}
				if p.Server != "10.0.0.1" {
					t.Errorf("Server=%q, want 10.0.0.1", p.Server)
				}
				if p.Port != 1080 {
					t.Errorf("Port=%d, want 1080", p.Port)
				}
			},
		},
		// -----------------------------------------------------------------
		// 2022-blake3 cipher
		// -----------------------------------------------------------------
		{
			name: "2022-blake3-aes-256-gcm SIP002 base64",
			// base64("2022-blake3-aes-256-gcm:supersecretkey")
			uri:    "ss://" + encodeB64("2022-blake3-aes-256-gcm:supersecretkey") + "@192.168.1.1:8443#blake3node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "2022-blake3-aes-256-gcm" {
					t.Errorf("Cipher=%q, want 2022-blake3-aes-256-gcm", p.Cipher)
				}
				if p.Password != "supersecretkey" {
					t.Errorf("Password=%q, want supersecretkey", p.Password)
				}
				if p.Server != "192.168.1.1" {
					t.Errorf("Server=%q, want 192.168.1.1", p.Server)
				}
				if p.Port != 8443 {
					t.Errorf("Port=%d, want 8443", p.Port)
				}
			},
		},
		// -----------------------------------------------------------------
		// Method lowercased
		// -----------------------------------------------------------------
		{
			name:   "method is lowercased",
			uri:    "ss://" + encodeB64("AES-256-GCM:pass") + "@1.2.3.4:8388#case",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-256-gcm" {
					t.Errorf("Cipher=%q, want aes-256-gcm (lowercased)", p.Cipher)
				}
			},
		},
		// -----------------------------------------------------------------
		// Fallback name when fragment is absent
		// -----------------------------------------------------------------
		{
			name:   "empty fragment generates fallback name",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				want := fallbackName("ss", "1.2.3.4", 8388)
				if p.Name != want {
					t.Errorf("Name=%q, want %q", p.Name, want)
				}
			},
		},
		// -----------------------------------------------------------------
		// Fragment is URL-decoded
		// -----------------------------------------------------------------
		{
			name:   "percent-encoded fragment is decoded",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#my%20node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Name != "my node" {
					t.Errorf("Name=%q, want 'my node'", p.Name)
				}
			},
		},
		// -----------------------------------------------------------------
		// Raw field preserved
		// -----------------------------------------------------------------
		{
			name:   "Raw field preserved verbatim",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#rawtest",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Raw != "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#rawtest" {
					t.Errorf("Raw=%q, want original URI", p.Raw)
				}
			},
		},
		// -----------------------------------------------------------------
		// SIP002 generated dynamically via helper
		// -----------------------------------------------------------------
		{
			name:   "SIP002 URL-safe no-padding constructed dynamically",
			uri:    "ss://" + encodeB64URL("aes-128-gcm:s3cr3t") + "@5.6.7.8:9000#dyn",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Cipher != "aes-128-gcm" {
					t.Errorf("Cipher=%q, want aes-128-gcm", p.Cipher)
				}
				if p.Password != "s3cr3t" {
					t.Errorf("Password=%q, want s3cr3t", p.Password)
				}
				if p.Port != 9000 {
					t.Errorf("Port=%d, want 9000", p.Port)
				}
			},
		},
		// -----------------------------------------------------------------
		// Invalid cases
		// -----------------------------------------------------------------
		{
			name:   "invalid: wrong scheme",
			uri:    "trojan://pw@1.2.3.4:443",
			wantOk: false,
		},
		{
			name:   "invalid: empty userinfo SIP002",
			uri:    "ss://@1.2.3.4:8388#empty",
			wantOk: false,
		},
		{
			name:   "invalid: no port SIP002",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4#noport",
			wantOk: false,
		},
		{
			name:   "invalid: port zero",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:0#zeroport",
			wantOk: false,
		},
		{
			name:   "invalid: non-numeric port",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:abc#badport",
			wantOk: false,
		},
		{
			name:   "invalid: port out of uint16 range",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:99999#overflow",
			wantOk: false,
		},
		{
			name:   "invalid: legacy base64 does not decode",
			uri:    "ss://!!!notbase64!!!#bad",
			wantOk: false,
		},
		{
			name:   "invalid: SIP002 missing host",
			uri:    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@:8388#nohost",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseSS(tt.uri)
			if ok != tt.wantOk {
				t.Fatalf("parseSS(%q) ok=%v, want %v", tt.uri, ok, tt.wantOk)
			}
			if tt.wantOk && tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestParseSS_Plugins(t *testing.T) {
	const userinfo = "YWVzLTI1Ni1nY206cGFzc3dvcmQ=" // base64("aes-256-gcm:password")

	tests := []struct {
		name  string
		uri   string
		check func(t *testing.T, p *Proxy)
	}{
		{
			name: "obfs-local tls",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.com#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin == nil {
					t.Fatal("SSPlugin nil")
				}
				if p.SSPlugin.Name != "obfs" {
					t.Errorf("Name=%q, want obfs", p.SSPlugin.Name)
				}
				if p.SSPlugin.Mode != "tls" {
					t.Errorf("Mode=%q, want tls", p.SSPlugin.Mode)
				}
				if p.SSPlugin.Host != "example.com" {
					t.Errorf("Host=%q", p.SSPlugin.Host)
				}
			},
		},
		{
			name: "simple-obfs http (alias to obfs)",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin.Name != "obfs" {
					t.Errorf("Name=%q, want obfs (alias)", p.SSPlugin.Name)
				}
				if p.SSPlugin.Mode != "http" {
					t.Errorf("Mode=%q", p.SSPlugin.Mode)
				}
			},
		},
		{
			name: "v2ray-plugin websocket+tls+mux",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws%3Btls%3Bmux#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin.Name != "v2ray-plugin" {
					t.Errorf("Name=%q", p.SSPlugin.Name)
				}
				if p.SSPlugin.Mode != "websocket" {
					t.Errorf("Mode=%q", p.SSPlugin.Mode)
				}
				if p.SSPlugin.Host != "cdn.example.com" {
					t.Errorf("Host=%q", p.SSPlugin.Host)
				}
				if p.SSPlugin.Path != "/ws" {
					t.Errorf("Path=%q", p.SSPlugin.Path)
				}
				if !p.SSPlugin.TLS {
					t.Error("TLS not set (bare 'tls' flag)")
				}
				if !p.SSPlugin.Mux {
					t.Error("Mux not set (bare 'mux' flag)")
				}
			},
		},
		{
			name: "shadow-tls v3",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=shadow-tls%3Bhost%3Dexample.com%3Bpassword%3Dmypw%3Bversion%3D3#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin.Name != "shadow-tls" {
					t.Errorf("Name=%q", p.SSPlugin.Name)
				}
				if p.SSPlugin.Host != "example.com" {
					t.Errorf("Host=%q", p.SSPlugin.Host)
				}
				if p.SSPlugin.Password != "mypw" {
					t.Errorf("Password=%q", p.SSPlugin.Password)
				}
				if p.SSPlugin.Version != 3 {
					t.Errorf("Version=%d, want 3", p.SSPlugin.Version)
				}
			},
		},
		{
			name: "no plugin param — SSPlugin stays nil",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin != nil {
					t.Errorf("SSPlugin should be nil, got %+v", p.SSPlugin)
				}
			},
		},
		{
			name: "empty plugin spec — SSPlugin stays nil",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=#n",
			check: func(t *testing.T, p *Proxy) {
				if p.SSPlugin != nil {
					t.Errorf("SSPlugin should be nil for empty spec")
				}
			},
		},
		{
			name: "v2ray-plugin tls=true explicit",
			uri:  "ss://" + userinfo + "@1.2.3.4:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Dtrue%3Bskip-cert-verify%3D1#n",
			check: func(t *testing.T, p *Proxy) {
				if !p.SSPlugin.TLS {
					t.Error("TLS=true not parsed")
				}
				if !p.SSPlugin.SkipCertVerify {
					t.Error("SkipCertVerify=1 not parsed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseSS(tt.uri)
			if !ok {
				t.Fatalf("parseSS returned ok=false")
			}
			tt.check(t, p)
		})
	}
}
