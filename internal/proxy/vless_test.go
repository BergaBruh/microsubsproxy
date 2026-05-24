package proxy

import (
	"testing"
)

func TestParseVLESS(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		wantOk bool
		check  func(t *testing.T, p *Proxy)
	}{
		{
			name:   "TLS+xhttp+mlkem encryption preserved",
			uri:    "vless://u1@pl1.example.com:443?encryption=mlkem768x25519plus.native.0rtt.BASE64KEYDATA&host=pl1.example.com&mode=auto&path=%2Fapi%2Fv2%2Fstatus&security=tls&type=xhttp&sni=pl1.example.com&fp=chrome#enc-node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Encryption != "mlkem768x25519plus.native.0rtt.BASE64KEYDATA" {
					t.Errorf("Encryption=%q, want the full mlkem string", p.Encryption)
				}
				if p.Network != "xhttp" {
					t.Errorf("Network=%q, want xhttp", p.Network)
				}
				if p.XHTTP == nil {
					t.Fatal("XHTTP is nil, want non-nil")
				}
			},
		},
		{
			name:   "encryption=none normalized to empty",
			uri:    "vless://u2@1.2.3.4:443?security=reality&encryption=none&pbk=P&sid=01&type=xhttp&path=%2F&host=h&mode=auto&sni=s#none-node",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Encryption != "" {
					t.Errorf("Encryption=%q, want empty for encryption=none", p.Encryption)
				}
			},
		},
		{
			name:   "TCP+Reality+Vision",
			uri:    "vless://abc@1.2.3.4:443?security=reality&encryption=none&pbk=PUB&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.google.com&sid=01ab#node1",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Type != "vless" {
					t.Errorf("Type=%q, want vless", p.Type)
				}
				if p.UUID != "abc" {
					t.Errorf("UUID=%q, want abc", p.UUID)
				}
				if p.Server != "1.2.3.4" {
					t.Errorf("Server=%q, want 1.2.3.4", p.Server)
				}
				if p.Port != 443 {
					t.Errorf("Port=%d, want 443", p.Port)
				}
				if p.Network != "tcp" {
					t.Errorf("Network=%q, want tcp", p.Network)
				}
				if p.Flow != "xtls-rprx-vision" {
					t.Errorf("Flow=%q, want xtls-rprx-vision", p.Flow)
				}
				if p.Name != "node1" {
					t.Errorf("Name=%q, want node1", p.Name)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil, want non-nil")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled=false, want true")
				}
				if p.TLS.SNI != "www.google.com" {
					t.Errorf("TLS.SNI=%q, want www.google.com", p.TLS.SNI)
				}
				if p.TLS.Fingerprint != "chrome" {
					t.Errorf("TLS.Fingerprint=%q, want chrome", p.TLS.Fingerprint)
				}
				if p.Reality == nil {
					t.Fatal("Reality is nil, want non-nil")
				}
				if p.Reality.PublicKey != "PUB" {
					t.Errorf("Reality.PublicKey=%q, want PUB", p.Reality.PublicKey)
				}
				if p.Reality.ShortID != "01ab" {
					t.Errorf("Reality.ShortID=%q, want 01ab", p.Reality.ShortID)
				}
				if p.WS != nil {
					t.Error("WS should be nil for tcp transport")
				}
				if p.GRPC != nil {
					t.Error("GRPC should be nil for tcp transport")
				}
				if p.Raw == "" {
					t.Error("Raw should not be empty")
				}
			},
		},
		{
			name:   "WS+TLS",
			uri:    "vless://abc@example.com:443?type=ws&security=tls&path=/ws&host=cdn.example.com&sni=cdn.example.com#wsnode",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Network != "ws" {
					t.Errorf("Network=%q, want ws", p.Network)
				}
				if p.Name != "wsnode" {
					t.Errorf("Name=%q, want wsnode", p.Name)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil, want non-nil")
				}
				if !p.TLS.Enabled {
					t.Error("TLS.Enabled=false, want true")
				}
				if p.TLS.SNI != "cdn.example.com" {
					t.Errorf("TLS.SNI=%q, want cdn.example.com", p.TLS.SNI)
				}
				if p.Reality != nil {
					t.Error("Reality should be nil for tls security")
				}
				if p.WS == nil {
					t.Fatal("WS is nil, want non-nil")
				}
				if p.WS.Path != "/ws" {
					t.Errorf("WS.Path=%q, want /ws", p.WS.Path)
				}
				if p.WS.Headers == nil {
					t.Fatal("WS.Headers is nil, want non-nil")
				}
				if p.WS.Headers["Host"] != "cdn.example.com" {
					t.Errorf("WS.Headers[Host]=%q, want cdn.example.com", p.WS.Headers["Host"])
				}
			},
		},
		{
			name:   "gRPC+TLS",
			uri:    "vless://abc@example.com:443?type=grpc&security=tls&serviceName=grpc-svc&mode=gun&sni=sni.example.com#grpc",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Network != "grpc" {
					t.Errorf("Network=%q, want grpc", p.Network)
				}
				if p.Name != "grpc" {
					t.Errorf("Name=%q, want grpc", p.Name)
				}
				if p.TLS == nil {
					t.Fatal("TLS is nil, want non-nil")
				}
				if p.TLS.SNI != "sni.example.com" {
					t.Errorf("TLS.SNI=%q, want sni.example.com", p.TLS.SNI)
				}
				if p.GRPC == nil {
					t.Fatal("GRPC is nil, want non-nil")
				}
				if p.GRPC.ServiceName != "grpc-svc" {
					t.Errorf("GRPC.ServiceName=%q, want grpc-svc", p.GRPC.ServiceName)
				}
				if p.GRPC.Mode != "gun" {
					t.Errorf("GRPC.Mode=%q, want gun", p.GRPC.Mode)
				}
				if p.WS != nil {
					t.Error("WS should be nil for grpc transport")
				}
			},
		},
		{
			name:   "empty fragment uses fallback name",
			uri:    "vless://myuuid@10.0.0.1:1080?type=tcp&security=none",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				want := fallbackName("vless", "10.0.0.1", 1080)
				if p.Name != want {
					t.Errorf("Name=%q, want %q", p.Name, want)
				}
				if p.TLS != nil {
					t.Error("TLS should be nil when security=none")
				}
				if p.Reality != nil {
					t.Error("Reality should be nil when security=none")
				}
			},
		},
		{
			name:   "ALPN with url-encoded comma",
			uri:    "vless://abc@1.2.3.4:443?security=tls&alpn=h2%2Chttp%2F1.1&sni=example.com#alpntest",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if len(p.TLS.ALPN) != 2 {
					t.Fatalf("ALPN len=%d, want 2; got %v", len(p.TLS.ALPN), p.TLS.ALPN)
				}
				if p.TLS.ALPN[0] != "h2" {
					t.Errorf("ALPN[0]=%q, want h2", p.TLS.ALPN[0])
				}
				if p.TLS.ALPN[1] != "http/1.1" {
					t.Errorf("ALPN[1]=%q, want http/1.1", p.TLS.ALPN[1])
				}
			},
		},
		{
			name:   "invalid: missing port",
			uri:    "vless://abc@example.com?type=tcp",
			wantOk: false,
		},
		{
			name:   "invalid: empty uuid",
			uri:    "vless://@example.com:443?type=tcp",
			wantOk: false,
		},
		{
			name:   "invalid: wrong scheme",
			uri:    "vmess://abc@example.com:443",
			wantOk: false,
		},
		{
			name:   "httpupgrade uses WSConfig",
			uri:    "vless://abc@1.2.3.4:8080?type=httpupgrade&security=tls&path=/upgrade&host=cdn.example.com&sni=cdn.example.com#hu",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Network != "httpupgrade" {
					t.Errorf("Network=%q, want httpupgrade", p.Network)
				}
				if p.WS == nil {
					t.Fatal("WS is nil for httpupgrade, want WSConfig")
				}
				if p.WS.Path != "/upgrade" {
					t.Errorf("WS.Path=%q, want /upgrade", p.WS.Path)
				}
				if p.WS.Headers["Host"] != "cdn.example.com" {
					t.Errorf("WS.Headers[Host]=%q, want cdn.example.com", p.WS.Headers["Host"])
				}
			},
		},
		{
			name:   "xhttp transport",
			uri:    "vless://abc@1.2.3.4:443?type=xhttp&security=tls&mode=stream-up&path=/xhttp&host=xhttp.example.com&sni=xhttp.example.com#xh",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Network != "xhttp" {
					t.Errorf("Network=%q, want xhttp", p.Network)
				}
				if p.XHTTP == nil {
					t.Fatal("XHTTP is nil, want non-nil")
				}
				if p.XHTTP.Mode != "stream-up" {
					t.Errorf("XHTTP.Mode=%q, want stream-up", p.XHTTP.Mode)
				}
				if p.XHTTP.Path != "/xhttp" {
					t.Errorf("XHTTP.Path=%q, want /xhttp", p.XHTTP.Path)
				}
				if p.XHTTP.Host != "xhttp.example.com" {
					t.Errorf("XHTTP.Host=%q, want xhttp.example.com", p.XHTTP.Host)
				}
			},
		},
		{
			name:   "TCP no transport params leaves nested configs nil",
			uri:    "vless://uuid123@192.168.1.1:443?type=tcp&security=reality&pbk=KEY&sid=ab12&sni=google.com#plain",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.WS != nil {
					t.Error("WS should be nil for tcp")
				}
				if p.GRPC != nil {
					t.Error("GRPC should be nil for tcp")
				}
				if p.XHTTP != nil {
					t.Error("XHTTP should be nil for tcp")
				}
				if p.Reality == nil {
					t.Fatal("Reality should be non-nil")
				}
			},
		},
		{
			name:   "Raw field preserved",
			uri:    "vless://abc@1.2.3.4:443?type=tcp#rawtest",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.Raw != "vless://abc@1.2.3.4:443?type=tcp#rawtest" {
					t.Errorf("Raw=%q, want original URI", p.Raw)
				}
			},
		},

		// --- Bug 1: allowInsecure / insecure → TLS.SkipVerify ---

		{
			name:   "allowInsecure=1 sets SkipVerify",
			uri:    "vless://abc@1.2.3.4:443?security=tls&allowInsecure=1#skiptest",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=false, want true")
				}
			},
		},
		{
			name:   "allowInsecure=true sets SkipVerify",
			uri:    "vless://abc@1.2.3.4:443?security=tls&allowInsecure=true#skiptest2",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=false, want true")
				}
			},
		},
		{
			name:   "insecure=1 sets SkipVerify",
			uri:    "vless://abc@1.2.3.4:443?security=tls&insecure=1#skiptest3",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=false, want true")
				}
			},
		},
		{
			name:   "missing allowInsecure param → SkipVerify false",
			uri:    "vless://abc@1.2.3.4:443?security=tls#noskip",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=true, want false")
				}
			},
		},
		{
			name:   "allowInsecure=0 → SkipVerify false",
			uri:    "vless://abc@1.2.3.4:443?security=tls&allowInsecure=0#noskip2",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=true, want false")
				}
			},
		},
		{
			name:   "TLS disabled: no TLSConfig even with allowInsecure=1",
			uri:    "vless://abc@1.2.3.4:1080?type=tcp&security=none&allowInsecure=1#notls",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS != nil {
					t.Errorf("TLS should be nil when security=none, got %+v", p.TLS)
				}
			},
		},
		{
			name:   "Reality+allowInsecure=1 sets SkipVerify",
			uri:    "vless://abc@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12&allowInsecure=1#realityskip",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("TLS.SkipVerify=false, want true")
				}
				if p.Reality == nil {
					t.Fatal("Reality is nil")
				}
			},
		},

		// --- Bug 2: Reality without fp defaults to "chrome" ---

		{
			name:   "Reality without fp defaults fingerprint to chrome",
			uri:    "vless://abc@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12#nofp",
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
			name:   "Reality with explicit fp is not overridden",
			uri:    "vless://abc@1.2.3.4:443?security=reality&pbk=PUB&sid=ab12&fp=firefox#explicitfp",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.Fingerprint != "firefox" {
					t.Errorf("TLS.Fingerprint=%q, want firefox", p.TLS.Fingerprint)
				}
			},
		},
		{
			name:   "plain TLS without fp does not default to chrome",
			uri:    "vless://abc@1.2.3.4:443?security=tls#nofptls",
			wantOk: true,
			check: func(t *testing.T, p *Proxy) {
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.Fingerprint != "" {
					t.Errorf("TLS.Fingerprint=%q, want empty for plain TLS without fp param", p.TLS.Fingerprint)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseVLESS(tt.uri)
			if ok != tt.wantOk {
				t.Fatalf("parseVLESS ok=%v, want %v", ok, tt.wantOk)
			}
			if tt.wantOk && tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}
