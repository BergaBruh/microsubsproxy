package proxy

import (
	"reflect"
	"testing"
)

func TestParseTrojan(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		want   *Proxy
		wantOK bool
	}{
		{
			name:   "plain tcp+tls with sni and fragment",
			uri:    "trojan://pass@example.com:443?sni=example.com#node",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?sni=example.com#node",
				Type:     "trojan",
				Name:     "node",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled: true,
					SNI:     "example.com",
				},
			},
		},
		{
			name:   "websocket transport",
			uri:    "trojan://pass@example.com:443?type=ws&path=/trojan&host=cdn.example.com&sni=cdn.example.com#tnode",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?type=ws&path=/trojan&host=cdn.example.com&sni=cdn.example.com#tnode",
				Type:     "trojan",
				Name:     "tnode",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "ws",
				TLS: &TLSConfig{
					Enabled: true,
					SNI:     "cdn.example.com",
				},
				WS: &WSConfig{
					Path:    "/trojan",
					Headers: map[string]string{"Host": "cdn.example.com"},
				},
			},
		},
		{
			name:   "grpc transport",
			uri:    "trojan://pass@example.com:443?type=grpc&serviceName=tj-grpc&sni=sni.example.com#g",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?type=grpc&serviceName=tj-grpc&sni=sni.example.com#g",
				Type:     "trojan",
				Name:     "g",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "grpc",
				TLS: &TLSConfig{
					Enabled: true,
					SNI:     "sni.example.com",
				},
				GRPC: &GRPCConfig{
					ServiceName: "tj-grpc",
				},
			},
		},
		{
			name:   "allowInsecure=1 sets SkipVerify",
			uri:    "trojan://pass@example.com:443?allowInsecure=1#skip",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?allowInsecure=1#skip",
				Type:     "trojan",
				Name:     "skip",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled:    true,
					SkipVerify: true,
				},
			},
		},
		{
			name:   "allowInsecure=true sets SkipVerify",
			uri:    "trojan://pass@example.com:443?allowInsecure=true#skipb",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?allowInsecure=true#skipb",
				Type:     "trojan",
				Name:     "skipb",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled:    true,
					SkipVerify: true,
				},
			},
		},
		{
			name:   "ALPN comma list parsing",
			uri:    "trojan://pass@example.com:443?alpn=h2,http/1.1&sni=example.com#alpntest",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443?alpn=h2,http/1.1&sni=example.com#alpntest",
				Type:     "trojan",
				Name:     "alpntest",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled: true,
					SNI:     "example.com",
					ALPN:    []string{"h2", "http/1.1"},
				},
			},
		},
		{
			name:   "URL-encoded password with special chars",
			uri:    "trojan://p%40ss%21word@example.com:443#encoded",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://p%40ss%21word@example.com:443#encoded",
				Type:     "trojan",
				Name:     "encoded",
				Server:   "example.com",
				Port:     443,
				Password: "p@ss!word",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled: true,
				},
			},
		},
		{
			name:   "empty fragment uses fallback name",
			uri:    "trojan://pass@example.com:443",
			wantOK: true,
			want: &Proxy{
				Raw:      "trojan://pass@example.com:443",
				Type:     "trojan",
				Name:     "trojan-example.com-443",
				Server:   "example.com",
				Port:     443,
				Password: "pass",
				Network:  "tcp",
				TLS: &TLSConfig{
					Enabled: true,
				},
			},
		},
		{
			name:   "invalid: no password",
			uri:    "trojan://@example.com:443",
			wantOK: false,
			want:   nil,
		},
		{
			name:   "invalid: no port",
			uri:    "trojan://pass@example.com",
			wantOK: false,
			want:   nil,
		},
		{
			name:   "invalid: port zero",
			uri:    "trojan://pass@example.com:0",
			wantOK: false,
			want:   nil,
		},
		{
			name:   "invalid: non-numeric port",
			uri:    "trojan://pass@example.com:abc",
			wantOK: false,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTrojan(tc.uri)
			if ok != tc.wantOK {
				t.Fatalf("parseTrojan() ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got == nil {
				t.Fatal("parseTrojan() returned nil proxy but ok=true")
			}

			// Compare field by field for clear failure messages
			if got.Raw != tc.want.Raw {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.want.Raw)
			}
			if got.Type != tc.want.Type {
				t.Errorf("Type = %q, want %q", got.Type, tc.want.Type)
			}
			if got.Name != tc.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tc.want.Name)
			}
			if got.Server != tc.want.Server {
				t.Errorf("Server = %q, want %q", got.Server, tc.want.Server)
			}
			if got.Port != tc.want.Port {
				t.Errorf("Port = %d, want %d", got.Port, tc.want.Port)
			}
			if got.Password != tc.want.Password {
				t.Errorf("Password = %q, want %q", got.Password, tc.want.Password)
			}
			if got.Network != tc.want.Network {
				t.Errorf("Network = %q, want %q", got.Network, tc.want.Network)
			}

			// TLS
			if tc.want.TLS == nil && got.TLS != nil {
				t.Errorf("TLS: got non-nil, want nil")
			} else if tc.want.TLS != nil {
				if got.TLS == nil {
					t.Fatalf("TLS: got nil, want %+v", tc.want.TLS)
				}
				wt := tc.want.TLS
				gt := got.TLS
				if gt.Enabled != wt.Enabled {
					t.Errorf("TLS.Enabled = %v, want %v", gt.Enabled, wt.Enabled)
				}
				if gt.SNI != wt.SNI {
					t.Errorf("TLS.SNI = %q, want %q", gt.SNI, wt.SNI)
				}
				if !reflect.DeepEqual(gt.ALPN, wt.ALPN) {
					t.Errorf("TLS.ALPN = %v, want %v", gt.ALPN, wt.ALPN)
				}
				if gt.Fingerprint != wt.Fingerprint {
					t.Errorf("TLS.Fingerprint = %q, want %q", gt.Fingerprint, wt.Fingerprint)
				}
				if gt.SkipVerify != wt.SkipVerify {
					t.Errorf("TLS.SkipVerify = %v, want %v", gt.SkipVerify, wt.SkipVerify)
				}
			}

			// WS
			if !reflect.DeepEqual(got.WS, tc.want.WS) {
				t.Errorf("WS = %+v, want %+v", got.WS, tc.want.WS)
			}

			// GRPC
			if !reflect.DeepEqual(got.GRPC, tc.want.GRPC) {
				t.Errorf("GRPC = %+v, want %+v", got.GRPC, tc.want.GRPC)
			}
		})
	}
}
