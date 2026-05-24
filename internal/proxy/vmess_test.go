package proxy

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// encodeVMess base64-encodes a JSON map into a vmess:// URI using the
// provided encoding. Panics on marshal failure (test helper only).
func encodeVMess(enc *base64.Encoding, fields map[string]any) string {
	data, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return "vmess://" + enc.EncodeToString(data)
}

// stdEnc is a shorthand for standard (padded) base64.
var stdEnc = base64.StdEncoding

func TestParseVMess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string

		// expected outcome
		wantOK  bool
		wantOut func(t *testing.T, p *Proxy)
	}{
		// ---------------------------------------------------------------
		// 1. Standard TCP + TLS
		// ---------------------------------------------------------------
		{
			name: "tcp+tls standard base64",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "vm1", "add": "1.2.3.4", "port": "443",
				"id": "uuid-xyz", "aid": "0", "net": "tcp", "type": "none",
				"host": "", "path": "", "tls": "tls", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "vmess", p.Type)
				assertEqual(t, "vm1", p.Name)
				assertEqual(t, "1.2.3.4", p.Server)
				assertEqual(t, uint16(443), p.Port)
				assertEqual(t, "uuid-xyz", p.UUID)
				assertEqual(t, "auto", p.Cipher)
				assertEqual(t, 0, p.AlterID)
				assertEqual(t, "tcp", p.Network)
				if p.TLS == nil {
					t.Fatal("expected TLS config, got nil")
				}
				if !p.TLS.Enabled {
					t.Error("expected TLS.Enabled=true")
				}
				if p.WS != nil || p.GRPC != nil || p.HTTP != nil {
					t.Error("unexpected transport config for tcp")
				}
			},
		},

		// ---------------------------------------------------------------
		// 2. WS + TLS with Host header
		// ---------------------------------------------------------------
		{
			name: "ws+tls with host header",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "ws-node", "add": "example.com", "port": "443",
				"id": "ws-uuid", "aid": "0", "net": "ws", "type": "none",
				"host": "cdn.example.com", "path": "/wpath", "tls": "tls",
				"scy": "auto", "sni": "sni.example.com", "fp": "chrome",
				"alpn": "h2,http/1.1",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "ws", p.Network)
				if p.WS == nil {
					t.Fatal("expected WS config, got nil")
				}
				assertEqual(t, "/wpath", p.WS.Path)
				if p.WS.Headers == nil {
					t.Fatal("expected WS.Headers, got nil")
				}
				assertEqual(t, "cdn.example.com", p.WS.Headers["Host"])
				if p.TLS == nil {
					t.Fatal("expected TLS config, got nil")
				}
				assertEqual(t, "sni.example.com", p.TLS.SNI)
				assertEqual(t, "chrome", p.TLS.Fingerprint)
				wantALPN := []string{"h2", "http/1.1"}
				if len(p.TLS.ALPN) != len(wantALPN) {
					t.Fatalf("ALPN: want %v, got %v", wantALPN, p.TLS.ALPN)
				}
				for i, a := range wantALPN {
					if p.TLS.ALPN[i] != a {
						t.Errorf("ALPN[%d]: want %q, got %q", i, a, p.TLS.ALPN[i])
					}
				}
			},
		},

		// ---------------------------------------------------------------
		// 3. gRPC + TLS
		// ---------------------------------------------------------------
		{
			name: "grpc+tls",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "grpc-node", "add": "grpc.example.com", "port": "443",
				"id": "grpc-uuid", "aid": "0", "net": "grpc", "type": "gun",
				"path": "grpcsvc", "tls": "tls", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "grpc", p.Network)
				if p.GRPC == nil {
					t.Fatal("expected GRPC config, got nil")
				}
				assertEqual(t, "grpcsvc", p.GRPC.ServiceName)
				assertEqual(t, "gun", p.GRPC.Mode)
				if p.TLS == nil || !p.TLS.Enabled {
					t.Error("expected TLS enabled")
				}
			},
		},

		// ---------------------------------------------------------------
		// 4. gRPC multi mode
		// ---------------------------------------------------------------
		{
			name: "grpc multi mode",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "grpc-multi", "add": "grpc.example.com", "port": "443",
				"id": "grpc-uuid", "aid": "0", "net": "grpc", "type": "multi",
				"path": "multisvc", "tls": "tls", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.GRPC == nil {
					t.Fatal("expected GRPC config, got nil")
				}
				assertEqual(t, "multi", p.GRPC.Mode)
				assertEqual(t, "multisvc", p.GRPC.ServiceName)
			},
		},

		// ---------------------------------------------------------------
		// 5. Port as integer (not string)
		// ---------------------------------------------------------------
		{
			name: "port as integer",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "int-port", "add": "5.6.7.8", "port": 443,
				"id": "uuid-int-port", "aid": 0, "net": "tcp", "tls": "",
				"scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, uint16(443), p.Port)
			},
		},

		// ---------------------------------------------------------------
		// 6. AlterID as integer
		// ---------------------------------------------------------------
		{
			name: "alterid as integer",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "aid-int", "add": "9.9.9.9", "port": "80",
				"id": "uuid-aid", "aid": 64, "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, 64, p.AlterID)
			},
		},

		// ---------------------------------------------------------------
		// 7. Empty ps → fallback name
		// ---------------------------------------------------------------
		{
			name: "empty ps uses fallback name",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "", "add": "1.1.1.1", "port": "8080",
				"id": "uuid-fallback", "aid": "0", "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				want := fallbackName("vmess", "1.1.1.1", 8080)
				assertEqual(t, want, p.Name)
			},
		},

		// ---------------------------------------------------------------
		// 8. URL-safe base64 without padding (RawURLEncoding)
		// ---------------------------------------------------------------
		{
			name: "raw url-safe base64",
			uri: encodeVMess(base64.RawURLEncoding, map[string]any{
				"v": "2", "ps": "raw-url", "add": "2.3.4.5", "port": "1080",
				"id": "uuid-rawurl", "aid": "0", "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "raw-url", p.Name)
				assertEqual(t, "2.3.4.5", p.Server)
				assertEqual(t, uint16(1080), p.Port)
			},
		},

		// ---------------------------------------------------------------
		// 9. "security" alias for "scy"
		// ---------------------------------------------------------------
		{
			name: "security alias for scy",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "sec-alias", "add": "3.3.3.3", "port": "443",
				"id": "uuid-sec", "aid": "0", "net": "tcp", "tls": "tls",
				"security": "chacha20-poly1305",
				// deliberately omit "scy"
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "chacha20-poly1305", p.Cipher)
			},
		},

		// ---------------------------------------------------------------
		// 10. h2 (HTTP/2) transport
		// ---------------------------------------------------------------
		{
			name: "h2 transport",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "h2-node", "add": "4.4.4.4", "port": "443",
				"id": "uuid-h2", "aid": "0", "net": "h2",
				"host": "h2.example.com", "path": "/h2path", "tls": "tls", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "h2", p.Network)
				if p.HTTP == nil {
					t.Fatal("expected HTTP config for h2, got nil")
				}
				if len(p.HTTP.Path) == 0 || p.HTTP.Path[0] != "/h2path" {
					t.Errorf("HTTP.Path: want [/h2path], got %v", p.HTTP.Path)
				}
				if len(p.HTTP.Host) == 0 || p.HTTP.Host[0] != "h2.example.com" {
					t.Errorf("HTTP.Host: want [h2.example.com], got %v", p.HTTP.Host)
				}
			},
		},

		// ---------------------------------------------------------------
		// 11. TCP + HTTP obfuscation (type=http)
		// ---------------------------------------------------------------
		{
			name: "tcp+http obfuscation",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "tcp-http", "add": "5.5.5.5", "port": "80",
				"id": "uuid-tcphttp", "aid": "0", "net": "tcp", "type": "http",
				"host": "obfs.example.com", "path": "/obfs", "tls": "", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				assertEqual(t, "tcp", p.Network)
				if p.HTTP == nil {
					t.Fatal("expected HTTP config for tcp+http obfuscation, got nil")
				}
				if len(p.HTTP.Path) == 0 || p.HTTP.Path[0] != "/obfs" {
					t.Errorf("HTTP.Path: want [/obfs], got %v", p.HTTP.Path)
				}
				if len(p.HTTP.Host) == 0 || p.HTTP.Host[0] != "obfs.example.com" {
					t.Errorf("HTTP.Host: want [obfs.example.com], got %v", p.HTTP.Host)
				}
			},
		},

		// ---------------------------------------------------------------
		// 12. TLS=="" → no TLS config
		// ---------------------------------------------------------------
		{
			name: "no tls when tls field empty",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "no-tls", "add": "6.6.6.6", "port": "80",
				"id": "uuid-notls", "aid": "0", "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS != nil {
					t.Errorf("expected nil TLS, got %+v", p.TLS)
				}
			},
		},

		// ---------------------------------------------------------------
		// 13–15. Invalid inputs → nil,false
		// ---------------------------------------------------------------
		{
			name:    "corrupt base64",
			uri:     "vmess://!!!not-valid-base64!!!",
			wantOK:  false,
			wantOut: nil,
		},
		{
			name:    "valid base64 but invalid JSON",
			uri:     "vmess://" + base64.StdEncoding.EncodeToString([]byte("not json {")),
			wantOK:  false,
			wantOut: nil,
		},
		{
			name: "missing uuid",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "no-uuid", "add": "7.7.7.7", "port": "443",
				// "id" intentionally omitted
				"aid": "0", "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK:  false,
			wantOut: nil,
		},
		{
			name: "missing server",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "no-server",
				// "add" intentionally omitted
				"port": "443", "id": "uuid-x", "aid": "0",
				"net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK:  false,
			wantOut: nil,
		},
		{
			name: "port zero",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "zero-port", "add": "8.8.8.8", "port": "0",
				"id": "uuid-y", "aid": "0", "net": "tcp", "tls": "", "scy": "auto",
			}),
			wantOK:  false,
			wantOut: nil,
		},
		{
			name:    "missing vmess:// prefix",
			uri:     "vless://something",
			wantOK:  false,
			wantOut: nil,
		},

		// ---------------------------------------------------------------
		// Bug fix: VMess skip_cert_verify / allowInsecure / verify_hostname
		// ---------------------------------------------------------------

		{
			name: "skip_cert_verify=true sets SkipVerify",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "skip1", "add": "1.2.3.4", "port": "443",
				"id": "uuid-sv", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "skip_cert_verify": true,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true")
				}
			},
		},
		{
			name: "allowInsecure=true sets SkipVerify",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "skip2", "add": "1.2.3.4", "port": "443",
				"id": "uuid-ai", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "allowInsecure": true,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true")
				}
			},
		},
		{
			name: "verify_hostname=false sets SkipVerify",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "skip3", "add": "1.2.3.4", "port": "443",
				"id": "uuid-vh", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "verify_hostname": false,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true")
				}
			},
		},
		{
			name: "verify_hostname=true → SkipVerify=false",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "noskip1", "add": "1.2.3.4", "port": "443",
				"id": "uuid-vht", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "verify_hostname": true,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.SkipVerify {
					t.Error("SkipVerify=true, want false")
				}
			},
		},
		{
			name: "no skip-verify fields → SkipVerify=false",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "noskip2", "add": "1.2.3.4", "port": "443",
				"id": "uuid-ns", "aid": "0", "net": "tcp", "tls": "tls", "scy": "auto",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if p.TLS.SkipVerify {
					t.Error("SkipVerify=true, want false")
				}
			},
		},
		{
			name: "skip_cert_verify as string true",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "skip-str", "add": "1.2.3.4", "port": "443",
				"id": "uuid-ss", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "skip_cert_verify": "true",
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true")
				}
			},
		},
		{
			name: "skip_cert_verify as integer 1",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "skip-int", "add": "1.2.3.4", "port": "443",
				"id": "uuid-si", "aid": "0", "net": "tcp", "tls": "tls",
				"scy": "auto", "skip_cert_verify": 1,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS == nil {
					t.Fatal("TLS is nil")
				}
				if !p.TLS.SkipVerify {
					t.Error("SkipVerify=false, want true")
				}
			},
		},
		{
			name: "TLS disabled: skip_cert_verify ignored, no TLSConfig",
			uri: encodeVMess(stdEnc, map[string]any{
				"v": "2", "ps": "notls-sv", "add": "1.2.3.4", "port": "80",
				"id": "uuid-ntls", "aid": "0", "net": "tcp", "tls": "",
				"scy": "auto", "skip_cert_verify": true,
			}),
			wantOK: true,
			wantOut: func(t *testing.T, p *Proxy) {
				t.Helper()
				if p.TLS != nil {
					t.Errorf("TLS should be nil when tls field empty, got %+v", p.TLS)
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, ok := parseVMess(tc.uri)
			if ok != tc.wantOK {
				t.Fatalf("parseVMess ok=%v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				if p != nil {
					t.Errorf("expected nil Proxy on failure, got %+v", p)
				}
				return
			}
			if p == nil {
				t.Fatal("parseVMess returned nil Proxy with ok=true")
			}
			// Verify Raw is preserved.
			if p.Raw != tc.uri {
				t.Errorf("Raw: want %q, got %q", tc.uri, p.Raw)
			}
			if tc.wantOut != nil {
				tc.wantOut(t, p)
			}
		})
	}
}

// assertEqual is a typed equality helper that keeps test output readable.
func assertEqual[T comparable](t *testing.T, want, got T) {
	t.Helper()
	if want != got {
		t.Errorf("want %v, got %v", want, got)
	}
}
