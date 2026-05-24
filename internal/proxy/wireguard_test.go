package proxy

import (
	"testing"
)

// TestParseWireGuard_Minimal tests the simplest valid wireguard:// URI.
// Private key is URL-encoded (with %3D for the '=' padding character).
func TestParseWireGuard_Minimal(t *testing.T) {
	uri := "wireguard://PRIVKEY%3D@example.com:51820/?publickey=PEERKEY%3D&address=10.0.0.2/32#wg1"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success, got false")
	}
	if p.Type != "wireguard" {
		t.Errorf("Type: want wireguard, got %q", p.Type)
	}
	if p.Name != "wg1" {
		t.Errorf("Name: want wg1, got %q", p.Name)
	}
	if p.Server != "example.com" {
		t.Errorf("Server: want example.com, got %q", p.Server)
	}
	if p.Port != 51820 {
		t.Errorf("Port: want 51820, got %d", p.Port)
	}
	if p.Raw != uri {
		t.Errorf("Raw not preserved")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.PrivateKey != "PRIVKEY=" {
		t.Errorf("PrivateKey: want %q, got %q", "PRIVKEY=", wg.PrivateKey)
	}
	if wg.PublicKey != "PEERKEY=" {
		t.Errorf("PublicKey: want %q, got %q", "PEERKEY=", wg.PublicKey)
	}
	if wg.IP != "10.0.0.2/32" {
		t.Errorf("IP: want 10.0.0.2/32, got %q", wg.IP)
	}
	if wg.IPv6 != "" {
		t.Errorf("IPv6: want empty, got %q", wg.IPv6)
	}
}

// TestParseWireGuard_WgAlias verifies that wg:// is accepted as an alias for wireguard://.
func TestParseWireGuard_WgAlias(t *testing.T) {
	uri := "wg://privkey@h:51820/?publickey=peer&address=10.0.0.2/32&allowed_ips=0.0.0.0/0,::/0#alias"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success with wg:// scheme")
	}
	if p.Type != "wireguard" {
		t.Errorf("Type: want wireguard, got %q", p.Type)
	}
	if p.Name != "alias" {
		t.Errorf("Name: want alias, got %q", p.Name)
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.PrivateKey != "privkey" {
		t.Errorf("PrivateKey: want privkey, got %q", wg.PrivateKey)
	}
	if wg.PublicKey != "peer" {
		t.Errorf("PublicKey: want peer, got %q", wg.PublicKey)
	}
	if len(wg.AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs: want 2 entries, got %d: %v", len(wg.AllowedIPs), wg.AllowedIPs)
	}
	if wg.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs[0]: want 0.0.0.0/0, got %q", wg.AllowedIPs[0])
	}
	if wg.AllowedIPs[1] != "::/0" {
		t.Errorf("AllowedIPs[1]: want ::/0, got %q", wg.AllowedIPs[1])
	}
}

// TestParseWireGuard_DualStackAddress verifies comma-separated IPv4 + IPv6 address splitting.
func TestParseWireGuard_DualStackAddress(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?address=10.0.0.2/32,fd00::2/128&publickey=peer"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.IP != "10.0.0.2/32" {
		t.Errorf("IP: want 10.0.0.2/32, got %q", wg.IP)
	}
	if wg.IPv6 != "fd00::2/128" {
		t.Errorf("IPv6: want fd00::2/128, got %q", wg.IPv6)
	}
}

// TestParseWireGuard_PresharedKeyAndMTU verifies presharedkey and mtu params.
func TestParseWireGuard_PresharedKeyAndMTU(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&address=10.0.0.2/32&presharedkey=PSK&mtu=1380"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.PresharedKey != "PSK" {
		t.Errorf("PresharedKey: want PSK, got %q", wg.PresharedKey)
	}
	if wg.MTU != 1380 {
		t.Errorf("MTU: want 1380, got %d", wg.MTU)
	}
}

// TestParseWireGuard_CloudflareWARPReserved tests the Cloudflare WARP reserved field.
func TestParseWireGuard_CloudflareWARPReserved(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&address=10.0.0.2/32&reserved=1,2,3"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if len(wg.Reserved) != 3 {
		t.Fatalf("Reserved: want 3 entries, got %d: %v", len(wg.Reserved), wg.Reserved)
	}
	want := []int{1, 2, 3}
	for i, v := range want {
		if wg.Reserved[i] != v {
			t.Errorf("Reserved[%d]: want %d, got %d", i, v, wg.Reserved[i])
		}
	}
}

// TestParseWireGuard_HyphenAliases verifies that hyphenated param names work.
func TestParseWireGuard_HyphenAliases(t *testing.T) {
	// public-key instead of publickey; preshared-key instead of presharedkey; allowed-ips instead of allowed_ips
	uri := "wireguard://privkey@h:51820/?public-key=peer&address=10.0.0.2/32&preshared-key=PSK&allowed-ips=0.0.0.0/0"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success with hyphen aliases")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.PublicKey != "peer" {
		t.Errorf("PublicKey via public-key: want peer, got %q", wg.PublicKey)
	}
	if wg.PresharedKey != "PSK" {
		t.Errorf("PresharedKey via preshared-key: want PSK, got %q", wg.PresharedKey)
	}
	if len(wg.AllowedIPs) != 1 || wg.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs via allowed-ips: want [0.0.0.0/0], got %v", wg.AllowedIPs)
	}
}

// TestParseWireGuard_UnderscoreAliases verifies that underscore param names work (allowedips, peer_publickey).
func TestParseWireGuard_UnderscoreAliases(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?peer_publickey=peer&address=10.0.0.2/32&allowedips=0.0.0.0/0"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success with underscore aliases")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	if wg.PublicKey != "peer" {
		t.Errorf("PublicKey via peer_publickey: want peer, got %q", wg.PublicKey)
	}
	if len(wg.AllowedIPs) != 1 || wg.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs via allowedips: want [0.0.0.0/0], got %v", wg.AllowedIPs)
	}
}

// TestParseWireGuard_URLEncodedPrivateKey tests a private key encoded with %3D%3D padding.
func TestParseWireGuard_URLEncodedPrivateKey(t *testing.T) {
	// "cHJpdmtleQ==" base64-encoded (URL percent-encoded as cHJpdmtleQ%3D%3D)
	uri := "wireguard://cHJpdmtleQ%3D%3D@h:51820/?publickey=peer&address=10.0.0.2/32"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	wg := p.WireGuard
	if wg == nil {
		t.Fatal("WireGuard config is nil")
	}
	// url.Parse percent-decodes userinfo automatically.
	if wg.PrivateKey != "cHJpdmtleQ==" {
		t.Errorf("PrivateKey: want cHJpdmtleQ==, got %q", wg.PrivateKey)
	}
}

// TestParseWireGuard_EmptyFragmentFallback verifies that a missing fragment produces a stable fallback name.
func TestParseWireGuard_EmptyFragmentFallback(t *testing.T) {
	uri := "wireguard://privkey@example.com:51820/?publickey=peer&address=10.0.0.2/32"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	want := fallbackName("wireguard", "example.com", 51820)
	if p.Name != want {
		t.Errorf("Name fallback: want %q, got %q", want, p.Name)
	}
}

// TestParseWireGuard_MissingPublicKey confirms nil,false when publickey param is absent.
func TestParseWireGuard_MissingPublicKey(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?address=10.0.0.2/32#nopub"
	p, ok := parseWireGuard(uri)
	if ok || p != nil {
		t.Error("expected nil,false when publickey is missing")
	}
}

// TestParseWireGuard_MissingPrivateKey confirms nil,false when userinfo (private key) is absent.
func TestParseWireGuard_MissingPrivateKey(t *testing.T) {
	uri := "wireguard://h:51820/?publickey=peer&address=10.0.0.2/32#noprivkey"
	p, ok := parseWireGuard(uri)
	if ok || p != nil {
		t.Error("expected nil,false when private key (userinfo) is missing")
	}
}

// TestParseWireGuard_BadPort confirms nil,false for an invalid port.
func TestParseWireGuard_BadPort(t *testing.T) {
	uri := "wireguard://privkey@h:notaport/?publickey=peer&address=10.0.0.2/32"
	p, ok := parseWireGuard(uri)
	if ok || p != nil {
		t.Error("expected nil,false for bad port")
	}
}

// TestParseWireGuard_NoTLS verifies that TLS is never allocated for WireGuard proxies.
func TestParseWireGuard_NoTLS(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&address=10.0.0.2/32#wg"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	if p.TLS != nil {
		t.Errorf("TLS should be nil for WireGuard, got %+v", p.TLS)
	}
}

// TestParseWireGuard_AllowedIPsAbsent verifies that AllowedIPs is nil/empty when param is absent.
func TestParseWireGuard_AllowedIPsAbsent(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&address=10.0.0.2/32"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	if len(p.WireGuard.AllowedIPs) != 0 {
		t.Errorf("AllowedIPs: want empty when absent, got %v", p.WireGuard.AllowedIPs)
	}
}

// TestParseWireGuard_IPParamAlias checks that ?ip= is accepted as an alias for ?address=.
func TestParseWireGuard_IPParamAlias(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&ip=10.0.0.3/32"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success with ip= param")
	}
	if p.WireGuard.IP != "10.0.0.3/32" {
		t.Errorf("IP via ip=: want 10.0.0.3/32, got %q", p.WireGuard.IP)
	}
}

// TestParseWireGuard_PSKAlias verifies the psk short-form alias.
func TestParseWireGuard_PSKAlias(t *testing.T) {
	uri := "wireguard://privkey@h:51820/?publickey=peer&address=10.0.0.2/32&psk=MYPSK"
	p, ok := parseWireGuard(uri)
	if !ok {
		t.Fatal("expected parse success")
	}
	if p.WireGuard.PresharedKey != "MYPSK" {
		t.Errorf("PresharedKey via psk: want MYPSK, got %q", p.WireGuard.PresharedKey)
	}
}

// TestParseWireGuard_ZeroPort confirms nil,false for port 0.
func TestParseWireGuard_ZeroPort(t *testing.T) {
	uri := "wireguard://privkey@h:0/?publickey=peer&address=10.0.0.2/32"
	p, ok := parseWireGuard(uri)
	if ok || p != nil {
		t.Error("expected nil,false for port 0")
	}
}
