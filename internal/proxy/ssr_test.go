package proxy

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// encodeSSR builds a valid ssr:// URI from raw fields.
// password, obfsparam, protoparam, and remarks are base64-encoded individually
// (RawURLEncoding, matching the most common real-world panel output).
// The outer blob is also RawURLEncoding.
func encodeSSR(host string, port uint16, protocol, method, obfs, password string, extras map[string]string) string {
	b64pw := base64.RawURLEncoding.EncodeToString([]byte(password))
	main := fmt.Sprintf("%s:%d:%s:%s:%s:%s", host, port, protocol, method, obfs, b64pw)

	params := url.Values{}
	for k, v := range extras {
		params.Set(k, base64.RawURLEncoding.EncodeToString([]byte(v)))
	}

	body := main
	if len(params) > 0 {
		body = main + "/?" + params.Encode()
	}

	blob := base64.RawURLEncoding.EncodeToString([]byte(body))
	return "ssr://" + blob
}

// encodeSSRPadded is like encodeSSR but uses standard (padded) base64.
func encodeSSRPadded(host string, port uint16, protocol, method, obfs, password string, extras map[string]string) string {
	b64pw := base64.StdEncoding.EncodeToString([]byte(password))
	main := fmt.Sprintf("%s:%d:%s:%s:%s:%s", host, port, protocol, method, obfs, b64pw)

	params := url.Values{}
	for k, v := range extras {
		params.Set(k, base64.StdEncoding.EncodeToString([]byte(v)))
	}

	body := main
	if len(params) > 0 {
		body = main + "/?" + params.Encode()
	}

	// Outer blob: standard padded base64 (replace + and / with - and _ for URL safety, keep =)
	raw := base64.StdEncoding.EncodeToString([]byte(body))
	// We want the outer to also be standard (non-URL-safe) to test StdEncoding path.
	return "ssr://" + raw
}

// encodeSSRURLSafePadded uses URLEncoding (URL-safe with padding).
func encodeSSRURLSafePadded(host string, port uint16, protocol, method, obfs, password string, extras map[string]string) string {
	b64pw := base64.RawURLEncoding.EncodeToString([]byte(password))
	main := fmt.Sprintf("%s:%d:%s:%s:%s:%s", host, port, protocol, method, obfs, b64pw)

	params := url.Values{}
	for k, v := range extras {
		params.Set(k, base64.RawURLEncoding.EncodeToString([]byte(v)))
	}

	body := main
	if len(params) > 0 {
		body = main + "/?" + params.Encode()
	}

	// URLEncoding: URL-safe alphabet WITH padding.
	blob := base64.URLEncoding.EncodeToString([]byte(body))
	return "ssr://" + blob
}

func TestParseSSR_Standard(t *testing.T) {
	extras := map[string]string{
		"obfsparam":  "ticket.example.com",
		"protoparam": "12345",
		"remarks":    "My Node",
	}
	uri := encodeSSR("1.2.3.4", 8388, "auth_aes128_md5", "aes-256-cfb", "tls1.2_ticket_auth", "secretpw", extras)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for valid URI: %s", uri)
	}

	if p.Type != "ssr" {
		t.Errorf("Type: got %q, want %q", p.Type, "ssr")
	}
	if p.Server != "1.2.3.4" {
		t.Errorf("Server: got %q, want %q", p.Server, "1.2.3.4")
	}
	if p.Port != 8388 {
		t.Errorf("Port: got %d, want %d", p.Port, 8388)
	}
	if p.Cipher != "aes-256-cfb" {
		t.Errorf("Cipher: got %q, want %q", p.Cipher, "aes-256-cfb")
	}
	if p.Password != "secretpw" {
		t.Errorf("Password: got %q, want %q", p.Password, "secretpw")
	}
	if p.Network != "tcp" {
		t.Errorf("Network: got %q, want %q", p.Network, "tcp")
	}
	if p.Name != "My Node" {
		t.Errorf("Name: got %q, want %q", p.Name, "My Node")
	}
	if p.Raw != uri {
		t.Errorf("Raw: got %q, want %q", p.Raw, uri)
	}
	if p.SSR == nil {
		t.Fatal("SSR config is nil")
	}
	if p.SSR.Protocol != "auth_aes128_md5" {
		t.Errorf("SSR.Protocol: got %q, want %q", p.SSR.Protocol, "auth_aes128_md5")
	}
	if p.SSR.ProtocolParam != "12345" {
		t.Errorf("SSR.ProtocolParam: got %q, want %q", p.SSR.ProtocolParam, "12345")
	}
	if p.SSR.Obfs != "tls1.2_ticket_auth" {
		t.Errorf("SSR.Obfs: got %q, want %q", p.SSR.Obfs, "tls1.2_ticket_auth")
	}
	if p.SSR.ObfsParam != "ticket.example.com" {
		t.Errorf("SSR.ObfsParam: got %q, want %q", p.SSR.ObfsParam, "ticket.example.com")
	}
}

func TestParseSSR_PaddedBase64(t *testing.T) {
	// Outer blob uses standard (padded) base64 — tryBase64Decode must handle it.
	uri := encodeSSRPadded("10.0.0.1", 443, "origin", "chacha20", "plain", "p4ssw0rd", nil)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for padded-base64 URI: %s", uri)
	}
	if p.Server != "10.0.0.1" {
		t.Errorf("Server: got %q, want %q", p.Server, "10.0.0.1")
	}
	if p.Password != "p4ssw0rd" {
		t.Errorf("Password: got %q, want %q", p.Password, "p4ssw0rd")
	}
}

func TestParseSSR_URLSafePaddedBase64(t *testing.T) {
	// Outer blob uses URL-safe WITH padding (URLEncoding).
	uri := encodeSSRURLSafePadded("192.168.1.1", 1080, "auth_chain_a", "rc4-md5", "http_simple", "mypass", nil)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for URL-safe-padded URI: %s", uri)
	}
	if p.Password != "mypass" {
		t.Errorf("Password: got %q, want %q", p.Password, "mypass")
	}
	if p.SSR.Protocol != "auth_chain_a" {
		t.Errorf("Protocol: got %q, want %q", p.SSR.Protocol, "auth_chain_a")
	}
}

func TestParseSSR_NonASCIIRemarks(t *testing.T) {
	// Remarks containing non-ASCII characters (Russian + emoji).
	extras := map[string]string{
		"remarks": "Россия 🌍",
	}
	uri := encodeSSR("5.5.5.5", 2333, "auth_aes128_sha1", "aes-128-ctr", "tls1.2_ticket_fastauth", "pw", extras)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for non-ASCII remarks URI")
	}
	if p.Name != "Россия 🌍" {
		t.Errorf("Name: got %q, want %q", p.Name, "Россия 🌍")
	}
}

func TestParseSSR_MissingOptionalParams(t *testing.T) {
	// No obfsparam, protoparam, or remarks.
	uri := encodeSSR("8.8.8.8", 9000, "auth_aes128_md5", "aes-256-cfb", "tls1.2_ticket_auth", "pass123", nil)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for URI without optional params")
	}
	// Name should fall back to generated name.
	want := fallbackName("ssr", "8.8.8.8", 9000)
	if p.Name != want {
		t.Errorf("Name: got %q, want %q", p.Name, want)
	}
	if p.SSR.ObfsParam != "" {
		t.Errorf("SSR.ObfsParam should be empty, got %q", p.SSR.ObfsParam)
	}
	if p.SSR.ProtocolParam != "" {
		t.Errorf("SSR.ProtocolParam should be empty, got %q", p.SSR.ProtocolParam)
	}
}

func TestParseSSR_DefaultProtocol(t *testing.T) {
	// Empty protocol field should default to "origin".
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	main := fmt.Sprintf("1.1.1.1:8080::%s:plain:%s", "aes-256-cfb", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for empty protocol")
	}
	if p.SSR.Protocol != "origin" {
		t.Errorf("SSR.Protocol default: got %q, want %q", p.SSR.Protocol, "origin")
	}
}

func TestParseSSR_DefaultObfs(t *testing.T) {
	// Empty obfs field should default to "plain".
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	main := fmt.Sprintf("1.1.1.1:8080:origin:aes-256-cfb::%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for empty obfs")
	}
	if p.SSR.Obfs != "plain" {
		t.Errorf("SSR.Obfs default: got %q, want %q", p.SSR.Obfs, "plain")
	}
}

func TestParseSSR_NoBlobDelimiter(t *testing.T) {
	// Valid URI with no "/?" separator in the decoded body (params-less).
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("simplepass"))
	main := fmt.Sprintf("2.2.2.2:3000:origin:rc4-md5:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for URI without /?")
	}
	if p.Password != "simplepass" {
		t.Errorf("Password: got %q, want %q", p.Password, "simplepass")
	}
}

func TestParseSSR_MethodLowercased(t *testing.T) {
	// Method should be lowercased regardless of input case.
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	main := fmt.Sprintf("3.3.3.3:8080:origin:AES-256-CFB:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for URI with uppercase method")
	}
	if p.Cipher != "aes-256-cfb" {
		t.Errorf("Cipher: got %q, want %q", p.Cipher, "aes-256-cfb")
	}
}

func TestParseSSR_GroupIgnored(t *testing.T) {
	// "group" param should be parsed but not stored anywhere observable.
	extras := map[string]string{
		"remarks": "Node",
		"group":   "MyGroup",
	}
	uri := encodeSSR("4.4.4.4", 7000, "origin", "chacha20", "plain", "pw", extras)

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR returned false for URI with group param")
	}
	// Just verify we get a valid proxy — group isn't stored anywhere.
	if p.Name != "Node" {
		t.Errorf("Name: got %q, want %q", p.Name, "Node")
	}
}

// --- Invalid input tests ---

func TestParseSSR_InvalidNotBase64(t *testing.T) {
	uri := "ssr://this is not base64!!!"
	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for invalid base64 body")
	}
}

func TestParseSSR_WrongFieldCount(t *testing.T) {
	// Only 5 fields instead of 6.
	body := "host:1234:origin:method:obfs"
	blob := base64.RawURLEncoding.EncodeToString([]byte(body))
	uri := "ssr://" + blob

	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for wrong field count (5 fields)")
	}
}

func TestParseSSR_TooManyColonsInPassword(t *testing.T) {
	// SplitN(..., 6) means extra colons in password part are absorbed correctly.
	password := "pass:with:colons"
	b64pw := base64.RawURLEncoding.EncodeToString([]byte(password))
	main := fmt.Sprintf("9.9.9.9:9999:origin:aes-256-cfb:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	p, ok := parseSSR(uri)
	if !ok {
		t.Fatalf("parseSSR should succeed with colons in password")
	}
	if p.Password != password {
		t.Errorf("Password: got %q, want %q", p.Password, password)
	}
}

func TestParseSSR_InvalidPort(t *testing.T) {
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	// Port "notaport" is not numeric.
	main := fmt.Sprintf("1.1.1.1:notaport:origin:aes-256-cfb:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for non-numeric port")
	}
}

func TestParseSSR_PortZero(t *testing.T) {
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	main := fmt.Sprintf("1.1.1.1:0:origin:aes-256-cfb:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for port 0")
	}
}

func TestParseSSR_EmptyHost(t *testing.T) {
	b64pw := base64.RawURLEncoding.EncodeToString([]byte("pw"))
	main := fmt.Sprintf(":8080:origin:aes-256-cfb:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for empty host")
	}
}

func TestParseSSR_EmptyPassword(t *testing.T) {
	// b64 of empty string decodes to "" — should be rejected.
	b64pw := base64.RawURLEncoding.EncodeToString([]byte(""))
	main := fmt.Sprintf("1.1.1.1:8080:origin:aes-256-cfb:plain:%s", b64pw)
	blob := base64.RawURLEncoding.EncodeToString([]byte(main))
	uri := "ssr://" + blob

	_, ok := parseSSR(uri)
	if ok {
		t.Error("expected false for empty password")
	}
}

func TestParseSSR_EmptyURI(t *testing.T) {
	_, ok := parseSSR("ssr://")
	if ok {
		t.Error("expected false for ssr:// with no body")
	}
}

func TestParseSSR_WrongScheme(t *testing.T) {
	_, ok := parseSSR("ss://something")
	if ok {
		t.Error("expected false for ss:// scheme")
	}
}

func TestParseSSR_SSRConfigAlwaysAllocated(t *testing.T) {
	uri := encodeSSR("1.2.3.4", 8388, "auth_aes128_md5", "aes-256-cfb", "tls1.2_ticket_auth", "pw", nil)
	p, ok := parseSSR(uri)
	if !ok {
		t.Fatal("parseSSR returned false")
	}
	if p.SSR == nil {
		t.Error("SSR config must always be allocated for ssr:// type")
	}
}

// TestParseSSR_ViaDispatcher verifies that the top-level Parse dispatcher routes
// ssr:// correctly and does not confuse it with ss://.
func TestParseSSR_ViaDispatcher(t *testing.T) {
	uri := encodeSSR("7.7.7.7", 1234, "origin", "chacha20", "plain", "dispatchpw", nil)

	p, ok := Parse(uri)
	if !ok {
		t.Fatalf("Parse returned false for ssr:// URI")
	}
	if p.Type != "ssr" {
		t.Errorf("Type from dispatcher: got %q, want %q", p.Type, "ssr")
	}
}

// TestParseSSR_SSPrefixNotConfused verifies ss:// URIs are not parsed as SSR.
func TestParseSSR_SSPrefixNotConfused(t *testing.T) {
	// A valid-looking ss:// URI should NOT be caught by parseSSR.
	// We just verify parseSSR itself returns false for ss:// input.
	ssURI := "ss://dGVzdDp0ZXN0QDEuMi4zLjQ6ODA4MA==#name"
	_, ok := parseSSR(ssURI)
	if ok {
		t.Error("parseSSR must return false for ss:// scheme")
	}
}

// Compile-time check: ensure encodeSSRPadded is used (suppresses unused warning).
var _ = strings.Contains
