package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name       string
		queryType  string // ?type= value; empty means omit
		userAgent  string
		wantFormat string
	}{
		// ── query-param overrides (priority 1) ─────────────────────────────────
		{name: "query clash", queryType: "clash", wantFormat: "clash"},
		{name: "query mihomo", queryType: "mihomo", wantFormat: "clash"},
		{name: "query v2ray", queryType: "v2ray", wantFormat: "v2ray"},
		// query param beats UA
		{name: "query clash beats UA", queryType: "clash", userAgent: "Mozilla/5.0", wantFormat: "clash"},
		{name: "query v2ray beats clash UA", queryType: "v2ray", userAgent: "Clash/v1.18.0", wantFormat: "v2ray"},

		// ── UA matching: positive cases (should detect clash) ──────────────────
		{name: "UA Clash/version", userAgent: "Clash/v1.18.0", wantFormat: "clash"},
		{name: "UA ClashforWindows", userAgent: "ClashforWindows/0.20.39", wantFormat: "clash"},
		{name: "UA Clash for Windows", userAgent: "Clash for Windows/0.20.39", wantFormat: "clash"},
		{name: "UA ClashX", userAgent: "ClashX/1.118.0", wantFormat: "clash"},
		{name: "UA ClashMeta", userAgent: "ClashMeta/1.0", wantFormat: "clash"},
		{name: "UA mihomo lowercase", userAgent: "mihomo/1.18.10", wantFormat: "clash"},
		{name: "UA Mihomo uppercase", userAgent: "Mihomo/1.18.10", wantFormat: "clash"},
		{name: "UA Mihomo Party with space", userAgent: "Mihomo Party/1.2.3", wantFormat: "clash"},
		{name: "UA Mihomo-Party with dash", userAgent: "Mihomo-Party/1.2.3", wantFormat: "clash"},
		{name: "UA Stash", userAgent: "Stash/2.5.0", wantFormat: "clash"},
		{name: "UA FlClash", userAgent: "FlClash/0.8.69", wantFormat: "clash"},
		{name: "UA Verge", userAgent: "Verge/1.7.7", wantFormat: "clash"},
		// case-insensitivity
		{name: "UA stash lowercase", userAgent: "stash/2.5.0", wantFormat: "clash"},
		{name: "UA CLASH uppercase", userAgent: "CLASH/1.0", wantFormat: "clash"},

		// ── UA matching: negative cases (must NOT flip to clash) ──────────────
		{name: "plain browser UA", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", wantFormat: "v2ray"},
		{name: "empty UA", userAgent: "", wantFormat: "v2ray"},
		{name: "stash in comment no slash", userAgent: "Mozilla/5.0 (compatible; stash bot)", wantFormat: "v2ray"},
		{name: "clash in path no slash after name", userAgent: "MyApp ClashModule/1.0", wantFormat: "v2ray"},
		{name: "verge in arbitrary string", userAgent: "Mozilla/5.0 (compatible; verge bot)", wantFormat: "v2ray"},
		{name: "clash word only no slash", userAgent: "clash", wantFormat: "v2ray"},
		{name: "v2rayN", userAgent: "v2rayN/6.23", wantFormat: "v2ray"},
		{name: "Shadowrocket", userAgent: "Shadowrocket/2.2.40", wantFormat: "v2ray"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.queryType != "" {
				q := req.URL.Query()
				q.Set("type", tc.queryType)
				req.URL.RawQuery = q.Encode()
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			got := detectFormat(req)
			if got != tc.wantFormat {
				t.Errorf("detectFormat(UA=%q, type=%q) = %q, want %q",
					tc.userAgent, tc.queryType, got, tc.wantFormat)
			}
		})
	}
}
