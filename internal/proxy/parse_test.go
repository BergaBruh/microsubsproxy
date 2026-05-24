package proxy

import "testing"

func TestParseAll(t *testing.T) {
	validVLESS := "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none&type=tcp#node1"
	invalidURI := "notascheme://garbage"
	unknownScheme := "http://example.com"

	tests := []struct {
		name        string
		input       []string
		wantParsed  int
		wantDropped int
	}{
		{
			name:        "empty input",
			input:       []string{},
			wantParsed:  0,
			wantDropped: 0,
		},
		{
			name:        "all valid",
			input:       []string{validVLESS, validVLESS},
			wantParsed:  2,
			wantDropped: 0,
		},
		{
			name:        "all invalid",
			input:       []string{invalidURI, unknownScheme},
			wantParsed:  0,
			wantDropped: 2,
		},
		{
			name:        "mixed valid and invalid",
			input:       []string{validVLESS, invalidURI, validVLESS, unknownScheme},
			wantParsed:  2,
			wantDropped: 2,
		},
		{
			name:        "single valid",
			input:       []string{validVLESS},
			wantParsed:  1,
			wantDropped: 0,
		},
		{
			name:        "single invalid",
			input:       []string{invalidURI},
			wantParsed:  0,
			wantDropped: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, dropped := ParseAll(tc.input)
			if len(parsed) != tc.wantParsed {
				t.Errorf("ParseAll() parsed=%d, want %d", len(parsed), tc.wantParsed)
			}
			if dropped != tc.wantDropped {
				t.Errorf("ParseAll() dropped=%d, want %d", dropped, tc.wantDropped)
			}
		})
	}
}
