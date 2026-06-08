package analyzer

import "testing"

func TestExtractHost(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"https://example.com", "example.com"},
		{"https://example.com/path/to/page", "example.com"},
		{"http://sub.example.com", "sub.example.com"},
		{"https://example.com:8080/path", "example.com:8080"},
	}
	for _, tc := range tests {
		got := extractHost(tc.rawURL)
		if got != tc.want {
			t.Errorf("extractHost(%q) = %q, want %q", tc.rawURL, got, tc.want)
		}
	}
}
