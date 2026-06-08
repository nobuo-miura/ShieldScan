package analyzer

import "testing"

func TestIsSensitiveCookie(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"session_id", true},
		{"auth_token", true},
		{"JWT", true},
		{"XSRF-TOKEN", true},
		{"user_pref", true},
		{"theme", false},
		{"lang", false},
		{"_ga", false},
	}
	for _, tc := range tests {
		got := isSensitiveCookie(tc.name)
		if got != tc.want {
			t.Errorf("isSensitiveCookie(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestUpgradeSeverity(t *testing.T) {
	tests := []struct {
		current, candidate, want string
	}{
		{"info", "warning", "warning"},
		{"warning", "high", "high"},
		{"high", "critical", "critical"},
		{"critical", "high", "critical"},
		{"warning", "info", "warning"},
		{"info", "info", "info"},
	}
	for _, tc := range tests {
		got := upgradeSeverity(tc.current, tc.candidate)
		if got != tc.want {
			t.Errorf("upgradeSeverity(%q, %q) = %q, want %q", tc.current, tc.candidate, got, tc.want)
		}
	}
}
