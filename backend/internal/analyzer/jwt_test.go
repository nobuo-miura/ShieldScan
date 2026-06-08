package analyzer

import (
	"strings"
	"testing"
)

func TestToInt64(t *testing.T) {
	tests := []struct {
		input interface{}
		want  int64
		ok    bool
	}{
		{float64(1234567890), 1234567890, true},
		{int64(42), 42, true},
		{nil, 0, false},
		{"string", 0, false},
	}
	for _, tc := range tests {
		got, ok := toInt64(tc.input)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("toInt64(%v) = (%d, %v), want (%d, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAnalyzeJWT_InvalidFormat(t *testing.T) {
	result, err := AnalyzeJWT("notajwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ParseError == "" {
		t.Error("expected ParseError for invalid JWT, got empty string")
	}
}

func TestAnalyzeJWT_AlgNone(t *testing.T) {
	// header: {"alg":"none","typ":"JWT"}, payload: {"sub":"1"}, signature: empty
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
	result, err := AnalyzeJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Severity == "critical" && strings.Contains(f.Title, "none") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical finding for alg:none, but not found")
	}
}

func TestAnalyzeJWT_NoExp(t *testing.T) {
	// header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1"} (no exp)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc"
	result, err := AnalyzeJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Severity == "high" && strings.Contains(f.Title, "exp") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected high finding for missing exp claim, but not found")
	}
}
