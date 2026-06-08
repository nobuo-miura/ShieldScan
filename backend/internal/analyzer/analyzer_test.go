package analyzer

import "testing"

func TestCalcGrade(t *testing.T) {
	tests := []struct {
		score, max int
		want       string
	}{
		{90, 100, "A+"},
		{80, 100, "A"},
		{70, 100, "B"},
		{60, 100, "C"},
		{50, 100, "D"},
		{49, 100, "F"},
		{0, 100, "F"},
		{0, 0, "F"},
		{100, 100, "A+"},
	}
	for _, tc := range tests {
		got := calcGrade(tc.score, tc.max)
		if got != tc.want {
			t.Errorf("calcGrade(%d, %d) = %q, want %q", tc.score, tc.max, got, tc.want)
		}
	}
}
