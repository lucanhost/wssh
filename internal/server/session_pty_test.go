package server

import (
	"testing"
)

func TestClampWinsize(t *testing.T) {
	cases := []struct {
		name     string
		rows     uint32
		cols     uint32
		wantRows uint16
		wantCols uint16
		wantOk   bool
	}{
		{"0x0 substitute", 0, 0, 24, 80, true},
		{"70000x70000 clamp", 70000, 70000, 0xFFFF, 0xFFFF, true},
		{"1x1 pass", 1, 1, 1, 1, true},
		{"FFFF x FFFF pass", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, true},
		{"FFFF+1 clamp", 0xFFFF + 1, 0xFFFF + 1, 0xFFFF, 0xFFFF, true},
		{"0 rows valid cols", 0, 100, 24, 100, true},
		{"100 rows valid 0 cols", 100, 0, 100, 80, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c, ok := clampWinsize(tc.rows, tc.cols)
			if r != tc.wantRows || c != tc.wantCols || ok != tc.wantOk {
				t.Fatalf("clampWinsize(%d,%d) = (%d,%d,%v), want (%d,%d,%v)",
					tc.rows, tc.cols, r, c, ok, tc.wantRows, tc.wantCols, tc.wantOk)
			}
		})
	}
}
