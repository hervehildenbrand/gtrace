package update

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    Version
		wantErr bool
	}{
		{"v0.5.0", Version{0, 5, 0}, false},
		{"0.5.0", Version{0, 5, 0}, false},
		{"v1.2.3", Version{1, 2, 3}, false},
		{"1.0.0", Version{1, 0, 0}, false},
		{"v10.20.30", Version{10, 20, 30}, false},
		{"dev", Version{}, true},
		{"", Version{}, true},
		{"v1.2", Version{}, true},
		{"v1.2.3.4", Version{}, true},
		{"vx.y.z", Version{}, true},
		{"v1.2.abc", Version{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseVersion(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestVersion_IsNewer(t *testing.T) {
	tests := []struct {
		name  string
		v     Version
		other Version
		want  bool
	}{
		{"major newer", Version{1, 0, 0}, Version{0, 9, 9}, true},
		{"minor newer", Version{0, 5, 0}, Version{0, 4, 0}, true},
		{"patch newer", Version{0, 5, 1}, Version{0, 5, 0}, true},
		{"equal", Version{0, 5, 0}, Version{0, 5, 0}, false},
		{"major older", Version{0, 9, 9}, Version{1, 0, 0}, false},
		{"minor older", Version{0, 4, 0}, Version{0, 5, 0}, false},
		{"patch older", Version{0, 5, 0}, Version{0, 5, 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.IsNewer(tt.other); got != tt.want {
				t.Errorf("%v.IsNewer(%v) = %v, want %v", tt.v, tt.other, got, tt.want)
			}
		})
	}
}

func TestVersion_String(t *testing.T) {
	v := Version{1, 2, 3}
	if s := v.String(); s != "1.2.3" {
		t.Errorf("Version.String() = %q, want %q", s, "1.2.3")
	}
}
