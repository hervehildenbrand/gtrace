package enrich

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataDir(t *testing.T) {
	dir, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir() error: %v", err)
	}
	if dir == "" {
		t.Error("DataDir() returned empty string")
	}
	// Should be under home directory
	home, _ := os.UserHomeDir()
	if home != "" && !filepath.HasPrefix(dir, home) {
		t.Errorf("DataDir() = %q, expected under %q", dir, home)
	}
}

func TestEnsureDataDir(t *testing.T) {
	// Create a temp directory for testing
	tmpDir := t.TempDir()
	testDataDir := filepath.Join(tmpDir, ".gtr", "data")

	err := EnsureDataDirAt(testDataDir)
	if err != nil {
		t.Fatalf("EnsureDataDirAt() error: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(testDataDir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("created path is not a directory")
	}
}

func TestDBStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   DBStatus
		expected string
	}{
		{
			name:     "not installed",
			status:   DBStatus{Installed: false},
			expected: "not installed",
		},
		{
			name:     "installed",
			status:   DBStatus{Installed: true, Path: "/path/to/db.mmdb"},
			expected: "installed at /path/to/db.mmdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expected {
				t.Errorf("DBStatus.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCheckDBStatus(t *testing.T) {
	status := CheckDBStatus()

	// Just verify it returns something without error
	if status.Path == "" {
		t.Error("CheckDBStatus() returned empty path")
	}
}
