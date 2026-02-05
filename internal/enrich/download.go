// Package enrich provides IP enrichment functionality (ASN, GeoIP, rDNS).
package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Database file names
const (
	GeoLite2CityDB    = "GeoLite2-City.mmdb"
	GeoLite2CountryDB = "GeoLite2-Country.mmdb"
	GeoLite2ASNDB     = "GeoLite2-ASN.mmdb"
)

// DBStatus represents the status of a downloaded database.
type DBStatus struct {
	Installed   bool      // Whether the database is installed
	Path        string    // Path to the database file
	Size        int64     // File size in bytes
	ModTime     time.Time // Last modification time
	NeedsUpdate bool      // Whether an update is available
}

// String returns a human-readable status.
func (s DBStatus) String() string {
	if !s.Installed {
		return "not installed"
	}
	return fmt.Sprintf("installed at %s", s.Path)
}

// DataDir returns the gtr data directory path.
func DataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".gtr", "data"), nil
}

// EnsureDataDir creates the data directory if it doesn't exist.
func EnsureDataDir() error {
	dir, err := DataDir()
	if err != nil {
		return err
	}
	return EnsureDataDirAt(dir)
}

// EnsureDataDirAt creates the specified directory if it doesn't exist.
func EnsureDataDirAt(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// CheckDBStatus checks the status of the GeoIP database.
func CheckDBStatus() DBStatus {
	path := DefaultGeoDBPath()
	status := DBStatus{
		Path: path,
	}

	info, err := os.Stat(path)
	if err != nil {
		return status
	}

	status.Installed = true
	status.Size = info.Size()
	status.ModTime = info.ModTime()

	// Check if update needed (older than 30 days)
	if time.Since(info.ModTime()) > 30*24*time.Hour {
		status.NeedsUpdate = true
	}

	return status
}

// DownloadConfig holds configuration for database downloads.
type DownloadConfig struct {
	// LicenseKey is the MaxMind license key (required since Dec 2019)
	LicenseKey string

	// DataDir is the directory to store databases
	DataDir string

	// Databases is the list of databases to download
	Databases []string
}

// DefaultDownloadConfig returns sensible defaults.
func DefaultDownloadConfig() *DownloadConfig {
	dir, _ := DataDir()
	return &DownloadConfig{
		DataDir: dir,
		Databases: []string{
			GeoLite2CityDB,
		},
	}
}

// DownloadResult represents the result of a download operation.
type DownloadResult struct {
	Database string
	Success  bool
	Path     string
	Size     int64
	Error    error
}

// DownloadDatabases downloads the specified databases.
// Note: MaxMind requires a license key since December 2019.
// Users need to register at https://www.maxmind.com/en/geolite2/signup
func DownloadDatabases(cfg *DownloadConfig) ([]DownloadResult, error) {
	if cfg.LicenseKey == "" {
		return nil, fmt.Errorf("MaxMind license key required. Register at https://www.maxmind.com/en/geolite2/signup")
	}

	if err := EnsureDataDirAt(cfg.DataDir); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	var results []DownloadResult

	for _, db := range cfg.Databases {
		result := DownloadResult{
			Database: db,
		}

		// Download URL format for MaxMind
		// https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz
		// Note: Actual download implementation would require HTTP client and tar extraction
		// For now, we provide the infrastructure

		result.Error = fmt.Errorf("download not implemented - please download manually from MaxMind")
		results = append(results, result)
	}

	return results, nil
}

// PrintDBStatus prints a formatted database status report.
func PrintDBStatus() string {
	status := CheckDBStatus()

	var report string
	report += "GeoIP Database Status:\n"
	report += fmt.Sprintf("  Path: %s\n", status.Path)

	if status.Installed {
		report += fmt.Sprintf("  Status: Installed\n")
		report += fmt.Sprintf("  Size: %d bytes\n", status.Size)
		report += fmt.Sprintf("  Modified: %s\n", status.ModTime.Format(time.RFC3339))
		if status.NeedsUpdate {
			report += "  Note: Database is older than 30 days, consider updating\n"
		}
	} else {
		report += "  Status: Not installed\n"
		report += "\n"
		report += "To install:\n"
		report += "  1. Register at https://www.maxmind.com/en/geolite2/signup\n"
		report += "  2. Download GeoLite2-City.mmdb\n"
		report += fmt.Sprintf("  3. Place it at: %s\n", status.Path)
	}

	return report
}
