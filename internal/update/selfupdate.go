package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SelfUpdate downloads the release asset and replaces the current binary.
func SelfUpdate(ctx context.Context, result *CheckResult, binaryPath string) error {
	if result == nil || result.AssetURL == "" {
		return fmt.Errorf("no asset URL available for update")
	}

	// Download archive
	archivePath, err := downloadAsset(ctx, result.AssetURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(archivePath)

	// Extract binary from archive
	newBinaryPath, err := extractBinary(archivePath, result.AssetName)
	if err != nil {
		return fmt.Errorf("extract failed: %w", err)
	}
	defer os.Remove(newBinaryPath)

	// Replace current binary
	if err := replaceBinary(binaryPath, newBinaryPath); err != nil {
		return fmt.Errorf("replace failed: %w", err)
	}

	return nil
}

func downloadAsset(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "gtrace-update-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func extractBinary(archivePath, assetName string) (string, error) {
	if strings.HasSuffix(assetName, ".zip") {
		return extractFromZip(archivePath)
	}
	return extractFromTarGz(archivePath)
}

func extractFromTarGz(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	binaryName := "gtrace"
	if runtime.GOOS == "windows" {
		binaryName = "gtrace.exe"
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		name := filepath.Base(hdr.Name)
		if name != binaryName {
			continue
		}

		tmpFile, err := os.CreateTemp("", "gtrace-bin-*")
		if err != nil {
			return "", err
		}

		if _, err := io.Copy(tmpFile, tr); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return "", err
		}
		tmpFile.Close()

		if err := os.Chmod(tmpFile.Name(), 0o755); err != nil {
			os.Remove(tmpFile.Name())
			return "", err
		}

		return tmpFile.Name(), nil
	}

	return "", fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractFromZip(archivePath string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	binaryName := "gtrace"
	if runtime.GOOS == "windows" {
		binaryName = "gtrace.exe"
	}

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name != binaryName {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", err
		}

		tmpFile, err := os.CreateTemp("", "gtrace-bin-*")
		if err != nil {
			rc.Close()
			return "", err
		}

		if _, err := io.Copy(tmpFile, rc); err != nil {
			tmpFile.Close()
			rc.Close()
			os.Remove(tmpFile.Name())
			return "", err
		}
		tmpFile.Close()
		rc.Close()

		if err := os.Chmod(tmpFile.Name(), 0o755); err != nil {
			os.Remove(tmpFile.Name())
			return "", err
		}

		return tmpFile.Name(), nil
	}

	return "", fmt.Errorf("binary %q not found in archive", binaryName)
}
