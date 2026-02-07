package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func createTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func createZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	return buf.Bytes()
}

func TestDownloadAsset(t *testing.T) {
	payload := []byte("fake-binary-content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	tmpPath, err := downloadAsset(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("downloadAsset: %v", err)
	}
	defer os.Remove(tmpPath)

	got, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("downloaded content mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestDownloadAsset_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := downloadAsset(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error on server error response")
	}
}

func TestExtractBinary_TarGz(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello")
	archive := createTarGz(t, map[string][]byte{
		"gtrace": binaryContent,
	})

	tmpFile := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := os.WriteFile(tmpFile, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	binPath, err := extractBinary(tmpFile, "test.tar.gz")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	defer os.Remove(binPath)

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binaryContent) {
		t.Errorf("extracted content mismatch")
	}
}

func TestExtractBinary_TarGz_MissingBinary(t *testing.T) {
	archive := createTarGz(t, map[string][]byte{
		"README.md": []byte("readme"),
	})

	tmpFile := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := os.WriteFile(tmpFile, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := extractBinary(tmpFile, "test.tar.gz")
	if err == nil {
		t.Fatal("expected error when binary not found in archive")
	}
}

func TestExtractBinary_Zip(t *testing.T) {
	binaryName := "gtrace"
	if runtime.GOOS == "windows" {
		binaryName = "gtrace.exe"
	}
	binaryContent := []byte("MZ fake exe content")
	archive := createZip(t, map[string][]byte{
		binaryName: binaryContent,
	})

	tmpFile := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(tmpFile, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	binPath, err := extractBinary(tmpFile, "test.zip")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	defer os.Remove(binPath)

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binaryContent) {
		t.Errorf("extracted content mismatch")
	}
}

func TestSelfUpdate_EndToEnd(t *testing.T) {
	// Create a fake binary to replace
	tmpDir := t.TempDir()
	oldBinary := filepath.Join(tmpDir, "gtrace")
	if runtime.GOOS == "windows" {
		oldBinary += ".exe"
	}
	if err := os.WriteFile(oldBinary, []byte("old-version"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Create archive with new binary
	newContent := []byte("new-version-binary")
	var archive []byte
	var assetName string
	if runtime.GOOS == "windows" {
		archive = createZip(t, map[string][]byte{"gtrace.exe": newContent})
		assetName = "gtrace_1.0.0_windows_amd64.zip"
	} else {
		archive = createTarGz(t, map[string][]byte{"gtrace": newContent})
		assetName = "gtrace_1.0.0_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	}))
	defer srv.Close()

	result := &CheckResult{
		UpdateAvailable: true,
		LatestVersion:   "1.0.0",
		CurrentVersion:  "0.5.0",
		AssetURL:        srv.URL + "/" + assetName,
		AssetName:       assetName,
	}

	err := SelfUpdate(context.Background(), result, oldBinary)
	if err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}

	got, err := os.ReadFile(oldBinary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newContent) {
		t.Errorf("binary not updated: got %q, want %q", got, newContent)
	}
}
