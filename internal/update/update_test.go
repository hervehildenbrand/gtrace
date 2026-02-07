package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

// githubRelease mirrors the subset of the GitHub API response we parse.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func newTestServer(t *testing.T, release githubRelease) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(release); err != nil {
			t.Fatal(err)
		}
	}))
}

func TestChecker_NewVersionAvailable(t *testing.T) {
	assetName := getAssetName("0.6.0")
	srv := newTestServer(t, githubRelease{
		TagName: "v0.6.0",
		HTMLURL: "https://github.com/hervehildenbrand/gtrace/releases/tag/v0.6.0",
		Assets: []githubAsset{
			{Name: assetName, BrowserDownloadURL: "https://example.com/" + assetName},
		},
	})
	defer srv.Close()

	c := &Checker{baseURL: srv.URL, httpClient: srv.Client()}
	result := c.Check(context.Background(), "0.5.0")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.UpdateAvailable {
		t.Error("expected UpdateAvailable to be true")
	}
	if result.LatestVersion != "0.6.0" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "0.6.0")
	}
	if result.CurrentVersion != "0.5.0" {
		t.Errorf("CurrentVersion = %q, want %q", result.CurrentVersion, "0.5.0")
	}
	if result.AssetURL == "" {
		t.Error("expected AssetURL to be set")
	}
}

func TestChecker_AlreadyLatest(t *testing.T) {
	srv := newTestServer(t, githubRelease{
		TagName: "v0.5.0",
		HTMLURL: "https://github.com/hervehildenbrand/gtrace/releases/tag/v0.5.0",
	})
	defer srv.Close()

	c := &Checker{baseURL: srv.URL, httpClient: srv.Client()}
	result := c.Check(context.Background(), "0.5.0")
	if result != nil {
		t.Errorf("expected nil result when already latest, got %+v", result)
	}
}

func TestChecker_NetworkError_ReturnsNil(t *testing.T) {
	c := &Checker{baseURL: "http://127.0.0.1:1", httpClient: http.DefaultClient}
	result := c.Check(context.Background(), "0.5.0")
	if result != nil {
		t.Errorf("expected nil on network error, got %+v", result)
	}
}

func TestChecker_DevVersion_ReturnsNil(t *testing.T) {
	c := NewChecker()
	result := c.Check(context.Background(), "dev")
	if result != nil {
		t.Errorf("expected nil for dev version, got %+v", result)
	}
}

func TestGetAssetName(t *testing.T) {
	name := getAssetName("0.6.0")

	// Should contain version, OS, and arch
	wantOS := runtime.GOOS
	wantArch := runtime.GOARCH
	if wantOS == "darwin" {
		wantOS = "darwin"
	}

	expected := "gtrace_0.6.0_" + wantOS + "_" + wantArch
	if runtime.GOOS == "windows" {
		expected += ".zip"
	} else {
		expected += ".tar.gz"
	}
	if name != expected {
		t.Errorf("getAssetName(0.6.0) = %q, want %q", name, expected)
	}
}

func TestChecker_ServerError_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Checker{baseURL: srv.URL, httpClient: srv.Client()}
	result := c.Check(context.Background(), "0.5.0")
	if result != nil {
		t.Errorf("expected nil on server error, got %+v", result)
	}
}
