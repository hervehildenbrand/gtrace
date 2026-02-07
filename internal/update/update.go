package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

const defaultBaseURL = "https://api.github.com/repos/hervehildenbrand/gtrace/releases/latest"

// CheckResult contains the result of an update check.
type CheckResult struct {
	UpdateAvailable bool
	LatestVersion   string
	CurrentVersion  string
	ReleaseURL      string
	AssetURL        string
	AssetName       string
}

// Checker queries GitHub for the latest release.
type Checker struct {
	baseURL    string
	httpClient *http.Client
}

// NewChecker returns a Checker configured for the gtrace repository.
func NewChecker() *Checker {
	return &Checker{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Check queries GitHub for the latest release and compares it to currentVersion.
// Returns nil if no update is available, or if the check fails for any reason.
func (c *Checker) Check(ctx context.Context, currentVersion string) *CheckResult {
	current, err := ParseVersion(currentVersion)
	if err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil
	}

	latest, err := ParseVersion(release.TagName)
	if err != nil {
		return nil
	}

	if !latest.IsNewer(current) {
		return nil
	}

	result := &CheckResult{
		UpdateAvailable: true,
		LatestVersion:   latest.String(),
		CurrentVersion:  current.String(),
		ReleaseURL:      release.HTMLURL,
	}

	assetName := getAssetName(latest.String())
	result.AssetName = assetName
	for _, a := range release.Assets {
		if a.Name == assetName {
			result.AssetURL = a.BrowserDownloadURL
			break
		}
	}

	return result
}

// getAssetName returns the expected archive name for the current platform.
func getAssetName(version string) string {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("gtrace_%s_%s_%s%s", version, runtime.GOOS, runtime.GOARCH, ext)
}
