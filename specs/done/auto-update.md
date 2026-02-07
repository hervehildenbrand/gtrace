# Plan: Auto-Update Check & Self-Upgrade for gtrace

## Status: DONE (2026-02-07)

Released as v0.6.0.

## Goal
Add version update detection on startup (non-blocking) and a `gtrace upgrade` subcommand for self-update.

---

## Architecture

```
internal/update/
├── semver.go              # Minimal version parsing & comparison
├── semver_test.go
├── update.go              # GitHub API check (Checker)
├── update_test.go         # httptest-based tests
├── selfupdate.go          # Download, extract, replace binary
├── selfupdate_test.go
├── selfupdate_unix.go     # Unix: atomic rename
└── selfupdate_windows.go  # Windows: rename dance

cmd/gtrace/
├── main.go                # Wire upgrade subcommand, pass Version
├── root.go                # Start background check in PreRunE, print notification after RunE
└── upgrade.go             # `gtrace upgrade` subcommand
```

**Disable mechanism**: `GTRACE_NO_UPDATE_CHECK=1` env var (no CLI flag — keeps help clean).

---

## Step 1: Semver Parsing (TDD)

### 1a. Test — `internal/update/semver_test.go`
```go
func TestParseVersion(t *testing.T)     // "v0.5.0" → {0,5,0}, "dev" → error
func TestVersion_IsNewer(t *testing.T)  // {0,5,0}.IsNewer({0,4,0}) == true
```

### 1b. Implement — `internal/update/semver.go`
```go
type Version struct { Major, Minor, Patch int }
func ParseVersion(s string) (Version, error)  // strips "v" prefix, splits on "."
func (v Version) IsNewer(other Version) bool   // major > minor > patch comparison
```

### 1c. Verify
```bash
go test ./internal/update/ -run TestParse -v
go test ./internal/update/ -run TestVersion -v
```

---

## Step 2: Update Checker (TDD)

### 2a. Test — `internal/update/update_test.go`
```go
func TestChecker_NewVersionAvailable(t *testing.T)    // httptest returns v0.6.0, current 0.5.0 → available
func TestChecker_AlreadyLatest(t *testing.T)          // httptest returns v0.5.0, current 0.5.0 → nil
func TestChecker_NetworkError_ReturnsNil(t *testing.T) // bad URL → nil (graceful)
func TestChecker_DevVersion_ReturnsNil(t *testing.T)   // "dev" → nil
func TestGetAssetName(t *testing.T)                    // matches runtime.GOOS/GOARCH pattern
```

### 2b. Implement — `internal/update/update.go`

```go
type CheckResult struct {
    UpdateAvailable bool
    LatestVersion   string   // "0.6.0"
    CurrentVersion  string
    ReleaseURL      string   // GitHub release page
    AssetURL        string   // Direct download for current OS/arch
    AssetName       string
}

type Checker struct {
    baseURL    string        // overridable for tests
    httpClient *http.Client
}

func NewChecker() *Checker   // baseURL = "https://api.github.com/repos/hervehildenbrand/gtrace/releases/latest"
func (c *Checker) Check(ctx context.Context, currentVersion string) *CheckResult
func getAssetName(version string) string   // "gtrace_0.6.0_darwin_arm64.tar.gz"
```

**GitHub API**: `GET https://api.github.com/repos/hervehildenbrand/gtrace/releases/latest`
- Parse `tag_name`, `html_url`, `assets[].name`, `assets[].browser_download_url`
- 3-second timeout, silent on any error

### 2c. Verify
```bash
go test ./internal/update/ -v
```

---

## Step 3: CLI Integration — Background Check & Notification

### 3a. Modify `cmd/gtrace/main.go`

Pass `Version` to `NewRootCmd` so it can start the background check:

```go
func main() {
    cmd := NewRootCmd(Version)
    cmd.Version = Version
    // ...
}
```

### 3b. Modify `cmd/gtrace/root.go`

**`NewRootCmd` signature**: `func NewRootCmd(version string) *cobra.Command`

**In `PreRunE`** (after validation, before return):
```go
// Start non-blocking update check
if version != "dev" && os.Getenv("GTRACE_NO_UPDATE_CHECK") != "1" {
    cfg.updateResult = startUpdateCheck(version)
}
```

**After `runTrace` returns in `RunE`**:
```go
err := runTrace(cmd, &cfg)
printUpdateNotification(cmd.ErrOrStderr(), cfg.updateResult)
return err
```

**Config struct** — add field:
```go
updateResult <-chan *update.CheckResult // unexported, not a CLI flag
```

### 3c. Fix existing test

`cmd/gtrace/root_test.go` calls `NewRootCmd()` — update to `NewRootCmd("dev")`.

### 3d. Verify
```bash
go test ./cmd/gtrace/... -v
go build -ldflags "-X main.Version=0.1.0" -o /tmp/gtr ./cmd/gtrace && sudo /tmp/gtr --simple --max-hops 3 8.8.8.8
# Should show update notification at the end
```

---

## Step 4: Self-Update Logic (TDD)

### 4a. Test — `internal/update/selfupdate_test.go`
```go
func TestDownloadAsset(t *testing.T)         // httptest serves tar.gz, verify download
func TestExtractBinary_TarGz(t *testing.T)   // extract "gtrace" from tar.gz archive
func TestExtractBinary_Zip(t *testing.T)     // extract "gtrace.exe" from zip (Windows)
```

### 4b. Implement — `internal/update/selfupdate.go`

```go
func SelfUpdate(ctx context.Context, result *CheckResult) error
func downloadAsset(ctx context.Context, url string) (tmpPath string, err error)
func extractBinary(archivePath, assetName string) (binaryPath string, err error)
```

**Archive handling**:
- `.tar.gz`: `archive/tar` + `compress/gzip` — extract file named `gtrace`
- `.zip`: `archive/zip` — extract file named `gtrace.exe`

### 4c. Platform-specific replacement

**`selfupdate_unix.go`** (`//go:build !windows`):
```go
func replaceBinary(oldPath, newPath string) error
// os.Rename (atomic), fallback to copy if cross-device
```

**`selfupdate_windows.go`** (`//go:build windows`):
```go
func replaceBinary(oldPath, newPath string) error
// Rename old → .old, copy new → old path
```

### 4d. Verify
```bash
go test ./internal/update/ -v
```

---

## Step 5: Upgrade Subcommand

### 5a. Create `cmd/gtrace/upgrade.go`
```go
func NewUpgradeCmd(currentVersion string) *cobra.Command {
    // Use: "upgrade"
    // Short: "Upgrade gtrace to the latest version"
    // Checks for update, prompts y/N, calls SelfUpdate
    // --force flag to skip prompt
}
```

### 5b. Wire in `main.go`
```go
if Version != "dev" {
    cmd.AddCommand(NewUpgradeCmd(Version))
}
```

### 5c. Verify
```bash
go build -ldflags "-X main.Version=0.1.0" -o /tmp/gtr ./cmd/gtrace
/tmp/gtr upgrade        # Should detect v0.5.0 available, prompt, and update
/tmp/gtr upgrade --force # Non-interactive
```

---

## Step 6: README Update

Add to Usage section:
- Document `GTRACE_NO_UPDATE_CHECK=1` env var
- Document `gtrace upgrade` subcommand
- Add entry to feature comparison table

---

## Verification

All verified 2026-02-07:
- `go test ./...` — 9/9 packages pass
- `go vet ./...` — clean
- Build with old version → notification shown after trace
- `gtrace upgrade --force` → binary replaced from 0.1.0 to 0.6.0
- `GTRACE_NO_UPDATE_CHECK=1` → no notification
- CI green on ubuntu, macos, windows
- Released as v0.6.0
