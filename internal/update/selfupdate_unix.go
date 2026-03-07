//go:build !windows

package update

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

func replaceBinary(oldPath, newPath string) error {
	// Try atomic rename first (same filesystem).
	if err := os.Rename(newPath, oldPath); err == nil {
		codesignIfMacOS(oldPath)
		return nil
	}

	// Fallback: copy across filesystems.
	// Remove the old binary first to avoid "text file busy" (ETXTBSY)
	// on Linux when the binary is currently executing. Unlinking a
	// running binary is safe — the kernel keeps the inode until the
	// process exits.
	src, err := os.Open(newPath)
	if err != nil {
		return fmt.Errorf("open new binary: %w", err)
	}
	defer src.Close()

	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("remove old binary: %w", err)
	}

	dst, err := os.OpenFile(oldPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create new binary: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	codesignIfMacOS(oldPath)
	return nil
}

// codesignIfMacOS ad-hoc signs the binary on macOS.
// Goreleaser builds on Linux produce unsigned binaries that macOS
// will kill when run with elevated privileges (sudo).
func codesignIfMacOS(path string) {
	if runtime.GOOS != "darwin" {
		return
	}
	// Best-effort: if codesign fails, the binary may still work
	// for non-privileged use cases.
	_ = exec.Command("codesign", "--force", "--sign", "-", path).Run()
}
