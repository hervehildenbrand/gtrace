//go:build !windows

package update

import (
	"fmt"
	"io"
	"os"
)

func replaceBinary(oldPath, newPath string) error {
	// Try atomic rename first (same filesystem).
	if err := os.Rename(newPath, oldPath); err == nil {
		return nil
	}

	// Fallback: copy across filesystems.
	src, err := os.Open(newPath)
	if err != nil {
		return fmt.Errorf("open new binary: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(oldPath, os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("open old binary for write: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	return nil
}
