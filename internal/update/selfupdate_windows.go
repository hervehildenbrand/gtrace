//go:build windows

package update

import (
	"fmt"
	"io"
	"os"
)

func replaceBinary(oldPath, newPath string) error {
	// Windows can't overwrite a running binary directly.
	// Rename the old one out of the way, then copy the new one in.
	backupPath := oldPath + ".old"
	os.Remove(backupPath) // ignore error if doesn't exist

	if err := os.Rename(oldPath, backupPath); err != nil {
		return fmt.Errorf("rename old binary: %w", err)
	}

	src, err := os.Open(newPath)
	if err != nil {
		// Try to restore backup.
		os.Rename(backupPath, oldPath)
		return fmt.Errorf("open new binary: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		os.Rename(backupPath, oldPath)
		return fmt.Errorf("create new binary: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Rename(backupPath, oldPath)
		return fmt.Errorf("copy binary: %w", err)
	}

	// Clean up backup.
	os.Remove(backupPath)
	return nil
}
