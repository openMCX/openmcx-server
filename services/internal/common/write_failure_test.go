// Test helper: storage failures that hold for root too (image builds run the tests as root, which ignores file
// permissions).
package common

import (
	"os"
	"path/filepath"
	"testing"
)

// ------------------------------------------------------------------------------
// blockWrites makes every writeFileAtomic into dir fail until the returned function is called: for each file in dir
// a non-empty directory takes the name of its temporary file, so the write of the temporary file fails and so does
// its removal.
func blockWrites(test *testing.T, dir string) func() {
	test.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		test.Fatal(err)
	}
	var blocks []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		block := filepath.Join(dir, entry.Name()+".tmp")
		if err := os.MkdirAll(filepath.Join(block, "keep"), 0o700); err != nil {
			test.Fatal(err)
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		test.Fatalf("no file in %s to block", dir)
	}
	return func() {
		for _, block := range blocks {
			if err := os.RemoveAll(block); err != nil {
				test.Fatal(err)
			}
		}
	}
}
