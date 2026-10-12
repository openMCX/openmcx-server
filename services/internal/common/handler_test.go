//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// The background work of a service stops when its context ends (WithContext).
func TestBackgroundWorkStopsWithContext(test *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	svc := &service{ctx: ctx}
	var runs atomic.Int64
	svc.every(time.Millisecond, func(time.Time) { runs.Add(1) })
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runs.Load() == 0 {
		test.Fatal("the work never ran")
	}
	cancel()
	time.Sleep(20 * time.Millisecond) // a tick already taken may still finish
	stopped := runs.Load()
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != stopped {
		test.Fatalf("the work went on after the context ended: %d then %d runs", stopped, runs.Load())
	}
}

// ------------------------------------------------------------------------------
// writeFileAtomic replaces a file, and leaves no temporary file when the rename fails.
func TestWriteFileAtomicCleansUpOnFailure(test *testing.T) {
	dir := test.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := writeFileAtomic(path, []byte("one")); err != nil {
		test.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("two")); err != nil {
		test.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "two" {
		test.Fatalf("content %q, %v", raw, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		test.Fatalf("mode %v, %v", info, err)
	}
	// A non-empty directory in the way: the rename fails.
	blocked := filepath.Join(dir, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "inside"), 0o700); err != nil {
		test.Fatal(err)
	}
	if err := writeFileAtomic(blocked, []byte("three")); err == nil {
		test.Fatal("rename over a directory succeeded")
	}
	if _, err := os.Stat(blocked + ".tmp"); !os.IsNotExist(err) {
		test.Fatalf("temporary file left behind: %v", err)
	}
}

// ------------------------------------------------------------------------------
// Helper: the handler of a role whose verification key is the public half of its signing key (the tests').
func NewHandler(role Role, cfg Config, signingKey *rsa.PrivateKey, dataDir string, opts ...Option) (http.Handler, error) {
	if signingKey == nil {
		return nil, errors.New("signing key is required")
	}
	return NewHandlerWithKeys(role, cfg, signingKey, &signingKey.PublicKey, dataDir, opts...)
}
