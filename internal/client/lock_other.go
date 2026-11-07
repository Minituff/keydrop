//go:build !unix

package client

import (
	"errors"
	"os"
	"time"
)

const isWindows = true

// lockFile takes a lock by creating path exclusively, waiting while
// another process holds it. A lock older than staleLock is taken to be
// left by a process that died, and is removed.
func lockFile(path string) (func(), error) {
	const staleLock = time.Minute
	deadline := time.Now().Add(2 * staleLock)
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > staleLock {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("another keydrop is holding " + path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func syncDir(string) {}
