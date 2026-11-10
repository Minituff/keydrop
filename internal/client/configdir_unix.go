//go:build unix

package client

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkConfigDir refuses an existing config directory that another user
// owns or could write to: whoever can put a url or pin file there decides
// where the token goes and which certificate is trusted. One that doesn't
// exist yet is fine; keydrop creates it mode 700.
func checkConfigDir(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s isn't a directory; move it away so keydrop can create its config directory there", dir)
	}
	if !ownedByMe(fi) {
		return fmt.Errorf("%s belongs to another user, so keydrop won't trust the server URL, pin or token in it; move it away and run keydrop pair (or login) again", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by other users, so keydrop won't trust the server URL, pin or token in it; run chmod 700 %s", dir, dir)
	}
	return nil
}

// checkConfigFile refuses a url or pin file another user owns or could
// write to, for the same reason. (They aren't secret, so reading isn't
// checked; the token file is.)
func checkConfigFile(path string, fi os.FileInfo) error {
	if !ownedByMe(fi) {
		return fmt.Errorf("%s belongs to another user, so keydrop won't trust it; delete it and run keydrop pair (or login) again", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by other users, so keydrop won't trust it; run chmod 600 %s", path, path)
	}
	return nil
}

func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(st.Uid) == uint64(os.Getuid())
}
