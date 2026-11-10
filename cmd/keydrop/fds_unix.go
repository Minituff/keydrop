//go:build unix

package main

import (
	"os"
	"strconv"
	"syscall"
)

// closeInheritedFDs marks every open descriptor above stderr close-on-exec,
// so a command run by `keydrop run` gets only stdin, stdout and stderr.
// Descriptors keydrop itself inherited (a shell's 3>&1, say) would
// otherwise pass straight to the command, and what it writes there skips
// the masking. Go opens its own files close-on-exec already.
func closeInheritedFDs() {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		d, err := os.Open(dir)
		if err != nil {
			continue
		}
		names, err := d.Readdirnames(-1)
		d.Close()
		if err != nil || len(names) == 0 {
			continue
		}
		for _, n := range names {
			if fd, err := strconv.Atoi(n); err == nil && fd > 2 {
				syscall.CloseOnExec(fd)
			}
		}
		return
	}
	// No way to list them: try every descriptor up to the limit (a closed
	// one just fails).
	limit := uint64(4096)
	var rl syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl) == nil && rl.Cur < 1<<16 {
		limit = uint64(rl.Cur)
	}
	for fd := 3; uint64(fd) < limit; fd++ {
		syscall.CloseOnExec(fd)
	}
}
