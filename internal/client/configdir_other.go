//go:build !unix

package client

import "os"

// On Windows a file's mode bits say nothing (Go reports 0666 or 0444) and
// what protects the config directory is its ACL, which a profile directory
// already limits to its user. There's nothing here to check.
func checkConfigDir(string) error { return nil }

func checkConfigFile(string, os.FileInfo) error { return nil }
