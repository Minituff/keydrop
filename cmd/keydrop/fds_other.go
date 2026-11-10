//go:build !unix

package main

// closeInheritedFDs is for Unix, where descriptors are inherited unless
// marked close-on-exec. On Windows a child gets only its standard handles
// from Go's exec, so there's nothing to do.
func closeInheritedFDs() {}
