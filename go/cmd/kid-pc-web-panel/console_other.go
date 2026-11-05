//go:build !windows

package main

// hideOwnConsole is Windows-only; elsewhere there is no console window.
func hideOwnConsole() bool { return false }
