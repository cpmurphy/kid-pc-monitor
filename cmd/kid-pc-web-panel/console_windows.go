//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	user32                    = syscall.NewLazyDLL("user32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procShowWindow            = user32.NewProc("ShowWindow")
)

// hideOwnConsole hides the console window when this process is the only one
// attached to it, which means Windows created it for this launch (as for a
// scheduled task). A console shared with a shell is left alone.
func hideOwnConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 {
		return false
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return false
	}
	const swHide = 0
	procShowWindow.Call(hwnd, swHide)
	return true
}
