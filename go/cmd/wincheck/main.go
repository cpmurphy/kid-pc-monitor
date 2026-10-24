//go:build windows

// Command wincheck exercises winplatform against the real Windows host, for
// checking the port by hand:
//
//	wincheck status [-watch 2s]
//	    print the lock/session signals once, or repeatedly until Ctrl+C
//	wincheck lock [-watch 15s]
//	    lock the workstation, then print the lock state every second
//	wincheck message [-text T] [-title T]
//	    show the warning popup (closes itself after 60 s)
//	wincheck shutdown [-seconds 600]
//	    schedule a shutdown; undo it with "wincheck cancel"
//	wincheck cancel
//	    abort a pending shutdown
//
// Run it from the user's interactive session, as the agent would be.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"kidpcmonitor/winplatform"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: wincheck status|lock|message|shutdown|cancel [flags]")
	}
	slog.SetLogLoggerLevel(slog.LevelDebug)
	p := &winplatform.Platform{}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "status":
		watch := fs.Duration("watch", 0, "repeat at this interval")
		_ = fs.Parse(os.Args[2:])
		printDiagnostics(p)
		for *watch > 0 {
			time.Sleep(*watch)
			printStatus(p)
		}
	case "lock":
		watch := fs.Duration("watch", 15*time.Second, "how long to report the lock state")
		_ = fs.Parse(os.Args[2:])
		printStatus(p)
		if err := p.LockWorkstation(); err != nil {
			fatalf("LockWorkstation: %v", err)
		}
		fmt.Println("LockWorkstation ok")
		for end := time.Now().Add(*watch); time.Now().Before(end); {
			time.Sleep(time.Second)
			printStatus(p)
		}
	case "message":
		text := fs.String("text", "You have 5 minutes left.", "message text")
		title := fs.String("title", "PC Time Control", "window title")
		_ = fs.Parse(os.Args[2:])
		if err := p.ShowMessage(*text, *title); err != nil {
			fatalf("ShowMessage: %v", err)
		}
		fmt.Println("ShowMessage returned; waiting 65 s for the box to time out (Ctrl+C to stop)")
		time.Sleep(65 * time.Second)
	case "shutdown":
		seconds := fs.Int64("seconds", 600, "delay before shutdown")
		_ = fs.Parse(os.Args[2:])
		if err := p.Shutdown(*seconds); err != nil {
			fatalf("Shutdown: %v", err)
		}
		fmt.Printf("shutdown scheduled in %ds; run \"wincheck cancel\" to abort\n", *seconds)
	case "cancel":
		if err := p.CancelShutdown(); err != nil {
			fatalf("CancelShutdown: %v", err)
		}
		fmt.Println("shutdown cancelled")
	default:
		fatalf("unknown command %q", os.Args[1])
	}
}

func printDiagnostics(p *winplatform.Platform) {
	d := p.Diagnose()
	fmt.Printf("hostname        %s\n", p.Hostname())
	fmt.Printf("os version      %s (flags inverted: %v)\n", d.OSVersion, d.FlagsInverted)
	fmt.Printf("process session %d %s\n", d.ProcessSession, errText(d.ProcessErr))
	fmt.Printf("console session %d\n", int32(d.ConsoleSession))
	fmt.Printf("WTS flags       %#x %s\n", d.WTSFlags, errText(d.WTSErr))
	fmt.Printf("LogonUI here    %v %s\n", d.LogonUI, errText(d.LogonUIErr))
	printStatus(p)
}

func printStatus(p *winplatform.Platform) {
	locked, lerr := p.CheckSessionLocked()
	active, aerr := p.SessionIsActive()
	fmt.Printf("%s locked=%v%s active=%v%s\n", time.Now().Format("15:04:05"),
		locked, errText(lerr), active, errText(aerr))
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return " (error: " + err.Error() + ")"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wincheck: "+format+"\n", args...)
	os.Exit(1)
}
