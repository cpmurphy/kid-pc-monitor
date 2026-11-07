package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Reverse sessions and HTTP handlers write concurrently; every write must
// succeed (busy_timeout + immediate transactions) and none may be lost.
func TestConcurrentWriters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), DBFilename))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const writers, rounds = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds*3)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", w+1)
			host := fmt.Sprintf("PC-%d", w)
			for r := 0; r < rounds; r++ {
				info := Info{"hostname": host, "ip": ip, "status": "UNLOCKED", "current_user": "kid",
					"reachable": true, "locked": r%2 == 0}
				errs <- s.RecordPollInspect(ip, info, time.Time{})
				errs <- s.SaveSnapshot(info)
				errs <- s.RecordAgentPoll(host, ip, info)
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	tracked, err := s.TrackedIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(tracked) != writers {
		t.Fatalf("tracked %d PCs, want %d", len(tracked), writers)
	}
	var scanRows int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&scanRows); err != nil {
		t.Fatal(err)
	}
	// Every round flips "locked", so every update is a status change.
	if scanRows != writers*rounds {
		t.Fatalf("%d scan rows, want %d", scanRows, writers*rounds)
	}
}

// Opening an existing database (for example one the Python panel created)
// keeps its data and leaves it in WAL mode; opening it twice is fine.
func TestReopenKeepsDataAndWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFilename)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordPollInspect("10.0.0.1", Info{"hostname": "A"}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := other.ScanPC("10.0.0.1")
	if err != nil || pc["hostname"] != "A" {
		t.Fatalf("second store sees %v, %v", pc, err)
	}
	other.Close()
	s.Close()

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var mode string
	if err := raw.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v", mode, err)
	}
}
