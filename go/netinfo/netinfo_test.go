package netinfo

import (
	"net"
	"testing"
)

func TestUsableIPv4(t *testing.T) {
	for ip, want := range map[string]string{
		"192.168.1.20": "192.168.1.20",
		"10.0.0.5":     "10.0.0.5",
		"127.0.0.1":    "",
		"169.254.3.4":  "",
		"0.0.0.0":      "",
		"":             "",
		"::1":          "",
		"fe80::1":      "",
		"not an ip":    "",
	} {
		if got := usableIPv4(ip); got != want {
			t.Errorf("usableIPv4(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestLocalIPIsIPv4(t *testing.T) {
	ip := net.ParseIP(LocalIP())
	if ip == nil || ip.To4() == nil {
		t.Fatalf("LocalIP() = %q", LocalIP())
	}
}
