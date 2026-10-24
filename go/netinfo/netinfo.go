// Package netinfo finds this machine's primary IPv4 address without
// contacting external hosts, a port of src/kid_pc_monitor/network.py as the
// Windows agent uses it: ask the kernel which source address it would route
// from (a UDP "connect" to TEST-NET-1 sends no packets), then fall back to the
// addresses the host name resolves to. The Linux /proc and macOS route
// resolvers are not ported; the agent only runs on Windows.
package netinfo

import (
	"net"
	"os"
	"strings"
	"time"
)

// RFC 5737 TEST-NET-1: only used to pick a route.
const routingProbe = "192.0.2.1:1"

// PrimaryIPv4 returns the primary IPv4 address, or "" when there is none.
func PrimaryIPv4() string {
	if ip := routingIPv4(); ip != "" {
		return ip
	}
	return hostnameIPv4()
}

// LocalIP is PrimaryIPv4, or 127.0.0.1 when that is unknown.
func LocalIP() string {
	if ip := PrimaryIPv4(); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func routingIPv4() string {
	conn, err := net.DialTimeout("udp4", routingProbe, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return usableIPv4(addr.IP.String())
}

func hostnameIPv4() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	addrs, err := net.LookupHost(name)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ip := usableIPv4(a); ip != "" {
			return ip
		}
	}
	return ""
}

// usableIPv4 returns ip when it is a routable-looking IPv4 address: not
// loopback, link-local or 0.0.0.0.
func usableIPv4(ip string) string {
	if ip == "" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "169.254.") {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.To4().Equal(net.IPv4zero) {
		return ""
	}
	return ip
}
