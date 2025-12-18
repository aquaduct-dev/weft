package util

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// EnsurePort ensures that the URL has a port set, using defaults for http/https.
func EnsurePort(u *url.URL) error {
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			u.Host = net.JoinHostPort(u.Hostname(), "80")
		case "https":
			u.Host = net.JoinHostPort(u.Hostname(), "443")
		case "tcp", "udp":
			// For tcp/udp we can't easily guess a default port if it's missing.
			return fmt.Errorf("missing port for %s scheme: %s", u.Scheme, u.String())
		default:
			return fmt.Errorf("unsupported scheme for missing port: %s", u.String())
		}
	}
	return nil
}

// ParsePort parses the port from a host string, with a default if missing.
func ParsePort(host string, defaultPort int) (int, error) {
	_, portStr, err := net.SplitHostPort(host)
	if err != nil {
		// Might be just the host without port
		if strings.Contains(host, ":") {
			return 0, fmt.Errorf("invalid host format: %s", host)
		}
		return defaultPort, nil
	}
	return strconv.Atoi(portStr)
}

// RewriteHost updates the host part of a URL while preserving the port.
func RewriteHost(u *url.URL, newHost string) {
	if newHost == "0.0.0.0" || newHost == "" {
		return
	}
	port := u.Port()
	if port != "" {
		u.Host = net.JoinHostPort(newHost, port)
	} else {
		u.Host = newHost
	}
}
