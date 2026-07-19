package gateway

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func normalizeRequestHost(value string, tls bool) (string, error) {
	return normalizeHost(value, tls, true)
}

func normalizeConfiguredHost(value string, tls bool) (string, error) {
	return normalizeHost(value, tls, false)
}

func normalizeHost(value string, tls, permitCase bool) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "@,\t\r\n /\\") {
		return "", errors.New("host is empty, ambiguous, or contains forbidden syntax")
	}
	for _, r := range value {
		if r > 0x7f || r < 0x21 {
			return "", errors.New("host must be printable ASCII")
		}
	}
	if !permitCase && value != strings.ToLower(value) {
		return "", errors.New("configured host must be lowercase")
	}

	host := value
	port := ""
	if strings.HasPrefix(value, "[") {
		return "", errors.New("IP literals are not allowed")
	}
	if strings.Count(value, ":") > 1 {
		return "", errors.New("ambiguous host port")
	}
	if strings.Contains(value, ":") {
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return "", errors.New("invalid host port")
		}
	}
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
		if strings.HasSuffix(host, ".") {
			return "", errors.New("host has multiple trailing dots")
		}
	}
	if host == "" || len(host) > 253 {
		return "", errors.New("host length is invalid")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", errors.New("IP literals are not allowed")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS label is invalid")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", errors.New("host contains a non-DNS character")
			}
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("host port is invalid")
		}
		defaultPort := "80"
		if tls {
			defaultPort = "443"
		}
		if port != defaultPort {
			return net.JoinHostPort(host, port), nil
		}
	}
	return host, nil
}

func canonicalPeer(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("remote address must contain an IP and port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("remote address is not an IP")
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, errors.New("v0.1 gateway events require an IPv4 peer")
	}
	return addr, nil
}
