package normalize

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

var (
	ErrEmptyInput    = errors.New("empty input")
	ErrInvalidURL    = errors.New("invalid url")
	ErrInvalidIP     = errors.New("invalid ip address")
	ErrInvalidDomain = errors.New("invalid domain")
)

// URL parses and deterministically normalizes an HTTP/HTTPS URL.
func URL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrEmptyInput
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	if u.Scheme == "" || u.Host == "" {
		return "", ErrInvalidURL
	}

	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrInvalidURL
	}

	hostname := strings.ToLower(u.Hostname())
	port := u.Port()

	var host string
	if (u.Scheme == "http" && port == "80") ||
		(u.Scheme == "https" && port == "443") {
		host = hostname
	} else if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else {
		host = strings.ToLower(u.Host)
	}

	u.Host = host

	if u.Path != "" {
		cleaned := path.Clean(u.Path)
		if strings.HasSuffix(u.Path, "/") && cleaned != "/" {
			cleaned += "/"
		}
		u.Path = cleaned
	} else {
		u.Path = "/"
	}

	u.Fragment = ""

	return u.String(), nil
}

// IP validates and returns the canonical string representation
// of an IPv4 or IPv6 address.
func IP(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrEmptyInput
	}

	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return "", ErrInvalidIP
	}

	return parsed.String(), nil
}

// Domain validates and normalizes a domain name.
func Domain(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrEmptyInput
	}

	trimmed = strings.TrimSuffix(trimmed, ".")

	if len(trimmed) > 253 ||
		strings.ContainsAny(trimmed, " \t\r\n/\\:;?#") {
		return "", ErrInvalidDomain
	}

	if !strings.Contains(trimmed, ".") && trimmed != "localhost" {
		return "", ErrInvalidDomain
	}

	return strings.ToLower(trimmed), nil
}
