package normalize

import "testing"

func TestURL_NormalURL(t *testing.T) {
	got, err := URL("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != "https://example.com/" {
		t.Errorf("expected %q, got %q", "https://example.com/", got)
	}
}

func TestURL_WithPath(t *testing.T) {
	got, err := URL("https://EXAMPLE.COM/api/v1/users/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/api/v1/users/"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestURL_WithQueryParams(t *testing.T) {
	got, err := URL("https://example.com/search?q=sukku&page=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/search?q=sukku&page=1"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestURL_WithFragment(t *testing.T) {
	got, err := URL("https://example.com:443/docs#section-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/docs"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestURL_InvalidURL(t *testing.T) {
	invalids := []string{
		"",
		"://missing-scheme",
		"ftp://example.com",
		"example.com/no-scheme",
		"https://",
	}

	for _, raw := range invalids {
		if _, err := URL(raw); err == nil {
			t.Errorf("expected error for invalid URL %q", raw)
		}
	}
}

func TestURL_DeterministicNormalization(t *testing.T) {
	raw := "HTTP://Example.COM:80/a/../b/./c?param=1#fragment"
	expected := "http://example.com/b/c?param=1"

	for i := 0; i < 5; i++ {
		got, err := URL(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != expected {
			t.Fatalf("iteration %d: expected %q, got %q", i, expected, got)
		}
	}
}

func TestIP_And_Domain(t *testing.T) {
	ip, err := IP(" 192.0.2.1 ")
	if err != nil || ip != "192.0.2.1" {
		t.Errorf("IP normalization failed: %v, got %q", err, ip)
	}

	ipv6, err := IP("2001:0db8::1")
	if err != nil || ipv6 != "2001:db8::1" {
		t.Errorf("IPv6 normalization failed: %v, got %q", err, ipv6)
	}

	if _, err := IP("999.999.999.999"); err == nil {
		t.Errorf("expected error on invalid IP")
	}

	dom, err := Domain(" SUB.Example.COM. ")
	if err != nil || dom != "sub.example.com" {
		t.Errorf("Domain normalization failed: %v, got %q", err, dom)
	}

	if _, err := Domain("invalid domain space"); err == nil {
		t.Errorf("expected error on invalid domain")
	}
}
