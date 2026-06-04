//go:build android || darwin

package iptables

import (
	"strings"
	"testing"

	"fusiontunx/pkg/config"
)

func TestNewWithConfig(t *testing.T) {
	if _, err := execLookPath("/bin/true"); err != nil {
		t.Skipf("no /bin/true on this platform: %v", err)
	}
	impl, err := newIptablesWithMock("/bin/true", "/bin/true", Config{
		TProxyPort:   7894,
		RedirectPort: 7891,
		LocalIPv4:    []string{"127.0.0.0/8"},
		ReservedIPv4: []string{"127.0.0.0/8"},
		TunDevice:    "tun",
	})
	if err != nil {
		t.Fatalf("newIptablesWithMock: %v", err)
	}
	if impl == nil {
		t.Fatal("nil impl")
	}
}

func TestParseHexOrInt(t *testing.T) {
	cases := map[string]uint32{
		"0x80":  0x80,
		"0X80":  0x80,
		"128":   128,
		"0x100": 0x100,
		"256":   256,
		"junk":  0,
	}
	for in, want := range cases {
		if got := parseHexOrInt(in); got != want {
			t.Errorf("parseHexOrInt(%q) = %d want %d", in, got, want)
		}
	}
}

func TestMarkHex(t *testing.T) {
	if got := markHex(0x80); got != "0x80" {
		t.Errorf("markHex(0x80) = %q want 0x80", got)
	}
	if got := markMaskHex(0x80, 0xFF); got != "0x80/0xff" {
		t.Errorf("markMaskHex = %q want 0x80/0xff", got)
	}
}

func TestPortStr(t *testing.T) {
	if got := portStr(7894); got != "7894" {
		t.Errorf("portStr(7894) = %q want 7894", got)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := defaultConfig()
	if cfg.TProxyPort != 7894 {
		t.Errorf("default TProxyPort = %d want 7894", cfg.TProxyPort)
	}
	if cfg.RedirectPort != 7891 {
		t.Errorf("default RedirectPort = %d want 7891", cfg.RedirectPort)
	}
	if cfg.TProxyMark != 0x80 {
		t.Errorf("default TProxyMark = %#x want 0x80", cfg.TProxyMark)
	}
	if cfg.TunMark != 0x200 {
		t.Errorf("default TunMark = %#x want 0x200", cfg.TunMark)
	}
	if len(cfg.ReservedIPv4) == 0 {
		t.Error("ReservedIPv4 should not be empty")
	}
}

func TestListContains(t *testing.T) {
	if !listContains([]string{"a", "b"}, "a") {
		t.Error("expected true for 'a'")
	}
	if listContains([]string{"a", "b"}, "c") {
		t.Error("expected false for 'c'")
	}
}

func TestArgEscape(t *testing.T) {
	cases := map[string]string{
		"abc":          "abc",
		"with space":   "'with space'",
		`a"b`:          `'a"b'`,
	}
	for in, want := range cases {
		if got := argEscape(in); got != want {
			t.Errorf("argEscape(%q) = %q want %q", in, got, want)
		}
	}
}

func TestRoutingModes(t *testing.T) {
	for _, mode := range []config.RoutingMode{
		config.RoutingModeTUN,
		config.RoutingModeTProxy,
		config.RoutingModeRedirect,
		config.RoutingModeDisable,
	} {
		if string(mode) == "" {
			t.Errorf("routing mode is empty: %v", mode)
		}
	}
	if !strings.Contains(string(config.RoutingModeTProxy), "tproxy") {
		t.Errorf("routing mode string mismatch: %v", config.RoutingModeTProxy)
	}
}
