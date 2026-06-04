//go:build android || darwin

package iptables

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseHexOrInt parses a mark/port-like string that may be in
// hexadecimal (0xNN) or decimal (NN) form. Returns 0 on parse error.
func ParseHexOrInt(s string) uint32 {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		if v, err := strconv.ParseUint(s[2:], 16, 32); err == nil {
			return uint32(v)
		}
	}
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(v)
	}
	return 0
}

// parseHexOrInt is an internal alias kept for in-package tests.
func parseHexOrInt(s string) uint32 { return ParseHexOrInt(s) }

const (
	packagesListPath = "/data/system/packages.list"
)

func runIP(ip string, args ...string) error {
	if ip == "" {
		return fmt.Errorf("ip binary not configured")
	}
	return runCmd(ip, args...)
}

func runIPIgnore(ip string, args ...string) error {
	_ = runIP(ip, args...)
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func portStr(p uint16) string { return strconv.Itoa(int(p)) }

func listContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func findPackageUIDs(pkgs []string) (map[string]int, error) {
	uidMap := make(map[string]int)
	f, err := os.Open(packagesListPath)
	if err != nil {
		return uidMap, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkg := fields[0]
		if listContains(pkgs, pkg) {
			uid, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			uidMap[pkg] = uid
		}
	}
	return uidMap, scanner.Err()
}

func matchDevice(iface string, patterns []string) bool {
	for _, p := range patterns {
		matched, err := filepath.Match(p, iface)
		if err == nil && matched {
			return true
		}
	}
	return false
}
