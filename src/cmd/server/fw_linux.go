//go:build linux && !android

package main

import (
	"fusiontunx/internal/firewall"
	"fusiontunx/internal/firewall/nftables"
)

func newFirewall() (firewall.Firewall, error) {
	return nftables.New(), nil
}
