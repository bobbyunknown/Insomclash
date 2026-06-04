//go:build android || darwin

package main

import (
	"fusiontunx/internal/firewall"
	"fusiontunx/internal/firewall/iptables"
)

func newFirewall() (firewall.Firewall, error) {
	return iptables.New()
}
