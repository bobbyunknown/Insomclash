//go:build android || darwin

package iptables

import (
	"fmt"
	"os/exec"
	"strings"

	"fusiontunx/pkg/config"
	"fusiontunx/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type tun struct {
	ipt     *goiptables.IPTables
	ip      string
	device  string
	cfg     Config
	tcpMode string
	udpMode string
}

func newTun(ipt *goiptables.IPTables, ip string, cfg Config) *tun {
	return &tun{ipt: ipt, ip: ip, cfg: cfg, device: cfg.TunDevice}
}

func (t *tun) setDevice(name string) {
	t.device = name
}

func (t *tun) setup(routingConfig config.RoutingConfig) error {
	t.tcpMode = string(routingConfig.TCP)
	t.udpMode = string(routingConfig.UDP)
	if err := t.createPreroutingChain(); err != nil {
		return fmt.Errorf("create CLASH_TUN: %w", err)
	}
	if err := t.createForwardChain(); err != nil {
		return fmt.Errorf("create CLASH_TUN_FWD: %w", err)
	}
	if err := t.createOutputChain(); err != nil {
		return fmt.Errorf("create CLASH_TUN_OUTPUT: %w", err)
	}
	if err := t.hookChains(); err != nil {
		return fmt.Errorf("hook chains: %w", err)
	}
	if err := t.addPolicyRouting(); err != nil {
		return fmt.Errorf("policy routing: %w", err)
	}
	if err := t.enableForwarding(); err != nil {
		return fmt.Errorf("forwarding: %w", err)
	}
	logger.Info("TUN iptables rules created successfully")
	return nil
}

func (t *tun) createPreroutingChain() error {
	if err := t.ipt.ClearChain("mangle", "CLASH_TUN"); err != nil {
		return err
	}

	for _, subnet := range t.cfg.ReservedIPv4 {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
			"-d", subnet, "-j", "RETURN",
		); err != nil {
			return err
		}
	}

	mark := markHex(t.cfg.TunMark)
	for _, iface := range []string{"wlan+", "swlan+", "ap+", "rndis+", "usb+", "eth+", "bt-pan"} {
		if t.tcpMode == "tun" {
			if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
				"-p", "tcp", "-i", iface, "-j", "MARK", "--set-mark", mark,
			); err != nil {
				return err
			}
		}
		if t.udpMode == "tun" {
			if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
				"-p", "udp", "-i", iface, "-j", "MARK", "--set-mark", mark,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *tun) createForwardChain() error {
	if err := t.ipt.ClearChain("mangle", "CLASH_TUN_FWD"); err != nil {
		return err
	}
	for _, iface := range []string{"wlan+", "swlan+", "ap+", "rndis+", "usb+", "eth+", "bt-pan"} {
		if t.tcpMode == "tun" {
			if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_FWD",
				"-p", "tcp", "-i", iface, "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu",
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *tun) createOutputChain() error {
	if err := t.ipt.ClearChain("mangle", "CLASH_TUN_OUTPUT"); err != nil {
		return err
	}

	if t.cfg.MihomoGID > 0 {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
			"-m", "owner",
			"--uid-owner", fmt.Sprintf("%d", t.cfg.MihomoUID),
			"--gid-owner", fmt.Sprintf("%d", t.cfg.MihomoGID),
			"-j", "ACCEPT",
		); err != nil {
			return err
		}
	}

	for _, subnet := range t.cfg.LocalIPv4 {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
			"-d", subnet, "-j", "ACCEPT",
		); err != nil {
			return err
		}
	}

	for _, subnet := range []string{"224.0.0.0/4", "255.255.255.255/32"} {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
			"-d", subnet, "-j", "ACCEPT",
		); err != nil {
			return err
		}
	}

	if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
		"-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT",
	); err != nil {
		return err
	}
	if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
		"-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT",
	); err != nil {
		return err
	}

	mark := markHex(t.cfg.TunMark)
	if t.tcpMode == "tun" {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
			"-p", "tcp", "-j", "MARK", "--set-mark", mark,
		); err != nil {
			return err
		}
	}
	if t.udpMode == "tun" {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN_OUTPUT",
			"-p", "udp", "-j", "MARK", "--set-mark", mark,
		); err != nil {
			return err
		}
	}
	return nil
}

func (t *tun) hookChains() error {
	if err := t.ipt.AppendUnique("mangle", "PREROUTING", "-j", "CLASH_TUN"); err != nil {
		return err
	}
	if err := t.ipt.AppendUnique("mangle", "FORWARD", "-j", "CLASH_TUN_FWD"); err != nil {
		return err
	}
	if err := t.ipt.AppendUnique("mangle", "OUTPUT", "-j", "CLASH_TUN_OUTPUT"); err != nil {
		return err
	}
	return nil
}

func (t *tun) addPolicyRouting() error {
	if t.ip == "" || t.device == "" {
		return nil
	}
	if err := runIP(t.ip, "rule", "add", "fwmark", markHex(t.cfg.TunMark),
		"table", fmt.Sprintf("%d", t.cfg.TunTableID),
		"pref", fmt.Sprintf("%d", t.cfg.RulePref),
	); err != nil {
		return fmt.Errorf("ip rule add: %w", err)
	}

	for _, subnet := range t.cfg.LocalIPv4 {
		if err := runIP(t.ip, "rule", "add", "pref", "8998", "to", subnet, "goto", "9010"); err != nil {
			return fmt.Errorf("ip rule add bypass 8998: %w", err)
		}
	}

	if err := runIP(t.ip, "route", "add", "default", "dev", t.device,
		"table", fmt.Sprintf("%d", t.cfg.TunTableID),
	); err != nil {
		return fmt.Errorf("ip route add: %w", err)
	}
	return nil
}

func (t *tun) delPolicyRouting() {
	if t.ip == "" {
		return
	}
	_ = runIPIgnore(t.ip, "rule", "del", "fwmark", markHex(t.cfg.TunMark),
		"table", fmt.Sprintf("%d", t.cfg.TunTableID),
	)
	for _, subnet := range t.cfg.LocalIPv4 {
		_ = runIPIgnore(t.ip, "rule", "del", "pref", "8998", "to", subnet)
	}
	_ = runIPIgnore(t.ip, "route", "flush", "table", fmt.Sprintf("%d", t.cfg.TunTableID))
}

func (t *tun) cleanup() error {
	var firstErr error
	if err := t.ipt.DeleteIfExists("mangle", "PREROUTING", "-j", "CLASH_TUN"); err != nil {
		logger.Debugf("cleanup: remove tun prerouting hook: %v", err)
	}
	if err := t.ipt.DeleteIfExists("mangle", "FORWARD", "-j", "CLASH_TUN_FWD"); err != nil {
		logger.Debugf("cleanup: remove tun forward hook: %v", err)
	}
	if err := t.ipt.DeleteIfExists("mangle", "OUTPUT", "-j", "CLASH_TUN_OUTPUT"); err != nil {
		logger.Debugf("cleanup: remove tun output hook: %v", err)
	}
	if err := t.ipt.ClearAndDeleteChain("mangle", "CLASH_TUN"); err != nil {
		logger.Debugf("cleanup: clear/delete CLASH_TUN: %v", err)
		firstErr = err
	}
	if err := t.ipt.ClearAndDeleteChain("mangle", "CLASH_TUN_FWD"); err != nil {
		logger.Debugf("cleanup: clear/delete CLASH_TUN_FWD: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := t.ipt.ClearAndDeleteChain("mangle", "CLASH_TUN_OUTPUT"); err != nil {
		logger.Debugf("cleanup: clear/delete CLASH_TUN_OUTPUT: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	t.delPolicyRouting()
	t.disableForwarding()
	return firstErr
}

func (t *tun) isActive() bool {
	exists, err := t.ipt.ChainExists("mangle", "CLASH_TUN")
	if err != nil {
		return false
	}
	if !exists {
		return false
	}
	hasHook, err := t.ipt.Exists("mangle", "PREROUTING", "-j", "CLASH_TUN")
	if err != nil {
		return false
	}
	return hasHook
}

func sysctlWrite(key, value string) error {
	out, err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", key, value)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl %s=%s: %s: %w", key, value, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (t *tun) enableForwarding() error {
	if t.device == "" {
		return nil
	}

	if err := t.ipt.InsertUnique("filter", "FORWARD", 1, "-o", t.device, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("FORWARD -o %s ACCEPT: %w", t.device, err)
	}
	if err := t.ipt.InsertUnique("filter", "FORWARD", 1, "-i", t.device, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("FORWARD -i %s ACCEPT: %w", t.device, err)
	}

	if err := sysctlWrite("net.ipv4.ip_forward", "1"); err != nil {
		logger.Debugf("sysctl ip_forward: %v", err)
	}
	if err := sysctlWrite("net.ipv4.conf.all.rp_filter", "2"); err != nil {
		logger.Debugf("sysctl rp_filter all: %v", err)
	}
	if err := sysctlWrite("net.ipv4.conf.default.rp_filter", "2"); err != nil {
		logger.Debugf("sysctl rp_filter default: %v", err)
	}

	logger.Infof("TUN forwarding enabled for %s", t.device)
	return nil
}

func (t *tun) disableForwarding() {
	if t.device == "" {
		return
	}
	_ = t.ipt.DeleteIfExists("filter", "FORWARD", "-o", t.device, "-j", "ACCEPT")
	_ = t.ipt.DeleteIfExists("filter", "FORWARD", "-i", t.device, "-j", "ACCEPT")
}
