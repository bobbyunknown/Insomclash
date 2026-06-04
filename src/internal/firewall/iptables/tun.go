//go:build android || darwin

package iptables

import (
	"fmt"

	"fusiontunx/pkg/config"
	"fusiontunx/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type tun struct {
	ipt     *goiptables.IPTables
	ip      string
	cfg     Config
	device  string
}

func newTun(ipt *goiptables.IPTables, ip string, cfg Config) *tun {
	return &tun{ipt: ipt, ip: ip, cfg: cfg, device: cfg.TunDevice}
}

func (t *tun) setDevice(name string) {
	if name != "" {
		t.device = name
	}
}

func (t *tun) setup(routingConfig config.RoutingConfig) error {
	if err := t.createMangleChain(); err != nil {
		return fmt.Errorf("create CLASH_TUN: %w", err)
	}
	if err := t.hookChains(); err != nil {
		return fmt.Errorf("hook chains: %w", err)
	}
	if err := t.addPolicyRouting(routingConfig); err != nil {
		return fmt.Errorf("policy routing: %w", err)
	}
	logger.Info("TUN iptables rules created successfully")
	return nil
}

func (t *tun) createMangleChain() error {
	if err := t.ipt.ClearChain("mangle", "CLASH_TUN"); err != nil {
		return err
	}

	if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
		"-i", "lo", "-j", "ACCEPT",
	); err != nil {
		return err
	}
	if t.device != "" {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
			"-i", t.device, "-j", "ACCEPT",
		); err != nil {
			return err
		}
	}
	for _, subnet := range t.cfg.LocalIPv4 {
		if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
			"-d", subnet, "-j", "ACCEPT",
		); err != nil {
			return err
		}
	}
	mark := markHex(t.cfg.TunMark)
	if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
		"-p", "tcp", "-j", "MARK", "--set-mark", mark,
	); err != nil {
		return err
	}
	if err := t.ipt.AppendUnique("mangle", "CLASH_TUN",
		"-p", "udp", "-j", "MARK", "--set-mark", mark,
	); err != nil {
		return err
	}
	return nil
}

func (t *tun) hookChains() error {
	return t.ipt.AppendUnique("mangle", "PREROUTING", "-j", "CLASH_TUN")
}

func (t *tun) addPolicyRouting(routingConfig config.RoutingConfig) error {
	if t.ip == "" || t.device == "" {
		return nil
	}
	if err := runIP(t.ip, "rule", "add", "fwmark", markHex(t.cfg.TunMark),
		"table", fmt.Sprintf("%d", t.cfg.TunTableID),
		"pref", fmt.Sprintf("%d", t.cfg.RulePref),
	); err != nil {
		return fmt.Errorf("ip rule add: %w", err)
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
	_ = runIPIgnore(t.ip, "route", "flush", "table", fmt.Sprintf("%d", t.cfg.TunTableID))
}

func (t *tun) cleanup() error {
	var firstErr error
	if err := t.ipt.DeleteIfExists("mangle", "PREROUTING", "-j", "CLASH_TUN"); err != nil {
		logger.Debugf("cleanup: remove tun prerouting hook: %v", err)
	}
	if err := t.ipt.ClearAndDeleteChain("mangle", "CLASH_TUN"); err != nil {
		logger.Debugf("cleanup: clear/delete CLASH_TUN: %v", err)
		firstErr = err
	}
	t.delPolicyRouting()
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
