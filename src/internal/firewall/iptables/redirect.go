//go:build android || darwin

package iptables

import (
	"fmt"

	"fusiontunx/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type redirect struct {
	ipt *goiptables.IPTables
	cfg Config
}

func newRedirect(ipt *goiptables.IPTables, cfg Config) *redirect {
	return &redirect{ipt: ipt, cfg: cfg}
}

func (r *redirect) setup() error {
	if err := r.createNatChain(); err != nil {
		return fmt.Errorf("create CLASH_NAT: %w", err)
	}
	if err := r.hookChains(); err != nil {
		return fmt.Errorf("hook chains: %w", err)
	}
	logger.Info("REDIRECT iptables rules created successfully")
	return nil
}

func (r *redirect) createNatChain() error {
	if err := r.ipt.ClearChain("nat", "CLASH_NAT"); err != nil {
		return err
	}
	if err := r.ipt.AppendUnique("nat", "CLASH_NAT",
		"-o", "lo", "-j", "RETURN",
	); err != nil {
		return err
	}
	for _, subnet := range r.cfg.LocalIPv4 {
		if err := r.ipt.AppendUnique("nat", "CLASH_NAT",
			"-d", subnet, "-j", "RETURN",
		); err != nil {
			return err
		}
	}
	if err := r.ipt.AppendUnique("nat", "CLASH_NAT",
		"-p", "tcp", "-j", "REDIRECT", "--to-ports", portStr(r.cfg.RedirectPort),
	); err != nil {
		return err
	}
	return nil
}

func (r *redirect) hookChains() error {
	return r.ipt.AppendUnique("nat", "OUTPUT", "-j", "CLASH_NAT")
}

func (r *redirect) cleanup() error {
	var firstErr error
	if err := r.ipt.DeleteIfExists("nat", "OUTPUT", "-j", "CLASH_NAT"); err != nil {
		logger.Debugf("cleanup: remove nat output hook: %v", err)
	}
	if err := r.ipt.ClearAndDeleteChain("nat", "CLASH_NAT"); err != nil {
		logger.Debugf("cleanup: clear/delete CLASH_NAT: %v", err)
		firstErr = err
	}
	return firstErr
}
