//go:build android || darwin

package iptables

import (
	"fmt"

	"fusiontunx/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type tproxy struct {
	ipt     *goiptables.IPTables
	ip      string
	cfg     Config
	tcpMode string
	udpMode string
}

func newTproxy(ipt *goiptables.IPTables, ip string, cfg Config) *tproxy {
	return &tproxy{ipt: ipt, ip: ip, cfg: cfg}
}

func (tp *tproxy) setup(tcpMode, udpMode string) error {
	tp.tcpMode = tcpMode
	tp.udpMode = udpMode
	if err := tp.createExternalChain(); err != nil {
		return fmt.Errorf("create CLASH_EXTERNAL: %w", err)
	}
	if err := tp.createLocalChain(); err != nil {
		return fmt.Errorf("create CLASH_LOCAL: %w", err)
	}
	if err := tp.createDivert(); err != nil {
		return fmt.Errorf("create DIVERT: %w", err)
	}
	if err := tp.createNatDNS(); err != nil {
		return fmt.Errorf("create NAT DNS: %w", err)
	}
	if err := tp.hookChains(); err != nil {
		return fmt.Errorf("hook chains: %w", err)
	}
	if err := tp.addPolicyRouting(); err != nil {
		return fmt.Errorf("policy routing: %w", err)
	}
	if err := tp.blockLoopback(); err != nil {
		return fmt.Errorf("block loopback: %w", err)
	}
	logger.Info("TPROXY iptables rules created successfully")
	return nil
}

func (tp *tproxy) createExternalChain() error {
	if err := tp.ipt.ClearChain("mangle", "CLASH_EXTERNAL"); err != nil {
		return err
	}

	if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
		"-p", "udp", "--dport", "443", "-j", "DROP",
	); err != nil {
		return err
	}

	if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
		"-p", "tcp", "--dport", "53", "-j", "RETURN",
	); err != nil {
		return err
	}
	if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
		"-p", "udp", "--dport", "53", "-j", "RETURN",
	); err != nil {
		return err
	}

	for _, subnet := range tp.cfg.ReservedIPv4 {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
			"-d", subnet, "-j", "RETURN",
		); err != nil {
			return err
		}
	}

	markMask := markMaskHex(tp.cfg.TProxyMark, tp.cfg.TProxyMask)
	port := fmt.Sprintf("%d", tp.cfg.TProxyPort)

	if tp.tcpMode == "tproxy" {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
			"-p", "tcp", "-i", "lo", "-j", "TPROXY",
			"--on-port", port, "--tproxy-mark", markMask,
		); err != nil {
			return err
		}
	}
	if tp.udpMode == "tproxy" {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
			"-p", "udp", "-i", "lo", "-j", "TPROXY",
			"--on-port", port, "--tproxy-mark", markMask,
		); err != nil {
			return err
		}
	}

	for _, iface := range []string{"wlan+", "swlan+", "ap+", "rndis+", "usb+", "eth+", "bt-pan"} {
		if tp.tcpMode == "tproxy" {
			if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
				"-p", "tcp", "-i", iface, "-j", "TPROXY",
				"--on-port", port, "--tproxy-mark", markMask,
			); err != nil {
				return err
			}
		}
		if tp.udpMode == "tproxy" {
			if err := tp.ipt.AppendUnique("mangle", "CLASH_EXTERNAL",
				"-p", "udp", "-i", iface, "-j", "TPROXY",
				"--on-port", port, "--tproxy-mark", markMask,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func (tp *tproxy) createLocalChain() error {
	if err := tp.ipt.ClearChain("mangle", "CLASH_LOCAL"); err != nil {
		return err
	}

	if tp.cfg.MihomoGID > 0 {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
			"-m", "owner", "--uid-owner", fmt.Sprintf("%d", tp.cfg.MihomoUID),
			"--gid-owner", fmt.Sprintf("%d", tp.cfg.MihomoGID),
			"-j", "RETURN",
		); err != nil {
			return err
		}
	}

	if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
		"-p", "tcp", "--dport", "53", "-j", "RETURN",
	); err != nil {
		return err
	}
	if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
		"-p", "udp", "--dport", "53", "-j", "RETURN",
	); err != nil {
		return err
	}

	for _, subnet := range tp.cfg.ReservedIPv4 {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
			"-d", subnet, "-j", "RETURN",
		); err != nil {
			return err
		}
	}

	mark := markHex(tp.cfg.TProxyMark)
	if tp.tcpMode == "tproxy" {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
			"-p", "tcp", "-j", "MARK", "--set-mark", mark,
		); err != nil {
			return err
		}
	}
	if tp.udpMode == "tproxy" {
		if err := tp.ipt.AppendUnique("mangle", "CLASH_LOCAL",
			"-p", "udp", "-j", "MARK", "--set-mark", mark,
		); err != nil {
			return err
		}
	}

	return nil
}

func (tp *tproxy) createDivert() error {
	if err := tp.ipt.ClearChain("mangle", "DIVERT"); err != nil {
		return err
	}
	mark := markHex(tp.cfg.TProxyMark)
	if err := tp.ipt.AppendUnique("mangle", "DIVERT",
		"-j", "MARK", "--set-mark", mark,
	); err != nil {
		return err
	}
	if err := tp.ipt.AppendUnique("mangle", "DIVERT", "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

func (tp *tproxy) createNatDNS() error {
	if tp.cfg.DNSPort == 0 {
		return nil
	}
	port := fmt.Sprintf("%d", tp.cfg.DNSPort)

	if err := tp.ipt.ClearChain("nat", "CLASH_DNS"); err != nil {
		return err
	}
	if err := tp.ipt.AppendUnique("nat", "CLASH_DNS",
		"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port,
	); err != nil {
		return err
	}

	if err := tp.ipt.ClearChain("nat", "CLASH_DNS_LOCAL"); err != nil {
		return err
	}
	if tp.cfg.MihomoGID > 0 {
		if err := tp.ipt.AppendUnique("nat", "CLASH_DNS_LOCAL",
			"-m", "owner", "--uid-owner", fmt.Sprintf("%d", tp.cfg.MihomoUID),
			"--gid-owner", fmt.Sprintf("%d", tp.cfg.MihomoGID),
			"-j", "RETURN",
		); err != nil {
			return err
		}
	}
	if err := tp.ipt.AppendUnique("nat", "CLASH_DNS_LOCAL",
		"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port,
	); err != nil {
		return err
	}

	logger.Info("NAT DNS redirect rules created")
	return nil
}

func (tp *tproxy) hookChains() error {
	if tp.tcpMode == "tproxy" {
		if err := tp.ipt.InsertUnique("mangle", "PREROUTING", 1,
			"-p", "tcp", "-m", "socket", "-j", "DIVERT",
		); err != nil {
			return err
		}
	}
	if err := tp.ipt.AppendUnique("mangle", "PREROUTING", "-j", "CLASH_EXTERNAL"); err != nil {
		return err
	}

	if err := tp.ipt.AppendUnique("mangle", "OUTPUT", "-j", "CLASH_LOCAL"); err != nil {
		return err
	}

	if tp.cfg.DNSPort > 0 {
		if err := tp.ipt.InsertUnique("nat", "PREROUTING", 1, "-j", "CLASH_DNS"); err != nil {
			return err
		}
		if err := tp.ipt.InsertUnique("nat", "OUTPUT", 1, "-j", "CLASH_DNS_LOCAL"); err != nil {
			return err
		}
	}

	return nil
}

func (tp *tproxy) blockLoopback() error {
	if tp.cfg.MihomoGID > 0 {
		if err := tp.ipt.AppendUnique("filter", "OUTPUT",
			"-d", "127.0.0.1", "-p", "tcp",
			"-m", "owner", "--uid-owner", fmt.Sprintf("%d", tp.cfg.MihomoUID),
			"--gid-owner", fmt.Sprintf("%d", tp.cfg.MihomoGID),
			"-m", "tcp", "--dport", fmt.Sprintf("%d", tp.cfg.TProxyPort),
			"-j", "REJECT",
		); err != nil {
			return err
		}
	}
	return nil
}

func (tp *tproxy) addPolicyRouting() error {
	if tp.ip == "" {
		return nil
	}
	if err := runIP(tp.ip, "rule", "add", "fwmark", markMaskHex(tp.cfg.TProxyMark, tp.cfg.TProxyMask),
		"table", fmt.Sprintf("%d", tp.cfg.TProxyTableID),
		"pref", fmt.Sprintf("%d", tp.cfg.RulePref),
	); err != nil {
		return fmt.Errorf("ip rule add: %w", err)
	}
	if err := runIP(tp.ip, "route", "add", "local", "default", "dev", "lo",
		"table", fmt.Sprintf("%d", tp.cfg.TProxyTableID),
	); err != nil {
		return fmt.Errorf("ip route add: %w", err)
	}
	return nil
}

func (tp *tproxy) delPolicyRouting() {
	if tp.ip == "" {
		return
	}
	_ = runIPIgnore(tp.ip, "rule", "del", "fwmark", markMaskHex(tp.cfg.TProxyMark, tp.cfg.TProxyMask),
		"table", fmt.Sprintf("%d", tp.cfg.TProxyTableID),
	)
	_ = runIPIgnore(tp.ip, "route", "flush", "table", fmt.Sprintf("%d", tp.cfg.TProxyTableID))
}

func (tp *tproxy) cleanup() error {
	chains := []struct{ table, name string }{
		{"mangle", "DIVERT"},
		{"mangle", "CLASH_LOCAL"},
		{"mangle", "CLASH_EXTERNAL"},
	}
	natChains := []struct{ table, name string }{
		{"nat", "CLASH_DNS_LOCAL"},
		{"nat", "CLASH_DNS"},
	}
	var firstErr error

	_ = tp.ipt.DeleteIfExists("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "DIVERT")
	_ = tp.ipt.DeleteIfExists("mangle", "PREROUTING", "-j", "CLASH_EXTERNAL")
	_ = tp.ipt.DeleteIfExists("mangle", "OUTPUT", "-j", "CLASH_LOCAL")
	_ = tp.ipt.DeleteIfExists("nat", "PREROUTING", "-j", "CLASH_DNS")
	_ = tp.ipt.DeleteIfExists("nat", "OUTPUT", "-j", "CLASH_DNS_LOCAL")

	_ = tp.ipt.DeleteIfExists("filter", "OUTPUT",
		"-d", "127.0.0.1", "-p", "tcp",
		"-m", "owner", "--uid-owner", fmt.Sprintf("%d", tp.cfg.MihomoUID),
		"--gid-owner", fmt.Sprintf("%d", tp.cfg.MihomoGID),
		"-m", "tcp", "--dport", fmt.Sprintf("%d", tp.cfg.TProxyPort),
		"-j", "REJECT",
	)

	for _, c := range chains {
		if err := tp.ipt.ClearAndDeleteChain(c.table, c.name); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Debugf("cleanup: clear/delete chain %s/%s: %v", c.table, c.name, err)
		}
	}

	for _, c := range natChains {
		if err := tp.ipt.ClearAndDeleteChain(c.table, c.name); err != nil {
			logger.Debugf("cleanup: clear/delete chain %s/%s: %v", c.table, c.name, err)
		}
	}

	tp.delPolicyRouting()
	return firstErr
}
