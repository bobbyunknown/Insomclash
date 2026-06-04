//go:build android || darwin

package iptables

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"fusiontunx/internal/firewall"
	"fusiontunx/pkg/config"
	"fusiontunx/pkg/logger"

	goiptables "github.com/coreos/go-iptables/iptables"
)

type Config struct {
	IPTablesPath  string
	IP6TablesPath string
	IPPath        string
	TProxyPort    uint16
	MihomoMark    uint32
	TProxyMark    uint32
	TProxyMask    uint32
	TunMark       uint32
	TunTableID    int
	TProxyTableID int
	RulePref      int
	RedirectPort  uint16
	DNSPort       uint16
	MihomoUID     int
	MihomoGID     int
	ReservedIPv4  []string
	LocalIPv4     []string
	TunDevice     string
}

func defaultConfig() Config {
	return Config{
		IPTablesPath:  "",
		IP6TablesPath: "",
		IPPath:        "",
		TProxyPort:    7894,
		MihomoMark:    0x1000000,
		TProxyMark:    0x1000000,
		TProxyMask:    0x1000000,
		TunMark:       0x1000000,
		TunTableID:    2024,
		TProxyTableID: 2024,
		RulePref:      100,
		RedirectPort:  7891,
		DNSPort:       1053,
		MihomoUID:     0,
		MihomoGID:     3005,
		ReservedIPv4: []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
			"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
			"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
			"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		},
		LocalIPv4: []string{
			"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		},
		TunDevice: "tun",
	}
}

type Impl struct {
	cfg    Config
	ipt4   *goiptables.IPTables
	tproxy *tproxy
	tun    *tun
	redir  *redirect
}

func New() (*Impl, error) {
	return NewWithConfig(defaultConfig())
}

func NewWithConfig(cfg Config) (*Impl, error) {
	ipt, err := newIptables(goiptables.ProtocolIPv4, cfg.IPTablesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init iptables: %w", err)
	}

	ip, err := resolveBinary(cfg.IPPath, "ip")
	if err != nil {
		logger.Warnf("ip binary not found, policy routing setup will be skipped: %v", err)
	}

	return &Impl{
		cfg:    cfg,
		ipt4:   ipt,
		tproxy: newTproxy(ipt, ip, cfg),
		tun:    newTun(ipt, ip, cfg),
		redir:  newRedirect(ipt, cfg),
	}, nil
}

func newIptables(proto goiptables.Protocol, path string) (*goiptables.IPTables, error) {
	if path == "" {
		return goiptables.NewWithProtocol(proto)
	}
	return goiptables.New(goiptables.IPFamily(proto), goiptables.Timeout(5), goiptables.Path(path))
}

func resolveBinary(path, name string) (string, error) {
	if path != "" {
		return exec.LookPath(path)
	}
	return exec.LookPath(name)
}

func (i *Impl) Setup(routingConfig config.RoutingConfig) error {
	logger.Debug("iptables firewall: starting setup")
	logger.Debugf("routing tcp=%s udp=%s", routingConfig.TCP, routingConfig.UDP)

	if err := i.tproxy.cleanup(); err != nil {
		logger.Warnf("pre-setup tproxy cleanup failed: %v", err)
	}
	if err := i.tun.cleanup(); err != nil {
		logger.Warnf("pre-setup tun cleanup failed: %v", err)
	}
	if err := i.redir.cleanup(); err != nil {
		logger.Warnf("pre-setup redirect cleanup failed: %v", err)
	}

	if routingConfig.TunDevice != "" {
		i.tun.setDevice(routingConfig.TunDevice)
	}

	if routingConfig.TCP == config.RoutingModeTProxy || routingConfig.UDP == config.RoutingModeTProxy {
		logger.Debug("iptables: setting up TPROXY")
		tcp := string(routingConfig.TCP)
		udp := string(routingConfig.UDP)
		if err := i.tproxy.setup(tcp, udp); err != nil {
			return fmt.Errorf("tproxy setup: %w", err)
		}
		logger.Info("TPROXY routing setup completed")
	}

	if routingConfig.TCP == config.RoutingModeTUN || routingConfig.UDP == config.RoutingModeTUN {
		logger.Debug("iptables: setting up TUN")
		if err := i.tun.setup(routingConfig); err != nil {
			return fmt.Errorf("tun setup: %w", err)
		}
		logger.Info("TUN routing setup completed")
	}

	if routingConfig.TCP == config.RoutingModeRedirect {
		logger.Debug("iptables: setting up REDIRECT")
		if err := i.redir.setup(); err != nil {
			return fmt.Errorf("redirect setup: %w", err)
		}
		logger.Info("REDIRECT routing setup completed")
	}

	logger.Debug("iptables firewall: setup completed")
	return nil
}

func (i *Impl) Cleanup() error {
	logger.Debug("iptables firewall: cleaning up")
	var firstErr error
	if err := i.tproxy.cleanup(); err != nil {
		logger.Warnf("tproxy cleanup failed: %v", err)
		firstErr = err
	}
	if err := i.tun.cleanup(); err != nil {
		logger.Warnf("tun cleanup failed: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if err := i.redir.cleanup(); err != nil {
		logger.Warnf("redirect cleanup failed: %v", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (i *Impl) IsTUNActive() bool {
	return i.tun.isActive()
}

func (i *Impl) UsesNftables() bool {
	return false
}

var _ firewall.Firewall = (*Impl)(nil)

func markHex(m uint32) string {
	return "0x" + strconv.FormatUint(uint64(m), 16)
}

func markMaskHex(m, mask uint32) string {
	return markHex(m) + "/" + "0x" + strconv.FormatUint(uint64(mask), 16)
}

func argEscape(s string) string {
	if strings.ContainsAny(s, " \t\"'") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
