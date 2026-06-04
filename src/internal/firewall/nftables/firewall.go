//go:build linux && !android

package nftables

import (
	"fmt"

	"fusiontunx/pkg/config"
	"fusiontunx/pkg/logger"

	"github.com/sagernet/nftables"
)

type Nftables struct {
	tun      *tun
	tproxy   *tproxy
	redirect *redirect
}

func New() *Nftables {
	return &Nftables{
		tun:      newTun(),
		tproxy:   newTproxy(),
		redirect: newRedirect(),
	}
}

func (n *Nftables) Setup(routingConfig config.RoutingConfig) error {
	logger.Debug("Starting nftables firewall Setup")
	logger.Debugf("Routing config - TCP: %s, UDP: %s", routingConfig.TCP, routingConfig.UDP)

	logger.Debug("Step 1: Cleanup existing rules")
	n.tun.Cleanup(nil)
	n.tproxy.Cleanup(nil)
	n.redirect.Cleanup(nil)

	if routingConfig.TCP == config.RoutingModeTProxy || routingConfig.UDP == config.RoutingModeTProxy {
		logger.Debug("Step 2: Setting up TPROXY")

		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("failed to create nftables connection: %w", err)
		}

		tcpMode := string(routingConfig.TCP)
		udpMode := string(routingConfig.UDP)

		if err := n.tproxy.Setup(conn, tcpMode, udpMode); err != nil {
			logger.Errorf("TPROXY setup failed: %v", err)
			return fmt.Errorf("failed to setup TPROXY: %w", err)
		}

		logger.Debug("Step 3: Flushing TPROXY nftables")
		if err := conn.Flush(); err != nil {
			logger.Errorf("Failed to flush TPROXY nftables: %v", err)
			return fmt.Errorf("failed to flush nftables: %w", err)
		}

		logger.Debug("Step 4: Setting up policy routing")
		n.tproxy.addPolicyRouting()

		logger.Info("TPROXY routing setup completed")
	}

	if routingConfig.TCP == config.RoutingModeTUN || routingConfig.UDP == config.RoutingModeTUN {
		logger.Debug("Setting up TUN")

		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("failed to create nftables connection: %w", err)
		}

		if err := n.tun.Setup(conn, routingConfig); err != nil {
			logger.Errorf("TUN setup failed: %v", err)
			return fmt.Errorf("failed to setup TUN: %w", err)
		}

		if err := conn.Flush(); err != nil {
			logger.Errorf("Failed to flush TUN nftables: %v", err)
			return fmt.Errorf("failed to flush nftables: %w", err)
		}

		logger.Info("TUN routing setup completed")
	}

	if routingConfig.TCP == config.RoutingModeRedirect {
		logger.Debug("Setting up REDIRECT")

		conn, err := nftables.New()
		if err != nil {
			return fmt.Errorf("failed to create nftables connection: %w", err)
		}

		if err := n.redirect.Setup(conn); err != nil {
			logger.Errorf("REDIRECT setup failed: %v", err)
			return fmt.Errorf("failed to setup REDIRECT: %w", err)
		}

		if err := conn.Flush(); err != nil {
			logger.Errorf("Failed to flush REDIRECT nftables: %v", err)
			return fmt.Errorf("failed to flush nftables: %w", err)
		}

		logger.Info("REDIRECT routing setup completed")
	}

	logger.Debug("nftables firewall Setup completed successfully")
	return nil
}

func (n *Nftables) Cleanup() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to create nftables connection: %w", err)
	}

	n.tun.Cleanup(conn)
	n.tproxy.Cleanup(conn)
	n.redirect.Cleanup(conn)

	return conn.Flush()
}

func (n *Nftables) IsTUNActive() bool {
	return n.tun.IsActive()
}

func (n *Nftables) UsesNftables() bool {
	return true
}
