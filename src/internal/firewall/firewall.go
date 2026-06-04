package firewall

import "fusiontunx/pkg/config"

type Firewall interface {
	Setup(routing config.RoutingConfig) error
	Cleanup() error
	IsTUNActive() bool
	UsesNftables() bool
}
