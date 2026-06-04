//go:build android || darwin

package iptables

import (
	"os/exec"

	goiptables "github.com/coreos/go-iptables/iptables"
)

// execLookPath is an indirection used by tests; in production it is
// just exec.LookPath.
func execLookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// newIptablesWithMock is a test helper that builds an Impl wired to
// the supplied iptables/ip binaries. It is the only place that
// references the implementation detail of the go-iptables package
// using non-default options from this codebase.
func newIptablesWithMock(iptablesPath, ipPath string, cfg Config) (*Impl, error) {
	ipt, err := goiptables.New(
		goiptables.IPFamily(goiptables.ProtocolIPv4),
		goiptables.Timeout(1),
		goiptables.Path(iptablesPath),
	)
	if err != nil {
		return nil, err
	}
	ip, _ := execLookPath(ipPath)

	impl := &Impl{
		cfg:    cfg,
		ipt4:   ipt,
		tproxy: newTproxy(ipt, ip, cfg),
		tun:    newTun(ipt, ip, cfg),
		redir:  newRedirect(ipt, cfg),
	}
	return impl, nil
}
