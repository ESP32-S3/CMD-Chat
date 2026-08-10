package network

import "net"

// Relay defines the optional fallback transport used when direct peer
// connectivity is impossible because of NAT or firewall restrictions.
//
// The normal CMD-Chat flow remains host-to-client. A relay only exists as an
// escape hatch when direct connections cannot be established.
type Relay interface {
	Dial(peer string) (net.Conn, error)
	Accept() (net.Conn, error)
}

// RelayUnavailable is returned when no relay has been configured.
type RelayUnavailable struct{}

func (RelayUnavailable) Error() string {
	return "relay fallback is not configured"
}
