package phonebook

import (
	"net"
	"sort"

	"github.com/ESP32-S3/CMD-Chat/internal/network"
)

// Candidate priorities, mirroring the intent of network.Order(): try the
// cheapest, most likely path first.
const (
	PriorityHostLAN        = 100
	PriorityHostRoutable   = 150
	PriorityServerReflexiv = 200
)

// STUNFunc discovers this host's public UDP mapping. It is a parameter so that
// tests never touch the network; production passes network.DiscoverPublicEndpoint.
type STUNFunc func() (*network.Endpoint, error)

// GatherCandidates builds the candidate list a host publishes.
//
// It always includes the host's own routable interface addresses paired with
// the TCP chat port, and adds the STUN-discovered public UDP mapping when one
// is available. A STUN failure is not fatal: LAN and port-forwarded peers are
// still reachable without it.
func GatherCandidates(tcpPort int, stun STUNFunc) ([]Candidate, error) {
	candidates := make([]Candidate, 0, 4)

	for _, ip := range localAddresses() {
		priority := PriorityHostLAN
		if !ip.IsPrivate() {
			priority = PriorityHostRoutable
		}
		candidates = append(candidates, Candidate{
			Kind:      KindHost,
			Transport: "tcp",
			Address:   ip.String(),
			Port:      intPtr(tcpPort),
			Priority:  priority,
		})
	}

	var stunErr error
	if stun != nil {
		endpoint, err := stun()
		switch {
		case err != nil:
			stunErr = err
		case endpoint != nil && endpoint.Address != "":
			candidates = append(candidates, Candidate{
				Kind:      KindServerReflexive,
				Transport: "udp",
				Address:   endpoint.Address,
				Port:      intPtr(endpoint.Port),
				Priority:  PriorityServerReflexiv,
			})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Priority > candidates[j].Priority })

	// The directory caps the list; publish the best few rather than being rejected.
	if len(candidates) > 7 {
		candidates = candidates[:7]
	}
	return candidates, stunErr
}

// localAddresses returns this machine's usable unicast IPs, skipping loopback
// and link-local addresses that no remote peer could ever dial.
func localAddresses() []net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			out = append(out, ip)
		}
	}
	return out
}

// TCPEndpoints returns the peer's TCP candidates as dialable host:port strings,
// best first. These are what chat.Client accepts.
func (p *Peer) TCPEndpoints() []string {
	var out []string
	for _, c := range p.Candidates {
		if c.Transport != "tcp" || c.Port == nil {
			continue
		}
		out = append(out, net.JoinHostPort(c.Address, itoa(*c.Port)))
	}
	return out
}

// UDPEndpoints returns the peer's UDP candidates, best first. These are what
// network.TryHolePunch probes.
func (p *Peer) UDPEndpoints() []network.Endpoint {
	var out []network.Endpoint
	for _, c := range p.Candidates {
		if c.Transport != "udp" || c.Port == nil {
			continue
		}
		out = append(out, network.Endpoint{Address: c.Address, Port: *c.Port})
	}
	return out
}

// ObservedIPs returns addresses the directory saw the peer connect from but for
// which no usable port is known. They are useful to pair with a known chat port
// when the peer has forwarded one, and useless on their own.
func (p *Peer) ObservedIPs() []string {
	var out []string
	for _, c := range p.Candidates {
		if c.Kind == KindServerReflexiveHTTP {
			out = append(out, c.Address)
		}
	}
	return out
}

func intPtr(v int) *int { return &v }

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	return string(buf)
}
