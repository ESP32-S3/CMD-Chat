package network

import "net"

// LocalEndpoint describes a reachable address discovered by the client.
type LocalEndpoint struct {
	IP   net.IP
	Port int
}

func (e LocalEndpoint) String() string {
	return net.JoinHostPort(e.IP.String(), itoa(e.Port))
}

// Small internal integer formatter to avoid extra dependencies in networking code.
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
