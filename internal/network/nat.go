package network

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type Endpoint struct {
	Address string
	Port    int
}

// DiscoverPublicEndpoint performs a STUN Binding request. It discovers the
// public UDP mapping but does not require or create a permanent server.
func DiscoverPublicEndpoint() (*Endpoint, error) {
	return discoverSTUN("stun.l.google.com:19302")
}

func discoverSTUN(server string) (*Endpoint, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var tx [12]byte
	if _, err := rand.Read(tx[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], 0x0001)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], 0x2112A442)
	copy(msg[8:20], tx[:])
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	if _, err = conn.WriteToUDP(msg, addr); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if n < 20 {
		return nil, errors.New("short STUN response")
	}
	if binary.BigEndian.Uint32(buf[4:8]) != 0x2112A442 || string(buf[8:20]) != string(tx[:]) {
		return nil, errors.New("invalid STUN transaction")
	}
	for off := 20; off+4 <= n; {
		typ := binary.BigEndian.Uint16(buf[off : off+2])
		ln := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		off += 4
		if off+ln > n {
			return nil, errors.New("invalid STUN attribute length")
		}
		v := buf[off : off+ln]
		if typ == 0x0020 && ln >= 8 {
			family := v[1]
			if family == 0x01 {
				port := int(binary.BigEndian.Uint16(v[2:4]) ^ 0x2112)
				ip := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					ip[i] = v[4+i] ^ []byte{0x21, 0x12, 0xA4, 0x42}[i]
				}
				return &Endpoint{Address: ip.String(), Port: port}, nil
			}
		}
		if typ == 0x0001 && ln >= 8 {
			family := v[1]
			if family == 0x01 {
				return &Endpoint{Address: net.IPv4(v[4], v[5], v[6], v[7]).String(), Port: int(binary.BigEndian.Uint16(v[2:4]))}, nil
			}
		}
		off += (ln + 3) &^ 3
	}
	return nil, fmt.Errorf("STUN response has no mapped address")
}

// TryHolePunch sends UDP probes to a peer candidate. A rendezvous service must
// exchange the candidates; this function deliberately does not provide one.
func TryHolePunch(peer Endpoint) error {
	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peer.Address, fmt.Sprint(peer.Port)))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	probe := []byte("CMD-CHAT-P2P-PROBE-1")
	for i := 0; i < 5; i++ {
		if _, err := conn.WriteToUDP(probe, remote); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buf := make([]byte, 128)
		n, from, err := conn.ReadFromUDP(buf)
		if err == nil && n > 0 && from.IP.Equal(remote.IP) && from.Port == remote.Port {
			return nil
		}
	}
	return errors.New("UDP hole punch did not establish a response")
}
