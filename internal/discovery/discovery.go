package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"
)

const udpPort = 38555
const magic = "CMDCHAT/1"

type Announcement struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Endpoint    string `json:"endpoint,omitempty"`
}
type packet struct {
	Magic        string        `json:"magic"`
	Type         string        `json:"type"`
	Announcement *Announcement `json:"announcement,omitempty"`
	ID           string        `json:"id,omitempty"`
}

func hostIPFor(peer *net.UDPAddr) string {
	c, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}
func Serve(a Announcement) error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: udpPort})
	if err != nil {
		return err
	}
	defer c.Close()
	for {
		buf := make([]byte, 4096)
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		var p packet
		if json.Unmarshal(buf[:n], &p) != nil || p.Magic != magic || p.Type != "discover" || p.ID != a.ID {
			continue
		}
		r := a
		if ip := hostIPFor(addr); ip != "" {
			r.Endpoint = net.JoinHostPort(ip, strconv.Itoa(a.Port))
		}
		out, _ := json.Marshal(packet{Magic: magic, Type: "found", Announcement: &r})
		_, _ = c.WriteToUDP(out, addr)
	}
}
func Find(id string, timeout time.Duration) ([]Announcement, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	target := &net.UDPAddr{IP: net.IPv4bcast, Port: udpPort}
	q, _ := json.Marshal(packet{Magic: magic, Type: "discover", ID: id})
	if _, err = c.WriteToUDP(q, target); err != nil {
		return nil, fmt.Errorf("LAN discovery broadcast failed: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	var out []Announcement
	seen := map[string]bool{}
	for {
		buf := make([]byte, 4096)
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var p packet
		if json.Unmarshal(buf[:n], &p) != nil || p.Magic != magic || p.Type != "found" || p.Announcement == nil {
			continue
		}
		if p.Announcement.ID != id {
			continue
		}
		if seen[p.Announcement.ID] {
			continue
		}
		seen[p.Announcement.ID] = true
		out = append(out, *p.Announcement)
	}
	return out, nil
}
func Address(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

// Find drops any announcement whose ID is not the one that was asked for.
//
// A UDP broadcast reply is unauthenticated and anyone on the LAN can send one.
// Without this filter, a rogue machine could answer a search for a friend's ID
// with its OWN ID, and the caller would go on to pin and authenticate that
// identity instead. On first contact there is nothing in the trust store to
// catch it. The ID the user typed is the only thing here that is not
// attacker-controlled, so it is what everything else is checked against.
