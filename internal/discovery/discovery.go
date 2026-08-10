package discovery

import (
    "encoding/json"
    "fmt"
    "net"
    "strconv"
    "strings"
    "time"
)

const udpPort = 38555
const magic = "CMDCHAT/1"

type Announcement struct { ID string `json:"id"`; Name string `json:"name"`; Port int `json:"port"`; Fingerprint string `json:"fingerprint"` }
type packet struct { Magic string `json:"magic"`; Type string `json:"type"`; Announcement *Announcement `json:"announcement,omitempty"`; ID string `json:"id,omitempty"` }

// Serve responds to LAN discovery requests. It never leaves the local network.
func Serve(a Announcement) error {
    c, err := net.ListenUDP("udp4", &net.UDPAddr{IP:net.IPv4zero,Port:udpPort}); if err!=nil{return err}; defer c.Close()
    for { buf:=make([]byte,4096); n,addr,err:=c.ReadFromUDP(buf);if err!=nil{continue};var p packet;if json.Unmarshal(buf[:n],&p)!=nil||p.Magic!=magic||p.Type!="discover"||p.ID!=a.ID{continue};out,_:=json.Marshal(packet{Magic:magic,Type:"found",Announcement:&a});_,_=c.WriteToUDP(out,addr) }
}

func Find(id string, timeout time.Duration) ([]Announcement,error) {
    c,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4zero,Port:0});if err!=nil{return nil,err};defer c.Close();if err=c.SetWriteDeadline(time.Now().Add(timeout));err!=nil{return nil,err}
    target:=&net.UDPAddr{IP:net.IPv4bcast,Port:udpPort};q,_:=json.Marshal(packet{Magic:magic,Type:"discover",ID:id});if _,err=c.WriteToUDP(q,target);err!=nil{return nil,fmt.Errorf("LAN discovery broadcast failed: %w",err)}
    deadline:=time.Now().Add(timeout);_ = c.SetReadDeadline(deadline);seen:=map[string]bool{};var out []Announcement
    for {buf:=make([]byte,4096);n,addr,err:=c.ReadFromUDP(buf);if err!=nil{break};var p packet;if json.Unmarshal(buf[:n],&p)!=nil||p.Magic!=magic||p.Type!="found"||p.Announcement==nil{continue};if seen[p.Announcement.ID]{continue};seen[p.Announcement.ID]=true; a:=*p.Announcement; if !strings.Contains(a.Name,"@") {a.Name=a.Name+" @ "+addr.IP.String()};out=append(out,a)}
    return out,nil
}

func Address(ip string, port int) string{return net.JoinHostPort(ip,strconv.Itoa(port))}
