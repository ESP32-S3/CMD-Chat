package discovery

import("encoding/json";"fmt";"net";"strconv";"time")
const udpPort=38555
const magic="CMDCHAT/1"
type Announcement struct{ID string `json:"id"`;Name string `json:"name"`;Port int `json:"port"`;Fingerprint string `json:"fingerprint"`;Endpoint string `json:"endpoint,omitempty"`}
type packet struct{Magic string `json:"magic"`;Type string `json:"type"`;Announcement *Announcement `json:"announcement,omitempty"`;ID string `json:"id,omitempty"`}
func Serve(a Announcement)error{c,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4zero,Port:udpPort});if err!=nil{return err};defer c.Close();for{buf:=make([]byte,4096);n,addr,err:=c.ReadFromUDP(buf);if err!=nil{continue};var p packet;if json.Unmarshal(buf[:n],&p)!=nil||p.Magic!=magic||p.Type!="discover"||p.ID!=a.ID{continue};r:=a;r.Endpoint=net.JoinHostPort(addr.IP.String(),strconv.Itoa(a.Port));out,_:=json.Marshal(packet{Magic:magic,Type:"found",Announcement:&r});_,_=c.WriteToUDP(out,addr)}}
func Find(id string,timeout time.Duration)([]Announcement,error){c,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4zero,Port:0});if err!=nil{return nil,err};defer c.Close();target:=&net.UDPAddr{IP:net.IPv4bcast,Port:udpPort};q,_:=json.Marshal(packet{Magic:magic,Type:"discover",ID:id});if _,err=c.WriteToUDP(q,target);err!=nil{return nil,fmt.Errorf("LAN discovery broadcast failed: %w",err)};_=c.SetReadDeadline(time.Now().Add(timeout));var out []Announcement;seen:=map[string]bool{};for{buf:=make([]byte,4096);n,_,err:=c.ReadFromUDP(buf);if err!=nil{break};var p packet;if json.Unmarshal(buf[:n],&p)!=nil||p.Magic!=magic||p.Type!="found"||p.Announcement==nil{continue};if seen[p.Announcement.ID]{continue};seen[p.Announcement.ID]=true;out=append(out,*p.Announcement)};return out,nil}
func Address(ip string,port int)string{return net.JoinHostPort(ip,strconv.Itoa(port))}
