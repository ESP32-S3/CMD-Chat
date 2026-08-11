package chat

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/auth"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

const MaxMessageBytes = 4096

type Packet struct { Type string `json:"type"`; From string `json:"from,omitempty"`; Name string `json:"name,omitempty"`; Text string `json:"text,omitempty"` }
type Host struct { ID string; Name string; Identity *identity.Identity; Fingerprint string; TLSConfig *tls.Config; Listener net.Listener; Clients map[net.Conn]struct{}; Mu sync.Mutex; WriteMu sync.Mutex }

func newTLSConfig() (*tls.Config,string,error){key,err:=rsa.GenerateKey(rand.Reader,2048);if err!=nil{return nil,"",err};serial,err:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),120));if err!=nil{return nil,"",err};tmpl:=x509.Certificate{SerialNumber:serial,NotBefore:time.Now().Add(-time.Minute),NotAfter:time.Now().Add(365*24*time.Hour),DNSNames:[]string{"cmd-chat"},KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}};der,err:=x509.CreateCertificate(rand.Reader,&tmpl,&tmpl,&key.PublicKey,key);if err!=nil{return nil,"",err};cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key};sum:=sha256.Sum256(der);return &tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS13},hex.EncodeToString(sum[:]),nil}
func NewHost(id,name string,ident *identity.Identity)(*Host,error){cfg,fp,err:=newTLSConfig();if err!=nil{return nil,err};return &Host{ID:id,Name:name,Identity:ident,Fingerprint:fp,TLSConfig:cfg,Clients:make(map[net.Conn]struct{})},nil}
func (h *Host) Listen(port int)error{ln,err:=tls.Listen("tcp",fmt.Sprintf(":%d",port),h.TLSConfig);if err!=nil{return err};h.Listener=ln;fmt.Printf("Hosting as %s on %s\nTLS fingerprint: %s\n",h.ID,ln.Addr(),h.Fingerprint);for{c,err:=ln.Accept();if err!=nil{return err};go h.handle(c)}}
func (h *Host) handle(c net.Conn){defer c.Close();dec:=json.NewDecoder(bufio.NewReader(c));var challenge auth.Challenge;if err:=dec.Decode(&challenge);err!=nil||challenge.Type!="auth_challenge"{return};hostResponse,err:=auth.Respond(h.Identity,&challenge);if err!=nil{return};if err=h.writeJSON(c,hostResponse);err!=nil{return};ownChallenge,err:=auth.NewChallenge();if err!=nil{return};if err=h.writeJSON(c,ownChallenge);err!=nil{return};var clientResponse auth.Response;if err=dec.Decode(&clientResponse);err!=nil{return};if err=auth.Verify(ownChallenge,&clientResponse);err!=nil{_=h.writePacket(c,Packet{Type:"error",Text:"authentication failed"});return};store:=auth.Load();if err=store.Trust(clientResponse.ID,clientResponse.PublicKey);err!=nil{_=h.writePacket(c,Packet{Type:"error",Text:"peer identity key changed; refusing connection"});return};h.Mu.Lock();h.Clients[c]=struct{}{};h.Mu.Unlock();defer func(){h.Mu.Lock();delete(h.Clients,c);h.Mu.Unlock()}();if err=h.writePacket(c,Packet{Type:"hello",From:h.ID,Name:h.Name});err!=nil{return};for{var p Packet;if err:=dec.Decode(&p);err!=nil{return};if p.Type!="msg"{continue};if len([]byte(p.Text))>MaxMessageBytes{_=h.writePacket(c,Packet{Type:"error",Text:"message exceeds 4096 bytes"});continue};fmt.Printf("\r[%s] %s\n> ",p.Name,p.Text);h.broadcast(Packet{Type:"msg",From:p.From,Name:p.Name,Text:p.Text},c)}}
func(h *Host)writeJSON(c net.Conn,v any)error{h.WriteMu.Lock();defer h.WriteMu.Unlock();return json.NewEncoder(c).Encode(v)}
func(h *Host)writePacket(c net.Conn,p Packet)error{return h.writeJSON(c,p)}
func(h *Host)broadcast(p Packet,except net.Conn){h.Mu.Lock();clients:=make([]net.Conn,0,len(h.Clients));for c:=range h.Clients{if c!=except{clients=append(clients,c)}};h.Mu.Unlock();for _,c:=range clients{if err:=h.writePacket(c,p);err!=nil{_=c.Close()}}}
func(h *Host)Broadcast(p Packet){if p.Type=="msg"&&len([]byte(p.Text))>MaxMessageBytes{return};h.broadcast(p,nil)}

// DialTimeout bounds a direct TCP connection attempt so a black-holed candidate
// cannot stall the connection strategy.
const DialTimeout = 8*time.Second

// HandleConn serves one already-established transport as the host side.
//
// The transport may be a plain TCP connection or a relayed byte pipe; the TLS
// session and the CMD-Chat handshake are identical either way, which is what
// keeps the relay out of the trust model.
func (h *Host) HandleConn(raw net.Conn){h.handle(tls.Server(raw,h.TLSConfig))}

func Client(address,expectedFingerprint,expectedHostID,id,name string,ident *identity.Identity)(net.Conn,*json.Decoder,error){raw,err:=net.DialTimeout("tcp",address,DialTimeout);if err!=nil{return nil,nil,err};return ClientConn(raw,expectedFingerprint,expectedHostID,id,name,ident)}

// ClientConn runs the client handshake over an already-established transport.
//
// Certificate pinning and the mutual Ed25519 challenge happen here, end to end,
// so a relayed connection is authenticated exactly as strictly as a direct one:
// a relay that tampered with the stream would fail the fingerprint check.
func ClientConn(raw net.Conn,expectedFingerprint,expectedHostID,id,name string,ident *identity.Identity)(net.Conn,*json.Decoder,error){c:=tls.Client(raw,&tls.Config{MinVersion:tls.VersionTLS13,InsecureSkipVerify:true});if err:=c.Handshake();err!=nil{_=raw.Close();return nil,nil,err};state:=c.ConnectionState();if len(state.PeerCertificates)==0{_=c.Close();return nil,nil,errors.New("host sent no certificate")};sum:=sha256.Sum256(state.PeerCertificates[0].Raw);actual:=hex.EncodeToString(sum[:]);expected:=strings.TrimSpace(expectedFingerprint);if expected!=""&&!strings.EqualFold(actual,expected){_=c.Close();return nil,nil,fmt.Errorf("host fingerprint mismatch")};if expected==""{fmt.Println("Warning: host certificate is not pinned; identity authentication is still required.")};reader:=bufio.NewReader(c);dec:=json.NewDecoder(reader);challenge,err:=auth.NewChallenge();if err!=nil{_=c.Close();return nil,nil,err};if err=json.NewEncoder(c).Encode(challenge);err!=nil{_=c.Close();return nil,nil,err};var hostResponse auth.Response;if err=dec.Decode(&hostResponse);err!=nil{_=c.Close();return nil,nil,err};if err=auth.Verify(challenge,&hostResponse);err!=nil{_=c.Close();return nil,nil,fmt.Errorf("host identity authentication failed: %w",err)};if expectedHostID!=""&&hostResponse.ID!=expectedHostID{_=c.Close();return nil,nil,fmt.Errorf("host identity mismatch: expected %s, got %s",expectedHostID,hostResponse.ID)};store:=auth.Load();if err=store.Trust(hostResponse.ID,hostResponse.PublicKey);err!=nil{_=c.Close();return nil,nil,fmt.Errorf("trusted host key changed: %w",err)};var hostChallenge auth.Challenge;if err=dec.Decode(&hostChallenge);err!=nil{_=c.Close();return nil,nil,err};response,err:=auth.Respond(ident,&hostChallenge);if err!=nil{_=c.Close();return nil,nil,err};if err=json.NewEncoder(c).Encode(response);err!=nil{_=c.Close();return nil,nil,err};return c,dec,nil}
func Send(c net.Conn,p Packet)error{if p.Type=="msg"&&len([]byte(p.Text))>MaxMessageBytes{return fmt.Errorf("message exceeds %d bytes",MaxMessageBytes)};return json.NewEncoder(c).Encode(p)}
func ReadLoop(dec *json.Decoder,onMessage func(Packet)){for{var p Packet;if err:=dec.Decode(&p);err!=nil{if err!=io.EOF{fmt.Printf("\nConnection closed: %v\n",err)};return};onMessage(p)}}

// PublicKeyFingerprint returns the SHA-256 fingerprint of a base64 Ed25519 key.
func PublicKeyFingerprint(publicKey string) string { b,err:=base64.StdEncoding.DecodeString(publicKey);if err!=nil{return ""};sum:=sha256.Sum256(b);return hex.EncodeToString(sum[:]) }
