package chat

import (
    "bufio"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
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
)

const MaxMessageBytes = 4096

type Packet struct {
    Type string `json:"type"`
    From string `json:"from,omitempty"`
    Name string `json:"name,omitempty"`
    Text string `json:"text,omitempty"`
}

type Host struct {
    ID          string
    Name        string
    Fingerprint string
    TLSConfig   *tls.Config
    Listener    net.Listener
    Clients     map[net.Conn]struct{}
    Mu          sync.Mutex
    WriteMu     sync.Mutex
}

func newTLSConfig() (*tls.Config, string, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, "", err
    }
    serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
    if err != nil {
        return nil, "", err
    }
    tmpl := x509.Certificate{
        SerialNumber: serial,
        NotBefore:    time.Now().Add(-time.Minute),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        DNSNames:     []string{"cmd-chat"},
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
    if err != nil {
        return nil, "", err
    }
    cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
    sum := sha256.Sum256(der)
    return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, hex.EncodeToString(sum[:]), nil
}

func NewHost(id, name string) (*Host, error) {
    cfg, fp, err := newTLSConfig()
    if err != nil {
        return nil, err
    }
    return &Host{ID: id, Name: name, Fingerprint: fp, TLSConfig: cfg, Clients: make(map[net.Conn]struct{})}, nil
}

func (h *Host) Listen(port int) error {
    ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), h.TLSConfig)
    if err != nil {
        return err
    }
    h.Listener = ln
    fmt.Printf("Hosting as %s on %s\nTLS fingerprint: %s\n", h.ID, ln.Addr(), h.Fingerprint)
    for {
        c, err := ln.Accept()
        if err != nil {
            return err
        }
        go h.handle(c)
    }
}

func (h *Host) handle(c net.Conn) {
    defer c.Close()
    h.Mu.Lock()
    h.Clients[c] = struct{}{}
    h.Mu.Unlock()
    defer func() {
        h.Mu.Lock()
        delete(h.Clients, c)
        h.Mu.Unlock()
    }()

    if err := h.writePacket(c, Packet{Type: "hello", From: h.ID, Name: h.Name}); err != nil {
        return
    }

    dec := json.NewDecoder(bufio.NewReader(c))
    for {
        var p Packet
        if err := dec.Decode(&p); err != nil {
            return
        }
        if p.Type != "msg" {
            continue
        }
        if len([]byte(p.Text)) > MaxMessageBytes {
            _ = h.writePacket(c, Packet{Type: "error", Text: "message exceeds 4096 bytes"})
            continue
        }
        fmt.Printf("\r[%s] %s\n> ", p.Name, p.Text)
        h.broadcast(Packet{Type: "msg", From: p.From, Name: p.Name, Text: p.Text}, c)
    }
}

func (h *Host) writePacket(c net.Conn, p Packet) error {
    h.WriteMu.Lock()
    defer h.WriteMu.Unlock()
    return json.NewEncoder(c).Encode(p)
}

func (h *Host) broadcast(p Packet, except net.Conn) {
    h.Mu.Lock()
    clients := make([]net.Conn, 0, len(h.Clients))
    for c := range h.Clients {
        if c != except {
            clients = append(clients, c)
        }
    }
    h.Mu.Unlock()

    for _, c := range clients {
        if err := h.writePacket(c, p); err != nil {
            _ = c.Close()
        }
    }
}

func (h *Host) Broadcast(p Packet) {
    if p.Type == "msg" && len([]byte(p.Text)) > MaxMessageBytes {
        return
    }
    h.broadcast(p, nil)
}

func Client(address, expectedFingerprint, id, name string) (net.Conn, *json.Decoder, error) {
    c, err := tls.Dial("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
    if err != nil {
        return nil, nil, err
    }
    state := c.ConnectionState()
    if len(state.PeerCertificates) == 0 {
        _ = c.Close()
        return nil, nil, errors.New("host sent no certificate")
    }
    sum := sha256.Sum256(state.PeerCertificates[0].Raw)
    actual := hex.EncodeToString(sum[:])
    expected := strings.TrimSpace(expectedFingerprint)
    if expected == "" {
        fmt.Println("Warning: host certificate is not pinned; verify the fingerprint out of band.")
    } else if !strings.EqualFold(actual, expected) {
        _ = c.Close()
        return nil, nil, fmt.Errorf("host fingerprint mismatch")
    }
    if _, err := x509.ParseCertificate(state.PeerCertificates[0].Raw); err != nil {
        _ = c.Close()
        return nil, nil, err
    }
    if err := json.NewEncoder(c).Encode(Packet{Type: "hello", From: id, Name: name}); err != nil {
        _ = c.Close()
        return nil, nil, err
    }
    return c, json.NewDecoder(bufio.NewReader(c)), nil
}

func Send(c net.Conn, p Packet) error {
    if p.Type == "msg" && len([]byte(p.Text)) > MaxMessageBytes {
        return fmt.Errorf("message exceeds %d bytes", MaxMessageBytes)
    }
    return json.NewEncoder(c).Encode(p)
}

func ReadLoop(dec *json.Decoder, onMessage func(Packet)) {
    for {
        var p Packet
        if err := dec.Decode(&p); err != nil {
            if err != io.EOF {
                fmt.Printf("\nConnection closed: %v\n", err)
            }
            return
        }
        onMessage(p)
    }
}
