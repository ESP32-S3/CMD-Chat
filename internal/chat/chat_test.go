package chat

import (
    "net"
    "testing"
)

func TestSendRejectsOversizedMessage(t *testing.T) {
    a, b := net.Pipe()
    defer a.Close()
    defer b.Close()

    err := Send(a, Packet{Type: "msg", Text: string(make([]byte, MaxMessageBytes+1))})
    if err == nil {
        t.Fatal("expected oversized message to be rejected")
    }
}

func TestSendAcceptsNormalMessage(t *testing.T) {
    a, b := net.Pipe()
    defer a.Close()
    defer b.Close()

    done := make(chan error, 1)
    go func() {
        done <- Send(a, Packet{Type: "msg", Text: "hello"})
    }()

    buf := make([]byte, 1024)
    if _, err := b.Read(buf); err != nil {
        t.Fatal(err)
    }
    if err := <-done; err != nil {
        t.Fatal(err)
    }
}
