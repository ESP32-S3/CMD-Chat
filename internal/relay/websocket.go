package relay

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 client, client-side only.
//
// CMD-Chat has no third-party dependencies (it even hand-rolls its STUN client
// in internal/network), and pulling in a full WebSocket library to move opaque
// bytes would be disproportionate. Only what the relay actually needs is
// implemented: a masked binary data channel, JSON text frames for control, and
// ping/pong plus close handling.

// The RFC 6455 handshake magic string. TestAcceptComputationMatchesRFC6455
// pins it against the specification's worked example, because a wrong value
// fails every handshake with a confusing "accept check failed".
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxFrameBytes mirrors the relay's own limit; anything larger is a protocol
// error rather than something to buffer.
const maxFrameBytes = 64 * 1024

// wsConn is a WebSocket connection presented as a net.Conn.
//
// Read returns the payload of binary frames only, so a TLS session can be run
// straight over it. Text frames are relay control messages and are diverted to
// a separate channel instead of being mixed into the byte stream.
type wsConn struct {
	raw net.Conn
	br  *bufio.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex

	pending []byte      // undelivered bytes of the current binary frame
	control chan []byte // buffered relay control messages

	closeOnce sync.Once
	closeErr  error
}

// dialWebSocket performs the HTTP upgrade and returns a framed connection.
func dialWebSocket(target string, headers http.Header, timeout time.Duration) (*wsConn, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("relay: bad url: %w", err)
	}

	var host string
	secure := false
	switch parsed.Scheme {
	case "wss", "https":
		secure = true
		host = withDefaultPort(parsed.Host, "443")
	case "ws", "http":
		host = withDefaultPort(parsed.Host, "80")
	default:
		return nil, fmt.Errorf("relay: unsupported scheme %q", parsed.Scheme)
	}

	dialer := &net.Dialer{Timeout: timeout}
	var raw net.Conn
	if secure {
		raw, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12})
	} else {
		raw, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("relay: dial: %w", err)
	}

	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		raw.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", parsed.Host)
	req.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	for name, values := range headers {
		for _, v := range values {
			// Header values are ours (identity, signature, timestamp) but a
			// stray newline would let one forge extra headers.
			if strings.ContainsAny(v, "\r\n") {
				raw.Close()
				return nil, errors.New("relay: illegal header value")
			}
			fmt.Fprintf(&req, "%s: %s\r\n", name, v)
		}
	}
	req.WriteString("\r\n")

	if _, err := io.WriteString(raw, req.String()); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay: handshake write: %w", err)
	}

	br := bufio.NewReaderSize(raw, 4096)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay: handshake read: %w", err)
	}

	if res.StatusCode != http.StatusSwitchingProtocols {
		// The relay reports refusals (no host waiting, bad signature, session
		// busy) as a normal JSON response, so surface that rather than a bare
		// status code.
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		raw.Close()
		return nil, &HTTPError{Status: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	expected := base64.StdEncoding.EncodeToString(sum[:])
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != expected {
		raw.Close()
		return nil, fmt.Errorf("relay: WebSocket accept check failed (got %q, want %q; headers=%v)", got, expected, res.Header)
	}

	if err := raw.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}

	return &wsConn{raw: raw, br: br, control: make(chan []byte, 8)}, nil
}

func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

// HTTPError is a non-101 response to the upgrade request.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("relay: HTTP %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("relay: HTTP %d", e.Status)
}

// readFrame reads one complete (possibly fragmented) message.
//
// Ping and close are handled here so callers only ever see data frames.
func (c *wsConn) readFrame() (opcode byte, payload []byte, err error) {
	var assembled []byte
	var firstOpcode byte
	fragmented := false

	for {
		var header [2]byte
		if _, err := io.ReadFull(c.br, header[:]); err != nil {
			return 0, nil, err
		}

		fin := header[0]&0x80 != 0
		op := header[0] & 0x0F
		masked := header[1]&0x80 != 0
		length := int64(header[1] & 0x7F)

		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, nil, err
			}
			length = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, nil, err
			}
			length = int64(binary.BigEndian.Uint64(ext[:]))
		}

		if length < 0 || length > maxFrameBytes {
			return 0, nil, fmt.Errorf("relay: frame of %d bytes exceeds limit", length)
		}

		// A conforming server never masks; refuse rather than guess.
		if masked {
			return 0, nil, errors.New("relay: server sent a masked frame")
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(c.br, data); err != nil {
			return 0, nil, err
		}

		switch op {
		case opPing:
			if err := c.writeFrame(opPong, data); err != nil {
				return 0, nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			code, reason := parseClose(data)
			_ = c.writeFrame(opClose, data)
			c.raw.Close()
			return 0, nil, &CloseError{Code: code, Reason: reason}
		}

		if op == opContinuation {
			if !fragmented {
				return 0, nil, errors.New("relay: continuation frame without a start")
			}
		} else {
			if fragmented {
				return 0, nil, errors.New("relay: interleaved data frames")
			}
			firstOpcode = op
			fragmented = true
		}

		assembled = append(assembled, data...)
		if len(assembled) > maxFrameBytes {
			return 0, nil, errors.New("relay: fragmented message exceeds limit")
		}
		if fin {
			return firstOpcode, assembled, nil
		}
	}
}

func parseClose(data []byte) (int, string) {
	if len(data) < 2 {
		return 1005, ""
	}
	return int(binary.BigEndian.Uint16(data[:2])), string(data[2:])
}

// CloseError is returned once the peer or the relay closes the session.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("relay closed the session (%d): %s", e.Code, e.Reason)
	}
	return fmt.Sprintf("relay closed the session (%d)", e.Code)
}

// writeFrame emits one masked client frame. RFC 6455 requires clients to mask.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var header []byte
	header = append(header, 0x80|opcode)

	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(0x80|n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}

	if _, err := c.raw.Write(append(header, masked...)); err != nil {
		return err
	}
	return nil
}

// nextControl returns the next relay control message, waiting up to timeout.
func (c *wsConn) nextControl(timeout time.Duration) ([]byte, error) {
	select {
	case msg := <-c.control:
		return msg, nil
	default:
	}

	deadline := time.Now().Add(timeout)
	if err := c.raw.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer c.raw.SetReadDeadline(time.Time{})

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		op, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		if op == opText {
			return payload, nil
		}
		// A data frame arriving before pairing completes is out of order;
		// keep it so the stream is not corrupted once TLS starts.
		c.pending = append(c.pending, payload...)
	}
}

// Read implements net.Conn over the binary channel.
func (c *wsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.pending) == 0 {
		op, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if op == opText {
			select {
			case c.control <- payload:
			default: // control backlog is not worth stalling the chat for
			}
			continue
		}
		c.pending = payload
	}

	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Write sends p as a single binary frame, splitting anything oversized.
func (c *wsConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		end := written + maxFrameBytes
		if end > len(p) {
			end = len(p)
		}
		if err := c.writeFrame(opBinary, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (c *wsConn) Close() error {
	c.closeOnce.Do(func() {
		var payload [2]byte
		binary.BigEndian.PutUint16(payload[:], 1000)
		_ = c.writeFrame(opClose, payload[:])
		c.closeErr = c.raw.Close()
	})
	return c.closeErr
}

func (c *wsConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
