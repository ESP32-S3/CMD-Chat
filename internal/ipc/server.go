package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
)

// Command is a message received from local frontends such as the ChromeOS UI.
type Command struct {
	Cmd     string `json:"cmd"`
	Message string `json:"message,omitempty"`
	ID      string `json:"id,omitempty"`
}

// Event is sent back to local frontends.
type Event struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

// Server exposes a localhost-only bridge. It is intentionally not exposed to
// the network; P2P networking remains handled by the core.
type Server struct {
	Address string
	OnCommand func(Command)
}

func (s Server) Listen() error {
	addr := s.Address
	if addr == "" {
		addr = "127.0.0.1:5050"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go s.handle(conn)
	}
}

func (s Server) handle(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var command Command
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			continue
		}

		if s.OnCommand != nil {
			s.OnCommand(command)
		}

		response := Event{Type: "received", Message: fmt.Sprintf("command:%s", command.Cmd)}
		data, _ := json.Marshal(response)
		_, _ = conn.Write(append(data, '\n'))
	}
}
