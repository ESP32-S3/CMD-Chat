package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

//go:embed ui/index.html
var uiFiles embed.FS

type guiSession struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	mode      string
	id        string
	logs      []string
	connected bool
}

func (s *guiSession) addLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if found := extractID(line); found != "" {
		s.id = found
	}
	s.logs = append(s.logs, line)
	if len(s.logs) > 500 {
		s.logs = s.logs[len(s.logs)-500:]
	}
	if strings.Contains(line, "Authenticated host") {
		s.connected = true
	}
}

func (s *guiSession) stop() {
	s.mu.Lock()
	cmd := s.cmd
	stdin := s.stdin
	s.cmd = nil
	s.stdin = nil
	s.mu.Unlock()
	if stdin != nil {
		_ = stdin.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func runGUI(id *identity.Identity) {
	var session guiSession
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(uiFiles)))

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		session.mu.Lock()
		logs := append([]string(nil), session.logs...)
		mode, sid, running, connected := session.mode, session.id, session.cmd != nil, session.connected
		session.mu.Unlock()
		writeJSON(w, map[string]any{"id": id.ID, "mode": mode, "sessionId": sid, "running": running, "connected": connected, "logs": logs})
	})

	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode string `json:"mode"`
			ID   string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "Invalid request."})
			return
		}
		if req.Mode != "host" && req.Mode != "join" {
			writeJSON(w, map[string]any{"ok": false, "error": "Unknown chat mode."})
			return
		}
		if req.Mode == "join" && strings.TrimSpace(req.ID) == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "Enter your friend's ID."})
			return
		}
		session.stop()
		session.mu.Lock()
		session.mode, session.id, session.logs, session.connected = req.Mode, "", nil, false
		session.mu.Unlock()
		args := []string{req.Mode}
		if req.Mode == "join" {
			args = append(args, strings.TrimSpace(req.ID))
		}
		if err := startGUISession(&session, args); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "Message is empty."})
			return
		}
		session.mu.Lock()
		stdin, running := session.stdin, session.cmd != nil
		session.mu.Unlock()
		if !running || stdin == nil {
			writeJSON(w, map[string]any{"ok": false, "error": "No active chat."})
			return
		}
		if _, err := io.WriteString(stdin, strings.TrimSpace(req.Text)+"\n"); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "Could not send the message."})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		session.stop()
		session.mu.Lock()
		session.mode, session.id, session.logs, session.connected = "", "", nil, false
		session.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not start the CMD-Chat interface:", err)
		return
	}
	url := "http://" + listener.Addr().String() + "/"
	fmt.Println("CMD-Chat interface:", url)
	if err := openBrowser(url); err != nil {
		fmt.Println("Open this address in your browser:", url)
	}
	server := &http.Server{Handler: mux}
	defer session.stop()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "Interface stopped:", err)
	}
}

func startGUISession(s *guiSession, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find CMD-Chat executable: %w", err)
	}
	cmd := exec.Command(exe, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("could not open chat input: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("could not open chat output: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("could not open chat errors: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("could not start chat: %w", err)
	}
	s.mu.Lock()
	s.cmd, s.stdin = cmd, stdin
	s.mu.Unlock()
	read := func(r io.Reader) {
		buf := make([]byte, 4096)
		var pending string
		for {
			n, err := r.Read(buf)
			if n > 0 {
				pending += string(buf[:n])
				for {
					i := strings.IndexByte(pending, '\n')
					if i < 0 {
						break
					}
					s.addLog(pending[:i])
					pending = pending[i+1:]
				}
			}
			if err != nil {
				if pending != "" {
					s.addLog(pending)
				}
				return
			}
		}
	}
	go read(stdout)
	go read(stderr)
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		if s.cmd == cmd {
			s.cmd, s.stdin = nil, nil
		}
		s.mu.Unlock()
	}()
	return nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

var idLine = regexp.MustCompile(`(?i)(?:Your ID|Hosting chat for):\s*(cc-[A-Za-z0-9_-]+)`)

func openBrowser(url string) error {
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		return fmt.Errorf("refusing to open non-local URL")
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", "--", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func extractID(line string) string {
	m := idLine.FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}
