package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

var (
	mu sync.Mutex
	enabled bool
	file *os.File
)

func Enable() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if enabled && file != nil { return file.Name(), nil }
	dir, err := os.UserConfigDir()
	if err != nil { return "", err }
	dir = filepath.Join(dir, "CMD-Chat", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil { return "", err }
	path := filepath.Join(dir, fmt.Sprintf("crash-%s.log", time.Now().Format("20060102-150405")))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil { return "", err }
	file, enabled = f, true
	writeLocked("Debug logging enabled")
	return path, nil
}

func Enabled() bool { mu.Lock(); defer mu.Unlock(); return enabled }

func Log(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if !enabled || file == nil { return }
	writeLocked(format, args...)
}

func writeLocked(format string, args ...any) {
	_, _ = fmt.Fprintf(file, "[%s] %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	_ = file.Sync()
}

func Recover() {
	if r := recover(); r != nil {
		mu.Lock()
		if enabled && file != nil {
			writeLocked("PANIC: %v", r)
			_, _ = file.Write(debug.Stack())
			_ = file.Sync()
		}
		mu.Unlock()
		panic(r)
	}
}
