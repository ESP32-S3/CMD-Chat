package identity

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base32"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const idBytes = 16

// LoadOrCreate returns a stable, locally stored identity. The ID is not an IP address,
// so it remains unchanged when the machine changes networks.
func LoadOrCreate() (string, error) {
    dir, err := os.UserConfigDir()
    if err != nil { return "", err }
    dir = filepath.Join(dir, "cmd-chat")
    if err := os.MkdirAll(dir, 0700); err != nil { return "", err }
    path := filepath.Join(dir, "identity")
    if b, err := os.ReadFile(path); err == nil {
        id := strings.TrimSpace(string(b))
        if id != "" { return id, nil }
    }
    raw := make([]byte, idBytes)
    if _, err := rand.Read(raw); err != nil { return "", err }
    sum := sha256.Sum256(raw)
    id := "cc-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]))
    if err := os.WriteFile(path, []byte(id+"\n"), 0600); err != nil { return "", err }
    return id, nil
}

func Short(id string) string {
    if len(id) <= 14 { return id }
    return fmt.Sprintf("%s…", id[:14])
}
