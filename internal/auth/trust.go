package auth

import (
    "encoding/json"
    "os"
    "path/filepath"
)

// Store keeps identities that the user explicitly trusts.
type Store struct {
    Peers map[string]string `json:"peers"`
}

func path() string {
    dir, _ := os.UserConfigDir()
    dir = filepath.Join(dir, "cmd-chat")
    _ = os.MkdirAll(dir, 0700)
    return filepath.Join(dir, "trusted_peers.json")
}

func Load() *Store {
    s := &Store{Peers: map[string]string{}}
    data, err := os.ReadFile(path())
    if err == nil {
        _ = json.Unmarshal(data, s)
    }
    return s
}

func (s *Store) Trust(id, publicKey string) error {
    s.Peers[id] = publicKey
    data, err := json.MarshalIndent(s, "", "  ")
    if err != nil { return err }
    return os.WriteFile(path(), data, 0600)
}

func (s *Store) IsTrusted(id, publicKey string) bool {
    return s.Peers[id] == publicKey
}
