// Package auth holds CMD-Chat's peer trust decisions.
//
// The cryptographic proof of an identity lives in internal/e2ee, which runs the
// CMDC2 handshake. What lives here is the question that comes AFTER the proof:
// this peer really does hold the private key for the ID it presented — but is it
// the same key we saw for that ID last time?
package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/identity"
)

// ErrKeyChanged means a known ID presented a different public key.
//
// This is the one that matters. It is either a peer that reinstalled and lost
// its identity, or an attacker substituting its own key for someone the user
// already trusts — and nothing in the protocol can tell those two apart. CMD-Chat
// therefore FAILS CLOSED: the connection is refused, and the only way forward is
// for the user to remove the old entry deliberately, out of band, after checking
// with the other person by some means that is not this chat.
var ErrKeyChanged = errors.New("auth: this ID previously used a different identity key")

// Record is what is remembered about one peer.
type Record struct {
	PublicKey string `json:"public_key"`

	// FirstSeen and LastSeen are for the user's benefit when a key change has to
	// be investigated: "you first talked to this ID in March" is the kind of
	// thing that makes an unexpected change obviously wrong.
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// Store is the trust-on-first-use database.
type Store struct {
	mu    sync.Mutex
	peers map[string]Record

	// path is where the store is persisted. Tests set it; production leaves it
	// empty and gets the real location.
	path string
}

// file is the on-disk shape. The legacy version 1 file mapped ID directly to a
// base64 key string, and is still read.
type file struct {
	Peers map[string]Record `json:"peers"`
}

func defaultPath() string {
	dir, err := identity.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "trusted_peers.json")
}

// Load reads the trust store, returning an empty one when there is nothing to
// read.
func Load() *Store { return LoadFrom(defaultPath()) }

// LoadFrom reads a trust store from an explicit path.
func LoadFrom(path string) *Store {
	s := &Store{peers: map[string]Record{}, path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}

	var current file
	if json.Unmarshal(data, &current) == nil && current.Peers != nil {
		s.peers = current.Peers
		return s
	}

	// Version 1: {"peers": {"cc-…": "base64key"}}.
	var legacy struct {
		Peers map[string]string `json:"peers"`
	}
	if json.Unmarshal(data, &legacy) == nil {
		for id, key := range legacy.Peers {
			s.peers[id] = Record{PublicKey: key}
		}
	}
	return s
}

// Authorize implements e2ee.TrustPolicy.
//
// It is called only with an identity the handshake has already PROVEN, so the
// question here is purely continuity. A first sighting is recorded; a matching
// key is refreshed; a mismatch is refused.
func (s *Store) Authorize(id string, publicKey ed25519.PublicKey) error {
	return s.Trust(id, base64.StdEncoding.EncodeToString(publicKey))
}

// Trust records a proven identity, or refuses a changed one.
func (s *Store) Trust(id, publicKey string) error {
	if id == "" || publicKey == "" {
		return errors.New("auth: invalid trusted identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	existing, known := s.peers[id]
	switch {
	case known && existing.PublicKey != publicKey:
		return fmt.Errorf("%w (first seen %s)", ErrKeyChanged, existing.FirstSeen.Format(time.RFC3339))
	case known:
		existing.LastSeen = now
		s.peers[id] = existing
	default:
		s.peers[id] = Record{PublicKey: publicKey, FirstSeen: now, LastSeen: now}
	}
	return s.saveLocked()
}

// IsTrusted reports whether this exact (id, key) pair is the remembered one.
func (s *Store) IsTrusted(id, publicKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.peers[id]
	return ok && record.PublicKey == publicKey
}

// Known reports whether an ID has been seen before, and what key it used.
func (s *Store) Known(id string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.peers[id]
	return record, ok
}

// Forget removes a peer, which is the deliberate act a user must take before a
// changed key will be accepted. It is not reachable from a network message.
func (s *Store) Forget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, id)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(file{Peers: s.peers}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
