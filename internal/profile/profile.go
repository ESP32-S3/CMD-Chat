// Package profile stores the preferences that belong to this computer alone:
// the nickname shown next to your messages, and whether you allow more than one
// person into a chat you host.
//
// None of this is ever published. The phonebook stores an ID, a key, a
// certificate fingerprint and short-lived addresses; a nickname is none of
// those, and adding one would turn a directory of reachable addresses into a
// directory of people. It travels only inside an already-authenticated chat
// session, directly to the peers you are talking to.
//
// A nickname is therefore self-asserted and cosmetic. It is not an identity and
// must never be treated as one: the CMD-Chat ID is the only thing a peer proves.
package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// MaxNicknameLength bounds what a peer can put on your screen. A nickname is
// printed next to every message that peer sends, so it stays short enough that
// it cannot push the message itself out of view or forge a prompt.
const MaxNicknameLength = 24

// Profile is the on-disk preference file.
type Profile struct {
	// Nickname is shown next to your messages. Empty means "use the operating
	// system account name".
	Nickname string `json:"nickname,omitempty"`

	// GroupChat records whether people you host may talk to each other, and
	// whether a second person may join at all. Stored as a pointer so an absent
	// value can default to true instead of to the zero value.
	GroupChat *bool `json:"group_chat,omitempty"`
}

var (
	mu     sync.Mutex
	loaded *Profile
)

// Path is the profile file, beside the identity it describes.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "cmd-chat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "profile.json"), nil
}

// Load reads the profile, returning an empty one if it does not exist yet.
//
// A corrupt or unreadable file is not an error worth stopping for: preferences
// are cosmetic, and refusing to start a chat over an unparseable nickname would
// be a worse outcome than forgetting it.
func Load() *Profile {
	mu.Lock()
	defer mu.Unlock()
	if loaded != nil {
		return copyOf(loaded)
	}
	loaded = &Profile{}
	path, err := Path()
	if err != nil {
		return copyOf(loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return copyOf(loaded)
	}
	var p Profile
	if json.Unmarshal(data, &p) == nil {
		p.Nickname = CleanNickname(p.Nickname)
		loaded = &p
	}
	return copyOf(loaded)
}

func copyOf(p *Profile) *Profile {
	out := &Profile{Nickname: p.Nickname}
	if p.GroupChat != nil {
		v := *p.GroupChat
		out.GroupChat = &v
	}
	return out
}

// save writes the profile with owner-only permissions.
func save(p *Profile) error {
	path, err := Path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	mu.Lock()
	loaded = copyOf(p)
	mu.Unlock()
	return nil
}

// Name returns the nickname to show next to this user's messages, falling back
// to the operating system account name.
func Name() string {
	if nick := Load().Nickname; nick != "" {
		return nick
	}
	return accountName()
}

func accountName() string {
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return "user"
}

// SetNickname stores a nickname. An empty value clears it, restoring the
// account name.
func SetNickname(nickname string) error {
	p := Load()
	p.Nickname = CleanNickname(nickname)
	return save(p)
}

// GroupChatEnabled reports whether this host lets more than one person in, and
// lets the people it hosts talk to each other. It defaults to true: a host that
// silently refused a second guest would be indistinguishable from one that was
// offline.
func GroupChatEnabled() bool {
	p := Load()
	if p.GroupChat == nil {
		return true
	}
	return *p.GroupChat
}

// SetGroupChatEnabled stores the host's choice.
func SetGroupChatEnabled(enabled bool) error {
	p := Load()
	p.GroupChat = &enabled
	return save(p)
}

// CleanNickname makes a nickname safe to print.
//
// Anything a peer sends lands directly in another person's terminal, so control
// characters are removed rather than escaped: a carriage return or an ANSI
// escape in a nickname could redraw the prompt, hide a line, or impersonate a
// system notice. This is applied to what a peer sends as well as to what the
// local user types.
func CleanNickname(nickname string) string {
	var b strings.Builder
	for _, r := range nickname {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case r == 0x7f || unicode.IsControl(r):
			// Dropped: never printed, never stored.
		case !unicode.IsGraphic(r) && r != ' ':
			// Dropped for the same reason.
		default:
			b.WriteRune(r)
		}
	}

	out := strings.TrimSpace(b.String())
	// Collapse runs of spaces so padding cannot be used to shove a name across
	// the screen or fake a column of its own.
	out = strings.Join(strings.Fields(out), " ")

	if len(out) > MaxNicknameLength {
		out = strings.TrimSpace(truncate(out, MaxNicknameLength))
	}
	return out
}

// truncate cuts to at most n bytes without splitting a multi-byte rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
