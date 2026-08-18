//go:build !windows

package identity

import "errors"

// DPAPI does not exist outside Windows.
//
// macOS Keychain and the freedesktop Secret Service are the equivalents, and
// both need either cgo or a live session D-Bus, neither of which a statically
// built terminal binary can count on. Rather than ship something that appears to
// protect the key and silently does not, these platforms report DPAPI as
// unavailable and fall back to the documented "none" mode — or to the passphrase
// mode, which works everywhere and is genuinely stronger.
func dpapiAvailable() bool { return false }

func dpapiProtect([]byte) ([]byte, error) {
	return nil, errors.New("identity: DPAPI is only available on Windows")
}

func dpapiUnprotect([]byte) ([]byte, error) {
	return nil, errors.New("identity: this identity file was sealed with Windows DPAPI and cannot be read on this platform")
}
