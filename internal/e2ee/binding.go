package e2ee

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// TLSChannelBinding extracts the exporter value that ties a CMDC2 handshake to
// one specific TLS session.
//
// This is the single most important function in the package. Without it, CMDC2
// would authenticate two identities to each other but say nothing about WHICH
// connection they were authenticating over — and an attacker who terminates TLS
// on both sides could forward the whole handshake verbatim between two sessions
// and sit in the middle of a conversation both endpoints believe is private.
// That is precisely the break recorded as W1 in docs/SECURITY-BASELINE.md.
//
// With it, the two sessions such an attacker holds produce two different
// exporter values, the transcripts differ, and the signatures it forwards do not
// verify on the far side. The attack fails at the handshake instead of
// succeeding silently.
//
// RFC 8446 §7.5 defines the TLS 1.3 exporter; RFC 5705 reserves the "EXPORTER-"
// label prefix. The value is a PRF output over the session's master secret, so
// it is unpredictable to anyone without that secret and unique per session.
func TLSChannelBinding(c *tls.Conn) ([]byte, error) {
	if c == nil {
		return nil, errors.New("e2ee: no TLS connection to bind to")
	}
	state := c.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("e2ee: TLS handshake must complete before channel binding")
	}
	// TLS 1.3 only. In TLS 1.2 the exporter can be computed without the extended
	// master secret extension, which makes it forwardable by a triple-handshake
	// attacker — the exact adversary this defends against.
	if state.Version < tls.VersionTLS13 {
		return nil, fmt.Errorf("e2ee: channel binding requires TLS 1.3, got 0x%04x", state.Version)
	}
	binding, err := state.ExportKeyingMaterial(ChannelBindingLabel, nil, ChannelBindingLength)
	if err != nil {
		return nil, fmt.Errorf("e2ee: TLS exporter unavailable: %w", err)
	}
	if len(binding) != ChannelBindingLength {
		return nil, errors.New("e2ee: TLS exporter returned the wrong length")
	}
	return binding, nil
}
