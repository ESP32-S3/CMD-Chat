package relay

import (
	"crypto/sha1"
	"encoding/base64"
	"testing"
)

// The RFC 6455 section 1.3 worked example. If this drifts, every handshake
// fails, so it is worth pinning explicitly.
func TestAcceptComputationMatchesRFC6455(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	sum := sha1.Sum([]byte(key + wsGUID))
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("accept = %q, want %q", got, want)
	}
}
