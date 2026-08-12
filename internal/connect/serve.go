package connect

import (
	"errors"
	"time"

	"github.com/ESP32-S3/CMD-Chat/internal/chat"
	"github.com/ESP32-S3/CMD-Chat/internal/identity"
	"github.com/ESP32-S3/CMD-Chat/internal/relay"
)

// How long the host waits on one relay connection before refreshing it. The
// relay drops an unpaired host after ten minutes, so this stays comfortably
// under that.
const relayWaitWindow = 4 * time.Minute

// Backoff bounds for a relay that is unreachable or refusing connections.
const (
	relayRetryMin = 3 * time.Second
	relayRetryMax = 60 * time.Second
)

// ServeRelay keeps the host reachable through the relay for as long as it is
// hosting.
//
// This runs alongside — never instead of — the normal TCP listener. A guest
// that can reach the host directly never touches the relay; this is only what
// makes the host reachable when it cannot be dialled at all.
//
// Each paired session is served exactly like an accepted TCP connection, so the
// relay adds no new trust: the TLS handshake and mutual Ed25519 authentication
// still happen end to end inside the relayed byte stream.
func ServeRelay(h *chat.Host, ident *identity.Identity, relayURL string, log, debug Logf, stop <-chan struct{}) {
	if log == nil {
		log = func(string, ...any) {}
	}
	if debug == nil {
		debug = func(string, ...any) {}
	}

	backoff := relayRetryMin
	announced := false

	for {
		select {
		case <-stop:
			return
		default:
		}

		session, err := relay.Listen(relayURL, ident, relayWaitWindow)
		if err != nil {
			// A plain wait timeout is the normal idle case, not a failure.
			if isWaitTimeout(err) {
				backoff = relayRetryMin
				continue
			}

			select {
			case <-stop:
				return
			default:
			}

			debug("relay listen failed: %v", err)
			if !announced {
				log("[network] relay unavailable; only direct connections will work")
				announced = true
			}
			select {
			case <-stop:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > relayRetryMax {
				backoff = relayRetryMax
			}
			continue
		}

		backoff = relayRetryMin
		announced = false

		log("[network] peer connected through the relay")
		debug("relay session paired with %s", session.PeerID)

		// Serve in the background so the host immediately goes back to waiting
		// and a second guest is not locked out for the length of a chat.
		go func(s *relay.Session) {
			defer s.Close()
			h.HandleConn(s.Conn)
			debug("relay session with %s ended", s.PeerID)
		}(session)
	}
}

// isWaitTimeout reports the ordinary "nobody joined" outcomes, which should
// simply loop rather than trigger backoff or a warning.
func isWaitTimeout(err error) bool {
	if errors.Is(err, relay.ErrWaitTimeout) {
		return true
	}
	// The relay closes an idle host session itself; reconnecting is correct.
	var closeErr *relay.CloseError
	return errors.As(err, &closeErr)
}
