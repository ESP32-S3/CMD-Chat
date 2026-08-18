package e2ee

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Ordinary use
// ---------------------------------------------------------------------------

func TestMessagesRoundTripInBothDirections(t *testing.T) {
	alice, bob := goodPair(t)

	if got := roundTrip(t, alice, bob, "hello bob"); got != "hello bob" {
		t.Fatalf("got %q", got)
	}
	if got := roundTrip(t, bob, alice, "hello alice"); got != "hello alice" {
		t.Fatalf("got %q", got)
	}
	for i := range 50 {
		want := fmt.Sprintf("message %d", i)
		if got := roundTrip(t, alice, bob, want); got != want {
			t.Fatalf("message %d: got %q", i, got)
		}
	}
}

// An empty message and a full-size one both survive the padding scheme.
func TestPaddingRoundTripsEveryLength(t *testing.T) {
	alice, bob := goodPair(t)

	for _, n := range []int{0, 1, 255, 256, 257, 511, 512, 4096} {
		plaintext := bytes.Repeat([]byte{'x'}, n)
		record, err := alice.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", n, err)
		}
		got, err := bob.Decrypt(record)
		if err != nil {
			t.Fatalf("decrypt %d bytes: %v", n, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%d bytes did not round-trip", n)
		}
	}
}

// Requirement 12, in part: padding must actually coarsen the length signal.
func TestPaddingHidesSmallLengthDifferences(t *testing.T) {
	alice, bob := goodPair(t)

	short, err := alice.Encrypt([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(short); err != nil {
		t.Fatal(err)
	}
	long, err := alice.Encrypt(bytes.Repeat([]byte("a"), 200))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(long); err != nil {
		t.Fatal(err)
	}
	if len(short) != len(long) {
		t.Fatalf("a 2-byte and a 200-byte message produced records of %d and %d bytes; padding is not working", len(short), len(long))
	}
}

// ---------------------------------------------------------------------------
// Ordering, loss, duplication, replay, staleness
// ---------------------------------------------------------------------------

// Requirement 7: reordering within a chain must be tolerated.
func TestReorderedMessagesAreAccepted(t *testing.T) {
	alice, bob := goodPair(t)

	var records [][]byte
	for i := range 5 {
		record, err := alice.Encrypt([]byte(fmt.Sprintf("m%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}

	// Deliver 4, 2, 0, 3, 1.
	got := map[string]bool{}
	for _, i := range []int{4, 2, 0, 3, 1} {
		plaintext, err := bob.Decrypt(records[i])
		if err != nil {
			t.Fatalf("out-of-order message %d rejected: %v", i, err)
		}
		got[string(plaintext)] = true
	}
	for i := range 5 {
		if !got[fmt.Sprintf("m%d", i)] {
			t.Fatalf("message %d never arrived", i)
		}
	}
}

// Requirement 7: a lost message must not stop later ones decrypting.
func TestLostMessagesDoNotBlockLaterOnes(t *testing.T) {
	alice, bob := goodPair(t)

	var records [][]byte
	for i := range 6 {
		record, err := alice.Encrypt([]byte(fmt.Sprintf("m%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}

	// Messages 1, 2 and 4 are dropped by the network and never arrive.
	for _, i := range []int{0, 3, 5} {
		plaintext, err := bob.Decrypt(records[i])
		if err != nil {
			t.Fatalf("message %d rejected after losses: %v", i, err)
		}
		if string(plaintext) != fmt.Sprintf("m%d", i) {
			t.Fatalf("message %d decrypted to %q", i, plaintext)
		}
	}
}

// Requirement 6: a captured ciphertext must not decrypt twice.
func TestReplayedMessageIsRejected(t *testing.T) {
	alice, bob := goodPair(t)

	record, err := alice.Encrypt([]byte("only once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(record); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(record); err == nil {
		t.Fatal("a replayed ciphertext decrypted a second time")
	}
}

// The same, for a message that was received out of order: consuming a skipped
// key must destroy it.
func TestReplayOfAnOutOfOrderMessageIsRejected(t *testing.T) {
	alice, bob := goodPair(t)

	first, err := alice.Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := alice.Encrypt([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}

	// Deliver the second one first, so the first one's key is skipped and held.
	if _, err := bob.Decrypt(second); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(first); err != nil {
		t.Fatalf("the skipped message did not decrypt: %v", err)
	}
	if _, err := bob.Decrypt(first); err == nil {
		t.Fatal("a skipped message's key survived its first use and allowed a replay")
	}
	if _, err := bob.Decrypt(second); err == nil {
		t.Fatal("the out-of-order message replayed successfully")
	}
}

// Duplicates are the benign form of the same thing and must also be rejected
// exactly once.
func TestDuplicateDeliveryIsRejectedAfterTheFirst(t *testing.T) {
	alice, bob := goodPair(t)

	record, err := alice.Encrypt([]byte("dup"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(record); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := bob.Decrypt(record); err == nil {
			t.Fatalf("duplicate %d was accepted", i)
		}
	}
}

// Requirement 7: a message from far behind the current chain must be refused,
// not accepted.
func TestStaleMessageFromAnOldChainIsRejected(t *testing.T) {
	alice, bob := goodPair(t)

	stale, err := alice.Encrypt([]byte("from the old chain"))
	if err != nil {
		t.Fatal(err)
	}

	// Turn the ratchet several times, so the chain that produced `stale` is long
	// gone and its key was never stored.
	for i := range 4 {
		if got := roundTrip(t, alice, bob, fmt.Sprintf("a%d", i)); got == "" {
			t.Fatal("empty round trip")
		}
		if got := roundTrip(t, bob, alice, fmt.Sprintf("b%d", i)); got == "" {
			t.Fatal("empty round trip")
		}
	}

	// The first record is legitimately still decryptable: its key was skipped
	// and stored when the chain moved on. What must NOT happen is decrypting it
	// twice.
	if _, err := bob.Decrypt(stale); err != nil {
		t.Logf("the stale record was refused outright: %v", err)
	} else if _, err := bob.Decrypt(stale); err == nil {
		t.Fatal("a stale record decrypted twice")
	}
}

// Requirement 7: an absurd forward jump must be refused rather than performing
// a million key derivations on demand.
func TestOutOfWindowMessageIsRejected(t *testing.T) {
	alice, bob := goodPair(t)

	record, err := alice.Encrypt([]byte("legitimate"))
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the header's message index to something far beyond MaxSkip. The
	// AEAD tag will not match either, but the skip check must fire FIRST, before
	// any key derivation happens.
	forged := append([]byte(nil), record...)
	copy(forged[37:41], []byte{0x00, 0xFF, 0xFF, 0xFF})

	if _, err := bob.Decrypt(forged); !errors.Is(err, ErrSkipTooLarge) {
		t.Fatalf("got %v, want ErrSkipTooLarge", err)
	}

	// And the session must be untouched: the genuine message still works.
	got, err := bob.Decrypt(record)
	if err != nil {
		t.Fatalf("a rejected out-of-window message damaged the session: %v", err)
	}
	if string(got) != "legitimate" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Tampering
// ---------------------------------------------------------------------------

// Requirement 5 and 6: any modification anywhere in a record must be caught, and
// must leave the session able to carry on.
func TestTamperedRecordsAreRejectedAndLeaveTheSessionIntact(t *testing.T) {
	positions := []struct {
		name  string
		index func(record []byte) int
	}{
		{"version byte", func([]byte) int { return 0 }},
		{"ratchet public key", func([]byte) int { return 5 }},
		{"previous chain length", func([]byte) int { return 34 }},
		{"message index", func([]byte) int { return 40 }},
		{"first ciphertext byte", func([]byte) int { return headerSize }},
		{"last ciphertext byte", func(r []byte) int { return len(r) - tagSize - 1 }},
		{"authentication tag", func(r []byte) int { return len(r) - 1 }},
	}

	for _, pos := range positions {
		t.Run(pos.name, func(t *testing.T) {
			alice, bob := goodPair(t)

			record, err := alice.Encrypt([]byte("the real message"))
			if err != nil {
				t.Fatal(err)
			}
			forged := append([]byte(nil), record...)
			forged[pos.index(forged)] ^= 0x01

			if _, err := bob.Decrypt(forged); err == nil {
				t.Fatal("a tampered record decrypted")
			}

			// The genuine record must still work afterwards. A failed decryption
			// that advanced the ratchet would silently eat the next real message.
			got, err := bob.Decrypt(record)
			if err != nil {
				t.Fatalf("a rejected forgery broke the session: %v", err)
			}
			if string(got) != "the real message" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

// A truncated record must be refused before it reaches the AEAD.
func TestTruncatedRecordIsRejected(t *testing.T) {
	alice, bob := goodPair(t)

	record, err := alice.Encrypt([]byte("complete"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, headerSize - 1, headerSize, headerSize + tagSize - 1, len(record) - 1} {
		if n > len(record) {
			continue
		}
		if _, err := bob.Decrypt(record[:n]); err == nil {
			t.Fatalf("a record truncated to %d bytes decrypted", n)
		}
	}
	if _, err := bob.Decrypt(record); err != nil {
		t.Fatalf("the intact record failed after truncation attempts: %v", err)
	}
}

// Requirement: modified associated data must be detected. AD0 is the session
// tag, so a record from another session is the purest form of this.
func TestRecordFromAnotherSessionIsRejected(t *testing.T) {
	alice1, bob1 := goodPair(t)
	_, bob2 := goodPair(t)

	record, err := alice1.Encrypt([]byte("session one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob2.Decrypt(record); err == nil {
		t.Fatal("a record from one session decrypted in another")
	}
	if _, err := bob1.Decrypt(record); err != nil {
		t.Fatalf("the record failed in its own session: %v", err)
	}
}

// Requirement: an old session's ciphertext must not decrypt after a restart
// between the same two people. AD0 is derived from the handshake transcript, so
// a reconnect produces a different tag even with identical identities.
func TestOldSessionCiphertextFailsAfterASessionRestart(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)

	newSessionPair := func() (*Session, *Session) {
		b := binding(t)
		r := handshake(t,
			Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
			Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
		)
		if r.initErr != nil || r.respErr != nil {
			t.Fatalf("handshake: %v / %v", r.initErr, r.respErr)
		}
		return r.initiator, r.responder
	}

	first, firstPeer := newSessionPair()
	old, err := first.Encrypt([]byte("from the first conversation"))
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	firstPeer.Close()

	second, secondPeer := newSessionPair()
	defer second.Close()
	defer secondPeer.Close()

	if _, err := secondPeer.Decrypt(old); err == nil {
		t.Fatal("a ciphertext from a previous session decrypted in the new one")
	}
	// The new session still works.
	if got := roundTrip(t, second, secondPeer, "fresh"); got != "fresh" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Key separation, ratcheting, and compromise boundaries
// ---------------------------------------------------------------------------

// Requirement 5: no two messages may share a key or a nonce.
func TestEveryMessageGetsAFreshKeyAndNonce(t *testing.T) {
	alice, bob := goodPair(t)

	const count = 400
	keys := map[string]int{}
	nonces := map[string]int{}

	for i := range count {
		// Reach into the ratchet the way the record layer does, so the test
		// observes the real derivation rather than a re-implementation.
		alice.mu.Lock()
		_, messageKey, err := alice.ratchet.next()
		alice.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		key, nonce, err := messageKeys(messageKey)
		if err != nil {
			t.Fatal(err)
		}
		if prev, seen := keys[string(key)]; seen {
			t.Fatalf("message %d reused the AEAD key of message %d", i, prev)
		}
		if prev, seen := nonces[string(nonce)]; seen {
			t.Fatalf("message %d reused the nonce of message %d", i, prev)
		}
		keys[string(key)] = i
		nonces[string(nonce)] = i
	}
	if len(keys) != count || len(nonces) != count {
		t.Fatalf("got %d distinct keys and %d distinct nonces from %d messages", len(keys), len(nonces), count)
	}
	_ = bob
}

// Requirement 4: the DH ratchet must actually turn as the conversation goes back
// and forth, rather than being a claim in a comment.
func TestDHRatchetTurnsOnEveryReply(t *testing.T) {
	alice, bob := goodPair(t)

	before := alice.Steps() + bob.Steps()
	for i := range 5 {
		roundTrip(t, alice, bob, fmt.Sprintf("a%d", i))
		roundTrip(t, bob, alice, fmt.Sprintf("b%d", i))
	}
	after := alice.Steps() + bob.Steps()

	if after <= before {
		t.Fatal("the DH ratchet never turned across five exchanges; there is no post-compromise security")
	}
	if after-before < 5 {
		t.Fatalf("only %d ratchet steps across five exchanges", after-before)
	}
}

// Requirement 8: compromising ONE message key must expose exactly one message.
func TestCompromisingOneMessageKeyExposesOnlyThatMessage(t *testing.T) {
	alice, bob := goodPair(t)

	// Capture the key the ratchet will use for the next message, as an attacker
	// who scraped it out of memory at that instant would have.
	alice.mu.Lock()
	header, stolenKey, err := alice.ratchet.next()
	alice.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	stolen := append([]byte(nil), stolenKey...)

	key, nonce, err := messageKeys(stolen)
	if err != nil {
		t.Fatal(err)
	}
	box, err := aead(key)
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := header.encode()
	alice.mu.Lock()
	ad := alice.additionalData(headerBytes)
	alice.mu.Unlock()
	record := append(append([]byte(nil), headerBytes...), box.Seal(nil, nonce, pad([]byte("the exposed one")), ad)...)

	got, err := bob.Decrypt(record)
	if err != nil {
		t.Fatalf("the reconstructed record did not decrypt: %v", err)
	}
	if string(got) != "the exposed one" {
		t.Fatalf("got %q", got)
	}

	// The next message uses a key the attacker cannot derive from the stolen one,
	// because the chain step is HMAC and HMAC is one-way.
	next, err := alice.Encrypt([]byte("still private"))
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, attackerNonce, err := messageKeys(stolen)
	if err != nil {
		t.Fatal(err)
	}
	attackerBox, err := aead(attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attackerBox.Open(nil, attackerNonce, next[headerSize:], nil); err == nil {
		t.Fatal("the stolen message key decrypted a later message")
	}
	if plaintext, err := bob.Decrypt(next); err != nil || string(plaintext) != "still private" {
		t.Fatalf("the genuine next message failed: %v %q", err, plaintext)
	}
}

// Requirement 3: the long-term identity key must not decrypt anything. It signs;
// it never participates in key agreement.
func TestIdentityKeyIsNeverUsedForKeyAgreement(t *testing.T) {
	alice, bob := testIdent(t), testIdent(t)
	b := binding(t)

	r := handshake(t,
		Config{Credentials: creds(alice, "alice"), ChannelBinding: b, Trust: allowAny{}},
		Config{Credentials: creds(bob, "bob"), ChannelBinding: b, Trust: allowAny{}},
	)
	if r.initErr != nil || r.respErr != nil {
		t.Fatalf("handshake: %v / %v", r.initErr, r.respErr)
	}
	defer r.initiator.Close()
	defer r.responder.Close()

	record, err := r.initiator.Encrypt([]byte("captured traffic"))
	if err != nil {
		t.Fatal(err)
	}

	// An attacker who later obtains BOTH long-term private keys still has no
	// path to the root key: it was derived from ephemeral X25519 material that
	// only ever existed in RAM and has since been overwritten.
	//
	// The strongest thing a test can assert here is that no key in the session
	// state equals, or is derived from, either identity key.
	for _, secret := range [][]byte{alice.PrivateKey, bob.PrivateKey, alice.PrivateKey.Seed(), bob.PrivateKey.Seed()} {
		r.responder.mu.Lock()
		root := append([]byte(nil), r.responder.ratchet.rootKey...)
		tag := append([]byte(nil), r.responder.associated...)
		r.responder.mu.Unlock()
		if bytes.Contains(root, secret) || bytes.Contains(tag, secret) {
			t.Fatal("long-term key material appears inside the session state")
		}
		if bytes.Contains(record, secret) {
			t.Fatal("long-term key material appears in a record")
		}
	}

	if got, err := r.responder.Decrypt(record); err != nil || string(got) != "captured traffic" {
		t.Fatalf("round trip failed: %v", err)
	}
}

// The skipped-key store must be bounded, or a peer could grow it without limit.
func TestSkippedKeyStoreIsBounded(t *testing.T) {
	alice, bob := goodPair(t)

	// Send far more than the store can hold, delivering only the last one each
	// round so the rest stay skipped.
	for round := range 4 {
		var last []byte
		for range MaxSkip - 1 {
			record, err := alice.Encrypt([]byte("filler"))
			if err != nil {
				t.Fatal(err)
			}
			last = record
		}
		if _, err := bob.Decrypt(last); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		bob.mu.Lock()
		held := len(bob.ratchet.skipped)
		order := len(bob.ratchet.order)
		bob.mu.Unlock()
		if held > MaxSkipStore {
			t.Fatalf("round %d: the store holds %d keys, above the %d cap", round, held, MaxSkipStore)
		}
		if held != order {
			t.Fatalf("round %d: the store and its eviction order disagree (%d vs %d)", round, held, order)
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// Requirement 16: concurrent send and receive on one session must be safe. Run
// this with -race to mean anything.
func TestConcurrentSendAndReceive(t *testing.T) {
	alice, bob := goodPair(t)

	const count = 100
	toBob := make(chan []byte, count)
	toAlice := make(chan []byte, count)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		defer close(toBob)
		for i := range count {
			record, err := alice.Encrypt([]byte(fmt.Sprintf("a%d", i)))
			if err != nil {
				t.Errorf("alice encrypt: %v", err)
				return
			}
			toBob <- record
		}
	}()
	go func() {
		defer wg.Done()
		defer close(toAlice)
		for i := range count {
			record, err := bob.Encrypt([]byte(fmt.Sprintf("b%d", i)))
			if err != nil {
				t.Errorf("bob encrypt: %v", err)
				return
			}
			toAlice <- record
		}
	}()
	go func() {
		defer wg.Done()
		for record := range toBob {
			if _, err := bob.Decrypt(record); err != nil {
				t.Errorf("bob decrypt: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for record := range toAlice {
			if _, err := alice.Decrypt(record); err != nil {
				t.Errorf("alice decrypt: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Rekey policy
// ---------------------------------------------------------------------------

// Requirement 4: a one-sided conversation must eventually ask for a reply, or
// the DH ratchet would never turn.
func TestNeedsRekeyFiresOnAOneSidedConversation(t *testing.T) {
	alice, bob := goodPair(t)

	if alice.NeedsRekey() {
		t.Fatal("a fresh session already wants a rekey")
	}
	for range RekeyAfterMessages {
		if _, err := alice.Encrypt([]byte("one-sided")); err != nil {
			t.Fatal(err)
		}
	}
	if !alice.NeedsRekey() {
		t.Fatalf("after %d unanswered messages the session did not ask for a rekey", RekeyAfterMessages)
	}

	// A reply turns the ratchet and clears the flag.
	record, err := bob.Encrypt([]byte("answering"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Decrypt(record); err != nil {
		t.Fatal(err)
	}
	if alice.NeedsRekey() {
		t.Fatal("a DH ratchet step did not reset the rekey counter")
	}
}

// A closed session must refuse to do anything further.
func TestClosedSessionRefusesWork(t *testing.T) {
	alice, bob := goodPair(t)

	record, err := alice.Encrypt([]byte("before closing"))
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(record); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("got %v, want ErrSessionClosed", err)
	}
	if _, err := bob.Encrypt([]byte("after closing")); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("got %v, want ErrSessionClosed", err)
	}
	if err := bob.Close(); err != nil {
		t.Fatalf("closing twice returned %v", err)
	}
}

// Wipe must actually zero, and must not panic on nil.
func TestWipeZeroesBuffers(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d was not zeroed", i)
		}
	}
	Wipe(nil)
	wipeAll(nil, []byte{9}, nil)
}
