package e2ee

// Every domain-separation label used by CMDC1 lives here, and nowhere else.
//
// Keeping them in one file is the whole point: a reader can check at a glance
// that no two purposes share a label, and a reviewer can see that adding a new
// derivation means adding a new label rather than reusing a convenient one.
//
// The rule this file exists to enforce: one label, one purpose, forever. If the
// purpose of a derivation changes, the label changes with it.
const (
	// Protocol identity. Bumping the version bumps every label below with it,
	// because the version string is part of each one.
	protocolName = "CMD-CHAT-E2EE"
	versionTag   = "v1"

	// Transcript.
	labelTranscript = protocolName + " " + versionTag + " transcript"

	// Handshake AEAD keys. Each encrypts exactly one ciphertext.
	labelHandshakeKeyResponder = protocolName + " " + versionTag + " hs responder key"
	labelHandshakeKeyInitiator = protocolName + " " + versionTag + " hs initiator key"

	// Handshake key-confirmation MAC keys (SIGMA).
	labelHandshakeMACResponder = protocolName + " " + versionTag + " hs responder mac"
	labelHandshakeMACInitiator = protocolName + " " + versionTag + " hs initiator mac"

	// Signed and MACed payload contexts. These are prefixes of the signed
	// message, not KDF labels, but they follow the same one-purpose rule.
	labelSignatureResponder = protocolName + " " + versionTag + " responder signature"
	labelSignatureInitiator = protocolName + " " + versionTag + " initiator signature"
	labelConfirmResponder   = protocolName + " " + versionTag + " responder confirm"
	labelConfirmInitiator   = protocolName + " " + versionTag + " initiator confirm"

	// Session outputs of the handshake.
	labelRootKey       = protocolName + " " + versionTag + " root key"
	labelAssociatedTag = protocolName + " " + versionTag + " associated data"

	// Record layer.
	labelRatchetRoot = protocolName + " " + versionTag + " ratchet root"
	labelMessageKeys = protocolName + " " + versionTag + " message keys"

	// TLS exporter label for channel binding. RFC 5705 reserves the
	// "EXPORTER-" prefix for exactly this kind of use.
	ChannelBindingLabel = "EXPORTER-CMD-Chat-CMDC1-channel-binding"
)

// ChannelBindingLength is how many bytes of TLS exporter material CMDC1 binds
// to. 32 bytes is a full SHA-256 block of unpredictable, session-unique data.
const ChannelBindingLength = 32

// ProtocolVersionName is the human-readable name of the current protocol, for
// status output. It is not used in any cryptographic input.
const ProtocolVersionName = protocolName + "/" + versionTag + " (CMDC1)"
