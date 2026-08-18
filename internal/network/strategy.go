package network

// Strategy documents the connection fallback order used by CMD-Chat.
// The host remains the chat server; these layers only decide how to reach it.
type Strategy string

const (
	Localhost     Strategy = "localhost"
	LAN           Strategy = "lan"
	Direct        Strategy = "direct"
	NATTraversal  Strategy = "nat-traversal"
	RelayFallback Strategy = "relay-fallback"
)

func Order() []Strategy {
	return []Strategy{Localhost, LAN, Direct, NATTraversal, RelayFallback}
}
