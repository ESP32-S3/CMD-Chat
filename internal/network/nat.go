package network

// NAT traversal interface placeholder.
// Future implementation will add STUN discovery and UDP hole punching.
type Endpoint struct {
    Address string
    Port int
}

func DiscoverPublicEndpoint() (*Endpoint, error) {
    return nil, nil
}

func TryHolePunch(peer Endpoint) error {
    return nil
}
