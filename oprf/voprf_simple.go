// Package oprf provides a simplified VOPRF implementation
package oprf

import (
	"github.com/cloudflare/circl/oprf"
)

// Suite represents a VOPRF cipher suite
type Suite = oprf.Suite

// Available VOPRF suites
const (
	// OPRFP256 uses P-256 curve
	OPRFP256 = oprf.OPRFP256
	// OPRFP384 uses P-384 curve
	OPRFP384 = oprf.OPRFP384
	// OPRFP521 uses P-521 curve  
	OPRFP521 = oprf.OPRFP521
	// OPRFRistretto255 uses Ristretto255 group
	OPRFRistretto255 = oprf.OPRFRistretto255
)

// Mode represents the OPRF protocol mode
type Mode = oprf.Mode

// Available modes
const (
	// BaseMode provides oblivious evaluation
	BaseMode = oprf.BaseMode
	// VerifiableMode allows client to verify server's key
	VerifiableMode = oprf.VerifiableMode
	// PartialObliviousMode includes public info in PRF input
	PartialObliviousMode = oprf.PartialObliviousMode
)

// Client wraps the OPRF client
type Client struct {
	*oprf.Client
}

// Server wraps the OPRF server
type Server struct {
	*oprf.Server
}

// VerifiableClient wraps the verifiable OPRF client
type VerifiableClient struct {
	*oprf.VerifiableClient
}

// VerifiableServer wraps the verifiable OPRF server
type VerifiableServer struct {
	*oprf.VerifiableServer
}

// NewClient creates a new OPRF client
func NewClient(suite Suite) (*Client, error) {
	client, err := oprf.NewClient(suite)
	if err != nil {
		return nil, err
	}
	return &Client{client}, nil
}

// NewServer creates a new OPRF server
func NewServer(suite Suite, privateKey []byte) (*Server, error) {
	server, err := oprf.NewServer(suite, privateKey)
	if err != nil {
		return nil, err
	}
	return &Server{server}, nil
}

// NewVerifiableClient creates a new verifiable OPRF client
func NewVerifiableClient(suite Suite, publicKey []byte) (*VerifiableClient, error) {
	client, err := oprf.NewVerifiableClient(suite, publicKey)
	if err != nil {
		return nil, err
	}
	return &VerifiableClient{client}, nil
}

// NewVerifiableServer creates a new verifiable OPRF server
func NewVerifiableServer(suite Suite, privateKey []byte) (*VerifiableServer, error) {
	server, err := oprf.NewVerifiableServer(suite, privateKey)
	if err != nil {
		return nil, err
	}
	return &VerifiableServer{server}, nil
}