# Lux Crypto Package

[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/crypto.svg)](https://pkg.go.dev/github.com/luxfi/crypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/luxfi/crypto)](https://goreportcard.com/report/github.com/luxfi/crypto)

## Overview

The `crypto` package provides cryptographic primitives and utilities for the Lux Network ecosystem. It includes implementations for BLS signatures, key derivation, certificate handling, and secp256k1 operations, all optimized for blockchain applications.

## Features

- **BLS Signatures**: Threshold signature scheme supporting multi-party computation
- **SLIP-10 HD Wallets**: Hierarchical deterministic key derivation
- **secp256k1**: Elliptic curve operations for Ethereum compatibility
- **Certificate Management**: TLS certificate handling for node identity
- **Key Factories**: Secure key generation and management

## Installation

```bash
go get github.com/luxfi/crypto
```

## Usage

### BLS Signatures

BLS (Boneh-Lynn-Shacham) signatures provide efficient threshold signature schemes:

```go
import (
    "github.com/luxfi/crypto/bls"
)

// Generate a private key
sk, err := bls.NewSecretKey()
if err != nil {
    log.Fatal(err)
}

// Get the public key
pk := bls.PublicFromSecretKey(sk)

// Sign a message
message := []byte("Hello, Lux!")
signature := bls.Sign(sk, message)

// Verify the signature
valid := bls.Verify(pk, signature, message)
```

### Key Derivation (SLIP-10)

Hierarchical deterministic key derivation following SLIP-10 standard:

```go
import (
    "github.com/luxfi/crypto/keychain"
)

// Create a new keychain from seed
seed := []byte("your-secure-seed-phrase")
kc, err := keychain.NewFromSeed(seed)
if err != nil {
    log.Fatal(err)
}

// Derive a key at a specific path
key, err := kc.Derive([]uint32{44, 9000, 0, 0, 0})
if err != nil {
    log.Fatal(err)
}
```

### secp256k1 Operations

Ethereum-compatible elliptic curve operations:

```go
import (
    "github.com/luxfi/crypto/secp256k1"
)

// Generate a private key
privKey, err := secp256k1.NewPrivateKey()
if err != nil {
    log.Fatal(err)
}

// Get the public key
pubKey := privKey.PublicKey()

// Sign a message
messageHash := crypto.Keccak256([]byte("message"))
signature, err := privKey.Sign(messageHash)
if err != nil {
    log.Fatal(err)
}

// Verify signature
valid := pubKey.Verify(messageHash, signature)
```

### Certificate Handling

TLS certificate management for node identity:

```go
import (
    "github.com/luxfi/crypto"
)

// Create a certificate structure
cert := &crypto.Certificate{
    Raw:       tlsCert.Raw,
    PublicKey: tlsCert.PublicKey,
}

// Use with node identity generation
// nodeID := ids.NodeIDFromCert(cert)
```

## Package Structure

```
crypto/
├── bls/           # BLS signature scheme implementation
├── keychain/      # SLIP-10 HD key derivation
├── secp256k1/     # secp256k1 elliptic curve operations
├── certificate.go # TLS certificate structures
└── README.md      # This file
```

## Security Considerations

1. **Key Storage**: Never store private keys in plain text. Use secure key management systems.
2. **Randomness**: This package uses cryptographically secure random number generation.
3. **Constant Time**: Critical operations are implemented to be constant-time where applicable.
4. **Threshold Signatures**: BLS signatures support threshold schemes for distributed signing.

## Performance

The crypto package is optimized for blockchain operations:
- Fast signature verification for consensus
- Batch verification support in BLS
- Optimized elliptic curve operations
- Minimal memory allocations

## Testing

Run the comprehensive test suite:

```bash
go test ./...
```

Run benchmarks:

```bash
go test -bench=. ./...
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../CONTRIBUTING.md) for details.

### Development Setup

1. Clone the repository
2. Install dependencies: `go mod download`
3. Run tests: `go test ./...`
4. Run linters: `golangci-lint run`

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](../LICENSE) file for details.

## References

- [BLS Signatures](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf)
- [SLIP-10: Universal HD Key Derivation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [secp256k1](https://www.secg.org/sec2-v2.pdf)
- [Lux Network Documentation](https://docs.lux.network)