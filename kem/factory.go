package kem

import (
	"os"
	"sync"
)

var (
	// useCGO determines if CGO implementations should be used
	useCGO     bool
	useCGOOnce sync.Once
)

// shouldUseCGO checks if CGO implementations are available and should be used
func shouldUseCGO() bool {
	useCGOOnce.Do(func() {
		// Check if CGO_ENABLED environment variable is set to 0
		if os.Getenv("CGO_ENABLED") == "0" {
			useCGO = false
			return
		}
		
		// Default to CGO if available (detected at build time)
		useCGO = cgoAvailable()
	})
	return useCGO
}

// NewMLKEM768 creates a new ML-KEM-768 instance
// It automatically selects CGO or pure Go implementation based on availability
func NewMLKEM768() (KEM, error) {
	if shouldUseCGO() {
		if impl, err := NewMLKEM768CGO(); err == nil {
			return impl, nil
		}
		// Fall back to pure Go if CGO fails
	}
	return newMLKEM768PureGo()
}

// NewMLKEM1024 creates a new ML-KEM-1024 instance
// It automatically selects CGO or pure Go implementation based on availability
func NewMLKEM1024() (KEM, error) {
	if shouldUseCGO() {
		if impl, err := NewMLKEM1024CGO(); err == nil {
			return impl, nil
		}
		// Fall back to pure Go if CGO fails
	}
	return newMLKEM1024PureGo()
}

// NewX25519Factory creates a new X25519 instance with error handling
func NewX25519Factory() (KEM, error) {
	// X25519 always uses pure Go implementation for now
	return newX25519PureGo()
}

// NewHybrid creates a new hybrid KEM (X25519 + ML-KEM-768)
func NewHybrid() (KEM, error) {
	x25519, err := NewX25519Factory()
	if err != nil {
		return nil, err
	}
	
	mlkem, err := NewMLKEM768()
	if err != nil {
		return nil, err
	}
	
	return newHybridKEM(x25519, mlkem)
}

// newMLKEM768PureGo creates a pure Go ML-KEM-768 implementation
func newMLKEM768PureGo() (KEM, error) {
	return &MLKEM768Impl{}, nil
}

// newMLKEM1024PureGo creates a pure Go ML-KEM-1024 implementation
func newMLKEM1024PureGo() (KEM, error) {
	return &MLKEM1024Impl{}, nil
}

// newX25519PureGo creates a pure Go X25519 implementation
func newX25519PureGo() (KEM, error) {
	return NewX25519(), nil
}

// newHybridKEM creates a hybrid KEM from two KEMs
func newHybridKEM(classical, pq KEM) (KEM, error) {
	return &HybridKEMImpl{
		x25519: classical,
		mlkem:  pq,
	}, nil
}