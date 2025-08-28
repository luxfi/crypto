//go:build cgo && !liboqs
// +build cgo,!liboqs

package kem

import "errors"

// cgoAvailable returns false when liboqs is not installed
func cgoAvailable() bool {
	return false
}

// NewMLKEM768CGO returns an error when liboqs is not available
func NewMLKEM768CGO() (KEM, error) {
	return nil, errors.New("liboqs not installed, using pure Go implementation")
}

// NewMLKEM1024CGO returns an error when liboqs is not available
func NewMLKEM1024CGO() (KEM, error) {
	return nil, errors.New("liboqs not installed, using pure Go implementation")
}