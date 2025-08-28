//go:build !cgo
// +build !cgo

package kem

import "errors"

// cgoAvailable returns false when CGO is disabled
func cgoAvailable() bool {
	return false
}

// NewMLKEM768CGO returns an error when CGO is disabled
func NewMLKEM768CGO() (KEM, error) {
	return nil, errors.New("CGO disabled, using pure Go implementation")
}

// NewMLKEM1024CGO returns an error when CGO is disabled
func NewMLKEM1024CGO() (KEM, error) {
	return nil, errors.New("CGO disabled, using pure Go implementation")
}