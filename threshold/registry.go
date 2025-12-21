// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"sync"
)

// registry holds all registered threshold schemes.
var (
	registry     = make(map[SchemeID]Scheme)
	registryLock sync.RWMutex
)

// RegisterScheme registers a threshold signature scheme.
// This should be called during init() by scheme implementations.
// Panics if the scheme ID is already registered.
func RegisterScheme(scheme Scheme) {
	registryLock.Lock()
	defer registryLock.Unlock()

	id := scheme.ID()
	if _, exists := registry[id]; exists {
		panic("threshold: scheme " + id.String() + " already registered")
	}
	registry[id] = scheme
}

// GetScheme returns a registered threshold scheme by ID.
func GetScheme(id SchemeID) (Scheme, error) {
	registryLock.RLock()
	defer registryLock.RUnlock()

	scheme, exists := registry[id]
	if !exists {
		return nil, ErrSchemeNotFound
	}
	return scheme, nil
}

// ListSchemes returns all registered scheme IDs.
func ListSchemes() []SchemeID {
	registryLock.RLock()
	defer registryLock.RUnlock()

	ids := make([]SchemeID, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	return ids
}

// HasScheme returns true if the scheme is registered.
func HasScheme(id SchemeID) bool {
	registryLock.RLock()
	defer registryLock.RUnlock()

	_, exists := registry[id]
	return exists
}

// MustGetScheme returns a registered scheme or panics.
func MustGetScheme(id SchemeID) Scheme {
	scheme, err := GetScheme(id)
	if err != nil {
		panic("threshold: " + err.Error())
	}
	return scheme
}

// SchemeInfo provides metadata about a threshold scheme.
type SchemeInfo struct {
	ID             SchemeID
	Name           string
	Description    string
	PostQuantum    bool
	NonInteractive bool
	KeyShareSize   int
	SignatureSize  int
	DKGRounds      int
	SigningRounds  int
}

// GetSchemeInfo returns information about a registered scheme.
func GetSchemeInfo(id SchemeID) (*SchemeInfo, error) {
	scheme, err := GetScheme(id)
	if err != nil {
		return nil, err
	}

	return &SchemeInfo{
		ID:             id,
		Name:           scheme.Name(),
		PostQuantum:    id.IsPostQuantum(),
		NonInteractive: id.SupportsNonInteractive(),
		KeyShareSize:   scheme.KeyShareSize(),
		SignatureSize:  scheme.SignatureSize(),
	}, nil
}

// AllSchemeInfo returns information about all registered schemes.
func AllSchemeInfo() []*SchemeInfo {
	registryLock.RLock()
	defer registryLock.RUnlock()

	infos := make([]*SchemeInfo, 0, len(registry))
	for id, scheme := range registry {
		infos = append(infos, &SchemeInfo{
			ID:             id,
			Name:           scheme.Name(),
			PostQuantum:    id.IsPostQuantum(),
			NonInteractive: id.SupportsNonInteractive(),
			KeyShareSize:   scheme.KeyShareSize(),
			SignatureSize:  scheme.SignatureSize(),
		})
	}
	return infos
}
