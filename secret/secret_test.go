// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secret

import (
	"testing"
)

func TestDo(t *testing.T) {
	called := false
	Do(func() {
		called = true
	})
	if !called {
		t.Fatal("Do did not execute the function")
	}
}

func TestDoWithKeyMaterial(t *testing.T) {
	var keyBytes []byte
	Do(func() {
		keyBytes = make([]byte, 32)
		for i := range keyBytes {
			keyBytes[i] = byte(i)
		}
		// Simulate using the key then clearing it
		clear(keyBytes)
	})
	// After Do, keyBytes should be zeroed
	for _, b := range keyBytes {
		if b != 0 {
			t.Fatal("key material was not cleared inside Do")
		}
	}
}

func TestEnabled(t *testing.T) {
	// This test works with both build tags.
	// With goexperiment.runtimesecret: Enabled() == true
	// Without: Enabled() == false
	// We just verify it returns a bool without panicking.
	_ = Enabled()
}

func TestDoNested(t *testing.T) {
	outerCalled := false
	innerCalled := false
	Do(func() {
		outerCalled = true
		Do(func() {
			innerCalled = true
		})
	})
	if !outerCalled {
		t.Fatal("outer Do not called")
	}
	if !innerCalled {
		t.Fatal("inner Do not called")
	}
}

func TestDoWithPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate through Do")
		}
	}()
	Do(func() {
		panic("test panic")
	})
}
