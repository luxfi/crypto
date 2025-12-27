//go:build cgo
// +build cgo

// Consolidated cgo wrapper to avoid duplicate linking
package gpu

/*
#cgo pkg-config: lux-all
#include <lux/crypto/crypto.h>
*/
import "C"

// This file consolidates all cgo dependencies to avoid duplicate library warnings
// Individual packages should import this instead of having their own cgo directives
