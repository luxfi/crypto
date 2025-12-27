//go:build darwin
// +build darwin

// Suppress duplicate library warnings on macOS
// This file is intentionally left with minimal content as the suppression
// is handled via build flags or environment variables
package luxlink

import "C"
