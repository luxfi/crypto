// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// gen produces the pinned KAT vector files (vectors_mldsa{44,65,87}.go)
// consumed by package kats. Invocation:
//
//	go run github.com/luxfi/crypto/pq/mldsa/kats/internal/gen
//
// The generated source is deterministic — the same fixed seeds in
// the same order produce byte-identical output on every run, on
// every architecture. The Makefile target `make gen_kats` invokes
// this binary then re-runs the test suite to confirm the freshly-
// written vectors still pass.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"

	"github.com/luxfi/crypto/pq/mldsa/mldsa44"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/crypto/pq/mldsa/mldsa87"
)

// vectorSpec is the input recipe for one KAT vector. A spec is
// deterministically reduced to a Vector by running it through the
// per-parameter-set NewKeyFromSeed + Sign code paths.
type vectorSpec struct {
	seedByte byte   // every byte of the 32-byte ξ is set to seedByte
	msg      string // message under test (string lit for readability)
	ctx      string // domain-separation context; "" means nil ctx
}

// specs lists the synthetic KAT recipes shared across all three
// parameter sets. The order is meaningful (Count = index) and MUST
// NOT be reordered without regenerating the pinned files.
var specs = []vectorSpec{
	{0x00, "", ""},
	{0xFF, "FIPS204 KAT all-ones seed", "LUX/KAT/v1"},
	{0x42, "deterministic ML-DSA signature", ""},
	{0xA5, "context-bound signature", "LUX/KAT/ctx/v1"},
	{0x5A, "long message" + strings.Repeat("/", 64), "LUX/KAT/longmsg/v1"},
}

func main() {
	out := flag.String("out", "", "output directory (default: package dir of kats)")
	flag.Parse()

	outDir := *out
	if outDir == "" {
		// Resolve relative to this generator's source file.
		// CWD at `go run` time = caller's CWD, so default to
		// the canonical relative path from the repo root.
		outDir = "pq/mldsa/kats"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		die("mkdir %s: %v", outDir, err)
	}

	if err := genMLDSA44(filepath.Join(outDir, "vectors_mldsa44.go")); err != nil {
		die("mldsa44: %v", err)
	}
	if err := genMLDSA65(filepath.Join(outDir, "vectors_mldsa65.go")); err != nil {
		die("mldsa65: %v", err)
	}
	if err := genMLDSA87(filepath.Join(outDir, "vectors_mldsa87.go")); err != nil {
		die("mldsa87: %v", err)
	}
}

func genMLDSA44(path string) error {
	var buf bytes.Buffer
	writeHeader(&buf, "mldsa44", "ML-DSA-44 (NIST Level 2)")
	for i, s := range specs {
		seed := bytes.Repeat([]byte{s.seedByte}, mldsa44.SeedSize)
		pk, sk, err := mldsa44.NewKeyFromSeed(seed)
		if err != nil {
			return fmt.Errorf("spec %d NewKeyFromSeed: %w", i, err)
		}
		var ctx []byte
		if s.ctx != "" {
			ctx = []byte(s.ctx)
		}
		sig, err := mldsa44.Sign(sk, []byte(s.msg), ctx, false)
		if err != nil {
			return fmt.Errorf("spec %d Sign: %w", i, err)
		}
		writeVector(&buf, i, seed, []byte(s.msg), ctx, pk.Bytes(), sk.Bytes(), sig)
	}
	writeFooter(&buf, "mldsa44")
	return writeFormatted(path, buf.Bytes())
}

func genMLDSA65(path string) error {
	var buf bytes.Buffer
	writeHeader(&buf, "mldsa65", "ML-DSA-65 (NIST Level 3 — recommended)")
	for i, s := range specs {
		seed := bytes.Repeat([]byte{s.seedByte}, mldsa65.SeedSize)
		pk, sk, err := mldsa65.NewKeyFromSeed(seed)
		if err != nil {
			return fmt.Errorf("spec %d NewKeyFromSeed: %w", i, err)
		}
		var ctx []byte
		if s.ctx != "" {
			ctx = []byte(s.ctx)
		}
		sig, err := mldsa65.Sign(sk, []byte(s.msg), ctx, false)
		if err != nil {
			return fmt.Errorf("spec %d Sign: %w", i, err)
		}
		writeVector(&buf, i, seed, []byte(s.msg), ctx, pk.Bytes(), sk.Bytes(), sig)
	}
	writeFooter(&buf, "mldsa65")
	return writeFormatted(path, buf.Bytes())
}

func genMLDSA87(path string) error {
	var buf bytes.Buffer
	writeHeader(&buf, "mldsa87", "ML-DSA-87 (NIST Level 5)")
	for i, s := range specs {
		seed := bytes.Repeat([]byte{s.seedByte}, mldsa87.SeedSize)
		pk, sk, err := mldsa87.NewKeyFromSeed(seed)
		if err != nil {
			return fmt.Errorf("spec %d NewKeyFromSeed: %w", i, err)
		}
		var ctx []byte
		if s.ctx != "" {
			ctx = []byte(s.ctx)
		}
		sig, err := mldsa87.Sign(sk, []byte(s.msg), ctx, false)
		if err != nil {
			return fmt.Errorf("spec %d Sign: %w", i, err)
		}
		writeVector(&buf, i, seed, []byte(s.msg), ctx, pk.Bytes(), sk.Bytes(), sig)
	}
	writeFooter(&buf, "mldsa87")
	return writeFormatted(path, buf.Bytes())
}

// writeHeader emits the file preamble: copyright, // Code generated
// marker (so editor tooling flags it as machine-written), package
// statement, and the start of the per-parameter-set vectors slice.
func writeHeader(buf *bytes.Buffer, paramSet, label string) {
	fmt.Fprintln(buf, "// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.")
	fmt.Fprintln(buf, "// See the file LICENSE for licensing terms.")
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "// Code generated by pq/mldsa/kats/internal/gen. DO NOT EDIT.")
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "package kats")
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "// Vectors%s holds the synthetic Known-Answer-Test vectors for the\n",
		strings.ToUpper(paramSet[len("mldsa"):]))
	fmt.Fprintf(buf, "// %s parameter set. Regenerate via `make gen_kats`.\n", label)
	fmt.Fprintf(buf, "var Vectors%s = []Vector{\n", strings.ToUpper(paramSet[len("mldsa"):]))
}

// writeFooter emits the closing brace of the slice literal.
func writeFooter(buf *bytes.Buffer, _ string) {
	fmt.Fprintln(buf, "}")
}

// writeVector emits one Vector{...} struct literal. Each byte slice
// is emitted via hexBytes() for compact, diff-friendly output.
func writeVector(buf *bytes.Buffer, count int, seed, msg, ctx, pk, sk, sig []byte) {
	fmt.Fprintln(buf, "\t{")
	fmt.Fprintf(buf, "\t\tCount: %d,\n", count)
	fmt.Fprintf(buf, "\t\tSeed: %s,\n", hexBytes(seed))
	fmt.Fprintf(buf, "\t\tMsg: %s,\n", hexBytes(msg))
	fmt.Fprintf(buf, "\t\tCtx: %s,\n", hexBytes(ctx))
	fmt.Fprintf(buf, "\t\tPublicKey: %s,\n", hexBytes(pk))
	fmt.Fprintf(buf, "\t\tPrivateKey: %s,\n", hexBytes(sk))
	fmt.Fprintf(buf, "\t\tSignature: %s,\n", hexBytes(sig))
	fmt.Fprintln(buf, "\t},")
}

// hexBytes renders a []byte slice as a Go literal. nil is preserved
// as `nil` (not `[]byte{}`) so the test can distinguish the two.
// Non-nil slices use the `mustDecodeHex("...")` helper defined in
// vectors_helpers.go for compact source output.
func hexBytes(b []byte) string {
	if b == nil {
		return "nil"
	}
	if len(b) == 0 {
		return "[]byte{}"
	}
	return fmt.Sprintf("mustDecodeHex(%q)", hexString(b))
}

func hexString(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}

func writeFormatted(path string, src []byte) error {
	formatted, err := format.Source(src)
	if err != nil {
		// Write the unformatted source for diagnosis, then fail.
		_ = os.WriteFile(path+".unformatted", src, 0o644)
		return fmt.Errorf("gofmt: %w (unformatted source written to %s.unformatted)", err, path)
	}
	return os.WriteFile(path, formatted, 0o644)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen: "+format+"\n", args...)
	os.Exit(1)
}
