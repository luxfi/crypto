// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package entropy

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// fixed is a source that returns the same bytes forever and claims to be well.
// It stands for "an attacker knows exactly what this contributes".
type fixed struct {
	name string
	b    byte
}

func (f fixed) Name() string  { return f.name }
func (f fixed) Health() error { return nil }
func (f fixed) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.b
	}
	return len(p), nil
}

// broken reports itself unhealthy.
type broken struct{ name string }

func (b broken) Name() string               { return b.name }
func (b broken) Health() error              { return ErrUnhealthy }
func (b broken) Read(p []byte) (int, error) { return 0, ErrUnhealthy }

func draw(t *testing.T, s Source, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(s, b); err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

// TestOneGoodSourceCarriesTheCombination is the property the whole design
// rests on: a source that contributes nothing cannot take anything away. It is
// what makes it safe to put an unproven device into a running deployment.
func TestOneGoodSourceCarriesTheCombination(t *testing.T) {
	// Every source but one is a constant the adversary knows.
	withKnown := Combine(fixed{"known-a", 0x00}, OS(), fixed{"known-b", 0xFF})
	alone := Combine(OS())

	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		for _, s := range []Source{withKnown, alone} {
			b := string(draw(t, s, 32))
			if seen[b] {
				t.Fatal("a draw repeated: the known sources are determining the output")
			}
			seen[b] = true
		}
	}
}

// And the converse: with no unpredictable source, the output is a function of
// what the adversary knows. This is the control — without it the test above
// would pass for a combiner that ignored its inputs entirely.
func TestKnownSourcesAloneGiveAPredictableResult(t *testing.T) {
	a := Combine(fixed{"a", 0x01}, fixed{"b", 0x02})
	b := Combine(fixed{"a", 0x01}, fixed{"b", 0x02})
	if !bytes.Equal(draw(t, a, 32), draw(t, b, 32)) {
		t.Fatal("two combinations of the same known sources disagreed")
	}
}

// TestLengthsKeepContributionsApart is tested against mix directly, because
// the ambiguity it prevents needs contributions of differing length and
// Combine draws a fixed amount from every source. "ab" then "c" and "a" then
// "bc" concatenate to the same bytes; without a length prefix they hash alike,
// and two deployments holding different things would derive one value.
func TestLengthsKeepContributionsApart(t *testing.T) {
	read := func(parts ...[]byte) []byte {
		out := make([]byte, 32)
		if _, err := io.ReadFull(mix(parts), out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := [][2][][]byte{
		{{[]byte("ab"), []byte("c")}, {[]byte("a"), []byte("bc")}},
		{{[]byte("abc")}, {[]byte("ab"), []byte("c")}},
		{{[]byte(""), []byte("x")}, {[]byte("x"), []byte("")}},
	}
	for _, c := range cases {
		if bytes.Equal(read(c[0]...), read(c[1]...)) {
			t.Fatalf("%q and %q mixed to one value", c[0], c[1])
		}
	}
}

// The same contributions must of course still give the same value, or the
// construction is not a function.
func TestMixIsAFunctionOfItsContributions(t *testing.T) {
	read := func() []byte {
		out := make([]byte, 32)
		if _, err := io.ReadFull(mix([][]byte{[]byte("ab"), []byte("c")}), out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if !bytes.Equal(read(), read()) {
		t.Fatal("the same contributions mixed to two different values")
	}
}

// A combination is only as usable as its least healthy member: a deployment
// told a source is broken should stop, not quietly continue on the rest while
// believing it has more sources than it has.
func TestAnUnhealthySourceFailsTheCombination(t *testing.T) {
	c := Combine(OS(), broken{"dead"})
	if err := c.Health(); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("health = %v, want unhealthy", err)
	}
	if _, err := c.Read(make([]byte, 32)); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("read from an unhealthy combination returned %v", err)
	}
}

func TestNoSourcesIsNotASource(t *testing.T) {
	if err := Combine().Health(); !errors.Is(err, ErrUnhealthy) {
		t.Fatal("a combination of nothing reported healthy")
	}
}

// TestRepetitionCountCatchesAStuckSource. The loudest failure a physical
// source has: it stops changing. The test must catch it within a few samples,
// because everything downstream will happily use the output.
func TestRepetitionCountCatchesAStuckSource(t *testing.T) {
	// 7.9 bits per byte is a near-ideal source; its cutoff is small.
	tst := newRepetitionCount(7.9)
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = tst.Observe(0x42)
	}
	if !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("a source stuck at one value was not caught: %v", err)
	}

	// A source that changes is left alone.
	tst.Reset()
	for i := 0; i < 10000; i++ {
		if err := tst.Observe(byte(i)); err != nil {
			t.Fatalf("a healthy source was failed at sample %d: %v", i, err)
		}
	}
}

// A failed test stays failed. A source that has stopped being random is not
// re-trusted by being asked again.
func TestAFailedTestStaysFailed(t *testing.T) {
	tst := newRepetitionCount(7.9)
	for i := 0; i < 100; i++ {
		_ = tst.Observe(0x42)
	}
	if err := tst.Observe(0x01); !errors.Is(err, ErrUnhealthy) {
		t.Fatal("a failed test recovered on a different sample")
	}
}

// TestAdaptiveProportionCatchesACollapsedSource. The quieter failure: the
// source still changes value, but draws from far fewer values than it claims.
// A repetition-count test never sees this.
func TestAdaptiveProportionCatchesACollapsedSource(t *testing.T) {
	tst := newAdaptiveProportion(7.9, adaptiveWindowOther)
	var err error
	// Alternate between two values: never repeats, but carries one bit.
	for i := 0; i < 4096 && err == nil; i++ {
		err = tst.Observe(byte(i % 2))
	}
	if !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("a source alternating between two values was not caught: %v", err)
	}
}

// The cutoffs must admit a healthy source. A test that fails everything proves
// nothing, and would take a working deployment down.
func TestHealthyRandomnessIsNotFailed(t *testing.T) {
	m := newMonitor(7.9, false)
	buf := make([]byte, 1<<16)
	if _, err := io.ReadFull(OS(), buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := m.observe(buf); err != nil {
		t.Fatalf("real randomness was declared unhealthy: %v", err)
	}
	if err := m.health(); err != nil {
		t.Fatalf("health after 65536 good samples: %v", err)
	}
}

// A source releases nothing until it has passed a run of samples, so one that
// comes up broken is refused rather than used once and then noticed.
func TestNothingIsReleasedBeforeStartupCompletes(t *testing.T) {
	m := newMonitor(7.9, false)
	if err := m.health(); !errors.Is(err, ErrUnhealthy) {
		t.Fatal("a source reported healthy before startup completed")
	}
	buf := make([]byte, startupSamples)
	if _, err := io.ReadFull(OS(), buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := m.observe(buf); err != nil {
		t.Fatalf("startup: %v", err)
	}
	if err := m.health(); err != nil {
		t.Fatalf("health after startup: %v", err)
	}
}

// TestCutoffsMatchTheClaimedEntropy. The cutoff is what ties a test to the
// assessment behind a device: a source claiming less per sample must be
// allowed longer runs before it is called broken, or every honest low-rate
// device is refused.
func TestCutoffsMatchTheClaimedEntropy(t *testing.T) {
	strong := newRepetitionCount(8.0).cutoff
	weak := newRepetitionCount(1.0).cutoff
	if weak <= strong {
		t.Fatalf("a source claiming 1 bit/sample got cutoff %d, one claiming 8 got %d: "+
			"a weaker claim must permit longer runs", weak, strong)
	}
	// The stated form: C = 1 + ceil(40 / h).
	for _, h := range []float64{1, 2, 4, 7.9, 8} {
		want := 1 + int(math.Ceil(40.0/h))
		if got := newRepetitionCount(h).cutoff; got != want {
			t.Errorf("h=%v: cutoff %d, want %d", h, got, want)
		}
	}
}

// The adaptive cutoff must sit above what a healthy source reaches and below
// what a collapsed one does, or it is either useless or hostile.
func TestAdaptiveCutoffIsBetweenHealthyAndCollapsed(t *testing.T) {
	c := binomialCutoff(adaptiveWindowOther, math.Exp2(-7.9))
	if c <= 1 {
		t.Fatalf("cutoff %d would fail any repeated value at all", c)
	}
	if c >= adaptiveWindowOther {
		t.Fatalf("cutoff %d cannot be reached inside the window", c)
	}
	// A fair byte source repeats a given value ~2 times in 512; a collapsed
	// one repeats it ~256 times. The cutoff belongs between.
	if c > adaptiveWindowOther/4 {
		t.Fatalf("cutoff %d is too loose to catch a collapse", c)
	}
}

// TestDeviceRefusesAStuckDevice: a file of one repeated byte stands for a
// source that has stuck. It must be refused at open rather than accepted and
// used.
func TestDeviceRefusesAStuckDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stuck")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x5A}, 1<<16), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Device(path, 7.9); err == nil {
		t.Fatal("a device stuck at one value was accepted")
	}
}

// And a device that behaves is opened, conditioned and read.
func TestDeviceReadsAndConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "good")
	buf := make([]byte, 1<<20)
	if _, err := io.ReadFull(OS(), buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Device(path, 7.9)
	if err != nil {
		t.Fatalf("open a healthy device: %v", err)
	}
	if err := d.Health(); err != nil {
		t.Fatalf("health: %v", err)
	}
	out := draw(t, d, 32)
	// Whatever else it is, it must not be the raw file.
	if bytes.Contains(buf[:4096], out) {
		t.Fatal("device output appears verbatim in the raw samples: it was not conditioned")
	}
}

func TestDeviceRefusesAnImpossibleEntropyClaim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d")
	if err := os.WriteFile(path, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, h := range []float64{0, -1, 8.1, 100} {
		if _, err := Device(path, h); err == nil {
			t.Fatalf("a claim of %v bits per byte was accepted", h)
		}
	}
}
