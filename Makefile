# Lux Post-Quantum Cryptography Makefile

.PHONY: all test bench clean fmt lint install-deps verify build gen_kats dist

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=gofmt
GOMOD=$(GOCMD) mod

# Packages
PACKAGES=./mlkem/... ./mldsa/... ./slhdsa/... ./lamport/... ./precompile/...
ALL_PACKAGES=./...

# Build variables
CGO_ENABLED ?= 1
GOFLAGS ?=

all: fmt lint test

# Install dependencies
install-deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	$(GOFMT) -s -w .
	@echo "✅ Code formatted"

# Lint code
lint:
	@echo "🔍 Linting code..."
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6; \
	fi
	golangci-lint run --timeout=5m || true
	@echo "✅ Linting complete"

# Run tests (exclude cgo/ when native C libs not installed, timeout per package)
test:
	@echo "Running tests..."
	@if pkg-config --exists lux-crypto lux-gpu 2>/dev/null; then \
		CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -count=1 -timeout 600s $(ALL_PACKAGES); \
	else \
		CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -count=1 -timeout 600s $$($(GOCMD) list ./... | grep -v /cgo); \
	fi
	@echo "Tests complete"

# Run tests with coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	CGO_ENABLED=$(CGO_ENABLED) $(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic $(ALL_PACKAGES)
	@echo "Coverage report generated: coverage.out"
	@go tool cover -func=coverage.out
	@echo "✅ Coverage analysis complete"

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	CGO_ENABLED=1 $(GOTEST) -bench=. -benchmem -run=^$ $(ALL_PACKAGES)
	@echo "✅ Benchmarks complete"

# Build all packages
build:
	@echo "🔨 Building packages..."
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -v $(ALL_PACKAGES)
	@echo "✅ Build complete"

# The C shared library, for the callers that are not Go: Rust, Python, C++.
#
# On macOS a shared library carries the name its consumers will ask the loader
# for, and `go build -buildmode=c-shared` writes the bare file name. A binary
# linked against that asks for "libluxcrypto.dylib" with no directory, which the
# loader looks for beside the process and nowhere else — an -rpath in the
# consumer is never consulted, because the request it would answer was never
# made. Naming it @rpath/... is what lets a consumer say where the library is
# and be believed. Linux resolves by SONAME and needs nothing extra.
DIST     ?= dist
ifeq ($(shell uname -s),Darwin)
LIBNAME   = libluxcrypto.dylib
LDFLAGS_SHARED = -ldflags "-extldflags '-Wl,-install_name,@rpath/$(LIBNAME)'"
else
LIBNAME   = libluxcrypto.so
LDFLAGS_SHARED =
endif

dist:
	@echo "🔨 Building libluxcrypto.a and $(LIBNAME)..."
	@mkdir -p $(DIST)
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-archive \
		-o $(DIST)/libluxcrypto.a ./bindings/cabi/
	CGO_ENABLED=1 $(GOBUILD) -buildmode=c-shared $(LDFLAGS_SHARED) \
		-o $(DIST)/$(LIBNAME) ./bindings/cabi/
	@echo "✅ $(DIST)/libluxcrypto.a $(DIST)/$(LIBNAME)"

# Verify module
verify:
	@echo "✔️ Verifying module..."
	$(GOMOD) verify
	@echo "✅ Module verified"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCMD) clean
	rm -f coverage.out
	@echo "✅ Clean complete"

# Regenerate KAT vector files for crypto/pq/mldsa.
#
# The generator is deterministic: a second run produces byte-identical
# output. The kats package itself has a TestRegen_Deterministic guard
# that asserts the checked-in vectors_mldsa{44,65,87}.go files match a
# fresh `go run`. After running this target, commit the regenerated
# files; the test suite then proves they round-trip.
gen_kats:
	@echo "Regenerating ML-DSA KAT vectors..."
	GOWORK=off $(GOCMD) run ./pq/mldsa/kats/internal/gen -out pq/mldsa/kats
	@echo "Validating regenerated vectors..."
	GOWORK=off $(GOTEST) -count=1 ./pq/mldsa/kats/...
	@echo "✅ KAT vectors regenerated and validated"

# Install CI tools
install-tools:
	@echo "🛠️ Installing CI tools..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
	@echo "✅ Tools installed"

# Help
help:
	@echo "Lux Post-Quantum Cryptography Makefile"
	@echo "Usage: make [target]"
