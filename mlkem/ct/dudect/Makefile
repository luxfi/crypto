# Lux ML-KEM-768 constant-time analysis harness -- dudect bridge.
#
# Builds the cgo shim libraries (libmlkem_keygen, libmlkem_encaps,
# libmlkem_decaps) and links the C dudect harnesses against them.
#
# Prereqs (run once):
#   ./fetch.sh           # pulls dudect.h at the pinned commit
#
# Build:
#   make                 # all three
#   make keygen          # just keygen
#   make encaps          # just encaps
#   make decaps          # just decaps
#
# Run:
#   ./dudect_keygen      # smoke test
#   ./dudect_encaps      # smoke test
#   ./dudect_decaps      # smoke test (CT-CRITICAL)
#
# Full submission run (10^9 samples on a pinned-CPU quiet host):
#   DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_decaps

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    SHLIB_EXT := dylib
    RPATH_FLAG := -Wl,-rpath,@loader_path
else
    SHLIB_EXT := so
    RPATH_FLAG := -Wl,-rpath,'$$ORIGIN'
endif

REPO_ROOT := $(shell cd ../.. && pwd)
DUDECT_HDR := dudect/src/dudect.h

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wno-unused-parameter -I. -Idudect/src
LDFLAGS ?=
LDLIBS  := -lm

ifeq ($(UNAME_M),arm64)
    CFLAGS += -include dudect_compat.h
endif
ifeq ($(UNAME_M),aarch64)
    CFLAGS += -include dudect_compat.h
endif

GO     ?= go
GOENV  := GOWORK=off CGO_ENABLED=1

.PHONY: all keygen encaps decaps clean check-dudect

all: keygen encaps decaps

libmlkem_keygen.$(SHLIB_EXT): keygen_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags mlkem_keygen_ct \
		-o libmlkem_keygen.$(SHLIB_EXT) \
		./keygen_ct.go

libmlkem_encaps.$(SHLIB_EXT): encaps_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags mlkem_encaps_ct \
		-o libmlkem_encaps.$(SHLIB_EXT) \
		./encaps_ct.go

libmlkem_decaps.$(SHLIB_EXT): decaps_ct.go check-dudect
	$(GOENV) $(GO) build -buildmode=c-shared \
		-tags mlkem_decaps_ct \
		-o libmlkem_decaps.$(SHLIB_EXT) \
		./decaps_ct.go

dudect_keygen: dudect_keygen.c libmlkem_keygen.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_keygen dudect_keygen.c \
		-L. -lmlkem_keygen $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_encaps: dudect_encaps.c libmlkem_encaps.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_encaps dudect_encaps.c \
		-L. -lmlkem_encaps $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

dudect_decaps: dudect_decaps.c libmlkem_decaps.$(SHLIB_EXT) $(DUDECT_HDR)
	$(CC) $(CFLAGS) -o dudect_decaps dudect_decaps.c \
		-L. -lmlkem_decaps $(LDFLAGS) $(LDLIBS) $(RPATH_FLAG)

keygen: dudect_keygen
encaps: dudect_encaps
decaps: dudect_decaps

check-dudect:
	@if [ ! -f $(DUDECT_HDR) ]; then \
		echo "==> dudect.h missing -- run ./fetch.sh"; \
		exit 1; \
	fi

clean:
	rm -f dudect_keygen dudect_encaps dudect_decaps
	rm -f libmlkem_keygen.$(SHLIB_EXT) libmlkem_keygen.h
	rm -f libmlkem_encaps.$(SHLIB_EXT) libmlkem_encaps.h
	rm -f libmlkem_decaps.$(SHLIB_EXT) libmlkem_decaps.h
