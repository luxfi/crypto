#!/bin/bash
# Build script for SLH-DSA using Sloth high-performance implementation
# Copyright (C) 2025, Lux Industries Inc.

set -e

echo "Building SLH-DSA with Sloth high-performance library..."

# Create C directory if it doesn't exist
mkdir -p c

cd c

# Clone Sloth if not already present
if [ ! -d "sloth" ]; then
    echo "Cloning Sloth repository..."
    git clone https://github.com/slh-dsa/sloth.git
    cd sloth
else
    echo "Updating Sloth repository..."
    cd sloth
    git pull
fi

# Build Sloth library
echo "Building Sloth library..."

# Build all variants with AVX2 optimizations
mkdir -p build
cd build

# Configure with CMake for maximum performance
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_AVX2=ON \
    -DENABLE_SHA_NI=ON \
    -DBUILD_SHARED_LIBS=OFF

# Build the library
make -j$(nproc)

# Copy the static library to parent directory
cp libsloth.a ../../libslhdsa.a

echo "SLH-DSA library built successfully!"

# Build test program to verify
cd ../..
cat > test_slhdsa.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include "sloth/include/slh_dsa.h"

int main() {
    printf("SLH-DSA Sloth library test\n");
    printf("SHA2-128s public key size: %d\n", SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
    printf("SHA2-128s signature size: %d\n", SLHDSA_SHA2_128S_SIGNATURE_BYTES);
    printf("SHA2-256s public key size: %d\n", SLHDSA_SHA2_256S_PUBLIC_KEY_BYTES);
    printf("SHA2-256s signature size: %d\n", SLHDSA_SHA2_256S_SIGNATURE_BYTES);
    
    // Test key generation
    unsigned char pk[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES];
    unsigned char sk[SLHDSA_SHA2_128S_SECRET_KEY_BYTES];
    
    if (slhdsa_sha2_128s_keypair(pk, sk) == 0) {
        printf("Key generation successful!\n");
    } else {
        printf("Key generation failed!\n");
        return 1;
    }
    
    // Test signing
    const char *msg = "Test message";
    unsigned char sig[SLHDSA_SHA2_128S_SIGNATURE_BYTES];
    size_t siglen;
    
    if (slhdsa_sha2_128s_sign(sig, &siglen, (unsigned char*)msg, strlen(msg), sk) == 0) {
        printf("Signing successful! Signature size: %zu\n", siglen);
    } else {
        printf("Signing failed!\n");
        return 1;
    }
    
    // Test verification
    if (slhdsa_sha2_128s_verify(sig, siglen, (unsigned char*)msg, strlen(msg), pk) == 0) {
        printf("Verification successful!\n");
    } else {
        printf("Verification failed!\n");
        return 1;
    }
    
    printf("All tests passed!\n");
    return 0;
}
EOF

# Compile test program
gcc -o test_slhdsa test_slhdsa.c -L. -lslhdsa -lsloth/build/libsloth.a -lcrypto -O3 -march=native

# Run test
echo "Running test program..."
./test_slhdsa

echo "Build complete! Libraries created:"
echo "  - libslhdsa.a (static library for CGO)"
echo ""
echo "To use with CGO:"
echo "  CGO_ENABLED=1 go build"
echo ""
echo "Performance notes:"
echo "  - Sloth provides 3-10x speedup over reference implementation"
echo "  - AVX2 optimizations enabled for modern CPUs"
echo "  - Fast variants (128f, 192f, 256f) optimized for signing speed"