# Makefile for ML-DSA (Dilithium) C library
# Copyright (C) 2025, Lux Industries Inc.

CC = gcc
CFLAGS = -Wall -Wextra -O3 -fPIC -I./ref
LDFLAGS = -shared

# Source files from reference implementation
SOURCES = ref/fips202.c \
          ref/ntt.c \
          ref/packing.c \
          ref/poly.c \
          ref/polyvec.c \
          ref/reduce.c \
          ref/rounding.c \
          ref/sign.c \
          ref/symmetric-shake.c \
          ref/randombytes.c

OBJECTS = $(SOURCES:.c=.o)
TARGET = libmldsa.a

# Default to Dilithium3 (ML-DSA-65)
DILITHIUM_MODE ?= 3

all: $(TARGET)

$(TARGET): $(OBJECTS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=$(DILITHIUM_MODE) -c $< -o $@

shared: $(OBJECTS)
	$(CC) $(LDFLAGS) -o libmldsa.so $^

clean:
	rm -f $(OBJECTS) $(TARGET) libmldsa.so

test: $(TARGET)
	$(CC) -o test_mldsa ref/test/test_dilithium.c -L. -lmldsa $(CFLAGS)
	./test_mldsa

.PHONY: all clean test shared