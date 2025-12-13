# AI Assistant Knowledge Base

**Last Updated**: 2025-08-15
**Project**: crypto
**Organization**: lux

## Project Overview

This repository contains the Lux post-quantum cryptography implementation.

## Essential Commands

### Development
```bash
# Run tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make bench

# Full CI suite
make ci
```

## Architecture

The Lux crypto library provides comprehensive post-quantum cryptography support including:
- ML-KEM (Module-Lattice-based Key Encapsulation Mechanism)
- ML-DSA (Module-Lattice-Based Digital Signature Algorithm)  
- SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- BLS signatures
- Ringtail ring signatures
- SHAKE hash functions

## Key Technologies

- Go 1.21+
- Cloudflare CIRCL library for post-quantum cryptography
- CGO optimizations for performance
- Comprehensive test coverage

## Development Workflow

1. Implement cryptographic algorithms using Cloudflare CIRCL
2. Add comprehensive unit tests
3. Implement precompiled contracts for EVM integration
4. Run full test suite and benchmarks
5. Update documentation

## Context for All AI Assistants

This file (`LLM.md`) serves as the central knowledge base for AI assistants working on this project.

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit AI-generated summary files
3. **NEVER** create redundant documentation - update existing files
4. Follow Go coding standards and best practices
5. Ensure all implementations are properly tested

---

**Note**: This file serves as the single source of truth for all AI assistants working on this project.
