# Crypto Consolidation Migration Plan

## Overview
Consolidate all cryptographic implementations from various packages into `/Users/z/work/lux/crypto` to eliminate duplication and ensure consistency.

## Current Situation

### Duplicate Implementations Found

1. **BLS Signatures**
   - `/Users/z/work/lux/node/utils/crypto/bls/` - Uses `supranational/blst` (C library, high performance)
   - `/Users/z/work/lux/crypto/bls/` - Uses `cloudflare/circl` (Pure Go)
   - **Decision**: Keep BLST implementation for performance, move to crypto package

2. **SECP256K1**
   - `/Users/z/work/lux/node/utils/crypto/secp256k1/` - Full implementation
   - `/Users/z/work/lux/crypto/secp256k1/` - Existing implementation
   - **Decision**: Merge best features from both

3. **Keychain & Ledger**
   - `/Users/z/work/lux/node/utils/crypto/keychain/` - Key management
   - `/Users/z/work/lux/node/utils/crypto/ledger/` - Hardware wallet support
   - **Decision**: Move to crypto package as-is

## Migration Steps

### Phase 1: BLS Consolidation

1. **Create new BLS structure in crypto**
   ```
   /Users/z/work/lux/crypto/bls/
   ├── bls.go           (BLST-based implementation from node)
   ├── bls_circl.go     (CIRCL-based for compatibility)
   ├── interface.go     (Common interface)
   └── bls_test.go      (Unified tests)
   ```

2. **Merge implementations**
   - Primary: BLST for performance
   - Fallback: CIRCL for pure Go environments
   - Build tags to select implementation

### Phase 2: SECP256K1 Consolidation

1. **Merge node SECP256K1 into crypto**
   - Keep best test coverage
   - Maintain API compatibility
   - Add RFC6979 deterministic nonce support

### Phase 3: Move Supporting Infrastructure

1. **Keychain**: `/Users/z/work/lux/crypto/keychain/`
2. **Ledger**: `/Users/z/work/lux/crypto/ledger/`
3. **Common utilities**: Extract and consolidate

### Phase 4: Extract Common Crypto from Other Packages

1. **From threshold package**:
   - Blake3 hash → `/Users/z/work/lux/crypto/hashing/blake3/`
   - Keep threshold-specific logic in place

2. **From MPC package**:
   - Age encryption utilities → `/Users/z/work/lux/crypto/encryption/age/`
   - Ed25519 wrappers → `/Users/z/work/lux/crypto/ed25519/`

### Phase 5: Update Import Paths

All imports need to be updated from:
```go
"github.com/luxfi/node/utils/crypto/bls"
"github.com/luxfi/node/utils/crypto/secp256k1"
```

To:
```go
"github.com/luxfi/crypto/bls"
"github.com/luxfi/crypto/secp256k1"
```

## Files Requiring Import Updates

### Consensus Package
- `/Users/z/work/lux/consensus/snowman/validator.go`
- `/Users/z/work/lux/consensus/ctx.go`

### Node Package
- `/Users/z/work/lux/node/vms/platformvm/signer/*.go`
- `/Users/z/work/lux/node/wallet/subnet/primary/*.go`
- `/Users/z/work/lux/node/staking/*.go`

## Implementation Plan

### Step 1: Create Compatibility Layer
Create interfaces that both implementations satisfy to ensure smooth migration.

### Step 2: Move and Test
1. Copy node crypto to crypto package
2. Update imports in crypto package
3. Run tests to ensure functionality
4. Update external imports one package at a time

### Step 3: Remove Duplicates
Once all imports are updated and tests pass, remove the original implementations from node.

## Testing Strategy

1. **Unit Tests**: Ensure all existing tests pass
2. **Integration Tests**: Test with consensus and node packages
3. **Performance Tests**: Verify no performance regression
4. **Compatibility Tests**: Ensure API compatibility

## Risk Mitigation

1. **Backup**: Keep original implementations until migration is complete
2. **Gradual Migration**: Update one package at a time
3. **Feature Flags**: Use build tags to switch implementations if needed
4. **Rollback Plan**: Git tags at each migration phase