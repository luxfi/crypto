# Post-Quantum Cryptography Integration Analysis for Lux Network

## Current State of Integration

### What's Actually Implemented

1. **Post-Quantum Crypto Libraries** ✅
   - ML-KEM (FIPS 203) - Key encapsulation
   - ML-DSA (FIPS 204) - Digital signatures (Dilithium)
   - SLH-DSA (FIPS 205) - Hash-based signatures (SPHINCS+)
   - Located in `/crypto/mlkem`, `/crypto/mldsa`, `/crypto/slhdsa`

2. **Precompile Infrastructure** ✅
   - Framework exists in `/crypto/precompile/`
   - Address ranges reserved: 0x0110-0x0139
   - But NOT yet integrated into geth's VM

3. **Current Consensus Signatures** 
   - **P-Chain**: BLS signatures (BLS12-381) for validators
   - **C-Chain**: ECDSA (secp256k1) for EVM transactions
   - **X-Chain**: ECDSA (secp256k1) for UTXO transactions

### Integration Gaps

## 1. EVM/Geth Integration ❌

The post-quantum precompiles are NOT yet in geth's contracts.go:

```go
// Need to add to /geth/core/vm/contracts.go:
var PrecompiledContractsLux = PrecompiledContracts{
    // ... existing precompiles ...
    
    // ML-DSA (Dilithium)
    common.BytesToAddress([]byte{0x01, 0x10}): &mldsaVerify44{},
    common.BytesToAddress([]byte{0x01, 0x11}): &mldsaVerify65{},
    common.BytesToAddress([]byte{0x01, 0x12}): &mldsaVerify87{},
    
    // ML-KEM 
    common.BytesToAddress([]byte{0x01, 0x20}): &mlkemEncapsulate512{},
    common.BytesToAddress([]byte{0x01, 0x21}): &mlkemDecapsulate512{},
    // ... etc
}
```

## 2. Account/Wallet Level Signature Selection ❌

Currently, signature types are hardcoded per chain:

### Current Architecture:
```
P-Chain (Platform) → BLS only (validator consensus)
C-Chain (Contract) → ECDSA only (EVM compatibility)  
X-Chain (Exchange) → ECDSA only (UTXO model)
M-Chain (proposed) → Would need Dilithium MPC
```

### What's Needed for User Choice:

1. **Account Abstraction (EIP-4337 style)**
   ```solidity
   contract PostQuantumAccount {
       enum SignatureType { ECDSA, MLDSA44, MLDSA65, MLDSA87 }
       
       SignatureType public sigType;
       bytes public publicKey;
       
       function validateSignature(bytes memory signature) {
           if (sigType == SignatureType.MLDSA65) {
               // Call precompile at 0x0111
               (bool success, ) = address(0x0111).staticcall(
                   abi.encode(publicKey, message, signature)
               );
               require(success, "Invalid ML-DSA signature");
           }
       }
   }
   ```

2. **Transaction Format Extension**
   ```go
   type PostQuantumTx struct {
       SignatureAlgorithm uint8  // 0=ECDSA, 1=ML-DSA, 2=SLH-DSA
       Signature          []byte // Variable size based on algorithm
   }
   ```

## 3. Consensus Integration

### Current State:
- **P-Chain**: BLS + Ringtail (post-quantum ready)
- **Validators**: Use BLS for aggregatable signatures
- **Not using ML-DSA/Dilithium for consensus**

### Why Not Dilithium for Consensus?
1. **Signature Size**: ML-DSA signatures are 2.4-4.6 KB vs BLS's 96 bytes
2. **Aggregation**: BLS supports signature aggregation, ML-DSA doesn't
3. **Network Overhead**: Would increase block size significantly

### Actual Post-Quantum Strategy:
```
Consensus: BLS + Ringtail (hybrid classical/PQ)
User Transactions: ECDSA with optional PQ via precompiles
Smart Contracts: Can use PQ via precompiles
```

## 4. MPC for M-Chain

For threshold signatures with ML-DSA:

```go
// Theoretical implementation needed:
type MLDSAThresholdSigner struct {
    shares    []MLDSAShare
    threshold int
}

// Challenge: ML-DSA doesn't naturally support threshold
// Would need lattice-based secret sharing scheme
```

## Implementation Roadmap

### Phase 1: EVM Precompile Integration ⏳
```bash
# What needs to be done:
1. Wire up precompiles in geth/core/vm/contracts.go
2. Add to PrecompiledContractsLux
3. Test with C-Chain
```

### Phase 2: Smart Contract Support ✅ (Ready when Phase 1 done)
```solidity
// Users can already write contracts like:
contract PostQuantumVault {
    function verifyMLDSA(
        bytes memory pubKey,
        bytes memory message, 
        bytes memory signature
    ) public view returns (bool) {
        (bool success, bytes memory result) = address(0x0111).staticcall(
            abi.encode(pubKey, message, signature)
        );
        return success && result[0] == 1;
    }
}
```

### Phase 3: Wallet Integration 🔮
```javascript
// Future wallet support:
const wallet = new LuxWallet({
    signatureType: 'ML-DSA-65',
    // Larger keys and signatures
    privateKey: mldsaPrivateKey, // 4000 bytes
});
```

### Phase 4: Optional Account Abstraction 🔮
- Allow users to choose signature scheme per account
- Backward compatible with ECDSA
- Higher gas costs for PQ signatures

## Practical Usage Today

### What Works Now:
1. **Library Level**: All PQ crypto works
2. **Testing**: Can test algorithms independently
3. **Benchmarking**: Performance metrics available

### What Doesn't Work Yet:
1. **On-chain verification**: Precompiles not wired to EVM
2. **Wallet support**: No UI/UX for PQ keys
3. **Network consensus**: Still BLS, not ML-DSA

## Recommended Architecture

```
┌─────────────────────────────────────┐
│         User Layer                  │
├─────────────────────────────────────┤
│ Wallet: ECDSA (default)             │
│         ML-DSA (optional via AA)    │
├─────────────────────────────────────┤
│         Chain Layer                 │
├─────────────────────────────────────┤
│ P-Chain: BLS + Ringtail (consensus) │
│ C-Chain: ECDSA + PQ precompiles     │
│ X-Chain: ECDSA (UTXO compatible)    │
│ M-Chain: ECDSA (MPC) / Future: PQ   │
├─────────────────────────────────────┤
│      Precompile Layer (0x0110+)    │
├─────────────────────────────────────┤
│ ML-KEM │ ML-DSA │ SLH-DSA │ SHAKE  │
└─────────────────────────────────────┘
```

## Summary

**Current Reality:**
- Post-quantum crypto is implemented but not integrated
- Consensus uses BLS + Ringtail (hybrid approach)
- No user-facing PQ signature support yet

**What's Needed:**
1. Wire precompiles to geth EVM ← Critical next step
2. Create example smart contracts using PQ
3. Add wallet support (much later)
4. Consider account abstraction for signature choice

**Not Planned:**
- Replacing BLS with ML-DSA for consensus (too expensive)
- Forcing PQ signatures (backward compatibility matters)
- M-Chain Dilithium MPC (research needed)

The post-quantum crypto is ready at the library level but needs integration work to be usable on-chain.