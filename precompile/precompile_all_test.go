package precompile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/lamport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// Test vectors for SHAKE from NIST
var shakeTestVectors = []struct {
	name     string
	input    string
	output128 string // First 32 bytes of SHAKE128
	output256 string // First 32 bytes of SHAKE256
}{
	{
		name:      "empty",
		input:     "",
		output128: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
		output256: "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
	},
	{
		name:      "abc",
		input:     "616263",
		output128: "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
		output256: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
	},
	{
		name:      "long",
		input:     "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
		output128: "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5",
		output256: "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329",
	},
}

// TestSHAKEPrecompiles tests all SHAKE variants
func TestSHAKEPrecompiles(t *testing.T) {
	t.Run("SHAKE128", func(t *testing.T) {
		shake128 := &SHAKE128{}
		
		for _, tv := range shakeTestVectors {
			t.Run(tv.name, func(t *testing.T) {
				inputData, _ := hex.DecodeString(tv.input)
				expectedOutput, _ := hex.DecodeString(tv.output128)
				
				// Create input with 32-byte output length
				input := make([]byte, 4+len(inputData))
				binary.BigEndian.PutUint32(input[:4], 32)
				copy(input[4:], inputData)
				
				// Test gas calculation
				gas := shake128.RequiredGas(input)
				expectedGas := uint64(60 + 12*((len(input)+31)/32) + 3)
				assert.Equal(t, expectedGas, gas, "Gas calculation mismatch")
				
				// Test output
				output, err := shake128.Run(input)
				require.NoError(t, err)
				assert.Equal(t, expectedOutput, output, "Output mismatch for %s", tv.name)
			})
		}
	})

	t.Run("SHAKE256", func(t *testing.T) {
		shake256 := &SHAKE256{}
		
		for _, tv := range shakeTestVectors {
			t.Run(tv.name, func(t *testing.T) {
				inputData, _ := hex.DecodeString(tv.input)
				expectedOutput, _ := hex.DecodeString(tv.output256)
				
				// Create input with 32-byte output length
				input := make([]byte, 4+len(inputData))
				binary.BigEndian.PutUint32(input[:4], 32)
				copy(input[4:], inputData)
				
				// Test gas calculation
				gas := shake256.RequiredGas(input)
				expectedGas := uint64(60 + 12*((len(input)+31)/32) + 3)
				assert.Equal(t, expectedGas, gas, "Gas calculation mismatch")
				
				// Test output
				output, err := shake256.Run(input)
				require.NoError(t, err)
				assert.Equal(t, expectedOutput, output, "Output mismatch for %s", tv.name)
			})
		}
	})

	t.Run("SHAKE256_Fixed", func(t *testing.T) {
		// Test fixed output variants
		variants := []struct {
			name      string
			precompile PrecompiledContract
			outputLen  int
			gas       uint64
		}{
			{"SHAKE256_256", &SHAKE256_256{}, 32, 200},
			{"SHAKE256_512", &SHAKE256_512{}, 64, 250},
			{"SHAKE256_1024", &SHAKE256_1024{}, 128, 350},
		}
		
		for _, v := range variants {
			t.Run(v.name, func(t *testing.T) {
				input := []byte("test input for fixed shake")
				
				// Test gas
				gas := v.precompile.RequiredGas(input)
				assert.Equal(t, v.gas, gas)
				
				// Test output length
				output, err := v.precompile.Run(input)
				require.NoError(t, err)
				assert.Len(t, output, v.outputLen)
				
				// Verify it matches variable SHAKE with same output length
				shake := &SHAKE256{}
				varInput := make([]byte, 4+len(input))
				binary.BigEndian.PutUint32(varInput[:4], uint32(v.outputLen))
				copy(varInput[4:], input)
				
				varOutput, err := shake.Run(varInput)
				require.NoError(t, err)
				assert.Equal(t, varOutput, output, "Fixed and variable SHAKE should match")
			})
		}
	})

	t.Run("cSHAKE", func(t *testing.T) {
		cshake128 := &CSHAKE128{}
		cshake256 := &CSHAKE256{}
		
		testCases := []struct {
			name         string
			customization string
			data         string
			outputLen    uint32
		}{
			{"empty", "", "test", 32},
			{"custom", "custom string", "test data", 64},
			{"long_custom", "very long customization string for testing", "data", 32},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Build input
				customBytes := []byte(tc.customization)
				dataBytes := []byte(tc.data)
				
				input := make([]byte, 8+len(customBytes)+len(dataBytes))
				binary.BigEndian.PutUint32(input[:4], tc.outputLen)
				binary.BigEndian.PutUint32(input[4:8], uint32(len(customBytes)))
				copy(input[8:], customBytes)
				copy(input[8+len(customBytes):], dataBytes)
				
				// Test CSHAKE128
				output128, err := cshake128.Run(input)
				require.NoError(t, err)
				assert.Len(t, output128, int(tc.outputLen))
				
				// Test CSHAKE256
				output256, err := cshake256.Run(input)
				require.NoError(t, err)
				assert.Len(t, output256, int(tc.outputLen))
				
				// Outputs should be different between 128 and 256
				if tc.customization != "" {
					assert.NotEqual(t, output128, output256)
				}
			})
		}
	})

	t.Run("EdgeCases", func(t *testing.T) {
		shake := &SHAKE256{}
		
		t.Run("MaxOutput", func(t *testing.T) {
			// Test maximum output size (8192 bytes)
			input := make([]byte, 4+10)
			binary.BigEndian.PutUint32(input[:4], 8192)
			copy(input[4:], []byte("test data"))
			
			output, err := shake.Run(input)
			require.NoError(t, err)
			assert.Len(t, output, 8192)
		})
		
		t.Run("TooLargeOutput", func(t *testing.T) {
			// Test output size exceeding maximum
			input := make([]byte, 4+10)
			binary.BigEndian.PutUint32(input[:4], 8193)
			copy(input[4:], []byte("test data"))
			
			_, err := shake.Run(input)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "exceeds maximum")
		})
		
		t.Run("ZeroOutput", func(t *testing.T) {
			// Test zero output length
			input := make([]byte, 4+10)
			binary.BigEndian.PutUint32(input[:4], 0)
			copy(input[4:], []byte("test data"))
			
			output, err := shake.Run(input)
			require.NoError(t, err)
			assert.Len(t, output, 0)
		})
		
		t.Run("InsufficientInput", func(t *testing.T) {
			// Test input shorter than 4 bytes
			input := []byte{0, 0}
			
			_, err := shake.Run(input)
			assert.Error(t, err)
		})
	})
}

// TestLamportPrecompiles tests Lamport signature operations
func TestLamportPrecompiles(t *testing.T) {
	t.Run("LamportVerifySHA256", func(t *testing.T) {
		verifier := &LamportVerifySHA256{}
		
		// Generate test key and signature
		priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		require.NoError(t, err)
		
		message := []byte("test message for lamport")
		sig, err := priv.Sign(message)
		require.NoError(t, err)
		
		// Build precompile input
		messageHash := sha256.Sum256(message)
		sigBytes := sig.Bytes()
		pubBytes := priv.Public().Bytes()
		
		input := make([]byte, 32+len(sigBytes)+len(pubBytes))
		copy(input[:32], messageHash[:])
		copy(input[32:], sigBytes)
		copy(input[32+len(sigBytes):], pubBytes)
		
		// Test gas
		gas := verifier.RequiredGas(input)
		assert.Equal(t, uint64(50000), gas)
		
		// Test verification (should succeed)
		output, err := verifier.Run(input)
		require.NoError(t, err)
		expected := make([]byte, 32)
		expected[31] = 1
		assert.Equal(t, expected, output, "Valid signature should return 1")
		
		// Test with wrong message
		wrongHash := sha256.Sum256([]byte("wrong message"))
		copy(input[:32], wrongHash[:])
		
		output, err = verifier.Run(input)
		require.NoError(t, err)
		expected = make([]byte, 32)
		assert.Equal(t, expected, output, "Invalid signature should return 0")
	})

	t.Run("LamportVerifySHA512", func(t *testing.T) {
		verifier := &LamportVerifySHA512{}
		
		// Generate test key and signature
		priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA512)
		require.NoError(t, err)
		
		message := []byte("test message for lamport sha512")
		sig, err := priv.Sign(message)
		require.NoError(t, err)
		
		// Build precompile input
		messageHash := sha512.Sum512(message)
		sigBytes := sig.Bytes()
		pubBytes := priv.Public().Bytes()
		
		input := make([]byte, 64+len(sigBytes)+len(pubBytes))
		copy(input[:64], messageHash[:])
		copy(input[64:], sigBytes)
		copy(input[64+len(sigBytes):], pubBytes)
		
		// Test gas
		gas := verifier.RequiredGas(input)
		assert.Equal(t, uint64(80000), gas)
		
		// Test verification
		output, err := verifier.Run(input)
		require.NoError(t, err)
		expected := make([]byte, 32)
		expected[31] = 1
		assert.Equal(t, expected, output, "Valid signature should return 1")
	})

	t.Run("LamportBatchVerify", func(t *testing.T) {
		batchVerifier := &LamportBatchVerify{}
		
		// Generate multiple signatures
		numSigs := 3
		var messages [][]byte
		var sigs []*lamport.Signature
		var pubs []*lamport.PublicKey
		
		for i := 0; i < numSigs; i++ {
			priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
			require.NoError(t, err)
			
			message := []byte(fmt.Sprintf("message %d", i))
			messages = append(messages, message)
			
			sig, err := priv.Sign(message)
			require.NoError(t, err)
			sigs = append(sigs, sig)
			pubs = append(pubs, priv.Public())
		}
		
		// Build batch input
		// Format: [num_sigs(4)][hash_type(1)][data...]
		// data = [msg_hash][sig][pubkey] repeated
		
		// Calculate total size
		hashSize := 32 // SHA256
		sigSize := len(sigs[0].Bytes())
		pubSize := len(pubs[0].Bytes())
		dataSize := numSigs * (hashSize + sigSize + pubSize)
		
		input := make([]byte, 5+dataSize)
		binary.BigEndian.PutUint32(input[:4], uint32(numSigs))
		input[4] = 0 // SHA256
		
		offset := 5
		for i := 0; i < numSigs; i++ {
			hash := sha256.Sum256(messages[i])
			copy(input[offset:], hash[:])
			offset += hashSize
			
			copy(input[offset:], sigs[i].Bytes())
			offset += sigSize
			
			copy(input[offset:], pubs[i].Bytes())
			offset += pubSize
		}
		
		// Test gas
		gas := batchVerifier.RequiredGas(input)
		expectedGas := uint64(30000 + 40000*uint64(numSigs))
		assert.Equal(t, expectedGas, gas)
		
		// Test batch verification
		output, err := batchVerifier.Run(input)
		require.NoError(t, err)
		expected := make([]byte, 32)
		expected[31] = 1
		assert.Equal(t, expected, output, "All valid signatures should return 1")
		
		// Corrupt one signature
		input[5+hashSize] ^= 0xFF
		
		output, err = batchVerifier.Run(input)
		require.NoError(t, err)
		assert.Equal(t, []byte{0}, output, "Any invalid signature should return 0")
	})

	t.Run("LamportMerkleRoot", func(t *testing.T) {
		merkleRoot := &LamportMerkleRoot{}
		
		// Generate multiple public keys
		numKeys := 4
		var pubs []*lamport.PublicKey
		
		for i := 0; i < numKeys; i++ {
			priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
			require.NoError(t, err)
			pubs = append(pubs, priv.Public())
		}
		
		// Build input
		// Format: [num_keys(4)][hash_type(1)][pubkeys...]
		pubSize := len(pubs[0].Bytes())
		input := make([]byte, 5+numKeys*pubSize)
		binary.BigEndian.PutUint32(input[:4], uint32(numKeys))
		input[4] = 0 // SHA256
		
		offset := 5
		for _, pub := range pubs {
			copy(input[offset:], pub.Bytes())
			offset += pubSize
		}
		
		// Test gas
		gas := merkleRoot.RequiredGas(input)
		assert.Equal(t, uint64(100000), gas)
		
		// Test root computation
		output, err := merkleRoot.Run(input)
		require.NoError(t, err)
		assert.Len(t, output, 32, "Merkle root should be 32 bytes")
		
		// Same keys should produce same root
		output2, err := merkleRoot.Run(input)
		require.NoError(t, err)
		assert.Equal(t, output, output2, "Same keys should produce same root")
		
		// Different order should produce different root
		// Swap first two keys
		copy(input[5:5+pubSize], pubs[1].Bytes())
		copy(input[5+pubSize:5+2*pubSize], pubs[0].Bytes())
		
		output3, err := merkleRoot.Run(input)
		require.NoError(t, err)
		assert.NotEqual(t, output, output3, "Different order should produce different root")
	})
}

// TestBLSPrecompiles tests BLS signature operations
func TestBLSPrecompiles(t *testing.T) {
	t.Run("BLSVerify", func(t *testing.T) {
		verifier := &BLSVerify{}
		
		// Create dummy input (placeholder implementation)
		// Format: [96 bytes sig][48 bytes pubkey][message]
		message := []byte("test message for BLS")
		input := make([]byte, 96+48+len(message))
		rand.Read(input[:96])  // Random signature
		rand.Read(input[96:144]) // Random pubkey
		copy(input[144:], message)
		
		// Test gas
		gas := verifier.RequiredGas(input)
		assert.Equal(t, uint64(150000), gas)
		
		// Test run (placeholder always returns success)
		output, err := verifier.Run(input)
		require.NoError(t, err)
		assert.Len(t, output, 32)
	})

	t.Run("BLSAggregateVerify", func(t *testing.T) {
		aggVerifier := &BLSAggregateVerify{}
		
		// Build aggregate input
		// Format: [num_sigs(4)][signatures][pubkeys][encoded_messages]
		numSigs := 3
		sigSize := 96
		pubSize := 48
		msgSize := 32
		
		totalSize := 4 + numSigs*(sigSize+pubSize+4+msgSize)
		input := make([]byte, totalSize)
		binary.BigEndian.PutUint32(input[:4], uint32(numSigs))
		
		offset := 4
		// Add signatures
		for i := 0; i < numSigs; i++ {
			rand.Read(input[offset : offset+sigSize])
			offset += sigSize
		}
		
		// Add public keys
		for i := 0; i < numSigs; i++ {
			rand.Read(input[offset : offset+pubSize])
			offset += pubSize
		}
		
		// Add messages (with length prefixes)
		for i := 0; i < numSigs; i++ {
			binary.BigEndian.PutUint32(input[offset:offset+4], uint32(msgSize))
			offset += 4
			rand.Read(input[offset : offset+msgSize])
			offset += msgSize
		}
		
		// Test gas
		gas := aggVerifier.RequiredGas(input)
		expectedGas := uint64(200000 + 30000*uint64(numSigs))
		assert.Equal(t, expectedGas, gas)
		
		// Test run
		output, err := aggVerifier.Run(input)
		require.NoError(t, err)
		assert.Len(t, output, 32)
	})

	t.Run("BLSPublicKeyAggregate", func(t *testing.T) {
		aggregator := &BLSPublicKeyAggregate{}
		
		// Build input
		// Format: [num_keys(4)][pubkeys...]
		numKeys := 5
		pubSize := 48
		
		input := make([]byte, 4+numKeys*pubSize)
		binary.BigEndian.PutUint32(input[:4], uint32(numKeys))
		
		for i := 0; i < numKeys; i++ {
			rand.Read(input[4+i*pubSize : 4+(i+1)*pubSize])
		}
		
		// Test gas
		gas := aggregator.RequiredGas(input)
		expectedGas := uint64(50000 + 10000*uint64(numKeys))
		assert.Equal(t, expectedGas, gas)
		
		// Test run
		output, err := aggregator.Run(input)
		require.NoError(t, err)
		assert.Len(t, output, pubSize, "Aggregated key should be same size as single key")
	})

	t.Run("BLSHashToPoint", func(t *testing.T) {
		hashToPoint := &BLSHashToPoint{}
		
		// Test with various message sizes
		messages := [][]byte{
			[]byte("short"),
			[]byte("medium length message for testing"),
			bytes.Repeat([]byte("long "), 100),
		}
		
		for _, msg := range messages {
			// Test gas
			gas := hashToPoint.RequiredGas(msg)
			assert.Equal(t, uint64(80000), gas)
			
			// Test run
			output, err := hashToPoint.Run(msg)
			require.NoError(t, err)
			assert.Len(t, output, 96, "Hash to point should produce 96-byte point")
			
			// Same message should produce same point
			output2, err := hashToPoint.Run(msg)
			require.NoError(t, err)
			assert.Equal(t, output, output2, "Deterministic hashing")
		}
	})
}

// TestPrecompileRegistry tests the registry and metadata
func TestPrecompileRegistry(t *testing.T) {
	t.Run("AllPrecompilesRegistered", func(t *testing.T) {
		// Check that all expected addresses are registered
		expectedAddresses := []string{
			// SHAKE
			"0x0140", "0x0141", "0x0142", "0x0143", "0x0144", "0x0145", "0x0146", "0x0147", "0x0148",
			// Lamport
			"0x0150", "0x0151", "0x0152", "0x0153", "0x0154",
			// BLS
			"0x0160", "0x0161", "0x0162", "0x0163", "0x0164", "0x0165", "0x0166",
		}
		
		for _, addr := range expectedAddresses {
			t.Run(addr, func(t *testing.T) {
				// Convert hex string to address
				addrBytes, err := hex.DecodeString(addr[2:])
				require.NoError(t, err)
				
				var address [20]byte
				copy(address[20-len(addrBytes):], addrBytes)
				
				precompile, exists := PostQuantumRegistry.contracts[address]
				assert.True(t, exists, "Address %s should be registered", addr)
				assert.NotNil(t, precompile, "Precompile at %s should not be nil", addr)
			})
		}
	})

	t.Run("GetGasEstimate", func(t *testing.T) {
		// Test SHAKE256 gas estimate
		shake256Addr := [20]byte{}
		shake256Addr[19] = 0x43
		
		input := make([]byte, 36)
		binary.BigEndian.PutUint32(input[:4], 32)
		copy(input[4:], []byte("test"))
		
		gas := GetGasEstimate(shake256Addr, len(input))
		assert.Greater(t, gas, uint64(0), "Should return non-zero gas estimate")
		
		// Test unknown address
		unknownAddr := [20]byte{0xFF}
		gas = GetGasEstimate(unknownAddr, len(input))
		assert.Equal(t, uint64(0), gas, "Unknown address should return 0")
	})

	t.Run("Info", func(t *testing.T) {
		info := Info()
		
		// Check that info contains expected content
		assert.Contains(t, info, "Post-Quantum Precompiled Contracts")
		assert.Contains(t, info, "SHAKE")
		assert.Contains(t, info, "Lamport")
		assert.Contains(t, info, "BLS")
		assert.Contains(t, info, "0x0140")
		assert.Contains(t, info, "0x0150")
		assert.Contains(t, info, "0x0160")
		
		// Check formatting
		assert.Contains(t, info, "Address Range")
		assert.Contains(t, info, "Functions")
	})

	t.Run("CGOStatus", func(t *testing.T) {
		// Test EnableCGO function
		EnableCGO()
		// This is mainly to ensure it doesn't panic
		// Actual CGO enabling would require build tags
	})
}

// TestErrorHandling tests error conditions across all precompiles
func TestErrorHandling(t *testing.T) {
	t.Run("InsufficientInput", func(t *testing.T) {
		precompiles := []PrecompiledContract{
			&SHAKE256{},
			&LamportVerifySHA256{},
			&BLSVerify{},
		}
		
		for _, p := range precompiles {
			// Empty input
			_, err := p.Run([]byte{})
			assert.Error(t, err, "%T should error on empty input", p)
			
			// Too short input
			_, err = p.Run([]byte{0, 1, 2})
			assert.Error(t, err, "%T should error on short input", p)
		}
	})

	t.Run("InvalidParameters", func(t *testing.T) {
		// SHAKE with invalid output length
		shake := &SHAKE256{}
		input := make([]byte, 8)
		binary.BigEndian.PutUint32(input[:4], 8193) // Too large
		
		_, err := shake.Run(input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
		
		// Batch verify with 0 signatures
		batch := &LamportBatchVerify{}
		input = make([]byte, 5)
		binary.BigEndian.PutUint32(input[:4], 0)
		input[4] = 0
		
		_, err = batch.Run(input)
		assert.Error(t, err)
		
		// BLS aggregate with mismatched counts
		agg := &BLSAggregateVerify{}
		input = make([]byte, 4)
		binary.BigEndian.PutUint32(input[:4], 10) // Claims 10 sigs but no data
		
		_, err = agg.Run(input)
		assert.Error(t, err)
	})

	t.Run("ConsistentErrorMessages", func(t *testing.T) {
		// Test that similar errors have consistent messages
		shake128 := &SHAKE128{}
		shake256 := &SHAKE256{}
		
		shortInput := []byte{0, 1}
		
		_, err1 := shake128.Run(shortInput)
		_, err2 := shake256.Run(shortInput)
		
		if err1 != nil && err2 != nil {
			// Both should have similar error messages
			assert.Contains(t, err1.Error(), "insufficient")
			assert.Contains(t, err2.Error(), "insufficient")
		}
	})
}

// Benchmark tests
func BenchmarkPrecompiles(b *testing.B) {
	b.Run("SHAKE256_32bytes", func(b *testing.B) {
		shake := &SHAKE256{}
		input := make([]byte, 36)
		binary.BigEndian.PutUint32(input[:4], 32)
		copy(input[4:], bytes.Repeat([]byte("x"), 32))
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = shake.Run(input)
		}
	})

	b.Run("SHAKE256_1024bytes", func(b *testing.B) {
		shake := &SHAKE256_1024{}
		input := bytes.Repeat([]byte("x"), 128)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = shake.Run(input)
		}
	})

	b.Run("LamportVerify", func(b *testing.B) {
		verifier := &LamportVerifySHA256{}
		
		// Generate a signature once
		priv, _ := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		message := []byte("benchmark message")
		sig, _ := priv.Sign(message)
		
		messageHash := sha256.Sum256(message)
		sigBytes := sig.Bytes()
		pubBytes := priv.Public().Bytes()
		
		input := make([]byte, 32+len(sigBytes)+len(pubBytes))
		copy(input[:32], messageHash[:])
		copy(input[32:], sigBytes)
		copy(input[32+len(sigBytes):], pubBytes)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = verifier.Run(input)
		}
	})

	b.Run("BLSVerify", func(b *testing.B) {
		verifier := &BLSVerify{}
		
		input := make([]byte, 96+48+32)
		rand.Read(input)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = verifier.Run(input)
		}
	})
}

// TestCrossPrecompileWorkflows tests using multiple precompiles together
func TestCrossPrecompileWorkflows(t *testing.T) {
	t.Run("HashAndSign", func(t *testing.T) {
		// Use SHAKE to hash, then Lamport to sign
		shake := &SHAKE256_256{}
		lamportVerify := &LamportVerifySHA256{}
		
		// Original message
		message := []byte("cross-precompile test message")
		
		// Hash with SHAKE256
		hashedOutput, err := shake.Run(message)
		require.NoError(t, err)
		assert.Len(t, hashedOutput, 32)
		
		// Generate Lamport signature on the hash
		priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
		require.NoError(t, err)
		
		sig, err := priv.Sign(hashedOutput)
		require.NoError(t, err)
		
		// Build verification input
		sigBytes := sig.Bytes()
		pubBytes := priv.Public().Bytes()
		
		verifyInput := make([]byte, 32+len(sigBytes)+len(pubBytes))
		copy(verifyInput[:32], hashedOutput)
		copy(verifyInput[32:], sigBytes)
		copy(verifyInput[32+len(sigBytes):], pubBytes)
		
		// Verify
		result, err := lamportVerify.Run(verifyInput)
		require.NoError(t, err)
		expected := make([]byte, 32)
		expected[31] = 1
		assert.Equal(t, expected, result, "Cross-precompile signature should verify")
	})

	t.Run("MerkleAndBatch", func(t *testing.T) {
		// Create merkle root of keys, then batch verify signatures
		merkleRoot := &LamportMerkleRoot{}
		batchVerify := &LamportBatchVerify{}
		
		// Generate multiple keys
		numKeys := 3
		var privKeys []*lamport.PrivateKey
		var pubKeys []*lamport.PublicKey
		
		for i := 0; i < numKeys; i++ {
			priv, err := lamport.GenerateKey(rand.Reader, lamport.SHA256)
			require.NoError(t, err)
			privKeys = append(privKeys, priv)
			pubKeys = append(pubKeys, priv.Public())
		}
		
		// Compute merkle root
		pubSize := len(pubKeys[0].Bytes())
		rootInput := make([]byte, 5+numKeys*pubSize)
		binary.BigEndian.PutUint32(rootInput[:4], uint32(numKeys))
		rootInput[4] = 0 // SHA256
		
		offset := 5
		for _, pub := range pubKeys {
			copy(rootInput[offset:], pub.Bytes())
			offset += pubSize
		}
		
		root, err := merkleRoot.Run(rootInput)
		require.NoError(t, err)
		assert.Len(t, root, 32)
		
		// Create signatures with the same keys
		messages := make([][]byte, numKeys)
		sigs := make([]*lamport.Signature, numKeys)
		
		for i := 0; i < numKeys; i++ {
			messages[i] = []byte(fmt.Sprintf("message %d", i))
			sig, err := privKeys[i].Sign(messages[i])
			require.NoError(t, err)
			sigs[i] = sig
		}
		
		// Batch verify
		hashSize := 32
		sigSize := len(sigs[0].Bytes())
		batchInput := make([]byte, 5+numKeys*(hashSize+sigSize+pubSize))
		binary.BigEndian.PutUint32(batchInput[:4], uint32(numKeys))
		batchInput[4] = 0 // SHA256
		
		offset = 5
		for i := 0; i < numKeys; i++ {
			hash := sha256.Sum256(messages[i])
			copy(batchInput[offset:], hash[:])
			offset += hashSize
			
			copy(batchInput[offset:], sigs[i].Bytes())
			offset += sigSize
			
			copy(batchInput[offset:], pubKeys[i].Bytes())
			offset += pubSize
		}
		
		result, err := batchVerify.Run(batchInput)
		require.NoError(t, err)
		expected := make([]byte, 32)
		expected[31] = 1
		assert.Equal(t, expected, result, "Batch verification should succeed")
		
		t.Logf("Merkle root: %x", root)
		t.Log("All signatures verified in batch")
	})
}

// Helper function to compare SHAKE output with reference implementation
func verifyShakeOutput(t *testing.T, input []byte, outputLen int, isShake256 bool) []byte {
	t.Helper()
	
	var h sha3.ShakeHash
	if isShake256 {
		h = sha3.NewShake256()
	} else {
		h = sha3.NewShake128()
	}
	
	h.Write(input)
	output := make([]byte, outputLen)
	h.Read(output)
	
	return output
}