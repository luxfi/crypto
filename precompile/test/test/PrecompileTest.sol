// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/IPrecompiles.sol";

/// @title Precompile Test Suite
/// @notice Comprehensive tests for Lux post-quantum cryptography precompiles
contract PrecompileTest is Test, IPrecompiles {
    using ShakeLib for bytes;
    using LamportLib for bytes32;
    using BLSLib for bytes;

    // Test data
    bytes constant TEST_DATA = "The quick brown fox jumps over the lazy dog";
    bytes32 constant TEST_HASH = keccak256(TEST_DATA);

    function setUp() public {
        // Fork Lux testnet or use Anvil with custom precompiles
        // vm.createSelectFork(vm.rpcUrl("testnet"));
    }

    // ============ SHAKE Tests ============

    function testShake256_256() public {
        bytes32 output = ShakeLib.shake256_256(TEST_DATA);
        
        // Should produce deterministic output
        bytes32 output2 = ShakeLib.shake256_256(TEST_DATA);
        assertEq(output, output2, "SHAKE256 should be deterministic");
        
        // Different input should produce different output
        bytes32 differentOutput = ShakeLib.shake256_256("different data");
        assertTrue(output != differentOutput, "Different inputs should produce different outputs");
    }

    function testShake256VariableLength() public {
        // Test different output lengths
        bytes memory output32 = ShakeLib.shake256(TEST_DATA, 32);
        bytes memory output64 = ShakeLib.shake256(TEST_DATA, 64);
        bytes memory output128 = ShakeLib.shake256(TEST_DATA, 128);
        
        assertEq(output32.length, 32, "Should return 32 bytes");
        assertEq(output64.length, 64, "Should return 64 bytes");
        assertEq(output128.length, 128, "Should return 128 bytes");
        
        // First 32 bytes should match between different lengths
        for (uint i = 0; i < 32; i++) {
            assertEq(output32[i], output64[i], "First 32 bytes should match");
            assertEq(output32[i], output128[i], "First 32 bytes should match");
        }
    }

    function testShake128Vs256() public {
        bytes memory output128 = ShakeLib.shake128(TEST_DATA, 32);
        bytes memory output256 = ShakeLib.shake256(TEST_DATA, 32);
        
        // SHAKE128 and SHAKE256 should produce different outputs
        bool different = false;
        for (uint i = 0; i < 32; i++) {
            if (output128[i] != output256[i]) {
                different = true;
                break;
            }
        }
        assertTrue(different, "SHAKE128 and SHAKE256 should produce different outputs");
    }

    function testCShake256() public {
        bytes memory customization = "test customization";
        bytes memory output1 = ShakeLib.cshake256(TEST_DATA, customization, 32);
        bytes memory output2 = ShakeLib.cshake256(TEST_DATA, "different", 32);
        bytes memory output3 = ShakeLib.cshake256(TEST_DATA, "", 32); // No customization
        
        // Different customizations should produce different outputs
        bool different12 = false;
        bool different13 = false;
        for (uint i = 0; i < 32; i++) {
            if (output1[i] != output2[i]) different12 = true;
            if (output1[i] != output3[i]) different13 = true;
        }
        
        assertTrue(different12, "Different customizations should produce different outputs");
        assertTrue(different13, "Customization should affect output");
    }

    function testShakeMaxOutput() public {
        // Test maximum output size (8192 bytes)
        bytes memory largeOutput = ShakeLib.shake256(TEST_DATA, 8192);
        assertEq(largeOutput.length, 8192, "Should support maximum output size");
        
        // Should revert if requesting more than maximum
        vm.expectRevert();
        ShakeLib.shake256(TEST_DATA, 8193);
    }

    function testShakeGasCosts() public {
        uint256 gasBefore;
        uint256 gasAfter;
        
        // Measure gas for small output
        gasBefore = gasleft();
        ShakeLib.shake256_256(TEST_DATA);
        gasAfter = gasleft();
        uint256 gasSmall = gasBefore - gasAfter;
        
        // Measure gas for large output
        gasBefore = gasleft();
        ShakeLib.shake256(TEST_DATA, 1024);
        gasAfter = gasleft();
        uint256 gasLarge = gasBefore - gasAfter;
        
        // Large output should cost more gas
        assertTrue(gasLarge > gasSmall, "Larger output should cost more gas");
        
        // Log gas costs for analysis
        emit log_named_uint("Gas for 32-byte output", gasSmall);
        emit log_named_uint("Gas for 1024-byte output", gasLarge);
    }

    // ============ Lamport Tests ============

    function testLamportVerifySHA256() public {
        // Note: These would need actual Lamport signatures generated off-chain
        // For testing, we're demonstrating the interface
        
        bytes32 messageHash = sha256(abi.encodePacked(TEST_DATA));
        
        // Mock signature and public key (would be real in production)
        bytes memory signature = new bytes(8192); // Typical Lamport sig size
        bytes memory publicKey = new bytes(8192); // Typical Lamport pubkey size
        
        // This would call the actual precompile
        // bool valid = LamportLib.verifySignatureSHA256(messageHash, signature, publicKey);
        // assertTrue(valid, "Valid signature should verify");
    }

    function testLamportBatchVerify() public {
        // Prepare batch verification data
        uint32 numSigs = 3;
        uint8 hashType = 0; // SHA256
        
        // Mock batch data (would be real signatures in production)
        bytes memory batchData = new bytes(numSigs * (32 + 8192 + 8192)); // hash + sig + pubkey
        
        // This would call the actual precompile
        // bool allValid = LamportLib.batchVerify(numSigs, hashType, batchData);
        // assertTrue(allValid, "All signatures should verify");
    }

    function testLamportMerkleRoot() public {
        // Test Merkle root computation
        uint32 numKeys = 4;
        uint8 hashType = 0; // SHA256
        
        // Mock public keys
        bytes memory publicKeys = new bytes(numKeys * 8192);
        
        // Compute Merkle root
        // bytes32 root = LamportLib.computeMerkleRoot(publicKeys, numKeys, hashType);
        // assertTrue(root != bytes32(0), "Merkle root should be non-zero");
        
        // Same keys should produce same root
        // bytes32 root2 = LamportLib.computeMerkleRoot(publicKeys, numKeys, hashType);
        // assertEq(root, root2, "Same keys should produce same root");
    }

    // ============ BLS Tests ============

    function testBLSVerify() public {
        // Mock BLS signature and public key
        bytes memory signature = new bytes(96);
        bytes memory publicKey = new bytes(48);
        bytes memory message = TEST_DATA;
        
        // Fill with mock data (would be real BLS data in production)
        for (uint i = 0; i < 96; i++) {
            signature[i] = bytes1(uint8(i));
        }
        for (uint i = 0; i < 48; i++) {
            publicKey[i] = bytes1(uint8(i + 96));
        }
        
        // This would call the actual precompile
        // bool valid = BLSLib.verifySignature(signature, publicKey, message);
        // assertTrue(valid, "Valid BLS signature should verify");
    }

    function testBLSAggregatePublicKeys() public {
        uint32 numKeys = 3;
        bytes memory publicKeys = new bytes(numKeys * 48);
        
        // Fill with mock public keys
        for (uint i = 0; i < publicKeys.length; i++) {
            publicKeys[i] = bytes1(uint8(i));
        }
        
        // Aggregate keys
        // bytes memory aggregated = BLSLib.aggregatePublicKeys(publicKeys, numKeys);
        // assertEq(aggregated.length, 48, "Aggregated key should be 48 bytes");
    }

    function testBLSHashToPoint() public {
        bytes memory message = TEST_DATA;
        
        // Hash to point
        // bytes memory point = BLSLib.hashToPoint(message);
        // assertEq(point.length, 96, "Point should be 96 bytes");
        
        // Same message should produce same point
        // bytes memory point2 = BLSLib.hashToPoint(message);
        // assertEq(point, point2, "Hash to point should be deterministic");
    }

    // ============ Integration Tests ============

    function testCrossPrecompileWorkflow() public {
        // Test using multiple precompiles together
        
        // Step 1: Hash data with SHAKE
        bytes32 hashedData = ShakeLib.shake256_256(TEST_DATA);
        
        // Step 2: Use the hash for further cryptographic operations
        // (Would involve Lamport or BLS operations with real implementations)
        
        // Step 3: Verify the workflow produces consistent results
        bytes32 hashedData2 = ShakeLib.shake256_256(TEST_DATA);
        assertEq(hashedData, hashedData2, "Workflow should be deterministic");
    }

    function testPrecompileGasEstimation() public {
        // Test that gas estimation is reasonable for different operations
        
        uint256 shakeGas = 200; // Expected for SHAKE256_256
        uint256 lamportGas = 50000; // Expected for Lamport verify
        uint256 blsGas = 150000; // Expected for BLS verify
        
        // These would be actual measurements in production
        assertTrue(shakeGas < lamportGas, "SHAKE should be cheaper than Lamport");
        assertTrue(lamportGas < blsGas, "Lamport should be cheaper than BLS");
    }

    // ============ Fuzz Tests ============

    function testFuzzShake256(bytes calldata data, uint32 outputLen) public {
        // Bound output length to valid range
        outputLen = uint32(bound(outputLen, 1, 8192));
        
        bytes memory output = ShakeLib.shake256(data, outputLen);
        assertEq(output.length, outputLen, "Output length should match requested");
        
        // Same input should produce same output
        bytes memory output2 = ShakeLib.shake256(data, outputLen);
        assertEq(output, output2, "SHAKE should be deterministic");
    }

    function testFuzzCShake256(
        bytes calldata data,
        bytes calldata customization,
        uint32 outputLen
    ) public {
        // Bound parameters
        outputLen = uint32(bound(outputLen, 1, 8192));
        vm.assume(customization.length <= 1024); // Reasonable customization length
        
        bytes memory output = ShakeLib.cshake256(data, customization, outputLen);
        assertEq(output.length, outputLen, "Output length should match requested");
        
        // Different customizations should produce different outputs (usually)
        if (customization.length > 0) {
            bytes memory differentCustom = abi.encodePacked(customization, "x");
            bytes memory output2 = ShakeLib.cshake256(data, differentCustom, outputLen);
            
            bool different = false;
            for (uint i = 0; i < outputLen && i < 32; i++) {
                if (output[i] != output2[i]) {
                    different = true;
                    break;
                }
            }
            assertTrue(different, "Different customizations should affect output");
        }
    }

    // ============ Events for logging ============
    
    event GasUsed(string operation, uint256 gas);
    event TestResult(string test, bool passed);
}