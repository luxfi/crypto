// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "../src/IPrecompiles.sol";

/// @title Precompile Testing Script
/// @notice Script to test precompiles on local Anvil or testnet
contract TestPrecompilesScript is Script, IPrecompiles {
    using ShakeLib for bytes;

    function run() public {
        vm.startBroadcast();

        console.log("Testing Lux Post-Quantum Precompiles");
        console.log("=====================================");

        // Test SHAKE256
        testShake256();
        
        // Test Lamport (if available)
        testLamport();
        
        // Test BLS (if available)
        testBLS();

        vm.stopBroadcast();
    }

    function testShake256() internal {
        console.log("\nTesting SHAKE256 Precompiles:");
        
        bytes memory testData = "Hello, Lux!";
        
        // Test SHAKE256 with 32-byte output
        try ShakeLib.shake256_256(testData) returns (bytes32 output) {
            console.log("SHAKE256_256 Success!");
            console.logBytes32(output);
        } catch Error(string memory reason) {
            console.log("SHAKE256_256 Failed:", reason);
        } catch {
            console.log("SHAKE256_256 Failed: Unknown error");
        }

        // Test SHAKE256 with variable length
        try ShakeLib.shake256(testData, 64) returns (bytes memory output) {
            console.log("SHAKE256 (64 bytes) Success!");
            console.log("Output length:", output.length);
        } catch Error(string memory reason) {
            console.log("SHAKE256 Failed:", reason);
        } catch {
            console.log("SHAKE256 Failed: Unknown error");
        }

        // Test cSHAKE256
        try ShakeLib.cshake256(testData, "customization", 32) returns (bytes memory output) {
            console.log("cSHAKE256 Success!");
            console.log("Output length:", output.length);
        } catch Error(string memory reason) {
            console.log("cSHAKE256 Failed:", reason);
        } catch {
            console.log("cSHAKE256 Failed: Unknown error");
        }
    }

    function testLamport() internal {
        console.log("\nTesting Lamport Precompiles:");
        
        // Create test data
        bytes32 messageHash = sha256("Test message");
        bytes memory signature = new bytes(8192); // Mock signature
        bytes memory publicKey = new bytes(8192); // Mock public key
        
        // Try to verify (will likely fail with mock data)
        bytes memory input = abi.encodePacked(messageHash, signature, publicKey);
        
        (bool success, bytes memory result) = LAMPORT_VERIFY_SHA256.staticcall{gas: 100000}(input);
        
        if (success) {
            console.log("Lamport Verify call succeeded");
            if (result.length > 0) {
                console.log("Verification result:", result[0] == 0x01 ? "Valid" : "Invalid");
            }
        } else {
            console.log("Lamport Verify not available or failed");
        }
    }

    function testBLS() internal {
        console.log("\nTesting BLS Precompiles:");
        
        // Create test data
        bytes memory signature = new bytes(96);
        bytes memory publicKey = new bytes(48);
        bytes memory message = "Test BLS message";
        
        bytes memory input = abi.encodePacked(signature, publicKey, message);
        
        (bool success, bytes memory result) = BLS_VERIFY.staticcall{gas: 200000}(input);
        
        if (success) {
            console.log("BLS Verify call succeeded");
            console.log("Result length:", result.length);
        } else {
            console.log("BLS Verify not available or failed");
        }
    }
}