// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title Post-Quantum Precompile Interfaces
/// @notice Interfaces for calling Lux post-quantum cryptography precompiles
/// @dev These precompiles are available at specific addresses on Lux

interface IPrecompiles {
    // SHAKE addresses (FIPS 202)
    address constant SHAKE128 = address(0x0140);
    address constant SHAKE128_256 = address(0x0141);
    address constant SHAKE128_512 = address(0x0142);
    address constant SHAKE256 = address(0x0143);
    address constant SHAKE256_256 = address(0x0144);
    address constant SHAKE256_512 = address(0x0145);
    address constant SHAKE256_1024 = address(0x0146);
    address constant cSHAKE128 = address(0x0147);
    address constant cSHAKE256 = address(0x0148);

    // Lamport addresses
    address constant LAMPORT_VERIFY_SHA256 = address(0x0150);
    address constant LAMPORT_VERIFY_SHA512 = address(0x0151);
    address constant LAMPORT_BATCH_VERIFY = address(0x0152);
    address constant LAMPORT_MERKLE_ROOT = address(0x0153);
    address constant LAMPORT_MERKLE_VERIFY = address(0x0154);

    // BLS addresses
    address constant BLS_VERIFY = address(0x0160);
    address constant BLS_AGGREGATE_VERIFY = address(0x0161);
    address constant BLS_FAST_AGGREGATE = address(0x0162);
    address constant BLS_THRESHOLD_VERIFY = address(0x0163);
    address constant BLS_THRESHOLD_COMBINE = address(0x0164);
    address constant BLS_PUBLIC_KEY_AGGREGATE = address(0x0165);
    address constant BLS_HASH_TO_POINT = address(0x0166);
}

/// @title SHAKE Precompile Library
/// @notice Helper functions for calling SHAKE precompiles
library ShakeLib {
    /// @notice Call SHAKE256 with variable output length
    /// @param data Input data to hash
    /// @param outputLen Desired output length in bytes (max 8192)
    /// @return output The SHAKE256 output
    function shake256(bytes memory data, uint32 outputLen) internal view returns (bytes memory output) {
        bytes memory input = abi.encodePacked(outputLen, data);
        
        (bool success, bytes memory result) = IPrecompiles.SHAKE256.staticcall(input);
        require(success, "SHAKE256 failed");
        
        return result;
    }

    /// @notice Call SHAKE256 with 32-byte output
    /// @param data Input data to hash
    /// @return output The 32-byte SHAKE256 output
    function shake256_256(bytes memory data) internal view returns (bytes32 output) {
        (bool success, bytes memory result) = IPrecompiles.SHAKE256_256.staticcall(data);
        require(success, "SHAKE256_256 failed");
        require(result.length == 32, "Invalid output length");
        
        assembly {
            output := mload(add(result, 0x20))
        }
    }

    /// @notice Call SHAKE128 with variable output length
    /// @param data Input data to hash
    /// @param outputLen Desired output length in bytes (max 8192)
    /// @return output The SHAKE128 output
    function shake128(bytes memory data, uint32 outputLen) internal view returns (bytes memory output) {
        bytes memory input = abi.encodePacked(outputLen, data);
        
        (bool success, bytes memory result) = IPrecompiles.SHAKE128.staticcall(input);
        require(success, "SHAKE128 failed");
        
        return result;
    }

    /// @notice Call cSHAKE256 with customization string
    /// @param data Input data to hash
    /// @param customization Customization string
    /// @param outputLen Desired output length
    /// @return output The cSHAKE256 output
    function cshake256(
        bytes memory data,
        bytes memory customization,
        uint32 outputLen
    ) internal view returns (bytes memory output) {
        bytes memory input = abi.encodePacked(
            outputLen,
            uint32(customization.length),
            customization,
            data
        );
        
        (bool success, bytes memory result) = IPrecompiles.cSHAKE256.staticcall(input);
        require(success, "cSHAKE256 failed");
        
        return result;
    }
}

/// @title Lamport Precompile Library
/// @notice Helper functions for calling Lamport signature precompiles
library LamportLib {
    /// @notice Verify a Lamport signature using SHA256
    /// @param messageHash SHA256 hash of the message (32 bytes)
    /// @param signature The Lamport signature
    /// @param publicKey The public key
    /// @return valid True if signature is valid
    function verifySignatureSHA256(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory publicKey
    ) internal view returns (bool valid) {
        bytes memory input = abi.encodePacked(messageHash, signature, publicKey);
        
        (bool success, bytes memory result) = IPrecompiles.LAMPORT_VERIFY_SHA256.staticcall(input);
        require(success, "Lamport verify failed");
        
        return result.length > 0 && result[0] == 0x01;
    }

    /// @notice Batch verify multiple Lamport signatures
    /// @param numSignatures Number of signatures to verify
    /// @param hashType Hash type (0 for SHA256, 1 for SHA512)
    /// @param data Packed data containing hashes, signatures, and public keys
    /// @return valid True if all signatures are valid
    function batchVerify(
        uint32 numSignatures,
        uint8 hashType,
        bytes memory data
    ) internal view returns (bool valid) {
        bytes memory input = abi.encodePacked(numSignatures, hashType, data);
        
        (bool success, bytes memory result) = IPrecompiles.LAMPORT_BATCH_VERIFY.staticcall(input);
        require(success, "Batch verify failed");
        
        return result.length > 0 && result[0] == 0x01;
    }

    /// @notice Compute Merkle root of public keys
    /// @param publicKeys Array of public keys (concatenated)
    /// @param numKeys Number of keys
    /// @param hashType Hash type (0 for SHA256)
    /// @return root The Merkle root
    function computeMerkleRoot(
        bytes memory publicKeys,
        uint32 numKeys,
        uint8 hashType
    ) internal view returns (bytes32 root) {
        bytes memory input = abi.encodePacked(numKeys, hashType, publicKeys);
        
        (bool success, bytes memory result) = IPrecompiles.LAMPORT_MERKLE_ROOT.staticcall(input);
        require(success, "Merkle root computation failed");
        require(result.length == 32, "Invalid root length");
        
        assembly {
            root := mload(add(result, 0x20))
        }
    }
}

/// @title BLS Precompile Library
/// @notice Helper functions for calling BLS signature precompiles
library BLSLib {
    /// @notice Verify a single BLS signature
    /// @param signature 96-byte BLS signature
    /// @param publicKey 48-byte BLS public key
    /// @param message Message that was signed
    /// @return valid True if signature is valid
    function verifySignature(
        bytes memory signature,
        bytes memory publicKey,
        bytes memory message
    ) internal view returns (bool valid) {
        require(signature.length == 96, "Invalid signature length");
        require(publicKey.length == 48, "Invalid public key length");
        
        bytes memory input = abi.encodePacked(signature, publicKey, message);
        
        (bool success, bytes memory result) = IPrecompiles.BLS_VERIFY.staticcall(input);
        require(success, "BLS verify failed");
        
        // Check if verification passed (non-zero result)
        for (uint i = 0; i < result.length; i++) {
            if (result[i] != 0) return true;
        }
        return false;
    }

    /// @notice Aggregate multiple BLS public keys
    /// @param publicKeys Concatenated public keys (each 48 bytes)
    /// @param numKeys Number of keys to aggregate
    /// @return aggregatedKey The aggregated public key (48 bytes)
    function aggregatePublicKeys(
        bytes memory publicKeys,
        uint32 numKeys
    ) internal view returns (bytes memory aggregatedKey) {
        require(publicKeys.length == numKeys * 48, "Invalid keys length");
        
        bytes memory input = abi.encodePacked(numKeys, publicKeys);
        
        (bool success, bytes memory result) = IPrecompiles.BLS_PUBLIC_KEY_AGGREGATE.staticcall(input);
        require(success, "Key aggregation failed");
        require(result.length == 48, "Invalid aggregated key length");
        
        return result;
    }

    /// @notice Hash a message to a BLS curve point
    /// @param message Message to hash
    /// @return point The curve point (96 bytes)
    function hashToPoint(bytes memory message) internal view returns (bytes memory point) {
        (bool success, bytes memory result) = IPrecompiles.BLS_HASH_TO_POINT.staticcall(message);
        require(success, "Hash to point failed");
        require(result.length == 96, "Invalid point length");
        
        return result;
    }
}