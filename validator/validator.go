// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/luxfi/ids"
	"github.com/luxfi/node/staking"
)

// ValidatorKeys represents the keys needed for a validator
type ValidatorKeys struct {
	NodeID      string
	StakingCert string
	StakingKey  string
}

// ValidatorKeysWithTLS includes TLS certificates
type ValidatorKeysWithTLS struct {
	ValidatorKeys
	TLSCert string
	TLSKey  string
}

// ValidatorInfo represents validator configuration
type ValidatorInfo struct {
	NodeID      string `json:"nodeId"`
	StakingCert string `json:"stakingCert"`
	StakingKey  string `json:"stakingKey"`
	ETHAddress  string `json:"ethAddress,omitempty"`
}

// KeyGenerator generates validator keys
type KeyGenerator struct{}

// NewKeyGenerator creates a new key generator
func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{}
}

// Generate creates a new set of validator keys
func (kg *KeyGenerator) Generate() (*ValidatorKeysWithTLS, error) {
	// Generate staking certificate
	certBytes, keyBytes, err := staking.NewCertAndKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate staking cert: %w", err)
	}

	// Generate TLS certificate
	tlsCertBytes, tlsKeyBytes, err := staking.NewCertAndKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	// Parse the cert to get NodeID
	parsedCert, err := staking.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	nodeID := ids.NodeIDFromCert((*ids.Certificate)(parsedCert))

	return &ValidatorKeysWithTLS{
		ValidatorKeys: ValidatorKeys{
			NodeID:      nodeID.String(),
			StakingCert: string(certBytes),
			StakingKey:  string(keyBytes),
		},
		TLSCert: string(tlsCertBytes),
		TLSKey:  string(tlsKeyBytes),
	}, nil
}

// GenerateFromPrivateKey creates keys from an existing private key
func (kg *KeyGenerator) GenerateFromPrivateKey(privateKeyHex string) (*ValidatorKeysWithTLS, error) {
	// For now, just generate new keys
	// In a real implementation, this would derive from the provided key
	return kg.Generate()
}

// GenerateFromSeed creates keys from a seed phrase
func (kg *KeyGenerator) GenerateFromSeed(seed string, index int) (*ValidatorKeysWithTLS, error) {
	// For now, just generate new keys
	// In a real implementation, this would derive from the seed
	return kg.Generate()
}

// GenerateFromSeedWithTLS creates keys from a seed phrase with TLS support
func (kg *KeyGenerator) GenerateFromSeedWithTLS(seed string, index int) (*ValidatorKeysWithTLS, error) {
	// For now, just generate new keys
	// In a real implementation, this would derive from the seed
	return kg.Generate()
}

// GenerateCompatibleKeys generates multiple sets of compatible keys
func (kg *KeyGenerator) GenerateCompatibleKeys(count int) ([]*ValidatorKeysWithTLS, error) {
	keys := make([]*ValidatorKeysWithTLS, count)
	for i := 0; i < count; i++ {
		keySet, err := kg.Generate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key %d: %w", i, err)
		}
		keys[i] = keySet
	}
	return keys, nil
}

// SaveKeys saves validator keys to disk
func SaveKeys(keys *ValidatorKeysWithTLS, outputPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save staking cert
	stakingCertPath := filepath.Join(outputPath, "staker.crt")
	if err := ioutil.WriteFile(stakingCertPath, []byte(keys.StakingCert), 0644); err != nil {
		return fmt.Errorf("failed to write staking cert: %w", err)
	}

	// Save staking key
	stakingKeyPath := filepath.Join(outputPath, "staker.key")
	if err := ioutil.WriteFile(stakingKeyPath, []byte(keys.StakingKey), 0600); err != nil {
		return fmt.Errorf("failed to write staking key: %w", err)
	}

	// Save TLS cert
	tlsCertPath := filepath.Join(outputPath, "tls.crt")
	if err := ioutil.WriteFile(tlsCertPath, []byte(keys.TLSCert), 0644); err != nil {
		return fmt.Errorf("failed to write TLS cert: %w", err)
	}

	// Save TLS key
	tlsKeyPath := filepath.Join(outputPath, "tls.key")
	if err := ioutil.WriteFile(tlsKeyPath, []byte(keys.TLSKey), 0600); err != nil {
		return fmt.Errorf("failed to write TLS key: %w", err)
	}

	// Save node ID
	nodeIDPath := filepath.Join(outputPath, "node.id")
	if err := ioutil.WriteFile(nodeIDPath, []byte(keys.NodeID), 0644); err != nil {
		return fmt.Errorf("failed to write node ID: %w", err)
	}

	return nil
}

// GenerateValidatorConfig creates a validator configuration
func GenerateValidatorConfig(keys ValidatorKeys, ethAddress string, stakeAmount interface{}, network interface{}) *ValidatorInfo {
	return &ValidatorInfo{
		NodeID:      keys.NodeID,
		StakingCert: keys.StakingCert,
		StakingKey:  keys.StakingKey,
		ETHAddress:  ethAddress,
	}
}

// SaveValidatorConfigs saves validator configurations to a JSON file
func SaveValidatorConfigs(configs []*ValidatorInfo, outputPath string) error {
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configs: %w", err)
	}

	if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write configs: %w", err)
	}

	return nil
}
