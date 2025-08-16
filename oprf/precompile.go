package oprf

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Precompile addresses for VOPRF operations
var (
	VOPRFSetupAddress    = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA0}
	VOPRFEvaluateAddress = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA1}
	VOPRFVerifyAddress   = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA2}
	VOPRFFinalizeAddress = [20]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA3}
)

// Gas costs for VOPRF operations
const (
	VOPRFSetupGas    = 150000
	VOPRFEvaluateGas = 200000
	VOPRFVerifyGas   = 250000
	VOPRFFinalizeGas = 180000
	
	// Per-byte costs
	VOPRFInputGas  = 200
	VOPRFOutputGas = 100
)

// VOPRFSetupPrecompile handles VOPRF key generation and setup
type VOPRFSetupPrecompile struct{}

// RequiredGas calculates the gas required for VOPRF setup
func (v *VOPRFSetupPrecompile) RequiredGas(input []byte) uint64 {
	return VOPRFSetupGas + uint64(len(input))*VOPRFInputGas
}

// Run executes VOPRF setup
// Input format: [suite(1)][mode(1)][seed(32) optional]
// Output format: [private_key][public_key]
func (v *VOPRFSetupPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 2 {
		return nil, errors.New("invalid input: too short")
	}
	
	suite := Suite(input[0])
	// mode := Mode(input[1]) // For future use
	
	var privateKey *PrivateKey
	var err error
	
	if len(input) >= 34 {
		// Derive from seed
		seed := input[2:34]
		privateKey, err = DeriveKey(suite, seed)
	} else {
		// Generate random key
		privateKey, err = GenerateKey(suite)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	
	// Serialize keys
	privData := privateKey.Serialize()
	pubData := privateKey.Public().Serialize()
	
	// Pack output: [priv_len(2)][priv_data][pub_len(2)][pub_data]
	output := make([]byte, 2+len(privData)+2+len(pubData))
	binary.BigEndian.PutUint16(output[0:2], uint16(len(privData)))
	copy(output[2:], privData)
	binary.BigEndian.PutUint16(output[2+len(privData):], uint16(len(pubData)))
	copy(output[4+len(privData):], pubData)
	
	return output, nil
}

// VOPRFEvaluatePrecompile handles server-side evaluation
type VOPRFEvaluatePrecompile struct{}

// RequiredGas calculates the gas required for VOPRF evaluation
func (v *VOPRFEvaluatePrecompile) RequiredGas(input []byte) uint64 {
	return VOPRFEvaluateGas + uint64(len(input))*VOPRFInputGas
}

// Run executes VOPRF evaluation
// Input format: [suite(1)][priv_key_len(2)][priv_key][eval_req_len(2)][eval_req]
// Output format: [eval_response]
func (v *VOPRFEvaluatePrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 6 {
		return nil, errors.New("invalid input: too short")
	}
	
	suite := Suite(input[0])
	privKeyLen := binary.BigEndian.Uint16(input[1:3])
	
	if len(input) < int(3+privKeyLen+2) {
		return nil, errors.New("invalid input: missing private key")
	}
	
	privKeyData := input[3 : 3+privKeyLen]
	privateKey, err := DeserializePrivateKey(suite, privKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}
	
	evalReqOffset := 3 + privKeyLen
	evalReqLen := binary.BigEndian.Uint16(input[evalReqOffset : evalReqOffset+2])
	evalReqData := input[evalReqOffset+2 : evalReqOffset+2+evalReqLen]
	
	evalReq, err := DeserializeEvaluationRequest(suite, evalReqData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize evaluation request: %w", err)
	}
	
	server, err := NewServer(suite, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}
	
	evalResp, err := server.Evaluate(evalReq)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate: %w", err)
	}
	
	return evalResp.Serialize(), nil
}

// VOPRFFinalizePrecompile handles client-side finalization
type VOPRFFinalizePrecompile struct{}

// RequiredGas calculates the gas required for VOPRF finalization
func (v *VOPRFFinalizePrecompile) RequiredGas(input []byte) uint64 {
	return VOPRFFinalizeGas + uint64(len(input))*VOPRFInputGas
}

// Run executes VOPRF finalization
// Input format: [suite(1)][input_len(2)][input][eval_resp_len(2)][eval_resp]
// Output format: [output(32)]
func (v *VOPRFFinalizePrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 6 {
		return nil, errors.New("invalid input: too short")
	}
	
	suite := Suite(input[0])
	inputLen := binary.BigEndian.Uint16(input[1:3])
	
	if len(input) < int(3+inputLen+2) {
		return nil, errors.New("invalid input: missing input data")
	}
	
	inputData := input[3 : 3+inputLen]
	
	// Create client and blind the input
	client, err := NewClient(suite)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	
	evalReq, finalData, err := client.Blind(inputData)
	if err != nil {
		return nil, fmt.Errorf("failed to blind input: %w", err)
	}
	
	// Get evaluation response from input
	evalRespOffset := 3 + inputLen
	evalRespLen := binary.BigEndian.Uint16(input[evalRespOffset : evalRespOffset+2])
	evalRespData := input[evalRespOffset+2 : evalRespOffset+2+evalRespLen]
	
	evalResp, err := DeserializeEvaluationResponse(suite, evalRespData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize evaluation response: %w", err)
	}
	
	// Finalize
	output, err := client.Finalize(finalData, evalResp)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize: %w", err)
	}
	
	// For demonstration, also include the evaluation request in case it's needed
	_ = evalReq
	
	return output, nil
}

// VOPRFVerifyPrecompile handles verification in verifiable mode
type VOPRFVerifyPrecompile struct{}

// RequiredGas calculates the gas required for VOPRF verification
func (v *VOPRFVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return VOPRFVerifyGas + uint64(len(input))*VOPRFInputGas
}

// Run executes VOPRF verification
// Input format: [suite(1)][pub_key_len(2)][pub_key][input_len(2)][input][output_len(2)][output]
// Output format: [valid(1)] where 1=valid, 0=invalid
func (v *VOPRFVerifyPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 8 {
		return nil, errors.New("invalid input: too short")
	}
	
	suite := Suite(input[0])
	pubKeyLen := binary.BigEndian.Uint16(input[1:3])
	
	if len(input) < int(3+pubKeyLen+2) {
		return nil, errors.New("invalid input: missing public key")
	}
	
	pubKeyData := input[3 : 3+pubKeyLen]
	publicKey, err := DeserializePublicKey(suite, pubKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %w", err)
	}
	
	inputOffset := 3 + pubKeyLen
	inputLen := binary.BigEndian.Uint16(input[inputOffset : inputOffset+2])
	inputData := input[inputOffset+2 : inputOffset+2+inputLen]
	
	outputOffset := inputOffset + 2 + inputLen
	outputLen := binary.BigEndian.Uint16(input[outputOffset : outputOffset+2])
	outputData := input[outputOffset+2 : outputOffset+2+outputLen]
	
	// Create client and verify
	client, err := NewClient(suite)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	
	err = client.VerifyFinalize(publicKey, inputData, outputData)
	if err != nil {
		return []byte{0}, nil // Invalid
	}
	
	return []byte{1}, nil // Valid
}

// Helper function to extract suite from precompile input
func ExtractSuite(input []byte) (Suite, error) {
	if len(input) < 1 {
		return 0, errors.New("input too short to extract suite")
	}
	return Suite(input[0]), nil
}