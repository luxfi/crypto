package oprf

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestVOPRFBasicFlow(t *testing.T) {
	suites := []Suite{
		OPRFP256,
		OPRFP384, 
		OPRFP521,
		OPRFRistretto255,
	}

	for _, suite := range suites {
		t.Run(suite.String(), func(t *testing.T) {
			// Generate server key
			privateKey, err := GenerateKey(suite)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			// Create server
			server, err := NewServer(suite, privateKey)
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}

			// Create client
			client, err := NewClient(suite)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Input data
			input := []byte("test input data")

			// Client blinds the input
			evalReq, finalData, err := client.Blind(input)
			if err != nil {
				t.Fatalf("failed to blind: %v", err)
			}

			// Server evaluates
			evalResp, err := server.Evaluate(evalReq)
			if err != nil {
				t.Fatalf("failed to evaluate: %v", err)
			}

			// Client finalizes
			output, err := client.Finalize(finalData, evalResp)
			if err != nil {
				t.Fatalf("failed to finalize: %v", err)
			}

			// Verify output is deterministic
			serverOutput, err := server.FullEvaluate(input)
			if err != nil {
				t.Fatalf("failed to full evaluate: %v", err)
			}

			if !bytes.Equal(output, serverOutput) {
				t.Error("client output doesn't match server output")
			}
		})
	}
}

func TestVOPRFBatchFlow(t *testing.T) {
	suite := OPRFRistretto255

	// Generate server key
	privateKey, err := GenerateKey(suite)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create server
	server, err := NewServer(suite, privateKey)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create client
	client, err := NewClient(suite)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Batch inputs
	inputs := [][]byte{
		[]byte("input1"),
		[]byte("input2"),
		[]byte("input3"),
		[]byte("input4"),
		[]byte("input5"),
	}

	// Client blinds batch
	evalReqs, finalDatas, err := client.BlindBatch(inputs)
	if err != nil {
		t.Fatalf("failed to blind batch: %v", err)
	}

	// Server evaluates batch
	evalResps, err := server.EvaluateBatch(evalReqs)
	if err != nil {
		t.Fatalf("failed to evaluate batch: %v", err)
	}

	// Client finalizes batch
	outputs, err := client.FinalizeBatch(finalDatas, evalResps)
	if err != nil {
		t.Fatalf("failed to finalize batch: %v", err)
	}

	// Verify outputs
	for i, input := range inputs {
		serverOutput, err := server.FullEvaluate(input)
		if err != nil {
			t.Fatalf("failed to full evaluate input %d: %v", i, err)
		}

		if !bytes.Equal(outputs[i], serverOutput) {
			t.Errorf("output mismatch for input %d", i)
		}
	}
}

func TestVOPRFKeySerialization(t *testing.T) {
	suite := OPRFP256

	// Generate key
	privateKey, err := GenerateKey(suite)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Serialize private key
	privData := privateKey.Serialize()

	// Deserialize private key
	privKey2, err := DeserializePrivateKey(suite, privData)
	if err != nil {
		t.Fatalf("failed to deserialize private key: %v", err)
	}

	// Check they produce same output
	input := []byte("test")
	
	server1, _ := NewServer(suite, privateKey)
	server2, _ := NewServer(suite, privKey2)
	
	output1, _ := server1.FullEvaluate(input)
	output2, _ := server2.FullEvaluate(input)
	
	if !bytes.Equal(output1, output2) {
		t.Error("deserialized key produces different output")
	}

	// Test public key serialization
	publicKey := privateKey.Public()
	pubData := publicKey.Serialize()
	
	pubKey2, err := DeserializePublicKey(suite, pubData)
	if err != nil {
		t.Fatalf("failed to deserialize public key: %v", err)
	}
	
	if !bytes.Equal(publicKey.Serialize(), pubKey2.Serialize()) {
		t.Error("public key serialization mismatch")
	}
}

func TestVOPRFDeriveKey(t *testing.T) {
	suite := OPRFRistretto255
	
	// Generate random seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("failed to generate seed: %v", err)
	}
	
	// Derive key from seed
	key1, err := DeriveKey(suite, seed)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}
	
	// Derive again with same seed
	key2, err := DeriveKey(suite, seed)
	if err != nil {
		t.Fatalf("failed to derive key again: %v", err)
	}
	
	// Keys should be identical
	if !bytes.Equal(key1.Serialize(), key2.Serialize()) {
		t.Error("derived keys from same seed don't match")
	}
	
	// Test with different seed
	seed2 := make([]byte, 32)
	if _, err := rand.Read(seed2); err != nil {
		t.Fatalf("failed to generate seed2: %v", err)
	}
	
	key3, err := DeriveKey(suite, seed2)
	if err != nil {
		t.Fatalf("failed to derive key3: %v", err)
	}
	
	// Keys should be different
	if bytes.Equal(key1.Serialize(), key3.Serialize()) {
		t.Error("keys from different seeds shouldn't match")
	}
}

func TestVOPRFMessageSerialization(t *testing.T) {
	suite := OPRFP384
	
	// Setup
	privateKey, _ := GenerateKey(suite)
	server, _ := NewServer(suite, privateKey)
	client, _ := NewClient(suite)
	
	input := []byte("serialize this")
	
	// Blind
	evalReq, finalData, err := client.Blind(input)
	if err != nil {
		t.Fatalf("failed to blind: %v", err)
	}
	
	// Serialize request
	reqData := evalReq.Serialize()
	
	// Deserialize request
	evalReq2, err := DeserializeEvaluationRequest(suite, reqData)
	if err != nil {
		t.Fatalf("failed to deserialize request: %v", err)
	}
	
	// Server evaluates deserialized request
	evalResp, err := server.Evaluate(evalReq2)
	if err != nil {
		t.Fatalf("failed to evaluate: %v", err)
	}
	
	// Serialize response
	respData := evalResp.Serialize()
	
	// Deserialize response
	evalResp2, err := DeserializeEvaluationResponse(suite, respData)
	if err != nil {
		t.Fatalf("failed to deserialize response: %v", err)
	}
	
	// Client finalizes with deserialized response
	output, err := client.Finalize(finalData, evalResp2)
	if err != nil {
		t.Fatalf("failed to finalize: %v", err)
	}
	
	// Verify output
	serverOutput, _ := server.FullEvaluate(input)
	if !bytes.Equal(output, serverOutput) {
		t.Error("output mismatch after serialization")
	}
}

func TestVOPRFErrorCases(t *testing.T) {
	suite := OPRFP256
	
	// Test nil private key
	_, err := NewServer(suite, nil)
	if err == nil {
		t.Error("expected error for nil private key")
	}
	
	// Test suite mismatch
	key384, _ := GenerateKey(OPRFP384)
	_, err = NewServer(OPRFP256, key384)
	if err == nil {
		t.Error("expected error for suite mismatch")
	}
	
	// Test nil evaluation request
	key, _ := GenerateKey(suite)
	server, _ := NewServer(suite, key)
	_, err = server.Evaluate(nil)
	if err == nil {
		t.Error("expected error for nil evaluation request")
	}
	
	// Test batch size mismatch
	client, _ := NewClient(suite)
	datas := []*FinalizeData{{}, {}}
	resps := []*EvaluationResponse{{}}
	_, err = client.FinalizeBatch(datas, resps)
	if err == nil {
		t.Error("expected error for batch size mismatch")
	}
}

func BenchmarkVOPRF(b *testing.B) {
	suites := []Suite{
		OPRFP256,
		OPRFP384,
		OPRFP521,
		OPRFRistretto255,
	}
	
	for _, suite := range suites {
		b.Run(suite.String(), func(b *testing.B) {
			privateKey, _ := GenerateKey(suite)
			server, _ := NewServer(suite, privateKey)
			client, _ := NewClient(suite)
			input := []byte("benchmark input data")
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				evalReq, finalData, _ := client.Blind(input)
				evalResp, _ := server.Evaluate(evalReq)
				client.Finalize(finalData, evalResp)
			}
		})
	}
}

func BenchmarkVOPRFBatch(b *testing.B) {
	suite := OPRFRistretto255
	batchSizes := []int{10, 50, 100, 500}
	
	for _, size := range batchSizes {
		b.Run(fmt.Sprintf("BatchSize%d", size), func(b *testing.B) {
			privateKey, _ := GenerateKey(suite)
			server, _ := NewServer(suite, privateKey)
			client, _ := NewClient(suite)
			
			// Prepare batch inputs
			inputs := make([][]byte, size)
			for i := range inputs {
				inputs[i] = []byte(fmt.Sprintf("input%d", i))
			}
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				evalReqs, finalDatas, _ := client.BlindBatch(inputs)
				evalResps, _ := server.EvaluateBatch(evalReqs)
				client.FinalizeBatch(finalDatas, evalResps)
			}
		})
	}
}