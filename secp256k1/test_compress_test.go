package secp256k1_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/crypto/secp256k1"
)

func TestCompressKey(t *testing.T) {
	privKeyHex := "abd51d463510cb17d7ba09e535828383d9c2c817aa386024aacce1660a1ee625"
	privKeyBytes, _ := hex.DecodeString(privKeyHex)

	privKey, err := secp256k1.ToPrivateKey(privKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := privKey.PublicKey()

	// Print raw fields
	fmt.Printf("pubKey.Bytes() (stored bytes): %x\n", pubKey.Bytes())
	fmt.Printf("pubKey.CompressedBytes(): %x\n", pubKey.CompressedBytes())

	// Hash
	compressed := pubKey.CompressedBytes()
	addrBytes := hash.PubkeyBytesToAddress(compressed)
	fmt.Printf("Address bytes: %x\n", addrBytes)

	addr := pubKey.Address()
	fmt.Printf("Address(): %x\n", addr[:])

	fmt.Printf("\nExpected (genesis): cd6a2975ad2514c903b57ba057f1dc2e143207d9\n")
}
