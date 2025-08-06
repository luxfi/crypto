package main

import (
	"fmt"
	"github.com/luxfi/crypto"
)

func main() {
	key, _ := crypto.HexToECDSA("289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032")
	addr := crypto.HexToAddress("970e8128ab834e8eac17ab8e3812f010678cf791")
	genAddr := crypto.PubkeyToAddress(key.PublicKey)
	
	fmt.Printf("addr: %s\n", addr.Hex())
	fmt.Printf("genAddr: %s\n", genAddr.Hex())
	fmt.Printf("Equal: %v\n", addr == genAddr)
	
	caddr0 := crypto.CreateAddress(addr, 0)
	fmt.Printf("Contract addr 0: %s\n", caddr0.Hex())
	fmt.Printf("Expected:        0x333c3310824b7c685133f2bedb2ca4b8b4df633d\n")
}
