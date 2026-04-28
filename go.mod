module github.com/luxfi/crypto

go 1.26.1

exclude github.com/luxfi/geth v1.16.1

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20260215031811-a0ab0b218a81
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/cloudflare/circl v1.6.3
	github.com/consensys/gnark-crypto v0.19.2
	github.com/crate-crypto/go-eth-kzg v1.5.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/ethereum/c-kzg-4844/v2 v2.1.5
	github.com/ethereum/go-bigmodexpfix v0.0.0-20250911101455-f9e208c548ab
	github.com/google/btree v1.1.3
	github.com/google/gofuzz v1.2.0
	github.com/jedisct1/go-minisign v0.0.0-20241212093149-d2f9f49435c7
	github.com/leanovate/gopter v0.2.11
	github.com/luxfi/accel v1.0.7
	github.com/luxfi/age v1.4.0
	github.com/luxfi/cache v1.1.0
	github.com/luxfi/go-verkle v0.2.3-luxfi
	github.com/luxfi/ids v1.2.9
	github.com/luxfi/log v1.4.1
	github.com/luxfi/mock v0.1.0
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.11.1
	github.com/supranational/blst v0.3.16
	github.com/zeebo/blake3 v0.2.4
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.48.0
	golang.org/x/sync v0.19.0
	golang.org/x/sys v0.41.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/crate-crypto/go-ipa v0.0.0-20240223125850-b1e8a79f509c // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/luxfi/crypto/ipa v1.2.4 // indirect
	github.com/luxfi/utils v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/zeebo/assert v1.3.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Route upstream crypto modules through luxfi-maintained mirrors so that
// downstream Lux services consume a single canonical source. See
// LUXFI-FORK.md in each fork for pin SHAs and sync policy.
replace github.com/crate-crypto/go-ipa => github.com/luxfi/go-ipa v0.0.0-20260427175713-d31adc040fa6
