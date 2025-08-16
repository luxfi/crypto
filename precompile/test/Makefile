.PHONY: install test test-anvil test-fork clean

# Install Foundry if not already installed
install:
	@which forge > /dev/null || curl -L https://foundry.paradigm.xyz | bash
	@foundryup
	@forge install foundry-rs/forge-std --no-commit

# Run tests on local Anvil with custom precompiles
test-anvil:
	@echo "Starting Anvil with custom precompiles..."
	@anvil --fork-url http://localhost:8545 \
		--code-size-limit 100000 \
		--gas-limit 30000000 \
		--accounts 10 \
		--balance 1000 \
		--port 8546 &
	@sleep 2
	@echo "Running tests..."
	@forge test -vvv --rpc-url http://localhost:8546
	@pkill anvil

# Run tests against local Lux node
test-local:
	@echo "Testing against local Lux node..."
	@forge test -vvv --rpc-url http://localhost:8545

# Run tests on Lux testnet
test-testnet:
	@echo "Testing on Lux testnet..."
	@forge test -vvv --rpc-url ${LUX_TESTNET_RPC}

# Run the test script
script:
	@forge script script/TestPrecompiles.s.sol:TestPrecompilesScript \
		--rpc-url http://localhost:8545 \
		--broadcast \
		-vvvv

# Run all tests
test: test-anvil

# Clean build artifacts
clean:
	@forge clean
	@rm -rf out cache

# Build contracts
build:
	@forge build

# Run gas report
gas:
	@forge test --gas-report

# Format Solidity code
fmt:
	@forge fmt

# Check Solidity formatting
fmt-check:
	@forge fmt --check