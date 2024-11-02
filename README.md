# buidl-wallet-contracts
Official repository for all smart wallet contracts used by Circle web3 API/SDK. 

This repository includes support for both the Hardhat and Foundry frameworks. Going forward, all new code / tests / scripts should be built on Foundry. Hardhat is currently only included for legacy contracts in the following folders:
- `src/account/v1`
- `src/paymaster/v1/permissioned`

## Setup
1. Run `git submodule update --init --recursive` to update/download all libraries.
2. Run `yarn install` to install any additional dependencies.
3. Run `curl -L https://foundry.paradigm.xyz | bash` and follow the outputted instructions to source env file. 
4. Run `foundryup`
5. Create a `.env` file and provide the required API keys, wallets (can be generated for deployment), and configuration values. You can look at the `.env.example` for reference.

## Development

### Lint
Run `yarn lint` to lint all `.sol` files in the `src` and `test` directories. Run `yarn format:check` and `yarn format:write` to check for, and fix formatting issues, respectively.

### Test
To run tests using Foundry, follow the steps below:
1. Run `yarn build`
2. Run `yarn test`

### Test Coverage
To generate a viewable test coverage report, run:
- `brew install lcov` if not yet installed
- `forge coverage --ir-minimum --report lcov && genhtml lcov.info -o report --branch-coverage && open report/index.html`
(Note: some contracts like WeightedMultisigPlugin require using --ir-minimum because of stack depth. To build coverage
faster locally, comment out this and dependent contracts and omit --ir-minimum flag.)


### Continuous Integration
We use Github actions to run linter and all the tests. The workflow configuration can be found in [.github/workflows/ci.yml](.github/workflows/ci.yml)


### Release
We are using [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) structure to automatically generate releases.

## Export Interface
To export contract bytecode & ABI for programmable wallet:
1. Execute `forge build src/msca/6900/v0.7 --force --extra-output-files abi evm`. Replace v0.7 with v0.8 if you want v0.8.
2. Execute `make abigen`
3. Interface files will appear under `abigen` folder
4. After changes are merged, release new repository tag
5. update `buidl-wallet-contracts` go mod version of programmable-wallet, and import bytecode from `abigen` folder

For running integration tests in Anvil node, run `make anvil-tests`. This runs the python tests in [test/anvil](test/anvil/)

## Gas Report
### Function report
* Run `yarn build`
* Run `yarn gasreport`

### E2E gas benchmarking
* `anvil`
* update `.env` (pointing to local) and `source .env`
* deploy (only choose the account type you're interested in benchmarking)
  * `forge script script/<SCRIPT_NAME> --rpc-url $RPC_URL --broadcast --verify -vvvv --slow --watch`

    Example: `forge script script/001_DeployPluginManager.s.sol --rpc-url $RPC_URL --broadcast --verify -vvvv --slow --watch`

* `cast code $address`

## On-chain Deployment & Verification

### Start a Local Network (optional, for testing)

`npx hardhat node` (if using hardhat stack)

`make anvil` (if using foundry stack). To get a list of pre-funded addresses, you can look at the beginning of the logs in the `anvil` Docker container, or reference <https://github.com/foundry-rs/foundry/blob/0d8302880b79fa9c3c4aa52ab446583dece19a34/crates/anvil/README.md?plain=1#L48>.

### Deploy & Verify
#### SCA and Paymaster
  1. Deployment
      * Run the command `env $(grep -v '^#' .env) yarn hardhat deploy --network <chain>` where `<chain>` is one of {`mumbai`, `goerli`}.

        If you only want to deploy a specific set of smart contracts, you can add the `--tags` flag, for example: `env $(grep -v '^#' .env) yarn hardhat deploy --tags SponsorPaymaster --network goerli`
  2. Verification
      * ECDSA wallet factory `env $(grep -v '^#' .env) npx hardhat verify --network mumbai --constructor-args script/ecdsa_account_factory_constructor_args.js ECDSA_ACCOUNT_FACTORY_ADDRESS`
      * Sponsor paymaster `env $(grep -v '^#' .env) npx hardhat verify --network goerli --constructor-args script/sponsor_paymaster_constructor_args.js STABLECOIN_PAYMASTER_ADDRESS`
      * Fallback: If the verification commands do not work for contracts deployed through the hardhat deployment scripts, you can still verify manually through etherscan's UI by submitting the standard input json. 
      
        You can find this file under `deployments/polygon/solcInputs` (you can try different blockchains but I'm unsure of the results). Then submit the file that you think is the one for the contract you're trying to verify. It's a bit of guessing, but you can look at the source code to try and figure it out. You may also need to verify the proxies manually through etherscan after having verified the implementation.
#### MSCA
  1. Set up `DEPLOYER_PRIVATE_KEY`, `RPC_URL` and `ETHERSCAN_API_KEY` in .env
  2. Run `source .env`
  3. Run the desired numbered scripts inside the `script/` folder using the below command format. Make sure any environment variable values from previous steps are updated if needed as you progress through the scripts.
       * `forge script script/<SCRIPT_NAME> --rpc-url $RPC_URL --broadcast --verify -vvvv`
       
          Example: `forge script script/001_DeployPluginManager.s.sol --rpc-url $RPC_URL --broadcast --verify -vvvv`

      Tip: before executing the above command, verify the simulation works as expected by running the above command without the `--broadcast` and `--verify` flags. This way, you can also make sure your address will have enough tokens to cover the transaction fee estimated in the simulation.

      Note: if you are deploying on a local network, don't use the `--verify` flag.
    
  4. Include the relevant logs from the `broadcast` folder in your commit.

        Tip: if you did multiple runs, search the appropriate block explorer for the tx hash corresponding to the desired contract's deployment, and then search the logs for the transaction hash.

        Tip: logs are organized by chain ID in the lower levels in the `broadcast` folder. Use <https://chainlist.org/> to lookup IDs of common chains.

  5. Create or update the corresponding file in the `script/cmd` folder using the creation bytecode of the contract from the logs. See the below "Chain Expansion" section for details on how to format the files in the `script/cmd` folder.
  6. Verify in block explorer like etherscan using standard input json
       * Create the standard input json: run the below command
       
          ```shell
          forge verify-contract <contract_address> <relative_path_to_source:classname> --show-standard-json-input > <script/verify/<filename>

          # Example
          forge verify-contract 0x03431fb00fb2e26b5bc502dfef8da30e1c8643b8 src/msca/6900/v0.7/plugins/v1_0_0/utility/DefaultTokenCallbackPlugin.sol:DefaultTokenCallbackPlugin --show-standard-json-input > script/verify/DefaultTokenCallbackPlugin.json
          ```
       * Verify and publish in block explorer (etherscan example)
         * Compiler type: `Solidity (Standard-Json-Input)`
         * Compiler version: `v0.8.24`
         * License: Option 5 in https://etherscan.io/contract-license-types
         * Upload the JSON file
         * If the contract you are verifying took constructor arguments, input the output of the below command with the `0x` prefix removed into the "Constructor Arguments ABI-encoded" section:

            ```shell
            cast abi-encode "constructor(<arg type 1>, <arg type 2>, ...)" "arg1Val" "arg2Val"

            # Example
            cast abi-encode "constructor(address,address,uint256)" "0x0166EA90E565476f13c6a0D25ED2C35599E58785" "0x0000000071727De22E5E9d8BAf0edAc6f37da032" 18
            ```

            Make sure to save this output under `script/verify/<ContractName>/abiEncodedConstructorArgs`.
            
            Tip: if your contract's constructor arguments have complicated types, you can get this value instead by `console.log`ing the output of `abi.encode(arg1, arg2, ...)` in Solidity.

          * For account factory contracts, you may also need to manually verify the proxy contract. To do this, you will first need to create an account using the account factory, and follow the above strategy. After verifying one account, all subsequent proxies should be automatically detected.

            Tip: analyze the account creation function on the factory (e.g. `createAccount` for `SingleOwnerMSCAFactory`) to deduce the constructor arguments for the proxy deployment when trying to verify it on a block explorer.

         * Click verify and publish

### Deployment Metadata

The below contract deployment is based on abi and bytecode to ensure the same address across all EVM-compatible chains. The abi and bytecode for each of the contracts are available at the locations below. These files were generated from first deployments, will all fields except `abi` and `bytecode` be removed.

| Contract Name | Location |
|:------------------------:|:------------------------:|
| ECDSAAcountFactory | `deploy/metadata/ECDSAAccountFactory.json` |
| SponsorPaymaster_Implementation | `deploy/metadata/SponsorPaymaster_Implementation.json` |
| SponsorPaymaster_Proxy | `deploy/metadata/SponsorPaymaster_Proxy.json` |

### Chain Expansion

To ensure consistent deployment of contracts across chains, we store the `cast send` deployment commands for contracts in the `script/cmd` folder. To deploy these contracts, simply run the command inside the file corresponding to that contract on the command line.

To build the `cast send` deployment command for a contract:
1. Run the Solidity deployment script for the contract in the `script/*` folder:
1. Find the deployment result in broadcast/*
2. Looking for “transactions” -> ”transaction” → “data” in run-*.json
3. Copy the "data" in step 2 without "0x" prefix. 
4. Add `cast send --rpc-url $RPC_URL --private-key $DEPLOYER_PRIVATE_KEY 0x4e59b44847b379578588920cA78FbF26c0B4956C 0x0000000000000000000000000000000000000000000000000000000000000000` in front of the bytecode from previous step (no space)

   Refer to the note after these steps, you may not need the `0x0...` prefix. The `0x4e59b44847b379578588920cA78FbF26c0B4956C` is foundry's default create2 address deployer. See <https://book.getfoundry.sh/reference/cast/cast-create2>.
5. Run the command in step5 in Terminal.
6. Save this command to script/cmd folder with `<script_name>`
7. Create the README under `broadcast` folder for the chain id. For example, see `broadcast/011_DeployTokenCallbackPlugin.s.sol/11155111/README.md`

Note: The "data" field may be called "input". Additionally, if the input/data field already contains the leading `0000000000000000000000000000000000000000000000000000000000000000` prefix, simply copy this value over directly (no need to re-add the zeros prefix).

## Troubleshooting
#### 1. `make: *** [test] Error 137`

If you encountered this error after executing `make test`, try increasing memory resource for docker engine.

#### 2. Encounter `ERROR: failed to solve: operating system is not supported` when executing `make build`
If you are using macbook with M1 or newer chips, try enabling `Use Rosetta for x86/amd64 emulation on Apple Silicon` under `Features in development` in Docker settings.

#### 3. Docker container `foundry:latest` not found
As an alternative to the above, if you are using macbook with M1 or newer chips, try adding the `--platform=linux/amd64` flag to the `build` Make command. If you encounter this error while running `make anvil`, make sure to run `make` before.

#### 4. API key errors when running deploy scripts on a local blockchain
When deploying contract deployment scripts from the `/script` folder on a local chain (started up using `make anvil`), you can remove the `--verify` flag if you are getting errors related to the API key, such as `Missing etherscan key for chain 31337`.

#### 5. failed to read artifact source file for ...

Run `forge clean && forge build`.
