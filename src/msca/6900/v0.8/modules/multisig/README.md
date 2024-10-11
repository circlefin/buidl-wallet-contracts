## Weighted Multisig Module

Weighted Multisig Module is an ERC6900-compatible weighted multisig ownership module that supports both EOA and smart contract owners. In a weighted multisig, each signer has an individual weight, and in order to form a valid multisig signature, enough signatures must be provided to accumulate a specified threshold weight.

## Core Functionalities

Weighted Multisig Module is an module that provides validation functions for a weighted multisig ownership scheme. **Multisig validation only works in the user operation context.**

Its core features include:
1. Weighted multisig user operation validation on native account functions (`installModule`, `uninstallModule`, `execute`, `executeBatch`, `upgradeToAndCall`).
2. Execution functions that modify account ownership by adding owners, removing owners, or updating owner weights, and/or modifying the threshold weight. These functions are guarded by the above validation function.
3. Support for ERC-1271 smart contract signatures based on the same multisig scheme.

### Technical Decisions

#### Multisig validation scheme is applied only for the User Operation context
We expect multisig signers to implement key management best practices such as key rotation. By using the user operation path, keys can be used just for signing without needing to procure native tokens for gas. Like other ERC-4337 operations, the transaction would be paid for by the account or by a paymaster service.

#### User Op Fields To Sign Over
When operating a multisig, there may be significant time elapsed between individual signings. This can be problematic when choosing user op gas fields to sign over, as network fees may fluctuate between signings. To solve this issue: for k signers, the module allows the first k - 1 signers to sign over a "minimal user op", and allows the final k-th signer to set the remaining fields. Specifically, the first k - 1 signers sign over the following user op fields with actual values:
- sender
- nonce
- initCode
- callData

Remaining user op fields should be set to their default values. See [default minimal user op values](https://github.com/circlefin/smart-wallet-contracts/blob/57e1588729694d3d4b09e6d4b590713e04192093/src/msca/6900/v0.8/modules/v1_0_0/multisig/BaseMultisigModule.sol#L94-L123) for reference.

The k-th signature should sign over a user op with all fields set to their actual values. Additionally, the `v` value of the k-th signature should be incremented by 32 to denote that the signature is over the actual gas values.

#### Multisig signature spec
The multisig signature scheme has the following format:

`k signatures` || `contract signatures (if any)`

Each signature in the `k signatures` is sorted in ascending order by owner address, is 65 bytes long, uses packed encoding and has the following format:
1. If it's an EOA signature, `signature = abi.encodePacked(r, s, v)`
2. If it's a contract signature, it is also `abi.encodePacked(r, s, v)` with `v` set to 0, `r` set to the address of the contract owner expanded to 32 bytes, and `s` being the bytes offset of where the actual signature is located. This is relative to the starting location of `k signatures`. The actual contract signature has regular ABI encoding, appended after the `k signatures`.

Each of the `k signatures` must be signed by an owner of the module, the k signers must cumulatively have at least the threshold weight set for the account. If at least 1 signer signed over a minimal digest which is different than the actual digest, then exactly 1 signer must sign over the actual digest, within the first k signatures which add up to the threshold weight.

## Acknowledgements

The weighted multisig module takes inspiration from [Alchemy's Multisig Module](https://github.com/alchemyplatform/multisig-module).

The signature verification logic takes inspiration from the work done by [Gnosis Safe](https://github.com/safe-global/safe-smart-account).
