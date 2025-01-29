## Weighted Multisig Module
Weighted Multisig Module is an ERC6900-compatible weighted multisig validation module that supports both EOA, smart contract and public key signers. In a weighted multisig, each signer has an individual weight, and in order to form a valid multisig signature, enough signatures must be provided to accumulate a specified threshold weight.

## Core Functionalities
Core features include:
1. Weighted multisig validation on execution functions.
2. Execution functions that modify account by adding signers, removing signers, updating signer weights, and/or modifying the threshold weight. These functions are guarded by the above validation function.
3. Support for EOA signers, ERC-1271 smart contract signers and public key signers.

## Technical Decisions
### UserOp Flow
When operating a multisig, there may be significant time elapsed between individual signings. This can be problematic when choosing user op gas fields to sign over, as network fees may fluctuate between signings. To solve this issue: for k signers, the module allows the first k - 1 signers to sign over a "minimal user op", and allows the final k-th signer to set the remaining fields. Specifically, the first k - 1 signers sign over the following user op fields with actual values:
- sender
- nonce
- initCode
- callData

Remaining user op fields should be set to their default values.
The k-th signature should sign over a user op with all fields set to their actual values. Additionally, the `v` value of the k-th signature should be incremented by 32 to denote that the signature is over the actual gas values.

### Runtime Flow
TODO.

### Multisig signature spec
Please refer to [Smart_Contract_Signatures_Encoding](../../../../../../docs/Smart_Contract_Signatures_Encoding.md).

## Acknowledgements
The signature verification logic takes inspiration from the work done by [Gnosis Safe](https://github.com/safe-global/safe-smart-account).
