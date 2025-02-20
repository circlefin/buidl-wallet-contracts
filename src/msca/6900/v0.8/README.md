# Modular Smart Contract Account
MSCA that's in compliant with [ERC-6900](https://eips.ethereum.org/EIPS/eip-6900).

## Disclaimer
Please be aware that all contracts within this package are still in active development and are not deployed on any mainnets yet, so proceed with caution if you intend to test them on your own.

## Features
1. Deploy an account using the account factory.
2. Receive **ERC-721, ERC-1155,** and **ERC-777** tokens.
3. Supports **ERC-1271** for contract signatures.
4. Enables **upgradeability** via the **ERC-1967 proxy**, allowing users to update their proxy’s implementation and choose different smart account versions. We follow the **ERC-7201 namespaced storage standard** to prevent storage collisions when switching implementations.
5. **Extensible through modules**, allowing additional functionality to be integrated into the account.

## Acknowledgements
The contracts in this repository follow the **ERC-6900 specification** and are largely inspired by the design of its reference implementation.
