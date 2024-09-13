/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.24;

/// @title IERC712CompliantPlugin
/// @author Circle
/// @notice Interface for ERC6900 modular smart contract account plugin compatible with ERC1271 standard signature
/// validation.
/// @notice Design and description inspired by Alchemy's [Equally Weighted Multisig
/// Plugin](https://github.com/alchemyplatform/multisig-plugin).
///
/// The implementation of this interface is recommended to support
/// [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the owner of
/// modular account also supports ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be
/// used as owners to validate user operation signatures. For example, the
/// contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967
/// proxy as it accesses a constant implementation slot not associated with
/// the account, violating storage access rules. This also means that the
/// owner of a modular account may not be another modular account if you want to
/// send user operations through a bundler.
interface IERC712CompliantPlugin {
    /// @notice Gets the EIP712 domain
    /// @dev This implementation is different from typical 712 via its use of msg.sender instead. As such, it
    /// should only be called from the SCAs that has installed this. See ERC-5267.
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );

    /// @notice Returns the pre-image of the message hash
    /// @dev Assumes that the SCA's implementation of `domainSeparator` is this plugin's
    /// @param account SCA to build the message encoding for
    /// @param message Message that should be encoded.
    /// @return Encoded message.
    function encodeMessageData(address account, bytes memory message) external view returns (bytes memory);

    /// @notice Returns hash of a message that can be signed by owners.
    /// @param account SCA to build the message hash for
    /// @param message Message that should be hashed.
    /// @return Message hash.
    function getMessageHash(address account, bytes memory message) external view returns (bytes32);
}
