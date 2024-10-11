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

import {MessageHashUtils} from "../../../../libs/MessageHashUtils.sol";

// @notice Inspired by 6900 reference implementation with some modifications.
// A base contract for modules that use EIP-712 structured data signing.
// Unlike other EIP712 libraries, this base contract uses the salt field (bytes32(bytes20(account)) to hold the
// account address
// and uses the verifyingContract field to hold module address.
// This abstract contract does not implement EIP-5267, as the domain retrieval function eip712Domain() does not provide
// a parameter to hold the account address.
// If we use verifyingContract to hold account address, then `msg.sender` would be address(0) for an `eth_call` without
// an override.
abstract contract BaseERC712CompliantModule {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    /// @notice Wraps a replay safe hash in an EIP-712 envelope to prevent cross-account replay attacks.
    /// domainSeparator = hashStruct(eip712Domain).
    /// eip712Domain = (string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
    /// The domain separator includes the chainId, module address and account address.
    /// hashStruct(s) = keccak256(typeHash ‖ encodeData(s)) where typeHash = keccak256(encodeType(typeOf(s)))
    /// @param account SCA to build the message hash for.
    /// @param hash Message that should be hashed.
    /// @return Replay safe message hash.
    function getReplaySafeMessageHash(address account, bytes32 hash) public view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash({
            domainSeparator: keccak256(
                abi.encode(
                    _DOMAIN_SEPARATOR_TYPEHASH, _getModuleIdHash(), block.chainid, address(this), bytes32(bytes20(account))
                )
            ),
            structHash: keccak256(abi.encode(_getModuleTypeHash(), hash))
        });
    }

    /// @dev Returns the module typehash.
    function _getModuleTypeHash() internal pure virtual returns (bytes32);

    /// @dev Returns the module id.
    function _getModuleIdHash() internal pure virtual returns (bytes32);
}
