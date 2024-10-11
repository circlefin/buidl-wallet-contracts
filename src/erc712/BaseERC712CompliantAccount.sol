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

import {MessageHashUtils} from "../libs/MessageHashUtils.sol";

abstract contract BaseERC712CompliantAccount {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @notice Wraps a replay safe hash in an EIP-712 envelope to prevent cross-account replay attacks.
    /// domainSeparator = hashStruct(eip712Domain).
    /// eip712Domain = (string name,string version,uint256 chainId,address verifyingContract)
    /// hashStruct(s) = keccak256(typeHash ‖ encodeData(s)) where typeHash = keccak256(encodeType(typeOf(s)))
    /// @param hash Message that should be hashed.
    /// @return Replay safe message hash.
    function getReplaySafeMessageHash(bytes32 hash) public view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash({
            domainSeparator: keccak256(
                abi.encode(
                    _DOMAIN_SEPARATOR_TYPEHASH, _getAccountName(), _getAccountVersion(), block.chainid, address(this)
                )
            ),
            structHash: keccak256(abi.encode(_getAccountTypeHash(), hash))
        });
    }

    /// @dev Returns the account message typehash.
    function _getAccountTypeHash() internal pure virtual returns (bytes32);

    /// @dev Returns the account name.
    function _getAccountName() internal pure virtual returns (bytes32);

    /// @dev Returns the account version.
    function _getAccountVersion() internal pure virtual returns (bytes32);
}
