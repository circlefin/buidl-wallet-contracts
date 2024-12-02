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

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    SIG_VALIDATION_FAILED,
    WALLET_VERSION_1
} from "../../common/Constants.sol";

import {BaseERC712CompliantAccount} from "../../erc712/BaseERC712CompliantAccount.sol";
import {CoreAccount} from "../CoreAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @dev Upgradable & ownable (by EOA key) contract. One of the most common templates.
 */
contract ECDSAAccount is CoreAccount, UUPSUpgradeable, BaseERC712CompliantAccount {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Circle_ECDSAAccount";
    bytes32 private constant _HASHED_NAME = keccak256(bytes(NAME));
    bytes32 private constant _HASHED_VERSION = keccak256(bytes(WALLET_VERSION_1));
    bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CircleECDSAAccountMessage(bytes32 hash)");

    /// @inheritdoc UUPSUpgradeable
    // The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
    // Authorize the owner to upgrade the contract.
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    // for immutable values in implementations
    constructor(IEntryPoint _newEntryPoint) CoreAccount(_newEntryPoint) {
        // lock the implementation contract so it can only be called from proxies
        _disableInitializers();
    }

    // for mutable values in proxies
    function initialize(address _newOwner) public initializer {
        __CoreAccount_init(_newOwner);
        __UUPSUpgradeable_init();
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        // ECDSA
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (!SignatureChecker.isValidSignatureNow(owner(), hash, userOp.signature)) {
            // uint256 constant internal SIG_VALIDATION_FAILED = 1;
            // defined in BaseAccount
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        // use address(this) to prevent replay attacks
        bytes32 replaySafeHash = getReplaySafeMessageHash(hash);
        if (SignatureChecker.isValidSignatureNow(owner(), replaySafeHash, signature)) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    /// @inheritdoc BaseERC712CompliantAccount
    function _getAccountTypeHash() internal pure override returns (bytes32) {
        return _MESSAGE_TYPEHASH;
    }

    /// @inheritdoc BaseERC712CompliantAccount
    function _getAccountName() internal pure override returns (bytes32) {
        return _HASHED_NAME;
    }

    /// @inheritdoc BaseERC712CompliantAccount
    function _getAccountVersion() internal pure override returns (bytes32) {
        return _HASHED_VERSION;
    }
}
