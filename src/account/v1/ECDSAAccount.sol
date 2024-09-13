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

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../CoreAccount.sol";
import {SIG_VALIDATION_FAILED} from "../../common/Constants.sol";

/**
 * @dev Upgradable & ownable (by EOA key) contract. One of the most common templates.
 */
contract ECDSAAccount is CoreAccount, UUPSUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @inheritdoc UUPSUpgradeable
    // The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
    // Authorize the owner to upgrade the contract.
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
        if (!SignatureChecker.isValidSignatureNow(owner(), hash.toEthSignedMessageHash(), signature)) {
            return bytes4(0xffffffff);
        }
        return EIP1271_MAGIC_VALUE;
    }
}
