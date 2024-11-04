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
    EMPTY_HASH,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED,
    ZERO,
    ZERO_BYTES32
} from "../../../../../common/Constants.sol";

import {NotImplementedFunction} from "../../../shared/common/Errors.sol";

import {BaseModule} from "../BaseModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Base Multisig Module
/// @author Circle
/// @notice Base contract for multisig modules.
/// Functions implemented in this contract are forked with modifications from
/// https://github.com/alchemyplatform/multisig-module/blob/170ec0df78aa20248ab6f792540b4d4d4e0f752c/src/MultisigModule.sol
abstract contract BaseMultisigModule is IValidationModule, BaseModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    error EmptyOwnersNotAllowed();
    error InvalidAddress();
    error InvalidNumSigsOnActualDigest(uint256 invalidNum);
    error InvalidMaxFeePerGas();
    error InvalidMaxPriorityFeePerGas();
    error InvalidOwner(bytes30 owner);
    error InvalidPreVerificationGas();
    error InvalidSigLength();
    error InvalidSigOffset();
    error InvalidContractSigLength();
    error OwnerDoesNotExist(bytes30 owner);
    error TooManyOwners(uint256 currentNumOwners, uint256 numOwnersToAdd);
    error ZeroOwnersInputNotAllowed();
    error InvalidUserOpDigest();

    enum EntityId {
        VALIDATION_OWNER // require owner access

    }

    // Linked list of account owners, in account address-associated storage
    AssociatedLinkedListSet internal _owners;

    address public immutable ENTRYPOINT;

    constructor(address entryPoint) {
        ENTRYPOINT = entryPoint;
    }

    /// @notice Check if the signatures are valid for the account.
    /// @param actualDigest The actual gas digest.
    /// @param minimalDigest Digest of user op with minimal required fields set:
    /// (address sender, uint256 nonce, bytes initCode, bytes callData), and remaining
    /// fields set to default values.
    /// @param account The account to check the signatures for.
    /// @param signatures The signatures to check.
    /// @return success True if the signatures are valid.
    /// @return firstFailure first failure, if failed is true.
    /// (Note: if all signatures are individually valid but do not satisfy the
    /// multisig, firstFailure will be set to the last signature's index.)
    function checkNSignatures(bytes32 actualDigest, bytes32 minimalDigest, address account, bytes memory signatures)
        public
        view
        virtual
        returns (bool success, uint256 firstFailure);

    /// @inheritdoc IValidationModule
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (entityId == uint32(EntityId.VALIDATION_OWNER)) {
            // UserOp.sig format:
            // 0-n: k signatures, each sig is 65 bytes each (so n = 65 * k)
            // n-: contract signatures if any
            bytes32 actualUserOpDigest = userOpHash.toEthSignedMessageHash();
            bytes32 minimalUserOpDigest = _getMinimalUserOpDigest(userOp).toEthSignedMessageHash();
            // actualUserOpDigest must differ from minimalUserOpDigest in userOp
            // when actualUserOpDigest != minimalUserOpDigest, numSigsOnActualDigest is set to one
            if (actualUserOpDigest == minimalUserOpDigest) {
                revert InvalidUserOpDigest();
            }
            (bool success,) = checkNSignatures(actualUserOpDigest, minimalUserOpDigest, msg.sender, userOp.signature);

            return success ? SIG_VALIDATION_SUCCEEDED : SIG_VALIDATION_FAILED;
        }

        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @inheritdoc IValidationModule
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external pure override {
        // TODO: implement this - the signatures can be put in the validationData field of the runtime validation
        // function
        (account, sender, value, data, authorization);
        revert NotImplementedFunction(msg.sig, entityId);
    }

    /// @dev get the minimal user op digest
    /// (user op hash with gas fields or paymasterAndData set to default values.)
    /// @param userOp The user operation
    /// @return minimal user op hash
    function _getMinimalUserOpDigest(PackedUserOperation calldata userOp) internal view returns (bytes32) {
        address sender;
        assembly ("memory-safe") {
            sender := calldataload(userOp)
        }
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = _calldataKeccak(userOp.initCode);
        bytes32 hashCallData = _calldataKeccak(userOp.callData);

        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                nonce,
                hashInitCode,
                hashCallData,
                ZERO_BYTES32, // accountGasLimits
                ZERO, // preVerificationGas = 0
                ZERO_BYTES32, // gasFees
                EMPTY_HASH // paymasterAndData = keccak256('')
            )
        );

        return keccak256(abi.encode(userOpHash, ENTRYPOINT, block.chainid));
    }

    /// @param data calldata to hash
    function _calldataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }

    /// @notice Check if the account has initialized this module yet
    /// @param account The account to check
    /// @return True if the account has initialized this module
    function _isInitialized(address account) internal view virtual override returns (bool) {
        return !_owners.isEmpty(account);
    }

    /// @dev Helper function to get a 65 byte signature from a multi-signature
    /// @dev Functions using this must make sure signatures is long enough to contain
    /// the signature (65 * pos + 65 bytes.)
    /// @param signatures signatures to split
    /// @param pos position in signatures
    function _signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly ("memory-safe") {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }
}
