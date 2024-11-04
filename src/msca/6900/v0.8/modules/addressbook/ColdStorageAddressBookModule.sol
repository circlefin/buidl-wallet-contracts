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

import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCEEDED} from "../../../../../common/Constants.sol";
import {CastLib} from "../../../../../libs/CastLib.sol";
import {RecipientAddressLib} from "../../../../../libs/RecipientAddressLib.sol";
import {SignatureInflation, Unsupported} from "../../../shared/common/Errors.sol";

import {Call} from "../../common/Structs.sol";

import {BaseModule} from "../BaseModule.sol";
import {IAddressBookModule} from "./IAddressBookModule.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/**
 * @dev This module serves as an enhanced version of the AddressBookModule, incorporating additional limitations on
 * target contracts.
 *      It necessitates verification of ownership through either native semi-MSCA mechanisms or a dedicated module
 * function
 *      designed for full MSCA compliance.
 *      1. For semi-MSCA with native validation such as SingleOwnerMSCA, please provide the follow dependency during
 * installation
 *          a. FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.EntityId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF))
 *          b. FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.EntityId.NATIVE_USER_OP_VALIDATION_OWNER))
 *
 *      2. For full MSCA with module validation such as UpgradableMSCA, please provide the follow dependency during
 * installation
 *          a. FunctionReference(singleOwnerModuleAddr,
 * uint8(ISingleOwnerModule.EntityId.RUNTIME_VALIDATION_OWNER_OR_SELF))
 *          b. FunctionReference(singleOwnerModuleAddr, uint8(ISingleOwnerModule.EntityId.USER_OP_VALIDATION_OWNER))
 *      Both runtime and userOp validations should be covered.
 *
 *      Design:
 *      1. For token transfers, verify support for the function selector; if unsupported, reject the transaction. This
 * validation is bypassed for native transfers.
 *      2. Extract the recipient's address from the transaction's calldata for token transfers, or from the target for
 * native transfers.
 *      3. If the recipient's address is not specified (== address(0)) within the calldata, reject the transaction.
 *      4. Validate the recipient against the on-chain address book; validate the target if value > 0 && recipient !=
 * target; unauthorized addresses result in transaction
 * rejection.
 *      5. If the recipient is authorized, proceed with the transaction.
 */
contract ColdStorageAddressBookModule is IAddressBookModule, BaseModule {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using RecipientAddressLib for bytes;

    // act as a safety mechanism if a module is blocking uninstallation
    uint16 internal constant _MAX_RECIPIENTS_TO_DELETE = 5000;
    // use MSCA's address as associated address to pass 4337 storage rule check
    AssociatedLinkedListSet internal _allowedRecipients;

    // entity id to module itself
    enum EntityId {
        PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK,
        PRE_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK
    }

    /**
     * @dev Add allowed recipient.
     * Can only be called by the current msg.sender.
     */
    function addAllowedRecipients(address[] calldata recipients) external {
        _addRecipients(recipients);
        emit AllowedAddressesAdded(msg.sender, recipients);
    }

    /**
     * @dev Remove allowed recipient.
     * Can only be called by the current msg.sender.
     */
    function removeAllowedRecipients(address[] calldata recipients) external {
        uint256 length = recipients.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_allowedRecipients.tryRemove(msg.sender, CastLib.toSetValue(recipients[i]))) {
                revert FailToRemoveRecipient(msg.sender, recipients[i]);
            }
        }
        emit AllowedAddressesRemoved(msg.sender, recipients);
    }

    /**
     * @dev Returns the allowed addresses of the current MSCA.
     */
    function getAllowedRecipients(address account) external view returns (address[] memory) {
        return _getAllowedRecipients(account);
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external virtual override {
        // if the caller does not provide any recipients during installation, the caller
        // must call addAllowedRecipients first before calling any other execution functions
        if (data.length != 0) {
            address[] memory recipients = abi.decode(data, (address[]));
            _addRecipients(recipients);
            emit AllowedAddressesAdded(msg.sender, recipients);
        }
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        (data);
        address[] memory recipients = _getAllowedRecipients(msg.sender);
        // clearing up module storage is optional for the caller;
        // callers should call removeAllowedRecipients in batches if they
        // need to clear module storage
        if (recipients.length < _MAX_RECIPIENTS_TO_DELETE) {
            _allowedRecipients.clear(msg.sender);
            emit AllowedAddressesRemoved(msg.sender, recipients);
        } else {
            emit AllowedAddressesNotRemoved(msg.sender);
        }
    }

    /// @inheritdoc IValidationHookModule
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        // TODO: add tests when we revamp this WIP module soon
        if (userOp.signature.length > 0) {
            revert SignatureInflation();
        }
        (userOpHash);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            // calldata length has already been checked in caller
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            if (!_isRecipientAllowed(_getTargetOrRecipient(target, targetValue, targetData))) {
                return SIG_VALIDATION_FAILED;
            }
            return SIG_VALIDATION_SUCCEEDED;
        } else if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            Call[] memory calls = abi.decode(userOp.callData[4:], (Call[]));
            uint256 length = calls.length;
            for (uint256 i = 0; i < length; ++i) {
                if (!_isRecipientAllowed(_getTargetOrRecipient(calls[i].target, calls[i].value, calls[i].data))) {
                    return SIG_VALIDATION_FAILED;
                }
            }
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert Unsupported();
    }

    /// @inheritdoc IValidationHookModule
    function preRuntimeValidationHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external view override {
        (value, authorization);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(data[4:], (address, uint256, bytes));
            address recipient = _getTargetOrRecipient(target, targetValue, targetData);
            if (!_isRecipientAllowed(recipient)) {
                revert UnauthorizedRecipient(sender, recipient);
            }
            return;
        } else if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            Call[] memory calls = abi.decode(data[4:], (Call[]));
            uint256 length = calls.length;
            for (uint256 i = 0; i < length; ++i) {
                address recipient = _getTargetOrRecipient(calls[i].target, calls[i].value, calls[i].data);
                if (!_isRecipientAllowed(recipient)) {
                    revert UnauthorizedRecipient(sender, recipient);
                }
            }
            return;
        }
        revert Unsupported();
    }

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        (entityId, sender, hash, signature);
        revert Unsupported();
    }

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        // TODO: allow global validation
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.addAllowedRecipients.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: true
        });
        manifest.interfaceIds = new bytes4[](1);
        manifest.interfaceIds[0] = type(IAddressBookModule).interfaceId;
        return manifest;
    }

    /// @inheritdoc IModule
    function moduleId() external pure returns (string memory) {
        return "circle.cold-storage-address-book-module.2.0.0";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IAddressBookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function _addRecipients(address[] memory recipientsToAdd) internal {
        uint256 length = recipientsToAdd.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_allowedRecipients.tryAdd(msg.sender, CastLib.toSetValue(recipientsToAdd[i]))) {
                revert FailToAddRecipient(msg.sender, recipientsToAdd[i]);
            }
        }
    }

    function _isRecipientAllowed(address recipient) internal view returns (bool) {
        return _allowedRecipients.contains(msg.sender, CastLib.toSetValue(recipient));
    }

    function _getAllowedRecipients(address account) internal view returns (address[] memory) {
        return CastLib.toAddressArray(_allowedRecipients.getAll(account));
    }

    /// @dev We do not permit sending native assets to a token contract while simultaneously interacting with it.
    function _getTargetOrRecipient(address target, uint256 value, bytes memory data) internal view returns (address) {
        if (value != 0) {
            // for native asset transfers, we require the calldata to be empty
            if (data.length != 0) {
                revert CallDataIsNotEmpty(msg.sender, target, value, data);
            }
            if (target == address(0)) {
                // we do not allow sending native assets to address(0)
                revert UnauthorizedRecipient(msg.sender, target);
            }
            return target;
        } else {
            // for token calls, we require that the target address contains code
            if (target.code.length == 0) {
                revert InvalidTargetCodeLength(msg.sender, target, value, data);
            }
            // the helper function will first check if the function selector is supported
            address recipient = data.getERC20TokenRecipient();
            if (recipient == address(0)) {
                recipient = data.getERC1155TokenRecipient();
            }
            if (recipient == address(0)) {
                recipient = data.getERC721TokenRecipient();
            }
            if (recipient == address(0)) {
                revert UnauthorizedRecipient(msg.sender, recipient);
            }
            return recipient;
        }
    }
}
