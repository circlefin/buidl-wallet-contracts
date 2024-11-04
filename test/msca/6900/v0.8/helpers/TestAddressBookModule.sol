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

import {SIG_VALIDATION_SUCCEEDED} from "../../../../../src/common/Constants.sol";
import {CastLib} from "../../../../../src/libs/CastLib.sol";

import {RecipientAddressLib} from "../../../../../src/libs/RecipientAddressLib.sol";
import {Unsupported} from "../../../../../src/msca/6900/shared/common/Errors.sol";

import {BaseModule} from "../../../../../src/msca/6900/v0.8/modules/BaseModule.sol";
import {IAddressBookModule} from "../../../../../src/msca/6900/v0.8/modules/addressbook/IAddressBookModule.sol";
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
 * @dev For testing only purpose.
 */
contract TestAddressBookModule is IAddressBookModule, BaseModule {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using RecipientAddressLib for bytes;

    // act as a safety mechanism if a module is blocking uninstallation
    uint16 internal constant _MAX_RECIPIENTS_TO_DELETE = 5000;
    // use MSCA's address as associated address to pass 4337 storage rule check
    AssociatedLinkedListSet internal _allowedRecipients;

    // entity id to module itself
    enum EntityId {
        PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK
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
        (userOpHash);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            // calldata length has already been checked in caller
            // the caller is expected to pack the hook function data in userOp.signature
            address recipient = address(bytes20(userOp.signature));
            if (!_isRecipientAllowed(recipient)) {
                // this is supposed to return SIG_VALIDATION_FAILED
                // but I'm reverting here to demonstrate the error stacktrace in tests
                revert UnauthorizedRecipient(msg.sender, recipient);
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
        (data, value);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // moduleManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            address recipient = address(bytes20(authorization));
            if (!_isRecipientAllowed(recipient)) {
                revert UnauthorizedRecipient(sender, recipient);
            }
            return;
        }
        revert Unsupported();
    }

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.addAllowedRecipients.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: true
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

    function moduleId() external pure returns (string memory) {
        return "circle.address-book-test-module.2.0.0";
    }

    /// @inheritdoc BaseModule
    function supportsInterface(bytes4 interfaceId) public view override(BaseModule, IERC165) returns (bool) {
        return interfaceId == type(IValidationHookModule).interfaceId || super.supportsInterface(interfaceId);
    }

    function preSignatureValidationHook(uint32 entityId, address sender, bytes32 hash, bytes calldata signature)
        external
        pure
        override
    {
        (entityId, sender, hash, signature);
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
}
