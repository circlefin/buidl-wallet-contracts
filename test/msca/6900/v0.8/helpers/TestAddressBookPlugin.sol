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

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {CastLib} from "../../../../../src/libs/CastLib.sol";
import {Unsupported} from "../../../../../src/msca/6900/shared/common/Errors.sol";
import {
    PluginManifest,
    PluginMetadata,
    SelectorPermission,
    ManifestExecutionFunction
} from "../../../../../src/msca/6900/v0.8/common/PluginManifest.sol";
import {SIG_VALIDATION_SUCCEEDED, PLUGIN_VERSION_1, PLUGIN_AUTHOR} from "../../../../../src/common/Constants.sol";
import {IAddressBookPlugin} from "../../../../../src/msca/6900/v0.8/plugins/v1_0_0/addressbook/IAddressBookPlugin.sol";
import {IPlugin} from "../../../../../src/msca/6900/v0.8/interfaces/IPlugin.sol";
import {IValidationHook} from "../../../../../src/msca/6900/v0.8/interfaces/IValidationHook.sol";
import {BasePlugin} from "../../../../../src/msca/6900/v0.8/plugins/BasePlugin.sol";
import {RecipientAddressLib} from "../../../../../src/libs/RecipientAddressLib.sol";

/**
 * @dev For testing only purpose.
 */
contract TestAddressBookPlugin is IAddressBookPlugin, BasePlugin {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using RecipientAddressLib for bytes;

    string public constant NAME = "Test Cold Storage Address Book Plugin";
    string internal constant ADDRESS_BOOK_READ = "AddressBookRead";
    string internal constant ADDRESS_BOOK_WRITE = "AddressBookWrite";
    uint256 internal constant _OWNER_VALIDATION_DEPENDENCY_INDEX = 0;
    // act as a safety mechanism if a plugin is blocking uninstallation
    uint16 internal constant _MAX_RECIPIENTS_TO_DELETE = 5000;
    // use MSCA's address as associated address to pass 4337 storage rule check
    AssociatedLinkedListSet internal _allowedRecipients;

    // entity id to plugin itself
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

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external virtual override {
        // if the caller does not provide any recipients during installation, the caller
        // must call addAllowedRecipients first before calling any other execution functions
        if (data.length != 0) {
            address[] memory recipients = abi.decode(data, (address[]));
            _addRecipients(recipients);
            emit AllowedAddressesAdded(msg.sender, recipients);
        }
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        (data);
        address[] memory recipients = _getAllowedRecipients(msg.sender);
        // clearing up plugin storage is optional for the caller;
        // callers should call removeAllowedRecipients in batches if they
        // need to clear plugin storage
        if (recipients.length < _MAX_RECIPIENTS_TO_DELETE) {
            _allowedRecipients.clear(msg.sender);
            emit AllowedAddressesRemoved(msg.sender, recipients);
        } else {
            emit AllowedAddressesNotRemoved(msg.sender);
        }
    }

    /// @inheritdoc IValidationHook
    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (userOpHash);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            // calldata length has already been checked in caller
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
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

    /// @inheritdoc IValidationHook
    function preRuntimeValidationHook(
        uint32 entityId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external view override {
        (value);
        if (entityId == uint32(EntityId.PRE_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(data[4:], (address, uint256, bytes));
            address recipient = address(bytes20(authorization));
            if (!_isRecipientAllowed(recipient)) {
                revert UnauthorizedRecipient(sender, recipient);
            }
            return;
        }
        revert Unsupported();
    }

    function pluginManifest() external pure virtual override returns (PluginManifest memory) {
        PluginManifest memory manifest;
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
        manifest.interfaceIds[0] = type(IAddressBookPlugin).interfaceId;
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](3);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.addAllowedRecipients.selector,
            permissionDescription: ADDRESS_BOOK_WRITE
        });
        metadata.permissionDescriptors[1] = SelectorPermission({
            functionSelector: this.removeAllowedRecipients.selector,
            permissionDescription: ADDRESS_BOOK_WRITE
        });
        metadata.permissionDescriptors[2] = SelectorPermission({
            functionSelector: this.getAllowedRecipients.selector,
            permissionDescription: ADDRESS_BOOK_READ
        });
        return metadata;
    }

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        return interfaceId == type(IAddressBookPlugin).interfaceId || super.supportsInterface(interfaceId);
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
