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

import {Unsupported} from "../../../../../../common//Errors.sol";
import {PLUGIN_AUTHOR, PLUGIN_VERSION_1, SIG_VALIDATION_SUCCEEDED} from "../../../../../../common/Constants.sol";
import {CastLib} from "../../../../../../libs/CastLib.sol";
import {RecipientAddressLib} from "../../../../../../libs/RecipientAddressLib.sol";
import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../../common/PluginManifest.sol";
import {Call} from "../../../common/Structs.sol";
import {IPlugin} from "../../../interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {BasePlugin} from "../../BasePlugin.sol";
import {IAddressBookPlugin} from "./IAddressBookPlugin.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";

/**
 * @dev This plugin serves as an enhanced version of the AddressBookPlugin, incorporating additional limitations on
 * target contracts.
 *      It necessitates verification of ownership through either native semi-MSCA mechanisms or a dedicated plugin
 * function
 *      designed for full MSCA compliance.
 *      1. For semi-MSCA with native validation such as SingleOwnerMSCA, please provide the follow dependency during
 * installation
 *          a. FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF))
 *          b. FunctionReference(mscaAddr, uint8(SingleOwnerMSCA.FunctionId.NATIVE_USER_OP_VALIDATION_OWNER))
 *
 *      2. For full MSCA with plugin validation such as UpgradableMSCA, please provide the follow dependency during
 * installation
 *          a. FunctionReference(singleOwnerPluginAddr,
 * uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF))
 *          b. FunctionReference(singleOwnerPluginAddr, uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER))
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
contract ColdStorageAddressBookPlugin is BasePlugin, IAddressBookPlugin {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;
    using RecipientAddressLib for bytes;

    string public constant NAME = "Cold Storage Address Book Plugin";
    string internal constant ADDRESS_BOOK_READ = "AddressBookRead";
    string internal constant ADDRESS_BOOK_WRITE = "AddressBookWrite";
    uint256 internal constant _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX = 0;
    uint256 internal constant _OWNER_USER_OP_VALIDATION_DEPENDENCY_INDEX = 1;
    // act as a safety mechanism if a plugin is blocking uninstallation
    uint16 internal constant _MAX_RECIPIENTS_TO_DELETE = 5000;
    // use MSCA's address as associated address to pass 4337 storage rule check
    AssociatedLinkedListSet internal _allowedRecipients;

    // function id to plugin itself
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK,
        PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK,
        PRE_USER_OP_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK,
        PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK
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

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external virtual override {
        // if the caller does not provide any recipients during installation, the caller
        // must call addAllowedRecipients first before calling any other execution functions
        if (data.length != 0) {
            address[] memory recipients = abi.decode(data, (address[]));
            _addRecipients(recipients);
            emit AllowedAddressesAdded(msg.sender, recipients);
        }
    }

    /// @inheritdoc BasePlugin
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

    function _verifyAllowedTargetOrRecipient(address target, uint256 value, bytes memory data) internal view {
        address recipient = _getTargetOrRecipient(target, value, data);
        if (!_allowedRecipients.contains(msg.sender, CastLib.toSetValue(recipient))) {
            revert UnauthorizedRecipient(msg.sender, recipient);
        }
    }

    /// @inheritdoc BasePlugin
    function preUserOpValidationHook(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (userOpHash);
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            // calldata length has already been checked in caller
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            _verifyAllowedTargetOrRecipient(target, targetValue, targetData);
            return SIG_VALIDATION_SUCCEEDED;
        } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.executeBatch as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            Call[] memory calls = abi.decode(userOp.callData[4:], (Call[]));
            uint256 length = calls.length;
            for (uint256 i = 0; i < length; ++i) {
                _verifyAllowedTargetOrRecipient(calls[i].target, calls[i].value, calls[i].data);
            }
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert Unsupported();
    }

    /// @inheritdoc BasePlugin
    function preRuntimeValidationHook(uint8 functionId, address, uint256 value, bytes calldata data)
        external
        view
        override
    {
        (value);
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.execute as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            (address target, uint256 targetValue, bytes memory targetData) =
                abi.decode(data[4:], (address, uint256, bytes));
            _verifyAllowedTargetOrRecipient(target, targetValue, targetData);
            return;
        } else if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK)) {
            // This functionality is exclusively compatible with the IStandardExecutor.executeBatch as delineated in the
            // pluginManifest.
            // It is incompatible with alternate execution functions, owing to the specific decoding logic employed
            // here.
            Call[] memory calls = abi.decode(data[4:], (Call[]));
            uint256 length = calls.length;
            for (uint256 i = 0; i < length; ++i) {
                _verifyAllowedTargetOrRecipient(calls[i].target, calls[i].value, calls[i].data);
            }
            return;
        }
        revert Unsupported();
    }

    /// @dev Upon initial installation of this plugin without designating approved recipients, it is critical to utilize
    /// addAllowedRecipients()
    /// before making use of the execute() function. It is advisable against embedding the addAllowedRecipients()
    /// function within the calldata destined for execute(),
    /// due to execute() being protected by specific hooks associated with this plugin. Additionally, it should be noted
    /// that when addAllowedRecipients()
    /// is accessed through the MSCA fallback function, it does not trigger these hooks.
    function pluginManifest() external pure virtual override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.executionFunctions = new bytes4[](3);
        manifest.executionFunctions[0] = this.addAllowedRecipients.selector;
        manifest.executionFunctions[1] = this.removeAllowedRecipients.selector;
        manifest.executionFunctions[2] = this.getAllowedRecipients.selector;

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_EXECUTE_BATCH_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        // fallback validation functions if MSCA doesn't have native ones
        manifest.dependencyInterfaceIds[_OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX] = type(IPlugin).interfaceId;
        manifest.dependencyInterfaceIds[_OWNER_USER_OP_VALIDATION_DEPENDENCY_INDEX] = type(IPlugin).interfaceId;
        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused for dependency
            dependencyIndex: _OWNER_USER_OP_VALIDATION_DEPENDENCY_INDEX
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addAllowedRecipients.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused for dependency
            dependencyIndex: _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX
        });
        ManifestFunction memory runtimeAlwaysAllowAssociatedFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0,
            dependencyIndex: 0
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addAllowedRecipients.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.getAllowedRecipients.selector,
            associatedFunction: runtimeAlwaysAllowAssociatedFunction
        });

        manifest.interfaceIds = new bytes4[](1);
        manifest.interfaceIds[0] = type(IAddressBookPlugin).interfaceId;
        return manifest;
    }

    /// @inheritdoc BasePlugin
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
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
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
