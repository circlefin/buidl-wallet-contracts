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
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {IPluginExecutor} from "../../../interfaces/IPluginExecutor.sol";
import {BasePlugin} from "../../BasePlugin.sol";
import {IAddressBookPlugin} from "./IAddressBookPlugin.sol";
import {IPlugin} from "../../../interfaces/IPlugin.sol";
import {
    AssociatedLinkedListSet,
    AssociatedLinkedListSetLib
} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";
import {CastLib} from "../../../../../../libs/CastLib.sol";
import {Unsupported, InvalidLength} from "../../../../shared/common/Errors.sol";
import "../../../common/Structs.sol";
import "../../../common/PluginManifest.sol";
import {
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED,
    PLUGIN_VERSION_1,
    PLUGIN_AUTHOR
} from "../../../../../../common/Constants.sol";

/**
 * @dev Implementation for IAddressBookPlugin. AddressBookPlugin would require the owner validation provided by native
 * semi-MSCA
 *      or a plugin function (full MSCA).
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
 *      Both runtime and userOp validations would be covered.
 *
 *      This plugin allows MSCA to check if the destination address is allowed to receive assets like native token,
 * ERC20 tokens, etc.
 *      The implementation could store an internal allowedRecipients that implements associated storage linked list
 *      because bundler validation rules only allow the entity to access the sender associated storage.
 *      By default the recipient is allowed to accept any tokens if it's added to the address book.
 */
contract AddressBookPlugin is BasePlugin, IAddressBookPlugin, ReentrancyGuard {
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    string public constant NAME = "Address Book Plugin";
    string internal constant ADDRESS_BOOK_READ = "AddressBookRead";
    string internal constant ADDRESS_BOOK_WRITE = "AddressBookWrite";
    uint256 internal constant _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX = 0;
    uint256 internal constant _OWNER_USER_OP_VALIDATION_DEPENDENCY_INDEX = 1;
    // use MSCA's address as associated address to pass 4337 storage rule check
    AssociatedLinkedListSet internal _allowedRecipients;

    // function id to plugin itself
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK,
        PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK,
        PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK_BATCH,
        PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK_BATCH
    }

    /**
     * @dev Execute the transactions with additional address book checks.
     */
    function executeWithAddressBook(address target, uint256 value, bytes calldata data, address recipient)
        external
        nonReentrant
        returns (bytes memory)
    {
        return _executeWithAddressBook(target, value, data, recipient);
    }

    /**
     * @dev Batch execute the transactions with additional address book checks.
     */
    function executeBatchWithAddressBook(
        address[] calldata target,
        uint256[] calldata value,
        bytes[] calldata data,
        address[] calldata recipients
    ) external nonReentrant returns (bytes[] memory) {
        uint256 length = target.length;
        if (length == 0 || length != value.length || length != data.length || length != recipients.length) {
            revert InvalidLength();
        }
        bytes[] memory result = new bytes[](length);
        for (uint256 i = 0; i < length; ++i) {
            result[i] = _executeWithAddressBook(target[i], value[i], data[i], recipients[i]);
        }
        return result;
    }

    /**
     * @dev Add allowed recipient. By default the recipient is allowed to accept all tokens.
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
        _allowedRecipients.clear(msg.sender);
        emit AllowedAddressesRemoved(msg.sender, recipients);
    }

    /// @inheritdoc BasePlugin
    function preUserOpValidationHook(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        (userOpHash);
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK)) {
            (,,, address recipient) = abi.decode(userOp.callData[4:], (address, uint256, bytes, address));
            if (!_isRecipientAllowed(recipient)) {
                return SIG_VALIDATION_FAILED;
            }
            return SIG_VALIDATION_SUCCEEDED;
        } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK_BATCH)) {
            (,,, address[] memory recipients) =
                abi.decode(userOp.callData[4:], (address[], uint256[], bytes[], address[]));
            uint256 length = recipients.length;
            for (uint256 i = 0; i < length; ++i) {
                if (!_isRecipientAllowed(recipients[i])) {
                    return SIG_VALIDATION_FAILED;
                }
            }
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert Unsupported();
    }

    /// @inheritdoc BasePlugin
    function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        view
        override
    {
        (value);
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK)) {
            (,,, address recipient) = abi.decode(data[4:], (address, uint256, bytes, address));
            if (!_isRecipientAllowed(recipient)) {
                revert UnauthorizedRecipient(sender, recipient);
            }
            return;
        } else if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK_BATCH)) {
            (,,, address[] memory recipients) = abi.decode(data[4:], (address[], uint256[], bytes[], address[]));
            uint256 length = recipients.length;
            for (uint256 i = 0; i < length; ++i) {
                if (!_isRecipientAllowed(recipients[i])) {
                    revert UnauthorizedRecipient(sender, recipients[i]);
                }
            }
            return;
        }
        revert Unsupported();
    }

    /// We're ONLY updating msg.sender associated storage in the execution functions;
    /// however, there might be attacking vector that calls the account to call the plugin to update recipients.
    /// We're preventing that from happening by relying on the native validation function.
    /// If we pre-define another ownership validation functions from other plugin (e.g. SingleOwnerPlugin),
    /// then we'll introduce dependency from ownership plugins, which is fine but semi SingleOwnerMSCA
    /// would fail to install this plugin because the dependency plugin needs to be installed first.
    function pluginManifest() external pure virtual override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        // needed for executeFromPluginExternal
        manifest.canSpendNativeToken = true;
        // needed for executeFromPluginExternal
        manifest.permitAnyExternalAddress = true;
        manifest.executionFunctions = new bytes4[](5);
        manifest.executionFunctions[0] = this.executeWithAddressBook.selector;
        manifest.executionFunctions[1] = this.executeBatchWithAddressBook.selector;
        manifest.executionFunctions[2] = this.addAllowedRecipients.selector;
        manifest.executionFunctions[3] = this.removeAllowedRecipients.selector;
        manifest.executionFunctions[4] = this.getAllowedRecipients.selector;

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithAddressBook.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.executeBatchWithAddressBook.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_ADDRESS_BOOK_BATCH),
                dependencyIndex: 0
            })
        });
        manifest.preUserOpValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        });
        manifest.preUserOpValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithAddressBook.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK),
                dependencyIndex: 0
            })
        });
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.executeBatchWithAddressBook.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_ADDRESS_BOOK_BATCH),
                dependencyIndex: 0
            })
        });
        manifest.preRuntimeValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        });
        manifest.preRuntimeValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
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
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithAddressBook.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.executeBatchWithAddressBook.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.addAllowedRecipients.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        // note: view via userOp is gas inefficient
        // we're just locking down the view permission to owner or account itself,
        // but you can still view from plugin directly
        manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.getAllowedRecipients.selector,
            associatedFunction: ownerUserOpValidationFunction
        });

        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused for dependency
            dependencyIndex: _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.executeWithAddressBook.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.executeBatchWithAddressBook.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.addAllowedRecipients.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.removeAllowedRecipients.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.getAllowedRecipients.selector,
            associatedFunction: ownerRuntimeValidationFunction
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
        metadata.permissionDescriptors = new SelectorPermission[](5);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.executeWithAddressBook.selector,
            permissionDescription: ADDRESS_BOOK_READ
        });
        metadata.permissionDescriptors[1] = SelectorPermission({
            functionSelector: this.executeBatchWithAddressBook.selector,
            permissionDescription: ADDRESS_BOOK_READ
        });
        metadata.permissionDescriptors[2] = SelectorPermission({
            functionSelector: this.addAllowedRecipients.selector,
            permissionDescription: ADDRESS_BOOK_WRITE
        });
        metadata.permissionDescriptors[3] = SelectorPermission({
            functionSelector: this.removeAllowedRecipients.selector,
            permissionDescription: ADDRESS_BOOK_WRITE
        });
        metadata.permissionDescriptors[4] = SelectorPermission({
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

    function _executeWithAddressBook(address target, uint256 value, bytes calldata data, address recipient)
        internal
        returns (bytes memory)
    {
        // check again during execution
        if (!_isRecipientAllowed(recipient)) {
            revert UnauthorizedRecipient(msg.sender, recipient);
        }
        return IPluginExecutor(msg.sender).executeFromPluginExternal(target, value, data);
    }

    function _isRecipientAllowed(address recipient) internal view returns (bool) {
        // skip the check if recipient is not provided;
        // it makes sense if the sender doesn't install any recipient initially
        // OR wants to bypass this check in follow up txs since we can't possibly validate the legitimacy of recipient
        // for every function call
        return recipient == address(0) || _allowedRecipients.contains(msg.sender, CastLib.toSetValue(recipient));
    }

    function _getAllowedRecipients(address account) internal view returns (address[] memory) {
        return CastLib.toAddressArray(_allowedRecipients.getAll(account));
    }
}
