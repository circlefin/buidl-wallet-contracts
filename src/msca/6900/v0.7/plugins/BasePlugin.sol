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

import {NotImplemented} from "../../shared/common/Errors.sol";
import "../common/PluginManifest.sol";
import "../common/Structs.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support open-ended execution.
 */
abstract contract BasePlugin is IPlugin, ERC165 {
    error AlreadyInitialized();
    error NotInitialized();

    /// @dev Ensure the account has initialized this plugin
    /// @param account the account to check
    modifier isNotInitialized(address account) {
        if (_isInitialized(account)) {
            revert AlreadyInitialized();
        }
        _;
    }

    /// @dev Ensure the account has not initialized this plugin
    /// @param account the account to check
    modifier isInitialized(address account) {
        if (!_isInitialized(account)) {
            revert NotInitialized();
        }
        _;
    }

    /// @notice Initialize plugin data for the modular account.
    /// @dev Called by the modular account during `installPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to setup initial plugin data for the
    /// modular account.
    function onInstall(bytes calldata data) external virtual {
        (data);
        revert NotImplemented(msg.sig, 0);
    }

    /// @notice Clear plugin data for the modular account.
    /// @dev Called by the modular account during `uninstallPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to clear plugin data for the modular
    /// account.
    function onUninstall(bytes calldata data) external virtual {
        (data);
        revert NotImplemented(msg.sig, 0);
    }

    /// @notice Run the pre user operation validation hook specified by the `functionId`.
    /// @dev Pre user operation validation hooks MUST NOT return an authorizer value other than 0 or 1.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be more
    /// than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return validationData Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20
    /// bytes).
    function preUserOpValidationHook(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256 validationData)
    {
        (functionId, userOp, userOpHash, validationData);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Run the user operation validationFunction specified by the `functionId`.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return validationData Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20
    /// bytes).
    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256 validationData)
    {
        (functionId, userOp, userOpHash, validationData);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Run the pre runtime validation hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be more
    /// than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function preRuntimeValidationHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
    {
        (functionId, sender, value, data);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Run the runtime validationFunction specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
    {
        (functionId, sender, value, data);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Run the pre execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be more
    /// than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    /// @return context Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        virtual
        returns (bytes memory context)
    {
        (functionId, sender, value, data, context);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Run the post execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be more
    /// than one.
    /// @param preExecHookData The context returned by its associated pre execution hook.
    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external virtual {
        (functionId, preExecHookData);
        revert NotImplemented(msg.sig, functionId);
    }

    /// @notice Describe the contents and intended configuration of the plugin.
    /// @dev The manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the plugin.
    function pluginManifest() external pure virtual returns (PluginManifest memory) {
        revert NotImplemented(msg.sig, 0);
    }

    /// @notice Describe the metadata of the plugin.
    /// @dev This metadata MUST stay constant over time.
    /// @return A metadata struct describing the plugin.
    function pluginMetadata() external pure virtual returns (PluginMetadata memory) {
        revert NotImplemented(msg.sig, 0);
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30,000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation (PluginManager). This is also used
    /// by the modular account to prevent StandardExecutor functions from making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @notice Check if the account has initialized this plugin yet
    /// @dev This function should be overwritten for plugins that have state-changing onInstall's
    /// @param account The account to check
    /// @return True if the account has initialized this plugin
    // solhint-disable-next-line no-empty-blocks
    function _isInitialized(address account) internal view virtual returns (bool) {
        (account);
        revert NotImplemented(msg.sig, 0);
    }
}
