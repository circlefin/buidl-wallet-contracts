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

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

library SelectorRegistryLib {
    bytes4 internal constant INITIALIZE_UPGRADABLE_MSCA =
        bytes4(keccak256("initializeUpgradableMSCA(address[],bytes32[],bytes[])"));
    bytes4 internal constant INITIALIZE_SINGLE_OWNER_MSCA = bytes4(keccak256("initializeSingleOwnerMSCA(address)"));
    bytes4 internal constant TRANSFER_NATIVE_OWNERSHIP = bytes4(keccak256("transferNativeOwnership(address)"));
    bytes4 internal constant RENOUNCE_NATIVE_OWNERSHIP = bytes4(keccak256("renounceNativeOwnership()"));
    bytes4 internal constant GET_NATIVE_OWNER = bytes4(keccak256("getNativeOwner()"));
    bytes4 internal constant VALIDATE_USER_OP = bytes4(keccak256("validateUserOp(UserOperation,bytes32,uint256)"));
    bytes4 internal constant GET_ENTRYPOINT = bytes4(keccak256("getEntryPoint()"));
    bytes4 internal constant GET_NONCE = bytes4(keccak256("getNonce()"));

    /**
     * @dev Check if the selector is for native function.
     * @param selector the function selector.
     */
    function _isNativeFunctionSelector(bytes4 selector) internal pure returns (bool) {
        return selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
            || selector == IPluginManager.installPlugin.selector || selector == IPluginManager.uninstallPlugin.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector || selector == UUPSUpgradeable.proxiableUUID.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against IPluginExecutor methods
        || selector == IPluginExecutor.executeFromPlugin.selector
            || selector == IPluginExecutor.executeFromPluginExternal.selector
        // check against IAccountLoupe methods
        || selector == IAccountLoupe.getExecutionFunctionConfig.selector
            || selector == IAccountLoupe.getExecutionHooks.selector
            || selector == IAccountLoupe.getPreValidationHooks.selector
            || selector == IAccountLoupe.getInstalledPlugins.selector || selector == VALIDATE_USER_OP
            || selector == GET_ENTRYPOINT || selector == GET_NONCE || selector == INITIALIZE_UPGRADABLE_MSCA
            || selector == INITIALIZE_SINGLE_OWNER_MSCA || selector == TRANSFER_NATIVE_OWNERSHIP
            || selector == RENOUNCE_NATIVE_OWNERSHIP || selector == GET_NATIVE_OWNER
            || selector == IERC1155Receiver.onERC1155Received.selector
            || selector == IERC1155Receiver.onERC1155BatchReceived.selector
            || selector == IERC721Receiver.onERC721Received.selector || selector == IERC777Recipient.tokensReceived.selector;
    }

    function _isErc4337FunctionSelector(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function _isIPluginFunctionSelector(bytes4 selector) internal pure returns (bool) {
        return selector == IPlugin.onInstall.selector || selector == IPlugin.onUninstall.selector
            || selector == IPlugin.preUserOpValidationHook.selector || selector == IPlugin.userOpValidationFunction.selector
            || selector == IPlugin.preRuntimeValidationHook.selector
            || selector == IPlugin.runtimeValidationFunction.selector || selector == IPlugin.preExecutionHook.selector
            || selector == IPlugin.postExecutionHook.selector || selector == IPlugin.pluginManifest.selector
            || selector == IPlugin.pluginMetadata.selector;
    }
}
