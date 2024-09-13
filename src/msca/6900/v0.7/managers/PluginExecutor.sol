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

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IPluginExecutor} from "../interfaces/IPluginExecutor.sol";
import {WalletStorageV1Lib} from "../libs/WalletStorageV1Lib.sol";
import {ExecutionHookLib} from "../libs/ExecutionHookLib.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import {NotFoundSelector, InvalidExecutionFunction} from "../../shared/common/Errors.sol";
import "../common/Structs.sol";

/**
 * @dev Default implementation of https://eips.ethereum.org/EIPS/eip-6900. MSCAs must implement this interface to
 * support execution from plugins.
 *      https://eips.ethereum.org/assets/eip-6900/Plugin_Execution_Flow.svg
 */
library PluginExecutor {
    using ExecutionHookLib for HookGroup;
    using ExecutionHookLib for PostExecHookToRun[];
    using ExecutionUtils for address;

    error ExecuteFromPluginToExternalNotPermitted();
    error ExecFromPluginToSelectorNotPermitted(address plugin, bytes4 selector);
    error NativeTokenSpendingNotPermitted(address plugin);

    /// @dev Refer to IPluginExecutor
    function executeFromPlugin(bytes calldata data) internal returns (bytes memory) {
        if (data.length < 4) {
            revert NotFoundSelector();
        }
        bytes4 selector = bytes4(data[0:4]);
        if (selector == bytes4(0)) {
            revert NotFoundSelector();
        }
        address callingPlugin = msg.sender;
        WalletStorageV1Lib.Layout storage walletStorage = WalletStorageV1Lib.getLayout();
        // permission check
        if (!walletStorage.permittedPluginCalls[callingPlugin][selector]) {
            revert ExecFromPluginToSelectorNotPermitted(callingPlugin, selector);
        }
        // this function call emulates a call to the fallback that routes calls into another plugin;
        // we use inner data here instead of the entire msg.data that includes the complete calldata of
        // executeFromPlugin
        ExecutionDetail storage executionDetail = walletStorage.executionDetails[selector];
        if (executionDetail.plugin == address(0)) {
            revert InvalidExecutionFunction(selector);
        }
        // pre execution hooks
        PostExecHookToRun[] memory postExecHooks = executionDetail.executionHooks._processPreExecHooks(data);
        // permitted to call the other plugin
        bytes memory returnData = executionDetail.plugin.callWithReturnDataOrRevert(0, data);
        // post execution hooks
        postExecHooks._processPostExecHooks();
        return returnData;
    }

    /// @dev Refer to IPluginExecutor
    function executeFromPluginToExternal(bytes calldata data, address target, uint256 value)
        internal
        returns (bytes memory)
    {
        if (target == address(this) || ERC165Checker.supportsInterface(target, type(IPlugin).interfaceId)) {
            revert ExecuteFromPluginToExternalNotPermitted();
        }
        WalletStorageV1Lib.Layout storage walletStorage = WalletStorageV1Lib.getLayout();
        address callingPlugin = msg.sender;
        // revert if the plugin can't cover the value and is not permitted to spend MSCA's native token
        if (value > 0 && value > msg.value && !walletStorage.pluginDetails[callingPlugin].canSpendNativeToken) {
            revert NativeTokenSpendingNotPermitted(callingPlugin);
        }
        PermittedExternalCall storage permittedExternalCall =
            walletStorage.permittedExternalCalls[callingPlugin][target];
        // permission check
        // addressPermitted can only be true if anyExternalAddressPermitted is false
        bool targetContractCallPermitted;
        // external call might not have function selector
        bytes4 selector = bytes4(data);
        if (permittedExternalCall.addressPermitted) {
            targetContractCallPermitted =
                permittedExternalCall.anySelector || permittedExternalCall.selectors[selector] || data.length == 0;
        } else {
            // also need to check the default permission in plugin detail
            targetContractCallPermitted = walletStorage.pluginDetails[callingPlugin].anyExternalAddressPermitted;
        }
        if (!targetContractCallPermitted) {
            revert ExecFromPluginToSelectorNotPermitted(callingPlugin, selector);
        }
        // we use msg.data here so the complete calldata of current function call executeFromPluginToExternalContract
        // can be passed
        // pre executeFromPluginToExternalContract hooks
        // process any pre exec hooks for IPluginExecutor.executeFromPluginExternal.selector during runtime
        PostExecHookToRun[] memory postExecHooks = walletStorage.executionDetails[IPluginExecutor
            .executeFromPluginExternal
            .selector].executionHooks._processPreExecHooks(msg.data);
        // call externally
        bytes memory returnData = target.callWithReturnDataOrRevert(value, data);
        // post executeFromPluginToExternalContract hooks
        postExecHooks._processPostExecHooks();
        return returnData;
    }
}
