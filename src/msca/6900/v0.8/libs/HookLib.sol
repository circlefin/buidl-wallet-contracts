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

import {EMPTY_MODULE_ENTITY, SENTINEL_BYTES32} from "../../../../common/Constants.sol";

import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import {Bytes32DLL} from "../../shared/common/Structs.sol";
import {Bytes32DLLLib} from "../../shared/libs/Bytes32DLLLib.sol";
import {PostExecHookToRun} from "../common/Structs.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {HookConfig, ModuleEntity} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

library HookLib {
    using Bytes32DLLLib for Bytes32DLL;
    using HookConfigLib for HookConfig;
    using ModuleEntityLib for ModuleEntity;

    error PreExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);
    error PostExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);

    function _processPreExecHooks(Bytes32DLL storage executionHooks, bytes calldata data)
        internal
        returns (PostExecHookToRun[] memory postExecHooksToRun)
    {
        HookConfig[] memory hookConfigs;
        // copy post hook first so the post hooks will not be affected by state changes
        (postExecHooksToRun, hookConfigs) = _copyPostExecHooks(executionHooks);
        for (uint256 i = 0; i < postExecHooksToRun.length; ++i) {
            (ModuleEntity hookFunction, bool hasPre, bool hasPost) = hookConfigs[i].unpackExecHook();
            // run pre hook and copy the return data if there's a post hook
            if (hasPre) {
                bytes memory preExecHookReturnData = _processPreExecHook(hookFunction, data);
                if (hasPost) {
                    postExecHooksToRun[i].preExecHookReturnData = preExecHookReturnData;
                }
            }
        }
    }

    /// @return postExecHooksToRun and hookConfigs, hookConfigs are used for running pre hooks
    function _copyPostExecHooks(Bytes32DLL storage executionHooks)
        internal
        view
        returns (PostExecHookToRun[] memory postExecHooksToRun, HookConfig[] memory hookConfigs)
    {
        uint256 hooksCount = executionHooks.size();
        postExecHooksToRun = new PostExecHookToRun[](hooksCount);
        hookConfigs = new HookConfig[](hooksCount);
        uint256 totalPostExecHooksToRunCount = 0;
        bytes32 startHook = SENTINEL_BYTES32;
        for (uint256 i = 0; i < hooksCount; ++i) {
            (bytes32[] memory execHooks, bytes32 nextHook) = executionHooks.getPaginated(startHook, 50);
            for (uint256 j = 0; j < execHooks.length; ++j) {
                hookConfigs[totalPostExecHooksToRunCount] = toHookConfig(execHooks[j]);
                (ModuleEntity hookFunction,, bool hasPost) = hookConfigs[totalPostExecHooksToRunCount].unpackExecHook();
                if (hasPost) {
                    postExecHooksToRun[totalPostExecHooksToRunCount].postExecHook = hookFunction;
                }
                unchecked {
                    totalPostExecHooksToRunCount++;
                }
            }
            if (nextHook == SENTINEL_BYTES32) {
                break;
            }
            startHook = nextHook;
        }
    }

    /// @dev return preExecHookReturnData
    function _processPreExecHook(ModuleEntity preExecHook, bytes calldata data) internal returns (bytes memory) {
        (address module, uint32 entityId) = preExecHook.unpack();
        try IExecutionHookModule(module).preExecutionHook(entityId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            return returnData;
        } catch {
            bytes memory revertReason = ExecutionUtils.fetchReturnData();
            revert PreExecHookFailed(preExecHook, revertReason);
        }
    }

    // @dev post exec hooks should be executed in reverse order of the pre exec hooks
    function _processPostExecHooks(PostExecHookToRun[] memory postExecHooksToRun) internal {
        uint256 length = postExecHooksToRun.length;
        for (uint256 i = length; i > 0;) {
            // adjust for array index
            unchecked {
                i--;
            }
            ModuleEntity postExecHook = postExecHooksToRun[i].postExecHook;
            if (ModuleEntity.unwrap(postExecHooksToRun[i].postExecHook) == EMPTY_MODULE_ENTITY) {
                // from preOnlyHook
                continue;
            }
            (address module, uint32 entityId) = postExecHook.unpack();
            // solhint-disable-next-line no-empty-blocks
            try IExecutionHookModule(module).postExecutionHook(entityId, postExecHooksToRun[i].preExecHookReturnData) {}
            catch {
                bytes memory revertReason = ExecutionUtils.fetchReturnData();
                revert PostExecHookFailed(postExecHook, revertReason);
            }
        }
    }

    function _toHookConfigs(Bytes32DLL storage hooksDLL) internal view returns (HookConfig[] memory hooks) {
        uint256 hooksCount = hooksDLL.size();
        hooks = new HookConfig[](hooksCount);
        uint256 totalExecHooksCount = 0;
        bytes32 startHook = SENTINEL_BYTES32;
        for (uint256 i = 0; i < hooksCount; ++i) {
            (bytes32[] memory execHooks, bytes32 nextHook) = hooksDLL.getPaginated(startHook, 50);
            for (uint256 j = 0; j < execHooks.length; ++j) {
                hooks[totalExecHooksCount] = toHookConfig(execHooks[j]);
                totalExecHooksCount++;
            }
            if (nextHook == SENTINEL_BYTES32) {
                break;
            }
            startHook = nextHook;
        }
        return hooks;
    }

    function toBytes32(HookConfig _config) internal pure returns (bytes32) {
        return bytes32(HookConfig.unwrap(_config));
    }

    function toHookConfig(bytes32 _value) internal pure returns (HookConfig hookConfig) {
        return HookConfig.wrap(bytes25(_value));
    }
}
