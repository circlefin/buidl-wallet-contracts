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
import {Bytes32DLL} from "../../shared/common/Structs.sol";

import {Bytes32DLLLib} from "../../shared/libs/Bytes32DLLLib.sol";
import {ExecutionHook, PostExecHookToRun} from "../common/Structs.sol";
import {ModuleEntity} from "../common/Types.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {ModuleEntityLib} from "./thirdparty/ModuleEntityLib.sol";

/**
 * @dev Process pre or post execution hooks.
 */
library ExecutionHookLib {
    using ModuleEntityLib for ModuleEntity;
    using Bytes32DLLLib for Bytes32DLL;

    error PreExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);
    error PostExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);

    function _processPreExecHooks(Bytes32DLL storage executionHooks, bytes calldata data)
        internal
        returns (PostExecHookToRun[] memory postExecHooksToRun)
    {
        uint256 hooksCount = executionHooks.size();
        postExecHooksToRun = new PostExecHookToRun[](hooksCount);
        uint256 totalPostExecHooksToRunCount = 0;
        // copy post hook first
        bytes32 startHook = SENTINEL_BYTES32;
        for (uint256 i = 0; i < hooksCount; ++i) {
            (bytes32[] memory execHooks, bytes32 nextHook) = executionHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < execHooks.length; ++j) {
                (ModuleEntity hookFunction, bool isPreHook, bool isPostHook) = toExecutionHook(execHooks[j]);
                if (isPostHook) {
                    postExecHooksToRun[totalPostExecHooksToRunCount++].postExecHook = hookFunction;
                }
                // run pre hook and copy the return data if there's a post hook
                if (isPreHook) {
                    bytes memory preExecHookReturnData = _processPreExecHook(hookFunction, data);
                    if (isPostHook) {
                        // store the data in last postExecHook
                        postExecHooksToRun[totalPostExecHooksToRunCount - 1].preExecHookReturnData =
                            preExecHookReturnData;
                    }
                }
            }
            if (nextHook == SENTINEL_BYTES32) {
                break;
            }
            startHook = nextHook;
        }
    }

    function _processPreExecHook(ModuleEntity preExecHook, bytes calldata data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        (address plugin, uint32 entityId) = preExecHook.unpack();
        try IExecutionHook(plugin).preExecutionHook(entityId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            preExecHookReturnData = returnData;
        } catch (bytes memory revertReason) {
            revert PreExecHookFailed(preExecHook, revertReason);
        }
        return preExecHookReturnData;
    }

    function _processPostExecHooks(PostExecHookToRun[] memory postExecHooksToRun) internal {
        uint256 length = postExecHooksToRun.length;
        for (uint256 i = 0; i < length; ++i) {
            ModuleEntity postExecHook = postExecHooksToRun[i].postExecHook;
            if (ModuleEntity.unwrap(postExecHooksToRun[i].postExecHook) == EMPTY_MODULE_ENTITY) {
                // from preOnlyHook
                continue;
            }
            (address plugin, uint32 entityId) = postExecHook.unpack();
            try IExecutionHook(plugin).postExecutionHook(entityId, postExecHooksToRun[i].preExecHookReturnData) {}
            catch (bytes memory revertReason) {
                revert PostExecHookFailed(postExecHook, revertReason);
            }
        }
    }

    function _getExecutionHooks(Bytes32DLL storage executionHooks)
        internal
        view
        returns (ExecutionHook[] memory hooks)
    {
        uint256 hooksCount = executionHooks.size();
        hooks = new ExecutionHook[](hooksCount);
        uint256 totalExecHooksCount = 0;
        bytes32 startHook = SENTINEL_BYTES32;
        for (uint256 i = 0; i < hooksCount; ++i) {
            (bytes32[] memory execHooks, bytes32 nextHook) = executionHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < execHooks.length; ++j) {
                (ModuleEntity hookFunction, bool isPreHook, bool isPostHook) = toExecutionHook(execHooks[j]);
                hooks[totalExecHooksCount].hookFunction = hookFunction;
                hooks[totalExecHooksCount].isPreHook = isPreHook;
                hooks[totalExecHooksCount].isPostHook = isPostHook;
                totalExecHooksCount++;
            }
            if (nextHook == SENTINEL_BYTES32) {
                break;
            }
            startHook = nextHook;
        }
        return hooks;
    }

    // ExecutionHook layout:
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF________________ Hook Module Entity - 24 bytes
    // 0x________________________________________________AA______________ is pre hook - 1 byte
    // 0x__________________________________________________BB____________ is post hook - 1 byte
    function toBytes32(ExecutionHook memory executionHook) internal pure returns (bytes32) {
        return bytes32(ModuleEntity.unwrap(executionHook.hookFunction))
            | bytes32(executionHook.isPreHook ? uint256(1) << 56 : 0)
            | bytes32(executionHook.isPostHook ? uint256(1) << 48 : 0);
    }

    function toExecutionHook(bytes32 value)
        internal
        pure
        returns (ModuleEntity hookFunction, bool isPreHook, bool isPostHook)
    {
        hookFunction = ModuleEntity.wrap(bytes24(value));
        isPreHook = (uint256(value) >> 56) & 0xFF == 1;
        isPostHook = (uint256(value) >> 48) & 0xFF == 1;
    }

    function getExecutionHookFunction(bytes32 value) internal pure returns (ModuleEntity hookFunction) {
        hookFunction = ModuleEntity.wrap(bytes24(value));
    }
}
