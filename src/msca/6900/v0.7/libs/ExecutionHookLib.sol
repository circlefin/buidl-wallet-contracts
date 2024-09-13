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

import {EMPTY_FUNCTION_REFERENCE, SENTINEL_BYTES21} from "../../../../common/Constants.sol";
import {InvalidValidationFunctionId} from "../../shared/common/Errors.sol";
import {
    PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE,
    RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
} from "../common/Constants.sol";
import "../common/Structs.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReferenceLib} from "./FunctionReferenceLib.sol";
import {RepeatableFunctionReferenceDLLLib} from "./RepeatableFunctionReferenceDLLLib.sol";

/**
 * @dev Process pre or post execution hooks.
 */
library ExecutionHookLib {
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for FunctionReference;
    using FunctionReferenceLib for bytes21;

    error PreExecHookFailed(address plugin, uint8 functionId, bytes revertReason);
    error PostExecHookFailed(address plugin, uint8 functionId, bytes revertReason);

    // avoid stack too deep
    struct SetPostExecHooksFromPreHooksParam {
        uint256 totalPostExecHooksToRunCount;
        PostExecHookToRun[] postExecHooksToRun;
    }

    function _processPreExecHooks(HookGroup storage hookGroup, bytes calldata data)
        internal
        returns (PostExecHookToRun[] memory postExecHooksToRun)
    {
        uint256 postOnlyHooksCount = hookGroup.postOnlyHooks.getUniqueItems();
        // hooks have three categories a. preOnlyHook b. preToPostHook c. postOnlyHook
        // 1. add repeated preHook into postHook 2. add postOnlyHooks
        uint256 maxPostHooksCount = postOnlyHooksCount + hookGroup.preHooks.getTotalItems();
        uint256 totalPostExecHooksToRunCount = 0;
        postExecHooksToRun = new PostExecHookToRun[](maxPostHooksCount);
        // copy postOnlyHooks into result first
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        for (uint256 i = 0; i < postOnlyHooksCount; ++i) {
            (FunctionReference[] memory resultPostOnlyHooks, FunctionReference memory nextHook) =
                hookGroup.postOnlyHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < resultPostOnlyHooks.length; ++j) {
                postExecHooksToRun[totalPostExecHooksToRunCount++].postExecHook = resultPostOnlyHooks[j];
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        // then run the preHooks and copy associated postHooks
        SetPostExecHooksFromPreHooksParam memory input;
        input.totalPostExecHooksToRunCount = totalPostExecHooksToRunCount;
        input.postExecHooksToRun = postExecHooksToRun;
        (totalPostExecHooksToRunCount, postExecHooksToRun) = _setPostExecHooksFromPreHooks(hookGroup, data, input);
        assembly ("memory-safe") {
            mstore(postExecHooksToRun, totalPostExecHooksToRunCount)
        }
    }

    function _processPreExecHook(FunctionReference memory preExecHook, bytes calldata data)
        internal
        returns (bytes memory preExecHookReturnData)
    {
        try IPlugin(preExecHook.plugin).preExecutionHook(preExecHook.functionId, msg.sender, msg.value, data) returns (
            bytes memory returnData
        ) {
            preExecHookReturnData = returnData;
        } catch (bytes memory revertReason) {
            revert PreExecHookFailed(preExecHook.plugin, preExecHook.functionId, revertReason);
        }
        return preExecHookReturnData;
    }

    function _processPostExecHooks(PostExecHookToRun[] memory postExecHooksToRun) internal {
        uint256 length = postExecHooksToRun.length;
        for (uint256 i = 0; i < length; ++i) {
            FunctionReference memory postExecHook = postExecHooksToRun[i].postExecHook;
            try IPlugin(postExecHook.plugin).postExecutionHook(
                postExecHook.functionId, postExecHooksToRun[i].preExecHookReturnData
            ) {} catch (bytes memory revertReason) {
                revert PostExecHookFailed(postExecHook.plugin, postExecHook.functionId, revertReason);
            }
        }
    }

    function _getExecutionHooks(HookGroup storage hookGroup) internal view returns (ExecutionHooks[] memory hooks) {
        uint256 preHooksCount = hookGroup.preHooks.getUniqueItems();
        uint256 postOnlyHooksCount = hookGroup.postOnlyHooks.getUniqueItems();
        // hooks have three categories a. preOnlyHook b. preToPostHook c. postOnlyHook
        // 1. add repeated preHook into postHook 2. add postOnlyHooks
        uint256 maxExecHooksCount = postOnlyHooksCount + hookGroup.preHooks.getTotalItems();
        uint256 totalExecHooksCount = 0;
        hooks = new ExecutionHooks[](maxExecHooksCount);
        // copy postOnlyHooks into result first
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        for (uint256 i = 0; i < postOnlyHooksCount; ++i) {
            (FunctionReference[] memory resultPostOnlyHooks, FunctionReference memory nextHook) =
                hookGroup.postOnlyHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < resultPostOnlyHooks.length; ++j) {
                hooks[totalExecHooksCount++].postExecHook = resultPostOnlyHooks[j];
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        // then copy preOnlyHooks or preToPostHooks
        startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        for (uint256 i = 0; i < preHooksCount; ++i) {
            (FunctionReference[] memory resultPreExecHooks, FunctionReference memory nextHook) =
                hookGroup.preHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < resultPreExecHooks.length; ++j) {
                // if any revert, the outer call MUST revert
                bytes21 packedPreExecHook = resultPreExecHooks[j].pack();
                // getAll can handle 1000+ hooks
                FunctionReference[] memory preToPostHooks = hookGroup.preToPostHooks[packedPreExecHook].getAll();
                if (preToPostHooks.length > 0) {
                    for (uint256 k = 0; k < preToPostHooks.length; ++k) {
                        hooks[totalExecHooksCount].preExecHook = resultPreExecHooks[j];
                        hooks[totalExecHooksCount].postExecHook = preToPostHooks[k];
                        totalExecHooksCount++;
                    }
                } else {
                    // no associated postHook
                    hooks[totalExecHooksCount++].preExecHook = resultPreExecHooks[j];
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        assembly ("memory-safe") {
            mstore(hooks, totalExecHooksCount)
        }
        return hooks;
    }

    /// @dev The caller would expect both input.totalPostExecHooksToRunCount and input.postExecHooksToRun to be assigned
    /// back to original values.
    function _setPostExecHooksFromPreHooks(
        HookGroup storage hookGroup,
        bytes calldata data,
        SetPostExecHooksFromPreHooksParam memory input
    ) internal returns (uint256, PostExecHookToRun[] memory) {
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        uint256 preHooksCount = hookGroup.preHooks.getUniqueItems();
        for (uint256 i = 0; i < preHooksCount; ++i) {
            (FunctionReference[] memory resultPreExecHooks, FunctionReference memory nextHook) =
                hookGroup.preHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < resultPreExecHooks.length; ++j) {
                // if any revert, the outer call MUST revert
                bytes21 packedPreExecHook = resultPreExecHooks[j].pack();
                if (
                    packedPreExecHook == EMPTY_FUNCTION_REFERENCE
                        || packedPreExecHook == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                        || packedPreExecHook == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                ) {
                    revert InvalidValidationFunctionId(resultPreExecHooks[j].functionId);
                }
                // getAll can handle 1000+ hooks
                // run duplicated (if any) preHooks only once
                bytes memory preExecHookReturnData = _processPreExecHook(resultPreExecHooks[j], data);
                FunctionReference[] memory preToPostHooks = hookGroup.preToPostHooks[packedPreExecHook].getAll();
                if (preToPostHooks.length > 0) {
                    for (uint256 k = 0; k < preToPostHooks.length; ++k) {
                        input.postExecHooksToRun[input.totalPostExecHooksToRunCount].postExecHook = preToPostHooks[k];
                        input.postExecHooksToRun[input.totalPostExecHooksToRunCount].preExecHookReturnData =
                            preExecHookReturnData;
                        input.totalPostExecHooksToRunCount++;
                    }
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        return (input.totalPostExecHooksToRunCount, input.postExecHooksToRun);
    }
}
