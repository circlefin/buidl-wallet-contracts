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
import {HookConfig, ModuleEntity} from "../common/Types.sol";
import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {ModuleEntityLib} from "./thirdparty/ModuleEntityLib.sol";

// Hook fields:
// module address
// entity ID
// hook flags

// Hook flags:
// hook type
// exec hook: hasPre, hasPost
// validation hook

// Hook config is a packed representation of a hook function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // Hook Flags

// Hook flags layout:
// 0b00000___ // unused
// 0b_____A__ // hasPre (exec only)
// 0b______B_ // hasPost (exec only)
// 0b_______C // hook type (0 for exec, 1 for validation)
/// @notice Built on top of 6900 reference impl.
library HookConfigLib {
    using ModuleEntityLib for ModuleEntity;
    using Bytes32DLLLib for Bytes32DLL;

    error PreExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);
    error PostExecHookFailed(ModuleEntity moduleEntity, bytes revertReason);
    // Hook type constants

    // Exec has no bits set
    bytes32 internal constant _HOOK_TYPE_EXEC = bytes32(uint256(0));
    // Validation has 1 bit in 8th bit the 25th byte
    bytes32 internal constant _HOOK_TYPE_VALIDATION = bytes32(uint256(1) << 56);

    // Exec hook flags constants
    // Pre hook has 1 bit in 6th bit in the 25th byte
    bytes32 internal constant _EXEC_HOOK_HAS_PRE = bytes32(uint256(1) << 58);
    // Post hook has 1 bit in 7th bit in the 25th byte
    bytes32 internal constant _EXEC_HOOK_HAS_POST = bytes32(uint256(1) << 57);

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
                HookConfig hookConfig = toHookConfig(execHooks[j]);
                (ModuleEntity hookFunction, bool hasPre, bool hasPost) = unpackExecHook(hookConfig);
                if (hasPost) {
                    postExecHooksToRun[totalPostExecHooksToRunCount++].postExecHook = hookFunction;
                }
                // run pre hook and copy the return data if there's a post hook
                if (hasPre) {
                    bytes memory preExecHookReturnData = _processPreExecHook(hookFunction, data);
                    if (hasPost) {
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

    function _processPostExecHooks(PostExecHookToRun[] memory postExecHooksToRun) internal {
        uint256 length = postExecHooksToRun.length;
        for (uint256 i = 0; i < length; ++i) {
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

    function _getExecutionHooks(Bytes32DLL storage executionHooks) internal view returns (HookConfig[] memory hooks) {
        uint256 hooksCount = executionHooks.size();
        hooks = new HookConfig[](hooksCount);
        uint256 totalExecHooksCount = 0;
        bytes32 startHook = SENTINEL_BYTES32;
        for (uint256 i = 0; i < hooksCount; ++i) {
            (bytes32[] memory execHooks, bytes32 nextHook) = executionHooks.getPaginated(startHook, 10);
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

    function packValidationHook(ModuleEntity _hookFunction) internal pure returns (HookConfig) {
        return HookConfig.wrap(bytes25(bytes25(ModuleEntity.unwrap(_hookFunction)) | bytes25(_HOOK_TYPE_VALIDATION)));
    }

    function packValidationHook(address _module, uint32 _entityId) internal pure returns (HookConfig) {
        return HookConfig.wrap(
            bytes25(
                // module address stored in the first 20 bytes
                bytes25(bytes20(_module))
                // entityId stored in the 21st - 24th byte
                | bytes25(bytes24(uint192(_entityId))) | bytes25(_HOOK_TYPE_VALIDATION)
            )
        );
    }

    function packExecHook(ModuleEntity _hookFunction, bool _hasPre, bool _hasPost) internal pure returns (HookConfig) {
        return HookConfig.wrap(
            bytes25(
                bytes25(ModuleEntity.unwrap(_hookFunction))
                // | bytes25(_HOOK_TYPE_EXEC) // Can omit because exec type is 0
                | bytes25(_hasPre ? _EXEC_HOOK_HAS_PRE : bytes32(0))
                    | bytes25(_hasPost ? _EXEC_HOOK_HAS_POST : bytes32(0))
            )
        );
    }

    function packExecHook(address _module, uint32 _entityId, bool _hasPre, bool _hasPost)
        internal
        pure
        returns (HookConfig)
    {
        return HookConfig.wrap(
            bytes25(
                // module address stored in the first 20 bytes
                bytes25(bytes20(_module))
                // entityId stored in the 21st - 24th byte
                | bytes25(bytes24(uint192(_entityId)))
                // | bytes25(_HOOK_TYPE_EXEC) // Can omit because exec type is 0
                | bytes25(_hasPre ? _EXEC_HOOK_HAS_PRE : bytes32(0))
                    | bytes25(_hasPost ? _EXEC_HOOK_HAS_POST : bytes32(0))
            )
        );
    }

    function unpackValidationHook(HookConfig _config) internal pure returns (ModuleEntity _hookFunction) {
        bytes25 configBytes = HookConfig.unwrap(_config);
        _hookFunction = ModuleEntity.wrap(bytes24(configBytes));
    }

    function unpackExecHook(HookConfig _config)
        internal
        pure
        returns (ModuleEntity _hookFunction, bool _hasPre, bool _hasPost)
    {
        bytes25 configBytes = HookConfig.unwrap(_config);
        _hookFunction = ModuleEntity.wrap(bytes24(configBytes));
        _hasPre = configBytes & _EXEC_HOOK_HAS_PRE != 0;
        _hasPost = configBytes & _EXEC_HOOK_HAS_POST != 0;
    }

    function getModule(HookConfig _config) internal pure returns (address) {
        return address(bytes20(HookConfig.unwrap(_config)));
    }

    function getEntityId(HookConfig _config) internal pure returns (uint32) {
        return uint32(bytes4(HookConfig.unwrap(_config) << 160));
    }

    function getModuleEntity(HookConfig _config) internal pure returns (ModuleEntity) {
        return ModuleEntity.wrap(bytes24(HookConfig.unwrap(_config)));
    }

    // Check if the hook is a validation hook
    function isValidationHook(HookConfig _config) internal pure returns (bool) {
        return HookConfig.unwrap(_config) & _HOOK_TYPE_VALIDATION != 0;
    }

    // @notice Check if the exec hook has a pre hook
    // Undefined behavior if the hook is not an exec hook
    function hasPreHook(HookConfig _config) internal pure returns (bool) {
        return HookConfig.unwrap(_config) & _EXEC_HOOK_HAS_PRE != 0;
    }

    // @notice Check if the exec hook has a post hook
    // Undefined behavior if the hook is not an exec hook
    function hasPostHook(HookConfig _config) internal pure returns (bool) {
        return HookConfig.unwrap(_config) & _EXEC_HOOK_HAS_POST != 0;
    }

    function toBytes32(HookConfig _config) internal pure returns (bytes32) {
        return bytes32(HookConfig.unwrap(_config));
    }

    function toHookConfig(bytes32 _value) internal pure returns (HookConfig hookConfig) {
        return HookConfig.wrap(bytes25(_value));
    }
}
