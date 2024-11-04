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

import {PLUGIN_AUTHOR, PLUGIN_VERSION_1, SIG_VALIDATION_SUCCEEDED} from "../../../../src/common/Constants.sol";
import "../../../../src/msca/6900/v0.7/common/Structs.sol";

import "../../../../src/msca/6900/v0.7/interfaces/IPluginExecutor.sol";
import "../../../../src/msca/6900/v0.7/interfaces/IPluginManager.sol";
import "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";

import "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import "../../../util/TestLiquidityPool.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "forge-std/src/console.sol";

/**
 * @dev Plugin for tests only. This plugin permits any external contract calls with post hook only.
 */
contract TestPermitAnyExternalAddressWithPostHookOnlyPlugin is BasePlugin {
    enum FunctionId {
        USER_OP_VALIDATION,
        RUNTIME_VALIDATION,
        POST_EXECUTION_HOOK,
        POST_PERMITTED_CALL_EXECUTION_HOOK
    }

    string public constant NAME = "Test Permit Any External Contract Plugin";

    // externalFromPluginExternal is allowed
    // mint to both liquidity pools
    function mintToken(uint256 value, address longLiquidityPoolAddr, address shortLiquidityPoolAddr) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            longLiquidityPoolAddr, 0, abi.encodeCall(TestLiquidityPool.mint, (msg.sender, value))
        );
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            shortLiquidityPoolAddr, 0, abi.encodeCall(TestLiquidityPool.mint, (msg.sender, value))
        );
    }

    function spendNativeToken(uint256 value, address longLiquidityPoolAddr) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            longLiquidityPoolAddr, value, abi.encodeCall(TestLiquidityPool.mint, (msg.sender, value))
        );
    }

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external pure override {
        (data);
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata data) external pure override {
        (data);
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        pure
        override
        returns (uint256 validationData)
    {
        (userOp, userOpHash);
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return SIG_VALIDATION_SUCCEEDED;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        pure
        override
    {
        (sender, value, data);
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION)) {
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    /// @inheritdoc BasePlugin
    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external pure override {
        console.logString("postExecutionHook data:");
        console.logBytes(preExecHookData);
        require(preExecHookData.length == 0, "postOnlyHook should not have data");
        if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            return;
        } else if (functionId == uint8(FunctionId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
            return;
        } else if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            return;
        } else if (functionId == uint8(FunctionId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
            return;
        }
        revert NotImplemented(msg.sig, functionId);
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        /// executionFunctions
        manifest.executionFunctions = new bytes4[](2);
        // Execution functions defined in this plugin to be installed on the MSCA.
        manifest.executionFunctions[0] = this.mintToken.selector;
        manifest.executionFunctions[1] = this.spendNativeToken.selector;

        /// permitAnyExternalAddress
        manifest.permitAnyExternalAddress = true;

        manifest.canSpendNativeToken = false;

        /// userOpValidationFunctions
        ManifestFunction memory userOpValidationAssociatedFunction =
            ManifestFunction(ManifestAssociatedFunctionType.SELF, uint8(FunctionId.USER_OP_VALIDATION), 0);
        // the following function calls (from entry point) should be gated by the userOpValidationAssociatedFunction
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](manifest.executionFunctions.length);
        // plugin functions
        // if the same executionSelector has already gated by other plugin.userOpValidationFunction, re-installation
        // will revert
        for (uint256 i = 0; i < manifest.executionFunctions.length; ++i) {
            manifest.userOpValidationFunctions[i] =
                ManifestAssociatedFunction(manifest.executionFunctions[i], userOpValidationAssociatedFunction);
        }

        /// preUserOpValidationHooks
        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](0);

        /// runtimeValidationFunctions
        ManifestFunction memory runtimeValidationAssociatedFunction =
            ManifestFunction(ManifestAssociatedFunctionType.SELF, uint8(FunctionId.RUNTIME_VALIDATION), 0);
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](manifest.executionFunctions.length);
        // plugin functions
        for (uint256 i = 0; i < manifest.executionFunctions.length; ++i) {
            manifest.runtimeValidationFunctions[i] =
                ManifestAssociatedFunction(manifest.executionFunctions[i], runtimeValidationAssociatedFunction);
        }

        /// preRuntimeValidationHooks
        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](0);

        /// executionHooks
        manifest.executionHooks = new ManifestExecutionHook[](1);
        manifest.executionHooks[0] = ManifestExecutionHook({
            selector: this.mintToken.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.NONE,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
                dependencyIndex: 0
            })
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;
        return metadata;
    }
}
