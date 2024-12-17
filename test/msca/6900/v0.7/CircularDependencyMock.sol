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

import {PLUGIN_AUTHOR, PLUGIN_VERSION_1} from "../../../../src/common/Constants.sol";
import {UnauthorizedCaller} from "../../../../src/common/Errors.sol";

import {IPlugin} from "../../../../src/msca/6900/v0.7/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {console} from "forge-std/src/console.sol";
import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest,
    PluginMetadata
} from "src/msca/6900/v0.7/common/PluginManifest.sol";

/**
 * @dev Plugin that has circular dependency to itself.
 */
contract CircularDependencyMock is BasePlugin {
    string public constant _NAME = "CircularDependencyMock Plugin";
    uint256 internal constant _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX = 0;

    enum FunctionId {
        RUNTIME_VALIDATION_SELF
    }

    function foo() external pure {
        console.logString("foo()");
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
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        pure
        override
        returns (uint256 validationData)
    {
        (functionId, userOp, userOpHash, validationData);
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        view
        override
    {
        console.logString("runtimeValidationFunction()");
        (functionId, sender, value, data);
        if (sender == msg.sender) {
            return;
        }
        revert UnauthorizedCaller();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.dependencyInterfaceIds = new bytes4[](1);
        manifest.dependencyInterfaceIds[_OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX] = type(IPlugin).interfaceId;
        // for a correct manifest, ManifestAssociatedFunctionType.SELF should be used,
        // but for the purpose of this malicious plugin, we use ManifestAssociatedFunctionType.DEPENDENCY
        ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // unused for dependency
            dependencyIndex: _OWNER_RUNTIME_VALIDATION_DEPENDENCY_INDEX
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ownerRuntimeValidationFunction
        });
        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;
        return metadata;
    }

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
