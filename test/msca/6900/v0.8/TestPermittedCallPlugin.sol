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

import {PLUGIN_VERSION_1, PLUGIN_AUTHOR} from "../../../../src/common/Constants.sol";
import {BasePlugin} from "../../../../src/msca/6900/v0.8/plugins/BasePlugin.sol";
import {
    PluginManifest,
    PluginMetadata,
    ManifestExecutionFunction
} from "../../../../src/msca/6900/v0.8/common/PluginManifest.sol";
import {IPlugin} from "../../../../src/msca/6900/v0.8/interfaces/IPlugin.sol";
import {FooBarPlugin} from "./FooBarPlugin.sol";

/**
 * @dev Plugin for tests only. This plugin demos permitted call.
 */
contract TestPermittedCallPlugin is BasePlugin {
    string public constant NAME = "Test Permitted Call Plugin";

    // solhint-disable-next-line no-empty-blocks
    function onInstall(bytes calldata) external override {}

    // solhint-disable-next-line no-empty-blocks
    function onUninstall(bytes calldata) external override {}

    // "foo" can skip runtime validation
    function permittedCallAllowed() external view returns (bytes memory) {
        return abi.encode(FooBarPlugin(msg.sender).foo());
    }

    // "bar" cannot skip runtime validation, so this should revert.
    function permittedCallNotAllowed() external view returns (bytes memory) {
        return abi.encode(FooBarPlugin(msg.sender).bar());
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0].executionSelector = this.permittedCallAllowed.selector;
        manifest.executionFunctions[1].executionSelector = this.permittedCallNotAllowed.selector;

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.executionFunctions[i].skipRuntimeValidation = true;
        }
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;
        return metadata;
    }
}
