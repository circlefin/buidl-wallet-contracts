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

import {PLUGIN_AUTHOR, PLUGIN_VERSION_1} from "../../../../../../common/Constants.sol";
import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestFunction,
    PluginManifest,
    PluginMetadata
} from "../../../common/PluginManifest.sol";
import {BasePlugin} from "../../BasePlugin.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/interfaces/IERC777Recipient.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @dev Default token callback handler plugin. Similar to DefaultCallbackHandler.
 *      This plugin allows MSCA to receive tokens such as 721, 1155 and 777.
 * @notice The user will have to register itself in the ERC1820 global registry
 *         in order to fully support ERC777 token operations upon the installation of this plugin.
 */
contract DefaultTokenCallbackPlugin is BasePlugin, IERC721Receiver, IERC1155Receiver, IERC777Recipient {
    string public constant NAME = "Default Token Callback Plugin";

    function onInstall(bytes calldata data) external pure override {
        (data);
    }

    function onUninstall(bytes calldata data) external pure override {
        (data);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    // ERC777
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external pure override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.executionFunctions = new bytes4[](4);
        manifest.executionFunctions[0] = this.onERC721Received.selector;
        manifest.executionFunctions[1] = this.onERC1155Received.selector;
        manifest.executionFunctions[2] = this.onERC1155BatchReceived.selector;
        manifest.executionFunctions[3] = this.tokensReceived.selector;
        // only runtimeValidationFunctions is needed since token contracts callback to the plugin
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](4);
        // we can consider implementing more complex logic to reject the scamming tokens in the future
        ManifestFunction memory runtimeValidationAlwaysAllow =
            ManifestFunction(ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW, 0, 0);
        manifest.runtimeValidationFunctions[0] =
            ManifestAssociatedFunction(this.onERC721Received.selector, runtimeValidationAlwaysAllow);
        manifest.runtimeValidationFunctions[1] =
            ManifestAssociatedFunction(this.onERC1155Received.selector, runtimeValidationAlwaysAllow);
        manifest.runtimeValidationFunctions[2] =
            ManifestAssociatedFunction(this.onERC1155BatchReceived.selector, runtimeValidationAlwaysAllow);
        manifest.runtimeValidationFunctions[3] =
            ManifestAssociatedFunction(this.tokensReceived.selector, runtimeValidationAlwaysAllow);
        manifest.interfaceIds = new bytes4[](3);
        manifest.interfaceIds[0] = type(IERC721Receiver).interfaceId;
        manifest.interfaceIds[1] = type(IERC1155Receiver).interfaceId;
        manifest.interfaceIds[2] = type(IERC777Recipient).interfaceId;
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
