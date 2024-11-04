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

import {DefaultCallbackHandler} from "../../../../callback/DefaultCallbackHandler.sol";
import {ExecutionUtils} from "../../../../utils/ExecutionUtils.sol";
import {InvalidInitializationInput} from "../../shared/common/Errors.sol";
import {FunctionReference} from "../common/Structs.sol";
import {PluginManager} from "../managers/PluginManager.sol";
import {BaseMSCA} from "./BaseMSCA.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @dev Leverage {ERC1967Proxy} brought by UUPS proxies, when this contract is set as the implementation behind such a
 * proxy.
 * The {_authorizeUpgrade} function is overridden here so more granular ACLs to the upgrade mechanism should be enforced
 * by plugins.
 */
contract UpgradableMSCA is BaseMSCA, DefaultCallbackHandler, UUPSUpgradeable {
    using ExecutionUtils for address;

    event UpgradableMSCAInitialized(address indexed account, address indexed entryPointAddress);

    constructor(IEntryPoint _newEntryPoint, PluginManager _newPluginManager)
        BaseMSCA(_newEntryPoint, _newPluginManager)
    {
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    /// @notice Initializes the account with a set of plugins
    /// @dev No dependencies can be injected with this installation. For a full installation, please use installPlugin.
    /// @param plugins The plugins to install
    /// @param manifestHashes The manifest hashes of the plugins to install
    /// @param pluginInstallData The plugin init data of the plugins to install, please pass in empty bytes if you don't
    /// need to init
    function initializeUpgradableMSCA(
        address[] memory plugins,
        bytes32[] memory manifestHashes,
        bytes[] memory pluginInstallData
    ) external walletStorageInitializer {
        uint256 length = plugins.length;
        if (length != manifestHashes.length || length != pluginInstallData.length) {
            revert InvalidInitializationInput();
        }
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        for (uint256 i = 0; i < length; ++i) {
            // call install directly to bypass validateNativeFunction modifier
            bytes memory data = abi.encodeCall(
                PluginManager.install,
                (plugins[i], manifestHashes[i], pluginInstallData[i], dependencies, address(this))
            );
            address(pluginManager).delegateCall(data);
            emit PluginInstalled(plugins[i], manifestHashes[i], dependencies);
        }
        emit UpgradableMSCAInitialized(address(this), address(entryPoint));
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(BaseMSCA, DefaultCallbackHandler)
        returns (bool)
    {
        // BaseMSCA has already implemented ERC165
        return BaseMSCA.supportsInterface(interfaceId) || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC1271).interfaceId;
    }

    /// @inheritdoc UUPSUpgradeable
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override
        onlyProxy
        validateNativeFunction
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    /**
     * @dev The function is overridden here so more granular ACLs to the upgrade mechanism should be enforced by
     * plugins.
     */
    function _authorizeUpgrade(address newImplementation) internal override {}
}
