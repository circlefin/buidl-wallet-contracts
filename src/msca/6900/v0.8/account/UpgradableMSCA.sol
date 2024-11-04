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

import {BaseMSCA} from "./BaseMSCA.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @dev Leverage {ERC1967Proxy} brought by UUPS proxies, when this contract is set as the implementation behind such a
 * proxy.
 * The {_authorizeUpgrade} function is overridden here so more granular ACLs to the upgrade mechanism should be enforced
 * by modules.
 */
contract UpgradableMSCA is BaseMSCA, DefaultCallbackHandler, UUPSUpgradeable {
    using ExecutionUtils for address;
    using ValidationConfigLib for ValidationConfig;

    // a unique identifier in the format "vendor.account.semver" for the account implementation
    string public constant ACCOUNT_ID = "circle.msca.2.0.0";

    event UpgradableMSCAInitialized(address indexed account, address indexed entryPointAddress);

    constructor(IEntryPoint _newEntryPoint) BaseMSCA(_newEntryPoint) {
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    /// @notice Initializes the account with a validation function.
    /// @dev This function is only callable once. It is expected to be called by the factory that deploys the account.
    ///      It can be overridden by subcontracts to add more initialization logic.
    function initializeWithValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external virtual walletStorageInitializer {
        _installValidation(validationConfig, selectors, installData, hooks);
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
        emit UpgradableMSCAInitialized(address(this), address(ENTRY_POINT));
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return ACCOUNT_ID;
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
    /// @notice Maybe be validated by a global validation.
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
     * modules.
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}
}
