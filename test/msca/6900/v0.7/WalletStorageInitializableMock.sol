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

import {WalletStorageInitializable} from "../../../../src/msca/6900/v0.7/account/WalletStorageInitializable.sol";
import {WalletStorageV1Lib} from "../../../../src/msca/6900/v0.7/libs/WalletStorageV1Lib.sol";

/**
 * @title InitializableMock, forked from OpenZeppelin
 * @dev This contract is a mock to test WalletStorageInitializable functionality. It is not intended for production.
 *      There are some use cases we don't use in our protocol, such as the contract is initialized at version 1 (no
 * reininitialization) and the current contract is just being deployed,
 *      but we still want to test them.
 */
contract WalletStorageInitializableMock is WalletStorageInitializable {
    bool public initializerRan;
    bool public onlyInitializingRan;

    function isInitializing() public view returns (bool) {
        return WalletStorageV1Lib.getLayout().initializing;
    }

    function initialize() public walletStorageInitializer {
        initializerRan = true;
    }

    function initializeOnlyInitializing() public onlyWalletStorageInitializing {
        onlyInitializingRan = true;
    }

    function initializerNested() public walletStorageInitializer {
        initialize();
    }

    function onlyInitializingNested() public walletStorageInitializer {
        initializeOnlyInitializing();
    }
}
