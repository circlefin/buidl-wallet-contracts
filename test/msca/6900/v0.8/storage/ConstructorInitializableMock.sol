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

import {WalletStorageInitializable} from "../../../../../src/msca/6900/v0.8/account/WalletStorageInitializable.sol";
import {console} from "forge-std/src/console.sol";

contract ConstructorInitializableMock is WalletStorageInitializable {
    bool public initializerRan;
    bool public onlyInitializingRan;

    constructor() walletStorageInitializer {
        console.logString("ConstructorInitializableMock constructor");
        initialize();
        initializeOnlyInitializing();
    }

    function initialize() public walletStorageInitializer {
        initializerRan = true;
    }

    function initializeOnlyInitializing() public onlyWalletStorageInitializing {
        onlyInitializingRan = true;
    }
}
