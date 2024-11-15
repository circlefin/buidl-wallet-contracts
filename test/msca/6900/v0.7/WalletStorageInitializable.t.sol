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

import {TestUtils} from "../../../util/TestUtils.sol";
import {ChildConstructorInitializableMock} from "./ChildConstructorInitializableMock.sol";
import {ConstructorInitializableMock} from "./ConstructorInitializableMock.sol";
import {DisableInitializingWalletStorageMock} from "./DisableInitializingWalletStorageMock.sol";
import {LockWalletStorageAfterInitializationMock} from "./LockWalletStorageAfterInitializationMock.sol";
import {LockedWalletStorageMock} from "./LockedWalletStorageMock.sol";

import {WalletStorageInitializableMock} from "./WalletStorageInitializableMock.sol";

contract WalletStorageInitializableTest is TestUtils {
    event WalletStorageInitialized();

    error WalletStorageIsInitialized();
    error WalletStorageIsNotInitializing();
    error WalletStorageIsInitializing();

    function testBeforeInitialize() public {
        WalletStorageInitializableMock wallet = new WalletStorageInitializableMock();
        assertFalse(wallet.initializerRan());
        assertFalse(wallet.isInitializing());

        // cannot call initializeOnlyInitializing function outside the scope of an initializable function
        vm.expectRevert(WalletStorageIsNotInitializing.selector);
        wallet.initializeOnlyInitializing();
    }

    function testAfterInitialize() public {
        WalletStorageInitializableMock wallet = new WalletStorageInitializableMock();
        wallet.initialize();
        assertTrue(wallet.initializerRan());
        assertFalse(wallet.isInitializing());
        vm.expectRevert(WalletStorageIsInitialized.selector);
        wallet.initialize();

        // cannot call initializeOnlyInitializing function outside the scope of an initializable function
        vm.expectRevert(WalletStorageIsNotInitializing.selector);
        wallet.initializeOnlyInitializing();
    }

    function testNestedUnderAnInitializer() public {
        WalletStorageInitializableMock wallet = new WalletStorageInitializableMock();
        vm.expectRevert(WalletStorageIsInitialized.selector);
        wallet.initializerNested();

        wallet.onlyInitializingNested();
        assertTrue(wallet.onlyInitializingRan());

        // cannot call initializeOnlyInitializing function outside the scope of an initializable function
        vm.expectRevert(WalletStorageIsNotInitializing.selector);
        wallet.initializeOnlyInitializing();
    }

    function testNestedInitializerCanRunDuringConstruction() public {
        ConstructorInitializableMock mock = new ConstructorInitializableMock();
        assertTrue(mock.initializerRan());
        assertTrue(mock.onlyInitializingRan());
    }

    function testMultipleConstructorLevelsCanBeInitializers() public {
        ChildConstructorInitializableMock mock = new ChildConstructorInitializableMock();
        assertTrue(mock.initializerRan());
        assertTrue(mock.onlyInitializingRan());
        assertTrue(mock.childInitializerRan());
    }

    function testInitLockedWalletStorage() public {
        // the wallet is disabled/locked from initializing,
        // so it should not be able to initialize in walletStorageInitializer
        vm.expectRevert(WalletStorageIsInitialized.selector);
        new LockedWalletStorageMock();
    }

    function testDisableInitializationInMiddleOfInitializing() public {
        // the wallet is the middle of initializing
        // so it should not be able to disable the process
        vm.expectRevert(WalletStorageIsInitializing.selector);
        new DisableInitializingWalletStorageMock();
    }

    function testDisableInitializationAfterInit() public {
        vm.expectEmit(true, true, true, true);
        emit WalletStorageInitialized();
        new LockWalletStorageAfterInitializationMock();
    }
}
