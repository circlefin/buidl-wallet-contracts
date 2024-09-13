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

import {WalletStorageV1Lib} from "../libs/WalletStorageV1Lib.sol";

/// @notice Forked from OpenZeppelin (proxy/utils/Initializable.sol) with wallet storage access.
///         Reinitialization is removed.
///         For V1 MSCA.
abstract contract WalletStorageInitializable {
    /**
     * @dev Triggered when the contract has been initialized.
     */
    event WalletStorageInitialized();

    error WalletStorageIsInitializing();
    error WalletStorageIsNotInitializing();
    error WalletStorageIsInitialized();

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyWalletStorageInitializing` functions can be used to initialize parent contracts.
     *
     * Functions marked with `walletStorageInitializer` can be nested in the context of a
     * constructor.
     *
     * Emits an {WalletStorageInitialized} event.
     */
    modifier walletStorageInitializer() {
        bool isTopLevelCall = _setWalletStorageInitializing();
        _;
        if (isTopLevelCall) {
            WalletStorageV1Lib.getLayout().initializing = false;
            emit WalletStorageInitialized();
        }
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {walletStorageInitializer} modifier, directly or indirectly.
     */
    modifier onlyWalletStorageInitializing() {
        if (!WalletStorageV1Lib.getLayout().initializing) {
            revert WalletStorageIsNotInitializing();
        }
        _;
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {WalletStorageInitialized} event the first time it is successfully executed.
     */
    function _disableWalletStorageInitializers() internal virtual {
        if (WalletStorageV1Lib.getLayout().initializing) {
            revert WalletStorageIsInitializing();
        }
        if (WalletStorageV1Lib.getLayout().initialized != type(uint8).max) {
            WalletStorageV1Lib.getLayout().initialized = type(uint8).max;
            emit WalletStorageInitialized();
        }
    }

    function _setWalletStorageInitializing() internal returns (bool) {
        bool isTopLevelCall = !WalletStorageV1Lib.getLayout().initializing;
        uint8 initialized = WalletStorageV1Lib.getLayout().initialized;
        if (!(isTopLevelCall && initialized < 1) || (address(this).code.length <= 0 && initialized == 1)) {
            revert WalletStorageIsInitialized();
        }
        WalletStorageV1Lib.getLayout().initialized = 1;
        if (isTopLevelCall) {
            WalletStorageV1Lib.getLayout().initializing = true;
        }
        return isTopLevelCall;
    }
}
