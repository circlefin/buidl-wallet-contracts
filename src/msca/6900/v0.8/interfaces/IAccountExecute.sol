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

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IAccountExecute {
    /**
     * Account may implement this execute method.
     * Passing this methodSig at the beginning of callData will cause the entryPoint to pass the full UserOp (and hash)
     * to the account.
     * The account should skip the methodSig, and use the callData (and optionally, other UserOp fields)
     *
     * @param userOp              - The operation that was just validated.
     * @param userOpHash          - Hash of the user's request data.
     */
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;
}
