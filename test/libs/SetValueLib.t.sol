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

import {TestUtils} from "../util/TestUtils.sol";
import {SetValueLibCaller} from "./SetValueLibCaller.sol";
import {SetValue} from "@modular-account-libs/libraries/Constants.sol";

contract SetValueLibTest is TestUtils {
    SetValueLibCaller private setValueLibCaller = new SetValueLibCaller();

    function testFuzz_toBytes30Array(SetValue[] memory values) public view {
        bytes30[] memory res = setValueLibCaller.toBytes30Array(values);
        uint256 len = res.length;
        for (uint256 i = 0; i < len; ++i) {
            assertEq(SetValue.unwrap(values[i]), res[i]);
        }
    }
}
