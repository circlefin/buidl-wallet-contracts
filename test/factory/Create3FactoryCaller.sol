/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.

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

import {Create3Factory} from "../../src/factory/Create3Factory.sol";

contract Create3FactoryCaller {
    function deploy(Create3Factory _factory, bytes32 _salt, bytes memory _creationCode) external returns (address) {
        return _factory.deploy(_salt, _creationCode);
    }

    function deploy(Create3Factory _factory, uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        returns (address)
    {
        return _factory.deploy{value: _value}(_value, _salt, _creationCode);
    }
}
