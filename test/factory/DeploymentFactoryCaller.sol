/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.24;

import {DeploymentFactory} from "../../src/factory/DeploymentFactory.sol";

contract DeploymentFactoryCaller {
    function deployCreate2(DeploymentFactory _factory, bytes32 _salt, bytes memory _creationCode)
        external
        returns (address)
    {
        return _factory.deployCreate2(_salt, _creationCode);
    }

    function deployCreate2(DeploymentFactory _factory, uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        returns (address)
    {
        return _factory.deployCreate2{value: _value}(_value, _salt, _creationCode);
    }

    function deployCreate2Permissionless(DeploymentFactory _factory, bytes32 _salt, bytes memory _creationCode)
        external
        returns (address)
    {
        return _factory.deployCreate2Permissionless(_salt, _creationCode);
    }

    function deployCreate2Permissionless(
        DeploymentFactory _factory,
        uint256 _value,
        bytes32 _salt,
        bytes memory _creationCode
    ) external payable returns (address) {
        return _factory.deployCreate2Permissionless{value: _value}(_value, _salt, _creationCode);
    }

    function deployCreate3(DeploymentFactory _factory, bytes32 _salt, bytes memory _creationCode)
        external
        returns (address)
    {
        return _factory.deployCreate3(_salt, _creationCode);
    }

    function deployCreate3(DeploymentFactory _factory, uint256 _value, bytes32 _salt, bytes memory _creationCode)
        external
        payable
        returns (address)
    {
        return _factory.deployCreate3{value: _value}(_value, _salt, _creationCode);
    }
}
