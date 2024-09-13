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

import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {TestUtils} from "../../../util/TestUtils.sol";

import {FooBarPlugin} from "./FooBarPlugin.sol";
import {TestPermittedCallPlugin} from "./TestPermittedCallPlugin.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract PermittedCallTest is TestUtils {
    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    FooBarPlugin private fooBarPlugin;
    TestPermittedCallPlugin private permittedCallPlugin;
    address private factoryOwner;
    UpgradableMSCAFactory private factory;
    UpgradableMSCA private msca;
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    bytes private initializingData;
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;

    error ExecFromPluginToSelectorNotPermitted(address plugin, bytes4 selector);

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");

        fooBarPlugin = new FooBarPlugin();
        permittedCallPlugin = new TestPermittedCallPlugin();
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));

        address[] memory plugins = new address[](2);
        plugins[0] = address(fooBarPlugin);
        plugins[1] = address(permittedCallPlugin);
        bool[] memory permissions = new bool[](2);
        permissions[0] = true;
        permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(plugins, permissions);
        vm.stopPrank();

        bytes[] memory pluginInstallData = new bytes[](2);
        pluginInstallData[0] = "";
        pluginInstallData[1] = "";
        initializingData = abi.encode(plugins, pluginInstallData);
    }

    function testAllowedPermittedCall() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testAllowedPermittedCall");
        msca = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        bytes memory result = TestPermittedCallPlugin(address(msca)).permittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));
        assertEq(actual, keccak256("foo"));
    }

    function testNotAllowedPermittedCall() public {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testNotAllowedPermittedCall");
        msca = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecFromPluginToSelectorNotPermitted.selector, address(permittedCallPlugin), FooBarPlugin.bar.selector
            )
        );
        TestPermittedCallPlugin(address(msca)).permittedCallNotAllowed();
    }
}
