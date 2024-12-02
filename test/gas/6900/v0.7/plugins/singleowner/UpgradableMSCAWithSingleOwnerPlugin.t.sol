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

import {FunctionReference} from "../../../../../../src/msca/6900/v0.7/common/Structs.sol";
import {console} from "forge-std/src/console.sol";

import {
    PluginManager,
    UpgradableMSCA,
    UpgradableMSCAFactory
} from "../../../../../../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";
import {SingleOwnerPlugin} from "../../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import {ExecutionUtils} from "../../../../../../src/utils/ExecutionUtils.sol";
import {TestUserOpAllPassValidator} from "../../../../../msca/6900/v0.7/TestUserOpAllPassValidator.sol";
import {PluginGasProfileBaseTest} from "../../../../PluginGasProfileBase.t.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract UpgradableMSCAWithSingleOwnerPluginTest is PluginGasProfileBaseTest {
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    // upgrade
    event Upgraded(address indexed newImplementation);
    // 4337
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    PluginManager private pluginManager = new PluginManager();
    uint256 internal ownerPrivateKey;
    address private ownerAddr;
    UpgradableMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    // allPass provides basic validation function
    TestUserOpAllPassValidator private allPass;
    UpgradableMSCA private msca;
    address private singleOwnerPluginAddr;
    address private mscaAddr;
    address private factoryOwner;
    string public accountAndPluginType;

    function setUp() public override {
        super.setUp();
        accountAndPluginType = "UpgradableMSCAWithSingleOwnerPlugin";
        factoryOwner = makeAddr("factoryOwner");
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));
        singleOwnerPlugin = new SingleOwnerPlugin();
        singleOwnerPluginAddr = address(singleOwnerPlugin);
        allPass = new TestUserOpAllPassValidator();

        address[] memory _plugins = new address[](2);
        _plugins[0] = singleOwnerPluginAddr;
        _plugins[1] = address(allPass);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();
    }

    function testBenchmarkAll() external override {
        testBenchmarkPluginInstall();
        testBenchmarkPluginUninstall();
        writeTestResult(accountAndPluginType);
    }

    /// @notice This is just measuring runtime install because we can't delete SingleOwnerPlugin.
    function testBenchmarkPluginInstall() internal override {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginInstall");
        // install allPass first
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(allPass);
        manifestHashes[0] = keccak256(abi.encode(allPass.pluginManifest()));
        pluginInstallData[0] = "";
        createAccount(plugins, manifestHashes, pluginInstallData);

        FunctionReference[] memory fr = new FunctionReference[](0);
        string memory testName = "0001_install_runtime";
        vm.startPrank(ownerAddr);
        bytes32 manifestHash = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        bytes memory data = abi.encodeCall(
            PluginManager.install, (singleOwnerPluginAddr, manifestHash, abi.encode(ownerAddr), fr, mscaAddr)
        );
        uint256 ethBefore = gasleft();
        ExecutionUtils.delegateCall(address(pluginManager), data);
        uint256 gasUsed = ethBefore - gasleft();
        console.log("case - %s", testName);
        console.log("  gasUsed       : ", gasUsed);
        vm.serializeUint(jsonObj, testName, gasUsed);
        sum += gasUsed;
        vm.stopPrank();
    }

    function testBenchmarkPluginUninstall() internal override {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginUninstall");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        createAccount(plugins, manifestHashes, pluginInstallData);

        // now uninstall
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory uninstallCallData =
            abi.encodeCall(msca.uninstallPlugin, (address(singleOwnerPlugin), "", abi.encode(address(0))));
        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(uninstallCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0002_uninstall";
        executeUserOp(mscaAddr, userOp, testName, 0);
        assertEq(singleOwnerPlugin.getOwnerOf(mscaAddr), address(0));
    }

    function createAccount(address[] memory plugins, bytes32[] memory manifestHashes, bytes[] memory pluginInstallData)
        internal
        returns (address)
    {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        vm.startPrank(ownerAddr);
        msca = factory.createAccount(addressToBytes32(ownerAddr), salt, initializingData);
        vm.stopPrank();
        mscaAddr = address(msca);
        vm.deal(mscaAddr, 1 ether);
        return mscaAddr;
    }
}
