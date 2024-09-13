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

import "../../../../../../src/msca/6900/v0.7/common/Structs.sol";

import "../../../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import "../../../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import "../../../../../../src/utils/ExecutionUtils.sol";
import "../../../../PluginGasProfileBase.t.sol";

contract SingleOwnerMSCAWithSingleOwnerPluginTest is PluginGasProfileBaseTest {
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
    SingleOwnerMSCAFactory private factory;
    SingleOwnerPlugin private singleOwnerPlugin;
    SingleOwnerMSCA private msca;
    address private singleOwnerPluginAddr;
    address private mscaAddr;
    string public accountAndPluginType;

    function setUp() public override {
        super.setUp();
        accountAndPluginType = "SingleOwnerMSCAWithSingleOwnerPlugin";
        factory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
        singleOwnerPlugin = new SingleOwnerPlugin();
        singleOwnerPluginAddr = address(singleOwnerPlugin);
    }

    function testBenchmarkAll() external override {
        testBenchmarkPluginInstall();
        testBenchmarkPluginUninstall();
        writeTestResult(accountAndPluginType);
    }

    /// @notice This is just measuring runtime install because we can't delete SingleOwnerPlugin.
    function testBenchmarkPluginInstall() internal override {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginInstall");
        // create account first
        createAccount();

        // now uninstall
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes32 manifestHash = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        FunctionReference[] memory fr = new FunctionReference[](0);
        bytes memory installCallData =
            abi.encodeCall(msca.installPlugin, (address(singleOwnerPlugin), manifestHash, abi.encode(ownerAddr), fr));
        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(installCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0001_install";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function testBenchmarkPluginUninstall() internal override {
        // create account first
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey("testBenchmarkPluginUninstall");
        createAccount();
        // install singleOwnerPlugin first
        bytes32 manifestHash = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        FunctionReference[] memory fr = new FunctionReference[](0);
        vm.startPrank(ownerAddr);
        msca.installPlugin(address(singleOwnerPlugin), manifestHash, abi.encode(ownerAddr), fr);
        vm.stopPrank();

        // now uninstall
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        bytes memory uninstallCallData =
            abi.encodeCall(msca.uninstallPlugin, (address(singleOwnerPlugin), "", abi.encode(address(0))));
        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(uninstallCallData));

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;

        string memory testName = "0002_uninstall";
        executeUserOp(mscaAddr, userOp, testName, 0);
    }

    function createAccount() internal returns (address) {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        vm.startPrank(ownerAddr);
        msca = factory.createAccount(ownerAddr, salt, initializingData);
        vm.stopPrank();
        mscaAddr = address(msca);
        vm.deal(mscaAddr, 1 ether);
        return mscaAddr;
    }
}
