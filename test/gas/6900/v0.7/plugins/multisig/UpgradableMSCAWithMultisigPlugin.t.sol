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

import {OwnerData, OwnershipMetadata, PublicKey} from "../../../../../../src/common/CommonStructs.sol";
import {FunctionReference} from "../../../../../../src/msca/6900/v0.7/common/Structs.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Vm} from "forge-std/src/Vm.sol";
import {console} from "forge-std/src/console.sol";

import {
    PluginManager,
    UpgradableMSCA,
    UpgradableMSCAFactory
} from "../../../../../../src/msca/6900/v0.7/factories/UpgradableMSCAFactory.sol";
import {WeightedWebauthnMultisigPlugin} from
    "../../../../../../src/msca/6900/v0.7/plugins/v1_0_0/multisig/WeightedWebauthnMultisigPlugin.sol";
import {TestLiquidityPool} from "../../../../../util/TestLiquidityPool.sol";
import {PluginGasProfileBaseTest} from "../../../../PluginGasProfileBase.t.sol";

contract UpgradableMSCAWithMultisigPluginTest is PluginGasProfileBaseTest {
    using Strings for uint256;
    using MessageHashUtils for bytes32;

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

    uint256 internal ownerPrivateKey1;
    uint256 internal ownerPrivateKey2;
    address private ownerAddr1;
    address private ownerAddr2;
    UpgradableMSCAFactory private factory;
    WeightedWebauthnMultisigPlugin private multisigPlugin;
    UpgradableMSCA private msca;
    address private multisigPluginAddr;
    address private mscaAddr;
    string public accountAndPluginType;
    TestLiquidityPool private testLiquidityPool;

    function setUp() public override {
        super.setUp();
        testLiquidityPool = new TestLiquidityPool("TestERC20", "$$$");

        accountAndPluginType = "UpgradableMSCAWithMultisigPlugin";
        address factoryOwner = makeAddr("factoryOwner");
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));
        multisigPlugin = new WeightedWebauthnMultisigPlugin(address(entryPoint));
        multisigPluginAddr = address(multisigPlugin);

        address[] memory _plugins = new address[](1);
        _plugins[0] = multisigPluginAddr;
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();
    }

    function testBenchmarkAll() external override {
        testBenchmarkAccountCreation(2);
        testBenchmarkAccountCreation(3);
        testBenchmarkAccountCreation(5);
        testBenchmarkAccountCreation(10);
        testBenchmarkPluginAddOwners(1);
        testBenchmarkPluginAddOwners(2);
        testBenchmarkPluginAddOwners(3);
        testBenchmarkPluginAddOwners(5);
        testBenchmarkPluginAddOwners(10);
        testBenchmarkPluginUpdateMultisigWeights();
        testBenchmarkPluginRemoveOwners();
        testBenchmarkTokenTransfer();
        writeTestResult(accountAndPluginType);
    }

    function testBenchmarkPluginInstall() internal pure override {
        console.log("not implemented");
    }

    function testBenchmarkPluginUninstall() internal pure override {
        console.log("not implemented");
    }

    function testBenchmarkAccountCreation(uint256 ownerCount) internal {
        (ownerAddr, ownerPrivateKey) =
            makeAddrAndKey(string(abi.encodePacked("testBenchmarkAccountCreation_", ownerCount.toString())));
        address[] memory initialOwners = new address[](ownerCount);
        for (uint256 i = 0; i < ownerCount; i++) {
            initialOwners[i] = makeAddr(string(abi.encodePacked("owner", i)));
        }
        uint256[] memory ownerWeights = new uint256[](ownerCount);
        for (uint256 i = 0; i < ownerCount; i++) {
            ownerWeights[i] = 1;
        }
        PublicKey[] memory initialPublicKeyOwners = new PublicKey[](0);
        uint256[] memory initialPublicKeyWeights = new uint256[](0);
        uint256 thresholdWeight = 1;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(multisigPluginAddr);
        manifestHashes[0] = keccak256(abi.encode(multisigPlugin.pluginManifest()));
        pluginInstallData[0] =
            abi.encode(initialOwners, ownerWeights, initialPublicKeyOwners, initialPublicKeyWeights, thresholdWeight);
        vm.startPrank(ownerAddr);
        uint256 gasBefore = gasleft();
        msca = factory.createAccount(
            addressToBytes32(ownerAddr),
            0x0000000000000000000000000000000000000000000000000000000000000000,
            abi.encode(plugins, manifestHashes, pluginInstallData)
        );
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();
        mscaAddr = address(msca);
        vm.deal(mscaAddr, 1 ether);

        string memory testName = string(abi.encodePacked("0001_account_creation_runtime_", ownerCount.toString()));
        console.log("case - %s", testName);
        console.log("  gasUsed       : ", gasUsed);
        vm.serializeUint(jsonObj, testName, gasUsed);
        sum += gasUsed;

        (,, OwnershipMetadata memory ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.numOwners, ownerCount);
    }

    function testBenchmarkPluginAddOwners(uint256 ownerCount) internal {
        // create account first
        createMultisigAccount(string(abi.encodePacked("testBenchmarkPluginAddOwners_", ownerCount.toString())));

        (,, OwnershipMetadata memory ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.numOwners, 2);

        // now add owners
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        address[] memory ownersToAdd = new address[](ownerCount);
        for (uint256 i = 0; i < ownerCount; i++) {
            ownersToAdd[i] = makeAddr(string(abi.encodePacked("owner", i)));
        }
        uint256[] memory weightsToAdd = new uint256[](ownerCount);
        for (uint256 i = 0; i < ownerCount; i++) {
            weightsToAdd[i] = 1;
        }
        PublicKey[] memory publicKeyOwnersToAdd = new PublicKey[](0);
        uint256[] memory pubicKeyWeightsToAdd = new uint256[](0);
        uint256 newThresholdWeight = 1;
        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("addOwners(address[],uint256[],(uint256,uint256)[],uint256[],uint256)")),
            ownersToAdd,
            weightsToAdd,
            publicKeyOwnersToAdd,
            pubicKeyWeightsToAdd,
            newThresholdWeight
        );

        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(callData));

        bytes memory signatureActualDigest = signUserOpHashActualDigest(entryPoint, vm, ownerPrivateKey1, userOp);
        userOp.signature = signatureActualDigest;

        string memory testName = string(abi.encodePacked("0002_addOwners_", ownerCount.toString()));
        executeUserOp(mscaAddr, userOp, testName, 0);
        (,, ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        uint256 originalOwners = 2;
        uint256 updatedOwners = originalOwners + ownerCount;
        assertEq(ownershipMetadata.numOwners, updatedOwners);
    }

    function testBenchmarkPluginUpdateMultisigWeights() internal {
        // create account first
        createMultisigAccount("testBenchmarkPluginUpdateMultisigWeights");
        (,, OwnershipMetadata memory ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.thresholdWeight, 1);

        // now update owner weights
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        address[] memory ownersToUpdate = new address[](2);
        ownersToUpdate[0] = ownerAddr1;
        ownersToUpdate[1] = ownerAddr2;
        uint256[] memory newWeightsToUpdate = new uint256[](2);
        newWeightsToUpdate[0] = 2;
        newWeightsToUpdate[1] = 2;
        PublicKey[] memory publicKeyOwnersToUpdate = new PublicKey[](0);
        uint256[] memory pubicKeyNewWeightsToUpdate = new uint256[](0);
        uint256 newThresholdWeight = 2;
        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("updateMultisigWeights(address[],uint256[],(uint256,uint256)[],uint256[],uint256)")),
            ownersToUpdate,
            newWeightsToUpdate,
            publicKeyOwnersToUpdate,
            pubicKeyNewWeightsToUpdate,
            newThresholdWeight
        );

        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(callData));

        bytes memory signatureActualDigest = signUserOpHashActualDigest(entryPoint, vm, ownerPrivateKey1, userOp);
        userOp.signature = signatureActualDigest;

        string memory testName = "0003_updateMultisigWeights_updateTwo";
        executeUserOp(mscaAddr, userOp, testName, 0);
        (,, ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.thresholdWeight, 2);
    }

    function testBenchmarkPluginRemoveOwners() internal {
        // create account first
        createMultisigAccount("testBenchmarkPluginRemoveOwners");
        bytes30[] memory ownerAddresses;
        OwnerData[] memory ownersData;
        OwnershipMetadata memory ownershipMetadata;
        (ownerAddresses, ownersData, ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.numOwners, 2);

        // now remove one owner
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = ownerAddr2;
        PublicKey[] memory publicKeyOwnersToRemove = new PublicKey[](0);
        uint256 newThresholdWeight = 1;
        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("removeOwners(address[],(uint256,uint256)[],uint256)")),
            ownersToRemove,
            publicKeyOwnersToRemove,
            newThresholdWeight
        );

        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(callData));

        bytes memory signatureActualDigest = signUserOpHashActualDigest(entryPoint, vm, ownerPrivateKey1, userOp);
        userOp.signature = signatureActualDigest;

        string memory testName = "0004_removeOwners_1";
        executeUserOp(mscaAddr, userOp, testName, 0);
        (ownerAddresses, ownersData, ownershipMetadata) = multisigPlugin.ownershipInfoOf(mscaAddr);
        assertEq(ownershipMetadata.numOwners, 1);
    }

    function testBenchmarkTokenTransfer() internal {
        // create account first
        createMultisigAccount("testBenchmarkTokenTransfer");
        testLiquidityPool.mint(mscaAddr, 2000000);
        assertEq(testLiquidityPool.balanceOf(mscaAddr), 2000000);

        // now transfer
        uint256 acctNonce = entryPoint.getNonce(mscaAddr, 0);
        address recipientAddr = makeAddr("recipient");
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipientAddr, 1000000);
        bytes memory callData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), liquidityPoolSpenderAddr, 0, transferCallData
        );

        PackedUserOperation memory userOp = buildPartialUserOp(mscaAddr, acctNonce, vm.toString(callData));

        bytes memory signatureActualDigest = signUserOpHashActualDigest(entryPoint, vm, ownerPrivateKey1, userOp);
        userOp.signature = signatureActualDigest;

        string memory testName = "0005_erc20_transfer";
        executeUserOp(mscaAddr, userOp, testName, 0);
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 1000000);
        assertEq(testLiquidityPool.balanceOf(mscaAddr), 1000000);
    }

    function createMultisigAccount(string memory testName) internal returns (address) {
        (ownerAddr, ownerPrivateKey) = makeAddrAndKey(testName);
        address[] memory initialOwners = new address[](2);
        uint256[] memory ownerWeights = new uint256[](2);
        PublicKey[] memory initialPublicKeyOwners = new PublicKey[](0);
        uint256[] memory initialPublicKeyWeights = new uint256[](0);
        uint256 thresholdWeight = 1;
        (ownerAddr1, ownerPrivateKey1) = makeAddrAndKey("owner1");
        (ownerAddr2, ownerPrivateKey2) = makeAddrAndKey("owner2");
        initialOwners[0] = ownerAddr1;
        initialOwners[1] = ownerAddr2;
        ownerWeights[0] = 1;
        ownerWeights[1] = 1;
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(multisigPluginAddr);
        manifestHashes[0] = keccak256(abi.encode(multisigPlugin.pluginManifest()));
        pluginInstallData[0] =
            abi.encode(initialOwners, ownerWeights, initialPublicKeyOwners, initialPublicKeyWeights, thresholdWeight);
        return createAccount(plugins, manifestHashes, pluginInstallData);
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

    function signUserOpHashActualDigest(IEntryPoint entryPoint, Vm vm, uint256 key, PackedUserOperation memory userOp)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v + 32);
    }
}
