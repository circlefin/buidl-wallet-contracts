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
import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

// TODO: move it to createAccountWithValidation when it's added to the UpgradableMSCAFactory
contract UpgradableMSCAFactoryTest is AccountTestUtils {
    using ModuleEntityLib for ModuleEntity;

    event AccountCreated(address indexed proxy, bytes32 sender, bytes32 salt);
    event UpgradableMSCAInitialized(address indexed account, address indexed entryPointAddress);
    event SignerTransferred(
        address indexed account, uint32 indexed entityId, address indexed newSigner, address previousSigner
    );
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    event ValidationInstalled(address indexed module, uint32 indexed entityId);

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    // deprecate and replace with UpgradableMSCAFactory
    UpgradableMSCAFactory private factory;
    SingleSignerValidationModule private singleSignerValidationModule;
    TestLiquidityPool private testLiquidityPool;
    address payable private beneficiary; // e.g. bundler
    address private factoryOwner;
    ModuleEntity private ownerValidation;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        beneficiary = payable(address(makeAddr("bundler")));
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        singleSignerValidationModule = new SingleSignerValidationModule();
        address[] memory _modules = new address[](1);
        _modules[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(_modules, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
    }

    function testInstallDisabledModule() public {
        SingleSignerValidationModule maliciousModule = new SingleSignerValidationModule();
        ownerValidation = ModuleEntityLib.pack(address(maliciousModule), uint32(0));
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        bytes4 errorSelector = bytes4(keccak256("ModuleIsNotAllowed(address)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, address(maliciousModule)));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
    }

    function testGetAddressAndCreateMSCA() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateMSCA");
        vm.startPrank(ownerAddr);
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        (address counterfactualAddr,) =
            factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // emit OwnershipTransferred
        vm.expectEmit(true, true, true, true);
        emit SignerTransferred(counterfactualAddr, uint32(0), ownerAddr, address(0));
        // emit ModuleInstalled first
        vm.expectEmit(true, false, false, true);
        (address moduleAddr,) = ownerValidation.unpack();
        emit ValidationInstalled(moduleAddr, uint32(0));
        // emit UpgradableMSCAInitialized
        vm.expectEmit(true, true, false, false);
        emit UpgradableMSCAInitialized(counterfactualAddr, address(entryPoint));
        // emit AccountCreated
        vm.expectEmit(true, true, false, false);
        emit AccountCreated(counterfactualAddr, addressToBytes32(ownerAddr), salt);
        UpgradableMSCA accountCreated =
            factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertEq(address(accountCreated.ENTRY_POINT()), address(entryPoint));
        assertEq(singleSignerValidationModule.signers(uint32(0), address(accountCreated)), ownerAddr);
        // verify the address does not change
        assertEq(address(accountCreated), counterfactualAddr);
        // deploy again
        UpgradableMSCA accountCreatedAgain =
            factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // verify the address does not change
        assertEq(address(accountCreatedAgain), counterfactualAddr);
        vm.stopPrank();
    }

    // standard execution
    function testDeployMSCAWith1stOutboundUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDeployMSCAWith1stOutboundUserOp");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        (address sender,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory tokenTransferCallData = abi.encodeCall(testLiquidityPool.transfer, (recipient, 1000000));
        bytes memory executeCallData =
            abi.encodeCall(IModularAccount.execute, (liquidityPoolSpenderAddr, 0, tokenTransferCallData));
        bytes memory createAccountCall = abi.encodeCall(
            UpgradableMSCAFactory.createAccountWithValidation, (addressToBytes32(ownerAddr), salt, initializingData)
        );
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        // no paymaster
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        // verify the account has been deployed
        assertTrue(sender.code.length > 0);
        // verify the outbound ERC20 token transfer is successful by checking the balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
        assertEq(testLiquidityPool.balanceOf(sender), 1000000);
        vm.stopPrank();
    }

    function testStakeAndUnstakeWithEP() public {
        UpgradableMSCAFactory newFactory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        vm.deal(factoryOwner, 1 ether);
        address payable stakeWithdrawalAddr = payable(vm.addr(1));
        vm.startPrank(factoryOwner);
        newFactory.addStake{value: 123}(1);
        newFactory.unlockStake();
        // skip forward block.timestamp
        skip(10);
        newFactory.withdrawStake(stakeWithdrawalAddr);
        vm.stopPrank();
        assertEq(stakeWithdrawalAddr.balance, 123);

        address randomAddr = makeAddr("randomAddr");
        vm.startPrank(randomAddr);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        newFactory.withdrawStake(stakeWithdrawalAddr);

        vm.deal(randomAddr, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        newFactory.addStake{value: 123}(1);

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        newFactory.unlockStake();

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        newFactory.transferOwnership(address(0x1));

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomAddr));
        address[] memory _modules = new address[](1);
        _modules[0] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        newFactory.setModules(_modules, _permissions);
        vm.stopPrank();

        // transfer owner to address(1)
        address pendingOwner = vm.addr(1);
        vm.startPrank(factoryOwner);
        newFactory.transferOwnership(pendingOwner);
        vm.stopPrank();
        assertEq(newFactory.pendingOwner(), pendingOwner);
        // call from pendingOwner
        vm.startPrank(pendingOwner);
        newFactory.acceptOwnership();
        assertEq(newFactory.owner(), pendingOwner);
        vm.stopPrank();
    }

    function testEncodeAndDecodeFactoryWithValidPaddedInput() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testEncodeAndDecodeFactoryWithValidPaddedInput");
        address[] memory modules = new address[](1);
        bytes[] memory moduleInstallData = new bytes[](1);
        modules[0] = address(singleSignerValidationModule);
        moduleInstallData[0] = abi.encode(uint32(0), ownerAddr);
        bytes memory result = abi.encode(modules, moduleInstallData);
        address[] memory expectedModules = new address[](1);
        bytes[] memory expectedModuleInstallData = new bytes[](1);
        (expectedModules, expectedModuleInstallData) = abi.decode(result, (address[], bytes[]));
        assertEq(modules, expectedModules);
        for (uint256 i = 0; i < moduleInstallData.length; i++) {
            assertEq(moduleInstallData[i], expectedModuleInstallData[i]);
        }
    }

    function testEncodeAndDecodeFactoryWithInvalidPaddedInput() public {
        bytes memory result = hex"7109709ECfa91a80626fF3989D68f67F5b1DD12D";
        vm.expectRevert();
        abi.decode(result, (address[], bytes32[], bytes[]));
    }

    function testEncodeAndDecodeFactoryWithMaliciousBytes() public {
        // valid input with extra malicious bytes "12" in the beginning
        bytes memory result =
            hex"12000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000a0cb889707d426a7a386870a03bc70d1b069759800000000000000000000000000000000000000000000000000000000000000021fb17bac7936d72e95b49501e9c8757384ffae4690113008f5bd3ecf2de5750ed892482cc7e665eca1d358d318d38aa3a63c10247d473d04fc3538f4069ce4ae00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000200000000000000000000000001924ea847b70baedb7e066e092912d89ca8c654a0000000000000000000000000000000000000000000000000000000000000000";
        vm.expectRevert();
        abi.decode(result, (address[], bytes32[], bytes[]));
    }
}
