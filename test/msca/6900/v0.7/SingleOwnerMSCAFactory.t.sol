/**
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.24;

import {UnauthorizedCaller} from "../../../../src/common/Errors.sol";
import {Create3Factory} from "../../../../src/factory/Create3Factory.sol";
import {InvalidInitializationInput} from "../../../../src/msca/6900/shared/common/Errors.sol";
import {SingleOwnerMSCA} from "../../../../src/msca/6900/v0.7/account/semi/SingleOwnerMSCA.sol";
import {FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {SingleOwnerMSCAFactory} from "../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Vm} from "forge-std/src/Vm.sol";

contract SingleOwnerMSCAFactoryTest is TestUtils {
    bytes32 private constant ERC1967_IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    event FactoryDeployed(
        address indexed factory, address accountImplementation, address create3Factory, bytes32 factoryFamilyNamespace
    );
    event AccountCreated(address indexed proxy, address sender, bytes32 salt);
    event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner);
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    error InvalidFactoryOwner(address owner);
    error InvalidAccountImplementation(address implementation);
    error InvalidCreate3Factory(address factory);
    error InvalidWithdrawAddress(address withdrawAddress);
    error RenounceOwnershipNotAllowed();
    error AccountAlreadyDeployed(address account);
    error UnexpectedDeployedAddress(address expected, address actual);

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    Create3Factory private create3Factory;
    SingleOwnerMSCAFactory private factory;
    TestLiquidityPool private testLiquidityPool;
    address payable private beneficiary;
    address private factoryOwner;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        create3Factory = new Create3Factory(address(this));
        factory = new SingleOwnerMSCAFactory(
            factoryOwner, address(new SingleOwnerMSCA(entryPoint, pluginManager)), address(create3Factory)
        );
        address[] memory callers = new address[](1);
        callers[0] = address(factory);
        bool[] memory permissions = new bool[](1);
        permissions[0] = true;
        create3Factory.setCallers(callers, permissions);

        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        beneficiary = payable(address(makeAddr("bundler")));
    }

    function testConstructorWiresCreate3FactoryAndEmitsFactoryDeployed() public {
        SingleOwnerMSCA implementation = new SingleOwnerMSCA(entryPoint, pluginManager);
        Create3Factory anotherCreate3Factory = new Create3Factory(address(this));
        address anotherOwner = makeAddr("anotherOwner");

        vm.expectEmit(false, false, false, true);
        emit FactoryDeployed(
            address(0), address(implementation), address(anotherCreate3Factory), keccak256("circle.msca.single-owner")
        );

        SingleOwnerMSCAFactory anotherFactory =
            new SingleOwnerMSCAFactory(anotherOwner, address(implementation), address(anotherCreate3Factory));

        assertEq(address(anotherFactory.ACCOUNT_IMPLEMENTATION()), address(implementation));
        assertEq(address(anotherFactory.CREATE3_FACTORY()), address(anotherCreate3Factory));
        assertEq(address(anotherFactory.ENTRY_POINT()), address(entryPoint));
        assertEq(anotherFactory.FACTORY_FAMILY_NAMESPACE(), keccak256("circle.msca.single-owner"));
        assertEq(anotherFactory.owner(), anotherOwner);
    }

    function testConstructorRevertsWhenOwnerIsZeroAddress() public {
        SingleOwnerMSCA implementation = new SingleOwnerMSCA(entryPoint, pluginManager);

        vm.expectRevert(abi.encodeWithSelector(InvalidFactoryOwner.selector, address(0)));
        new SingleOwnerMSCAFactory(address(0), address(implementation), address(create3Factory));
    }

    function testConstructorRevertsWhenImplementationIsZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidAccountImplementation.selector, address(0)));
        new SingleOwnerMSCAFactory(factoryOwner, address(0), address(create3Factory));
    }

    function testConstructorRevertsWhenCreate3FactoryIsZeroAddress() public {
        SingleOwnerMSCA implementation = new SingleOwnerMSCA(entryPoint, pluginManager);

        vm.expectRevert(abi.encodeWithSelector(InvalidCreate3Factory.selector, address(0)));
        new SingleOwnerMSCAFactory(factoryOwner, address(implementation), address(0));
    }

    function testStakeAndUnstakeWithEP() public {
        vm.deal(factoryOwner, 1 ether);
        address payable stakeWithdrawalAddr = payable(vm.addr(1));

        vm.startPrank(factoryOwner);
        factory.addStake{value: 123}(1);
        factory.unlockStake();
        skip(10);
        factory.withdrawStake(stakeWithdrawalAddr);
        vm.stopPrank();

        assertEq(stakeWithdrawalAddr.balance, 123);
    }

    function testOnlyOwnerCanManageStakeAndOwnershipAdmin() public {
        address randomAddr = makeAddr("randomAddr");
        address payable stakeWithdrawalAddr = payable(vm.addr(1));

        vm.startPrank(randomAddr);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, randomAddr));
        factory.withdrawStake(stakeWithdrawalAddr);

        vm.deal(randomAddr, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, randomAddr));
        factory.addStake{value: 123}(1);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, randomAddr));
        factory.unlockStake();

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, randomAddr));
        factory.transferOwnership(address(0x1));
        vm.stopPrank();
    }

    function testWithdrawStakeRevertsWhenWithdrawAddressIsZero() public {
        vm.prank(factoryOwner);
        vm.expectRevert(abi.encodeWithSelector(InvalidWithdrawAddress.selector, address(0)));
        factory.withdrawStake(payable(address(0)));
    }

    function testRenounceOwnershipReverts() public {
        vm.prank(factoryOwner);
        vm.expectRevert(RenounceOwnershipNotAllowed.selector);
        factory.renounceOwnership();
    }

    function testOwnershipTransferTwoStep() public {
        address pendingOwner = vm.addr(1);

        vm.prank(factoryOwner);
        factory.transferOwnership(pendingOwner);
        assertEq(factory.owner(), factoryOwner);
        assertEq(factory.pendingOwner(), pendingOwner);

        vm.prank(pendingOwner);
        factory.acceptOwnership();
        assertEq(factory.owner(), pendingOwner);
        assertEq(factory.pendingOwner(), address(0));
    }

    function testGetAddressAndCreateSingleOwnerMSCA() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateSingleOwnerMSCA");
        vm.startPrank(ownerAddr);
        bytes32 salt = bytes32(0);
        bytes memory initializingData = abi.encode(ownerAddr);
        (address counterfactualAddr,) = factory.getAddress(ownerAddr, salt, initializingData);

        vm.expectEmit(true, true, true, false);
        emit OwnershipTransferred(counterfactualAddr, address(0), ownerAddr);
        vm.expectEmit(true, true, false, false);
        emit SingleOwnerMSCAInitialized(counterfactualAddr, address(entryPoint), ownerAddr);
        vm.expectEmit(true, true, false, false);
        emit AccountCreated(counterfactualAddr, ownerAddr, salt);

        SingleOwnerMSCA accountCreated = factory.createAccount(ownerAddr, salt, initializingData);
        assertEq(address(accountCreated.ENTRY_POINT()), address(entryPoint));
        assertEq(accountCreated.getNativeOwner(), ownerAddr);
        assertEq(address(accountCreated), counterfactualAddr);

        vm.expectRevert(abi.encodeWithSelector(AccountAlreadyDeployed.selector, counterfactualAddr));
        factory.createAccount(ownerAddr, salt, initializingData);
        vm.stopPrank();
    }

    function testDeploySingleOwnerMSCAWith1stOutboundUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDeploySingleOwnerMSCAWith1stOutboundUserOp");
        bytes32 salt = bytes32(0);
        bytes memory initializingData = abi.encode(ownerAddr);
        (address sender,) = factory.getAddress(ownerAddr, salt, initializingData);
        assertTrue(sender.code.length == 0);
        uint256 acctNonce = entryPoint.getNonce(sender, 0);

        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory tokenTransferCallData = abi.encodeCall(testLiquidityPool.transfer, (recipient, 1000000));
        bytes memory executeCallData =
            abi.encodeCall(IStandardExecutor.execute, (liquidityPoolSpenderAddr, 0, tokenTransferCallData));
        bytes memory createAccountCall =
            abi.encodeCall(SingleOwnerMSCAFactory.createAccount, (ownerAddr, salt, initializingData));
        bytes memory initCode = abi.encodePacked(address(factory), createAccountCall);
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
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        assertTrue(sender.code.length > 0);
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
        assertEq(testLiquidityPool.balanceOf(sender), 1000000);
        vm.stopPrank();
    }

    function testGetAddressAndCreateUsingAddressZero() public {
        ownerAddr = address(0);
        vm.startPrank(ownerAddr);
        bytes32 salt = bytes32(0);
        bytes memory initializingData = abi.encode(ownerAddr);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.getAddress(ownerAddr, salt, initializingData);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.createAccount(ownerAddr, salt, initializingData);
        vm.stopPrank();
    }

    function testGetAddressUsesInCodeNamespace() public {
        ownerAddr = makeAddr("namespaceOwner");
        bytes32 salt = bytes32(uint256(123));
        bytes memory initializingData = abi.encode(ownerAddr);

        (address predictedAddr, bytes32 mixedSalt) = factory.getAddress(ownerAddr, salt, initializingData);
        bytes32 expectedMixedSalt =
            keccak256(abi.encode(factory.FACTORY_FAMILY_NAMESPACE(), ownerAddr, ownerAddr, salt));

        assertEq(mixedSalt, expectedMixedSalt);
        assertEq(predictedAddr, create3Factory.getAddress(expectedMixedSalt));
    }

    function testFuzz_getAddressMatchesCreate3FactoryAddress(address sender, address owner, bytes32 salt) public view {
        vm.assume(owner != address(0));

        bytes memory initializingData = abi.encode(owner);
        (address predictedAddr, bytes32 mixedSalt) = factory.getAddress(sender, salt, initializingData);

        assertEq(mixedSalt, keccak256(abi.encode(factory.FACTORY_FAMILY_NAMESPACE(), sender, owner, salt)));
        assertEq(predictedAddr, create3Factory.getAddress(mixedSalt));
    }

    function testGetAddressChangesWhenSenderChanges() public {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(123));

        (address firstAddr, bytes32 firstMixedSalt) = factory.getAddress(makeAddr("senderA"), salt, abi.encode(owner));
        (address secondAddr, bytes32 secondMixedSalt) = factory.getAddress(makeAddr("senderB"), salt, abi.encode(owner));

        assertTrue(firstAddr != secondAddr);
        assertTrue(firstMixedSalt != secondMixedSalt);
    }

    function testGetAddressChangesWhenUserSaltChanges() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");

        (address firstAddr, bytes32 firstMixedSalt) =
            factory.getAddress(sender, bytes32(uint256(111)), abi.encode(owner));
        (address secondAddr, bytes32 secondMixedSalt) =
            factory.getAddress(sender, bytes32(uint256(222)), abi.encode(owner));

        assertTrue(firstAddr != secondAddr);
        assertTrue(firstMixedSalt != secondMixedSalt);
    }

    function testGetAddressChangesWhenOwnerChanges() public {
        address sender = makeAddr("sender");
        bytes32 salt = bytes32(uint256(123));

        (address firstAddr, bytes32 firstMixedSalt) = factory.getAddress(sender, salt, abi.encode(makeAddr("ownerA")));
        (address secondAddr, bytes32 secondMixedSalt) = factory.getAddress(sender, salt, abi.encode(makeAddr("ownerB")));

        assertTrue(firstAddr != secondAddr);
        assertTrue(firstMixedSalt != secondMixedSalt);
    }

    function testGetAddressAndCreateRevertOnMalformedInitializingData() public {
        bytes32 salt = bytes32(0);

        vm.expectRevert();
        factory.getAddress(makeAddr("sender"), salt, "");

        vm.expectRevert();
        factory.createAccount(makeAddr("sender"), salt, hex"1234");
    }

    function testGetAddressReturnsSameValueBeforeAndAfterDeployment() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(123));
        bytes memory initializingData = abi.encode(owner);

        (address predictedBefore, bytes32 mixedSaltBefore) = factory.getAddress(sender, salt, initializingData);

        vm.prank(sender);
        factory.createAccount(sender, salt, initializingData);

        (address predictedAfter, bytes32 mixedSaltAfter) = factory.getAddress(sender, salt, initializingData);

        assertEq(predictedBefore, predictedAfter);
        assertEq(mixedSaltBefore, mixedSaltAfter);
    }

    function testCreateAccountRevertsAfterDeploymentRegardlessOfAllowlist() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(123));
        bytes memory initializingData = abi.encode(owner);

        vm.prank(sender);
        SingleOwnerMSCA deployedAccount = factory.createAccount(sender, salt, initializingData);

        address[] memory callers = new address[](1);
        callers[0] = address(factory);
        bool[] memory permissions = new bool[](1);
        permissions[0] = false;
        create3Factory.setCallers(callers, permissions);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(AccountAlreadyDeployed.selector, address(deployedAccount)));
        factory.createAccount(sender, salt, initializingData);
    }

    function testCreateAccountDeploysProxyPointingToExpectedImplementation() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(123));

        vm.prank(sender);
        SingleOwnerMSCA account = factory.createAccount(sender, salt, abi.encode(owner));

        address implementation = address(uint160(uint256(vm.load(address(account), ERC1967_IMPLEMENTATION_SLOT))));
        assertEq(implementation, address(factory.ACCOUNT_IMPLEMENTATION()));
    }

    function testCreateAccountRevertsWhenFactoryIsNotAllowlisted() public {
        address[] memory callers = new address[](1);
        callers[0] = address(factory);
        bool[] memory permissions = new bool[](1);
        permissions[0] = false;
        create3Factory.setCallers(callers, permissions);

        vm.expectRevert(UnauthorizedCaller.selector);
        factory.createAccount(makeAddr("sender"), bytes32(uint256(123)), abi.encode(makeAddr("owner")));
    }

    function testCreateAccountRevertsWhenAccountAlreadyDeployed() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(123));
        bytes memory initializingData = abi.encode(owner);

        vm.prank(sender);
        SingleOwnerMSCA deployedAccount = factory.createAccount(sender, salt, initializingData);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(AccountAlreadyDeployed.selector, address(deployedAccount)));
        factory.createAccount(sender, salt, initializingData);
    }

    function testCreateAccountRevertsWhenAddressOccupiedByForeignCode() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(789));
        bytes memory initializingData = abi.encode(owner);

        (address counterfactualAddr,) = factory.getAddress(sender, salt, initializingData);

        // Plant arbitrary code at the predicted address before any deployment to confirm the
        // factory refuses to overwrite or alias an existing account address.
        vm.etch(counterfactualAddr, hex"6001");

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(AccountAlreadyDeployed.selector, counterfactualAddr));
        factory.createAccount(sender, salt, initializingData);
    }

    function testCreateAccountAssertsDeployedAddressMatchesPredicted() public {
        address sender = makeAddr("sender");
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(uint256(456));
        bytes memory initializingData = abi.encode(owner);

        (address counterfactualAddr,) = factory.getAddress(sender, salt, initializingData);

        vm.prank(sender);
        SingleOwnerMSCA account = factory.createAccount(sender, salt, initializingData);
        assertEq(address(account), counterfactualAddr);
    }

    function testConstructorEmitsExactlyOneOwnershipTransferred() public {
        address newOwner = makeAddr("ctorOwner");
        SingleOwnerMSCA implementation = new SingleOwnerMSCA(entryPoint, pluginManager);
        Create3Factory anotherCreate3Factory = new Create3Factory(address(this));

        vm.recordLogs();
        SingleOwnerMSCAFactory anotherFactory =
            new SingleOwnerMSCAFactory(newOwner, address(implementation), address(anotherCreate3Factory));
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 ownershipTransferredSig = keccak256("OwnershipTransferred(address,address)");
        uint256 ownershipTransferredCount = 0;
        bytes32 fromTopic;
        bytes32 toTopic;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(anotherFactory)) {
                continue;
            }
            if (logs[i].topics.length > 0 && logs[i].topics[0] == ownershipTransferredSig) {
                ownershipTransferredCount += 1;
                fromTopic = logs[i].topics[1];
                toTopic = logs[i].topics[2];
            }
        }

        assertEq(ownershipTransferredCount, 1);
        assertEq(fromTopic, bytes32(uint256(uint160(address(0)))));
        assertEq(toTopic, bytes32(uint256(uint160(newOwner))));
    }
}
