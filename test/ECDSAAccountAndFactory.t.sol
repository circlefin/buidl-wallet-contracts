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

import "../src/account/v1/factory/ECDSAAccountFactory.sol";

import "./util/TestERC1155.sol";
import "./util/TestERC721.sol";
import "./util/TestLiquidityPool.sol";
import "./util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "forge-std/src/console.sol";

contract ECDSAAccountAndFactoryTest is TestUtils {
    // erc721
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    // erc1155
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);
    // wallet
    event AccountCreated(address indexed proxy, address indexed owner);
    // test liquidity pool
    event ReceiveETH(address indexed from, uint256 indexed value);
    event Upgraded(address indexed implementation);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    event AccountReceivedNativeToken(address indexed sender, uint256 value);
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    ECDSAAccountFactory private ecdsaAccountFactory;
    address payable beneficiary; // e.g. bundler
    TestLiquidityPool private testLiquidityPool;
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;

    function setUp() public {
        ecdsaAccountFactory = new ECDSAAccountFactory(entryPoint);
        beneficiary = payable(address(makeAddr("bundler")));
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
    }

    function testGetAddressAndCreateAccount() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGetAddressAndCreateAccount");
        console.log(ownerAddr);
        address counterfactualAddr = ecdsaAccountFactory.getAddress(ownerAddr);
        // deploy
        // verify emitted event
        vm.expectEmit(true, true, false, false);
        emit AccountCreated(counterfactualAddr, ownerAddr);
        ECDSAAccount accountCreated = ecdsaAccountFactory.createAccount(ownerAddr);
        assertEq(address(accountCreated.entryPoint()), address(entryPoint));
        assertEq(accountCreated.owner(), ownerAddr);
        // verify the address does not change
        assertEq(address(accountCreated), counterfactualAddr);
        // deploy again
        assertTrue(ecdsaAccountFactory.getAddress(ownerAddr).code.length > 0);
        ECDSAAccount accountCreatedAgain = ecdsaAccountFactory.createAccount(ownerAddr);
        assertEq(address(accountCreatedAgain.entryPoint()), address(entryPoint));
        assertEq(accountCreatedAgain.owner(), ownerAddr);
        // verify the address does not change
        assertEq(address(accountCreatedAgain), counterfactualAddr);
    }

    /// update the entry point via a regular userOp
    // _checkOwner is overridden to accept calls from the account redirected through execute()
    function testUpgradeToNewImplementationViaUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUpgradeToNewImplementationViaUserOp");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        console.log(sender);
        // start with balance
        vm.deal(sender, 1 ether);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // upgradeTo v2 with new entryPoint
        // we should deploy new account factory to generate new account with new entry entryPoint
        // the test is creating new account directly for simplicity
        IEntryPoint newEntryPoint = IEntryPoint(address(vm.addr(999)));
        ECDSAAccount v2Impl = new ECDSAAccount(newEntryPoint);
        address v2ImplAddr = address(v2Impl);
        console.log(v2ImplAddr);
        bytes memory upgradeToCallData =
            abi.encodeWithSelector(bytes4(keccak256("upgradeToAndCall(address,bytes)")), v2ImplAddr, "");
        bytes memory executeCallData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), sender, 0, upgradeToCallData);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650, // increase due to deployment
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // verify Upgraded event
        vm.expectEmit(true, false, false, false);
        // successful event
        emit Upgraded(v2ImplAddr);

        // ignore gas
        vm.expectEmit(true, true, true, false);
        // successful execution
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 137380880000000, 121576);
        entryPoint.handleOps(ops, beneficiary);
    }

    function testValidateUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidateUserOp");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(proxy),
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        uint256 validationData = proxy.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0);
        vm.stopPrank();
    }

    function testValidateUserOp_sigFromOthers() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidateUserOp_sigFromOthers");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(proxy),
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // valid sig with correct ECDSA sig length, max number of non-zero bytes allowed, but not from the sender
        // note because the test already created the SCW, so isValidSignatureNow will staticcall
        // IERC1271.isValidSignature implemented by ECDSAAccount
        userOp.signature =
            "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";
        uint256 validationData = proxy.validateUserOp(userOp, userOpHash, 0);
        // uint256 constant internal SIG_VALIDATION_FAILED = 1;
        assertEq(validationData, 1);
        vm.stopPrank();
    }

    // account deployed, no paymaster setup
    function testHandleOps() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testHandleOps");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(proxy);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), liquidityPoolSpenderAddr, 0, transferCallData
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender, acctNonce, "0x", vm.toString(executeCallData), 83353, 102865, 45484, 516219199704, 1130000000, "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectEmit(true, true, true, false);
        // successful execution
        bool success = true;
        address pm = address(0);
        emit UserOperationEvent(userOpHash, sender, pm, acctNonce, success, 128487780000000, 113706);
        entryPoint.handleOps(ops, beneficiary);

        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
    }

    // account was not deployed
    function testHandleOps_accountWasNotDeployedBefore() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testHandleOps_accountWasNotDeployedBefore");
        console.log(ownerAddr);
        // only get address w/o deployment
        address sender = ecdsaAccountFactory.getAddress(ownerAddr);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), liquidityPoolSpenderAddr, 0, transferCallData
        );
        bytes memory createAccountCall =
            abi.encodeWithSelector(bytes4(keccak256("createAccount(address)")), (ownerAddr));
        address ecdsaAccountFactoryAddr = address(ecdsaAccountFactory);
        console.log(ecdsaAccountFactoryAddr);
        bytes memory initCode = abi.encodePacked(ecdsaAccountFactoryAddr, createAccountCall);
        console.logBytes(initCode);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353,
            1028650, // increase due to deployment
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectEmit(true, true, true, false);
        // successful execution
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
    }

    // create the account and try to deploy it again
    // fail on "AA10 sender already constructed"
    function testHandleOps_accountDeployedTwice() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testHandleOps_accountDeployedTwice");
        console.log(ownerAddr);
        // only get address w/o deployment
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        // start with balance
        vm.deal(sender, 1 ether);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        bytes memory transferCallData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")), address(0x9005Be081B8EC2A31258878409E88675Cd791376), 2000000
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")),
            address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F),
            0,
            transferCallData
        );
        bytes memory createAccountCall =
            abi.encodeWithSelector(bytes4(keccak256("createAccount(address)")), (ownerAddr));
        address ecdsaAccountFactoryAddr = address(ecdsaAccountFactory);
        console.log(ecdsaAccountFactoryAddr);
        // we're not supposed to provide initCode other than 0x
        bytes memory initCode = abi.encodePacked(ecdsaAccountFactoryAddr, createAccountCall);
        console.logBytes(initCode);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353,
            1028650, // increase due to deployment
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    // receive native token for un-deployed account
    function testAccountReceivedNativeToken_unDeployedAccount() public {
        // calculate counterfactual address first
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testAccountReceivedNativeToken_unDeployedAccount");
        console.log(ownerAddr);
        address counterfactualAddr = ecdsaAccountFactory.getAddress(ownerAddr);

        address senderAddr;
        uint256 senderPrivateKey;
        (senderAddr, senderPrivateKey) = makeAddrAndKey("testAccountReceivedNativeToken_unDeployedAccount_sender");
        console.log(senderAddr);
        // fund the senderAddr and use it as msg.sender
        hoax(senderAddr, 100);
        (bool ok,) = counterfactualAddr.call{value: 90}("");
        assertTrue(ok);
    }

    // receive native token for deployed account
    function testAccountReceivedNativeToken_deployedAccount() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testAccountReceivedNativeToken_deployedAccount");
        console.log(ownerAddr);
        ECDSAAccount account = ecdsaAccountFactory.createAccount(ownerAddr);

        address senderAddr;
        uint256 senderPrivateKey;
        (senderAddr, senderPrivateKey) = makeAddrAndKey("testAccountReceivedNativeToken_deployedAccount_sender");
        console.log(senderAddr);
        // fund the senderAddr and use it as msg.sender
        hoax(senderAddr, 1);
        vm.expectEmit(true, false, false, true);
        emit AccountReceivedNativeToken(senderAddr, 1);
        (bool ok,) = address(account).call{value: 1}("");
        assertTrue(ok);
    }

    function testOnlyOwnerCanUpgradeWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testOnlyOwnerCanUpgradeWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        assertEq(address(proxy.entryPoint()), address(entryPoint));
        assertEq(proxy.owner(), ownerAddr);
        IEntryPoint newEntryPoint = IEntryPoint(address(vm.addr(999)));
        assertNotEq(address(proxy.entryPoint()), address(newEntryPoint));
        ECDSAAccount v2Impl = new ECDSAAccount(newEntryPoint);
        address v2ImplAddr = address(v2Impl);
        // upgrade via owner
        vm.startPrank(ownerAddr);
        proxy.upgradeToAndCall(v2ImplAddr, "");
        vm.stopPrank();
        assertEq(address(proxy.entryPoint()), address(newEntryPoint));

        // upgrade via random address
        vm.startPrank(address(1));
        vm.expectRevert(bytes("Caller is not the owner"));
        proxy.upgradeToAndCall(v2ImplAddr, "");
        vm.stopPrank();
    }

    // call from random addresses
    function testOnlyEPAndOwnerCanCallExecuteOrExecuteBatch() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testOnlyEPAndOwnerCanCallExecuteOrExecuteBatch");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(proxy);
        // start with balance
        vm.deal(sender, 1 ether);
        bytes memory transferCallData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")), address(0x9005Be081B8EC2A31258878409E88675Cd791376), 2000000
        );

        vm.startPrank(address(1));
        vm.expectRevert();
        proxy.execute(address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F), 0, transferCallData);
        vm.stopPrank();

        vm.startPrank(address(2));
        vm.expectRevert();
        address[] memory dest = new address[](1);
        dest[0] = address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F);
        uint256[] memory value = new uint256[](1);
        value[0] = 0;
        bytes[] memory func = new bytes[](1);
        func[0] = transferCallData;
        proxy.executeBatch(dest, value, func);
        vm.stopPrank();
    }

    function testOnlyEPAndOwnerCanCallExecuteOrExecuteBatch_inconsistentArgs() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testOnlyEPAndOwnerCanCallExecuteOrExecuteBatch_inconsistentArgs");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(proxy);
        // start with balance
        vm.deal(sender, 1 ether);

        // func.length != dest.length
        bytes memory transferCallData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")), address(0x9005Be081B8EC2A31258878409E88675Cd791376), 2000000
        );
        address[] memory dest = new address[](2);
        uint256[] memory value = new uint256[](2);
        bytes[] memory func = new bytes[](1);
        dest[0] = address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F);
        value[0] = 0;
        func[0] = transferCallData;
        dest[1] = address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F);
        value[1] = 10;

        vm.startPrank(ownerAddr);
        vm.expectRevert(bytes("wrong array lengths"));
        proxy.executeBatch(dest, value, func);
        vm.stopPrank();

        // func.length != value.length
        address[] memory dest2 = new address[](2);
        uint256[] memory value2 = new uint256[](0);
        bytes[] memory func2 = new bytes[](2);
        dest2[0] = address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F);
        func2[0] = transferCallData;
        dest2[1] = address(0x07865c6E87B9F70255377e024ace6630C1Eaa37F);
        func2[1] = transferCallData;

        vm.startPrank(ownerAddr);
        vm.expectRevert(bytes("wrong array lengths"));
        proxy.executeBatch(dest2, value2, func2);
        vm.stopPrank();
    }

    // approve + supplyLiquidity
    function testHandleOps_executeBatch() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testHandleOps_executeBatch");
        console.log(ownerAddr);
        // only get address w/o deployment
        address sender = ecdsaAccountFactory.getAddress(ownerAddr);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // approve sender allowance
        bytes memory approveCallData =
            abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), liquidityPoolSpenderAddr, 2000000);
        // transferFrom
        bytes memory transferFromCallData = abi.encodeWithSelector(
            bytes4(keccak256("supplyLiquidity(address,address,uint256)")), sender, liquidityPoolSpenderAddr, 2000000
        );
        address[] memory dest = new address[](3);
        uint256[] memory value = new uint256[](3);
        bytes[] memory func = new bytes[](3);
        dest[0] = liquidityPoolSpenderAddr;
        value[0] = 0;
        func[0] = approveCallData;
        dest[1] = liquidityPoolSpenderAddr;
        value[1] = 0;
        func[1] = transferFromCallData;
        dest[2] = liquidityPoolSpenderAddr;
        func[2] = "";
        value[2] = 1000;
        bytes memory executeCallData =
            abi.encodeWithSelector(bytes4(keccak256("executeBatch(address[],uint256[],bytes[])")), dest, value, func);
        bytes memory createAccountCall =
            abi.encodeWithSelector(bytes4(keccak256("createAccount(address)")), (ownerAddr));
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(abi.encodePacked(address(ecdsaAccountFactory), createAccountCall)),
            vm.toString(executeCallData),
            83353,
            1028650, // increase due to deployment
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectEmit(true, true, true, false);
        // successful execution
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 356873210000000, 315817);
        emit ReceiveETH(sender, 1000);
        entryPoint.handleOps(ops, beneficiary);
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(liquidityPoolSpenderAddr), 2000000);
        assertEq(address(liquidityPoolSpenderAddr).balance, 1000);
    }

    function testReceive1155Token() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("account_owner");
        (address senderAddr,) = makeAddrAndKey("erc1155_sender");

        // deploy account
        ECDSAAccount ownerAccount = ecdsaAccountFactory.createAccount(ownerAddr);

        // start with balance
        vm.deal(senderAddr, 1 ether);

        // mint 1155 token
        testERC1155.mint(senderAddr, 0, 20, "");

        // set message sender as sender
        vm.startPrank(address(senderAddr));

        vm.expectEmit(true, true, true, true, address(testERC1155));
        emit TransferSingle(senderAddr, senderAddr, address(ownerAccount), 0, 15);
        testERC1155.safeTransferFrom(address(senderAddr), address(ownerAccount), 0, 15, "");

        // should successfully receive erc1155 token
        assertEq(testERC1155.balanceOf(address(ownerAccount), 0), 15);
        vm.stopPrank();
    }

    function testReceive721Token() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("account_owner");
        (address senderAddr,) = makeAddrAndKey("erc721_sender");

        // deploy account
        ECDSAAccount ownerAccount = ecdsaAccountFactory.createAccount(ownerAddr);

        // start with balance
        vm.deal(senderAddr, 1 ether);

        // mint 721 token
        testERC721.safeMint(senderAddr, 3);

        // set message sender as sender
        vm.startPrank(address(senderAddr));

        vm.expectEmit(true, true, true, true);
        emit Transfer(address(senderAddr), address(ownerAccount), 3);
        testERC721.safeTransferFrom(address(senderAddr), address(ownerAccount), 3, "");

        // should successfully receive erc1155 token
        assertEq(testERC721.ownerOf(3), address(ownerAccount));
        vm.stopPrank();
    }

    // test for depositTo/withdrawDepositTo/getDeposit
    function testDeposit() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDepositTo");
        console.log(ownerAddr);
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);

        vm.deal(ownerAddr, 1 ether);
        vm.startPrank(ownerAddr);
        proxy.addDeposit{value: 100}();

        (address randomAddr,) = makeAddrAndKey("randomAccount");
        assertEq(proxy.getDeposit(), 100);
        proxy.withdrawDepositTo(payable(randomAddr), 1);
        assertEq(proxy.getDeposit(), 99);
        assertEq(randomAddr.balance, 1);
        vm.stopPrank();

        // only owner can withdraw
        vm.startPrank(randomAddr);
        vm.expectRevert("Caller is not the owner");
        proxy.withdrawDepositTo(payable(randomAddr), 1);
        vm.stopPrank();
    }

    function testIsValidSignature() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testIsValidSignature");
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(proxy),
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        bytes4 magicValue = proxy.isValidSignature(userOpHash, signature);
        assertEq(magicValue, bytes4(0x1626ba7e));
        vm.stopPrank();
    }

    function testIsValidSignature_sigFromOthers() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testIsValidSignature_invalidSig");
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(proxy),
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // valid sig from others
        bytes memory signature =
            "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";
        bytes4 magicValue = proxy.isValidSignature(userOpHash, signature);
        assertEq(magicValue, bytes4(0xffffffff));
        vm.stopPrank();
    }

    function testPauseAndUnpauseAccount() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testPauseAndUnpauseAccount");
        ECDSAAccount proxy = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(proxy);
        (address randomAddr) = makeAddr("randomAccount");
        vm.startPrank(randomAddr);
        vm.expectRevert("Caller is not the owner");
        proxy.pause();
        vm.stopPrank();

        vm.startPrank(proxy.owner());
        proxy.pause();
        assertEq(true, proxy.paused());
        // should fail if we pause the paused contract
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        proxy.pause();
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), liquidityPoolSpenderAddr, 0, transferCallData
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender, acctNonce, "0x", vm.toString(executeCallData), 83353, 102865, 45484, 516219199704, 1130000000, "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectEmit(true, true, false, true);
        bytes memory revertReason = abi.encodePacked(PausableUpgradeable.EnforcedPause.selector);
        emit UserOperationRevertReason(userOpHash, sender, acctNonce, revertReason);
        vm.startPrank(address(entryPoint));
        // should fail because of paused contract
        entryPoint.handleOps(ops, beneficiary);
        // now unpause
        vm.startPrank(proxy.owner());
        proxy.unpause();
        assertEq(false, proxy.paused());
        vm.stopPrank();
    }

    // from SCA to undeployed SCA
    function testNativeTokenTransferBetweenSCAs() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testNativeTokenTransfer");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        console.log(sender);
        // start with balance
        vm.deal(sender, 1 ether);
        address recipient = ecdsaAccountFactory.getAddress(ownerAddr, "0x1");
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipient, 100000000000000000, "0x"
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender, acctNonce, "0x", vm.toString(executeCallData), 83353, 1028650, 45484, 516219199704, 1130000000, "0x"
        );

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // ignore gas
        vm.expectEmit(true, true, true, false);
        // successful execution
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 167684090000000, 148393);
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipient.balance, 100000000000000000);
        assertLt(sender.balance, 900000000000000000); // sent 0.1 and paid for gas, so the sender should have less than
            // 0.9
    }

    function testSendAndReceiveNativeTokenBetweenTwoSCAsWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveNativeTokenBetweenTwoSCAsWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        console.log(sender);
        // start with balance
        vm.deal(sender, 1 ether);
        address recipient = ecdsaAccountFactory.getAddress(ownerAddr, "0x1");
        vm.startPrank(ownerAddr);
        senderAccount.execute(recipient, 100000000000000000, "");
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipient.balance, 100000000000000000);
        assertEq(sender.balance, 900000000000000000);
        // hacker
        vm.startPrank(vm.addr(123));
        vm.expectRevert(bytes("account: not EntryPoint or Owner"));
        senderAccount.execute(recipient, 100, "");
        vm.stopPrank();
    }

    function testSendNativeTokenFromSCAToEOAWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendNativeTokenFromSCAToEOAWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        console.log(sender);
        // start with balance
        vm.deal(sender, 1 ether);
        address recipient = vm.addr(123);
        vm.startPrank(ownerAddr);
        senderAccount.execute(recipient, 100000000000000000, "");
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipient.balance, 100000000000000000);
        assertEq(sender.balance, 900000000000000000);
        // hacker
        vm.startPrank(vm.addr(456));
        vm.expectRevert(bytes("account: not EntryPoint or Owner"));
        senderAccount.execute(recipient, 100, "");
        vm.stopPrank();
    }

    function testSendAndReceiveERC20BetweenTwoSCAsWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC20BetweenTwoSCAsWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = ecdsaAccountFactory.getAddress(ownerAddr, "0x1");
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        vm.startPrank(ownerAddr);
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);

        // hacker
        vm.startPrank(vm.addr(123));
        vm.expectRevert(bytes("account: not EntryPoint or Owner"));
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
    }

    function testSendAndReceiveERC20FromSCAToEOAWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC20FromSCAToEOAWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = vm.addr(456);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        vm.startPrank(ownerAddr);
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);

        // hacker
        vm.startPrank(vm.addr(123));
        vm.expectRevert(bytes("account: not EntryPoint or Owner"));
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
    }

    function testTransferOwnershipWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testTransferOwnershipWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address recipient = vm.addr(456);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipient, 1000000);
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        vm.startPrank(ownerAddr);
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);

        // hacker
        vm.startPrank(vm.addr(123));
        vm.expectRevert(bytes("account: not EntryPoint or Owner"));
        senderAccount.execute(liquidityPoolSpenderAddr, 0, transferCallData);
        vm.stopPrank();
    }

    function testERC20AllowanceAndTransferFromWithRuntimeCall() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testERC20AllowanceAndTransferFromWithRuntimeCall");
        console.log(ownerAddr);
        ECDSAAccount senderAccount = ecdsaAccountFactory.createAccount(ownerAddr);
        address sender = address(senderAccount);
        // start with balance
        vm.deal(sender, 1 ether);
        testLiquidityPool.mint(sender, 2000000);
        address spenderOwnerAddr = makeAddr("testERC20AllowanceAndTransferFromWithRuntimeCall_spender");
        ECDSAAccount spenderAccount = ecdsaAccountFactory.createAccount(
            spenderOwnerAddr, 0x0000000000000000000000000000000000000000000000000000000000000001
        );
        address spender = address(spenderAccount);
        address recipient = ecdsaAccountFactory.getAddress(ownerAddr, "0x2");
        bytes memory approveCallData =
            abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), spender, 1000000);
        address erc20ContractAddr = address(testLiquidityPool);
        vm.startPrank(ownerAddr);
        senderAccount.execute(erc20ContractAddr, 0, approveCallData);
        vm.stopPrank();
        assertEq(testLiquidityPool.allowance(sender, spender), 1000000);
        bytes memory transferFromCallData = abi.encodeWithSelector(
            bytes4(keccak256("transferFrom(address,address,uint256)")), sender, recipient, 1000000
        );
        vm.startPrank(spenderOwnerAddr);
        spenderAccount.execute(erc20ContractAddr, 0, transferFromCallData);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipient), 1000000);
        assertEq(testLiquidityPool.allowance(sender, spender), 0);
    }
}
