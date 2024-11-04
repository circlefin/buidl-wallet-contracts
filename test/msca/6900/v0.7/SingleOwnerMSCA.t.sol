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

import {InvalidExecutionFunction} from "../../../../src/msca/6900/shared/common/Errors.sol";
import "../../../../src/msca/6900/v0.7/common/Structs.sol";
import "../../../../src/msca/6900/v0.7/factories/semi/SingleOwnerMSCAFactory.sol";
import "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import "../../../../src/utils/ExecutionUtils.sol";
import "../../../util/Mock1820Registry.sol";
import "../../../util/TestERC1155.sol";
import "../../../util/TestERC721.sol";
import "../../../util/TestERC777.sol";
import "../../../util/TestLiquidityPool.sol";
import "../../../util/TestUtils.sol";

import {TestTokenPlugin} from "./TestTokenPlugin.sol";

import {TestUserOpAllPassValidator} from "./TestUserOpAllPassValidator.sol";
import "./TestUserOpValidator.sol";
import "./TestUserOpValidatorHook.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "forge-std/src/console.sol";

contract SingleOwnerMSCATest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
    using ExecutionUtils for address;

    bytes32 private constant _TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");
    // upgrade

    event Upgraded(address indexed newImplementation);
    // erc721
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    // erc1155
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);
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

    error FailedOp(uint256 opIndex, string reason);

    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    // MSCA
    error WalletStorageIsInitialized();

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    address payable private beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestERC777 private testERC777;
    TestLiquidityPool private testLiquidityPool;
    SingleOwnerMSCAFactory private factory;
    IERC1820Registry private erc1820Registry;
    SingleOwnerPlugin private singleOwnerPlugin = new SingleOwnerPlugin();

    function setUp() public {
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        factory = new SingleOwnerMSCAFactory(address(entryPoint), address(pluginManager));
        // mock ERC1820Registry contract, could also use etch though, but I'm implementing a simplified registry
        erc1820Registry = new MockERC1820Registry();
        testERC777 = new TestERC777(erc1820Registry);
    }

    function testCreateSemiAccountFromEP() public {
        (address ownerAddr, uint256 eoaPrivateKey) = makeAddrAndKey("testCreateSemiAccountFromEP");
        createSemiAccount(ownerAddr, eoaPrivateKey);
    }

    // Since we don't have a multi-owner in place now, I'm using a single owner plugin for demonstration;
    // the expectation would be okay to install single owner plugin, however it's disabled because native owner
    // is enabled (only one validation is allowed).
    // In this test, owner1 is natively set, owner2 is installed via single owner plugin. In order to
    // complete a native transfer, we would need owner 1 to sign.
    function testCreateSemiAccountThenInstallSingleOwnerPluginThenDoNativeTransfer() public {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) =
            makeAddrAndKey("testCreateSemiAccountThenInstallSingleOwnerPluginThenDoNativeTransfer_native");
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        (address ownerInPluginAddr, uint256 ownerInPluginPrivateKey) =
            makeAddrAndKey("testCreateSemiAccountThenInstallSingleOwnerPluginThenDoNativeTransfer_plugin");
        installSingleOwnerPlugin(semiMSCA, nativeOwnerPrivateKey, ownerInPluginAddr);
        // use native owner private key
        sendNativeTokenFromRightOwner(semiMSCA, nativeOwnerPrivateKey);
        // attempt to use owner in plugin private key
        sendNativeTokenFromWrongOwner(semiMSCA, ownerInPluginPrivateKey);
    }

    // Install single owner plugin, renounce the native owner, then do a native transfer;
    // In this test, owner1 is natively set, owner2 is installed via single owner plugin, owner1 will be renounced.
    // In order to complete a native transfer, we would now need owner 2 to sign.
    function testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenDoNativeTransfer()
        public
    {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) = makeAddrAndKey(
            "testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenDoNativeTransfer_native"
        );
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        (address ownerInPluginAddr, uint256 ownerInPluginPrivateKey) = makeAddrAndKey(
            "testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenDoNativeTransfer_plugin"
        );
        installSingleOwnerPlugin(semiMSCA, nativeOwnerPrivateKey, ownerInPluginAddr);
        // renounce native ownership using native owner private key
        renounceNativeOwner(semiMSCA, nativeOwnerPrivateKey);
        // still use native owner private key
        sendNativeTokenFromWrongOwner(semiMSCA, nativeOwnerPrivateKey);
        // now use the owner in plugin key
        sendNativeTokenFromRightOwner(semiMSCA, ownerInPluginPrivateKey);
    }

    function testCreateSemiAccountWithNilOwner() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(0x0);
        vm.expectRevert(InvalidInitializationInput.selector);
        factory.createAccount(vm.addr(1), salt, initializingData);
    }

    // should be able to send/receive ERC1155 token
    function testSingleOwnerMSCACanSendAndReceiveERC1155Token() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address sendingOwnerAddr, uint256 sendingOwnerPrivateKey) =
            makeAddrAndKey("testSingleOwnerMSCACanSendAndReceiveERC1155Token_sender");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address senderAddr = address(sender);
        vm.deal(senderAddr, 1 ether);

        address receivingOwnerAddr = makeAddr("testSingleOwnerMSCACanSendAndReceiveERC1155Token_receiver");
        SingleOwnerMSCA recipient = factory.createAccount(receivingOwnerAddr, salt, initializingData);

        testERC1155.mint(senderAddr, 0, 2, "");
        address recipientAddr = address(recipient);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        // execute ERC1155 token contract
        bytes memory transferCallData = abi.encodeWithSelector(
            bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)")),
            senderAddr,
            recipientAddr,
            0,
            1,
            ""
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), address(testERC1155), 0, transferCallData
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, sendingOwnerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testERC1155.balanceOf(recipientAddr, 0), 1);
        assertEq(testERC1155.balanceOf(senderAddr, 0), 1);
    }

    // should be able to send/receive ERC721 token
    function testSingleOwnerMSCACanSendAndReceive721Token() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address sendingOwnerAddr, uint256 sendingOwnerPrivateKey) =
            makeAddrAndKey("testSingleOwnerMSCACanSendAndReceive721Token_sender");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address senderAddr = address(sender);
        vm.deal(senderAddr, 1 ether);

        address receivingOwnerAddr = makeAddr("testSingleOwnerMSCACanSendAndReceive721Token_receiver");
        SingleOwnerMSCA recipient = factory.createAccount(receivingOwnerAddr, salt, initializingData);

        testERC721.safeMint(senderAddr, 0);
        address recipientAddr = address(recipient);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        // execute ERC721 token contract
        bytes memory transferCallData = abi.encodeWithSelector(
            bytes4(keccak256("safeTransferFrom(address,address,uint256)")), senderAddr, recipientAddr, 0
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), address(testERC721), 0, transferCallData
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, sendingOwnerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testERC721.balanceOf(recipientAddr), 1);
        assertEq(testERC721.balanceOf(senderAddr), 0);
    }

    function testTransferOwnershipWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testTransferOwnershipWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address newOwner = vm.addr(123);
        vm.startPrank(sendingOwnerAddr);
        sender.transferNativeOwnership(newOwner);
        vm.stopPrank();
        assertEq(sender.getNativeOwner(), newOwner);

        // still use old owner to call
        // it fails at onlyFromEntryPointOrOwnerOrSelf,
        // and it would be the same in validateNativeFunction
        vm.startPrank(sendingOwnerAddr);
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.transferNativeOwnership(sendingOwnerAddr);
        vm.stopPrank();
    }

    function testRenounceOwnershipWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testRenounceOwnershipWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);

        // use a random owner to call
        // it fails at onlyFromEntryPointOrOwnerOrSelf,
        // and it would be the same in validateNativeFunction
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.renounceNativeOwnership();
        vm.stopPrank();

        vm.startPrank(sendingOwnerAddr);
        vm.expectRevert(SingleOwnerMSCA.NoOwnershipPluginDefined.selector);
        sender.renounceNativeOwnership();
        vm.stopPrank();

        // install singleOwnerPlugin before renounceNativeOwner
        address ownerInPlugin = makeAddr("testRenounceOwnershipWithRuntimeValidation_ownerInPlugin");
        vm.startPrank(sendingOwnerAddr);
        bytes32 manifest = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        sender.installPlugin(
            address(singleOwnerPlugin), manifest, abi.encode(ownerInPlugin), new FunctionReference[](0)
        );
        sender.renounceNativeOwnership();
        assertEq(sender.getNativeOwner(), address(0));
    }

    function testUpgradeWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testUpgradeWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        SingleOwnerMSCA newImpl = new SingleOwnerMSCA(entryPoint, pluginManager);

        // call from owner
        vm.startPrank(sendingOwnerAddr);
        sender.upgradeToAndCall(address(newImpl), "");
        vm.stopPrank();

        // use a random owner to call
        // it fails at _processPreRuntimeHooksAndValidation
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.upgradeToAndCall(address(newImpl), "");
        vm.stopPrank();
    }

    function testExecuteWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testExecuteWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address recipient = vm.addr(456);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        sender.execute(recipient, 111, "");
        vm.stopPrank();
        assertEq(recipient.balance, 111);

        // use a random owner to call
        // it fails at _processPreRuntimeHooksAndValidation
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.execute(recipient, 222, "");
        vm.stopPrank();
    }

    function testExecuteBatchWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testExecuteBatchWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address recipient = vm.addr(456);
        vm.deal(address(sender), 1 ether);
        Call[] memory calls = new Call[](1);
        calls[0].target = recipient;
        calls[0].value = 111;
        calls[0].data = "";
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        sender.executeBatch(calls);
        vm.stopPrank();
        assertEq(recipient.balance, 111);

        // use a random owner to call
        // it fails at _processPreRuntimeHooksAndValidation
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.executeBatch(calls);
        vm.stopPrank();
    }

    function testInstallPluginWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testInstallPluginWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        assertEq(sender.getInstalledPlugins().length, 0);
        vm.deal(address(sender), 1 ether);
        TestUserOpAllPassValidator testPlugin = new TestUserOpAllPassValidator();
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        bytes32 manifest = keccak256(abi.encode(testPlugin.pluginManifest()));
        FunctionReference[] memory emptyFR = new FunctionReference[](0);
        sender.installPlugin(address(testPlugin), manifest, "", emptyFR);
        vm.stopPrank();
        address[] memory installedPlugins = sender.getInstalledPlugins();
        assertEq(installedPlugins[0], address(testPlugin));

        // use a random owner to call
        // it fails at _processPreRuntimeHooksAndValidation
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.installPlugin(address(testPlugin), manifest, "", emptyFR);
        vm.stopPrank();
    }

    function testUninstallPluginWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testUninstallPluginWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        assertEq(sender.getInstalledPlugins().length, 0);
        vm.deal(address(sender), 1 ether);
        TestUserOpAllPassValidator testPlugin = new TestUserOpAllPassValidator();
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        bytes32 manifest = keccak256(abi.encode(testPlugin.pluginManifest()));
        FunctionReference[] memory emptyFR = new FunctionReference[](0);
        sender.installPlugin(address(testPlugin), manifest, "", emptyFR);
        address[] memory installedPlugins = sender.getInstalledPlugins();
        assertEq(installedPlugins[0], address(testPlugin));
        // now uninstall
        sender.uninstallPlugin(address(testPlugin), "", "");
        assertEq(sender.getInstalledPlugins().length, 0);
        vm.stopPrank();

        // use a random owner to call
        // it fails at _processPreRuntimeHooksAndValidation
        vm.startPrank(vm.addr(123));
        vm.expectRevert(UnauthorizedCaller.selector);
        sender.installPlugin(address(testPlugin), manifest, "", emptyFR);
        vm.stopPrank();
    }

    function testExecuteFromPluginWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testExecuteFromPluginWithRuntimeValidation");
        address ownerInPlugin = makeAddr("testExecuteFromPluginWithRuntimeValidation_ownerInPlugin");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        assertEq(sender.getInstalledPlugins().length, 0);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        bytes32 manifest = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        FunctionReference[] memory emptyFR = new FunctionReference[](0);
        sender.installPlugin(address(singleOwnerPlugin), manifest, abi.encode(ownerInPlugin), emptyFR);
        TestTokenPlugin testTokenPlugin = new TestTokenPlugin();
        manifest = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        sender.installPlugin(address(testTokenPlugin), manifest, abi.encode(1000), dependencies);
        vm.stopPrank();

        // now call executeFromPlugin
        vm.startPrank(address(sender));
        address owner = testTokenPlugin.airdropToken(123);
        assertEq(owner, ownerInPlugin);
        vm.stopPrank();

        // use a random owner to call
        // random address doesn't have executeFromPlugin installed at all
        vm.startPrank(vm.addr(123));
        vm.expectRevert();
        testTokenPlugin.airdropToken(123);
        vm.stopPrank();
    }

    function testExecuteFromPluginExternalWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testExecuteFromPluginExternalWithRuntimeValidation");
        address ownerInPlugin = makeAddr("testExecuteFromPluginExternalWithRuntimeValidation_ownerInPlugin");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        assertEq(sender.getInstalledPlugins().length, 0);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        bytes32 manifest = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        FunctionReference[] memory emptyFR = new FunctionReference[](0);
        sender.installPlugin(address(singleOwnerPlugin), manifest, abi.encode(ownerInPlugin), emptyFR);
        TestTokenPlugin testTokenPlugin = new TestTokenPlugin();
        manifest = keccak256(abi.encode(testTokenPlugin.pluginManifest()));
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        // import SingleOwnerPlugin as dependency
        dependencies[0] =
            FunctionReference(address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER));
        sender.installPlugin(address(testTokenPlugin), manifest, abi.encode(1000), dependencies);
        vm.stopPrank();

        // now call executeFromPluginExternal
        vm.startPrank(address(sender));
        assertTrue(testTokenPlugin.mintToken(123));
        vm.stopPrank();

        // use a random owner to call
        // random address doesn't have executeFromPlugin installed at all
        vm.startPrank(vm.addr(123));
        vm.expectRevert();
        testTokenPlugin.mintToken(123);
        vm.stopPrank();
    }

    function testGetExecutionFunctionConfigWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testGetExecutionFunctionConfigWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        ExecutionFunctionConfig memory executionFunctionConfig =
            sender.getExecutionFunctionConfig(IERC721Receiver.onERC721Received.selector);
        assertEq(executionFunctionConfig.plugin, address(sender));
        vm.stopPrank();

        // okay to use a random address to view
        vm.startPrank(vm.addr(123));
        executionFunctionConfig = sender.getExecutionFunctionConfig(IERC721Receiver.onERC721Received.selector);
        assertEq(executionFunctionConfig.plugin, address(sender));
        vm.stopPrank();
    }

    function testGetExecutionHooksWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testGetExecutionHooksWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        ExecutionHooks[] memory executionHooks = sender.getExecutionHooks(IERC721Receiver.onERC721Received.selector);
        assertEq(executionHooks.length, 0);
        vm.stopPrank();

        // okay to use a random address to view
        vm.startPrank(vm.addr(123));
        executionHooks = sender.getExecutionHooks(IERC721Receiver.onERC721Received.selector);
        assertEq(executionHooks.length, 0);
        vm.stopPrank();
    }

    function testGetPreValidationHooksWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testGetPreValidationHooksWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        vm.deal(address(sender), 1 ether);
        // call from owner
        vm.startPrank(sendingOwnerAddr);
        (FunctionReference[] memory preUserOpValidationHooks, FunctionReference[] memory preRuntimeValidationHooks) =
            sender.getPreValidationHooks(IERC721Receiver.onERC721Received.selector);
        assertEq(preUserOpValidationHooks.length, 0);
        assertEq(preRuntimeValidationHooks.length, 0);
        vm.stopPrank();

        // okay to use a random address to view
        vm.startPrank(vm.addr(123));
        (preUserOpValidationHooks, preRuntimeValidationHooks) =
            sender.getPreValidationHooks(IERC721Receiver.onERC721Received.selector);
        assertEq(preUserOpValidationHooks.length, 0);
        assertEq(preRuntimeValidationHooks.length, 0);
        vm.stopPrank();
    }

    function testInitializeSingleOwnerMSCAWithRuntimeValidation() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testGetPreValidationHooksWithRuntimeValidation");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        vm.deal(address(sender), 1 ether);
        // init from owner again
        vm.startPrank(sendingOwnerAddr);
        vm.expectRevert(WalletStorageIsInitialized.selector);
        sender.initializeSingleOwnerMSCA(sendingOwnerAddr);
        vm.stopPrank();
    }

    function testVerify1271SignatureForSingleOwnerMSCA() public {
        (address sendingOwnerAddr, uint256 sendingOwnerPrivateKey) = makeAddrAndKey("testERC1271");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA account = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        bytes32 hash = bytes32(keccak256("testVerify1271SignatureForSingleOwnerMSCA"));
        bytes32 replaySafeHash = account.getReplaySafeMessageHash(hash);
        bytes memory signature = signMessage(vm, sendingOwnerPrivateKey, replaySafeHash);
        assertEq(EIP1271_VALID_SIGNATURE, account.isValidSignature(hash, signature));

        // sign a hash with a random key
        (, uint256 randomPrivateKey) = makeAddrAndKey("random");
        signature = signMessage(vm, randomPrivateKey, replaySafeHash);
        assertEq(EIP1271_INVALID_SIGNATURE, account.isValidSignature(hash, signature));
    }

    /// single owner plugin is not activated
    function testCreateSemiAccountThenInstallSingleOwnerPluginThenVerify1271Signature() public {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) =
            makeAddrAndKey("testCreateSemiAccountThenInstallSingleOwnerPluginThenVerify1271Signature_native");
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        SingleOwnerMSCA account = SingleOwnerMSCA(payable(semiMSCA));
        (address ownerInPluginAddr, uint256 ownerInPluginPrivateKey) =
            makeAddrAndKey("testCreateSemiAccountThenInstallSingleOwnerPluginThenVerify1271Signature_plugin");
        installSingleOwnerPlugin(semiMSCA, nativeOwnerPrivateKey, ownerInPluginAddr);

        bytes32 hash = bytes32(keccak256("testCreateSemiAccountThenInstallSingleOwnerPluginThenVerify1271Signature"));
        bytes32 replaySafeHash = account.getReplaySafeMessageHash(hash);
        bytes memory signature = signMessage(vm, nativeOwnerPrivateKey, replaySafeHash);
        assertEq(EIP1271_VALID_SIGNATURE, account.isValidSignature(hash, signature));

        // would not work because the plugin is not activated yet
        signature = signMessage(vm, ownerInPluginPrivateKey, replaySafeHash);
        assertEq(EIP1271_INVALID_SIGNATURE, account.isValidSignature(hash, signature));
    }

    function testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenVerify1271Signature()
        public
    {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) = makeAddrAndKey(
            "testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenVerify1271Signature_native"
        );
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        SingleOwnerMSCA account = SingleOwnerMSCA(payable(semiMSCA));
        (address ownerInPluginAddr, uint256 ownerInPluginPrivateKey) = makeAddrAndKey(
            "testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenVerify1271Signature_plugin"
        );
        installSingleOwnerPlugin(semiMSCA, nativeOwnerPrivateKey, ownerInPluginAddr);
        // renounce native ownership using native owner private key
        renounceNativeOwner(semiMSCA, nativeOwnerPrivateKey);

        bytes32 hash = bytes32(
            keccak256(
                "testCreateSemiAccountThenInstallSingleOwnerPluginThenRenounceNativeOwnershipThenVerify1271Signature"
            )
        );
        bytes32 replaySafeHash = singleOwnerPlugin.getReplaySafeMessageHash(semiMSCA, hash);
        bytes memory signature = signMessage(vm, ownerInPluginPrivateKey, replaySafeHash);
        assertEq(EIP1271_VALID_SIGNATURE, account.isValidSignature(hash, signature));

        // would not work because the plugin has already been activated
        signature = signMessage(vm, nativeOwnerPrivateKey, replaySafeHash);
        assertEq(EIP1271_INVALID_SIGNATURE, account.isValidSignature(hash, signature));

        // would not work because we need the replaySafeHash from plugin instead of account
        replaySafeHash = account.getReplaySafeMessageHash(hash);
        signature = signMessage(vm, nativeOwnerPrivateKey, replaySafeHash);
        assertEq(EIP1271_INVALID_SIGNATURE, account.isValidSignature(hash, signature));
    }

    function testSigningFromWrongOwner() public {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) = makeAddrAndKey("testSigningFromWrongOwner_native");
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        (, uint256 randomOwnerPrivateKey) = makeAddrAndKey("testSigningFromWrongOwner_random");
        // attempt to use random owner private key, should not work and fail on "AA24 signature error"
        address recipientAddr = makeAddr("sendNativeTokenFromWrongOwner");
        vm.deal(semiMSCA, 1 ether);

        uint256 acctNonce = entryPoint.getNonce(semiMSCA, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipientAddr, 100000000000, "0x"
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            semiMSCA,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, randomOwnerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        bytes4 errorSelector = bytes4(keccak256("FailedOp(uint256,string)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    // should revert because MSCA doesn't know about the ERC20 transfer function selector
    function testCallERC20TransferFunctionDirectlyFromRuntime() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        address sendingOwnerAddr = makeAddr("testCallERC20TransferFunctionDirectly");
        bytes memory initializingData = abi.encode(sendingOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(sendingOwnerAddr, salt, initializingData);
        address recipient = vm.addr(456);
        vm.deal(address(sender), 1 ether);
        testLiquidityPool.mint(address(sender), 10);
        bytes memory data = abi.encodeCall(testLiquidityPool.transfer, (recipient, 2));
        vm.startPrank(sendingOwnerAddr);
        bytes memory revertReason =
            abi.encodeWithSelector(InvalidExecutionFunction.selector, testLiquidityPool.transfer.selector);
        vm.expectRevert(revertReason);
        address(sender).callWithReturnDataOrRevert(0, data);
        vm.stopPrank();
        assertEq(testLiquidityPool.balanceOf(recipient), 0);
    }

    // should revert because MSCA doesn't know about the ERC20 transfer function selector
    function testCallERC20TransferFunctionDirectlyFromUserOp() public {
        (address ownerAddr, uint256 eoaPrivateKey) = makeAddrAndKey("testCallERC20TransferFunctionDirectlyFromUserOp");
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory initializingData = abi.encode(ownerAddr);
        SingleOwnerMSCA sender = factory.createAccount(ownerAddr, salt, initializingData);
        address senderAddr = address(sender);
        assertTrue(senderAddr.code.length != 0);
        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        // start with balance
        vm.deal(senderAddr, 1 ether);
        testLiquidityPool.mint(senderAddr, 2000000);
        address recipient = address(0x9005Be081B8EC2A31258878409E88675Cd791376);
        // execute ERC20 token contract directly
        bytes memory tokenTransferCallData = abi.encodeCall(testLiquidityPool.transfer, (recipient, 1000000));
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(tokenTransferCallData),
            83353,
            1028650,
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
        vm.startPrank(address(entryPoint));
        bytes memory revertReason =
            abi.encodeWithSelector(InvalidExecutionFunction.selector, testLiquidityPool.transfer.selector);
        vm.expectEmit(true, true, true, true);
        emit UserOperationRevertReason(userOpHash, senderAddr, acctNonce, revertReason);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(testLiquidityPool.balanceOf(recipient), 0);
        vm.stopPrank();
    }

    // should be able to receive ERC777 token after registration with 1820 global registry
    function testSingleOwnerMSCACanReceive777Token() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address senderOwnerAddr,) = makeAddrAndKey("testSingleOwnerMSCACanReceive777Token_sender");
        bytes memory initializingData = abi.encode(senderOwnerAddr);
        SingleOwnerMSCA sender = factory.createAccount(senderOwnerAddr, salt, initializingData);

        address receivingOwnerAddr = makeAddr("testSingleOwnerMSCACanReceive777Token_receiver");
        SingleOwnerMSCA recipient = factory.createAccount(receivingOwnerAddr, salt, initializingData);

        testERC777.mint(address(sender), 11);
        address recipientAddr = address(recipient);
        Call[] memory calls = new Call[](1);
        calls[0].target = address(erc1820Registry);
        calls[0].value = 0;
        calls[0].data = abi.encodeCall(
            IERC1820Registry.setInterfaceImplementer, (recipientAddr, _TOKENS_RECIPIENT_INTERFACE_HASH, recipientAddr)
        );
        vm.startPrank(recipientAddr);
        recipient.executeBatch(calls);
        vm.stopPrank();

        vm.startPrank(address(sender));
        calls[0].target = address(testERC777);
        calls[0].value = 0;
        calls[0].data = abi.encodeCall(testERC777.send, (recipientAddr, 9, ""));
        sender.executeBatch(calls);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testERC777.balanceOf(recipientAddr), 9);
        assertEq(testERC777.balanceOf(address(sender)), 2);
    }

    function testTransferWithEmptyValidation() public {
        (address nativeOwnerAddr, uint256 nativeOwnerPrivateKey) =
            makeAddrAndKey("testTransferWithEmptyValidation_native");
        address semiMSCA = createSemiAccount(nativeOwnerAddr, nativeOwnerPrivateKey);
        (address ownerInPluginAddr,) = makeAddrAndKey("testTransferWithEmptyValidation_plugin");
        installSingleOwnerPlugin(semiMSCA, nativeOwnerPrivateKey, ownerInPluginAddr);
        // renounce native ownership using native owner private key
        renounceNativeOwner(semiMSCA, nativeOwnerPrivateKey);

        // fail on empty validation
        bytes memory executeBadCallData =
            abi.encodeWithSelector(bytes4(keccak256("executeBad(address,uint256,bytes)")), vm.addr(1), 1, "0x");
        vm.startPrank(address(semiMSCA));
        vm.expectRevert(abi.encodeWithSelector(InvalidValidationFunctionId.selector, 0));
        address(semiMSCA).callWithReturnDataOrRevert(0, executeBadCallData);
        vm.stopPrank();
    }

    function createSemiAccount(address ownerAddr, uint256 eoaPrivateKey) internal returns (address) {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        bytes memory initializingData = abi.encode(ownerAddr);
        (address sender,) = factory.getAddress(ownerAddr, salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 100 ether);
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (address(0), 0, ""));
        bytes memory createAccountCall =
            abi.encodeCall(SingleOwnerMSCAFactory.createAccount, (ownerAddr, salt, initializingData));
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            acctNonce,
            vm.toString(initCode),
            vm.toString(executeCallData),
            83353000,
            10286500,
            454840,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        // verify the account has been deployed
        assertTrue(sender.code.length > 0);
        vm.stopPrank();
        return sender;
    }

    function installSingleOwnerPlugin(address semiMSCA, uint256 ownerPrivateKey, address ownerInPlugin) internal {
        bytes32 manifestHash = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(semiMSCA, 0);
        FunctionReference[] memory dependencies = new FunctionReference[](0);
        bytes memory installPluginCallData = abi.encodeCall(
            IPluginManager.installPlugin,
            (address(singleOwnerPlugin), manifestHash, abi.encode(ownerInPlugin), dependencies)
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            semiMSCA,
            acctNonce,
            "0x",
            vm.toString(installPluginCallData),
            83353000,
            10286500,
            454840,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, semiMSCA, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(singleOwnerPlugin.getOwnerOf(semiMSCA), address(ownerInPlugin));
        vm.stopPrank();
    }

    function sendNativeTokenFromRightOwner(address senderAddr, uint256 senderPrivateKey) internal {
        address recipientAddr = makeAddr("sendNativeTokenFromRightOwner");
        vm.deal(senderAddr, 1 ether);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipientAddr, 100000000000, "0x"
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, senderPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 100000000000);
    }

    function sendNativeTokenFromWrongOwner(address senderAddr, uint256 senderPrivateKey) internal {
        address recipientAddr = makeAddr("sendNativeTokenFromWrongOwner");
        vm.deal(senderAddr, 1 ether);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipientAddr, 100000000000, "0x"
        );
        PackedUserOperation memory userOp = buildPartialUserOp(
            senderAddr,
            acctNonce,
            "0x",
            vm.toString(executeCallData),
            83353,
            1028650,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, senderPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function renounceNativeOwner(address semiMSCA, uint256 ownerPrivateKey) internal {
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(semiMSCA, 0);
        bytes memory renounceOwnerCallData = abi.encodeCall(SingleOwnerMSCA.renounceNativeOwnership, ());
        PackedUserOperation memory userOp = buildPartialUserOp(
            semiMSCA,
            acctNonce,
            "0x",
            vm.toString(renounceOwnerCallData),
            83353000,
            10286500,
            454840,
            516219199704,
            1130000000,
            "0x"
        ); // no paymaster

        bytes memory signature = signUserOpHash(entryPoint, vm, ownerPrivateKey, userOp);
        userOp.signature = signature;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        assertEq(SingleOwnerMSCA(payable(semiMSCA)).getNativeOwner(), address(0));
        vm.stopPrank();
    }

    /**
     * @dev Unpack into the deserialized packed format from validAfter | validUntil | authorizer.
     */
    function _unpackValidationData(uint256 validationDataInt)
        internal
        pure
        returns (ValidationData memory validationData)
    {
        address authorizer = address(uint160(validationDataInt));
        uint48 validUntil = uint48(validationDataInt >> 160);
        if (validUntil == 0) {
            validUntil = type(uint48).max;
        }
        uint48 validAfter = uint48(validationDataInt >> (48 + 160));
        return ValidationData(validAfter, validUntil, authorizer);
    }
}
