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

/* solhint-disable max-states-count */

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    EMPTY_MODULE_ENTITY,
    SIG_VALIDATION_SUCCEEDED
} from "../../../../src/common/Constants.sol";

import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";

import {BaseMSCA} from "../../../../src/msca/6900/v0.8/account/BaseMSCA.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction,
    ManifestExecutionHook
} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";

import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {ModuleEntity, ValidationConfig} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {Call, IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";
import {TestERC1155} from "../../../util/TestERC1155.sol";
import {TestERC721} from "../../../util/TestERC721.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {ValidationDataView} from "@erc6900/reference-implementation/interfaces/IModularAccountView.sol";

import {MockModule} from "./helpers/MockModule.sol";
import {IAccountExecute} from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// We use UpgradableMSCA (that inherits from UpgradableMSCA) because it has some convenience functions
contract UpgradableMSCATest is AccountTestUtils {
    using ModuleEntityLib for bytes21;
    using ModuleEntityLib for ModuleEntity;
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
    event ReceivedCall(bytes msgData);

    error RuntimeValidationFailed(address module, uint32 entityId, bytes revertReason);

    IEntryPoint private entryPoint = new EntryPoint();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testLiquidityPool;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    UpgradableMSCAFactory private factory;
    ModuleEntity private ownerValidation;
    uint256 internal eoaPrivateKey2;
    address private ownerAddr2;
    SingleSignerValidationModule private singleSignerValidationModule2;
    ModuleEntity private owner2Validation;
    bytes32 internal salt = bytes32(0);

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        factory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();
        singleSignerValidationModule2 = new SingleSignerValidationModule();
        address[] memory _modules = new address[](2);
        _modules[0] = address(singleSignerValidationModule);
        _modules[1] = address(singleSignerValidationModule2);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setModules(_modules, _permissions);
        factory.setModules(_modules, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        owner2Validation = ModuleEntityLib.pack(address(singleSignerValidationModule2), uint32(0));
    }

    function testInvalidCalldataLength() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testInvalidCalldataLength");
        UpgradableMSCA msca = new UpgradableMSCA(entryPoint);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            28,
            "0x",
            "0x12",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake sig
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, false);
        bytes4 selector = bytes4(keccak256("InvalidCalldataLength(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 1, 4));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testNotFoundFunctionSelector() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testNotFoundFunctionSelector");
        UpgradableMSCA msca = new UpgradableMSCA(entryPoint);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            28,
            "0x",
            "0x0000000012",
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, false);
        bytes4 selector = bytes4(keccak256("NotFoundSelector()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testEmptyUserOpValidationFunction() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testEmptyUserOpValidationFunction");
        UpgradableMSCA msca = new UpgradableMSCA(entryPoint);
        // functionSelector: 0xb61d27f6
        // FunctionReference userOpValidator is not configured
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            28,
            "0x",
            "0xb61d27f600000000000000000000000007865c6e87b9f70255377e024ace6630c1eaa37f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000009005be081b8ec2a31258878409e88675cd79137600000000000000000000000000000000000000000000000000000000001e848000000000000000000000000000000000000000000000000000000000",
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            // fake sig
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature =
            encodeSignature(new PreValidationHookData[](0), ModuleEntity.wrap(EMPTY_MODULE_ENTITY), signature, false);
        // empty module entity
        vm.expectRevert(abi.encodeWithSelector(BaseMSCA.InvalidModuleEntity.selector, uint32(0)));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testUpgradeMSCA() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUpgradeMSCA");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        vm.startPrank(address(entryPoint));
        UpgradableMSCA implMSCA = new UpgradableMSCA(IEntryPoint(vm.addr(123)));
        address v2ImplAddr = address(implMSCA);
        emit Upgraded(v2ImplAddr);
        // call upgradeTo from proxy
        msca.upgradeToAndCall(v2ImplAddr, "");
        vm.stopPrank();

        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        implMSCA.upgradeToAndCall(v2ImplAddr, "");
    }

    function testEncodeAndHashExecutionManifest() public pure {
        ExecutionManifest memory manifest;
        bytes4[] memory dependencyInterfaceIds = new bytes4[](1);
        dependencyInterfaceIds[0] = bytes4(0x12345678);
        string[] memory guardingPermissions = new string[](1);
        guardingPermissions[0] = "permissions";
        bytes4[] memory executionFunctions = new bytes4[](1);
        executionFunctions[0] = 0x12345678;
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = bytes4(0x12345678);
        ManifestExecutionHook[] memory executionHooks = new ManifestExecutionHook[](1);
        executionHooks[0] = ManifestExecutionHook(bytes4(0x12345678), 0, true, true);
        manifest.executionHooks = executionHooks;
        assertEq(abi.encode(manifest).length, 352);
        assertEq(keccak256(abi.encode(manifest)).length, 32);
    }

    function testSendAndReceiveNativeTokenWithoutAnyACLModule() public {
        (address randomSenderSeedAddr, uint256 senderPrivateKey) =
            makeAddrAndKey("testSendAndReceiveNativeTokenWithoutAnyACLModule_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData = abi.encode(
            validationConfig, new bytes4[](0), abi.encode(uint32(0), randomSenderSeedAddr), bytes(""), bytes("")
        );
        UpgradableMSCA sender = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        address senderAddr = address(sender);
        bytes[] memory empty = new bytes[](0);
        vm.startPrank(senderAddr);
        // remove ownership module
        sender.uninstallValidation(ownerValidation, abi.encode(uint32(0)), empty);
        vm.stopPrank();

        (address recipientAddr,) =
            factory.getAddressWithValidation(addressToBytes32(vm.addr(1)), salt, initializingData);
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

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, senderPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidValidationFunction.selector,
                bytes4(keccak256("execute(address,uint256,bytes)")),
                ownerValidation
            )
        );
        sender.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function testSendAndReceiveNativeTokenWithSingleSignerValidationModule() public {
        (ownerAddr, eoaPrivateKey) =
            makeAddrAndKey("testSendAndReceiveNativeTokenWithSingleSignerValidationModule_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address recipientAddr,) =
            factory.getAddressWithValidation(addressToBytes32(vm.addr(1)), salt, initializingData);
        vm.deal(senderAddr, 1 ether);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), recipientAddr, 10000000000000000, "0x"
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

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 10000000000000000);
        // 1 - 0.01 = 0.99 and also need to pay for the gas fee
        assertLt(senderAddr.balance, 0.99 ether);
    }

    // should be able to send & receive ERC20 token even w/o token callback handler
    function testSendAndReceiveERC20TokenWithoutDefaultCallbackHandler() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC20TokenWithoutDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // recipient account doesn't have the token callback
        (address recipientAddr,) =
            factory.getAddressWithValidation(addressToBytes32(vm.addr(1)), salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testLiquidityPool.mint(senderAddr, 2000000);

        uint256 acctNonce = entryPoint.getNonce(senderAddr, 0);
        // execute ERC20 token contract
        address liquidityPoolSpenderAddr = address(testLiquidityPool);
        bytes memory transferCallData =
            abi.encodeWithSelector(bytes4(keccak256("transfer(address,uint256)")), recipientAddr, 1000000);
        bytes memory executeCallData = abi.encodeWithSelector(
            bytes4(keccak256("execute(address,uint256,bytes)")), liquidityPoolSpenderAddr, 0, transferCallData
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

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testLiquidityPool.balanceOf(recipientAddr), 1000000);
        assertEq(testLiquidityPool.balanceOf(senderAddr), 1000000);
    }

    // should be able to receive ERC1155 token with token callback enshrined
    function testSendAndReceiveERC1155TokenNatively() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenNatively_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC1155.mint(senderAddr, 0, 2, "");
        assertEq(testERC1155.balanceOf(senderAddr, 0), 2);
    }

    // should not be able to receive ERC721 token with token callback enshrined
    function testSendAndReceiveERC721TokenNatively() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenNatively_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC721.safeMint(senderAddr, 0);
        assertEq(testERC721.balanceOf(senderAddr), 1);
    }

    // should be able to send/receive ERC1155 token with token callback handler
    function testSendAndReceiveERC1155TokenWithDefaultCallbackHandler() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenWithDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        address senderAddr = address(msca);
        // recipient account has the token callback installed
        UpgradableMSCA recipient =
            factory.createAccountWithValidation(addressToBytes32(vm.addr(1)), salt, initializingData);
        vm.deal(senderAddr, 1 ether);
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

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testERC1155.balanceOf(recipientAddr, 0), 1);
        assertEq(testERC1155.balanceOf(senderAddr, 0), 1);
    }

    // should be able to send/receive ERC721 token with token callback handler
    function testSendAndReceiveERC721TokenWithDefaultCallbackHandler() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenWithDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // recipient account has the token callback installed
        UpgradableMSCA recipient =
            factory.createAccountWithValidation(addressToBytes32(vm.addr(1)), salt, initializingData);
        vm.deal(senderAddr, 1 ether);
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

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        vm.stopPrank();
        // verify destination address balance
        assertEq(testERC721.balanceOf(recipientAddr), 1);
        assertEq(testERC721.balanceOf(senderAddr), 0);
    }

    // should be able to depositTo/withdrawDepositTo/getDeposit
    function testDepositAndWithdrawWithEP() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDepositAndWithdrawWithEP");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA sender = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        vm.deal(address(sender), 1 ether);
        vm.startPrank(address(sender));
        sender.addDeposit{value: 100}();

        (address randomAddr,) = makeAddrAndKey("randomAddr");
        assertEq(sender.getDeposit(), 100);
        sender.withdrawDepositTo(payable(randomAddr), 1);
        assertEq(sender.getDeposit(), 99);
        assertEq(randomAddr.balance, 1);
        vm.stopPrank();

        // only the account itself or userOp from EP can withdraw
        vm.startPrank(randomAddr);
        bytes4 errorSelector = bytes4(keccak256("UnauthorizedCaller()"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector));
        sender.withdrawDepositTo(payable(randomAddr), 1);
        vm.stopPrank();
    }

    function testCreateAccountFromEP() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testCreateAccountFromEP");

        // only get address w/o deployment
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        (address sender,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 100 ether);
        bytes memory executeCallData = abi.encodeCall(IModularAccount.execute, (address(0), 0, ""));
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
            83353000,
            10286500,
            454840,
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
        vm.stopPrank();
    }

    function testIsValidSignature() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testIsValidSignature");
        ExecutionManifest memory execManifest;
        MockModule mockModule = new MockModule(
            execManifest, SIG_VALIDATION_SUCCEEDED, true, true, bytes(""), true, SIG_VALIDATION_SUCCEEDED, true
        );
        bool[] memory permissions = new bool[](1);
        address[] memory modulesAddr = new address[](1);
        permissions[0] = true;
        modulesAddr[0] = address(mockModule);
        vm.prank(factoryOwner);
        factory.setModules(modulesAddr, permissions);
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(HookConfigLib.packValidationHook(address(mockModule), uint32(0)), "");
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), hooks);
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // raw message hash
        bytes memory rawMessage = abi.encodePacked("circle internet");
        bytes32 messageHash = keccak256(rawMessage);
        bytes32 replaySafeMessageHash =
            singleSignerValidationModule.getReplaySafeMessageHash(address(msca), messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, replaySafeMessageHash);
        // valid signature
        bytes memory signature =
            encode1271Signature(new PreValidationHookData[](0), ownerValidation, abi.encodePacked(r, s, v));
        assertEq(msca.isValidSignature(messageHash, signature), bytes4(EIP1271_VALID_SIGNATURE));

        // valid signature with pre hook
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        // FLAG_TO_PASS == 0
        preValidationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encode(uint8(0))});
        signature = encode1271Signature(preValidationHookData, ownerValidation, abi.encodePacked(r, s, v));
        assertEq(msca.isValidSignature(messageHash, signature), bytes4(EIP1271_VALID_SIGNATURE));

        // invalid signature
        signature =
            encode1271Signature(new PreValidationHookData[](0), ownerValidation, abi.encodePacked(r, s, uint32(0)));
        assertEq(msca.isValidSignature(messageHash, signature), bytes4(EIP1271_INVALID_SIGNATURE));

        // invalid validation module
        signature = encode1271Signature(
            new PreValidationHookData[](0), ModuleEntityLib.pack(address(0), uint32(0)), abi.encodePacked(r, s, v)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidSignatureValidation.selector, ModuleEntityLib.pack(address(0), uint32(0))
            )
        );
        msca.isValidSignature(messageHash, signature);

        // valid signature with pre hook fail entity id
        preValidationHookData = new PreValidationHookData[](1);
        // FLAG_TO_PASS == 0, so this is going to revert
        preValidationHookData[0] = PreValidationHookData({index: 0, hookData: abi.encode(uint8(1))});
        signature = encode1271Signature(preValidationHookData, ownerValidation, abi.encodePacked(r, s, v));
        vm.expectRevert(abi.encodeWithSelector(MockModule.PreSignatureValidationHookFailed.selector));
        msca.isValidSignature(messageHash, signature);
    }

    ///
    /// isSignatureValidation
    ///
    function testFalseSignatureValidationFlag() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testFalseSignatureValidationFlag");
        // isSignatureValidation == false
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, false, true);
        bytes[] memory hooks = new bytes[](0);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), hooks);
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // raw message hash
        bytes memory rawMessage = abi.encodePacked("circle internet");
        bytes32 messageHash = keccak256(rawMessage);
        bytes32 replaySafeMessageHash =
            singleSignerValidationModule.getReplaySafeMessageHash(address(msca), messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, replaySafeMessageHash);
        // valid signature but with false isSignatureValidation
        bytes memory signature =
            encode1271Signature(new PreValidationHookData[](0), ownerValidation, abi.encodePacked(r, s, v));
        vm.expectRevert(abi.encodeWithSelector(BaseMSCA.InvalidSignatureValidation.selector, ownerValidation));
        msca.isValidSignature(messageHash, signature);
    }

    ///
    /// isUserOpValidation
    ///
    function testFalseUserOpValidationFlag() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testFalseUserOpValidationFlag");
        // isUserOpValidation == false
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, false);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(address(msca), 0);
        // start with balance
        vm.deal(address(msca), 1 ether);
        address recipient = makeAddr("testFalseSignatureValidationFlag_recipient");
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            "0x",
            vm.toString(abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""))),
            83353000,
            10286500,
            0,
            1,
            1,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(BaseMSCA.InvalidUserOpValidation.selector, ownerValidation)
            )
        );
        entryPoint.handleOps(ops, beneficiary);
        assertEq(recipient.balance, 0 wei);
        vm.stopPrank();

        // runtime call should work
        vm.startPrank(ownerAddr);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, "")),
            encodeSignature(new PreValidationHookData[](0), ownerValidation, "", true)
        );
        assertEq(recipient.balance, 1 wei);
        vm.stopPrank();
    }

    ///
    /// multi validation
    ///
    function testOverlappingValidationInstall() public {
        (ownerAddr,) = makeAddrAndKey("testOverlappingValidationInstall");
        (ownerAddr2,) = makeAddrAndKey("testOverlappingValidationInstall2");
        _installMultipleOwnerValidations();
    }

    function testSpecifyRuntimeValidation() public {
        (ownerAddr,) = makeAddrAndKey("testSpecifyRuntimeValidation");
        (ownerAddr2,) = makeAddrAndKey("testSpecifyRuntimeValidation2");
        UpgradableMSCA msca = _installMultipleOwnerValidations();

        // pretend to be owner 1, expect fail
        vm.startPrank(ownerAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                RuntimeValidationFailed.selector,
                address(singleSignerValidationModule2),
                0,
                abi.encodeWithSignature("UnauthorizedCaller()")
            )
        );
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (address(0), 0, "")),
            encodeSignature(new PreValidationHookData[](0), owner2Validation, "", true)
        );
        vm.stopPrank();

        vm.startPrank(ownerAddr2);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (address(0), 0, "")),
            encodeSignature(new PreValidationHookData[](0), owner2Validation, "", true)
        );
        vm.stopPrank();
    }

    function testSpecifyUserOpValidation() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSpecifyUserOpValidation");
        (ownerAddr2, eoaPrivateKey2) = makeAddrAndKey("testSpecifyUserOpValidation2");
        UpgradableMSCA msca = _installMultipleOwnerValidations();
        vm.deal(address(msca), 1 ether);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            0,
            "0x",
            vm.toString(abi.encodeCall(IModularAccount.execute, (address(0), 0, ""))),
            83353,
            102865,
            45484,
            516219199704,
            1130000000,
            "0x"
        );

        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey2, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), owner2Validation, signature, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps(ops, beneficiary);

        // sign with owner 1, expect fail
        userOp.nonce = 1;
        signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), owner2Validation, signature, true);

        ops[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(ops, beneficiary);
    }

    ///
    /// global validation
    ///
    function testGlobalValidationViaUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGlobalValidationViaUserOp");

        // only get address w/o deployment
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        (address msca,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(msca.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(msca, 0);
        // start with balance
        vm.deal(msca, 2 ether);
        bytes memory createAccountCall = abi.encodeCall(
            UpgradableMSCAFactory.createAccountWithValidation, (addressToBytes32(ownerAddr), salt, initializingData)
        );
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        address recipient = makeAddr("testGlobalValidationViaUserOp_recipient");
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            vm.toString(initCode),
            vm.toString(abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""))),
            83353000,
            10286500,
            0,
            1,
            1,
            "0x"
        );

        // Generate signature
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        assertEq(recipient.balance, 1 wei);
        vm.stopPrank();
    }

    function testGlobalValidationViaRuntime() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testGlobalValidationViaRuntime");

        // only get address w/o deployment
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        (address mscaAddr,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(mscaAddr.code.length == 0);
        // start with balance
        vm.deal(mscaAddr, 2 ether);
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        address recipient = makeAddr("testGlobalValidationViaRuntime_recipient");
        vm.startPrank(ownerAddr);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, "")),
            encodeSignature(new PreValidationHookData[](0), ownerValidation, "", true)
        );
        vm.stopPrank();
        assertEq(recipient.balance, 1 wei);
    }

    ///
    /// executeUserOp
    ///
    function testExecuteUserOp() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testExecuteUserOp");

        // only get address w/o deployment
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));

        (address msca,) = factory.getAddressWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertTrue(msca.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(msca, 0);
        // start with balance
        vm.deal(msca, 2 ether);
        bytes memory createAccountCall = abi.encodeCall(
            UpgradableMSCAFactory.createAccountWithValidation, (addressToBytes32(ownerAddr), salt, initializingData)
        );
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        address recipient = makeAddr("testExecuteUserOp_recipient");
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            vm.toString(initCode),
            // pack executeUserOp first, so entry point would recognize
            vm.toString(
                abi.encodePacked(
                    IAccountExecute.executeUserOp.selector,
                    abi.encodeCall(IModularAccount.execute, (recipient, 1 wei, ""))
                )
            ),
            83353000,
            10286500,
            0,
            1,
            1,
            "0x"
        );

        // Generate signature
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        // global validation
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, true);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.startPrank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);
        assertEq(recipient.balance, 1 wei);
        vm.stopPrank();
    }

    ///
    /// replace module
    ///
    function testReplaceExecutionModule() public {
        uint32 entityId = 10;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("test_upgradeExecutionModule");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), entityId);
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        ExecutionManifest memory executionManifest;
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: MockModule.testFoo.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: true
        });
        executionManifest.executionFunctions = executionFunctions;
        ManifestExecutionHook[] memory executionHooks = new ManifestExecutionHook[](1);
        executionHooks[0] = ManifestExecutionHook({
            executionSelector: MockModule.testFoo.selector,
            entityId: entityId,
            isPreHook: true,
            isPostHook: true
        });
        executionManifest.executionHooks = executionHooks;

        MockModule moduleV1 = new MockModule(
            executionManifest, SIG_VALIDATION_SUCCEEDED, true, true, bytes(""), true, SIG_VALIDATION_SUCCEEDED, true
        );
        MockModule moduleV2 = new MockModule(
            executionManifest, SIG_VALIDATION_SUCCEEDED, true, true, bytes(""), true, SIG_VALIDATION_SUCCEEDED, true
        );
        vm.startPrank(address(entryPoint));
        msca.installExecution(address(moduleV1), moduleV1.executionManifest(), "");

        // verify installed
        vm.expectEmit(true, true, true, true);
        bytes memory callData = abi.encodePacked(MockModule.testFoo.selector);
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (entityId, address(entryPoint), 0, callData))
        );
        emit ReceivedCall(callData);
        emit ReceivedCall(abi.encodeCall(IExecutionHookModule.postExecutionHook, (entityId, bytes(""))));
        MockModule(address(msca)).testFoo();

        // upgrade module by batching uninstall existing module + install new module calls
        vm.startPrank(address(msca));
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(msca),
            value: 0,
            data: abi.encodeCall(IModularAccount.uninstallExecution, (address(moduleV1), moduleV1.executionManifest(), ""))
        });
        calls[1] = Call({
            target: address(msca),
            value: 0,
            data: abi.encodeCall(IModularAccount.installExecution, (address(moduleV2), moduleV2.executionManifest(), ""))
        });
        msca.executeWithRuntimeValidation(
            abi.encodeCall(msca.executeBatch, (calls)),
            encodeSignature(new PreValidationHookData[](0), ownerValidation, "", true)
        );

        // verify upgraded
        assertEq(msca.getExecutionData(MockModule.testFoo.selector).module, address(moduleV2));
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IExecutionHookModule.preExecutionHook, (entityId, address(msca), 0, callData)));
        emit ReceivedCall(abi.encodePacked(MockModule.testFoo.selector));
        emit ReceivedCall(abi.encodeCall(IExecutionHookModule.postExecutionHook, (entityId, bytes(""))));
        MockModule(address(msca)).testFoo();
        vm.stopPrank();
    }

    function testReplaceValidationModule() public {
        uint32 validationEntityIdV1 = 10;
        uint32 validationEntityIdV2 = 11;
        ModuleEntity moduleEntityV1 = ModuleEntityLib.pack(address(singleSignerValidationModule), validationEntityIdV1);
        ModuleEntity moduleEntityV2 = ModuleEntityLib.pack(address(singleSignerValidationModule2), validationEntityIdV2);
        (UpgradableMSCA msca, address mockPreValAndExecutionHookModule) =
            _createAccountForReplaceValidationModule(validationEntityIdV1, moduleEntityV1);

        vm.startPrank(address(msca));
        bytes memory callData = abi.encodeCall(IModularAccount.execute, (vm.addr(123), 1 ether, bytes("")));
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook,
                (validationEntityIdV1, address(msca), 0, callData, bytes(""))
            )
        );
        emit ReceivedCall(
            abi.encodeCall(
                IValidationModule.validateRuntime,
                (address(msca), validationEntityIdV1, address(msca), 0, callData, bytes(""))
            )
        );
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (validationEntityIdV1, address(msca), 0, callData))
        );
        emit ReceivedCall(abi.encodeCall(IExecutionHookModule.postExecutionHook, (validationEntityIdV1, bytes(""))));
        msca.executeWithRuntimeValidation(
            callData, encodeSignature(new PreValidationHookData[](0), moduleEntityV1, "", true)
        );
        assertEq(vm.addr(123).balance, 1 ether);

        // upgrade module by batching uninstall + install calls
        bytes[] memory hooksForValidationV2 = new bytes[](2);
        hooksForValidationV2[0] =
            abi.encodePacked(HookConfigLib.packValidationHook(mockPreValAndExecutionHookModule, validationEntityIdV2));
        hooksForValidationV2[1] = abi.encodePacked(
            HookConfigLib.packExecHook(mockPreValAndExecutionHookModule, validationEntityIdV2, true, true)
        );

        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(msca),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.uninstallValidation, (moduleEntityV1, abi.encode(moduleEntityV1), new bytes[](0))
            )
        });
        calls[1] = Call({
            target: address(msca),
            value: 0,
            data: abi.encodeCall(
                IModularAccount.installValidation,
                (
                    ValidationConfigLib.pack(moduleEntityV2, true, true, true),
                    new bytes4[](0),
                    abi.encode(validationEntityIdV2, ownerAddr),
                    hooksForValidationV2
                )
            )
        });
        // should use the existing validation function
        msca.executeWithRuntimeValidation(
            abi.encodeCall(msca.executeBatch, (calls)),
            encodeSignature(new PreValidationHookData[](0), moduleEntityV1, "", true)
        );

        // old validation should fail
        vm.expectRevert(
            abi.encodePacked(
                BaseMSCA.InvalidValidationFunction.selector,
                abi.encode(IModularAccount.execute.selector, moduleEntityV1)
            )
        );
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.execute, (vm.addr(123), 1 ether, "")),
            encodeSignature(new PreValidationHookData[](0), moduleEntityV1, "", true)
        );

        // new validation should work
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(
                IValidationHookModule.preRuntimeValidationHook,
                (validationEntityIdV2, address(msca), 0, callData, bytes(""))
            )
        );
        emit ReceivedCall(
            abi.encodeCall(
                IValidationModule.validateRuntime,
                (address(msca), validationEntityIdV2, address(msca), 0, callData, bytes(""))
            )
        );
        emit ReceivedCall(
            abi.encodeCall(IExecutionHookModule.preExecutionHook, (validationEntityIdV2, address(msca), 0, callData))
        );
        emit ReceivedCall(abi.encodeCall(IExecutionHookModule.postExecutionHook, (validationEntityIdV2, bytes(""))));
        msca.executeWithRuntimeValidation(
            callData, encodeSignature(new PreValidationHookData[](0), moduleEntityV2, "", true)
        );
        assertEq(vm.addr(123).balance, 2 ether);
        vm.stopPrank();
    }

    function _createAccountForReplaceValidationModule(uint32 validationEntityIdV1, ModuleEntity moduleEntityV1)
        internal
        returns (UpgradableMSCA msca, address mockPreValAndExecutionHookModuleAddr)
    {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("test_replaceValidationModule");
        MockModule mockPreValAndExecutionHookModule = new MockModule(
            ExecutionManifest({
                executionFunctions: new ManifestExecutionFunction[](0),
                executionHooks: new ManifestExecutionHook[](0),
                interfaceIds: new bytes4[](0)
            }),
            SIG_VALIDATION_SUCCEEDED,
            true,
            true,
            bytes(""),
            true,
            SIG_VALIDATION_SUCCEEDED,
            true
        );
        bool[] memory permissions = new bool[](1);
        address[] memory modulesAddr = new address[](1);
        permissions[0] = true;
        modulesAddr[0] = address(mockPreValAndExecutionHookModule);
        // setup a validation with pre validation and execution hooks
        bytes[] memory hooksForValidationV1 = new bytes[](2);
        hooksForValidationV1[0] =
            abi.encodePacked(HookConfigLib.packValidationHook(modulesAddr[0], validationEntityIdV1));
        hooksForValidationV1[1] =
            abi.encodePacked(HookConfigLib.packExecHook(modulesAddr[0], validationEntityIdV1, true, true));
        vm.prank(factoryOwner);
        factory.setModules(modulesAddr, permissions);

        ValidationConfig validationConfig = ValidationConfigLib.pack(moduleEntityV1, true, true, true);
        bytes memory initializingData = abi.encode(
            validationConfig, new bytes4[](0), abi.encode(validationEntityIdV1, ownerAddr), hooksForValidationV1
        );
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        vm.deal(address(msca), 10 ether);
        mockPreValAndExecutionHookModuleAddr = modulesAddr[0];
    }

    function testAccountId() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testAccountId");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        UpgradableMSCA msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
        assertEq(msca.accountId(), "circle.msca.2.0.0");
    }

    function testMaxLimitValidationHooks() public {
        MockModule[] memory modules = new MockModule[](300);
        bool[] memory permissions = new bool[](300);
        address[] memory modulesAddr = new address[](300);
        for (uint256 i = 0; i < 300; i++) {
            modules[i] = new MockModule(
                ExecutionManifest({
                    executionFunctions: new ManifestExecutionFunction[](0),
                    executionHooks: new ManifestExecutionHook[](0),
                    interfaceIds: new bytes4[](0)
                }),
                SIG_VALIDATION_SUCCEEDED,
                true,
                true,
                bytes(""),
                true,
                SIG_VALIDATION_SUCCEEDED,
                true
            );
            modulesAddr[i] = address(modules[i]);
            permissions[i] = true;
        }
        vm.prank(factoryOwner);
        factory.setModules(modulesAddr, permissions);
        bytes[] memory hooks = new bytes[](300);
        for (uint256 i = 0; i < 300; i++) {
            hooks[i] = abi.encodePacked(HookConfigLib.packValidationHook(address(modules[i]), uint32(i)));
        }
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), hooks);
        vm.expectRevert(abi.encodeWithSelector(BaseMSCA.MaxHooksExceeded.selector));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
    }

    function testMaxLimitExecutionHooks() public {
        MockModule[] memory modules = new MockModule[](300);
        bool[] memory permissions = new bool[](300);
        address[] memory modulesAddr = new address[](300);
        for (uint256 i = 0; i < 300; i++) {
            modules[i] = new MockModule(
                ExecutionManifest({
                    executionFunctions: new ManifestExecutionFunction[](0),
                    executionHooks: new ManifestExecutionHook[](0),
                    interfaceIds: new bytes4[](0)
                }),
                SIG_VALIDATION_SUCCEEDED,
                true,
                true,
                bytes(""),
                true,
                SIG_VALIDATION_SUCCEEDED,
                true
            );
            modulesAddr[i] = address(modules[i]);
            permissions[i] = true;
        }
        vm.prank(factoryOwner);
        factory.setModules(modulesAddr, permissions);
        bytes[] memory hooks = new bytes[](300);
        for (uint256 i = 0; i < 300; i++) {
            hooks[i] = abi.encodePacked(HookConfigLib.packExecHook(address(modules[i]), uint32(i), false, false));
        }
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), hooks);
        vm.expectRevert(abi.encodeWithSelector(BaseMSCA.MaxHooksExceeded.selector));
        factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);
    }

    function _installMultipleOwnerValidations() internal returns (UpgradableMSCA msca) {
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), new bytes[](0));
        vm.startPrank(ownerAddr);
        msca = factory.createAccountWithValidation(addressToBytes32(ownerAddr), salt, initializingData);

        owner2Validation = ModuleEntityLib.pack(address(singleSignerValidationModule2), uint32(0));
        validationConfig = ValidationConfigLib.pack(owner2Validation, true, true, true);
        vm.startPrank(address(msca));
        msca.installValidation(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr2), new bytes[](0));
        vm.stopPrank();

        vm.startPrank(address(entryPoint));
        ValidationDataView memory validationData = msca.getValidationData(ownerValidation);
        assertEq(validationData.selectors.length, 0);
        validationData = msca.getValidationData(owner2Validation);
        assertEq(validationData.selectors.length, 0);
        vm.stopPrank();
        return msca;
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
