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

import {EMPTY_FUNCTION_REFERENCE} from "../../../../src/common/Constants.sol";

import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.7/account/UpgradableMSCA.sol";

import {
    PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE,
    RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
} from "../../../../src/msca/6900/v0.7/common/Constants.sol";
import {
    ManifestAssociatedFunction,
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestExternalCallPermission,
    ManifestFunction,
    PluginManifest
} from "../../../../src/msca/6900/v0.7/common/PluginManifest.sol";
import {ExecutionFunctionConfig, FunctionReference} from "../../../../src/msca/6900/v0.7/common/Structs.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.7/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "../../../../src/msca/6900/v0.7/libs/FunctionReferenceLib.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.7/managers/PluginManager.sol";
import {SingleOwnerPlugin} from "../../../../src/msca/6900/v0.7/plugins/v1_0_0/acl/SingleOwnerPlugin.sol";
import {TestERC1155} from "../../../util/TestERC1155.sol";
import {TestERC721} from "../../../util/TestERC721.sol";

import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";
import {TestUtils} from "../../../util/TestUtils.sol";

import {TestValidatorHook} from "../v0.7/TestUserOpValidatorHook.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {TestUserOpValidator} from "./TestUserOpValidator.sol";
import {TestValidatorHook} from "./TestUserOpValidatorHook.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract UpgradableMSCATest is TestUtils {
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
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

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testLiquidityPool;
    TestCircleMSCAFactory private factory;
    address private factoryOwner;
    SingleOwnerPlugin private singleOwnerPlugin;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);
        singleOwnerPlugin = new SingleOwnerPlugin();
        address[] memory _plugins = new address[](1);
        _plugins[0] = address(singleOwnerPlugin);
        bool[] memory _permissions = new bool[](1);
        _permissions[0] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        vm.stopPrank();
    }

    function testInvalidCalldataLength() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testInvalidCalldataLength");
        UpgradableMSCA msca = new UpgradableMSCA(entryPoint, pluginManager);
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
        userOp.signature = signature;
        bytes4 selector = bytes4(keccak256("NotFoundSelector()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testNotFoundFunctionSelector() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testNotFoundFunctionSelector");
        UpgradableMSCA msca = new UpgradableMSCA(entryPoint, pluginManager);
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            28,
            "0x",
            "0x1234",
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
        userOp.signature = signature;
        bytes4 selector = bytes4(keccak256("NotFoundSelector()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testEmptyUserOpValidationFunction() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testEmptyUserOpValidationFunction");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // FunctionReference userOpValidator is not configured
        ExecutionFunctionConfig memory executionFunctionConfig;
        executionFunctionConfig.userOpValidationFunction = EMPTY_FUNCTION_REFERENCE.unpack();
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);
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
        userOp.signature = signature;
        bytes4 errorSelector = bytes4(keccak256("InvalidValidationFunctionId(uint8)"));
        // empty func ref
        vm.expectRevert(abi.encodeWithSelector(errorSelector, 0));
        msca.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
    }

    function testValidationPassButWithWrongTimeBounds() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationPassButWithWrongTimeBounds");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // wrong time bounds
        ValidationData memory expectToPass = ValidationData(10, 9, address(0));
        FunctionReference memory userOpValidator = FunctionReference(address(new TestUserOpValidator(expectToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        bytes4 selector = bytes4(keccak256("WrongTimeBounds()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        vm.stopPrank();
    }

    function testValidationPassWithoutHooks() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationPassWithoutHooks");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectToPass = ValidationData(1681493273, 1691493273, address(0));
        FunctionReference memory userOpValidator = FunctionReference(address(new TestUserOpValidator(expectToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 1681493273);
        assertEq(validationData.validUntil, 1691493273);
        assertEq(validationData.authorizer, address(0));
        vm.stopPrank();
    }

    function testValidationFailWithoutHooks() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationFailWithoutHooks");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectToPass = ValidationData(0, 1791493273, address(1));
        FunctionReference memory userOpValidator = FunctionReference(address(new TestUserOpValidator(expectToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 0);
        assertEq(validationData.validUntil, 1791493273);
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testValidationWhenHookDenies() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationWhenHookDenies");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        bytes4 selector = bytes4(0xb61d27f6);
        ValidationData memory expectValidatorToPass = ValidationData(1681493273, 1691493273, address(0));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(selector, executionFunctionConfig);

        FunctionReference memory preUserOpValidationHook = PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE.unpack();
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        bytes4 errorSelector = bytes4(keccak256("InvalidHookFunctionId(uint8)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, 2));
        _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        vm.stopPrank();
    }

    function testUserOpValidationFuncIsPreHookAlwaysDeny() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUserOpValidationFuncIsPreHookAlwaysDeny");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        bytes4 selector = bytes4(0xb61d27f6);
        FunctionReference memory userOpValidator = PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE.unpack();
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(selector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1781493273, 1791493273, address(0));
        FunctionReference memory preUserOpValidationHook =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 5);
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        bytes4 errorSelector = bytes4(keccak256("InvalidValidationFunctionId(uint8)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, 2));
        _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        vm.stopPrank();
    }

    function testUserOpValidationFuncIsRuntimeAlwaysAllow() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUserOpValidationFuncIsRuntimeAlwaysAllow");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        bytes4 selector = bytes4(0xb61d27f6);
        FunctionReference memory userOpValidator = RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE.unpack();
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(selector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1781493273, 1791493273, address(0));
        FunctionReference memory preUserOpValidationHook =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 5);
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        bytes4 errorSelector = bytes4(keccak256("InvalidValidationFunctionId(uint8)"));
        vm.expectRevert(abi.encodeWithSelector(errorSelector, 1));
        _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        vm.stopPrank();
    }

    function testValidationWhenHookFails() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationWhenHookFails");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectValidatorToPass = ValidationData(1681493273, 1691493273, address(0));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToFail = ValidationData(1781493273, 1791493273, address(1));
        FunctionReference memory preUserOpValidationHook =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToFail)), 3);
        msca.setPreUserOpValidationHook(functionSelector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        // this will be caught up in entryPoint
        assertEq(validationData.validAfter, 1781493273);
        assertEq(validationData.validUntil, 1691493273);
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testValidationWithInvalidTimeBounds() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationWithInvalidTimeBounds");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        bytes4 functionSelector = bytes4(0xb61d27f6);
        ValidationData memory expectValidatorToPass = ValidationData(1681493273, 1691493273, address(0));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToPass)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1781493273, 1791493273, address(0));
        FunctionReference memory preUserOpValidationHook =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 3);
        msca.setPreUserOpValidationHook(functionSelector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        // this will be caught up in entryPoint
        assertEq(validationData.validAfter, 1781493273);
        assertEq(validationData.validUntil, 1691493273);
        // the time bounds interception doesn't make sense
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testValidatorFailsButHookPasses() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidatorFailsButHookPasses");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectValidatorToFail = ValidationData(0, 1691493273, address(1));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToFail)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 1691493274, address(0));
        FunctionReference memory preUserOpValidationHook =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 3);
        msca.setPreUserOpValidationHook(functionSelector, preUserOpValidationHook);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 1);
        assertEq(validationData.validUntil, 1691493273);
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testOneHookPassesButTheOtherHookFails() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testOneHookPassesButTheOtherHookFails");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectValidatorToFail = ValidationData(0, 1691493273, address(1));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToFail)), 3);
        FunctionReference memory runtimeValidator;
        address executionPlugin = vm.addr(1);
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(executionPlugin, userOpValidator, runtimeValidator);
        msca.initExecutionDetail(functionSelector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 3, address(0));
        FunctionReference memory preUserOpValidationHook1 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 3);

        ValidationData memory expectValidatorHookToFail = ValidationData(2, 4, address(1));
        FunctionReference memory preUserOpValidationHook2 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToFail)), 3);
        msca.setPreUserOpValidationHook(functionSelector, preUserOpValidationHook1);
        msca.setPreUserOpValidationHook(functionSelector, preUserOpValidationHook2);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        userOp.signature = signature;
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 2);
        assertEq(validationData.validUntil, 3);
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testInterceptWhenAllValidationsPass() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testInterceptWhenAllValidationsPass");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 selector = bytes4(0xb61d27f6);
        // uint48 validAfter;
        // uint48 validUntil;
        // address authorizer;
        ValidationData memory expectValidatorToFail = ValidationData(0, 1691493273, address(0));
        FunctionReference memory userOpValidator =
            FunctionReference(address(new TestUserOpValidator(expectValidatorToFail)), 7);
        FunctionReference memory runtimeValidator;
        ExecutionFunctionConfig memory executionFunctionConfig =
            ExecutionFunctionConfig(vm.addr(1), userOpValidator, runtimeValidator);
        msca.initExecutionDetail(selector, executionFunctionConfig);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 20, address(0));
        FunctionReference memory preUserOpValidationHook1 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 3);

        expectValidatorHookToPass = ValidationData(2, 21, address(0));
        FunctionReference memory preUserOpValidationHook2 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 4);

        expectValidatorHookToPass = ValidationData(5, 30, address(0));
        FunctionReference memory preUserOpValidationHook3 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 5);

        expectValidatorHookToPass = ValidationData(7, 19, address(0));
        FunctionReference memory preUserOpValidationHook4 =
            FunctionReference(address(new TestValidatorHook(expectValidatorHookToPass)), 6);

        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook1);
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook2);
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook3);
        msca.setPreUserOpValidationHook(selector, preUserOpValidationHook4);
        assertEq(msca.sizeOfPreUserOpValidationHooks(selector), 4);
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
            "0x79cbffe6dd3c3cb46aab6ef51f1a4accb5567f4e0000000000000000000000000000000000000000000000000000000064d223990000000000000000000000000000000000000000000000000000000064398d19"
        );

        vm.startPrank(address(entryPoint));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp);
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 7);
        assertEq(validationData.validUntil, 19);
        assertEq(validationData.authorizer, address(0));
        vm.stopPrank();
    }

    function testUpgradeMSCA() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUpgradeMSCA");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        TestCircleMSCA msca = factory.createAccount(ownerAddr, salt, initializingData);

        vm.startPrank(ownerAddr);
        TestCircleMSCA implMSCA = new TestCircleMSCA(IEntryPoint(vm.addr(123)), pluginManager);
        address v2ImplAddr = address(implMSCA);
        emit Upgraded(v2ImplAddr);
        // call upgradeTo from proxy
        msca.upgradeToAndCall(v2ImplAddr, "");
        vm.stopPrank();

        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        implMSCA.upgradeToAndCall(v2ImplAddr, "");
    }

    function testEncodeAndHashPluginManifest() public pure {
        PluginManifest memory manifest;
        manifest.permitAnyExternalAddress = true;
        bytes4[] memory dependencyInterfaceIds = new bytes4[](1);
        dependencyInterfaceIds[0] = bytes4(0x12345678);
        string[] memory guardingPermissions = new string[](1);
        guardingPermissions[0] = "permissions";
        bytes4[] memory executionFunctions = new bytes4[](1);
        executionFunctions[0] = 0x12345678;
        bytes4[] memory permittedExecutionSelectors = new bytes4[](1);
        permittedExecutionSelectors[0] = 0x12345678;
        manifest.permittedExecutionSelectors = permittedExecutionSelectors;
        ManifestExternalCallPermission[] memory permittedExternalCalls = new ManifestExternalCallPermission[](1);
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = bytes4(0x12345678);
        ManifestExternalCallPermission memory permittedExternalCall =
            ManifestExternalCallPermission(address(0x1), false, functionSelectors);
        permittedExternalCalls[0] = permittedExternalCall;
        manifest.permittedExternalCalls = permittedExternalCalls;
        ManifestFunction memory manifestFunction = ManifestFunction(ManifestAssociatedFunctionType.SELF, 0, 0);
        ManifestAssociatedFunction memory associatedFunc =
            ManifestAssociatedFunction(bytes4(0x12345678), manifestFunction);
        ManifestAssociatedFunction[] memory userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        userOpValidationFunctions[0] = associatedFunc;
        ManifestAssociatedFunction[] memory runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        runtimeValidationFunctions[0] = associatedFunc;
        ManifestAssociatedFunction[] memory preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        preUserOpValidationHooks[0] = associatedFunc;
        ManifestAssociatedFunction[] memory preRuntimeValidationHooks = new ManifestAssociatedFunction[](1);
        preRuntimeValidationHooks[0] = associatedFunc;
        manifest.userOpValidationFunctions = userOpValidationFunctions;
        manifest.runtimeValidationFunctions = runtimeValidationFunctions;
        manifest.preUserOpValidationHooks = preUserOpValidationHooks;
        manifest.preRuntimeValidationHooks = preRuntimeValidationHooks;
        ManifestExecutionHook[] memory executionHooks = new ManifestExecutionHook[](1);
        executionHooks[0] = ManifestExecutionHook(bytes4(0x12345678), manifestFunction, manifestFunction);
        manifest.executionHooks = executionHooks;
        assertEq(abi.encode(manifest).length, 1696);
        assertEq(keccak256(abi.encode(manifest)).length, 32);
    }

    function testSendAndReceiveNativeTokenWithoutAnyACLPlugin() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address randomSenderSeedAddr, uint256 senderPrivateKey) =
            makeAddrAndKey("testSendAndReceiveNativeTokenWithoutAnyACLPlugin_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(randomSenderSeedAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        TestCircleMSCA sender = factory.createAccount(randomSenderSeedAddr, salt, initializingData);
        address senderAddr = address(sender);
        vm.startPrank(senderAddr);
        // remove ownership plugin
        sender.uninstallPlugin(plugins[0], "", "");
        vm.stopPrank();
        (address recipientAddr,) = factory.getAddress(vm.addr(1), salt, initializingData);
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
        userOp.signature = signature;
        vm.startPrank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("InvalidValidationFunctionId(uint8)")), EMPTY_FUNCTION_REFERENCE.unpack().functionId
            )
        );
        sender.validateUserOp(userOp, userOpHash, 0);
        vm.stopPrank();
        // verify recipient balance
        assertEq(recipientAddr.balance, 0);
    }

    function testSendAndReceiveNativeTokenWithSingleOwnerPlugin() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveNativeTokenWithSingleOwnerPlugin_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        (address recipientAddr,) = factory.getAddress(vm.addr(1), salt, initializingData);
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
        userOp.signature = signature;
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC20TokenWithoutDefaultCallbackHandler_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        // recipient account doesn't have the token callback
        (address recipientAddr,) = factory.getAddress(vm.addr(1), salt, initializingData);
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
        userOp.signature = signature;
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenNatively_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC1155.mint(senderAddr, 0, 2, "");
        assertEq(testERC1155.balanceOf(senderAddr, 0), 2);
    }

    // should not be able to receive ERC721 token with token callback enshrined
    function testSendAndReceiveERC721TokenNatively() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenNatively_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC721.safeMint(senderAddr, 0);
        assertEq(testERC721.balanceOf(senderAddr), 1);
    }

    // should be able to send/receive ERC1155 token with token callback handler
    function testSendAndReceiveERC1155TokenWithDefaultCallbackHandler() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenWithDefaultCallbackHandler_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        // recipient account has the token callback installed
        TestCircleMSCA recipient = factory.createAccount(vm.addr(1), salt, initializingData);
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

    // should be able to send/receive ERC721 token with token callback handler
    function testSendAndReceiveERC721TokenWithDefaultCallbackHandler() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenWithDefaultCallbackHandler_sender");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        factory.createAccount(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddress(ownerAddr, salt, initializingData);
        // recipient account has the token callback installed
        TestCircleMSCA recipient = factory.createAccount(vm.addr(1), salt, initializingData);
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

    // should be able to depositTo/withdrawDepositTo/getDeposit
    function testDepositAndWithdrawWithEP() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDepositAndWithdrawWithEP");
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        TestCircleMSCA sender = factory.createAccount(ownerAddr, salt, initializingData);

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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        address[] memory plugins = new address[](1);
        bytes32[] memory manifestHashes = new bytes32[](1);
        bytes[] memory pluginInstallData = new bytes[](1);
        plugins[0] = address(singleOwnerPlugin);
        manifestHashes[0] = keccak256(abi.encode(singleOwnerPlugin.pluginManifest()));
        pluginInstallData[0] = abi.encode(ownerAddr);
        bytes memory initializingData = abi.encode(plugins, manifestHashes, pluginInstallData);
        (address sender,) = factory.getAddress(ownerAddr, salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 100 ether);
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (address(0), 0, ""));
        bytes memory createAccountCall =
            abi.encodeCall(TestCircleMSCAFactory.createAccount, (ownerAddr, salt, initializingData));
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
        // no paymaster
        emit UserOperationEvent(userOpHash, sender, address(0), acctNonce, true, 287692350000000, 254595);
        entryPoint.handleOps(ops, beneficiary);
        // verify the account has been deployed
        assertTrue(sender.code.length > 0);
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
