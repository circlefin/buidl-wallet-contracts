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
    EMPTY_MODULE_ENTITY
} from "../../../../src/common/Constants.sol";

import {ValidationData} from "../../../../src/msca/6900/shared/common/Structs.sol";

import {BaseMSCA} from "../../../../src/msca/6900/v0.8/account/BaseMSCA.sol";
import {UpgradableMSCA} from "../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {
    ManifestExecutionHook,
    ManifestValidation,
    PluginManifest
} from "../../../../src/msca/6900/v0.8/common/PluginManifest.sol";
import {ModuleEntity, ValidationConfig} from "../../../../src/msca/6900/v0.8/common/Types.sol";
import {UpgradableMSCAFactory} from "../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";
import {IAccountExecute} from "../../../../src/msca/6900/v0.8/interfaces/IAccountExecute.sol";
import {IStandardExecutor} from "../../../../src/msca/6900/v0.8/interfaces/IStandardExecutor.sol";
import {ModuleEntityLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ModuleEntityLib.sol";

import {ValidationConfigLib} from "../../../../src/msca/6900/v0.8/libs/thirdparty/ValidationConfigLib.sol";
import {PluginManager} from "../../../../src/msca/6900/v0.8/managers/PluginManager.sol";
import {SingleSignerValidationModule} from
    "../../../../src/msca/6900/v0.8/plugins/v1_0_0/validation/SingleSignerValidationModule.sol";
import {TestERC1155} from "../../../util/TestERC1155.sol";
import {TestERC721} from "../../../util/TestERC721.sol";

import {TestLiquidityPool} from "../../../util/TestLiquidityPool.sol";

import {TestUserOpValidatorHook} from "../v0.8/TestUserOpValidatorHook.sol";
import {TestCircleMSCA} from "./TestCircleMSCA.sol";
import {TestCircleMSCAFactory} from "./TestCircleMSCAFactory.sol";
import {TestUserOpValidator} from "./TestUserOpValidator.sol";
import {TestUserOpValidatorHook} from "./TestUserOpValidatorHook.sol";
import {AccountTestUtils} from "./utils/AccountTestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

// We use TestCircleMSCA (that inherits from UpgradableMSCA) because it has some convenience functions
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

    error RuntimeValidationFailed(address plugin, uint32 entityId, bytes revertReason);

    IEntryPoint private entryPoint = new EntryPoint();
    PluginManager private pluginManager = new PluginManager();
    uint256 internal eoaPrivateKey;
    address private ownerAddr;
    address payable private beneficiary; // e.g. bundler
    TestERC1155 private testERC1155;
    TestERC721 private testERC721;
    TestLiquidityPool private testLiquidityPool;
    TestCircleMSCAFactory private factory;
    address private factoryOwner;
    SingleSignerValidationModule private singleSignerValidationModule;
    UpgradableMSCAFactory private mscaFactory;
    ModuleEntity private ownerValidation;
    uint256 internal eoaPrivateKey2;
    address private ownerAddr2;
    SingleSignerValidationModule private singleSignerValidationModule2;
    ModuleEntity private owner2Validation;

    function setUp() public {
        factoryOwner = makeAddr("factoryOwner");
        beneficiary = payable(address(makeAddr("bundler")));
        testERC1155 = new TestERC1155("getrich.com");
        testERC721 = new TestERC721("getrich", "$$$");
        testLiquidityPool = new TestLiquidityPool("getrich", "$$$");
        factory = new TestCircleMSCAFactory(factoryOwner, entryPoint, pluginManager);
        mscaFactory = new UpgradableMSCAFactory(factoryOwner, address(entryPoint), address(pluginManager));
        singleSignerValidationModule = new SingleSignerValidationModule();
        singleSignerValidationModule2 = new SingleSignerValidationModule();
        address[] memory _plugins = new address[](2);
        _plugins[0] = address(singleSignerValidationModule);
        _plugins[1] = address(singleSignerValidationModule2);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factoryOwner);
        factory.setPlugins(_plugins, _permissions);
        mscaFactory.setPlugins(_plugins, _permissions);
        vm.stopPrank();
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        owner2Validation = ModuleEntityLib.pack(address(singleSignerValidationModule2), uint32(0));
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), ownerValidation, signature, false);
        bytes4 selector = bytes4(keccak256("InvalidCalldataLength(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 1, 4));
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
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
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

    function testValidationPassButWithWrongTimeBounds() public {
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testValidationPassButWithWrongTimeBounds");
        TestCircleMSCA msca = new TestCircleMSCA(entryPoint, pluginManager);
        // 0xb61d27f6
        bytes4 functionSelector = bytes4(0xb61d27f6);
        // wrong time bounds
        ValidationData memory expectToPass = ValidationData(10, 9, address(0));
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectToPass)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectToPass)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectToPass)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 0);
        assertEq(validationData.validUntil, 1791493273);
        assertEq(validationData.authorizer, address(1));
        vm.stopPrank();
    }

    function testSkipRuntimeAlwaysAllow() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSkipRuntimeAlwaysAllow");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        TestCircleMSCA msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        bytes4 selector = bytes4(msca.upgradeToAndCall.selector);
        // skip runtime validation
        msca.setSkipRuntimeValidation(selector, true);
        vm.startPrank(address(entryPoint));
        TestCircleMSCA implMSCA = new TestCircleMSCA(IEntryPoint(vm.addr(123)), pluginManager);
        address v2ImplAddr = address(implMSCA);
        emit Upgraded(v2ImplAddr);
        msca.upgradeToAndCall(v2ImplAddr, "");

        // require runtime validation now, but would fail at singleSignerValidationModule.validateRuntime
        msca.setSkipRuntimeValidation(selector, false);
        vm.startPrank(vm.addr(1));
        bytes memory revertReason = abi.encodeWithSelector(bytes4(keccak256("UnauthorizedCaller()")));
        uint32 entityId = uint32(0);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("ExecFromPluginToSelectorNotPermitted(address,bytes4)")), vm.addr(1), selector
            )
        );
        msca.upgradeToAndCall(v2ImplAddr, "");
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectValidatorToPass)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);

        ValidationData memory expectValidatorHookToFail = ValidationData(1781493273, 1791493273, address(1));
        ModuleEntity preUserOpValidationHook =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToFail)), 3);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectValidatorToPass)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);

        ValidationData memory expectValidatorHookToPass = ValidationData(1781493273, 1791493273, address(0));
        ModuleEntity preUserOpValidationHook =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 3);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectValidatorToFail)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 1691493274, address(0));
        ModuleEntity preUserOpValidationHook =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 3);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectValidatorToFail)), 3);
        msca.associateSelectorToValidation(functionSelector, vm.addr(1), validatorFunc);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 3, address(0));
        ModuleEntity preUserOpValidationHook1 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 3);

        ValidationData memory expectValidatorHookToFail = ValidationData(2, 4, address(1));
        ModuleEntity preUserOpValidationHook2 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToFail)), 3);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook1);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook2);
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
        userOp.signature = encodeSignature(new PreValidationHookData[](0), validatorFunc, signature, false);
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
        ModuleEntity validatorFunc = ModuleEntityLib.pack(address(new TestUserOpValidator(expectValidatorToFail)), 7);
        msca.associateSelectorToValidation(selector, vm.addr(1), validatorFunc);

        ValidationData memory expectValidatorHookToPass = ValidationData(1, 20, address(0));
        ModuleEntity preUserOpValidationHook1 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 3);

        expectValidatorHookToPass = ValidationData(2, 21, address(0));
        ModuleEntity preUserOpValidationHook2 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 4);

        expectValidatorHookToPass = ValidationData(5, 30, address(0));
        ModuleEntity preUserOpValidationHook3 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 5);

        expectValidatorHookToPass = ValidationData(7, 19, address(0));
        ModuleEntity preUserOpValidationHook4 =
            ModuleEntityLib.pack(address(new TestUserOpValidatorHook(expectValidatorHookToPass)), 6);

        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook1);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook2);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook3);
        msca.setPreValidationHook(validatorFunc, preUserOpValidationHook4);
        assertEq(msca.sizeOfPreValidationHooks(validatorFunc), 4);
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
        userOp.signature = encodeSignature(
            new PreValidationHookData[](0), validatorFunc, signUserOpHash(entryPoint, vm, eoaPrivateKey, userOp), false
        );
        ValidationData memory validationData = _unpackValidationData(msca.validateUserOp(userOp, userOpHash, 0));
        assertEq(validationData.validAfter, 7);
        assertEq(validationData.validUntil, 19);
        assertEq(validationData.authorizer, address(0));
        vm.stopPrank();
    }

    function testUpgradeMSCA() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testUpgradeMSCA");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        TestCircleMSCA msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);

        vm.startPrank(address(entryPoint));
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
        bytes4[] memory dependencyInterfaceIds = new bytes4[](1);
        dependencyInterfaceIds[0] = bytes4(0x12345678);
        string[] memory guardingPermissions = new string[](1);
        guardingPermissions[0] = "permissions";
        bytes4[] memory executionFunctions = new bytes4[](1);
        executionFunctions[0] = 0x12345678;
        bytes4[] memory functionSelectors = new bytes4[](1);
        functionSelectors[0] = bytes4(0x12345678);
        manifest.validationFunctions = new ManifestValidation[](1);
        manifest.validationFunctions[0] = ManifestValidation({
            entityId: uint32(0),
            isGlobal: true,
            isSignatureValidation: true,
            selectors: functionSelectors
        });
        ManifestExecutionHook[] memory executionHooks = new ManifestExecutionHook[](1);
        executionHooks[0] = ManifestExecutionHook(bytes4(0x12345678), 0, true, true);
        manifest.executionHooks = executionHooks;
        assertEq(abi.encode(manifest).length, 640);
        assertEq(keccak256(abi.encode(manifest)).length, 32);
    }

    function testSendAndReceiveNativeTokenWithoutAnyACLPlugin() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address randomSenderSeedAddr, uint256 senderPrivateKey) =
            makeAddrAndKey("testSendAndReceiveNativeTokenWithoutAnyACLPlugin_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData = abi.encode(
            validationConfig, new bytes4[](0), abi.encode(uint32(0), randomSenderSeedAddr), bytes(""), bytes("")
        );
        TestCircleMSCA sender = factory.createAccountWithValidation(ownerAddr, salt, initializingData);

        address senderAddr = address(sender);
        bytes[] memory empty = new bytes[](0);
        vm.startPrank(senderAddr);
        // remove ownership plugin
        sender.uninstallValidation(ownerValidation, abi.encode(uint32(0)), abi.encode(empty), abi.encode(empty));
        vm.stopPrank();

        (address recipientAddr,) = factory.getAddressWithValidation(vm.addr(1), salt, initializingData);
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
                BaseMSCA.UserOpValidationFunctionMissing.selector,
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) =
            makeAddrAndKey("testSendAndReceiveNativeTokenWithSingleSignerValidationModule_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        (address recipientAddr,) = factory.getAddressWithValidation(vm.addr(1), salt, initializingData);
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC20TokenWithoutDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        // recipient account doesn't have the token callback
        (address recipientAddr,) = factory.getAddressWithValidation(vm.addr(1), salt, initializingData);
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenNatively_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC1155.mint(senderAddr, 0, 2, "");
        assertEq(testERC1155.balanceOf(senderAddr, 0), 2);
    }

    // should not be able to receive ERC721 token with token callback enshrined
    function testSendAndReceiveERC721TokenNatively() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenNatively_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        vm.deal(senderAddr, 1 ether);
        testERC721.safeMint(senderAddr, 0);
        assertEq(testERC721.balanceOf(senderAddr), 1);
    }

    // should be able to send/receive ERC1155 token with token callback handler
    function testSendAndReceiveERC1155TokenWithDefaultCallbackHandler() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC1155TokenWithDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        TestCircleMSCA msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        address senderAddr = address(msca);
        // recipient account has the token callback installed
        TestCircleMSCA recipient = factory.createAccountWithValidation(vm.addr(1), salt, initializingData);
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testSendAndReceiveERC721TokenWithDefaultCallbackHandler_sender");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        (address senderAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        // recipient account has the token callback installed
        TestCircleMSCA recipient = factory.createAccountWithValidation(vm.addr(1), salt, initializingData);
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testDepositAndWithdrawWithEP");
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        TestCircleMSCA sender = factory.createAccountWithValidation(ownerAddr, salt, initializingData);

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
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        (address sender,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        assertTrue(sender.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(sender, 0);
        // start with balance
        vm.deal(sender, 100 ether);
        bytes memory executeCallData = abi.encodeCall(IStandardExecutor.execute, (address(0), 0, ""));
        bytes memory createAccountCall =
            abi.encodeCall(TestCircleMSCAFactory.createAccountWithValidation, (ownerAddr, salt, initializingData));
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

    function testIsValidSignatureNew() public {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (ownerAddr, eoaPrivateKey) = makeAddrAndKey("testIsValidSignature");
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        TestCircleMSCA msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        // raw message hash
        bytes32 message = keccak256("circle internet");
        bytes32 wrappedMessage = singleSignerValidationModule.getReplaySafeMessageHash(address(msca), message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, wrappedMessage);

        bytes memory signature = abi.encodePacked(r, s, v);
        signature = abi.encodePacked(ownerValidation, signature);
        assertEq(IERC1271(address(msca)).isValidSignature(message, signature), bytes4(EIP1271_VALID_SIGNATURE));

        // invalid signature
        signature = abi.encodePacked(address(singleSignerValidationModule), uint32(0), r, s, uint32(0));
        assertEq(IERC1271(address(msca)).isValidSignature(message, signature), bytes4(EIP1271_INVALID_SIGNATURE));

        // invalid validation plugin
        signature = abi.encodePacked(address(0), uint32(0), r, s, v);
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseMSCA.InvalidSignatureValidation.selector, ModuleEntityLib.pack(address(0), uint32(0))
            )
        );
        IERC1271(address(msca)).isValidSignature(message, signature);
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
        msca.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(0), 0, "")),
            encodeSignature(new PreValidationHookData[](0), owner2Validation, "", true)
        );
        vm.stopPrank();

        vm.startPrank(ownerAddr2);
        msca.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(0), 0, "")),
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
            vm.toString(abi.encodeCall(IStandardExecutor.execute, (address(0), 0, ""))),
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        (address msca,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        assertTrue(msca.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(msca, 0);
        // start with balance
        vm.deal(msca, 2 ether);
        bytes memory createAccountCall =
            abi.encodeCall(TestCircleMSCAFactory.createAccountWithValidation, (ownerAddr, salt, initializingData));
        address factoryAddr = address(factory);
        bytes memory initCode = abi.encodePacked(factoryAddr, createAccountCall);
        address recipient = makeAddr("testGlobalValidationViaUserOp_recipient");
        PackedUserOperation memory userOp = buildPartialUserOp(
            address(msca),
            acctNonce,
            vm.toString(initCode),
            vm.toString(abi.encodeCall(IStandardExecutor.execute, (recipient, 1 wei, ""))),
            83353000,
            10286500,
            0,
            1,
            1,
            "0x"
        );

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        (address mscaAddr,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        assertTrue(mscaAddr.code.length == 0);
        // start with balance
        vm.deal(mscaAddr, 2 ether);
        TestCircleMSCA msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);
        address recipient = makeAddr("testGlobalValidationViaRuntime_recipient");
        vm.startPrank(ownerAddr);
        msca.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (recipient, 1 wei, "")),
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
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // only get address w/o deployment
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));

        (address msca,) = factory.getAddressWithValidation(ownerAddr, salt, initializingData);
        assertTrue(msca.code.length == 0);
        // nonce key is 0
        uint256 acctNonce = entryPoint.getNonce(msca, 0);
        // start with balance
        vm.deal(msca, 2 ether);
        bytes memory createAccountCall =
            abi.encodeCall(TestCircleMSCAFactory.createAccountWithValidation, (ownerAddr, salt, initializingData));
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
                    abi.encodeCall(IStandardExecutor.execute, (recipient, 1 wei, ""))
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
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
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

    function _installMultipleOwnerValidations() internal returns (TestCircleMSCA msca) {
        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        ownerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(0));
        ValidationConfig validationConfig = ValidationConfigLib.pack(ownerValidation, true, true);
        bytes memory initializingData =
            abi.encode(validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr), bytes(""), bytes(""));
        vm.startPrank(ownerAddr);
        msca = factory.createAccountWithValidation(ownerAddr, salt, initializingData);

        owner2Validation = ModuleEntityLib.pack(address(singleSignerValidationModule2), uint32(0));
        validationConfig = ValidationConfigLib.pack(owner2Validation, true, true);
        vm.startPrank(address(msca));
        msca.installValidation(
            validationConfig, new bytes4[](0), abi.encode(uint32(0), ownerAddr2), bytes(""), bytes("")
        );
        vm.stopPrank();

        vm.startPrank(address(entryPoint));
        bytes4[] memory selectors = msca.getSelectors(ownerValidation);
        assertEq(selectors.length, 0);
        selectors = msca.getSelectors(owner2Validation);
        assertEq(selectors.length, 0);
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
