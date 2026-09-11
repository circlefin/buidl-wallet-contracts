/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.

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

import {InvalidLength, UnauthorizedCaller} from "../../src/common/Errors.sol";
import {Create3Factory} from "../../src/factory/Create3Factory.sol";
import {ICreate3Factory} from "../../src/factory/ICreate3Factory.sol";

import {TestUtils} from "../util/TestUtils.sol";
import {Create3DeployedContractA} from "./Create3DeployedContractA.sol";
import {Create3DeployedContractB} from "./Create3DeployedContractB.sol";
import {Create3FactoryCaller} from "./Create3FactoryCaller.sol";
import {Create3PayableDeployedContract} from "./Create3PayableDeployedContract.sol";
import {Create3RevertingPayableDeployedContract} from "./Create3RevertingPayableDeployedContract.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Vm} from "forge-std/src/Vm.sol";

contract Create3FactoryTest is TestUtils {
    event CallerPermissionSet(address indexed caller, bool allowed);
    event ContractDeployed(address indexed deployed, address indexed caller, bytes32 indexed salt);

    address private owner;
    Create3Factory private factory;
    Create3FactoryCaller private allowedCaller;
    Create3FactoryCaller private disallowedCaller;

    function setUp() public {
        owner = makeAddr("owner");
        factory = new Create3Factory(owner);
        allowedCaller = new Create3FactoryCaller();
        disallowedCaller = new Create3FactoryCaller();
        vm.deal(address(allowedCaller), 10 ether);
        vm.deal(address(disallowedCaller), 10 ether);
    }

    function testDeployWithAllowedFactory() public {
        bytes32 salt = keccak256("allowed");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(7)));
        address predicted = factory.getAddress(salt);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        vm.expectEmit(true, true, true, false);
        emit ContractDeployed(predicted, address(allowedCaller), salt);

        address deployed = allowedCaller.deploy(factory, salt, creationCode);
        assertEq(deployed, predicted);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 7);
    }

    function testDeployRevertsForUnauthorizedCaller() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.expectRevert(UnauthorizedCaller.selector);
        factory.deploy(bytes32(uint256(1)), creationCode);
    }

    function testGetAddressMatchesDeployedAddress() public {
        bytes32 salt = keccak256("predicted");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractB).creationCode, abi.encode(makeAddr("predictedOwner")));
        address predicted = factory.getAddress(salt);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        address deployed = factory.deploy(salt, creationCode);
        assertEq(deployed, predicted);
    }

    function testSameSaltCannotBeDeployedTwice() public {
        bytes32 salt = keccak256("duplicate");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(11)));
        address predicted = factory.getAddress(salt);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        factory.deploy(salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(Create3Factory.ContractAlreadyDeployed.selector, predicted));
        factory.deploy(salt, creationCode);
    }

    function testDifferentSaltsYieldDifferentAddresses() public {
        bytes32 saltOne = keccak256("salt-one");
        bytes32 saltTwo = keccak256("salt-two");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(5)));

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        address deployedOne = factory.deploy(saltOne, creationCode);
        address deployedTwo = factory.deploy(saltTwo, creationCode);

        assertTrue(deployedOne != deployedTwo);
    }

    function testDifferentCreationCodeSameSaltHasSamePredictedAddress() public {
        bytes32 salt = keccak256("same-salt");
        bytes memory creationCodeOne =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(123)));
        bytes memory creationCodeTwo =
            abi.encodePacked(type(Create3DeployedContractB).creationCode, abi.encode(makeAddr("owner-two")));
        address predictedOne = factory.getAddress(salt);
        address predictedTwo = factory.getAddress(salt);

        assertEq(predictedOne, predictedTwo);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        address deployed = factory.deploy(salt, creationCodeOne);
        assertEq(deployed, predictedOne);

        vm.expectRevert(abi.encodeWithSelector(Create3Factory.ContractAlreadyDeployed.selector, predictedOne));
        factory.deploy(salt, creationCodeTwo);
    }

    function testDeploySupportsPayableConstructors() public {
        bytes32 salt = keccak256("payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        address deployed = allowedCaller.deploy(factory, 1 ether, salt, creationCode);
        assertEq(address(deployed).balance, 1 ether);
        assertEq(Create3PayableDeployedContract(deployed).INITIAL_BALANCE(), 1 ether);
    }

    function testPayableDeployWithZeroValueSucceeds() public {
        bytes32 salt = keccak256("payable-zero");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(9)));

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        address deployed = allowedCaller.deploy(factory, 0, salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 9);
    }

    function testDeployRevertsOnNativeValueMismatch() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        vm.expectRevert(abi.encodeWithSelector(Create3Factory.NativeValueMismatch.selector, 1 ether, 0));
        factory.deploy(1 ether, bytes32(uint256(1)), creationCode);
    }

    function testDeployRevertsWhenNonPayableVariantReceivesEth() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        (bool success,) = address(factory).call{value: 1 ether}(
            abi.encodeWithSignature("deploy(bytes32,bytes)", bytes32(uint256(1)), creationCode)
        );

        assertFalse(success);
    }

    function testPayableDeployRevertsForUnauthorizedCaller() public {
        bytes32 salt = keccak256("unauthorized-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        vm.expectRevert(UnauthorizedCaller.selector);
        disallowedCaller.deploy(factory, 1 ether, salt, creationCode);
    }

    function testPayableDeployRevertsOnEmptyCreationCode() public {
        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        vm.expectRevert(Create3Factory.EmptyCreationCode.selector);
        factory.deploy{value: 1 ether}(1 ether, bytes32(uint256(1)), "");
    }

    function testPayableDeploySameSaltCannotBeDeployedTwice() public {
        bytes32 salt = keccak256("payable-duplicate");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;
        address predicted = factory.getAddress(salt);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        allowedCaller.deploy(factory, 1 ether, salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(Create3Factory.ContractAlreadyDeployed.selector, predicted));
        allowedCaller.deploy(factory, 1 ether, salt, creationCode);
    }

    function testPayableDeployRevertingConstructorDoesNotLeaveFundsInFactory() public {
        bytes32 salt = keccak256("payable-reverting");
        bytes memory creationCode = type(Create3RevertingPayableDeployedContract).creationCode;

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        vm.expectRevert();
        allowedCaller.deploy(factory, 1 ether, salt, creationCode);

        assertEq(address(factory).balance, 0);
    }

    function testSetCallersCanAllowAndUnallow() public {
        address[] memory callers = new address[](2);
        bool[] memory permissions = new bool[](2);
        callers[0] = address(allowedCaller);
        callers[1] = address(disallowedCaller);
        permissions[0] = true;
        permissions[1] = true;

        vm.startPrank(owner);
        vm.expectEmit(true, false, false, true);
        emit CallerPermissionSet(address(allowedCaller), true);
        vm.expectEmit(true, false, false, true);
        emit CallerPermissionSet(address(disallowedCaller), true);
        factory.setCallers(callers, permissions);
        vm.stopPrank();

        assertTrue(factory.isCallerAllowed(address(allowedCaller)));
        assertTrue(factory.isCallerAllowed(address(disallowedCaller)));

        permissions[1] = false;
        vm.prank(owner);
        factory.setCallers(callers, permissions);

        assertTrue(factory.isCallerAllowed(address(allowedCaller)));
        assertFalse(factory.isCallerAllowed(address(disallowedCaller)));
    }

    function testSetCallersDoesNotEmitForUnchangedPermissions() public {
        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        vm.recordLogs();
        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 0);
        assertTrue(factory.isCallerAllowed(address(allowedCaller)));
    }

    function testSetCallersRevertsOnMismatchedLengths() public {
        address[] memory callers = new address[](1);
        bool[] memory permissions = new bool[](2);
        callers[0] = address(allowedCaller);
        permissions[0] = true;
        permissions[1] = false;

        vm.prank(owner);
        vm.expectRevert(InvalidLength.selector);
        factory.setCallers(callers, permissions);
    }

    function testSetCallersRevertsOnZeroAddress() public {
        address[] memory callers = new address[](1);
        bool[] memory permissions = new bool[](1);
        callers[0] = address(0);
        permissions[0] = true;

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Create3Factory.InvalidCaller.selector, address(0)));
        factory.setCallers(callers, permissions);
    }

    function testConstructorRevertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Create3Factory.InvalidOwner.selector, address(0)));
        new Create3Factory(address(0));
    }

    function testOnlyOwnerCanSetCallers() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        factory.setCallers(_toAddressArray(address(allowedCaller)), _toBoolArray(true));
    }

    function testOwnershipTransferTwoStep() public {
        address newOwner = makeAddr("newOwner");
        address notPendingOwner = makeAddr("notPendingOwner");

        vm.prank(owner);
        factory.transferOwnership(newOwner);

        assertEq(factory.owner(), owner);
        assertEq(factory.pendingOwner(), newOwner);

        vm.prank(notPendingOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, notPendingOwner));
        factory.acceptOwnership();

        vm.prank(newOwner);
        factory.acceptOwnership();

        assertEq(factory.owner(), newOwner);
        assertEq(factory.pendingOwner(), address(0));
    }

    function testRenounceOwnershipDisabled() public {
        vm.prank(owner);
        vm.expectRevert(Create3Factory.RenounceOwnershipNotAllowed.selector);
        factory.renounceOwnership();
    }

    function testDeployRevertsOnEmptyCreationCode() public {
        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        vm.expectRevert(Create3Factory.EmptyCreationCode.selector);
        factory.deploy(bytes32(uint256(1)), "");
    }

    function testCreate3FactoryImplementsICreate3FactoryInterface() public {
        bytes32 salt = keccak256("interface-routing");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(42)));

        ICreate3Factory factoryAsInterface = ICreate3Factory(address(factory));
        address predictedThroughInterface = factoryAsInterface.getAddress(salt);
        address predictedThroughConcrete = factory.getAddress(salt);
        assertEq(predictedThroughInterface, predictedThroughConcrete);

        vm.prank(owner);
        factory.setCallers(_toAddressArray(address(this)), _toBoolArray(true));

        address deployed = factoryAsInterface.deploy(salt, creationCode);
        assertEq(deployed, predictedThroughInterface);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 42);
    }

    function _toAddressArray(address _value) internal pure returns (address[] memory values) {
        values = new address[](1);
        values[0] = _value;
    }

    function _toBoolArray(bool _value) internal pure returns (bool[] memory values) {
        values = new bool[](1);
        values[0] = _value;
    }
}
