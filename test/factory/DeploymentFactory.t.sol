/*
 * Copyright 2026 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity 0.8.24;

import {UnauthorizedCaller} from "../../src/common/Errors.sol";
import {DeploymentFactory} from "../../src/factory/DeploymentFactory.sol";

import {TestUtils} from "../util/TestUtils.sol";
import {Create3DeployedContractA} from "./Create3DeployedContractA.sol";
import {Create3PayableDeployedContract} from "./Create3PayableDeployedContract.sol";
import {Create3RevertingPayableDeployedContract} from "./Create3RevertingPayableDeployedContract.sol";
import {DeploymentFactoryCaller} from "./DeploymentFactoryCaller.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {CREATE3} from "solady/utils/CREATE3.sol";

contract DeploymentFactoryTest is TestUtils {
    event Create2DeployerUpdated(address indexed oldDeployer, address indexed newDeployer);
    event Create3DeployerUpdated(address indexed oldDeployer, address indexed newDeployer);
    event Create2Deployed(address indexed deployed, address indexed caller, bytes32 indexed salt);
    event Create2PermissionlessDeployed(address indexed deployed, address indexed caller, bytes32 indexed salt);
    event Create3Deployed(address indexed deployed, address indexed caller, bytes32 indexed salt);

    address private owner;
    DeploymentFactory private factory;
    DeploymentFactoryCaller private create2Deployer;
    DeploymentFactoryCaller private create3Deployer;
    DeploymentFactoryCaller private unauthorizedCaller;

    function setUp() public {
        owner = makeAddr("owner");

        DeploymentFactory impl = new DeploymentFactory();
        ERC1967Proxy proxy =
            new ERC1967Proxy(address(impl), abi.encodeWithSelector(DeploymentFactory.initialize.selector, owner));
        factory = DeploymentFactory(address(proxy));

        create2Deployer = new DeploymentFactoryCaller();
        create3Deployer = new DeploymentFactoryCaller();
        unauthorizedCaller = new DeploymentFactoryCaller();
        vm.deal(address(create2Deployer), 10 ether);
        vm.deal(address(create3Deployer), 10 ether);
        vm.deal(address(unauthorizedCaller), 10 ether);

        vm.startPrank(owner);
        factory.setCreate2Deployer(address(create2Deployer));
        factory.setCreate3Deployer(address(create3Deployer));
        vm.stopPrank();
    }

    // ========== Permissioned CREATE2 ==========

    function testDeploy2PermissionedWithDesignatedDeployer() public {
        bytes32 salt = keccak256("deployCreate2-deployer");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(7)));
        address predicted = factory.getCreate2Address(salt, creationCode);

        vm.expectEmit(true, true, true, false);
        emit Create2Deployed(predicted, address(create2Deployer), salt);

        address deployed = create2Deployer.deployCreate2(factory, salt, creationCode);
        assertEq(deployed, predicted);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 7);
    }

    function testDeploy2PermissionedRevertsForUnauthorizedCaller() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.expectRevert(UnauthorizedCaller.selector);
        unauthorizedCaller.deployCreate2(factory, bytes32(uint256(1)), creationCode);
    }

    function testDeploy2PermissionedSupportsPayableConstructors() public {
        bytes32 salt = keccak256("deployCreate2-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        address deployed = create2Deployer.deployCreate2(factory, 1 ether, salt, creationCode);
        assertEq(address(deployed).balance, 1 ether);
        assertEq(Create3PayableDeployedContract(deployed).INITIAL_BALANCE(), 1 ether);
    }

    function testDeploy2PermissionedPayableRevertsForUnauthorizedCaller() public {
        bytes32 salt = keccak256("deployCreate2-unauthorized-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        vm.expectRevert(UnauthorizedCaller.selector);
        unauthorizedCaller.deployCreate2(factory, 1 ether, salt, creationCode);
    }

    function testDeploy2PermissionedRevertsOnValueMismatch() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.prank(address(create2Deployer));
        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.NativeValueMismatch.selector, 1 ether, 0));
        factory.deployCreate2(1 ether, bytes32(uint256(1)), creationCode);
    }

    function testDeploy2PermissionedRevertsOnEmptyCreationCode() public {
        vm.prank(address(create2Deployer));
        vm.expectRevert(DeploymentFactory.EmptyCreationCode.selector);
        factory.deployCreate2(bytes32(uint256(1)), "");
    }

    function testDeploy2PermissionedDuplicateReverts() public {
        bytes32 salt = keccak256("deployCreate2-dup");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(11)));
        address predicted = factory.getCreate2Address(salt, creationCode);

        create2Deployer.deployCreate2(factory, salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.ContractAlreadyDeployed.selector, predicted));
        create2Deployer.deployCreate2(factory, salt, creationCode);
    }

    function testGetCreate2AddressSameSaltSameCodeReturnsSameAddress() public view {
        bytes32 salt = keccak256("same-salt-same-code");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(42)));

        address predicted1 = factory.getCreate2Address(salt, creationCode);
        address predicted2 = factory.getCreate2Address(salt, creationCode);
        assertEq(predicted1, predicted2);
    }

    function testPayableDeploy2PermissionedWithZeroValueSucceeds() public {
        bytes32 salt = keccak256("deployCreate2-payable-zero");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(9)));

        address deployed = create2Deployer.deployCreate2(factory, 0, salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 9);
    }

    function testPayableDeploy2PermissionedRevertingConstructorDoesNotLeaveFundsInFactory() public {
        bytes32 salt = keccak256("deployCreate2-payable-reverting");
        bytes memory creationCode = type(Create3RevertingPayableDeployedContract).creationCode;

        vm.expectRevert();
        create2Deployer.deployCreate2(factory, 1 ether, salt, creationCode);

        assertEq(address(factory).balance, 0);
    }

    // ========== Permissionless CREATE2 ==========

    function testDeploy2PermissionlessFromAnyone() public {
        bytes32 salt = keccak256("deployCreate2Permissionless-anyone");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(7)));
        address predicted = factory.getCreate2PermissionlessAddress(salt, creationCode);

        vm.expectEmit(true, true, true, false);
        emit Create2PermissionlessDeployed(predicted, address(this), salt);

        address deployed = factory.deployCreate2Permissionless(salt, creationCode);
        assertEq(deployed, predicted);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 7);
    }

    function testDeploy2PermissionlessFromUnauthorizedCaller() public {
        bytes32 salt = keccak256("deployCreate2Permissionless-unauthorized");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(5)));
        address predicted = factory.getCreate2PermissionlessAddress(salt, creationCode);

        address deployed = unauthorizedCaller.deployCreate2Permissionless(factory, salt, creationCode);
        assertEq(deployed, predicted);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 5);
    }

    function testDeploy2PermissionlessDuplicateReverts() public {
        bytes32 salt = keccak256("deployCreate2Permissionless-dup");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(11)));
        address predicted = factory.getCreate2PermissionlessAddress(salt, creationCode);

        factory.deployCreate2Permissionless(salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.ContractAlreadyDeployed.selector, predicted));
        factory.deployCreate2Permissionless(salt, creationCode);
    }

    function testDeploy2PermissionlessDuplicateRevertsFromDifferentCaller() public {
        bytes32 salt = keccak256("deployCreate2Permissionless-dup-diff-caller");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(11)));
        address predicted = factory.getCreate2PermissionlessAddress(salt, creationCode);

        factory.deployCreate2Permissionless(salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.ContractAlreadyDeployed.selector, predicted));
        unauthorizedCaller.deployCreate2Permissionless(factory, salt, creationCode);
    }

    function testDeploy2PermissionlessRevertsOnEmptyCreationCode() public {
        vm.expectRevert(DeploymentFactory.EmptyCreationCode.selector);
        factory.deployCreate2Permissionless(bytes32(uint256(1)), "");
    }

    function testDeploy2PermissionlessSupportsPayableConstructors() public {
        bytes32 salt = keccak256("deployCreate2Permissionless-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        address deployed = unauthorizedCaller.deployCreate2Permissionless(factory, 1 ether, salt, creationCode);
        assertEq(address(deployed).balance, 1 ether);
        assertEq(Create3PayableDeployedContract(deployed).INITIAL_BALANCE(), 1 ether);
    }

    // ========== Salt Namespace Isolation ==========

    function testSameSaltDifferentCreate2ModesProduceDifferentAddresses() public view {
        bytes32 salt = keccak256("same-salt-cross-mode");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        address permissionless = factory.getCreate2PermissionlessAddress(salt, creationCode);
        address permissioned = factory.getCreate2Address(salt, creationCode);
        assertTrue(permissionless != permissioned);
    }

    function testPermissionlessCannotSquatPermissionedAddress() public {
        bytes32 salt = keccak256("squatting-attempt");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        factory.deployCreate2Permissionless(salt, creationCode);

        address deployed = create2Deployer.deployCreate2(factory, salt, creationCode);
        address predicted = factory.getCreate2Address(salt, creationCode);
        assertEq(deployed, predicted);
    }

    function testAllThreeModesProduceDifferentAddresses() public view {
        bytes32 salt = keccak256("all-modes");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        address create2Addr = factory.getCreate2Address(salt, creationCode);
        address create2PermissionlessAddr = factory.getCreate2PermissionlessAddress(salt, creationCode);
        address create3Addr = factory.getCreate3Address(salt);

        assertTrue(create2Addr != create2PermissionlessAddr);
        assertTrue(create2Addr != create3Addr);
        assertTrue(create2PermissionlessAddr != create3Addr);
    }

    function testSameSaltAllThreeModesDeploySuccessfully() public {
        bytes32 salt = keccak256("all-modes-deploy");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        address predicted2 = factory.getCreate2Address(salt, creationCode);
        address predicted2Open = factory.getCreate2PermissionlessAddress(salt, creationCode);
        address predicted3 = factory.getCreate3Address(salt);

        address deployed2 = create2Deployer.deployCreate2(factory, salt, creationCode);
        address deployed2Open = factory.deployCreate2Permissionless(salt, creationCode);
        address deployed3 = create3Deployer.deployCreate3(factory, salt, creationCode);

        assertEq(deployed2, predicted2);
        assertEq(deployed2Open, predicted2Open);
        assertEq(deployed3, predicted3);

        assertTrue(deployed2 != deployed2Open);
        assertTrue(deployed2 != deployed3);
        assertTrue(deployed2Open != deployed3);
    }

    // ========== Permissioned CREATE3 ==========

    function testDeploy3WithDesignatedDeployer() public {
        bytes32 salt = keccak256("deployCreate3-deployer");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(7)));
        address predicted = factory.getCreate3Address(salt);

        vm.expectEmit(true, true, true, false);
        emit Create3Deployed(predicted, address(create3Deployer), salt);

        address deployed = create3Deployer.deployCreate3(factory, salt, creationCode);
        assertEq(deployed, predicted);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 7);
    }

    function testDeploy3RevertsForUnauthorizedCaller() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.expectRevert(UnauthorizedCaller.selector);
        unauthorizedCaller.deployCreate3(factory, bytes32(uint256(1)), creationCode);
    }

    function testDeploy3RevertsForCreate2DeployerCallingCreate3() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.expectRevert(UnauthorizedCaller.selector);
        create2Deployer.deployCreate3(factory, bytes32(uint256(1)), creationCode);
    }

    function testGetCreate3AddressPredictionIsStableAcrossDeployment() public {
        bytes32 salt = keccak256("deployCreate3-same-addr");
        bytes memory codeA = abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        address predicted1 = factory.getCreate3Address(salt);

        address deployed = create3Deployer.deployCreate3(factory, salt, codeA);
        assertEq(deployed, predicted1);

        address predicted2 = factory.getCreate3Address(salt);
        assertEq(predicted1, predicted2);
    }

    function testCreate3AddressIsBytecodeIndependent() public view {
        bytes32 salt = keccak256("bytecode-independent");
        bytes memory codeA = abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));
        bytes memory codeB = type(Create3PayableDeployedContract).creationCode;

        // CREATE3 address depends only on salt, not bytecode
        // getCreate3Address doesn't take creationCode — same salt always yields same address
        address predicted = factory.getCreate3Address(salt);

        // Verify it's stable regardless of what code we intend to deploy
        assertTrue(keccak256(codeA) != keccak256(codeB));
        assertEq(predicted, factory.getCreate3Address(salt));
    }

    function testDeploy3DuplicateReverts() public {
        bytes32 salt = keccak256("deployCreate3-dup");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(11)));
        address predicted = factory.getCreate3Address(salt);

        create3Deployer.deployCreate3(factory, salt, creationCode);

        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.ContractAlreadyDeployed.selector, predicted));
        create3Deployer.deployCreate3(factory, salt, creationCode);
    }

    function testDeploy3SupportsPayableConstructors() public {
        bytes32 salt = keccak256("deployCreate3-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        address deployed = create3Deployer.deployCreate3(factory, 1 ether, salt, creationCode);
        assertEq(address(deployed).balance, 1 ether);
        assertEq(Create3PayableDeployedContract(deployed).INITIAL_BALANCE(), 1 ether);
    }

    function testDeploy3RevertsOnEmptyCreationCode() public {
        vm.expectRevert(DeploymentFactory.EmptyCreationCode.selector);
        create3Deployer.deployCreate3(factory, bytes32(uint256(1)), "");
    }

    function testDeploy3RevertsOnValueMismatch() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        vm.prank(address(create3Deployer));
        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.NativeValueMismatch.selector, 1 ether, 0));
        factory.deployCreate3(1 ether, bytes32(uint256(1)), creationCode);
    }

    function testPayableDeploy3WithZeroValueSucceeds() public {
        bytes32 salt = keccak256("deployCreate3-payable-zero");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(9)));

        address deployed = create3Deployer.deployCreate3(factory, 0, salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 9);
    }

    function testDeploy3RevertsWhenNonPayableVariantReceivesEth() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        (bool success,) = address(factory).call{value: 1 ether}(
            abi.encodeWithSignature("deployCreate3(bytes32,bytes)", bytes32(uint256(1)), creationCode)
        );

        assertFalse(success);
    }

    function testPayableDeploy3RevertsForUnauthorizedCaller() public {
        bytes32 salt = keccak256("deployCreate3-unauthorized-payable");
        bytes memory creationCode = type(Create3PayableDeployedContract).creationCode;

        vm.expectRevert(UnauthorizedCaller.selector);
        unauthorizedCaller.deployCreate3(factory, 1 ether, salt, creationCode);
    }

    function testPayableDeploy3RevertingConstructorDoesNotLeaveFundsInFactory() public {
        bytes32 salt = keccak256("deployCreate3-payable-reverting");
        bytes memory creationCode = type(Create3RevertingPayableDeployedContract).creationCode;

        vm.expectRevert();
        create3Deployer.deployCreate3(factory, 1 ether, salt, creationCode);

        assertEq(address(factory).balance, 0);
    }

    // ========== Admin ==========

    function testSetCreate2Deployer() public {
        address newDeployer = makeAddr("newCreate2Deployer");

        vm.expectEmit(true, true, false, false);
        emit Create2DeployerUpdated(address(create2Deployer), newDeployer);
        vm.prank(owner);
        factory.setCreate2Deployer(newDeployer);

        assertEq(factory.create2Deployer(), newDeployer);
    }

    function testSetCreate3Deployer() public {
        address newDeployer = makeAddr("newCreate3Deployer");

        vm.expectEmit(true, true, false, false);
        emit Create3DeployerUpdated(address(create3Deployer), newDeployer);
        vm.prank(owner);
        factory.setCreate3Deployer(newDeployer);

        assertEq(factory.create3Deployer(), newDeployer);
    }

    function testSetDeployerToZeroDisablesPermissionedMode() public {
        vm.prank(owner);
        factory.setCreate2Deployer(address(0));
        assertEq(factory.create2Deployer(), address(0));

        // Previously authorized deployer can no longer deploy
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));
        vm.expectRevert(UnauthorizedCaller.selector);
        create2Deployer.deployCreate2(factory, bytes32(uint256(1)), creationCode);

        vm.prank(owner);
        factory.setCreate3Deployer(address(0));
        assertEq(factory.create3Deployer(), address(0));

        vm.expectRevert(UnauthorizedCaller.selector);
        create3Deployer.deployCreate3(factory, bytes32(uint256(1)), creationCode);
    }

    function testDisableAndReEnableDeployer() public {
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        // Disable
        vm.prank(owner);
        factory.setCreate3Deployer(address(0));

        vm.expectRevert(UnauthorizedCaller.selector);
        create3Deployer.deployCreate3(factory, bytes32(uint256(1)), creationCode);

        // Re-enable
        vm.prank(owner);
        factory.setCreate3Deployer(address(create3Deployer));

        bytes32 salt = keccak256("re-enabled");
        address deployed = create3Deployer.deployCreate3(factory, salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 1);
    }

    function testOnlyOwnerCanSetDeployers() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        factory.setCreate2Deployer(makeAddr("x"));

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        factory.setCreate3Deployer(makeAddr("x"));
    }

    function testDeployerRotation() public {
        DeploymentFactoryCaller newDeployer = new DeploymentFactoryCaller();

        vm.prank(owner);
        factory.setCreate3Deployer(address(newDeployer));

        // Old deployer can no longer deploy
        vm.expectRevert(UnauthorizedCaller.selector);
        create3Deployer.deployCreate3(
            factory,
            bytes32(uint256(1)),
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)))
        );

        // New deployer works
        bytes32 salt = keccak256("rotated");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(42)));
        address deployed = newDeployer.deployCreate3(factory, salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 42);
    }

    function testOwnershipTransferTwoStep() public {
        address newOwner = makeAddr("newOwner");
        address notPendingOwner = makeAddr("notPendingOwner");

        vm.prank(owner);
        factory.transferOwnership(newOwner);

        assertEq(factory.owner(), owner);
        assertEq(factory.pendingOwner(), newOwner);

        vm.prank(notPendingOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, notPendingOwner));
        factory.acceptOwnership();

        vm.prank(newOwner);
        factory.acceptOwnership();

        assertEq(factory.owner(), newOwner);
        assertEq(factory.pendingOwner(), address(0));
    }

    function testRenounceOwnershipReverts() public {
        vm.prank(owner);
        vm.expectRevert(DeploymentFactory.RenounceOwnershipNotAllowed.selector);
        factory.renounceOwnership();
    }

    // ========== Initialization ==========

    function testInitializeRevertsOnZeroOwner() public {
        DeploymentFactory impl = new DeploymentFactory();
        vm.expectRevert(abi.encodeWithSelector(DeploymentFactory.InvalidOwner.selector, address(0)));
        new ERC1967Proxy(address(impl), abi.encodeWithSelector(DeploymentFactory.initialize.selector, address(0)));
    }

    function testCannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        factory.initialize(makeAddr("attacker"));
    }

    function testImplementationCannotBeInitialized() public {
        DeploymentFactory impl = new DeploymentFactory();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(owner);
    }

    // ========== Upgrade ==========

    function testOwnerCanUpgrade() public {
        DeploymentFactory newImpl = new DeploymentFactory();

        vm.prank(owner);
        factory.upgradeToAndCall(address(newImpl), "");

        bytes32 salt = keccak256("post-upgrade");
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(99)));

        address deployed = factory.deployCreate2Permissionless(salt, creationCode);
        assertEq(Create3DeployedContractA(deployed).VALUE(), 99);
    }

    function testNonOwnerCannotUpgrade() public {
        DeploymentFactory newImpl = new DeploymentFactory();
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, attacker));
        factory.upgradeToAndCall(address(newImpl), "");
    }

    function testStatePreservedAcrossUpgrade() public {
        DeploymentFactory newImpl = new DeploymentFactory();
        vm.prank(owner);
        factory.upgradeToAndCall(address(newImpl), "");

        assertEq(factory.create2Deployer(), address(create2Deployer));
        assertEq(factory.create3Deployer(), address(create3Deployer));
        assertEq(factory.owner(), owner);
    }

    // ========== Salt prefix lock ==========

    function testSaltPrefixConstantsMatchExpectedKeccakValues() public view {
        bytes32 salt = bytes32(uint256(0xC1A551CA1));
        bytes memory creationCode =
            abi.encodePacked(type(Create3DeployedContractA).creationCode, abi.encode(uint256(1)));

        // Mirror DeploymentFactory._namespacedSalt with the prefixes we expect.
        bytes32 expectedCreate2Salt = keccak256(abi.encode(keccak256("deployCreate2"), salt));
        bytes32 expectedCreate2PermissionlessSalt =
            keccak256(abi.encode(keccak256("deployCreate2Permissionless"), salt));
        bytes32 expectedCreate3Salt = keccak256(abi.encode(keccak256("deployCreate3"), salt));

        address expectedCreate2Address =
            Create2.computeAddress(expectedCreate2Salt, keccak256(creationCode), address(factory));
        address expectedCreate2PermissionlessAddress =
            Create2.computeAddress(expectedCreate2PermissionlessSalt, keccak256(creationCode), address(factory));
        address expectedCreate3Address = CREATE3.predictDeterministicAddress(expectedCreate3Salt, address(factory));

        assertEq(factory.getCreate2Address(salt, creationCode), expectedCreate2Address);
        assertEq(factory.getCreate2PermissionlessAddress(salt, creationCode), expectedCreate2PermissionlessAddress);
        assertEq(factory.getCreate3Address(salt), expectedCreate3Address);
    }
}
