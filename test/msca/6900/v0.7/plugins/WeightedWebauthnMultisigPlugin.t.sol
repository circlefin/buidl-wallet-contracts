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
    CredentialType,
    OwnerData,
    OwnershipMetadata,
    PublicKey,
    WebAuthnData,
    WebAuthnSigDynamicPart
} from "../../../../../src/common/CommonStructs.sol";
import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    PLUGIN_AUTHOR,
    PLUGIN_VERSION_1,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED
} from "../../../../../src/common/Constants.sol";

import {AddressBytesLib} from "../../../../../src/libs/AddressBytesLib.sol";
import {PublicKeyLib} from "../../../../../src/libs/PublicKeyLib.sol";

import {WebAuthnLib} from "../../../../../src/libs/WebAuthnLib.sol";
import {NotImplemented} from "../../../../../src/msca/6900/shared/common/Errors.sol";
import {PluginManifest, PluginMetadata} from "../../../../../src/msca/6900/v0.7/common/PluginManifest.sol";
import {IPlugin} from "../../../../../src/msca/6900/v0.7/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../../../src/msca/6900/v0.7/plugins/BasePlugin.sol";
import {BaseMultisigPlugin} from "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/multisig/BaseMultisigPlugin.sol";
import {IWeightedMultisigPlugin} from
    "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/multisig/IWeightedMultisigPlugin.sol";
import {WeightedWebauthnMultisigPlugin} from
    "../../../../../src/msca/6900/v0.7/plugins/v1_0_0/multisig/WeightedWebauthnMultisigPlugin.sol";

import {MockContractOwner} from "../../../../util/MockContractOwner.sol";
import {TestUtils} from "../../../../util/TestUtils.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";

import {FCL_Elliptic_ZZ} from "@fcl/FCL_elliptic.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {stdJson} from "forge-std/src/StdJson.sol";
import {VmSafe} from "forge-std/src/Vm.sol";
import {console} from "forge-std/src/console.sol";

contract WeightedWebauthnMultisigPluginTest is TestUtils {
    using ECDSA for bytes32;
    using PublicKeyLib for PublicKey[];
    using PublicKeyLib for PublicKey;
    using AddressBytesLib for address;
    using stdJson for string;

    event OwnersAdded(address account, bytes30[] owners, OwnerData[] weights);
    event OwnersRemoved(address account, bytes30[] owners, uint256 totalWeightRemoved);
    event OwnersUpdated(address account, bytes30[] owners, OwnerData[] weights);
    event ThresholdUpdated(address account, uint256 oldThresholdWeight, uint256 newThresholdWeight);

    error AlreadyInitialized();
    error EmptyOwnersNotAllowed();
    error InvalidOwner(bytes30 owner);
    error InvalidThresholdWeight();
    error InvalidTotalWeight();
    error InvalidWeight(bytes30 owner, address account, uint256 weight);
    error NotInitialized();
    error OwnerDoesNotExist(bytes30 owner);
    error OwnersWeightsMismatch();
    error ThresholdWeightExceedsTotalWeight(uint256 thresholdWeight, uint256 totalWeight);
    error TooManyOwners(uint256 currentNumOwners, uint256 numOwnersToAdd);
    error ZeroOwnersInputNotAllowed();

    WeightedWebauthnMultisigPlugin private plugin;
    address private account;
    address private ownerOne = address(1);
    address private ownerTwo = address(2);
    PublicKey private pubKeyOne = PublicKey({x: 1, y: 1});
    PublicKey private pubKeyTwo = PublicKey({x: 2, y: 2});
    uint256 private weightOne = 100;
    uint256 private weightTwo = 101;
    uint256 private pubKeyWeightOne = 100;
    uint256 private pubKeyWeightTwo = 101;
    address[] private ownerOneList;
    uint256[] private weightOneList;
    PublicKey[] private pubKeyOneList;
    uint256[] private pubKeyWeightOneList;
    uint256 private thresholdWeightOne = 1;
    uint256 private thresholdWeightTwo = 2;
    address[] private ownerTwoList;
    uint256[] private weightTwoList;
    PublicKey[] private pubKeyTwoList;
    uint256[] private pubKeyWeightTwoList;
    IEntryPoint private entryPoint;
    // TODO generate it dynamically
    uint256 private passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    uint256 private passkeyPublicKeyX = uint256(0x1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce42);
    uint256 private passkeyPublicKeyY = uint256(0x28fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d);

    struct Owner {
        bytes30 owner;
        /// A wallet with a public and private key.
        //  struct Wallet {
        //      // The wallet's address.
        //      address addr;
        //      // The wallet's public key `X`.
        //      uint256 publicKeyX;
        //      // The wallet's public key `Y`.
        //      uint256 publicKeyY;
        //      // The wallet's private key.
        //      uint256 privateKey;
        //  }
        VmSafe.Wallet signerWallet;
        uint8 sigType; // e.g. 0: contract 2: r1, see Smart_Contract_Signatures_Encoding.md
    }

    struct TestKey {
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    uint256 internal constant _MAX_OWNERS = 1000;
    uint256 internal constant _MAX_WEIGHT = 1000000;
    string internal constant _NAME = "Weighted Multisig Webauthn Plugin";
    // fixture source
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/5212e8eb1830be145cc7b6b2c955c7667a74e14c/test/utils/cryptography/ECDSA.test.js#L198
    bytes internal constant INVALID_ECDSA_SIGNATURE =
        "0xe742ff452d41413616a5bf43fe15dd88294e983d3d36206c2712f39083d638bde0a0fc89be718fbc1033e1d30d78be1c68081562ed2e97af876f286f3453231d1b";
    string internal constant P256_10_KEYS_FIXTURE = "/test/fixtures/p256key_10_fixture.json";

    function setUp() public {
        entryPoint = IEntryPoint(address(new EntryPoint()));
        plugin = new WeightedWebauthnMultisigPlugin(address(entryPoint));
        account = vm.addr(1);
        vm.prank(account);
        ownerOneList.push(ownerOne);
        weightOneList.push(weightOne);
        ownerTwoList.push(ownerTwo);
        weightTwoList.push(weightTwo);
        pubKeyOneList.push(pubKeyOne);
        pubKeyWeightOneList.push(pubKeyWeightOne);
        pubKeyTwoList.push(pubKeyTwo);
        pubKeyWeightTwoList.push(pubKeyWeightTwo);
    }

    function test_onInstall() public {
        _install();
    }

    function test_onInstall_alreadyInitialized() public {
        _install();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(AlreadyInitialized.selector));
        plugin.onInstall(
            abi.encode(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList, thresholdWeightOne)
        );
    }

    function test_onInstall_ownerWeightsMismatch() public {
        uint256[] memory _twoWeightsList = new uint256[](2);

        _twoWeightsList[0] = weightOne;
        _twoWeightsList[1] = weightTwo;

        vm.expectRevert(OwnersWeightsMismatch.selector);
        plugin.onInstall(
            abi.encode(ownerOneList, _twoWeightsList, pubKeyOneList, pubKeyWeightOneList, thresholdWeightOne)
        );
    }

    function test_onInstall_invalidThresholdWeight() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidThresholdWeight.selector));
        plugin.onInstall(abi.encode(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList, 0));
    }

    function test_onInstall_tooManyOwners() public {
        address[] memory _addresses = new address[](_MAX_OWNERS + 1);
        uint256[] memory _weights = new uint256[](_MAX_OWNERS + 1);
        PublicKey[] memory _pubKeys = new PublicKey[](_MAX_OWNERS + 1);

        // (This might be worth optimizing / mocking, but it still runs in ~70ms)
        for (uint256 i = 1; i <= _MAX_OWNERS + 1; i++) {
            _addresses[i - 1] = vm.addr(i);
            _weights[i - 1] = 1;
            _pubKeys[i - 1] = PublicKey(i, i);
        }

        vm.expectRevert(abi.encodeWithSelector(TooManyOwners.selector, 0, _MAX_OWNERS * 2 + 2));
        plugin.onInstall(abi.encode(_addresses, _weights, _pubKeys, _weights, thresholdWeightOne));
    }

    function test_onInstall_thresholdWeightExceedsTotalWeight() public {
        uint256 _newThresholdWeight = 99999999;

        vm.expectRevert(abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, 0, _newThresholdWeight));
        plugin.onInstall(
            abi.encode(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList, _newThresholdWeight)
        );
    }

    function test_onInstall_invalidOwner_addressZero() public {
        address[] memory badOwnersToAdd = new address[](1);
        badOwnersToAdd[0] = address(0);

        vm.expectRevert(abi.encodeWithSelector(InvalidOwner.selector, badOwnersToAdd[0]));
        plugin.onInstall(
            abi.encode(badOwnersToAdd, weightOneList, pubKeyOneList, pubKeyWeightOneList, thresholdWeightOne)
        );
    }

    function test_onInstall_invalidWeight_overOneMillion() public {
        uint256 _invalidWeight = _MAX_WEIGHT + 1;
        uint256[] memory _invalidWeightList = new uint256[](1);
        _invalidWeightList[0] = _invalidWeight;

        vm.expectRevert(abi.encodeWithSelector(InvalidWeight.selector, ownerOne.toBytes30(), account, _invalidWeight));
        plugin.onInstall(
            abi.encode(ownerOneList, _invalidWeightList, pubKeyOneList, pubKeyWeightOneList, thresholdWeightOne)
        );
    }

    function test_onUninstall() public {
        _install();
        vm.prank(account);

        (bytes30[] memory _tOwners,) = _mergeOwnersData(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList);
        vm.expectEmit(true, true, true, true);
        emit OwnersRemoved(account, _reverseBytes30Array(_tOwners), weightOne + pubKeyWeightOne);

        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, thresholdWeightOne, 0);

        plugin.onUninstall(abi.encode(""));
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        assertEq(returnedOwners.length, 0);
        assertEq(returnedOwnersData.length, 0);
        assertEq(returnedThresholdWeight, 0);

        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerOne.toBytes30(), account);
        assertEq(res, 0);
        (res,,,,) = plugin.ownerDataPerAccount(pubKeyOne.toBytes30(), account);
        assertEq(res, 0);
    }

    function test_pluginManifest() public {
        PluginManifest memory manifest = plugin.pluginManifest();
        // 4 execution functions (addOwners, removeOwners, updateMultisigWeights, isValidSignature,
        // getReplaySafeMessageHash)
        assertEq(5, manifest.executionFunctions.length);

        // 8 native + 1 plugin exec func
        assertEq(9, manifest.userOpValidationFunctions.length);

        // 11 runtime validations (isValidSignature, getReplaySafeMessageHash, 9 disabled functions)
        assertEq(11, manifest.runtimeValidationFunctions.length);
    }

    function test_pluginMetadata() public {
        PluginMetadata memory metadata = plugin.pluginMetadata();

        string memory addOwnersPermission = "Add Owners";
        string memory updateMultisigWeightsPermission = "Update Multisig Weights";
        string memory removeOwnersPermission = "Remove Owners";

        assertEq(metadata.name, _NAME);
        assertEq(metadata.version, PLUGIN_VERSION_1);
        assertEq(metadata.author, PLUGIN_AUTHOR);

        assertEq(metadata.permissionDescriptors[0].functionSelector, WeightedWebauthnMultisigPlugin.addOwners.selector);
        assertEq(metadata.permissionDescriptors[0].permissionDescription, addOwnersPermission);
        assertEq(
            metadata.permissionDescriptors[1].functionSelector,
            WeightedWebauthnMultisigPlugin.updateMultisigWeights.selector
        );
        assertEq(metadata.permissionDescriptors[1].permissionDescription, updateMultisigWeightsPermission);
        assertEq(
            metadata.permissionDescriptors[2].functionSelector, WeightedWebauthnMultisigPlugin.removeOwners.selector
        );
        assertEq(metadata.permissionDescriptors[2].permissionDescription, removeOwnersPermission);
    }

    function test_runtimeValidationFunction_ownerOrSelf(uint8 functionId) public {
        vm.expectRevert(
            abi.encodeWithSelector(NotImplemented.selector, BasePlugin.runtimeValidationFunction.selector, functionId)
        );
        plugin.runtimeValidationFunction(functionId, account, 0, "");
    }

    function test_addOwners() public {
        _install();
        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, thresholdWeightTwo);
    }

    function testFuzz_addOwners(
        address owner1,
        address owner2,
        address owner3,
        uint256 weight1,
        uint256 weight2,
        uint256 weight3,
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 pubKeyWeight1,
        uint256 pubKeyWeight2,
        uint256 pubKeyWeight3
    ) public {
        vm.assume(owner1 != address(0));
        vm.assume(owner2 != address(0));
        vm.assume(owner3 != address(0));
        vm.assume(owner1 != owner2);
        vm.assume(owner2 != owner3);
        vm.assume(owner3 != owner1);

        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));
        vm.assume(pubKey1.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner3.toBytes30());

        weight1 = bound(weight1, 1, _MAX_WEIGHT);
        weight2 = bound(weight2, 1, _MAX_WEIGHT);
        weight3 = bound(weight3, 1, _MAX_WEIGHT);

        pubKeyWeight1 = bound(pubKeyWeight1, 1, _MAX_WEIGHT);
        pubKeyWeight2 = bound(pubKeyWeight2, 1, _MAX_WEIGHT);
        pubKeyWeight3 = bound(pubKeyWeight3, 1, _MAX_WEIGHT);

        address[] memory initialOwners = new address[](2);
        initialOwners[0] = owner1;
        initialOwners[1] = owner2;

        PublicKey[] memory initialPubKeys = new PublicKey[](2);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;

        uint256[] memory initialWeights = new uint256[](2);
        initialWeights[0] = weight1;
        initialWeights[1] = weight2;

        uint256[] memory initialPubKeyWeights = new uint256[](2);
        initialPubKeyWeights[0] = pubKeyWeight1;
        initialPubKeyWeights[1] = pubKeyWeight2;

        uint256 initialThresholdWeight = weight1 + weight2 + pubKeyWeight1 + pubKeyWeight2;
        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        assertEq(returnedOwners.length, 4);
        assertEq(returnedOwnersData.length, 4);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey2.toBytes30());
        assertEq(returnedOwnersData[0].weight, pubKeyWeight2);
        assertEq(uint8(returnedOwnersData[0].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersData[0].addr, address(0));
        assertEq(returnedOwnersData[0].publicKeyX, pubKey2.x);
        assertEq(returnedOwnersData[0].publicKeyY, pubKey2.y);

        assertEq(returnedOwners[1], pubKey1.toBytes30());
        assertEq(returnedOwnersData[1].weight, pubKeyWeight1);
        assertEq(uint8(returnedOwnersData[1].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersData[1].addr, address(0));
        assertEq(returnedOwnersData[1].publicKeyX, pubKey1.x);
        assertEq(returnedOwnersData[1].publicKeyY, pubKey1.y);

        assertEq(returnedOwners[2], owner2.toBytes30());
        assertEq(returnedOwnersData[2].weight, weight2);
        assertEq(uint8(returnedOwnersData[2].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersData[2].addr, owner2);
        assertEq(returnedOwnersData[2].publicKeyX, uint256(0));
        assertEq(returnedOwnersData[2].publicKeyY, uint256(0));

        assertEq(returnedOwners[3], owner1.toBytes30());
        assertEq(returnedOwnersData[3].weight, weight1);
        assertEq(uint8(returnedOwnersData[3].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersData[3].addr, owner1);
        assertEq(returnedOwnersData[3].publicKeyX, uint256(0));
        assertEq(returnedOwnersData[3].publicKeyY, uint256(0));

        assertEq(returnedThresholdWeight, initialThresholdWeight);

        address[] memory newOwners = new address[](1);
        newOwners[0] = owner3;
        PublicKey[] memory newPubKeys = new PublicKey[](1);
        newPubKeys[0] = pubKey3;

        uint256[] memory newWeights = new uint256[](1);
        newWeights[0] = weight3;
        uint256[] memory newPubKeyWeights = new uint256[](1);
        newPubKeyWeights[0] = pubKeyWeight3;

        uint256 newThresholdWeight = weight1 + weight2 + weight3 + pubKeyWeight1 + pubKeyWeight2 + pubKeyWeight3;
        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(newOwners, newWeights, newPubKeys, newPubKeyWeights);
        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, initialThresholdWeight, newThresholdWeight);
        vm.expectEmit(true, true, true, true);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.prank(account);
        plugin.addOwners(newOwners, newWeights, newPubKeys, newPubKeyWeights, newThresholdWeight);

        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedOwnersDataAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 6);
        assertEq(returnedOwnersDataAfterUpdate.length, 6);
        // new
        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, pubKeyWeight3);
        assertEq(uint8(returnedOwnersDataAfterUpdate[0].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersDataAfterUpdate[0].addr, address(0));
        assertEq(returnedOwnersDataAfterUpdate[0].publicKeyX, pubKey3.x);
        assertEq(returnedOwnersDataAfterUpdate[0].publicKeyY, pubKey3.y);

        assertEq(returnedOwnersAfterUpdate[1], owner3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, weight3);
        assertEq(uint8(returnedOwnersDataAfterUpdate[1].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersDataAfterUpdate[1].addr, owner3);
        assertEq(returnedOwnersDataAfterUpdate[1].publicKeyX, uint256(0));
        assertEq(returnedOwnersDataAfterUpdate[1].publicKeyY, uint256(0));

        // old
        assertEq(returnedOwnersAfterUpdate[2], pubKey2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[2].weight, pubKeyWeight2);
        assertEq(returnedOwnersAfterUpdate[3], pubKey1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[3].weight, pubKeyWeight1);
        assertEq(returnedOwnersAfterUpdate[4], owner2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[4].weight, weight2);
        assertEq(returnedOwnersAfterUpdate[5], owner1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[5].weight, weight1);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function test_addOwnersZeroThreshold() public {
        _install();
        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, 0);
    }

    function test_addOwnersSameThreshold() public {
        _install();
        (,, OwnershipMetadata memory ownershipMetadata) = plugin.ownershipInfoOf(account);
        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, ownershipMetadata.thresholdWeight);
    }

    function test_addOwners_notInitialized() public {
        vm.expectRevert(abi.encodeWithSelector(NotInitialized.selector));
        plugin.addOwners(ownerOneList, weightOneList, new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_zeroOwnersInputNotAllowed() public {
        _install();
        vm.prank(account);
        vm.expectRevert(ZeroOwnersInputNotAllowed.selector);
        plugin.addOwners(new address[](0), new uint256[](0), new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_ownersAndWeightsLenMismatch() public {
        _install();

        vm.prank(account);

        uint256[] memory _twoWeightsList = new uint256[](2);

        _twoWeightsList[0] = weightOne;
        _twoWeightsList[1] = weightTwo;

        vm.expectRevert(OwnersWeightsMismatch.selector);
        plugin.addOwners(ownerTwoList, _twoWeightsList, new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_tooManyOwners() public {
        _install();

        // (This might be worth optimizing / mocking, but it still runs in ~70ms)
        for (uint256 i = 1; i < _MAX_OWNERS / 2; i++) {
            address[] memory _addresses = new address[](1);
            _addresses[0] = vm.addr(i);
            PublicKey[] memory _pubKeys = new PublicKey[](1);
            _pubKeys[0] = PublicKey(i + 2, i + 2);
            vm.prank(account);
            plugin.addOwners(_addresses, weightOneList, _pubKeys, pubKeyWeightOneList, 0);
        }

        address[] memory _lastAddress = new address[](1);
        _lastAddress[0] = vm.addr(_MAX_OWNERS + 1);
        PublicKey[] memory _lastPubKeys = new PublicKey[](1);
        _lastPubKeys[0] = PublicKey(_MAX_OWNERS + 2, _MAX_OWNERS + 2);
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(TooManyOwners.selector, _MAX_OWNERS, 2));
        plugin.addOwners(_lastAddress, weightOneList, _lastPubKeys, pubKeyWeightOneList, 0);
    }

    function test_addOwners_invalidOwner_addressZero() public {
        _install();

        vm.prank(account);

        address[] memory badOwnersToAdd = new address[](1);

        vm.expectRevert(abi.encodeWithSelector(InvalidOwner.selector, address(0).toBytes30()));
        plugin.addOwners(badOwnersToAdd, weightOneList, new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_invalidWeight_zero() public {
        _install();

        uint256 _invalidWeight = 0;
        uint256[] memory _invalidWeightList = new uint256[](1);
        _invalidWeightList[0] = _invalidWeight;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidWeight.selector, ownerTwo.toBytes30(), account, _invalidWeight));
        plugin.addOwners(ownerTwoList, _invalidWeightList, new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_invalidWeight_overOneMillion() public {
        _install();

        uint256 _invalidWeight = _MAX_WEIGHT + 1;
        uint256[] memory _invalidWeightList = new uint256[](1);
        _invalidWeightList[0] = _invalidWeight;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidWeight.selector, ownerTwo.toBytes30(), account, _invalidWeight));
        plugin.addOwners(ownerTwoList, _invalidWeightList, new PublicKey[](0), new uint256[](0), thresholdWeightOne);
    }

    function test_addOwners_invalidOwner_duplicate() public {
        _install();

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidOwner.selector, ownerOne.toBytes30()));
        plugin.addOwners(ownerOneList, weightOneList, new PublicKey[](0), new uint256[](0), thresholdWeightTwo);
    }

    function test_addOwners_thresholdWeightExceedsTotalWeight() public {
        _install();

        uint256 _newThresholdWeight = 99999999;

        vm.prank(account);

        uint256 _totalWeight = weightOne + weightTwo + pubKeyWeightOne + pubKeyWeightTwo;

        vm.expectRevert(
            abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, _newThresholdWeight, _totalWeight)
        );
        plugin.addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, _newThresholdWeight);
    }

    function test_removeOwners() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, thresholdWeightTwo);

        vm.prank(account);

        (bytes30[] memory _tOwners,) = _mergeOwnersData(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList);
        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, thresholdWeightOne + thresholdWeightOne, thresholdWeightOne);
        vm.expectEmit(true, true, true, true);
        emit OwnersRemoved(account, _tOwners, weightOne + pubKeyWeightOne);

        plugin.removeOwners(ownerOneList, pubKeyOneList, thresholdWeightOne);

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedWeights,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        // Total Weight
        assertEq(_sum(returnedWeights), weightTwo + pubKeyWeightTwo);

        // Threshold weight
        assertEq(returnedThresholdWeight, thresholdWeightOne);

        // Number of owners and weights
        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners.length, returnedWeights.length);

        // Specific owners
        assertEq(returnedOwners[1], ownerTwo.toBytes30());
        assertEq(returnedOwners[0], pubKeyTwo.toBytes30());

        // Specific weight
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerTwo.toBytes30(), account);
        assertEq(res, returnedWeights[1].weight);
        (res,,,,) = plugin.ownerDataPerAccount(pubKeyTwo.toBytes30(), account);
        assertEq(res, returnedWeights[0].weight);
    }

    function testFuzz_removeOwners(
        address owner1,
        address owner2,
        address owner3,
        uint256 weight1,
        uint256 weight2,
        uint256 weight3,
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 pubKeyWeight1,
        uint256 pubKeyWeight2,
        uint256 pubKeyWeight3
    ) public {
        vm.assume(owner1 != address(0));
        vm.assume(owner2 != address(0));
        vm.assume(owner3 != address(0));
        vm.assume(owner1 != owner2);
        vm.assume(owner2 != owner3);
        vm.assume(owner3 != owner1);

        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));
        vm.assume(pubKey1.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner3.toBytes30());

        weight1 = bound(weight1, 1, _MAX_WEIGHT);
        weight2 = bound(weight2, 1, _MAX_WEIGHT);
        weight3 = bound(weight3, 1, _MAX_WEIGHT);

        pubKeyWeight1 = bound(pubKeyWeight1, 1, _MAX_WEIGHT);
        pubKeyWeight2 = bound(pubKeyWeight2, 1, _MAX_WEIGHT);
        pubKeyWeight3 = bound(pubKeyWeight3, 1, _MAX_WEIGHT);

        address[] memory initialOwners = new address[](3);
        initialOwners[0] = owner1;
        initialOwners[1] = owner2;
        initialOwners[2] = owner3;
        PublicKey[] memory initialPubKeys = new PublicKey[](3);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;
        initialPubKeys[2] = pubKey3;

        uint256[] memory initialWeights = new uint256[](3);
        initialWeights[0] = weight1;
        initialWeights[1] = weight2;
        initialWeights[2] = weight3;

        uint256[] memory initialPubKeyWeights = new uint256[](3);
        initialPubKeyWeights[0] = pubKeyWeight1;
        initialPubKeyWeights[1] = pubKeyWeight2;
        initialPubKeyWeights[2] = pubKeyWeight3;

        uint256 initialThresholdWeight = weight1 + weight2 + pubKeyWeight1 + pubKeyWeight2;

        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        assertEq(returnedOwners.length, 6);
        assertEq(returnedOwnersData.length, 6);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey3.toBytes30());
        assertEq(returnedOwnersData[0].weight, pubKeyWeight3);
        assertEq(uint8(returnedOwnersData[0].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersData[0].addr, address(0));
        assertEq(returnedOwnersData[0].publicKeyX, pubKey3.x);
        assertEq(returnedOwnersData[0].publicKeyY, pubKey3.y);

        assertEq(returnedOwners[1], pubKey2.toBytes30());
        assertEq(returnedOwnersData[1].weight, pubKeyWeight2);
        assertEq(uint8(returnedOwnersData[1].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersData[1].addr, address(0));
        assertEq(returnedOwnersData[1].publicKeyX, pubKey2.x);
        assertEq(returnedOwnersData[1].publicKeyY, pubKey2.y);

        assertEq(returnedOwners[2], pubKey1.toBytes30());
        assertEq(returnedOwnersData[2].weight, pubKeyWeight1);
        assertEq(uint8(returnedOwnersData[2].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersData[2].addr, address(0));
        assertEq(returnedOwnersData[2].publicKeyX, pubKey1.x);
        assertEq(returnedOwnersData[2].publicKeyY, pubKey1.y);

        assertEq(returnedOwners[3], owner3.toBytes30());
        assertEq(returnedOwnersData[3].weight, weight3);
        assertEq(uint8(returnedOwnersData[3].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersData[3].addr, owner3);
        assertEq(returnedOwnersData[3].publicKeyX, uint256(0));
        assertEq(returnedOwnersData[3].publicKeyY, uint256(0));

        assertEq(returnedOwners[4], owner2.toBytes30());
        assertEq(returnedOwnersData[4].weight, weight2);
        assertEq(uint8(returnedOwnersData[4].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersData[4].addr, owner2);
        assertEq(returnedOwnersData[4].publicKeyX, uint256(0));
        assertEq(returnedOwnersData[4].publicKeyY, uint256(0));

        assertEq(returnedOwners[5], owner1.toBytes30());
        assertEq(returnedOwnersData[5].weight, weight1);
        assertEq(uint8(returnedOwnersData[5].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersData[5].addr, owner1);
        assertEq(returnedOwnersData[5].publicKeyX, uint256(0));
        assertEq(returnedOwnersData[5].publicKeyY, uint256(0));

        assertEq(returnedThresholdWeight, initialThresholdWeight);

        // remove owners
        address[] memory ownersToRemove = new address[](2);
        ownersToRemove[0] = owner1;
        ownersToRemove[1] = owner2;
        PublicKey[] memory pubKeysToRemove = new PublicKey[](2);
        pubKeysToRemove[0] = pubKey1;
        pubKeysToRemove[1] = pubKey2;

        uint256 newThresholdWeight = weight3 + pubKeyWeight3;

        vm.prank(account);
        plugin.removeOwners(ownersToRemove, pubKeysToRemove, newThresholdWeight);

        // assertions
        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedOwnersDataAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 2);
        assertEq(returnedOwnersDataAfterUpdate.length, 2);

        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, pubKeyWeight3);
        assertEq(uint8(returnedOwnersDataAfterUpdate[0].credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(returnedOwnersDataAfterUpdate[0].addr, address(0));
        assertEq(returnedOwnersDataAfterUpdate[0].publicKeyX, pubKey3.x);
        assertEq(returnedOwnersDataAfterUpdate[0].publicKeyY, pubKey3.y);

        assertEq(returnedOwnersAfterUpdate[1], owner3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, weight3);
        assertEq(uint8(returnedOwnersDataAfterUpdate[1].credType), uint8(CredentialType.ADDRESS));
        assertEq(returnedOwnersDataAfterUpdate[1].addr, owner3);
        assertEq(returnedOwnersDataAfterUpdate[1].publicKeyX, uint256(0));
        assertEq(returnedOwnersDataAfterUpdate[1].publicKeyY, uint256(0));

        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function test_removeOwners_zeroThreshold() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, thresholdWeightTwo);

        vm.prank(account);
        plugin.removeOwners(ownerOneList, pubKeyOneList, 0);

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedWeights,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        // Total Weight
        assertEq(_sum(returnedWeights), weightTwo + pubKeyWeightTwo);

        // Threshold weight
        assertEq(returnedThresholdWeight, thresholdWeightTwo);

        // Number of owners and weights
        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners.length, returnedWeights.length);

        // Specific owners
        assertEq(returnedOwners[1], ownerTwo.toBytes30());
        assertEq(returnedOwners[0], pubKeyTwo.toBytes30());

        // Specific weight
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerTwo.toBytes30(), account);
        assertEq(res, returnedWeights[1].weight);
        (res,,,,) = plugin.ownerDataPerAccount(pubKeyTwo.toBytes30(), account);
        assertEq(res, returnedWeights[0].weight);
    }

    function test_removeOwners_sameThreshold() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, weightTwo + pubKeyWeightTwo);

        vm.prank(account);
        (bytes30[] memory _tOwners,) = _mergeOwnersData(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList);
        vm.expectEmit(true, true, true, true);
        emit OwnersRemoved(account, _tOwners, weightOne + pubKeyWeightOne);
        plugin.removeOwners(ownerOneList, pubKeyOneList, thresholdWeightTwo);

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedWeights,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        // Total Weight
        assertEq(_sum(returnedWeights), weightTwo + pubKeyWeightTwo);

        // Threshold weight
        assertEq(returnedThresholdWeight, thresholdWeightTwo);

        // Number of owners and weights
        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners.length, returnedWeights.length);

        // Specific owners
        assertEq(returnedOwners[1], ownerTwo.toBytes30());
        assertEq(returnedOwners[0], pubKeyTwo.toBytes30());

        // Specific weight
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerTwo.toBytes30(), account);
        assertEq(res, returnedWeights[1].weight);
        (res,,,,) = plugin.ownerDataPerAccount(pubKeyTwo.toBytes30(), account);
        assertEq(res, returnedWeights[0].weight);
    }

    function test_removeOwners_notInitialized() public {
        vm.expectRevert(abi.encodeWithSelector(NotInitialized.selector));
        plugin.removeOwners(ownerOneList, new PublicKey[](0), thresholdWeightOne);
    }

    function test_removeOwners_zeroOwnersInputNotAllowed() public {
        _install();

        address[] memory zeroOwners;

        vm.prank(account);
        vm.expectRevert(ZeroOwnersInputNotAllowed.selector);
        plugin.removeOwners(zeroOwners, new PublicKey[](0), thresholdWeightOne);
    }

    function test_removeOwners_emptyOwnersNotAllowed() public {
        _install();

        vm.prank(account);
        vm.expectRevert(EmptyOwnersNotAllowed.selector);
        plugin.removeOwners(ownerOneList, pubKeyOneList, thresholdWeightOne);
    }

    function test_removeOwners_ownerDoesNotExist() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, thresholdWeightTwo);

        address _nonExistentOwner = vm.addr(1000);
        address[] memory nonExistentOwners = new address[](1);
        nonExistentOwners[0] = _nonExistentOwner;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(OwnerDoesNotExist.selector, _nonExistentOwner.toBytes30()));
        plugin.removeOwners(nonExistentOwners, new PublicKey[](0), thresholdWeightOne);
    }

    function test_removeOwners_thresholdWeightExceedsTotalWeight_withNewThresholdWeight() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, thresholdWeightTwo);

        uint256 _newThresholdWeight = 99999999;
        uint256 _totalWeightAfterRemovingOwnerTwo = weightOne + pubKeyWeightOne;

        vm.prank(account);

        vm.expectRevert(
            abi.encodeWithSelector(
                ThresholdWeightExceedsTotalWeight.selector, _newThresholdWeight, _totalWeightAfterRemovingOwnerTwo
            )
        );
        plugin.removeOwners(ownerTwoList, pubKeyTwoList, _newThresholdWeight);
    }

    function test_removeOwners_thresholdWeightExceedsTotalWeight_withZeroThresholdWeight() public {
        _install();

        _addOwners(ownerTwoList, weightTwoList, pubKeyTwoList, pubKeyWeightTwoList, weightTwo + pubKeyWeightTwo);

        uint256 _totalWeightAfterRemovingOwnerTwo = weightOne + pubKeyWeightOne;

        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                ThresholdWeightExceedsTotalWeight.selector,
                weightTwo + pubKeyWeightTwo,
                _totalWeightAfterRemovingOwnerTwo
            )
        );
        plugin.removeOwners(ownerTwoList, pubKeyTwoList, 0);
    }

    function test_updateMultisigWeights() public {
        _install();

        uint256 _updatedWeight = 900;
        uint256[] memory _updatedWeights = new uint256[](1);
        _updatedWeights[0] = _updatedWeight;

        uint256 _newThresholdWeight = 0;

        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(ownerOneList, _updatedWeights, pubKeyOneList, _updatedWeights);
        vm.expectEmit(true, true, true, true);
        emit OwnersUpdated(account, _tOwners, _tWeights);
        vm.prank(account);
        plugin.updateMultisigWeights(ownerOneList, _updatedWeights, pubKeyOneList, _updatedWeights, _newThresholdWeight);

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedWeights,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        // Total Weight
        assertEq(_sum(returnedWeights), _updatedWeight + _updatedWeight);

        // Threshold weight
        // threshold is unchanged as it was set to 0
        assertEq(returnedThresholdWeight, thresholdWeightOne);

        // Number of owners and weights
        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners.length, returnedWeights.length);

        // Specific owners
        assertEq(returnedOwners[1], ownerOne.toBytes30());
        assertEq(returnedOwners[0], pubKeyOne.toBytes30());

        uint256 weight;
        CredentialType credType;
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        (weight, credType, addr, publicKeyX, publicKeyY) = plugin.ownerDataPerAccount(ownerOne.toBytes30(), account);
        assertEq(weight, returnedWeights[1].weight);
        assertEq(uint8(credType), uint8(CredentialType.ADDRESS));
        assertEq(addr, ownerOne);
        assertEq(publicKeyX, uint256(0));
        assertEq(publicKeyY, uint256(0));

        (weight, credType, addr, publicKeyX, publicKeyY) = plugin.ownerDataPerAccount(pubKeyOne.toBytes30(), account);
        assertEq(weight, returnedWeights[0].weight);
        assertEq(uint8(credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(addr, address(0));
        assertEq(publicKeyX, pubKeyOne.x);
        assertEq(publicKeyY, pubKeyOne.y);
    }

    function test_updateMultisigWeights_notInitialized() public {
        vm.expectRevert(abi.encodeWithSelector(NotInitialized.selector));
        plugin.updateMultisigWeights(
            ownerOneList, weightOneList, new PublicKey[](0), new uint256[](0), thresholdWeightOne
        );
    }

    function test_updateMultisigWeights_ownerWeightsMismatch() public {
        _install();

        uint256[] memory _emptyWeights = new uint256[](0);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(OwnersWeightsMismatch.selector));
        plugin.updateMultisigWeights(
            ownerOneList, _emptyWeights, new PublicKey[](0), new uint256[](0), thresholdWeightOne
        );
    }

    function test_updateMultisigWeights_invalidWeight_zero() public {
        _install();

        uint256 _updatedWeight = 0;
        uint256[] memory _updatedWeights = new uint256[](1);
        _updatedWeights[0] = _updatedWeight;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidWeight.selector, ownerOne.toBytes30(), account, _updatedWeight));
        plugin.updateMultisigWeights(
            ownerOneList, _updatedWeights, new PublicKey[](0), new uint256[](0), thresholdWeightOne
        );
    }

    function test_updateMultisigWeights_invalidWeight_overOneMillion() public {
        _install();

        uint256 _updatedWeight = _MAX_WEIGHT + 1;
        uint256[] memory _updatedWeights = new uint256[](1);
        _updatedWeights[0] = _updatedWeight;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidWeight.selector, ownerOne.toBytes30(), account, _updatedWeight));
        plugin.updateMultisigWeights(
            ownerOneList, _updatedWeights, new PublicKey[](0), new uint256[](0), thresholdWeightOne
        );
    }

    function test_updateMultisigWeights_invalidOwner_notSet() public {
        _install();

        address _nonExistentOwner = vm.addr(1000);
        address[] memory nonExistentOwners = new address[](1);
        nonExistentOwners[0] = _nonExistentOwner;

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(InvalidOwner.selector, _nonExistentOwner.toBytes30()));
        plugin.updateMultisigWeights(
            nonExistentOwners, weightOneList, new PublicKey[](0), new uint256[](0), thresholdWeightOne
        );
    }

    function test_updateMultisigWeights_modifyOnlyThreshold() public {
        _install();

        address[] memory _emptyAddresses = new address[](0);
        PublicKey[] memory _emptyPubKeys = new PublicKey[](0);
        uint256[] memory _emptyWeights = new uint256[](0);

        uint256 _newThresholdWeight = 9;

        vm.prank(account);
        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, thresholdWeightOne, _newThresholdWeight);
        plugin.updateMultisigWeights(_emptyAddresses, _emptyWeights, _emptyPubKeys, _emptyWeights, _newThresholdWeight);

        // Only threshold should be updated
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerOne.toBytes30(), account);
        assertEq(res, weightOne);
        (res,,,,) = plugin.ownerDataPerAccount(pubKeyOne.toBytes30(), account);
        assertEq(res, pubKeyWeightOne);

        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners[1], ownerOne.toBytes30());
        assertEq(returnedOwners[0], pubKeyOne.toBytes30());

        assertEq(returnedOwnersData.length, 2);
        assertEq(returnedOwnersData[1].weight, pubKeyWeightOne);
        assertEq(returnedOwnersData[0].weight, weightOne);

        assertEq(returnedThresholdWeight, _newThresholdWeight);
    }

    function testFuzz_updateMultisigWeights(
        address owner1,
        address owner2,
        address owner3,
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 weight1,
        uint256 weight2,
        uint256 weight3,
        uint256 weight4,
        uint256 weight5,
        uint256 weight6
    ) public {
        vm.assume(owner1 != address(0));
        vm.assume(owner2 != address(0));
        vm.assume(owner3 != address(0));
        vm.assume(owner1 != owner2);
        vm.assume(owner2 != owner3);
        vm.assume(owner3 != owner1);

        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));
        vm.assume(pubKey1.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey1.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner3.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner2.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner3.toBytes30());

        weight1 = bound(weight1, 1, _MAX_WEIGHT);
        weight2 = bound(weight2, 1, _MAX_WEIGHT);
        weight3 = bound(weight3, 1, _MAX_WEIGHT);
        weight4 = bound(weight4, 1, _MAX_WEIGHT);
        weight5 = bound(weight5, 1, _MAX_WEIGHT);
        weight6 = bound(weight6, 1, _MAX_WEIGHT);

        address[] memory initialOwners = new address[](3);
        initialOwners[0] = owner1;
        initialOwners[1] = owner2;
        initialOwners[2] = owner3;

        PublicKey[] memory initialPubKeys = new PublicKey[](3);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;
        initialPubKeys[2] = pubKey3;

        uint256[] memory initialWeights = new uint256[](3);
        initialWeights[0] = weight1;
        initialWeights[1] = weight2;
        initialWeights[2] = weight3;

        uint256[] memory initialPubKeyWeights = new uint256[](3);
        initialPubKeyWeights[0] = weight1;
        initialPubKeyWeights[1] = weight2;
        initialPubKeyWeights[2] = weight3;

        uint256 initialThresholdWeight = weight1 + weight2 + weight3 + weight1 + weight2 + weight3;

        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        assertEq(returnedOwners.length, 6);
        assertEq(returnedOwnersData.length, 6);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey3.toBytes30());
        assertEq(returnedOwnersData[0].weight, weight3);
        assertEq(returnedOwners[1], pubKey2.toBytes30());
        assertEq(returnedOwnersData[1].weight, weight2);
        assertEq(returnedOwners[2], pubKey1.toBytes30());
        assertEq(returnedOwnersData[2].weight, weight1);
        assertEq(returnedOwners[3], owner3.toBytes30());
        assertEq(returnedOwnersData[3].weight, weight3);
        assertEq(returnedOwners[4], owner2.toBytes30());
        assertEq(returnedOwnersData[4].weight, weight2);
        assertEq(returnedOwners[5], owner1.toBytes30());
        assertEq(returnedOwnersData[5].weight, weight1);
        assertEq(returnedThresholdWeight, initialThresholdWeight);

        uint256[] memory newWeights = new uint256[](3);
        newWeights[0] = weight4;
        newWeights[1] = weight5;
        newWeights[2] = weight6;
        uint256[] memory newPubKeyWeights = new uint256[](3);
        newPubKeyWeights[0] = weight4;
        newPubKeyWeights[1] = weight5;
        newPubKeyWeights[2] = weight6;

        uint256 newThresholdWeight = weight4 + weight5 + weight6 + weight4 + weight5 + weight6;

        vm.prank(account);
        plugin.updateMultisigWeights(initialOwners, newWeights, initialPubKeys, newPubKeyWeights, newThresholdWeight);

        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedOwnersDataAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 6);
        assertEq(returnedOwnersDataAfterUpdate.length, 6);
        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, weight6);
        assertEq(returnedOwnersAfterUpdate[1], pubKey2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, weight5);
        assertEq(returnedOwnersAfterUpdate[2], pubKey1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[2].weight, weight4);
        assertEq(returnedOwnersAfterUpdate[3], owner3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[3].weight, weight6);
        assertEq(returnedOwnersAfterUpdate[4], owner2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[4].weight, weight5);
        assertEq(returnedOwnersAfterUpdate[5], owner1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[5].weight, weight4);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function test_supportsInterface() public {
        bool isSupported = plugin.supportsInterface(type(IWeightedMultisigPlugin).interfaceId);
        assertTrue(isSupported);
        isSupported = plugin.supportsInterface(type(IPlugin).interfaceId);
        assertTrue(isSupported);
        isSupported = plugin.supportsInterface(type(IEntryPoint).interfaceId);
        assertFalse(isSupported);
    }

    function test_isOwnerOf() public {
        _install();
        (bool isOwner, OwnerData memory ownerData) = plugin.isOwnerOf(account, ownerOne);
        assertTrue(isOwner);
        assertEq(ownerData.weight, weightOne);
        assertEq(uint8(ownerData.credType), uint8(CredentialType.ADDRESS));
        assertEq(ownerData.addr, ownerOne);
        assertEq(ownerData.publicKeyX, uint256(0));
        assertEq(ownerData.publicKeyY, uint256(0));

        (isOwner, ownerData) = plugin.isOwnerOf(account, pubKeyOne);
        assertTrue(isOwner);
        assertEq(ownerData.weight, pubKeyWeightOne);
        assertEq(uint8(ownerData.credType), uint8(CredentialType.PUBLIC_KEY));
        assertEq(ownerData.addr, address(0));
        assertEq(ownerData.publicKeyX, pubKeyOne.x);
        assertEq(ownerData.publicKeyY, pubKeyOne.y);

        (isOwner, ownerData) = plugin.isOwnerOf(account, ownerTwo);
        assertFalse(isOwner);
        assertEq(ownerData.weight, 0);
        assertEq(uint8(ownerData.credType), uint8(0));
        assertEq(ownerData.addr, address(0));
        assertEq(ownerData.publicKeyX, uint256(0));
        assertEq(ownerData.publicKeyY, uint256(0));

        (isOwner, ownerData) = plugin.isOwnerOf(account, pubKeyTwo);
        assertFalse(isOwner);
        assertEq(ownerData.weight, 0);
        assertEq(uint8(ownerData.credType), uint8(0));
        assertEq(ownerData.addr, address(0));
        assertEq(ownerData.publicKeyX, uint256(0));
        assertEq(ownerData.publicKeyY, uint256(0));
    }

    function testFuzz_getOwnerId(address addr, PublicKey memory pubKey) public {
        vm.assume(pubKey.x != 0 || pubKey.y != 0);
        console.logString("addrId:");
        console.logBytes32(addr.toBytes30());
        assertEq(plugin.getOwnerId(addr), addr.toBytes30());
        console.logString("pubKeyId:");
        console.logBytes32(pubKey.toBytes30());
        assertEq(plugin.getOwnerId(pubKey), pubKey.toBytes30());
    }

    function test_ownershipInfoOf() public {
        _install();

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerOne.toBytes30(), account);
        assertEq(res, weightOne);

        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners[1], ownerOne.toBytes30());
        assertEq(returnedOwners[0], pubKeyOne.toBytes30());
        assertEq(returnedOwnersData.length, 2);
        assertEq(returnedOwnersData[1].weight, weightOne);
        assertEq(returnedOwnersData[0].weight, pubKeyWeightOne);
        assertEq(returnedThresholdWeight, thresholdWeightOne);
    }

    function testFuzz_addPubKeyOnlyOwnersThenK1Owner(
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 pubKeyWeight1,
        uint256 pubKeyWeight2,
        uint256 pubKeyWeight3,
        address owner1,
        uint256 weight1
    ) public {
        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));

        vm.assume(owner1 != address(0));

        vm.assume(pubKey1.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey2.toBytes30() != owner1.toBytes30());
        vm.assume(pubKey3.toBytes30() != owner1.toBytes30());

        pubKeyWeight1 = bound(pubKeyWeight1, 1, _MAX_WEIGHT);
        pubKeyWeight2 = bound(pubKeyWeight2, 1, _MAX_WEIGHT);
        pubKeyWeight3 = bound(pubKeyWeight3, 1, _MAX_WEIGHT);

        weight1 = bound(weight1, 1, _MAX_WEIGHT);

        // no k1 owners
        address[] memory initialOwners;
        uint256[] memory initialWeights;

        PublicKey[] memory initialPubKeys = new PublicKey[](2);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;

        uint256[] memory initialPubKeyWeights = new uint256[](2);
        initialPubKeyWeights[0] = pubKeyWeight1;
        initialPubKeyWeights[1] = pubKeyWeight2;

        uint256 initialThresholdWeight = pubKeyWeight1 + pubKeyWeight2;
        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwnersData.length, 2);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey2.toBytes30());
        assertEq(returnedOwnersData[0].weight, pubKeyWeight2);
        assertEq(returnedOwners[1], pubKey1.toBytes30());
        assertEq(returnedOwnersData[1].weight, pubKeyWeight1);
        assertEq(returnedThresholdWeight, initialThresholdWeight);

        // still no k1 configs
        address[] memory newOwners;
        uint256[] memory newWeights;
        PublicKey[] memory newPubKeys = new PublicKey[](1);
        newPubKeys[0] = pubKey3;

        uint256[] memory newPubKeyWeights = new uint256[](1);
        newPubKeyWeights[0] = pubKeyWeight3;

        uint256 newThresholdWeight = pubKeyWeight1 + pubKeyWeight2 + pubKeyWeight3;
        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(newOwners, newWeights, newPubKeys, newPubKeyWeights);
        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, initialThresholdWeight, newThresholdWeight);
        vm.expectEmit(true, true, true, true);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.prank(account);
        plugin.addOwners(newOwners, newWeights, newPubKeys, newPubKeyWeights, newThresholdWeight);

        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedOwnersDataAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);

        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 3);
        assertEq(returnedOwnersDataAfterUpdate.length, 3);
        // new
        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, pubKeyWeight3);

        // old
        assertEq(returnedOwnersAfterUpdate[1], pubKey2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, pubKeyWeight2);
        assertEq(returnedOwnersAfterUpdate[2], pubKey1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[2].weight, pubKeyWeight1);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);

        // now we add k1 owners
        newOwners = new address[](1);
        newOwners[0] = owner1;

        newWeights = new uint256[](1);
        newWeights[0] = weight1;
        newPubKeys = new PublicKey[](0);
        newPubKeyWeights = new uint256[](0);

        initialThresholdWeight = pubKeyWeight1 + pubKeyWeight2 + pubKeyWeight3;
        newThresholdWeight = weight1 + initialThresholdWeight;
        (_tOwners, _tWeights) = _mergeOwnersData(newOwners, newWeights, newPubKeys, newPubKeyWeights);
        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, initialThresholdWeight, newThresholdWeight);
        vm.expectEmit(true, true, true, true);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.prank(account);
        plugin.addOwners(newOwners, newWeights, newPubKeys, newPubKeyWeights, newThresholdWeight);

        (returnedOwnersAfterUpdate, returnedOwnersDataAfterUpdate, ownershipMetadataAfterUpdate) =
            plugin.ownershipInfoOf(account);

        returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 4);
        assertEq(returnedOwnersDataAfterUpdate.length, 4);
        // new
        assertEq(returnedOwnersAfterUpdate[0], owner1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, weight1);

        // old
        assertEq(returnedOwnersAfterUpdate[1], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, pubKeyWeight3);
        assertEq(returnedOwnersAfterUpdate[2], pubKey2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[2].weight, pubKeyWeight2);
        assertEq(returnedOwnersAfterUpdate[3], pubKey1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[3].weight, pubKeyWeight1);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function testFuzz_removePubKeyOnlyOwners(
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 pubKeyWeight1,
        uint256 pubKeyWeight2,
        uint256 pubKeyWeight3
    ) public {
        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));

        pubKeyWeight1 = bound(pubKeyWeight1, 1, _MAX_WEIGHT);
        pubKeyWeight2 = bound(pubKeyWeight2, 1, _MAX_WEIGHT);
        pubKeyWeight3 = bound(pubKeyWeight3, 1, _MAX_WEIGHT);

        address[] memory initialOwners;
        uint256[] memory initialWeights;

        PublicKey[] memory initialPubKeys = new PublicKey[](3);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;
        initialPubKeys[2] = pubKey3;

        uint256[] memory initialPubKeyWeights = new uint256[](3);
        initialPubKeyWeights[0] = pubKeyWeight1;
        initialPubKeyWeights[1] = pubKeyWeight2;
        initialPubKeyWeights[2] = pubKeyWeight3;

        uint256 initialThresholdWeight = pubKeyWeight1 + pubKeyWeight2 + pubKeyWeight3;
        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        assertEq(returnedOwners.length, 3);
        assertEq(returnedOwnersData.length, 3);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey3.toBytes30());
        assertEq(returnedOwnersData[0].weight, pubKeyWeight3);
        assertEq(returnedOwners[1], pubKey2.toBytes30());
        assertEq(returnedOwnersData[1].weight, pubKeyWeight2);
        assertEq(returnedOwners[2], pubKey1.toBytes30());
        assertEq(returnedOwnersData[2].weight, pubKeyWeight1);
        assertEq(returnedThresholdWeight, initialThresholdWeight);

        address[] memory ownersToRemove;
        PublicKey[] memory pubKeysToRemove = new PublicKey[](2);
        pubKeysToRemove[0] = pubKey1;
        pubKeysToRemove[1] = pubKey2;

        uint256 newThresholdWeight = pubKeyWeight3;

        vm.prank(account);
        plugin.removeOwners(ownersToRemove, pubKeysToRemove, newThresholdWeight);

        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedWeightsAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 1);
        assertEq(returnedWeightsAfterUpdate.length, 1);
        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedWeightsAfterUpdate[0].weight, pubKeyWeight3);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function testFuzz_updateMultisigWeightsPubKeyOnly(
        PublicKey memory pubKey1,
        PublicKey memory pubKey2,
        PublicKey memory pubKey3,
        uint256 weight1,
        uint256 weight2,
        uint256 weight3,
        uint256 weight4,
        uint256 weight5,
        uint256 weight6
    ) public {
        vm.assume(!(pubKey1.x == 0 && pubKey1.y == 0));
        vm.assume(!(pubKey2.x == 0 && pubKey2.y == 0));
        vm.assume(!(pubKey3.x == 0 && pubKey3.y == 0));
        vm.assume(!_isSame(pubKey1, pubKey2));
        vm.assume(!_isSame(pubKey2, pubKey3));
        vm.assume(!_isSame(pubKey3, pubKey1));

        weight1 = bound(weight1, 1, _MAX_WEIGHT);
        weight2 = bound(weight2, 1, _MAX_WEIGHT);
        weight3 = bound(weight3, 1, _MAX_WEIGHT);
        weight4 = bound(weight4, 1, _MAX_WEIGHT);
        weight5 = bound(weight5, 1, _MAX_WEIGHT);
        weight6 = bound(weight6, 1, _MAX_WEIGHT);

        address[] memory initialOwners;

        PublicKey[] memory initialPubKeys = new PublicKey[](3);
        initialPubKeys[0] = pubKey1;
        initialPubKeys[1] = pubKey2;
        initialPubKeys[2] = pubKey3;

        uint256[] memory initialWeights;

        uint256[] memory initialPubKeyWeights = new uint256[](3);
        initialPubKeyWeights[0] = weight1;
        initialPubKeyWeights[1] = weight2;
        initialPubKeyWeights[2] = weight3;

        uint256 initialThresholdWeight = weight1 + weight2 + weight3;

        plugin.onInstall(
            abi.encode(initialOwners, initialWeights, initialPubKeys, initialPubKeyWeights, initialThresholdWeight)
        );
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;

        assertEq(returnedOwners.length, 3);
        assertEq(returnedOwnersData.length, 3);
        // (reverse insertion order)
        assertEq(returnedOwners[0], pubKey3.toBytes30());
        assertEq(returnedOwnersData[0].weight, weight3);
        assertEq(returnedOwners[1], pubKey2.toBytes30());
        assertEq(returnedOwnersData[1].weight, weight2);
        assertEq(returnedOwners[2], pubKey1.toBytes30());
        assertEq(returnedOwnersData[2].weight, weight1);
        assertEq(returnedThresholdWeight, initialThresholdWeight);

        uint256[] memory newWeights;
        uint256[] memory newPubKeyWeights = new uint256[](3);
        newPubKeyWeights[0] = weight4;
        newPubKeyWeights[1] = weight5;
        newPubKeyWeights[2] = weight6;

        uint256 newThresholdWeight = weight4 + weight5 + weight6;

        vm.prank(account);
        plugin.updateMultisigWeights(initialOwners, newWeights, initialPubKeys, newPubKeyWeights, newThresholdWeight);

        (
            bytes30[] memory returnedOwnersAfterUpdate,
            OwnerData[] memory returnedOwnersDataAfterUpdate,
            OwnershipMetadata memory ownershipMetadataAfterUpdate
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeightAfterUpdate = ownershipMetadataAfterUpdate.thresholdWeight;
        assertEq(returnedOwnersAfterUpdate.length, 3);
        assertEq(returnedOwnersDataAfterUpdate.length, 3);
        assertEq(returnedOwnersAfterUpdate[0], pubKey3.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[0].weight, weight6);
        assertEq(returnedOwnersAfterUpdate[1], pubKey2.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[1].weight, weight5);
        assertEq(returnedOwnersAfterUpdate[2], pubKey1.toBytes30());
        assertEq(returnedOwnersDataAfterUpdate[2].weight, weight4);
        assertEq(returnedThresholdWeightAfterUpdate, newThresholdWeight);
    }

    function testFuzz_isValidSignature_eoaOwner(string memory salt, bytes memory message) public {
        _install();

        // range bound the possible set of private keys
        (address signer, uint256 signerPrivateKey) = makeAddrAndKey(salt);
        bytes32 digest = keccak256(message);
        // the caller should sign the wrapped digest
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        bytes memory signature = signMessage(vm, signerPrivateKey, wrappedDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        (bool isOwner,) = plugin.isOwnerOf(account, signer);
        if (!isOwner) {
            // sig check should fail w/o valid signer
            vm.prank(account);
            assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, signature));

            vm.prank(account);
            plugin.addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 0);
        }

        (isOwner,) = plugin.isOwnerOf(account, signer);
        assertTrue(isOwner);
        // sig check should pass
        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, signature));
    }

    function testIsValidSignature_eoaOwner_emptySeedAndDigest() public {
        _install();
        string memory salt = "";
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        _addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 0);

        // sig check should pass
        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));
    }

    function testIsValidSignature_eoaOwner_emptySeedAndDigest_invalidOwner() public {
        _install();
        string memory salt = "";
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;

        // range bound the possible set of priv keys
        (, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);

        // sig check should fail (not owner)
        vm.prank(account);
        assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, abi.encodePacked(r, s, v)));
    }

    function testFuzz_isValidSignature_contractOwner(uint256 seed, bytes memory message) public {
        _install();

        Owner memory contractOwner = _createContractOwner(seed);
        bytes32 digest = keccak256(message);
        // the caller should sign the wrapped digest
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        bytes memory signerSig = signMessage(vm, contractOwner.signerWallet.privateKey, wrappedDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(contractOwner.owner);

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        // address || dynamic pos || sig type || length of bytes || sig data bytes
        bytes memory contractSig =
            abi.encodePacked(abi.encode(toAddress(contractOwner.owner)), uint256(65), uint8(0), uint256(65), signerSig);

        (bool isOwner,) = plugin.isOwnerOf(account, toAddress(contractOwner.owner));
        if (!isOwner) {
            // sig check should fail
            vm.prank(account);
            assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, contractSig));

            vm.prank(account);
            plugin.addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 0);
        }

        (isOwner,) = plugin.isOwnerOf(account, toAddress(contractOwner.owner));
        assertTrue(isOwner);
        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, contractSig));
    }

    function testIsValidSignature_contractOwner_emptySeedAndDigest() public {
        _install();
        uint256 seed = 0;
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;

        Owner memory newOwner = _createContractOwner(seed);
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.signerWallet.privateKey, messageDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(newOwner.owner);

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        vm.prank(account);
        _addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 0);

        bytes memory sig = abi.encodePacked(abi.encode(ownersToAdd1[0]), uint256(65), uint8(0), uint256(65), r, s, v);

        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, sig));
    }

    function testFuzz_isValidSignature_p256Owner(bytes memory message) public {
        _install();

        bytes32 digest = keccak256(message);
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPart;
        webAuthnSigDynamicPart.webAuthnData = _getWebAuthnData(wrappedDigest);
        bytes32 digestToSign = _getWebAuthnMessageHash(webAuthnSigDynamicPart.webAuthnData);
        (uint256 r, uint256 s) = signP256Message(vm, passkeyPrivateKey, digestToSign);
        webAuthnSigDynamicPart.r = r;
        webAuthnSigDynamicPart.s = s;
        // x || dynamic pos || sig type || length of bytes || sig data bytes
        uint256 dynamicPos = 65; // 1 constant part
        bytes memory sigBytes = abi.encode(webAuthnSigDynamicPart);
        PublicKey[] memory pubKeyOwnersToAdd1 = new PublicKey[](1);
        pubKeyOwnersToAdd1[0] = PublicKey(passkeyPublicKeyX, passkeyPublicKeyY);
        bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKeyOwnersToAdd1[0])));
        console.logString("pubKeyId:");
        console.logBytes32(pubKeyId);
        bytes memory p256Sig = abi.encodePacked(pubKeyId, dynamicPos, uint8(2), sigBytes.length, sigBytes);

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        (bool isOwner,) = plugin.isOwnerOf(account, pubKeyOwnersToAdd1[0]);
        if (!isOwner) {
            // sig check should fail
            vm.prank(account);
            assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, p256Sig));

            vm.prank(account);
            plugin.addOwners(new address[](0), new uint256[](0), pubKeyOwnersToAdd1, weightsToAdd1, 0);
        }

        (isOwner,) = plugin.isOwnerOf(account, pubKeyOwnersToAdd1[0]);
        assertTrue(isOwner);
        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, p256Sig));
    }

    function testIsValidSignature_p256Owner_emptyDigest() public {
        _install();
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPart;
        webAuthnSigDynamicPart.webAuthnData = _getWebAuthnData(wrappedDigest);
        bytes32 digestToSign = _getWebAuthnMessageHash(webAuthnSigDynamicPart.webAuthnData);
        (uint256 r, uint256 s) = signP256Message(vm, passkeyPrivateKey, digestToSign);
        webAuthnSigDynamicPart.r = r;
        webAuthnSigDynamicPart.s = s;
        // x || dynamic pos || sig type || length of bytes || sig data bytes
        uint256 dynamicPos = 65; // 1 constant part
        bytes memory sigBytes = abi.encode(webAuthnSigDynamicPart);
        PublicKey[] memory pubKeyOwnersToAdd1 = new PublicKey[](1);
        pubKeyOwnersToAdd1[0] = PublicKey(passkeyPublicKeyX, passkeyPublicKeyY);
        bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKeyOwnersToAdd1[0])));
        bytes memory p256Sig = abi.encodePacked(pubKeyId, dynamicPos, uint8(2), sigBytes.length, sigBytes);

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;
        vm.prank(account);
        plugin.addOwners(new address[](0), new uint256[](0), pubKeyOwnersToAdd1, weightsToAdd1, 0);
        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, p256Sig));
    }

    // mixed signature types
    function testFuzz_isValidSignature_mixedSigTypes(uint256 k, uint256 n, bytes memory message) public {
        // 1 < n < 10
        n %= 11;
        vm.assume(n > 0);

        // 1 < k < n
        k %= 11;
        k %= n;
        vm.assume(k > 0);

        bytes32 digest = keccak256(message);
        // for k1 signer
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPart;
        // for r1 signer
        webAuthnSigDynamicPart.webAuthnData = _getWebAuthnData(wrappedDigest);
        bytes32 webauthnDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPart.webAuthnData);

        // get all owners
        Owner[] memory owners = new Owner[](n);
        uint256 lenOfK1Signers;
        uint256 lenOfR1Signers;
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 3 == 2) {
                lenOfR1Signers++;
            } else {
                lenOfK1Signers++;
            }
        }
        console.log("lenOfK1Signers: ", lenOfK1Signers);
        console.log("lenOfR1Signers: ", lenOfR1Signers);
        assertEq(lenOfK1Signers + lenOfR1Signers, n);
        address[] memory initialOwners = new address[](lenOfK1Signers);
        uint256[] memory initialWeights = new uint256[](lenOfK1Signers);
        PublicKey[] memory initialPubKeyOwners = new PublicKey[](lenOfR1Signers);
        uint256[] memory initialPubKeyWeights = new uint256[](lenOfR1Signers);
        uint256 numOfK1Signers;
        uint256 numOfR1Signers;
        // load pre generated r1 keys list which has more keys than we need
        TestKey[] memory testR1Keys = _loadP256Keys();
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 3 == 0) {
                // contract owners
                console.logString("we have a contract owner..");
                owners[i] = _createContractOwner(seed);
                owners[i].sigType = 0;
                initialOwners[numOfK1Signers] = toAddress(owners[i].owner);
                initialWeights[numOfK1Signers] = 1;
                numOfK1Signers++;
            } else if (seed % 3 == 1) {
                // eoa owners
                console.logString("we have an eoa owner..");
                VmSafe.Wallet memory signerWallet;
                (signerWallet.addr, signerWallet.privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));
                owners[i] = Owner({owner: signerWallet.addr.toBytes30(), signerWallet: signerWallet, sigType: 27});
                initialOwners[numOfK1Signers] = signerWallet.addr;
                initialWeights[numOfK1Signers] = 1;
                numOfK1Signers++;
            } else {
                // r1 owners
                console.logString("we have a r1 owner..");
                VmSafe.Wallet memory signerWallet;
                signerWallet.privateKey = testR1Keys[numOfR1Signers].privateKey;
                signerWallet.publicKeyX = testR1Keys[numOfR1Signers].publicKeyX;
                signerWallet.publicKeyY = testR1Keys[numOfR1Signers].publicKeyY;
                // for sorting
                bytes30 ownerBytes = PublicKeyLib.toBytes30(signerWallet.publicKeyX, signerWallet.publicKeyY);
                owners[i] = Owner({owner: ownerBytes, signerWallet: signerWallet, sigType: 2});
                initialPubKeyOwners[numOfR1Signers] = PublicKey(signerWallet.publicKeyX, signerWallet.publicKeyY);
                initialPubKeyWeights[numOfR1Signers] = 1;
                numOfR1Signers++;
            }
        }

        // sort owners using address
        uint256 minIdx;
        for (uint256 i = 0; i < n; i++) {
            minIdx = i;
            for (uint256 j = i; j < n; j++) {
                if (owners[j].owner < owners[minIdx].owner) {
                    minIdx = j;
                }
            }
            (owners[i], owners[minIdx]) = (owners[minIdx], owners[i]);
        }

        // initialThresholdWeight is equivalent to k because every signer has weight 1
        vm.prank(account);
        plugin.onInstall(abi.encode(initialOwners, initialWeights, initialPubKeyOwners, initialPubKeyWeights, k));
        bytes memory sigDynamicParts = bytes("");
        uint256 offset = k * 65; // start after constant part
        bytes memory signature; // constant + dynamic
        for (uint256 i = 0; i < k; i++) {
            uint8 v;
            bytes32 r;
            bytes32 s;
            if (owners[i].sigType == 27) {
                console.logString("eoa owner signs..");
                (v, r, s) = vm.sign(owners[i].signerWallet.privateKey, wrappedDigest);
                // constant part only for EOA
                signature = abi.encodePacked(signature, abi.encodePacked(r, s, v));
            } else if (owners[i].sigType == 0) {
                console.logString("contract owner signs..");
                (v, r, s) = vm.sign(owners[i].signerWallet.privateKey, wrappedDigest);
                signature =
                    abi.encodePacked(signature, abi.encode(toAddress(owners[i].owner)), uint256(offset), uint8(0));
                // dynamic part because offset was set to the end of constant part initially
                offset += 97; // 65 (k1 sig length) + 32 (length of sig)
                // 65 is the length of k1 signature
                sigDynamicParts = abi.encodePacked(sigDynamicParts, uint256(65), r, s, v);
            } else {
                console.logString("r1 owner signs..");
                (r, s) = vm.signP256(owners[i].signerWallet.privateKey, webauthnDigest);
                uint256 ur = uint256(r);
                uint256 us = uint256(s);
                if (us > _P256_N_DIV_2) {
                    us = FCL_Elliptic_ZZ.n - us;
                }
                v = 2;
                webAuthnSigDynamicPart.r = ur;
                webAuthnSigDynamicPart.s = us;
                PublicKey memory pubKey =
                    PublicKey({x: owners[i].signerWallet.publicKeyX, y: owners[i].signerWallet.publicKeyY});
                bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKey)));
                // x || dynamic pos || sig type
                signature = abi.encodePacked(signature, pubKeyId, uint256(offset), v);

                bytes memory sigBytes = abi.encode(webAuthnSigDynamicPart);
                // dynamic part because offset was set to the end of constant part initially
                offset += (32 + sigBytes.length);
                // length of bytes || sig data bytes
                sigDynamicParts = abi.encodePacked(sigDynamicParts, uint256(sigBytes.length), sigBytes);
            }
        }
        // concatenate(constant, dynamic)
        signature = abi.encodePacked(signature, sigDynamicParts);

        vm.prank(account);
        assertEq(EIP1271_VALID_SIGNATURE, plugin.isValidSignature(digest, signature));
    }

    function testIsValidSignature_invalidContractOwner() public {
        _install();

        bytes memory message = "test msg";
        Owner memory contractOwner = _createContractOwner(123);
        bytes32 digest = keccak256(message);
        // the caller should sign the wrapped digest
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        bytes memory signerSig = signMessage(vm, contractOwner.signerWallet.privateKey, wrappedDigest);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(contractOwner.owner);

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        vm.prank(account);
        plugin.addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 9);

        // invalid address || dynamic pos || sig type || length of bytes || sig data bytes
        address anotherOwner = vm.addr(1);
        bytes memory contractSig =
            abi.encodePacked(abi.encode(anotherOwner), uint256(65), uint8(0), uint256(65), signerSig);
        vm.prank(anotherOwner);
        assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, contractSig));
    }

    function testIsValidSignature_invalidEOAOwner() public {
        _install();

        bytes memory message = "test msg";
        // range bound the possible set of private keys
        (, uint256 signerPrivateKey) = makeAddrAndKey("testIsValidSignature_invalidEOAOwner");
        bytes32 digest = keccak256(message);
        // the caller should sign the wrapped digest
        bytes32 wrappedDigest = plugin.getReplaySafeMessageHash(address(account), digest);

        address anotherOwner = vm.addr(1);
        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = anotherOwner; // random signer

        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        // add random signer
        vm.prank(account);
        plugin.addOwners(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), 0);

        bytes memory signature = signMessage(vm, signerPrivateKey, wrappedDigest);
        vm.prank(anotherOwner);
        assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, signature));
    }

    function testIsValidSignature_invalidThresholdWeight(bytes32 digest) public {
        bytes memory _sig = bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
        // test does not install, so no owner has a threshold
        vm.expectRevert(abi.encodeWithSelector(InvalidThresholdWeight.selector));
        plugin.isValidSignature(digest, _sig);
    }

    function testIsValidSignature_invalidSigLen() public {
        _install();
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes memory sig = bytes("foo");
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidSigLength.selector));
        vm.prank(account);
        plugin.isValidSignature(digest, sig);
    }

    function testIsValidSignature_remainingSigTooShort() public {
        uint256 seed = 0;
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;
        (address eoaOwner, uint256 privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));

        // 1. install with two owners, so contract owner has insufficient weight to pass threshold
        address[] memory listOfTwoOwners = new address[](2);
        listOfTwoOwners[0] = eoaOwner;
        listOfTwoOwners[1] = ownerTwo;

        uint256[] memory listOfTwoWeights = new uint256[](2);
        listOfTwoWeights[0] = weightOne; // 100
        listOfTwoWeights[1] = weightTwo; // 101

        uint256 threshold = weightOne + weightTwo;

        plugin.onInstall(abi.encode(listOfTwoOwners, listOfTwoWeights, new PublicKey[](0), new uint256[](0), threshold));

        // 2. create a valid signature for installed owner
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertEq(sig.length, 65);

        // 3. append <65 bytes of data
        bytes memory fooBytes = bytes("foo");
        bytes memory sigWithFooAppended = abi.encodePacked(sig, fooBytes);

        assertEq(sigWithFooAppended.length, 68);

        vm.prank(account);
        (bool success, uint256 firstFailure) =
            plugin.checkNSignatures(messageDigest, messageDigest, account, sigWithFooAppended);
        assertEq(success, false);
        assertEq(firstFailure, 1);

        vm.prank(account);
        assertEq(EIP1271_INVALID_SIGNATURE, plugin.isValidSignature(digest, sigWithFooAppended));
    }

    function testIsValidSignature_revertsOnTooHighV() public {
        _install();

        string memory salt = "";
        bytes32 digest = 0x0000000000000000000000000000000000000000000000000000000000000000;
        // range bound the possible set of priv keys
        (, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageDigest);

        // (60 - 32 = 28)
        v += 61;

        bytes memory sig = abi.encodePacked(r, s, v);

        // sig check should fail (not owner)
        vm.prank(account);
        vm.expectRevert("ECDSA: invalid signature");
        plugin.isValidSignature(digest, sig);
    }

    function testCheckNSignatures_revertsInvalidECDSASignature() public {
        _install();

        // incorrect digest
        bytes32 messageDigest = bytes32("foo");
        vm.prank(account);
        vm.expectRevert("ECDSA: invalid signature");
        plugin.checkNSignatures(messageDigest, messageDigest, account, INVALID_ECDSA_SIGNATURE);
    }

    function testCheckNSignatures_revertsECDSASignatureOnHighS() public {
        _install();

        // correct digest but signature has too high s value
        // fixture source:
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/5212e8eb1830be145cc7b6b2c955c7667a74e14c/test/utils/cryptography/ECDSA.test.js#L195C7-L195C92
        bytes32 messageDigest = 0xb94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9;
        vm.prank(account);
        vm.expectRevert("ECDSA: invalid signature");
        plugin.checkNSignatures(messageDigest, messageDigest, account, INVALID_ECDSA_SIGNATURE);
    }

    function testFuzz_checkNSignatures_failsOnIsValidERC1271SignatureNow(uint256 seed1, uint256 seed2, bytes32 digest)
        public
    {
        _install();
        vm.assume(seed1 != seed2);

        Owner memory newOwner1 = _createContractOwner(seed1);
        bytes32 messageDigest = plugin.getReplaySafeMessageHash(address(account), digest);

        // sign with owner2 (owner which does not match owner packed into constant part of contract sig)
        Owner memory newOwner2 = _createContractOwner(seed2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner2.signerWallet.privateKey, messageDigest);

        bytes memory sig =
            abi.encodePacked(abi.encode(toAddress(newOwner1.owner)), uint256(65), uint8(0), uint256(65), r, s, v);

        vm.prank(account);
        (bool success, uint256 firstFailure) = plugin.checkNSignatures(messageDigest, messageDigest, account, sig);
        assertEq(success, false);
        assertEq(firstFailure, 0);
    }

    function testFuzz_userOpValidationFunction_eoaOwner(string memory salt, UserOperation memory userOp) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        vm.assume(userOp.maxFeePerGas != 0);
        _install();

        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(r, s, v + 32);

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer;

        // Only check that the signature should fail if the signer is not already an owner
        (bool isOwner,) = plugin.isOwnerOf(account, signer);
        if (!isOwner) {
            // should fail without owner access
            vm.prank(account);
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                1
            );

            // add signer to owner
            vm.prank(account);
            plugin.addOwners(ownersToAdd1, weightOneList, new PublicKey[](0), new uint256[](0), 0);
        }

        vm.prank(account);
        assertEq(
            plugin.userOpValidationFunction(
                uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            0
        );
    }

    function testFuzz_userOpValidationFunction_contractOwner(uint256 seed, UserOperation memory userOp) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        vm.assume(userOp.maxFeePerGas != 0);
        _install();
        Owner memory newOwner = _createContractOwner(seed);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.signerWallet.privateKey, userOpHash.toEthSignedMessageHash());

        // https://docs.safe.global/advanced/smart-account-signatures#contract-signature-eip-1271
        userOp.signature = abi.encodePacked(
            // Constant part
            // 32-byte signature verifier: verifying contract address
            abi.encode(toAddress(newOwner.owner)),
            // 32-byte data position: 65
            uint256(65),
            // 1 byte signature type: 32 (for contract on actual digest)
            uint8(32),
            // Dynamic part
            // 32-byte signature length: 65
            uint256(65),
            // r,s,v for ECDSA signature by signer of contract
            r,
            s,
            v
        );

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(newOwner.owner);

        // Only check that the signature should fail if the signer is not already an owner
        (bool isOwner,) = plugin.isOwnerOf(account, ownersToAdd1[0]);
        if (!isOwner) {
            // should fail without owner access
            vm.prank(account);
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                SIG_VALIDATION_FAILED
            );

            // add signer to owner
            vm.prank(account);
            plugin.addOwners(ownersToAdd1, weightOneList, new PublicKey[](0), new uint256[](0), 0);
        }

        // sig check should pass
        vm.prank(account);
        assertEq(
            plugin.userOpValidationFunction(
                uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            SIG_VALIDATION_SUCCEEDED
        );
    }

    function testFuzz_userOpValidationFunction_p256Owner(UserOperation memory userOp) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        vm.assume(userOp.maxFeePerGas != 0);
        _install();
        // full userOp hash
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPart;
        webAuthnSigDynamicPart.webAuthnData = _getWebAuthnData(userOpHash.toEthSignedMessageHash());
        bytes32 webauthnDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPart.webAuthnData);
        (uint256 r, uint256 s) = signP256Message(vm, passkeyPrivateKey, webauthnDigest);
        webAuthnSigDynamicPart.r = r;
        webAuthnSigDynamicPart.s = s;
        // x || dynamic pos || sig type || length of bytes || sig data bytes
        uint256 dynamicPos = 65; // 1 constant part
        bytes memory sigBytes = abi.encode(webAuthnSigDynamicPart);
        PublicKey[] memory pubKeyOwnersToAdd1 = new PublicKey[](1);
        pubKeyOwnersToAdd1[0] = PublicKey(passkeyPublicKeyX, passkeyPublicKeyY);
        bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKeyOwnersToAdd1[0])));
        // actual digest sigType is 34 (2 + 32)
        userOp.signature = abi.encodePacked(pubKeyId, dynamicPos, uint8(34), sigBytes.length, sigBytes);
        uint256 weightToAdd1 = 9;
        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightToAdd1;

        (bool isOwner,) = plugin.isOwnerOf(account, pubKeyOwnersToAdd1[0]);
        if (!isOwner) {
            // sig check should fail
            vm.prank(account);
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                SIG_VALIDATION_FAILED
            );

            vm.prank(account);
            plugin.addOwners(new address[](0), new uint256[](0), pubKeyOwnersToAdd1, weightsToAdd1, 0);
        }

        (isOwner,) = plugin.isOwnerOf(account, pubKeyOwnersToAdd1[0]);
        assertTrue(isOwner);
        vm.prank(account);
        assertEq(
            plugin.userOpValidationFunction(
                uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
            ),
            SIG_VALIDATION_SUCCEEDED
        );
    }

    // mixed signature types in userOp.signature
    function testFuzz_userOpValidation_mixedSigTypes(uint256 k, uint256 n, UserOperation memory userOp) public {
        // 1 < n < 10
        n %= 11;
        vm.assume(n > 0);

        // 1 < k < n
        k %= 11;
        k %= n;
        vm.assume(k > 0);

        // full userOp hash
        // for k1 signer
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPartForFullUserOp;
        // for r1 signer
        webAuthnSigDynamicPartForFullUserOp.webAuthnData = _getWebAuthnData(fullUserOpHash.toEthSignedMessageHash());
        bytes32 webauthnDigestForFullUserOp = _getWebAuthnMessageHash(webAuthnSigDynamicPartForFullUserOp.webAuthnData);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.maxFeePerGas = 0;
        userOp.maxPriorityFeePerGas = 0;
        userOp.callGasLimit = 0;
        userOp.verificationGasLimit = 0;
        userOp.paymasterAndData = "";

        // minimal userOp hash
        // for k1 signer
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPartForMinimalUserOp;
        // for r1 signer
        webAuthnSigDynamicPartForMinimalUserOp.webAuthnData =
            _getWebAuthnData(minimalUserOpHash.toEthSignedMessageHash());
        bytes32 webauthnDigestForMinimalUserOp =
            _getWebAuthnMessageHash(webAuthnSigDynamicPartForMinimalUserOp.webAuthnData);

        // get all owners
        Owner[] memory owners = new Owner[](n);
        uint256 lenOfK1Signers;
        uint256 lenOfR1Signers;
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 3 == 2) {
                lenOfR1Signers++;
            } else {
                lenOfK1Signers++;
            }
        }
        console.log("lenOfK1Signers: ", lenOfK1Signers);
        console.log("lenOfR1Signers: ", lenOfR1Signers);
        assertEq(lenOfK1Signers + lenOfR1Signers, n);
        address[] memory initialOwners = new address[](lenOfK1Signers);
        uint256[] memory initialWeights = new uint256[](lenOfK1Signers);
        PublicKey[] memory initialPubKeyOwners = new PublicKey[](lenOfR1Signers);
        uint256[] memory initialPubKeyWeights = new uint256[](lenOfR1Signers);
        uint256 numOfK1Signers;
        uint256 numOfR1Signers;
        // load pre generated r1 keys list which has more keys than we need
        TestKey[] memory testR1Keys = _loadP256Keys();
        for (uint256 i = 0; i < n; i++) {
            uint256 seed = k + n + i;
            if (seed % 3 == 0) {
                // contract owners
                console.logString("we have a contract owner..");
                owners[i] = _createContractOwner(seed);
                owners[i].sigType = 0;
                initialOwners[numOfK1Signers] = toAddress(owners[i].owner);
                initialWeights[numOfK1Signers] = 1;
                numOfK1Signers++;
            } else if (seed % 3 == 1) {
                // eoa owners
                console.logString("we have an eoa owner..");
                VmSafe.Wallet memory signerWallet;
                (signerWallet.addr, signerWallet.privateKey) = makeAddrAndKey(string(abi.encodePacked(seed)));
                owners[i] = Owner({owner: signerWallet.addr.toBytes30(), signerWallet: signerWallet, sigType: 27});
                initialOwners[numOfK1Signers] = signerWallet.addr;
                initialWeights[numOfK1Signers] = 1;
                numOfK1Signers++;
            } else {
                // r1 owners
                console.logString("we have a r1 owner..");
                VmSafe.Wallet memory signerWallet;
                signerWallet.privateKey = testR1Keys[numOfR1Signers].privateKey;
                signerWallet.publicKeyX = testR1Keys[numOfR1Signers].publicKeyX;
                signerWallet.publicKeyY = testR1Keys[numOfR1Signers].publicKeyY;
                // for sorting
                bytes30 ownerBytes = PublicKeyLib.toBytes30(signerWallet.publicKeyX, signerWallet.publicKeyY);
                owners[i] = Owner({owner: ownerBytes, signerWallet: signerWallet, sigType: 2});
                initialPubKeyOwners[numOfR1Signers] = PublicKey(signerWallet.publicKeyX, signerWallet.publicKeyY);
                initialPubKeyWeights[numOfR1Signers] = 1;
                numOfR1Signers++;
            }
        }

        // sort owners using address
        uint256 minIdx;
        for (uint256 i = 0; i < n; i++) {
            minIdx = i;
            for (uint256 j = i; j < n; j++) {
                if (owners[j].owner < owners[minIdx].owner) {
                    minIdx = j;
                }
            }
            (owners[i], owners[minIdx]) = (owners[minIdx], owners[i]);
        }

        // grab a ~random owner in the first k sigs to be the last signer
        // last signer must sign over full(actual) gas vals used
        bytes30 ownerSignFullUserOp;
        // only require one singer to sign full digest if fullUserOpHash != minimalUserOpHash
        if (fullUserOpHash != minimalUserOpHash) {
            ownerSignFullUserOp = owners[n % k].owner;
        }

        // initialThresholdWeight is equivalent to k because every signer has weight 1
        vm.prank(account);
        plugin.onInstall(abi.encode(initialOwners, initialWeights, initialPubKeyOwners, initialPubKeyWeights, k));
        bytes memory sigDynamicParts = bytes("");
        uint256 offset = k * 65; // start after constant part
        userOp.signature = bytes(""); // constant + dynamic
        bytes32 k1Digest;
        bytes32 r1Digest;
        uint256 numOfSignersOnFullUserOp;
        for (uint256 i = 0; i < k; i++) {
            if (owners[i].owner == ownerSignFullUserOp) {
                k1Digest = fullUserOpHash.toEthSignedMessageHash();
                r1Digest = webauthnDigestForFullUserOp;
            } else {
                k1Digest = minimalUserOpHash.toEthSignedMessageHash();
                r1Digest = webauthnDigestForMinimalUserOp;
            }
            uint8 v;
            bytes32 r;
            bytes32 s;
            if (owners[i].sigType == 27) {
                console.logString("eoa owner signs..");
                (v, r, s) = vm.sign(owners[i].signerWallet.privateKey, k1Digest);
                if (owners[i].owner == ownerSignFullUserOp) {
                    v += 32;
                    numOfSignersOnFullUserOp++;
                }
                // constant part only for EOA
                userOp.signature = abi.encodePacked(userOp.signature, abi.encodePacked(r, s, v));
            } else if (owners[i].sigType == 0) {
                console.logString("contract owner signs..");
                (v, r, s) = vm.sign(owners[i].signerWallet.privateKey, k1Digest);
                // 65 is the length of k1 signature
                // use the original v for signer ecrecover
                sigDynamicParts = abi.encodePacked(sigDynamicParts, uint256(65), r, s, v);
                if (owners[i].owner == ownerSignFullUserOp) {
                    v = 32; // 0 + 32
                    numOfSignersOnFullUserOp++;
                } else {
                    v = 0;
                }
                userOp.signature =
                    abi.encodePacked(userOp.signature, abi.encode(toAddress(owners[i].owner)), uint256(offset), v);
                // dynamic part because offset was set to the end of constant part initially
                offset += 97; // 65 (k1 sig length) + 32 (length of sig)
            } else {
                console.logString("r1 owner signs..");
                (r, s) = vm.signP256(owners[i].signerWallet.privateKey, r1Digest);
                uint256 ur = uint256(r);
                uint256 us = uint256(s);
                if (us > _P256_N_DIV_2) {
                    us = FCL_Elliptic_ZZ.n - us;
                }
                if (owners[i].owner == ownerSignFullUserOp) {
                    v = 34; // 2 + 32
                    numOfSignersOnFullUserOp++;
                } else {
                    v = 2;
                }
                // x || dynamic pos || sig type
                PublicKey memory pubKey =
                    PublicKey({x: owners[i].signerWallet.publicKeyX, y: owners[i].signerWallet.publicKeyY});
                bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKey)));
                userOp.signature = abi.encodePacked(userOp.signature, pubKeyId, uint256(offset), v);

                bytes memory sigBytes;
                if (owners[i].owner == ownerSignFullUserOp) {
                    webAuthnSigDynamicPartForFullUserOp.r = ur;
                    webAuthnSigDynamicPartForFullUserOp.s = us;
                    sigBytes = abi.encode(webAuthnSigDynamicPartForFullUserOp);
                } else {
                    webAuthnSigDynamicPartForMinimalUserOp.r = ur;
                    webAuthnSigDynamicPartForMinimalUserOp.s = us;
                    sigBytes = abi.encode(webAuthnSigDynamicPartForMinimalUserOp);
                }

                // dynamic part because offset was set to the end of constant part initially
                offset += (32 + sigBytes.length);
                // length of bytes || sig data bytes
                sigDynamicParts = abi.encodePacked(sigDynamicParts, uint256(sigBytes.length), sigBytes);
            }
        }
        // concatenate(constant, dynamic)
        userOp.signature = abi.encodePacked(userOp.signature, sigDynamicParts);
        console.log("numOfSignersOnFullUserOp: ", numOfSignersOnFullUserOp);

        vm.prank(account);
        // sig check should pass
        assertEq(
            plugin.userOpValidationFunction(
                uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, fullUserOpHash
            ),
            SIG_VALIDATION_SUCCEEDED
        );
    }

    function test_failUserOpValidationFunction_noActualDigest() public {
        _install();
        UserOperation memory userOp;
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey("test_failUserOpValidationFunction_noActualDigest");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(r, s, v);

        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = signer;
        uint256[] memory weightsToAdd = new uint256[](1);
        weightsToAdd[0] = 100;

        // Only check that the signature should fail if the signer is not already an owner
        (bool isOwner,) = plugin.isOwnerOf(account, signer);
        if (!isOwner) {
            vm.prank(account);
            // add signer to owner
            plugin.addOwners(ownersToAdd, weightsToAdd, new PublicKey[](0), new uint256[](0), 0);
        }
        (isOwner,) = plugin.isOwnerOf(account, signer);
        assertTrue(isOwner);
        // sig check should pass
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidUserOpDigest.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
    }

    function testFuzz_failUserOpValidation_notImplementedFunction(
        uint8 functionId,
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) public {
        vm.assume(uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER) != functionId);

        vm.expectRevert(
            abi.encodeWithSelector(
                NotImplemented.selector, BaseMultisigPlugin.userOpValidationFunction.selector, functionId
            )
        );
        plugin.userOpValidationFunction(functionId, userOp, userOpHash);
    }

    function test_failUserOpValidationFunction_badAddress() public {
        _install();
        UserOperation memory userOp;
        // actual digest
        userOp.callGasLimit = uint256(1);

        Owner memory newOwner = _createContractOwner(0);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.signerWallet.privateKey, userOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(
            bytes32(uint256(uint240(newOwner.owner))) | bytes32(uint256(0xFF << 160)), // dirty upper bits
            uint256(65),
            uint8(32),
            uint256(65),
            r,
            s,
            v
        );

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidAddress.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
    }

    function testFuzz_failUserOpValidationFunction_wrongNumberOfSigsOnActualDigest(
        string memory salt1,
        UserOperation memory userOp
    ) public {
        userOp.preVerificationGas = 0;
        userOp.maxFeePerGas = 0;
        userOp.maxPriorityFeePerGas = 0;
        userOp.callGasLimit = 0;
        userOp.verificationGasLimit = 0;
        userOp.paymasterAndData = "";

        // make salts different
        string memory salt2 = string.concat(salt1, "foo");
        // range bound the possible set of priv keys
        (address signer1, uint256 privateKey1) = makeAddrAndKey(salt1);
        (address signer2, uint256 privateKey2) = makeAddrAndKey(salt2);

        vm.assume(signer1 != address(0));
        vm.assume(signer2 != address(0));
        vm.assume(signer2 > signer1); // enforce ascending order

        // add owners
        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = signer1;

        uint256[] memory weightsToAdd1 = new uint256[](1);
        weightsToAdd1[0] = weightOne;

        plugin.onInstall(abi.encode(ownersToAdd1, weightsToAdd1, new PublicKey[](0), new uint256[](0), weightOne));

        // sign minimal user op hash
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey1, minimalUserOpHash.toEthSignedMessageHash());

        userOp.signature = abi.encodePacked(r, s, v);

        // set an actual gas field
        userOp.callGasLimit = uint256(1);
        bytes32 actualUserOpHash = entryPoint.getUserOpHash(userOp);

        // Should fail with 0 sigs over actual digest
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidNumSigsOnActualDigest.selector, 1));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, actualUserOpHash
        );

        // Should succeed with 1 sig over actual digest
        address[] memory ownersToAdd2 = new address[](1);
        ownersToAdd2[0] = signer2;

        uint256[] memory weightsToAdd2 = new uint256[](1);
        weightsToAdd2[0] = weightOne;

        vm.prank(account);
        plugin.addOwners(ownersToAdd2, weightsToAdd2, new PublicKey[](0), new uint256[](0), weightOne * 2);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, actualUserOpHash.toEthSignedMessageHash());
        bytes memory sig2 = abi.encodePacked(r2, s2, v2 + 32); // add 32 to v for actual digest

        userOp.signature = abi.encodePacked(userOp.signature, sig2);

        vm.prank(account);
        assertEq(
            plugin.userOpValidationFunction(
                uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, actualUserOpHash
            ),
            SIG_VALIDATION_SUCCEEDED
        );

        // Should fail with 2 sig over actual digest
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(privateKey1, actualUserOpHash.toEthSignedMessageHash());
        bytes memory sig3 = abi.encodePacked(r3, s3, v3 + 32);

        userOp.signature = abi.encodePacked(sig3, sig2);

        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(BaseMultisigPlugin.InvalidNumSigsOnActualDigest.selector, type(uint256).max)
        );
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, actualUserOpHash
        );
    }

    function test_failUserOpValidation_sigOffset() public {
        _install();
        UserOperation memory userOp;
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        userOp.preVerificationGas = 1;

        Owner memory newOwner = _createContractOwner(uint256(keccak256("test_failUserOpValidation_sigOffset")));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.signerWallet.privateKey, userOpHash.toEthSignedMessageHash());

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(newOwner.owner);

        userOp.signature =
            abi.encodePacked(abi.encode(toAddress(newOwner.owner)), uint256(65), uint8(0), uint256(65), r, s, v);

        // Only check that the signature should fail if the signer is not already an owner
        (bool isOwner,) = plugin.isOwnerOf(account, ownersToAdd1[0]);
        if (!isOwner) {
            // should fail without owner access BUT not revert like below
            vm.prank(account);
            assertEq(
                plugin.userOpValidationFunction(
                    uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
                ),
                SIG_VALIDATION_FAILED
            );

            // add signer to owner
            vm.prank(account);
            plugin.addOwners(ownersToAdd1, weightOneList, new PublicKey[](0), new uint256[](0), 0);
        }

        userOp.signature = abi.encode(
            abi.encode(toAddress(newOwner.owner)),
            uint256(10000), // offset > len case
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidSigOffset.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );

        userOp.signature = abi.encode(
            abi.encode(toAddress(newOwner.owner)),
            uint256(0), // offset = 0 case
            uint8(0),
            uint256(65),
            r,
            s,
            v
        );

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidSigOffset.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
    }

    function test_failUserOpValidation_contractSignatureTooLong() public {
        _install();
        UserOperation memory userOp;
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        userOp.preVerificationGas = 1;

        Owner memory newOwner =
            _createContractOwner(uint256(keccak256("test_failUserOpValidation_contractSignatureTooLong")));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(newOwner.signerWallet.privateKey, userOpHash.toEthSignedMessageHash());

        address[] memory ownersToAdd1 = new address[](1);
        ownersToAdd1[0] = toAddress(newOwner.owner);

        userOp.signature = abi.encodePacked(
            abi.encode(toAddress(newOwner.owner)),
            uint256(65),
            uint8(0),
            uint256(100000), // sig length too long
            r,
            s,
            v
        );

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidContractSigLength.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
    }

    function test_failUserOpValidation_webauthnSignatureTooLong() public {
        _install();
        UserOperation memory userOp;
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        userOp.preVerificationGas = 1;

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPart;
        webAuthnSigDynamicPart.webAuthnData = _getWebAuthnData(userOpHash.toEthSignedMessageHash());
        bytes32 webauthnDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPart.webAuthnData);
        (uint256 r, uint256 s) = signP256Message(vm, passkeyPrivateKey, webauthnDigest);
        webAuthnSigDynamicPart.r = r;
        webAuthnSigDynamicPart.s = s;
        // x || dynamic pos || sig type || length of bytes || sig data bytes
        uint256 dynamicPos = 65; // 1 constant part
        bytes memory sigBytes = abi.encode(webAuthnSigDynamicPart);
        PublicKey[] memory pubKeyOwnersToAdd1 = new PublicKey[](1);
        pubKeyOwnersToAdd1[0] = PublicKey(passkeyPublicKeyX, passkeyPublicKeyY);
        bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), plugin.getOwnerId(pubKeyOwnersToAdd1[0])));
        // sig length too long
        userOp.signature = abi.encodePacked(pubKeyId, dynamicPos, uint8(34), sigBytes.length + 1, sigBytes);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(BaseMultisigPlugin.InvalidSigLength.selector));
        plugin.userOpValidationFunction(
            uint8(BaseMultisigPlugin.FunctionId.USER_OP_VALIDATION_OWNER), userOp, userOpHash
        );
    }

    function testAddUpdateThenRemoveWeights() public {
        // install with owner1
        address owner1 = address(0x1);
        uint256 weight1 = 2;
        uint256 thresholdWeight = 2;
        vm.expectEmit(true, true, true, true);
        address[] memory ownerList = new address[](1);
        uint256[] memory weightList = new uint256[](1);
        PublicKey[] memory emptyPubKeyList = new PublicKey[](0);
        uint256[] memory emptyPubKeyWeightList = new uint256[](0);
        // set the initial weight
        ownerList[0] = owner1;
        weightList[0] = weight1;

        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(ownerList, weightList, emptyPubKeyList, emptyPubKeyWeightList);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, 0, thresholdWeight);

        plugin.onInstall(abi.encode(ownerList, weightList, emptyPubKeyList, emptyPubKeyWeightList, thresholdWeight));

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        (uint256 res,,,,) = plugin.ownerDataPerAccount(owner1.toBytes30(), account);
        assertEq(res, weight1);

        uint256 returnedTotalWeight = ownershipMetadata.totalWeight;
        assertEq(_sum(returnedOwnersData), returnedTotalWeight);
        console.log("after installation with owner1, current total weight: %d", returnedTotalWeight);
        console.log("after installation with owner1, current total threshold weight: %d", returnedThresholdWeight);
        assertEq(returnedTotalWeight, weight1); // == 2
        assertEq(returnedThresholdWeight, thresholdWeight); // == 2
        assertEq(ownershipMetadata.numOwners, 1);

        // add owner2
        address owner2 = address(0x2);
        uint256 weight2 = 2;
        ownerList[0] = owner2;
        weightList[0] = weight2;
        thresholdWeight = 4;
        vm.prank(account);
        plugin.addOwners(ownerList, weightList, emptyPubKeyList, emptyPubKeyWeightList, thresholdWeight);

        (returnedOwners, returnedOwnersData, ownershipMetadata) = plugin.ownershipInfoOf(account);
        returnedTotalWeight = ownershipMetadata.totalWeight;
        returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        assertEq(_sum(returnedOwnersData), returnedTotalWeight);
        console.log("after adding owner2, new total weight: %d", returnedTotalWeight);
        console.log("after adding owner2, total threshold weight: %d", returnedThresholdWeight);
        assertEq(returnedTotalWeight, weight1 + weight2); // == 4
        assertEq(returnedThresholdWeight, thresholdWeight); // == 4
        assertEq(ownershipMetadata.numOwners, 2);

        // update owner2's weight from 2 to 4
        address[] memory updatedOwnerList = new address[](1);
        updatedOwnerList[0] = owner2;
        uint256 updatedWeight2 = 4;
        uint256[] memory updatedWeights = new uint256[](1);
        updatedWeights[0] = updatedWeight2;

        (_tOwners, _tWeights) =
            _mergeOwnersData(updatedOwnerList, updatedWeights, emptyPubKeyList, emptyPubKeyWeightList);
        vm.expectEmit(true, true, true, true);
        emit OwnersUpdated(account, _tOwners, _tWeights);
        vm.prank(account);
        thresholdWeight = 4;
        plugin.updateMultisigWeights(
            updatedOwnerList, updatedWeights, emptyPubKeyList, emptyPubKeyWeightList, thresholdWeight
        );

        (returnedOwners, returnedOwnersData, ownershipMetadata) = plugin.ownershipInfoOf(account);
        returnedTotalWeight = ownershipMetadata.totalWeight;
        assertEq(_sum(returnedOwnersData), returnedTotalWeight);
        uint256 expectedTotalWeight = weight1 + updatedWeight2;
        console.log("expected total weight: %d", expectedTotalWeight);
        console.log("after updating owner2, new total weight: %d", returnedTotalWeight);
        console.log("after updating owner2, new total threshold weight: %d", returnedThresholdWeight);
        assertEq(returnedTotalWeight, expectedTotalWeight); // == 6
        assertEq(returnedThresholdWeight, thresholdWeight); // == 4
        assertEq(ownershipMetadata.numOwners, 2);

        // remove owner1
        thresholdWeight = 4;
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = owner1;
        vm.prank(account);
        plugin.removeOwners(ownersToRemove, emptyPubKeyList, thresholdWeight);
        (returnedOwners, returnedOwnersData, ownershipMetadata) = plugin.ownershipInfoOf(account);
        returnedTotalWeight = ownershipMetadata.totalWeight;
        assertEq(_sum(returnedOwnersData), returnedTotalWeight);
        expectedTotalWeight = updatedWeight2;
        console.log("expected total weight: %d", expectedTotalWeight);
        console.log("after removing owner1, new total weight: %d", returnedTotalWeight);
        console.log("after removing owner1, new total threshold weight: %d", returnedThresholdWeight);
        assertEq(returnedTotalWeight, expectedTotalWeight); // == 4
        assertEq(returnedThresholdWeight, thresholdWeight); // == 4
        assertEq(ownershipMetadata.numOwners, 1);
    }

    function _addOwners(
        address[] memory _owners,
        uint256[] memory _weights,
        PublicKey[] memory _pubKeyOwners,
        uint256[] memory _pubKeyWeights,
        uint256 _newThresholdWeight
    ) internal {
        (,, OwnershipMetadata memory ownershipMetadata) = plugin.ownershipInfoOf(account);
        uint256 _oldThresholdWeight = ownershipMetadata.thresholdWeight;
        if (_newThresholdWeight > 0 && _newThresholdWeight != _oldThresholdWeight) {
            vm.expectEmit(true, true, true, true);
            emit ThresholdUpdated(account, _oldThresholdWeight, _newThresholdWeight);
        }

        vm.expectEmit(true, true, true, true);

        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(_owners, _weights, _pubKeyOwners, _pubKeyWeights);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.prank(account);
        plugin.addOwners(_owners, _weights, _pubKeyOwners, _pubKeyWeights, _newThresholdWeight);

        (bytes30[] memory _expectedOwners, OwnerData[] memory _expectedWeights) =
            _getExpectedOwnersAndWeights(_tOwners, _tWeights);
        uint256 _expectedThresholdWeight = _newThresholdWeight == 0 ? _oldThresholdWeight : _newThresholdWeight;
        _expectState(account, _expectedOwners, _expectedWeights, _expectedThresholdWeight);
    }

    function _install() internal {
        vm.expectEmit(true, true, true, true);
        (bytes30[] memory _tOwners, OwnerData[] memory _tWeights) =
            _mergeOwnersData(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList);
        emit OwnersAdded(account, _tOwners, _tWeights);

        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(account, 0, thresholdWeightOne);

        plugin.onInstall(
            abi.encode(ownerOneList, weightOneList, pubKeyOneList, pubKeyWeightOneList, thresholdWeightOne)
        );

        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        (uint256 res,,,,) = plugin.ownerDataPerAccount(ownerOne.toBytes30(), account);
        assertEq(res, weightOne);

        assertEq(returnedOwners.length, 2);
        assertEq(returnedOwners[0], pubKeyOne.toBytes30());
        assertEq(returnedOwners[1], ownerOne.toBytes30());
        assertEq(returnedOwnersData.length, 2);
        assertEq(returnedOwnersData[0].weight, pubKeyWeightOne);
        assertEq(returnedOwnersData[1].weight, weightOne);
        assertEq(returnedThresholdWeight, thresholdWeightOne);
    }

    function _createContractOwner(uint256 signerKeySeed) internal returns (Owner memory o) {
        VmSafe.Wallet memory signerWallet;
        (signerWallet.addr, signerWallet.privateKey) = makeAddrAndKey(string(abi.encodePacked(signerKeySeed)));
        MockContractOwner m = new MockContractOwner(signerWallet.addr);
        o.owner = address(m).toBytes30();
        o.signerWallet = signerWallet;
        return o;
    }

    function _expectState(
        address _account,
        bytes30[] memory _expectedOwners,
        OwnerData[] memory _expectedWeights,
        uint256 _threshold
    ) internal view {
        // Ownership Metadata is updated, including threshold
        (
            bytes30[] memory returnedOwners,
            OwnerData[] memory returnedOwnersData,
            OwnershipMetadata memory ownershipMetadata
        ) = plugin.ownershipInfoOf(_account);
        uint256 returnedThresholdWeight = ownershipMetadata.thresholdWeight;
        // Total Weight
        assertEq(_sum(returnedOwnersData), _sum(_expectedWeights));

        // Threshold weight
        assertEq(returnedThresholdWeight, _threshold);

        // Number of owners and weights
        assertEq(returnedOwners.length, _expectedOwners.length);
        assertEq(returnedOwners.length, returnedOwnersData.length);

        // Specific owners
        for (uint256 i = 0; i < returnedOwners.length; i++) {
            assertEq(returnedOwners[i], _expectedOwners[i]);
        }

        uint256 weight;
        CredentialType credType;
        address addr;
        uint256 publicKeyX;
        uint256 publicKeyY;
        for (uint256 i = 0; i < returnedOwnersData.length; i++) {
            // OwnerData are stored in address-associated mapping
            (weight, credType, addr, publicKeyX, publicKeyY) = plugin.ownerDataPerAccount(returnedOwners[i], account);
            assertEq(weight, returnedOwnersData[i].weight);
            assertEq(uint8(credType), uint8(returnedOwnersData[i].credType));
            assertEq(addr, returnedOwnersData[i].addr);
            assertEq(publicKeyX, returnedOwnersData[i].publicKeyX);
            assertEq(publicKeyY, returnedOwnersData[i].publicKeyY);
        }
    }

    // Before making assertions about expected added owners and weights, we need to do some translations on inputted
    // arrays:
    // reverse owner and weight arrays. This is necessary because we _ownershipInfoOf() returns in most recent insertion
    // order
    // add `ownerOne`, `weightOne`, `pubKeyOne` and `pubKeyWeightOne` at end of reversed arrays, because this owner is
    // added during installation.
    function _getExpectedOwnersAndWeights(bytes30[] memory _owners, OwnerData[] memory _weights)
        internal
        view
        returns (bytes30[] memory _expectedOwners, OwnerData[] memory _expectedWeights)
    {
        // 1 ownerOne, 1 pubKeyOne were preinstalled
        uint256 _expectedOwnerLen = _owners.length + 2;
        bytes30[] memory _ownersOrderedByLastInsertion = new bytes30[](_expectedOwnerLen);
        OwnerData[] memory _weightsOrderedByLastInsertion = new OwnerData[](_expectedOwnerLen);

        bytes30[] memory _ownersReversed = _reverseBytes30Array(_owners);
        OwnerData[] memory _weightsReversed = _reverseOwnerDataArray(_weights);

        for (uint256 i = 0; i < _owners.length; i++) {
            _ownersOrderedByLastInsertion[i] = _ownersReversed[i];
        }

        _ownersOrderedByLastInsertion[_ownersOrderedByLastInsertion.length - 1] = ownerOne.toBytes30();
        _ownersOrderedByLastInsertion[_ownersOrderedByLastInsertion.length - 2] = pubKeyOne.toBytes30();

        for (uint256 i = 0; i < _weights.length; i++) {
            _weightsOrderedByLastInsertion[i] = _weightsReversed[i];
        }

        _weightsOrderedByLastInsertion[_weightsOrderedByLastInsertion.length - 1].weight = weightOne;
        _weightsOrderedByLastInsertion[_weightsOrderedByLastInsertion.length - 2].weight = pubKeyWeightOne;
        return (_ownersOrderedByLastInsertion, _weightsOrderedByLastInsertion);
    }

    function _sum(uint256[] memory arr) internal pure returns (uint256 result) {
        for (uint256 i = 0; i < arr.length; i++) {
            result += arr[i];
        }
        return result;
    }

    function _sum(OwnerData[] memory arr) internal pure returns (uint256 result) {
        for (uint256 i = 0; i < arr.length; i++) {
            result += arr[i].weight;
        }
        return result;
    }

    function _reverseBytes30Array(bytes30[] memory array) internal pure returns (bytes30[] memory) {
        bytes30[] memory reversedArray = new bytes30[](array.length);

        for (uint256 i = 0; i < array.length; i++) {
            reversedArray[i] = array[array.length - 1 - i];
        }

        return reversedArray;
    }

    function _reverseOwnerDataArray(OwnerData[] memory array) internal pure returns (OwnerData[] memory) {
        OwnerData[] memory reversedArray = new OwnerData[](array.length);

        for (uint256 i = 0; i < array.length; i++) {
            reversedArray[i] = array[array.length - 1 - i];
        }

        return reversedArray;
    }

    function _mergeOwnersData(
        address[] memory owners,
        uint256[] memory weights,
        PublicKey[] memory publicKeyOwners,
        uint256[] memory pubicKeyWeights
    ) internal pure returns (bytes30[] memory totalOwners, OwnerData[] memory ownersData) {
        uint256 aLen = owners.length;
        uint256 bLen = publicKeyOwners.length;
        if (aLen != weights.length || bLen != pubicKeyWeights.length) {
            revert OwnersWeightsMismatch();
        }
        uint256 totalLen = aLen + bLen;
        totalOwners = new bytes30[](totalLen);
        ownersData = new OwnerData[](totalLen);
        uint256 index = 0;
        for (uint256 i = 0; i < aLen; ++i) {
            totalOwners[index] = owners[i].toBytes30();
            ownersData[index].weight = weights[i];
            ownersData[index].credType = CredentialType.ADDRESS;
            ownersData[index].addr = owners[i];
            index++;
        }
        for (uint256 i = 0; i < bLen; ++i) {
            totalOwners[index] = publicKeyOwners[i].toBytes30();
            ownersData[index].weight = pubicKeyWeights[i];
            ownersData[index].credType = CredentialType.PUBLIC_KEY;
            ownersData[index].publicKeyX = publicKeyOwners[i].x;
            ownersData[index].publicKeyY = publicKeyOwners[i].y;
            index++;
        }
    }

    function _isSame(PublicKey memory a, PublicKey memory b) internal pure returns (bool) {
        return a.x == b.x && a.y == b.y;
    }

    function _getWebAuthnData(bytes32 challenge) internal pure returns (WebAuthnData memory webAuthnData) {
        webAuthnData.clientDataJSON = string(
            abi.encodePacked(
                // solhint-disable-next-line quotes
                '{"type":"webauthn.get","challenge":"',
                WebAuthnLib.encodeURL(abi.encode(challenge)),
                // solhint-disable-next-line quotes
                '","origin":"https://developers.circle.com/","crossOrigin":false}'
            )
        );
        // TODO: write a python script to generate authenticator data randomly
        webAuthnData.authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001";
        webAuthnData.challengeIndex = 23;
        webAuthnData.typeIndex = 1;
        return webAuthnData;
    }

    function _getWebAuthnMessageHash(WebAuthnData memory webAuthnData) internal pure returns (bytes32 messageHash) {
        bytes32 clientDataJSONHash = sha256(bytes(webAuthnData.clientDataJSON));
        messageHash = sha256(abi.encodePacked(webAuthnData.authenticatorData, clientDataJSONHash));
        return messageHash;
    }

    /// @dev load 10 pre generated keys for testing purpose.
    function _loadP256Keys() internal view returns (TestKey[] memory testKeys) {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, P256_10_KEYS_FIXTURE);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".numOfKeys"), (uint256));
        testKeys = new TestKey[](count);

        for (uint256 i; i < count; ++i) {
            (, uint256 privateKey, uint256 x, uint256 y) = _parseJson({json: json, resultIndex: i});
            testKeys[i] = TestKey({privateKey: privateKey, publicKeyX: x, publicKeyY: y});
        }
    }

    function _parseJson(string memory json, uint256 resultIndex)
        internal
        pure
        returns (string memory jsonResultSelector, uint256 privateKey, uint256 x, uint256 y)
    {
        jsonResultSelector = string.concat(".results.[", string.concat(vm.toString(resultIndex), "]"));
        privateKey = abi.decode(json.parseRaw(string.concat(jsonResultSelector, ".private_key")), (uint256));
        x = abi.decode(json.parseRaw(string.concat(jsonResultSelector, ".x")), (uint256));
        y = abi.decode(json.parseRaw(string.concat(jsonResultSelector, ".y")), (uint256));
    }

    /// @dev Helper function to convert address stored as in bytes30 to address.
    function toAddress(bytes30 addrInBytes30) internal pure returns (address) {
        return address(uint160(uint240(addrInBytes30)));
    }
}
