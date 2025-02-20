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

import {PublicKey, WebAuthnData, WebAuthnSigDynamicPart} from "../../../../../src/common/CommonStructs.sol";
import {AddressBytesLib} from "../../../../../src/libs/AddressBytesLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {
    Call,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {PublicKeyLib} from "../../../../../src/libs/PublicKeyLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";

import {
    AccountMetadata,
    CheckNSignaturesRequest,
    CheckNSignaturesResponse,
    SignerMetadata,
    SignerMetadataWithId
} from "../../../../../src/msca/6900/v0.8/modules/multisig/MultisigStructs.sol";
import {SingleSignerValidationModule} from
    "../../../../../src/msca/6900/v0.8/modules/validation/SingleSignerValidationModule.sol";

import {UpgradableMSCA} from "../../../../../src/msca/6900/v0.8/account/UpgradableMSCA.sol";
import {UpgradableMSCAFactory} from "../../../../../src/msca/6900/v0.8/factories/UpgradableMSCAFactory.sol";

import {IWeightedMultisigValidationModule} from
    "../../../../../src/msca/6900/v0.8/modules/multisig/IWeightedMultisigValidationModule.sol";
import {WeightedMultisigValidationModule} from
    "../../../../../src/msca/6900/v0.8/modules/multisig/WeightedMultisigValidationModule.sol";

import {AccountTestUtils} from "../utils/AccountTestUtils.sol";

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED,
    ZERO,
    ZERO_BYTES32
} from "../../../../../src/common/Constants.sol";
import {WebAuthnLib} from "../../../../../src/libs/WebAuthnLib.sol";
import {MAX_SIGNERS} from "../../../../../src/msca/6900/v0.8/modules/multisig/MultisigConstants.sol";
import {MockContractOwner} from "../../../../util/MockContractOwner.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

import {UnauthorizedCaller} from "../../../../../src/common/Errors.sol";
import {CheckNSignatureError} from "../../../../../src/msca/6900/v0.8/modules/multisig/MultisigEnums.sol";
import {FCL_Elliptic_ZZ} from "@fcl/FCL_elliptic.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {stdJson} from "forge-std/src/StdJson.sol";
import {VmSafe} from "forge-std/src/Vm.sol";
import {console} from "forge-std/src/console.sol";

contract WeightedMultisigValidationModuleTest is AccountTestUtils {
    using ECDSA for bytes32;
    using PublicKeyLib for PublicKey[];
    using PublicKeyLib for PublicKey;
    using AddressBytesLib for address;
    using stdJson for string;
    using MessageHashUtils for bytes32;
    using Strings for uint256;

    event ValidationInstalled(address indexed module, uint32 indexed entityId);
    event WalletStorageInitialized();
    event UpgradableMSCAInitialized(address indexed account, address indexed entryPointAddress);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    event AccountMetadataUpdated(
        address indexed account, uint32 indexed entityId, AccountMetadata oldMetadata, AccountMetadata newMetadata
    );
    event SignersAdded(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] addedSigners);
    event SignersRemoved(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] removedSigners);
    event SignersUpdated(address indexed account, uint32 indexed entityId, SignerMetadataWithId[] updatedSigners);

    error InvalidSignerWeight(uint32 entityId, address account, bytes30 signerId, uint256 weight);
    error ZeroThresholdWeight(uint32 entityId, address account);
    error SignerWeightsLengthMismatch(uint32 entityId, address account);
    error ThresholdWeightExceedsTotalWeight(uint256 thresholdWeight, uint256 totalWeight);
    error TooManySigners(uint256 numSigners);
    error TooFewSigners(uint256 numSigners);
    error InvalidSignerMetadata(uint32 entityId, address account, SignerMetadata signerMetadata);
    error SignerIdAlreadyExists(uint32 entityId, address account, bytes30 signerId);
    error SignerIdDoesNotExist(uint32 entityId, address account, bytes30 signerId);
    error SignerMetadataDoesNotExist(uint32 entityId, address account, bytes30 signerId);
    error SignerMetadataAlreadyExists(uint32 entityId, address account, SignerMetadata signerMetaData);
    error AlreadyInitialized(uint32 entityId, address account);
    error Uninitialized(uint32 entityId, address account);
    error EmptyThresholdWeightAndSigners(uint32 entityId, address account);
    error InvalidSigLength(uint32 entityId, address account, uint256 length);
    error InvalidAddress(uint32 entityId, address account, address addr);
    error InvalidSigOffset(uint32 entityId, address account, uint256 offset);
    error InvalidNumSigsOnActualDigest(uint32 entityId, address account, uint256 numSigs);
    error Unsupported();
    error InvalidUserOpDigest(uint32 entityId, address account);
    error InvalidPublicKey(uint256 x, uint256 y);
    error FailToGeneratePublicKey(uint256 x, uint256 y);
    error UnsupportedSigType(uint32 entityId, address account, uint8 sigType);
    error InvalidAuthorizationLength(uint32 entityId, address account, uint256 length);

    SingleSignerValidationModule private singleSignerValidationModule;
    WeightedMultisigValidationModule private module;
    UpgradableMSCAFactory private factory;
    address payable private beneficiary;
    UpgradableMSCA private msca;
    // for WeightedMultisigValidationModule
    ModuleEntity private multisigValidation;
    uint32 private multisigEntityId = uint32(0);
    address private factorySigner;
    // SSVM = Single Signer Validation Module
    uint32 private ecdsaSignerOneEntityIdForSSVM = uint32(1);
    ModuleEntity private ecdsaSignerOneValidationForSSVM;
    IEntryPoint private entryPoint = new EntryPoint();
    bytes32 private salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
    string internal constant P256_10_KEYS_FIXTURE = "/test/fixtures/p256key_11_fixture.json";

    struct Signer {
        bytes30 signerId;
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
        address contractAddr; // sigType == 0
    }

    struct TestR1Key {
        uint256 publicKeyX;
        uint256 publicKeyY;
        uint256 privateKey;
    }

    Signer private eoaSignerOne;
    Signer private eoaSignerTwo;
    address private eoaSignerOneAddr;
    address private eoaSignerTwoAddr;
    uint256 private eoaSignerOnePrivateKey;
    uint256 private eoaSignerTwoPrivateKey;
    bytes30 private eoaSignerOneId;
    bytes30 private eoaSignerTwoId;

    Signer private contractSignerOne;
    Signer private contractSignerTwo;

    Signer private passKeySignerOne;
    Signer private passKeySignerTwo;
    PublicKey private passKeySignerOnePublicKey;
    PublicKey private passKeySignerTwoPublicKey;

    struct AddAndRemoveSignersFuzzInput {
        uint256 numOfSigner;
        uint32 entityId;
        uint256 signersToDelete;
    }

    /// @dev Each signer must have weight 1 for this setup.
    struct MultisigInput {
        uint256 actualSigners; // number of signers that actually sign
        uint256 totalSigners; // number of total signers
        uint256 sigDynamicPartOffset;
    }

    function setUp() public {
        beneficiary = payable(address(makeAddr("bundler")));
        factorySigner = makeAddr("factorySigner");
        factory = new UpgradableMSCAFactory(factorySigner, address(entryPoint));
        singleSignerValidationModule = new SingleSignerValidationModule();
        module = new WeightedMultisigValidationModule(address(entryPoint));

        address[] memory _modules = new address[](2);
        _modules[0] = address(module);
        // we enable singleSignerValidationModule for some test cases
        _modules[1] = address(singleSignerValidationModule);
        bool[] memory _permissions = new bool[](2);
        _permissions[0] = true;
        _permissions[1] = true;
        vm.startPrank(factorySigner);
        factory.setModules(_modules, _permissions);
        vm.stopPrank();

        ecdsaSignerOneValidationForSSVM =
            ModuleEntityLib.pack(address(singleSignerValidationModule), ecdsaSignerOneEntityIdForSSVM);
        // multisig
        multisigValidation = ModuleEntityLib.pack(address(module), multisigEntityId);
        // set up signers
        eoaSignerOne = _createEOASigner("eoaSigner1");
        eoaSignerTwo = _createEOASigner("eoaSigner2");
        eoaSignerOneAddr = eoaSignerOne.signerWallet.addr;
        eoaSignerTwoAddr = eoaSignerTwo.signerWallet.addr;
        eoaSignerOneId = eoaSignerOne.signerId;
        eoaSignerTwoId = eoaSignerTwo.signerId;
        eoaSignerOnePrivateKey = eoaSignerOne.signerWallet.privateKey;
        eoaSignerTwoPrivateKey = eoaSignerTwo.signerWallet.privateKey;

        contractSignerOne = _createContractSigner("contractSigner1");
        contractSignerTwo = _createContractSigner("contractSigner2");

        passKeySignerOne = _createPasskeySigner(0);
        passKeySignerTwo = _createPasskeySigner(1);
        passKeySignerOnePublicKey =
            PublicKey({x: passKeySignerOne.signerWallet.publicKeyX, y: passKeySignerOne.signerWallet.publicKeyY});
        passKeySignerTwoPublicKey =
            PublicKey({x: passKeySignerTwo.signerWallet.publicKeyX, y: passKeySignerTwo.signerWallet.publicKeyY});
    }

    function testEntryPoint() public view {
        assertEq(module.ENTRYPOINT(), address(entryPoint));
    }

    function testModuleId() public view {
        assertEq(module.moduleId(), "circle.weighted-multisig-module.1.0.0");
    }

    // they are also tested during signature signing
    function testFuzz_relaySafeMessageHash(bytes32 hash) public view {
        address account = address(msca);
        bytes32 replaySafeHash = module.getReplaySafeMessageHash(account, hash);
        bytes32 expected = MessageHashUtils.toTypedDataHash({
            domainSeparator: keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                    ),
                    keccak256(abi.encodePacked("circle.weighted-multisig-module.1.0.0")),
                    keccak256(abi.encodePacked("1.0.0")),
                    block.chainid,
                    address(module),
                    bytes32(bytes20(account))
                )
            ),
            structHash: keccak256(abi.encode(keccak256("CircleWeightedMultisigMessage(bytes message)"), hash))
        });
        assertEq(replaySafeHash, expected);
    }

    function testSupportsInterfaces() public view {
        assertTrue(module.supportsInterface(type(IWeightedMultisigValidationModule).interfaceId));
        assertTrue(module.supportsInterface(type(IValidationModule).interfaceId));
        assertTrue(module.supportsInterface(type(IERC165).interfaceId));
        assertTrue(module.supportsInterface(type(IModule).interfaceId));
    }

    // install WeightedMultisigValidationModule as part of deployment
    function testCreateAccountWithMultisigVM() public {
        ValidationConfig validationConfig = ValidationConfigLib.pack(multisigValidation, true, true, true);
        SignerMetadata[] memory signersMetadataToAdd = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadataToAdd[0] = signerMetaDataOne;
        signersMetadataToAdd[1] = signerMetaDataTwo;
        bytes memory installData = abi.encode(multisigEntityId, signersMetadataToAdd, 2);
        bytes memory initializingData = abi.encode(validationConfig, new bytes4[](0), installData, new bytes[](0));
        (address counterfactualAddr,) =
            factory.getAddressWithValidation(addressToBytes32(address(this)), salt, initializingData);

        // not needed for installation, only needed to verify the data
        SignerMetadataWithId[] memory addedSigners = new SignerMetadataWithId[](2);
        addedSigners[0].signerId = eoaSignerOneId;
        addedSigners[0].signerMetadata = signersMetadataToAdd[0];
        addedSigners[1].signerId = eoaSignerTwoId;
        addedSigners[1].signerMetadata = signersMetadataToAdd[1];
        vm.expectEmit(true, true, true, true);
        emit SignersAdded(counterfactualAddr, multisigEntityId, addedSigners);

        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(
            counterfactualAddr, multisigEntityId, AccountMetadata(0, 0, 0), AccountMetadata(2, 2, 2)
        );

        vm.expectEmit(true, true, true, true);
        emit ValidationInstalled(address(module), multisigEntityId);

        vm.expectEmit(true, true, true, true);
        emit UpgradableMSCAInitialized(counterfactualAddr, address(entryPoint));

        vm.expectEmit(true, true, true, true);
        emit WalletStorageInitialized();

        msca = factory.createAccountWithValidation(addressToBytes32(address(this)), salt, initializingData);
        assertEq(address(msca), counterfactualAddr);

        // verify module
        SignerMetadataWithId[] memory signersMetadataRet =
            module.signersMetadataOf(multisigEntityId, counterfactualAddr);
        assertEq(signersMetadataRet[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(signersMetadataRet[0].signerMetadata.weight, 1);
        assertFalse(signersMetadataRet[0].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[0].signerId, eoaSignerOneId);

        assertEq(signersMetadataRet[1].signerMetadata.addr, eoaSignerTwoAddr);
        assertEq(signersMetadataRet[1].signerMetadata.weight, 1);
        assertFalse(signersMetadataRet[1].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[1].signerId, eoaSignerTwoId);

        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, counterfactualAddr);
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 2);
    }

    // 1. create an account with SingleSignerValidationModule
    // 2. install WeightedMultisigValidationModule (WMVM) with entityId 0
    // 3. uninstall WeightedMultisigValidationModule with entityId 0
    function testInstallAndUninstallWMVMAfterAccountCreation() public {
        (address signer,) = makeAddrAndKey("testInstallAndUninstallWMVMAfterAccountCreation_signer");
        ModuleEntity signerValidation = ModuleEntityLib.pack(address(singleSignerValidationModule), uint32(3));
        // entityId is 3
        ValidationConfig singleSignerValidationConfig = ValidationConfigLib.pack(signerValidation, true, true, true);
        bytes memory installData = abi.encode(uint32(3), signer);
        bytes memory initializingData =
            abi.encode(singleSignerValidationConfig, new bytes4[](0), installData, new bytes[](0));
        msca = factory.createAccountWithValidation(addressToBytes32(address(this)), salt, initializingData);

        ValidationConfig multisigValidationConfig = ValidationConfigLib.pack(multisigValidation, true, true, true);
        SignerMetadata[] memory signersMetadataToAdd = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 3;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadataToAdd[0] = signerMetaDataOne;
        signersMetadataToAdd[1] = signerMetaDataTwo;
        installData = abi.encode(multisigEntityId, signersMetadataToAdd, 2);

        Call[] memory calls = new Call[](1);
        calls[0] = Call(
            address(msca),
            0,
            abi.encodeCall(
                IModularAccount.installValidation,
                (multisigValidationConfig, new bytes4[](0), installData, new bytes[](0))
            )
        );

        SignerMetadataWithId[] memory addedSigners = new SignerMetadataWithId[](2);
        addedSigners[0].signerId = eoaSignerOneId;
        addedSigners[0].signerMetadata = signersMetadataToAdd[0];
        addedSigners[1].signerId = eoaSignerTwoId;
        addedSigners[1].signerMetadata = signersMetadataToAdd[1];
        vm.prank(address(msca));
        vm.expectEmit(true, true, true, true);
        emit SignersAdded(address(msca), multisigEntityId, addedSigners);

        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(0, 0, 0), AccountMetadata(2, 2, 4));

        vm.expectEmit(true, true, true, true);
        emit ValidationInstalled(address(module), multisigEntityId);
        msca.executeWithRuntimeValidation(
            abi.encodeCall(IModularAccount.executeBatch, (calls)),
            encodeSignature(new PreValidationHookData[](0), signerValidation, bytes(""), true)
        );

        // verify module
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(multisigEntityId, address(msca));
        assertEq(signersMetadataRet[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(signersMetadataRet[0].signerMetadata.weight, 1);
        assertFalse(signersMetadataRet[0].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[0].signerId, eoaSignerOneId);

        assertEq(signersMetadataRet[1].signerMetadata.addr, eoaSignerTwoAddr);
        assertEq(signersMetadataRet[1].signerMetadata.weight, 3);
        assertFalse(signersMetadataRet[1].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[1].signerId, eoaSignerTwoId);

        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 4);
        _uninstallForTestInstallAndUninstallWMVMAfterAccountCreation(signerValidation, signersMetadataRet);
    }

    function _uninstallForTestInstallAndUninstallWMVMAfterAccountCreation(
        ModuleEntity signerValidation,
        SignerMetadataWithId[] memory signersMetadataBeforeUninstall
    ) internal {
        bytes memory uninstallData = abi.encode(multisigEntityId);
        bytes memory uninstallValidationData =
            abi.encodeCall(IModularAccount.uninstallValidation, (multisigValidation, uninstallData, new bytes[](0)));
        SignerMetadataWithId[] memory deletedSignersMetadata =
            new SignerMetadataWithId[](signersMetadataBeforeUninstall.length);
        for (uint256 i = 0; i < deletedSignersMetadata.length; ++i) {
            // we delete the oldest signer first
            // but signersMetadataOf returns the most recent signer first
            deletedSignersMetadata[i] = signersMetadataBeforeUninstall[signersMetadataBeforeUninstall.length - i - 1];
        }
        // still need signerValidation because WeightedMultisigValidationModule doesn't support runtime call yet
        vm.prank(address(msca));
        vm.expectEmit(true, true, true, true);
        emit SignersRemoved(address(msca), multisigEntityId, deletedSignersMetadata);
        msca.executeWithRuntimeValidation(
            uninstallValidationData, encodeSignature(new PreValidationHookData[](0), signerValidation, bytes(""), true)
        );

        // verify module doesn't have any data after uninstall
        SignerMetadataWithId[] memory signersMetadataAfterUninstall =
            module.signersMetadataOf(multisigEntityId, address(msca));
        assertEq(signersMetadataAfterUninstall.length, 0);

        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 0);
        assertEq(accountMetadata.thresholdWeight, 0);
        assertEq(accountMetadata.totalWeight, 0);
    }

    function testInstallSameSignerWithDifferentWeightsOnDifferentEntityIds() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        // install another entity id with same signer but different weights
        uint32 multisigEntityId2 = uint32(1);
        signerMetaDataOne.weight = 4;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(
            // different threshold weight
            abi.encode(multisigEntityId2, signersMetadata, 4)
        );
        // verify the data for entityId(1)
        SignerMetadataWithId[] memory addedSigners = module.signersMetadataOf(multisigEntityId2, address(msca));
        assertEq(addedSigners.length, 1);
        assertEq(addedSigners[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(addedSigners[0].signerMetadata.weight, 4);
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId2, address(msca));
        assertEq(accountMetadata.numSigners, 1);
        assertEq(accountMetadata.thresholdWeight, 4);
        assertEq(accountMetadata.totalWeight, 4);

        // verify the data for entityId(0)
        addedSigners = module.signersMetadataOf(multisigEntityId, address(msca));
        assertEq(addedSigners.length, 1);
        assertEq(addedSigners[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(addedSigners[0].signerMetadata.weight, 2);
        accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 1);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 2);
    }

    function testInstallInvalidThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(abi.encodeWithSelector(ZeroThresholdWeight.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 0));
    }

    function testInstallNoSignersMetadata() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](0);
        vm.expectRevert(abi.encodeWithSelector(TooFewSigners.selector, 0));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallTooManySigners() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](MAX_SIGNERS + 1);
        for (uint256 i = 0; i < signersMetadata.length; i++) {
            SignerMetadata memory signerMetaData;
            signerMetaData.weight = 1;
            signerMetaData.addr = vm.addr(i + 1);
            signersMetadata[i] = signerMetaData;
        }
        vm.expectRevert(abi.encodeWithSelector(TooManySigners.selector, signersMetadata.length));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallWithBothAddrAndPubKeyPresent() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signerMetaDataOne.publicKey =
            PublicKey(passKeySignerOne.signerWallet.publicKeyX, passKeySignerOne.signerWallet.publicKeyY);
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSignerMetadata.selector, multisigEntityId, address(msca), signerMetaDataOne)
        );
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallWithBothAddrAndPubKeyAbsent() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        // no address or public key
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSignerMetadata.selector, multisigEntityId, address(msca), signerMetaDataOne)
        );
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallDuplicatedAddr() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                SignerMetadataAlreadyExists.selector, multisigEntityId, address(msca), signerMetaDataOne
            )
        );
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallWithInvalidWeights() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 0;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector, multisigEntityId, address(msca), eoaSignerOneId, signerMetaDataOne.weight
            )
        );
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        signerMetaDataOne.weight = 1000001;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector, multisigEntityId, address(msca), eoaSignerOneId, signerMetaDataOne.weight
            )
        );
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    // totalWeight < thresholdWeight
    function testInstallWithHighThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, 2, 1));
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
    }

    function testInstallTwice() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
        vm.expectRevert(abi.encodeWithSelector(AlreadyInitialized.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
    }

    function testFuzz_onInstallInvalidPublicKey(uint256 x, uint256 y) public {
        vm.assume(x >= FCL_Elliptic_ZZ.p);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey = PublicKey(x, y);
        signersMetadata[0] = signerMetaDataOne;

        vm.expectRevert(abi.encodeWithSelector(InvalidPublicKey.selector, x, y));
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
    }

    function testUninstallOnlyProvidedEntityId() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        // install another entity id
        module.onInstall(abi.encode(uint32(1), signersMetadata, 2));
        // uninstall uint32(1)
        module.onUninstall(abi.encode(uint32(1)));

        // verify the data for entityId(1) doesn't exist
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(uint32(1), address(msca));
        assertEq(signersMetadataRet.length, 0);
        AccountMetadata memory accountMetadata = module.accountMetadataOf(uint32(1), address(msca));
        assertEq(accountMetadata.numSigners, 0);
        assertEq(accountMetadata.thresholdWeight, 0);
        assertEq(accountMetadata.totalWeight, 0);

        // verify the data for entityId(0) still exists
        signersMetadataRet = module.signersMetadataOf(multisigEntityId, address(msca));
        assertEq(signersMetadataRet.length, 1);
        assertEq(signersMetadataRet[0].signerMetadata.addr, signerMetaDataOne.addr);
        assertEq(signersMetadataRet[0].signerMetadata.weight, signerMetaDataOne.weight);
        accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 1);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 2);
    }

    function testUninstallTwice() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
        vm.prank(address(msca));
        module.onUninstall(abi.encode(multisigEntityId));
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.onUninstall(abi.encode(multisigEntityId));
    }

    // 1. deploy the MSCA with signer 1 with SingleSignerValidationModule that provides signature validation
    // 2. we install WeightedMultisigValidationModule
    // 3. uninstall WeightedMultisigValidationModule
    function testInstallAndUninstallViaUserOp() public {
        // deploy the account along with executeBatch call that installs the remaining validation functions
        bytes memory installData = abi.encode(ecdsaSignerOneEntityIdForSSVM, eoaSignerTwoAddr);
        bytes memory initializingData = abi.encode(
            ValidationConfigLib.pack(ecdsaSignerOneValidationForSSVM, true, true, true),
            new bytes4[](0),
            installData,
            new bytes[](0)
        );
        (address sender,) = factory.getAddressWithValidation(addressToBytes32(address(this)), salt, initializingData);
        vm.deal(sender, 1 ether);
        bytes memory createAccountCall = abi.encodeCall(
            UpgradableMSCAFactory.createAccountWithValidation, (addressToBytes32(address(this)), salt, initializingData)
        );
        bytes memory initCode = abi.encodePacked(address(factory), createAccountCall);
        // executeBatchCallData
        Call[] memory calls = new Call[](1);
        ValidationConfig multisigValidationConfig = ValidationConfigLib.pack(multisigValidation, true, true, true);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 3;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        calls[0] = Call(
            sender,
            0,
            abi.encodeCall(
                IModularAccount.installValidation,
                (
                    multisigValidationConfig,
                    new bytes4[](0),
                    abi.encode(multisigEntityId, signersMetadata, 2),
                    new bytes[](0)
                )
            )
        );
        bytes memory executeCallData = abi.encodeCall(IModularAccount.executeBatch, (calls));
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender, 0, vm.toString(initCode), vm.toString(executeCallData), 1000000, 1000000, 0, 1, 1, "0x"
        );
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        // signed by the signer two that deploys the account
        bytes memory signature = signUserOpHash(entryPoint, vm, eoaSignerTwoPrivateKey, userOp);
        userOp.signature =
            encodeSignature(new PreValidationHookData[](0), ecdsaSignerOneValidationForSSVM, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(address(entryPoint));
        vm.expectEmit(true, true, true, false);
        emit UserOperationEvent(userOpHash, sender, address(0), 0, true, 685419, 685419);
        entryPoint.handleOps(ops, beneficiary);
        _verifyResultForTestInstallAndUninstallViaUserOp(sender);
        // uninstall
        _uninstallForTestInstallAndUninstallViaUserOp(sender, eoaSignerTwoPrivateKey, ecdsaSignerOneValidationForSSVM);
    }

    function _verifyResultForTestInstallAndUninstallViaUserOp(address sender) internal view {
        // verify the account has been deployed
        assertTrue(sender.code.length > 0);
        // verify signer 2 has been installed on SingleSignerValidationModule
        assertEq(singleSignerValidationModule.signers(ecdsaSignerOneEntityIdForSSVM, sender), eoaSignerTwoAddr);
        // verify WeightedMultisigValidationModule has been installed
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(multisigEntityId, sender);
        assertEq(signersMetadataRet[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(signersMetadataRet[0].signerMetadata.weight, 1);
        assertFalse(signersMetadataRet[0].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[0].signerId, eoaSignerOneId);

        assertEq(signersMetadataRet[1].signerMetadata.addr, eoaSignerTwoAddr);
        assertEq(signersMetadataRet[1].signerMetadata.weight, 3);
        assertFalse(signersMetadataRet[1].signerMetadata.publicKey.isValidPublicKey());
        assertEq(signersMetadataRet[1].signerId, eoaSignerTwoId);

        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, sender);
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 4);
    }

    function _uninstallForTestInstallAndUninstallViaUserOp(address sender, uint256 key, ModuleEntity signerValidation)
        internal
    {
        bytes memory uninstallData = abi.encode(multisigEntityId);
        bytes memory uninstallValidationData =
            abi.encodeCall(IModularAccount.uninstallValidation, (multisigValidation, uninstallData, new bytes[](0)));
        PackedUserOperation memory userOp = buildPartialUserOp(
            sender,
            entryPoint.getNonce(sender, 0),
            "0x",
            vm.toString(uninstallValidationData),
            1000000,
            1000000,
            0,
            1,
            1,
            "0x"
        );
        // signed by the singer two that deploys the account
        bytes memory signature = signUserOpHash(entryPoint, vm, key, userOp);
        userOp.signature = encodeSignature(new PreValidationHookData[](0), signerValidation, signature, true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(address(entryPoint));
        entryPoint.handleOps(ops, beneficiary);

        // verify module doesn't have any data after uninstall
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(multisigEntityId, address(msca));
        assertEq(signersMetadataRet.length, 0);
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 0);
        assertEq(accountMetadata.thresholdWeight, 0);
        assertEq(accountMetadata.totalWeight, 0);
    }

    // fuzz test on numOfSigner, entityId and signersToDelete
    // we first install an initial signer,
    // then add new signers from fuzz input and verify the added signers and account metadata,
    // then remove some of the added signers and verify the removed & remaining signers
    function testFuzz_addAndRemoveSigners(AddAndRemoveSignersFuzzInput memory input) public {
        // using MAX_SIGNERS (1000) would need significantly more time to run
        input.numOfSigner = bound(input.numOfSigner, 1, 100);
        input.signersToDelete = bound(input.signersToDelete, 1, input.numOfSigner);
        // init with one signer
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(input.entityId, signersMetadata, 1));
        // add new signers
        signersMetadata = new SignerMetadata[](input.numOfSigner);
        uint256 newThresholdWeight = 0;
        // skip deleting the initial signer
        bytes30[] memory signerIdsDeleted = new bytes30[](input.signersToDelete);
        bytes30[] memory signerIdsRemained = new bytes30[](input.numOfSigner - input.signersToDelete);
        SignerMetadata[] memory signersMetadataRemained =
            new SignerMetadata[](input.numOfSigner - input.signersToDelete);
        console.log("num of signers: ", input.numOfSigner);
        console.log("deleted signers: ", input.signersToDelete);
        console.log("remaining signers: ", input.numOfSigner - input.signersToDelete);
        // counter for deleted signers
        uint256 c1;
        // counter for remained signers
        uint256 c2;
        // exclude initial signer
        for (uint256 i = 0; i < signersMetadata.length; ++i) {
            if (i % 2 == 0) {
                signersMetadata[i].weight = i + 1;
                signersMetadata[i].addr = vm.addr(i + 1);
            } else {
                signersMetadata[i].weight = i + 1;
                signersMetadata[i].publicKey = _generateRandomPublicKey(i + 1);
            }
            newThresholdWeight += signersMetadata[i].weight;
            if (c1 < input.signersToDelete) {
                signerIdsDeleted[c1++] = _getSignerId(signersMetadata[i]);
            } else {
                signerIdsRemained[c2] = _getSignerId(signersMetadata[i]);
                signersMetadataRemained[c2] = signersMetadata[i];
                c2++;
            }
        }
        vm.prank(address(msca));
        module.addSigners(input.entityId, signersMetadata, newThresholdWeight);
        // verify the added signers and account metadata
        _verifyAddSignersResultForTestFuzzAddAndRemoveSigners(input, newThresholdWeight);
        vm.prank(address(msca));
        // remove the added signers
        module.removeSigners(input.entityId, signerIdsDeleted, 1); // use initial signer's weight
        _verifyRemoveSignersResultForTestFuzzAddAndRemoveSigners(
            input, signerIdsDeleted, signerIdsRemained, signersMetadataRemained
        );
    }

    function _getSignerId(SignerMetadata memory signerMetadata) internal view returns (bytes30) {
        if (signerMetadata.addr != address(0)) {
            return module.getSignerId(signerMetadata.addr);
        } else {
            return module.getSignerId(signerMetadata.publicKey);
        }
    }

    function _verifyAddSignersResultForTestFuzzAddAndRemoveSigners(
        AddAndRemoveSignersFuzzInput memory input,
        uint256 newThresholdWeight
    ) internal view {
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(input.entityId, address(msca));
        // initial signer
        assertEq(signersMetadataRet[0].signerMetadata.addr, eoaSignerOneAddr);
        assertEq(signersMetadataRet[0].signerMetadata.weight, 1);
        // exclude initial signer
        for (uint256 i = 1; i < signersMetadataRet.length; ++i) {
            if (signersMetadataRet[i].signerMetadata.addr != address(0)) {
                assertEq(signersMetadataRet[i].signerMetadata.addr, vm.addr(i)); // need to offset by 1 compared to
                    // signersMetadata
                assertEq(signersMetadataRet[i].signerMetadata.weight, i);
                assertEq(signersMetadataRet[i].signerId, module.getSignerId(signersMetadataRet[i].signerMetadata.addr));
            } else {
                PublicKey memory pubKey = _generateRandomPublicKey(i);
                assertEq(signersMetadataRet[i].signerMetadata.publicKey.x, pubKey.x);
                assertEq(signersMetadataRet[i].signerMetadata.publicKey.y, pubKey.y);
                assertEq(signersMetadataRet[i].signerMetadata.weight, i);
                assertEq(
                    signersMetadataRet[i].signerId, module.getSignerId(signersMetadataRet[i].signerMetadata.publicKey)
                );
            }
        }
        AccountMetadata memory accountMetadata = module.accountMetadataOf(input.entityId, address(msca));
        assertEq(accountMetadata.numSigners, input.numOfSigner + 1); // +1 for the initial signer
        assertEq(accountMetadata.thresholdWeight, newThresholdWeight);
        assertEq(accountMetadata.totalWeight, newThresholdWeight + 1); // +1 for the initial signer weight
    }

    function _verifyRemoveSignersResultForTestFuzzAddAndRemoveSigners(
        AddAndRemoveSignersFuzzInput memory input,
        bytes30[] memory signerIdsDeleted,
        bytes30[] memory signerIdsRemained,
        SignerMetadata[] memory signersMetadataRemained
    ) internal view {
        SignerMetadataWithId[] memory signersMetadataRet = module.signersMetadataOf(input.entityId, address(msca));
        assertEq(signersMetadataRet.length, 1 + signerIdsRemained.length); // add the initial signer
        uint256 totalRemainingWeight = 0;
        {
            // verify initial signer
            (uint256 weight, address addr,) =
                module.signersMetadataPerEntity(input.entityId, eoaSignerOneId, address(msca));
            assertEq(addr, eoaSignerOneAddr);
            assertEq(weight, 1);
            totalRemainingWeight += weight;
        }
        // verify the deleted signers are gone
        for (uint256 i = 0; i < signerIdsDeleted.length; ++i) {
            (uint256 weight, address addr, PublicKey memory publicKey) =
                module.signersMetadataPerEntity(input.entityId, signerIdsDeleted[i], address(msca));
            assertEq(weight, 0);
            assertEq(addr, address(0));
            assertEq(publicKey.x, 0);
            assertEq(publicKey.y, 0);
        }
        // verify the remaining signers after deletion
        for (uint256 i = 0; i < signerIdsRemained.length; ++i) {
            (uint256 weight, address addr, PublicKey memory publicKey) =
                module.signersMetadataPerEntity(input.entityId, signerIdsRemained[i], address(msca));
            assertEq(weight, signersMetadataRemained[i].weight);
            totalRemainingWeight += weight;
            if (addr != address(0)) {
                assertEq(addr, signersMetadataRemained[i].addr);
            } else {
                assertEq(publicKey.x, signersMetadataRemained[i].publicKey.x);
                assertEq(publicKey.y, signersMetadataRemained[i].publicKey.y);
            }
        }
        AccountMetadata memory accountMetadata = module.accountMetadataOf(input.entityId, address(msca));
        assertEq(accountMetadata.numSigners, 1 + signersMetadataRemained.length);
        assertEq(accountMetadata.thresholdWeight, 1); // from the initial signer
        assertEq(accountMetadata.totalWeight, totalRemainingWeight);
    }

    function testAddSignersToUninitializedAccount() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        module.addSigners(multisigEntityId, signersMetadata, 1);
    }

    function testAddZeroSigners() public {
        // init with one signer
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](0);
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(TooFewSigners.selector, 0));
        module.addSigners(multisigEntityId, signersMetadata, 1);
    }

    function testAddTooManySigners() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](1001);
        for (uint256 i = 0; i < 1001; i++) {
            SignerMetadata memory signerMetaData;
            signerMetaData.weight = 1;
            signerMetaData.addr = vm.addr(i + 1);
            signersMetadata[i] = signerMetaData;
        }
        vm.expectRevert(abi.encodeWithSelector(TooManySigners.selector, 1001));
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);
    }

    function testAddSignerWithBothAddrAndPubKeyPresent() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](1);
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signerMetaDataOne.publicKey =
            PublicKey(passKeySignerOne.signerWallet.publicKeyX, passKeySignerOne.signerWallet.publicKeyY);
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSignerMetadata.selector, multisigEntityId, address(msca), signerMetaDataOne)
        );
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);
    }

    function testAddSignersWithBothAddrAndPubKeyAbsent() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](1);
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = address(0);
        signerMetaDataOne.publicKey = PublicKey({x: 0, y: 0});
        // no address or public key
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSignerMetadata.selector, multisigEntityId, address(msca), signerMetaDataOne)
        );
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);
    }

    function testAddSignersWithDuplicatedAddr() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](2);
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataOne;
        SignerMetadataWithId[] memory signersMetadataRet = new SignerMetadataWithId[](2);
        signersMetadataRet[0].signerId = eoaSignerOneId;
        signersMetadataRet[0].signerMetadata = signerMetaDataOne;
        signersMetadataRet[1].signerId = eoaSignerOneId;
        signersMetadataRet[1].signerMetadata = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                SignerMetadataAlreadyExists.selector, multisigEntityId, address(msca), signerMetaDataOne
            )
        );
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);
    }

    function testAddSignersWithInvalidWeights() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signerMetaDataOne.weight = 0;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector, multisigEntityId, address(msca), eoaSignerOneId, signerMetaDataOne.weight
            )
        );
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);

        signerMetaDataOne.weight = 1000001;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector, multisigEntityId, address(msca), eoaSignerOneId, signerMetaDataOne.weight
            )
        );
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 2);
    }

    // totalWeight < thresholdWeight
    function testAddSignersWithHighThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](1);
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaData;
        vm.expectRevert(abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, 3, 2));
        vm.prank(address(msca));
        module.addSigners(multisigEntityId, signersMetadata, 3);
    }

    function testAddSignersWithoutUpdatingThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        signersMetadata = new SignerMetadata[](1);
        // new signer with weight 2
        signerMetaData.weight = 2;
        signerMetaData.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaData;
        SignerMetadataWithId[] memory signersMetadataRet = new SignerMetadataWithId[](1);
        signersMetadataRet[0].signerId = eoaSignerTwoId;
        signersMetadataRet[0].signerMetadata = signerMetaData;
        vm.prank(address(msca));
        vm.expectEmit(true, true, true, true);
        emit SignersAdded(address(msca), multisigEntityId, signersMetadataRet);
        // do not update the threshold weight
        module.addSigners(multisigEntityId, signersMetadata, 0);
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.thresholdWeight, 1);
    }

    function testRemoveSignersFromUninitializedAccount() public {
        bytes30[] memory signersToDelete = new bytes30[](1);
        signersToDelete[0] = eoaSignerOneId;
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        module.removeSigners(multisigEntityId, signersToDelete, 0);
    }

    function testRemoveSignersWithRandomSignerId() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        bytes30[] memory signerIdsToDelete = new bytes30[](1);
        // random entityId 123
        signerIdsToDelete[0] = module.getSignerId(address(123));
        vm.prank(address(msca));
        vm.expectRevert(
            abi.encodeWithSelector(SignerIdDoesNotExist.selector, multisigEntityId, address(msca), signerIdsToDelete[0])
        );
        module.removeSigners(multisigEntityId, signerIdsToDelete, 0);
    }

    function testRemoveLastSigner() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        bytes30[] memory signerIdsToDelete = new bytes30[](1);
        signerIdsToDelete[0] = eoaSignerOneId;
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(TooFewSigners.selector, 0));
        module.removeSigners(multisigEntityId, signerIdsToDelete, 0);
    }

    // totalWeight < thresholdWeight
    function testRemoveSignersWithHighThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        bytes30[] memory signerIdsToDelete = new bytes30[](1);
        signerIdsToDelete[0] = eoaSignerOneId;
        vm.prank(address(msca));
        // removing 2, now totalWeight is 1 < thresholdWeight 2
        vm.expectRevert(abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, 2, 1));
        module.removeSigners(multisigEntityId, signerIdsToDelete, 0);
    }

    function testRemoveSignersWithoutUpdatingThresholdWeight() public {
        SignerMetadata[] memory signersToRemove = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersToRemove[0] = signerMetaDataOne;
        signersToRemove[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersToRemove, 1));

        bytes30[] memory signerIdsToDelete = new bytes30[](1);
        signerIdsToDelete[0] = eoaSignerOneId;
        SignerMetadataWithId[] memory removedSigners = new SignerMetadataWithId[](1);
        removedSigners[0].signerId = eoaSignerOneId;
        removedSigners[0].signerMetadata = signerMetaDataOne;
        vm.prank(address(msca));
        // removing 1, now totalWeight is 1 == thresholdWeight 1
        // no update to threshold weight
        vm.expectEmit(true, true, true, true);
        emit SignersRemoved(address(msca), multisigEntityId, removedSigners);
        module.removeSigners(multisigEntityId, signerIdsToDelete, 0);
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 1);
        assertEq(accountMetadata.thresholdWeight, 1); // still 1
        assertEq(accountMetadata.totalWeight, 1);
    }

    function testRemoveSignersWithSignerIds() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(TooFewSigners.selector, 0));
        // zero signers
        module.removeSigners(multisigEntityId, new bytes30[](0), 0);
    }

    function testUpdateWeightsWithUninitializedAccount() public {
        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signersToUpdate[0].signerMetadata = signerMetaData;
        SignerMetadataWithId[] memory updatedSigners = new SignerMetadataWithId[](1);
        updatedSigners[0].signerId = eoaSignerOneId;
        updatedSigners[0].signerMetadata = signerMetaData;
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
    }

    function testUpdateWeightsWithNothingToUpdate() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](0);
        vm.prank(address(msca));
        vm.expectRevert(
            abi.encodeWithSelector(EmptyThresholdWeightAndSigners.selector, multisigEntityId, address(msca))
        );
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
    }

    function testUpdateWeightsWithInvalidWeights() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaData;
        signerMetaData.weight = 1;
        signerMetaData.addr = eoaSignerOneAddr;
        signersMetadata[0] = signerMetaData;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](1);
        signersToUpdate[0].signerId = eoaSignerOneId;
        signersToUpdate[0].signerMetadata.weight = 0;
        // only need id & weight, setting addr just to verify logs
        signersToUpdate[0].signerMetadata.addr = signersMetadata[0].addr;
        vm.prank(address(msca));
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector,
                multisigEntityId,
                address(msca),
                signersToUpdate[0].signerId,
                signersToUpdate[0].signerMetadata.weight
            )
        );
        module.updateWeights(multisigEntityId, signersToUpdate, 0);

        signersToUpdate[0].signerMetadata.weight = 1000001;
        vm.prank(address(msca));
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidSignerWeight.selector,
                multisigEntityId,
                address(msca),
                signersToUpdate[0].signerId,
                signersToUpdate[0].signerMetadata.weight
            )
        );
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
    }

    function testUpdateWeightsWithOnlySignerWeights() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 2;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](2);
        signersToUpdate[0].signerMetadata = signerMetaDataOne;
        signersToUpdate[1].signerMetadata = signerMetaDataTwo;
        signersToUpdate[0].signerId = eoaSignerOneId;
        signersToUpdate[1].signerId = eoaSignerTwoId;
        // one decrease, one increase, delta is 1
        // 2 -> 1
        signersToUpdate[0].signerMetadata.weight = 1;
        // 2 -> 4
        signersToUpdate[1].signerMetadata.weight = 4;
        vm.expectEmit(true, true, true, true);
        emit SignersUpdated(address(msca), multisigEntityId, signersToUpdate);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 4), AccountMetadata(2, 2, 5));
        // no modification to threshold weight
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
        // verify account metadata
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 5);

        // one increase, one decrease, delta is 0
        // 1 -> 2
        signersToUpdate[0].signerMetadata.weight = 2;
        // 4 -> 3
        signersToUpdate[1].signerMetadata.weight = 3;
        vm.expectEmit(true, true, true, true);
        emit SignersUpdated(address(msca), multisigEntityId, signersToUpdate);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 5), AccountMetadata(2, 2, 5));
        // no modification to threshold weight
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
        // verify account metadata
        accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 5);

        // both decrease, delta is -3
        // 2 -> 1
        signersToUpdate[0].signerMetadata.weight = 1;
        // 3 -> 1
        signersToUpdate[1].signerMetadata.weight = 1;
        vm.expectEmit(true, true, true, true);
        emit SignersUpdated(address(msca), multisigEntityId, signersToUpdate);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 5), AccountMetadata(2, 2, 2));
        // no modification to threshold weight
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
        // verify account metadata
        accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 2);

        // both increase, delta is 2
        // 1 -> 2
        signersToUpdate[0].signerMetadata.weight = 2;
        // 1 -> 2
        signersToUpdate[1].signerMetadata.weight = 2;
        vm.expectEmit(true, true, true, true);
        emit SignersUpdated(address(msca), multisigEntityId, signersToUpdate);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 2), AccountMetadata(2, 2, 4));
        // no modification to threshold weight
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 0);
        // verify account metadata
        accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 4);
    }

    function testUpdateWeightsWithOnlyThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 2;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](0);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 4), AccountMetadata(2, 3, 4));
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 3);
        // verify account metadata
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 3);
        assertEq(accountMetadata.totalWeight, 4);
    }

    function testUpdateWeightsWithBothSignerAndThresholdWeights() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 2;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](2);
        signersToUpdate[0].signerMetadata = signerMetaDataOne;
        signersToUpdate[1].signerMetadata = signerMetaDataTwo;
        signersToUpdate[0].signerId = eoaSignerOneId;
        signersToUpdate[1].signerId = eoaSignerTwoId;
        // decrease from 2
        signersToUpdate[0].signerMetadata.weight = 1;
        // increase from 2
        signersToUpdate[1].signerMetadata.weight = 3;
        vm.expectEmit(true, true, true, true);
        emit SignersUpdated(address(msca), multisigEntityId, signersToUpdate);
        vm.expectEmit(true, true, true, true);
        emit AccountMetadataUpdated(address(msca), multisigEntityId, AccountMetadata(2, 2, 4), AccountMetadata(2, 3, 4));
        // no modification to threshold weight
        vm.prank(address(msca));
        module.updateWeights(multisigEntityId, signersToUpdate, 3);
        // verify account metadata
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 3);
        assertEq(accountMetadata.totalWeight, 4);
    }

    function testUpdateWeightsWithTooHighThresholdWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 2;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 2;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));

        SignerMetadataWithId[] memory signersToUpdate = new SignerMetadataWithId[](0);
        vm.prank(address(msca));
        vm.expectRevert(abi.encodeWithSelector(ThresholdWeightExceedsTotalWeight.selector, 10, 4));
        module.updateWeights(multisigEntityId, signersToUpdate, 10);
        // verify account metadata is not changed
        AccountMetadata memory accountMetadata = module.accountMetadataOf(multisigEntityId, address(msca));
        assertEq(accountMetadata.numSigners, 2);
        assertEq(accountMetadata.thresholdWeight, 2);
        assertEq(accountMetadata.totalWeight, 4);
    }

    function testValidateSignatureLengthTooShort() public {
        bytes32 digest = bytes32(0);
        bytes memory sig = bytes("foo");
        vm.expectRevert(abi.encodeWithSelector(InvalidSigLength.selector, multisigEntityId, address(msca), sig.length));
        vm.prank(address(msca));
        module.validateSignature(address(msca), multisigEntityId, address(this), digest, sig);
    }

    function testValidateSignatureUninitializedAccount() public {
        bytes32 digest = bytes32(0);
        bytes memory sig = bytes("0x0000000000000000000000000000000000000000000000000000000000000000");
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.validateSignature(address(msca), multisigEntityId, address(this), digest, sig);
    }

    // 2nd signer has too short signature
    function testCheckNSignaturesSigConstantPartTooShort() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // create a valid signature for 1st installed signer
        bytes32 digest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        bytes memory sig = signMessage(vm, eoaSignerOnePrivateKey, digest);
        assertEq(sig.length, 65);

        // append <65 bytes of data for 2nd installed signer
        bytes memory fooBytes = bytes("foo");
        bytes memory sigWithFooAppended = abi.encodePacked(sig, fooBytes);
        assertEq(sigWithFooAppended.length, 68);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: digest,
            minimalDigest: digest,
            requiredNumSigsOnActualDigest: 0,
            account: address(msca),
            signatures: sigWithFooAppended
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, false);
        assertEq(response.firstFailure, 1);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.SIG_PARTS_OVERLAP));
    }

    function testCheckNSignaturesSigRevertOnTooHighV() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // create a valid signature for 1st installed signer
        bytes32 digest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaSignerOnePrivateKey, digest);
        v += 61;
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: digest,
            minimalDigest: digest,
            requiredNumSigsOnActualDigest: 0,
            account: address(msca),
            signatures: sig
        });
        vm.expectRevert(abi.encodeWithSelector(UnsupportedSigType.selector, multisigEntityId, address(msca), 56));
        module.checkNSignatures(request);
    }

    function testCheckNSignaturesWithExactlyOneSignerOnActualDigest() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes32 minimalDigest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        bytes memory sig = _signEOASig(eoaSignerOne, actualDigest, minimalDigest, eoaSignerOneId);
        assertEq(sig.length, 65);

        bytes memory sig2 = _signEOASig(eoaSignerTwo, actualDigest, minimalDigest, eoaSignerOneId);
        assertEq(sig2.length, 65);
        // signer 1: 0xad3a4ceb930ec5721dd69ceedf111fd7af523ad67c5e1dbd0f6d12cfb611
        // signer 2: 0x0e634ce59dea96d6c8a2d23a25368a67f9e790b49fcc9b838bfefb4c2b30
        sig = abi.encodePacked(sig2, sig);
        assertEq(sig.length, 130);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: minimalDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, true);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.NONE));
    }

    function testCheckNSignaturesSignersOutOfOrder() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes32 minimumDigest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        bytes memory sig = _signEOASig(eoaSignerOne, actualDigest, minimumDigest, eoaSignerOneId);
        assertEq(sig.length, 65);

        bytes memory sig2 = _signEOASig(eoaSignerTwo, actualDigest, minimumDigest, eoaSignerOneId);
        assertEq(sig2.length, 65);
        // signer 1: 0xad3a4ceb930ec5721dd69ceedf111fd7af523ad67c5e1dbd0f6d12cfb611
        // signer 2: 0x0e634ce59dea96d6c8a2d23a25368a67f9e790b49fcc9b838bfefb4c2b30
        // out of order
        sig = abi.encodePacked(sig, sig2);
        assertEq(sig.length, 130);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: minimumDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, false);
        assertEq(response.firstFailure, 1);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.SIGS_OUT_OF_ORDER));
    }

    // we only require 1 signature on actualDigest, but we have 2
    function testCheckNSignaturesMoreThanOneSignersOnActualDigest() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes memory sig = _signEOASig(eoaSignerOne, actualDigest, actualDigest, eoaSignerOne.signerId);
        assertEq(sig.length, 65);

        bytes memory sig2 = _signEOASig(eoaSignerTwo, actualDigest, actualDigest, eoaSignerTwo.signerId);
        assertEq(sig2.length, 65);
        sig = abi.encodePacked(sig, sig2);
        assertEq(sig.length, 130);

        vm.prank(address(msca));
        vm.expectRevert(
            abi.encodeWithSelector(InvalidNumSigsOnActualDigest.selector, multisigEntityId, address(msca), 1 - 2)
        );
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        module.checkNSignatures(request);
    }

    // positive
    function testFuzz_validateSignatureEOASigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = eoaSignerOne;
        signers[1] = eoaSignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_VALID_SIGNATURE, module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    // negative
    function testFuzz_validateSignatureWrongEOASigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = _createEOASigner("randomSigner");
        signers[1] = eoaSignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_INVALID_SIGNATURE,
            module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    function testCheckNSignaturesContractSigUpperBitsNotClean() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        (uint8 v, bytes memory sigDynamicParts) =
            _signContractSig(contractSignerOne, actualDigest, actualDigest, contractSignerOne.signerId);
        bytes32 dirtyUpperBits =
            bytes32(uint256(uint160(contractSignerOne.contractAddr))) | bytes32(uint256(0xFF << 160)); // dirty upper bits
        bytes memory sig = abi.encodePacked(dirtyUpperBits, uint256(65), v, sigDynamicParts);
        assertEq(sig.length, 162); // 32 + 32 + 1 + 32 + 65

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        vm.expectRevert(
            abi.encodeWithSelector(
                InvalidAddress.selector, multisigEntityId, address(msca), contractSignerOne.contractAddr
            )
        );
        module.checkNSignatures(request);
    }

    function testCheckNSignaturesWrongContractAddress() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        (uint8 v, bytes memory sigDynamicParts) =
            _signContractSig(contractSignerOne, actualDigest, actualDigest, contractSignerOne.signerId);
        bytes32 wrongContract = bytes32(uint256(1));
        bytes memory sig = abi.encodePacked(wrongContract, uint256(65), v, sigDynamicParts);
        assertEq(sig.length, 162); // 32 + 32 + 1 + 32 + 65

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, false);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.INVALID_CONTRACT_ADDRESS));
    }

    function testCheckNSignaturesInvalidSigOffset() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        (uint8 v, bytes memory sigDynamicParts) =
            _signContractSig(contractSignerOne, actualDigest, actualDigest, contractSignerOne.signerId);
        uint256 wrongOffset = 1000; // offset > length
        bytes memory sig = abi.encodePacked(abi.encode(contractSignerOne.contractAddr), wrongOffset, v, sigDynamicParts);
        assertEq(sig.length, 162); // 32 + 32 + 1 + 32 + 65

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        vm.expectRevert(abi.encodeWithSelector(InvalidSigOffset.selector, multisigEntityId, address(msca), wrongOffset));
        module.checkNSignatures(request);

        wrongOffset = 0; // offset > length
        sig = abi.encodePacked(abi.encode(contractSignerOne.contractAddr), wrongOffset, v, sigDynamicParts);

        vm.prank(address(msca));
        request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        vm.expectRevert(abi.encodeWithSelector(InvalidSigOffset.selector, multisigEntityId, address(msca), wrongOffset));
        module.checkNSignatures(request);
    }

    function testCheckNSignaturesInvalidSigLength() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        uint256 wrongSigLength = 160; // sigDynamicParts offset + length > total length

        bytes32 r;
        bytes32 s;
        uint8 v;
        (v, r, s) = vm.sign(contractSignerOne.signerWallet.privateKey, actualDigest);
        bytes memory sigDynamicParts = abi.encodePacked(wrongSigLength, r, s, v);
        v = 32; // 0 + 32

        bytes memory sig = abi.encodePacked(abi.encode(contractSignerOne.contractAddr), uint256(65), v, sigDynamicParts);
        assertEq(sig.length, 162); // 32 + 32 + 1 + 32 + 65

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        // sigDynamicPartOffset: 65
        // sigDynamicPartTotalLen: 160 + 32
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSigLength.selector, multisigEntityId, address(msca), 65 + wrongSigLength + 32)
        );
        module.checkNSignatures(request);
    }

    function testCheckNSignaturesExactlyOneSignerOnActualDigest() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        (uint8 v, bytes memory sigDynamicParts) =
            _signContractSig(contractSignerOne, actualDigest, actualDigest, contractSignerOne.signerId);
        bytes memory sig = abi.encodePacked(abi.encode(contractSignerOne.contractAddr), uint256(65), v, sigDynamicParts);
        assertEq(sig.length, 162); // 32 + 32 + 1 + 32 + 65

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, true);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.NONE));
    }

    function testCheckNSignaturesTwoContractSigners() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = contractSignerTwo.contractAddr;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes32 minimalDigest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        Signer[] memory signers = new Signer[](2);
        signers[0] = contractSignerOne;
        signers[1] = contractSignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            minimalDigest
        );
        assertEq(sig.length, 324); // (32 + 32 + 1 + 32 + 65) * 2

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: minimalDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, true);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.NONE));
    }

    // signer 1 puts its signature dynamic part after signer 2
    // recommended encoding would be constant part 1, constant part 2, dynamic part 1, dynamic part 2
    // but constant part 1, constant part 2, dynamic part 2, dynamic part 1 would also work because
    // signature dynamic part is essentially indexed by the offset
    function testCheckNSignaturesSwappedSigDynamicPartsIndexedByOffset() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = contractSignerTwo.contractAddr;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes32 minimalDigest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        Signer[] memory signers = new Signer[](2);
        signers[0] = contractSignerOne;
        signers[1] = contractSignerTwo;
        _sortSignersById(signers);

        MultisigInput memory input = MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0});
        input.sigDynamicPartOffset = 130; // two constant parts
        // must be this order due to input.sigDynamicPartOffset += 97
        (bytes memory individualSigConstantPart2, bytes memory individualSigDynamicPart2) =
            _signIndividualSig(input, signers[1], actualDigest, minimalDigest, contractSignerOne.signerId);
        (bytes memory individualSigConstantPart1, bytes memory individualSigDynamicPart1) =
            _signIndividualSig(input, signers[0], actualDigest, minimalDigest, contractSignerOne.signerId);

        // constant part 1, constant part 2, dynamic part 2, dynamic part 1
        bytes memory sig = abi.encodePacked(
            individualSigConstantPart1, individualSigConstantPart2, individualSigDynamicPart2, individualSigDynamicPart1
        );
        assertEq(sig.length, 324); // (32 + 32 + 1 + 32 + 65) * 2

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: minimalDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, true);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.NONE));
    }

    function testCheckNSignaturesWrongContractSig() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(contractSignerOne.signerWallet.privateKey, actualDigest);
        // swap in an invalid s
        s = bytes32(0);
        bytes memory sigDynamicParts = abi.encodePacked(uint256(65), r, s, v);
        v = 32; // 0 + 32
        bytes memory sig = abi.encodePacked(abi.encode(contractSignerOne.contractAddr), uint256(65), v, sigDynamicParts);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, false);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.INVALID_SIG));
    }

    // positive
    function testFuzz_validateSignatureContractSigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = contractSignerTwo.contractAddr;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = contractSignerOne;
        signers[1] = contractSignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_VALID_SIGNATURE, module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    // negative
    function testFuzz_validateSignatureWrongContractSigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = contractSignerOne.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = contractSignerTwo.contractAddr;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = _createContractSigner("randomSigner");
        signers[1] = contractSignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_INVALID_SIGNATURE,
            module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    function testCheckNSignaturesWrongPasskeySig() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey = passKeySignerOnePublicKey;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        WebAuthnSigDynamicPart memory webAuthnSigDynamicPartForFullDigest;
        webAuthnSigDynamicPartForFullDigest.webAuthnData = _getWebAuthnData(actualDigest);
        bytes32 webauthnFullDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPartForFullDigest.webAuthnData);

        (webAuthnSigDynamicPartForFullDigest.r, webAuthnSigDynamicPartForFullDigest.s) =
            signP256Message(vm, passKeySignerOne.signerWallet.privateKey, webauthnFullDigest);
        uint8 v = 34; // 2 + 32
        // swap in an invalid s
        webAuthnSigDynamicPartForFullDigest.s = 0;
        bytes memory sigBytes = abi.encode(webAuthnSigDynamicPartForFullDigest);
        bytes memory sigDynamicParts = abi.encodePacked(uint256(sigBytes.length), sigBytes);

        bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), passKeySignerOne.signerId));
        bytes memory sigConstantPart = abi.encodePacked(pubKeyId, uint256(65), v);
        bytes memory sig = abi.encodePacked(sigConstantPart, sigDynamicParts);

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: actualDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, false);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.INVALID_SIG));
    }

    function testCheckNSignaturesPasskeySigner() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey = passKeySignerOnePublicKey;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight));

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), bytes32(uint256(1)));
        bytes32 minimalDigest = module.getReplaySafeMessageHash(address(msca), bytes32(0));
        Signer[] memory signers = new Signer[](1);
        signers[0] = passKeySignerOne;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 1, totalSigners: 1, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            minimalDigest
        );

        vm.prank(address(msca));
        CheckNSignaturesRequest memory request = CheckNSignaturesRequest({
            entityId: multisigEntityId,
            actualDigest: actualDigest,
            minimalDigest: minimalDigest,
            requiredNumSigsOnActualDigest: 1,
            account: address(msca),
            signatures: sig
        });
        CheckNSignaturesResponse memory response = module.checkNSignatures(request);
        assertEq(response.success, true);
        assertEq(response.firstFailure, 0);
        assertEq(uint8(response.errorCode), uint8(CheckNSignatureError.NONE));
    }

    // positive
    function testFuzz_validateSignaturePasskeySigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey = passKeySignerOnePublicKey;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.publicKey = passKeySignerTwoPublicKey;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = passKeySignerOne;
        signers[1] = passKeySignerTwo;
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_VALID_SIGNATURE, module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    // negative
    function testFuzz_validateSignatureWrongPasskeySigner(bytes32 hash) public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey = passKeySignerOnePublicKey;
        signersMetadata[0] = signerMetaDataOne;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.publicKey = passKeySignerTwoPublicKey;
        signersMetadata[1] = signerMetaDataTwo;

        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        bytes32 actualDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = new Signer[](2);
        signers[0] = passKeySignerOne;
        signers[1] = _createPasskeySigner(2);
        _sortSignersById(signers);
        bytes memory sig = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            actualDigest,
            actualDigest
        );

        vm.prank(address(msca));
        assertEq(
            EIP1271_INVALID_SIGNATURE,
            module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    function testFuzz_validateSignatureMixedSigTypes(MultisigInput memory input, bytes32 hash) public {
        // Ensure 1 < totalSigners <= 10
        input.totalSigners %= 11;
        vm.assume(input.totalSigners > 0);
        // Ensure 1 < actualSigners < totalSigners
        input.actualSigners %= 11;
        input.actualSigners %= input.totalSigners;
        vm.assume(input.actualSigners > 0);
        input.sigDynamicPartOffset = 0;
        console.log("totalSigners: ", input.totalSigners);
        console.log("actualSigners: ", input.actualSigners);
        bytes32 wrappedDigest = module.getReplaySafeMessageHash(address(msca), hash);
        Signer[] memory signers = _installSignersOfMixedTypes(input);
        _sortSignersById(signers);
        bytes memory sig = _signSigs(input, signers, wrappedDigest, wrappedDigest);
        vm.prank(address(msca));
        assertEq(
            EIP1271_VALID_SIGNATURE, module.validateSignature(address(msca), multisigEntityId, address(this), hash, sig)
        );
    }

    function testFuzz_validateUserOpNoActualDigestProvided(PackedUserOperation memory userOp) public {
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.preVerificationGas = ZERO;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        userOp.sender = address(msca);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.expectRevert(abi.encodeWithSelector(InvalidUserOpDigest.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.validateUserOp(multisigEntityId, userOp, userOpHash);
    }

    function testFuzz_validateUserOpLengthTooShort(PackedUserOperation memory userOp) public {
        userOp.sender = address(msca);
        userOp.signature = bytes("foo");
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.expectRevert(
            abi.encodeWithSelector(InvalidSigLength.selector, multisigEntityId, address(msca), userOp.signature.length)
        );
        vm.prank(address(msca));
        module.validateUserOp(multisigEntityId, userOp, userOpHash);
    }

    function testFuzz_validateUserOpUninitializedAccount(PackedUserOperation memory userOp) public {
        userOp.sender = address(msca);
        userOp.signature = bytes.concat(bytes32(0), bytes32(0), bytes1(0));
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        vm.expectRevert(abi.encodeWithSelector(Uninitialized.selector, multisigEntityId, address(msca)));
        vm.prank(address(msca));
        module.validateUserOp(multisigEntityId, userOp, userOpHash);
    }

    function testFuzz_validateUserOpSameSignerSignsRepeatedly(
        string memory salt1,
        string memory salt2,
        string memory salt3,
        PackedUserOperation memory userOp
    ) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt2)));
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt3)));
        vm.assume(keccak256(abi.encodePacked(salt2)) != keccak256(abi.encodePacked(salt3)));
        userOp.sender = address(msca);
        Signer memory signer1 = _createEOASigner(salt1);
        Signer memory signer2 = _createEOASigner(salt2);
        Signer memory signer3 = _createEOASigner(salt3);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](3);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signer1.signerWallet.addr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signer2.signerWallet.addr;
        SignerMetadata memory signerMetaDataThree;
        signerMetaDataThree.weight = 1;
        signerMetaDataThree.addr = signer3.signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        signersMetadata[2] = signerMetaDataThree;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(
                multisigEntityId,
                signersMetadata,
                signerMetaDataOne.weight + signerMetaDataTwo.weight + signerMetaDataThree.weight
            )
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        // repeated signer with the same weight
        signers[2] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 3, totalSigners: 3, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_FAILED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpEOASigner(
        string memory salt1,
        string memory salt2,
        PackedUserOperation memory userOp
    ) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt2)));
        userOp.sender = address(msca);
        Signer memory signer1 = _createEOASigner(salt1);
        Signer memory signer2 = _createEOASigner(salt2);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signer1.signerWallet.addr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signer2.signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_SUCCEEDED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpWrongEOASigner(
        string memory salt1,
        string memory salt2,
        PackedUserOperation memory userOp
    ) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt2)));
        userOp.sender = address(msca);
        Signer memory signer1 = _createEOASigner(salt1);
        Signer memory signer2 = _createEOASigner(salt2);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signer1.signerWallet.addr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signer2.signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = _createEOASigner("randomSigner");
        signers[1] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_FAILED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpContractSigner(
        string memory salt1,
        string memory salt2,
        PackedUserOperation memory userOp
    ) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt2)));
        userOp.sender = address(msca);
        Signer memory signer1 = _createContractSigner(salt1);
        Signer memory signer2 = _createContractSigner(salt2);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signer1.contractAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signer2.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_SUCCEEDED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpWrongContractSigner(
        string memory salt1,
        string memory salt2,
        PackedUserOperation memory userOp
    ) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(keccak256(abi.encodePacked(salt1)) != keccak256(abi.encodePacked(salt2)));
        userOp.sender = address(msca);
        Signer memory signer1 = _createContractSigner(salt1);
        Signer memory signer2 = _createContractSigner(salt2);
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signer1.contractAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signer2.contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = _createContractSigner("randomSigner");
        signers[1] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_FAILED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpPasskeySigner(uint8 salt1, PackedUserOperation memory userOp) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(salt1 <= uint8(9));
        uint8 salt2 = salt1 + 1;
        userOp.sender = address(msca);
        Signer memory signer1 = _createPasskeySigner(uint256(salt1));
        Signer memory signer2 = _createPasskeySigner(uint256(salt2));
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey =
            PublicKey({x: signer1.signerWallet.publicKeyX, y: signer1.signerWallet.publicKeyY});
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.publicKey =
            PublicKey({x: signer2.signerWallet.publicKeyX, y: signer2.signerWallet.publicKeyY});
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = signer1;
        signers[1] = signer2;
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_SUCCEEDED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpWrongPasskeySigner(uint8 salt1, PackedUserOperation memory userOp) public {
        // make sure we have actual digest set in userOp when it's submitted for estimation (simulation) or validation
        if (userOp.accountGasLimits == ZERO_BYTES32) {
            userOp.accountGasLimits = bytes32(uint256(1));
        }
        vm.assume(salt1 <= uint8(8));
        uint8 salt2 = salt1 + 1;
        uint8 randomSalt = salt1 + 2;
        vm.assume(randomSalt < uint8(11));
        userOp.sender = address(msca);
        Signer memory signer1 = _createPasskeySigner(uint256(salt1));
        Signer memory signer2 = _createPasskeySigner(uint256(salt2));
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey =
            PublicKey({x: signer1.signerWallet.publicKeyX, y: signer1.signerWallet.publicKeyY});
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.publicKey =
            PublicKey({x: signer2.signerWallet.publicKeyX, y: signer2.signerWallet.publicKeyY});
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(
            abi.encode(multisigEntityId, signersMetadata, signerMetaDataOne.weight + signerMetaDataTwo.weight)
        );

        // sign actual actualDigest
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = new Signer[](2);
        signers[0] = signer1;
        signers[1] = _createPasskeySigner(uint256(randomSalt));
        _sortSignersById(signers);

        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        userOp.signature = _signSigs(
            MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
            signers,
            fullUserOpHash.toEthSignedMessageHash(),
            minimalUserOpHash.toEthSignedMessageHash()
        );

        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_FAILED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testFuzz_validateUserOpMixedSigTypes(MultisigInput memory input, PackedUserOperation memory userOp)
        public
    {
        // Ensure 1 < totalSigners <= 10
        input.totalSigners %= 11;
        vm.assume(input.totalSigners > 0);
        // Ensure 1 < actualSigners < totalSigners
        input.actualSigners %= 11;
        input.actualSigners %= input.totalSigners;
        input.sigDynamicPartOffset = 0;
        userOp.sender = address(msca);
        vm.assume(input.actualSigners > 0);
        input.sigDynamicPartOffset = 0;
        bytes32 fullUserOpHash = entryPoint.getUserOpHash(userOp);
        // create minimal userOpHash
        userOp.preVerificationGas = 0;
        userOp.accountGasLimits = ZERO_BYTES32;
        userOp.gasFees = ZERO_BYTES32;
        userOp.paymasterAndData = "";
        bytes32 minimalUserOpHash = entryPoint.getUserOpHash(userOp);
        Signer[] memory signers = _installSignersOfMixedTypes(input);
        _sortSignersById(signers);
        userOp.signature = _signSigs(
            input, signers, fullUserOpHash.toEthSignedMessageHash(), minimalUserOpHash.toEthSignedMessageHash()
        );
        vm.prank(address(msca));
        assertEq(SIG_VALIDATION_SUCCEEDED, module.validateUserOp(multisigEntityId, userOp, fullUserOpHash));
    }

    function testValidateRuntimeSenderIsAccount() public {
        vm.prank(address(msca));
        // sender is the same as the account
        module.validateRuntime(address(msca), multisigEntityId, address(msca), 0, "", "");
    }

    function testValidateRuntimeSenderHasSufficientWeight() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOne.signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
        module.validateRuntime(address(msca), multisigEntityId, signerMetaDataOne.addr, 0, "", "");
    }

    function testValidateRuntimeAuthorizationTooShort() public {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = eoaSignerOneAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 2;
        signerMetaDataTwo.addr = eoaSignerTwoAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        vm.expectRevert(abi.encodeWithSelector(InvalidAuthorizationLength.selector, multisigEntityId, address(msca), 0));
        module.validateRuntime(address(msca), multisigEntityId, signerMetaDataOne.addr, 0, "", "");
    }

    function testValidateRuntimeUnauthorizedCaller() public {
        Signer[] memory signers = new Signer[](1);
        signers[0] = eoaSignerOne;
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](1);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        // we're actually installing signer two
        signerMetaDataOne.addr = eoaSignerTwo.signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 1));
        address sender = address(1);
        uint256 nonce = 0;
        vm.prank(sender);
        bytes32 gasLimit = _encodeGasLimit(50_000);
        bytes32 gasFees = _encodeGasFees(1, 1);
        bytes32 wrappedDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        // signer one (wrong signer) signs
        bytes memory authorization = abi.encode(
            nonce,
            gasLimit,
            gasFees,
            _signSigs(
                MultisigInput({actualSigners: 1, totalSigners: 1, sigDynamicPartOffset: 0}),
                signers,
                wrappedDigest,
                wrappedDigest
            )
        );
        vm.expectRevert(UnauthorizedCaller.selector);
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, "", authorization);
    }

    function testValidateRuntimeNoOneSignsFullDigest() public {
        Signer[] memory signers = new Signer[](2);
        signers[0] = eoaSignerOne;
        signers[1] = eoaSignerTwo;
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signers[0].signerWallet.addr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signers[1].signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        _sortSignersById(signers);
        address sender = address(1);
        uint256 nonce = 0;
        vm.prank(sender);
        bytes32 gasLimit = ZERO_BYTES32;
        bytes32 gasFees = ZERO_BYTES32;
        bytes32 digest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        bytes memory authorization = abi.encode(
            nonce,
            gasLimit,
            gasFees,
            _signSigs(
                MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}), signers, digest, digest
            )
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWeightedMultisigValidationModule.InvalidRuntimeDigest.selector, multisigEntityId, address(msca)
            )
        );
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, "", authorization);
    }

    function testValidateRuntimeEOASigner() public {
        Signer[] memory signers = new Signer[](2);
        signers[0] = eoaSignerOne;
        signers[1] = eoaSignerTwo;
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signers[0].signerWallet.addr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signers[1].signerWallet.addr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        _sortSignersById(signers);
        address sender = address(1);
        uint256 nonce = 0;
        vm.prank(sender);
        bytes32 gasLimit = _encodeGasLimit(50_000);
        bytes32 gasFees = _encodeGasFees(1, 1);
        bytes32 fullDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        bytes32 minimalDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: ZERO_BYTES32,
            gasFees: ZERO_BYTES32
        });
        bytes memory authorization = abi.encode(
            nonce,
            gasLimit,
            gasFees,
            _signSigs(
                MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
                signers,
                fullDigest,
                minimalDigest
            )
        );
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, "", authorization);
    }

    function testValidateRuntimeContractSigner() public {
        Signer[] memory signers = new Signer[](2);
        signers[0] = contractSignerOne;
        signers[1] = contractSignerTwo;
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.addr = signers[0].contractAddr;
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.addr = signers[1].contractAddr;
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        _sortSignersById(signers);
        address sender = address(1);
        uint256 nonce = 0;
        vm.prank(sender);
        bytes32 gasLimit = _encodeGasLimit(50_000);
        bytes32 gasFees = _encodeGasFees(1, 1);
        bytes32 fullDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        bytes32 minimalDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: ZERO_BYTES32,
            gasFees: ZERO_BYTES32
        });
        bytes memory authorization = abi.encode(
            nonce,
            gasLimit,
            gasFees,
            _signSigs(
                MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
                signers,
                fullDigest,
                minimalDigest
            )
        );
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, "", authorization);
    }

    function testValidateRuntimePasskeySigner() public {
        Signer[] memory signers = new Signer[](2);
        signers[0] = passKeySignerOne;
        signers[1] = passKeySignerTwo;
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](2);
        SignerMetadata memory signerMetaDataOne;
        signerMetaDataOne.weight = 1;
        signerMetaDataOne.publicKey =
            PublicKey({x: signers[0].signerWallet.publicKeyX, y: signers[0].signerWallet.publicKeyY});
        SignerMetadata memory signerMetaDataTwo;
        signerMetaDataTwo.weight = 1;
        signerMetaDataTwo.publicKey =
            PublicKey({x: signers[1].signerWallet.publicKeyX, y: signers[1].signerWallet.publicKeyY});
        signersMetadata[0] = signerMetaDataOne;
        signersMetadata[1] = signerMetaDataTwo;
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, 2));
        _sortSignersById(signers);
        address sender = address(1);
        uint256 nonce = 0;
        vm.prank(sender);
        bytes32 gasLimit = _encodeGasLimit(50_000);
        bytes32 gasFees = _encodeGasFees(1, 1);
        bytes32 fullDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        bytes32 minimalDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: "",
            nonce: nonce,
            value: 0,
            gasLimit: ZERO_BYTES32,
            gasFees: ZERO_BYTES32
        });
        bytes memory authorization = abi.encode(
            nonce,
            gasLimit,
            gasFees,
            _signSigs(
                MultisigInput({actualSigners: 2, totalSigners: 2, sigDynamicPartOffset: 0}),
                signers,
                fullDigest,
                minimalDigest
            )
        );
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, "", authorization);
    }

    function testFuzz_validateRuntimeMixedSigTypes(
        MultisigInput memory input,
        address sender,
        bytes calldata data,
        uint256 nonce
    ) public {
        // Ensure 1 < totalSigners <= 10
        input.totalSigners %= 11;
        vm.assume(input.totalSigners > 0);
        // Ensure 1 < actualSigners < totalSigners
        input.actualSigners %= 11;
        input.actualSigners %= input.totalSigners;
        vm.assume(input.actualSigners > 0);
        input.sigDynamicPartOffset = 0;
        vm.prank(address(msca));
        Signer[] memory signers = _installSignersOfMixedTypes(input);
        _sortSignersById(signers);
        vm.prank(sender);
        bytes32 gasLimit = _encodeGasLimit(50_000);
        bytes32 gasFees = _encodeGasFees(1, 1);
        bytes32 fullDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: data,
            nonce: nonce,
            value: 0,
            gasLimit: gasLimit,
            gasFees: gasFees
        });
        bytes32 minimalDigest = module.getReplaySafeHashForRuntimeValidation({
            account: address(msca),
            entityId: multisigEntityId,
            sender: sender,
            data: data,
            nonce: nonce,
            value: 0,
            gasLimit: ZERO_BYTES32,
            gasFees: ZERO_BYTES32
        });
        bytes memory authorization =
            abi.encode(nonce, gasLimit, gasFees, _signSigs(input, signers, fullDigest, minimalDigest));
        module.validateRuntime(address(msca), multisigEntityId, sender, 0, data, authorization);
    }

    function _signSigs(MultisigInput memory input, Signer[] memory signers, bytes32 fullDigest, bytes32 minimalDigest)
        internal
        pure
        returns (bytes memory signature)
    {
        bytes30 signerIdMustSignFullDigest;
        if (fullDigest != minimalDigest) {
            signerIdMustSignFullDigest = signers[input.totalSigners % input.actualSigners].signerId;
        }
        bytes memory sigConstantParts = bytes("");
        bytes memory sigDynamicParts = bytes("");
        input.sigDynamicPartOffset = input.actualSigners * 65; // start after constant part
        for (uint256 i = 0; i < input.actualSigners; i++) {
            // append constant and dynamic parts from individual signer
            (bytes memory individualSigConstantPart, bytes memory individualSigDynamicPart) =
                _signIndividualSig(input, signers[i], fullDigest, minimalDigest, signerIdMustSignFullDigest);
            sigConstantParts = abi.encodePacked(sigConstantParts, individualSigConstantPart);
            sigDynamicParts = abi.encodePacked(sigDynamicParts, individualSigDynamicPart);
        }
        signature = abi.encodePacked(sigConstantParts, sigDynamicParts);
        return signature;
    }

    function _signIndividualSig(
        MultisigInput memory input,
        Signer memory signer,
        bytes32 fullDigest,
        bytes32 minimalDigest,
        bytes30 signerIdMustSignFullDigest
    ) internal pure returns (bytes memory sigConstantPart, bytes memory sigDynamicPart) {
        if (signer.sigType == 27) {
            console.logString("eoa signer signs..");
            // only produce constant parts
            sigConstantPart = _signEOASig(signer, fullDigest, minimalDigest, signerIdMustSignFullDigest);
        } else if (signer.sigType == 0) {
            console.logString("contract signer signs..");
            uint8 v;
            (v, sigDynamicPart) = _signContractSig(signer, fullDigest, minimalDigest, signerIdMustSignFullDigest);
            sigConstantPart = abi.encodePacked(abi.encode(signer.contractAddr), uint256(input.sigDynamicPartOffset), v);
            input.sigDynamicPartOffset += sigDynamicPart.length; // ecdsa is 97 = 65 (k1 sig length) + 32 (length of
                // sig)
        } else {
            console.logString("r1 signer signs..");
            uint8 v;
            (v, sigDynamicPart) = _signR1Sig(signer, fullDigest, minimalDigest, signerIdMustSignFullDigest);
            bytes32 pubKeyId = bytes32(bytes.concat(bytes2(0), signer.signerId));
            sigConstantPart = abi.encodePacked(pubKeyId, uint256(input.sigDynamicPartOffset), v);
            input.sigDynamicPartOffset += (sigDynamicPart.length);
        }
        return (sigConstantPart, sigDynamicPart);
    }

    function _signEOASig(
        Signer memory signer,
        bytes32 fullDigest,
        bytes32 minimalDigest,
        bytes30 signerIdMustSignFullDigest
    ) internal pure returns (bytes memory signed) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signer.signerId == signerIdMustSignFullDigest) {
            (v, r, s) = vm.sign(signer.signerWallet.privateKey, fullDigest);
            v += 32;
        } else {
            (v, r, s) = vm.sign(signer.signerWallet.privateKey, minimalDigest);
        }
        signer.sigType = v;
        return abi.encodePacked(r, s, v);
    }

    function _signContractSig(
        Signer memory signer,
        bytes32 fullDigest,
        bytes32 minimalDigest,
        bytes30 signerIdMustSignFullDigest
    ) internal pure returns (uint8 v, bytes memory sigDynamicParts) {
        bytes32 r;
        bytes32 s;
        if (signer.signerId == signerIdMustSignFullDigest) {
            (v, r, s) = vm.sign(signer.signerWallet.privateKey, fullDigest);
            sigDynamicParts = abi.encodePacked(uint256(65), r, s, v);
            v = 32; // 0 + 32
        } else {
            (v, r, s) = vm.sign(signer.signerWallet.privateKey, minimalDigest);
            sigDynamicParts = abi.encodePacked(uint256(65), r, s, v);
            v = 0;
        }
        return (v, sigDynamicParts);
    }

    function _signR1Sig(
        Signer memory signer,
        bytes32 fullDigest,
        bytes32 minimalDigest,
        bytes30 signerIdMustSignFullDigest
    ) internal pure returns (uint8 v, bytes memory sigDynamicParts) {
        bytes memory sigBytes;
        if (signer.signerId == signerIdMustSignFullDigest) {
            WebAuthnSigDynamicPart memory webAuthnSigDynamicPartForFullDigest;
            webAuthnSigDynamicPartForFullDigest.webAuthnData = _getWebAuthnData(fullDigest);
            bytes32 webauthnFullDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPartForFullDigest.webAuthnData);
            (webAuthnSigDynamicPartForFullDigest.r, webAuthnSigDynamicPartForFullDigest.s) =
                signP256Message(vm, signer.signerWallet.privateKey, webauthnFullDigest);
            v = 34; // 2 + 32
            sigBytes = abi.encode(webAuthnSigDynamicPartForFullDigest);
        } else {
            WebAuthnSigDynamicPart memory webAuthnSigDynamicPartForMinimalDigest;
            webAuthnSigDynamicPartForMinimalDigest.webAuthnData = _getWebAuthnData(minimalDigest);
            bytes32 webauthnMinimalDigest = _getWebAuthnMessageHash(webAuthnSigDynamicPartForMinimalDigest.webAuthnData);
            (webAuthnSigDynamicPartForMinimalDigest.r, webAuthnSigDynamicPartForMinimalDigest.s) =
                signP256Message(vm, signer.signerWallet.privateKey, webauthnMinimalDigest);
            v = 2;
            sigBytes = abi.encode(webAuthnSigDynamicPartForMinimalDigest);
        }
        // length of bytes || sig data bytes
        sigDynamicParts = abi.encodePacked(uint256(sigBytes.length), sigBytes);
        return (v, sigDynamicParts);
    }

    function _createEOASigner(string memory signerKeySeed) internal returns (Signer memory o) {
        VmSafe.Wallet memory signerWallet;
        (signerWallet.addr, signerWallet.privateKey) = makeAddrAndKey(signerKeySeed);
        o.signerId = module.getSignerId(signerWallet.addr);
        o.signerWallet = signerWallet;
        o.sigType = 27; // will be overridden for full digest later
        return o;
    }

    function _createContractSigner(string memory signerKeySeed) internal returns (Signer memory o) {
        VmSafe.Wallet memory signerWallet;
        (signerWallet.addr, signerWallet.privateKey) = makeAddrAndKey(signerKeySeed);
        MockContractOwner m = new MockContractOwner(signerWallet.addr);
        o.signerId = module.getSignerId(address(m));
        o.signerWallet = signerWallet;
        o.contractAddr = address(m);
        o.sigType = 0; // will be overridden for full digest later
        return o;
    }

    // TODO: generate dynamic keys when library has better support
    function _createPasskeySigner(uint256 label) internal view returns (Signer memory o) {
        TestR1Key[] memory testR1Keys = _loadR1Keys();
        VmSafe.Wallet memory signerWallet;
        if (label < 11) {
            // p256key_11_fixture.json only supports 11 keys
            signerWallet.privateKey = testR1Keys[label].privateKey;
            signerWallet.publicKeyX = testR1Keys[label].publicKeyX;
            signerWallet.publicKeyY = testR1Keys[label].publicKeyY;
        } else {
            revert Unsupported();
        }
        o.signerId = module.getSignerId(PublicKey({x: signerWallet.publicKeyX, y: signerWallet.publicKeyY}));
        o.signerWallet = signerWallet;
        o.sigType = 2; // will be overridden for full digest later
        return o;
    }

    function _sortSignersById(Signer[] memory signers) internal pure {
        uint256 n = signers.length;
        uint256 minIdx;
        for (uint256 i = 0; i < n; i++) {
            minIdx = i;
            for (uint256 j = i; j < n; j++) {
                if (signers[j].signerId < signers[minIdx].signerId) {
                    minIdx = j;
                }
            }
            (signers[i], signers[minIdx]) = (signers[minIdx], signers[i]);
        }
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

    /// @dev load 10 pre generated r1 keys for testing purpose.
    function _loadR1Keys() internal view returns (TestR1Key[] memory testKeys) {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, P256_10_KEYS_FIXTURE);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".numOfKeys"), (uint256));
        testKeys = new TestR1Key[](count);

        for (uint256 i; i < count; ++i) {
            (, uint256 privateKey, uint256 x, uint256 y) = _parseJson({json: json, resultIndex: i});
            testKeys[i] = TestR1Key({privateKey: privateKey, publicKeyX: x, publicKeyY: y});
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

    function _installSignersOfMixedTypes(MultisigInput memory input) internal returns (Signer[] memory signers) {
        SignerMetadata[] memory signersMetadata = new SignerMetadata[](input.totalSigners);
        signers = new Signer[](input.totalSigners);
        uint256 numOfK1Signers;
        uint256 numOfR1Signers;
        for (uint256 i = 0; i < input.totalSigners; i++) {
            if ((input.actualSigners + input.totalSigners + i) % 3 == 0) {
                // contract k1 signer
                console.logString("we have a contract signer..");
                signers[i] = _createContractSigner((input.actualSigners + input.totalSigners + i).toString());
                signersMetadata[i].weight = 1;
                signersMetadata[i].addr = signers[i].contractAddr;
                numOfK1Signers++;
            } else if ((input.actualSigners + input.totalSigners + i) % 3 == 1) {
                // eoa k1 signer
                console.logString("we have an eoa signer..");
                signers[i] = _createEOASigner((input.actualSigners + input.totalSigners + i).toString());
                signersMetadata[i].weight = 1;
                signersMetadata[i].addr = signers[i].signerWallet.addr;
                numOfK1Signers++;
            } else {
                // r1 signer
                console.logString("we have a r1 signer..");
                signers[i] = _createPasskeySigner(numOfR1Signers);
                signersMetadata[i].weight = 1;
                signersMetadata[i].publicKey =
                    PublicKey({x: signers[i].signerWallet.publicKeyX, y: signers[i].signerWallet.publicKeyY});
                numOfR1Signers++;
            }
        }

        // initial thresholdWeight is set to k because every signer has weight 1
        vm.prank(address(msca));
        module.onInstall(abi.encode(multisigEntityId, signersMetadata, input.actualSigners));
        return signers;
    }

    function _generateRandomPublicKey(uint256 randomScalar) internal view returns (PublicKey memory) {
        (uint256 x, uint256 y) = _generateRandomPoint(randomScalar);
        return PublicKey(x, y);
    }

    // Generate a random point on secp256r1
    function _generateRandomPoint(uint256 randomScalar) internal view returns (uint256 x, uint256 y) {
        if (randomScalar == 0 || randomScalar >= FCL_Elliptic_ZZ.n) {
            // as multiplication with 0 always results in the neutral point (not a valid public key)
            randomScalar = 1;
        }
        // Perform scalar multiplication (k * G)
        (x, y) = FCL_Elliptic_ZZ.ecZZ_mulmuladd(FCL_Elliptic_ZZ.gx, FCL_Elliptic_ZZ.gy, randomScalar, 0); // Q = (Gx,
            // Gy), scalar_u = k
        if (FCL_Elliptic_ZZ.ecAff_isOnCurve(x, y)) {
            return (x, y);
        } else {
            revert FailToGeneratePublicKey(x, y);
        }
    }
}
