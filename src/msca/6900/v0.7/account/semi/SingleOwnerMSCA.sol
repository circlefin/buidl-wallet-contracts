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

import {DefaultCallbackHandler} from "../../../../../callback/DefaultCallbackHandler.sol";

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    EMPTY_FUNCTION_REFERENCE,
    EMPTY_FUNCTION_REFERENCE,
    SENTINEL_BYTES21,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED
} from "../../../../../common/Constants.sol";
import {ExecutionUtils} from "../../../../../utils/ExecutionUtils.sol";
import {
    InvalidAuthorizer,
    InvalidValidationFunctionId,
    NotFoundSelector,
    UnauthorizedCaller
} from "../../../shared/common/Errors.sol";
import {ValidationData} from "../../../shared/common/Structs.sol";
import {ValidationDataLib} from "../../../shared/libs/ValidationDataLib.sol";
import {
    PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE,
    RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
} from "../../common/Constants.sol";
import {ExecutionDetail, FunctionReference, RepeatableBytes21DLL} from "../../common/Structs.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {FunctionReferenceLib} from "../../libs/FunctionReferenceLib.sol";
import {RepeatableFunctionReferenceDLLLib} from "../../libs/RepeatableFunctionReferenceDLLLib.sol";
import {WalletStorageV1Lib} from "../../libs/WalletStorageV1Lib.sol";
import {PluginManager} from "../../managers/PluginManager.sol";
import {BaseMSCA} from "../BaseMSCA.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @dev Semi-MSCA that enshrines single owner into the account storage.
 */
contract SingleOwnerMSCA is BaseMSCA, DefaultCallbackHandler, UUPSUpgradeable, IERC1271 {
    using ExecutionUtils for address;
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using RepeatableFunctionReferenceDLLLib for RepeatableBytes21DLL;
    using FunctionReferenceLib for bytes21;
    using FunctionReferenceLib for FunctionReference;
    using ValidationDataLib for ValidationData;

    enum FunctionId {
        NATIVE_RUNTIME_VALIDATION_OWNER_OR_SELF,
        NATIVE_USER_OP_VALIDATION_OWNER
    }

    event SingleOwnerMSCAInitialized(address indexed account, address indexed entryPointAddress, address owner);
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    error InvalidOwnerForMSCA(address account, address owner);
    error NoOwnershipPluginDefined();

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyFromEntryPointOrOwnerOrSelf() {
        _checkFromEPOrOwnerOrSelf();
        _;
    }

    constructor(IEntryPoint _newEntryPoint, PluginManager _newPluginManager)
        BaseMSCA(_newEntryPoint, _newPluginManager)
    {
        // lock the implementation contract so it can only be called from proxies
        _disableWalletStorageInitializers();
    }

    /// @notice Initializes the account with a set of plugins
    /// @dev No dependencies or hooks can be injected with this installation. For a full installation, please use
    /// installPlugin.
    /// @param owner The initial owner
    function initializeSingleOwnerMSCA(address owner) external walletStorageInitializer {
        if (owner == address(0)) {
            revert InvalidOwnerForMSCA(address(this), owner);
        }
        _transferNativeOwnership(owner);
        emit SingleOwnerMSCAInitialized(address(this), address(entryPoint), owner);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        address owner = WalletStorageV1Lib.getLayout().owner;
        if (owner == address(0)) {
            // isValidSignature is installed via plugin, so it should fallback to the plugin
            (bool success, bytes memory returnData) = WalletStorageV1Lib.getLayout().executionDetails[IERC1271
                .isValidSignature
                .selector].plugin.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));
            if (!success) {
                return EIP1271_INVALID_SIGNATURE;
            }
            return abi.decode(returnData, (bytes4));
        }
        if (_verifySignature(owner, hash, signature)) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current msg.sender.
     */
    function transferNativeOwnership(address newOwner) public onlyFromEntryPointOrOwnerOrSelf validateNativeFunction {
        if (newOwner == address(0)) {
            revert InvalidOwnerForMSCA(address(this), newOwner);
        }
        _transferNativeOwnership(newOwner);
    }

    /**
     * @dev Leaves the contract without owner. Can only be initiated by the current owner.
     *
     * NOTE: Irreversible. Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner. Please
     * make sure you've already have other backup validations before calling this method.
     * If the user wants to switch to the validations provided by plugins, please call this
     * function after you install the plugin, so owner will be disabled.
     */
    function renounceNativeOwnership() public onlyFromEntryPointOrOwnerOrSelf validateNativeFunction {
        // we need a ownership plugin in place before renouncing native ownership
        if (WalletStorageV1Lib.getLayout().executionDetails[IERC1271.isValidSignature.selector].plugin == address(0)) {
            revert NoOwnershipPluginDefined();
        }
        _transferNativeOwnership(address(0));
    }

    /**
     * @dev Returns the current owner.
     */
    function getNativeOwner() public view returns (address) {
        return WalletStorageV1Lib.getLayout().owner;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(BaseMSCA, DefaultCallbackHandler)
        returns (bool)
    {
        // BaseMSCA has already implemented ERC165
        return BaseMSCA.supportsInterface(interfaceId) || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC1271).interfaceId;
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferNativeOwnership(address newOwner) internal {
        address oldOwner = WalletStorageV1Lib.getLayout().owner;
        WalletStorageV1Lib.getLayout().owner = newOwner;
        emit OwnershipTransferred(address(this), oldOwner, newOwner);
    }

    /**
     * @dev We run the native validation function if it's enabled, otherwise we fallback to the plugin validation
     * functions.
     *      In either case, we run the hooks from plugins if there's any.
     */
    function _authenticateAndAuthorizeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        // onlyFromEntryPoint is applied in the caller
        // if there is no function defined for the selector, or if userOp.callData.length < 4, then execution MUST
        // revert
        if (userOp.callData.length < 4) {
            revert NotFoundSelector();
        }
        bytes4 selector = bytes4(userOp.callData[0:4]);
        if (selector == bytes4(0)) {
            revert NotFoundSelector();
        }
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[selector];
        // check validation function for non native case first
        FunctionReference memory validationFunction = executionDetail.userOpValidationFunction;
        address owner = WalletStorageV1Lib.getLayout().owner;
        if (owner == address(0)) {
            bytes21 packedValidationFunction = validationFunction.pack();
            if (
                packedValidationFunction == EMPTY_FUNCTION_REFERENCE
                    || packedValidationFunction == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                    || packedValidationFunction == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
            ) {
                revert InvalidValidationFunctionId(validationFunction.functionId);
            }
        }
        // pre hook
        ValidationData memory unpackedValidationData =
            _processPreUserOpValidationHooks(executionDetail, userOp, userOpHash);
        uint256 currentValidationData;
        // userOp validation
        // no native validation function
        if (owner == address(0)) {
            IPlugin userOpValidatorPlugin = IPlugin(validationFunction.plugin);
            // execute the validation function with the user operation and its hash as parameters using the call opcode
            currentValidationData = userOpValidatorPlugin.userOpValidationFunction(
                executionDetail.userOpValidationFunction.functionId, userOp, userOpHash
            );
        } else {
            if (_verifySignature(owner, userOpHash, userOp.signature)) {
                currentValidationData = SIG_VALIDATION_SUCCEEDED;
            } else {
                currentValidationData = SIG_VALIDATION_FAILED;
            }
        }

        // intercept with last result
        unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
        if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1)) {
            // only revert on unexpected values
            revert InvalidAuthorizer();
        }
        validationData = unpackedValidationData._packValidationData();
    }

    function _processPreRuntimeHooksAndValidation(bytes4 selector) internal override {
        if (msg.sender == address(entryPoint)) {
            // entryPoint should go through validateUserOp flow which calls userOpValidationFunction
            return;
        }
        ExecutionDetail storage executionDetail = WalletStorageV1Lib.getLayout().executionDetails[selector];
        FunctionReference memory validationFunction = executionDetail.runtimeValidationFunction;
        RepeatableBytes21DLL storage preRuntimeValidationHooksDLL = executionDetail.preRuntimeValidationHooks;
        uint256 totalUniqueHookCount = preRuntimeValidationHooksDLL.getUniqueItems();
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        FunctionReference[] memory preRuntimeValidationHooks;
        FunctionReference memory nextHook;
        for (uint256 i = 0; i < totalUniqueHookCount; ++i) {
            (preRuntimeValidationHooks, nextHook) = preRuntimeValidationHooksDLL.getPaginated(startHook, 10);
            for (uint256 j = 0; j < preRuntimeValidationHooks.length; ++j) {
                // revert on EMPTY_FUNCTION_REFERENCE, RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE,
                // PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                // if any revert, the outer call MUST revert
                bytes21 packedPreRuntimeValidationHook = preRuntimeValidationHooks[j].pack();
                if (
                    packedPreRuntimeValidationHook == EMPTY_FUNCTION_REFERENCE
                        || packedPreRuntimeValidationHook == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                        || packedPreRuntimeValidationHook == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                ) {
                    revert InvalidValidationFunctionId(preRuntimeValidationHooks[j].functionId);
                }
                IPlugin preRuntimeValidationHookPlugin = IPlugin(preRuntimeValidationHooks[j].plugin);
                try preRuntimeValidationHookPlugin.preRuntimeValidationHook(
                    preRuntimeValidationHooks[j].functionId, msg.sender, msg.value, msg.data
                ) {} catch (bytes memory revertReason) {
                    revert PreRuntimeValidationHookFailed(
                        preRuntimeValidationHooks[j].plugin, preRuntimeValidationHooks[j].functionId, revertReason
                    );
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        address owner = WalletStorageV1Lib.getLayout().owner;
        // no native validation function
        if (owner == address(0)) {
            bytes21 packedValidationFunction = validationFunction.pack();
            if (
                packedValidationFunction == EMPTY_FUNCTION_REFERENCE
                    || packedValidationFunction == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
            ) {
                revert InvalidValidationFunctionId(validationFunction.functionId);
            }
            // call runtimeValidationFunction if it's not always allowed
            if (packedValidationFunction != RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE) {
                try IPlugin(validationFunction.plugin).runtimeValidationFunction(
                    validationFunction.functionId, msg.sender, msg.value, msg.data
                ) {} catch (bytes memory revertReason) {
                    revert RuntimeValidationFailed(
                        validationFunction.plugin, validationFunction.functionId, revertReason
                    );
                }
            }
            return;
        } else {
            // the msg.sender should be the owner of the account or itself
            if (msg.sender == owner || msg.sender == address(this)) {
                return;
            } else {
                revert UnauthorizedCaller();
            }
        }
    }

    /// @inheritdoc UUPSUpgradeable
    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override
        onlyProxy
        validateNativeFunction
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    /**
     * @dev The function is overridden here so more granular ACLs to the upgrade mechanism should be enforced by
     * plugins.
     */
    function _authorizeUpgrade(address newImplementation) internal override {}

    function _processPreUserOpValidationHooks(
        ExecutionDetail storage executionDetail,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (ValidationData memory unpackedValidationData) {
        unpackedValidationData = ValidationData(0, 0xFFFFFFFFFFFF, address(0));
        // if the function selector has associated pre user operation validation hooks, then those hooks MUST be run
        // sequentially
        uint256 totalUniqueHookCount = executionDetail.preUserOpValidationHooks.getUniqueItems();
        FunctionReference memory startHook = EMPTY_FUNCTION_REFERENCE.unpack();
        FunctionReference[] memory preUserOpValidatorHooks;
        FunctionReference memory nextHook;
        uint256 currentValidationData;
        for (uint256 i = 0; i < totalUniqueHookCount; ++i) {
            (preUserOpValidatorHooks, nextHook) = executionDetail.preUserOpValidationHooks.getPaginated(startHook, 10);
            for (uint256 j = 0; j < preUserOpValidatorHooks.length; ++j) {
                bytes21 packedUserOpValidatorHook = preUserOpValidatorHooks[j].pack();
                // if any revert, the outer call MUST revert
                if (
                    packedUserOpValidatorHook == EMPTY_FUNCTION_REFERENCE
                        || packedUserOpValidatorHook == RUNTIME_VALIDATION_ALWAYS_ALLOW_FUNCTION_REFERENCE
                        || packedUserOpValidatorHook == PRE_HOOK_ALWAYS_DENY_FUNCTION_REFERENCE
                ) {
                    revert InvalidHookFunctionId(preUserOpValidatorHooks[j].functionId);
                }
                IPlugin preUserOpValidationHookPlugin = IPlugin(preUserOpValidatorHooks[j].plugin);
                currentValidationData = preUserOpValidationHookPlugin.preUserOpValidationHook(
                    preUserOpValidatorHooks[j].functionId, userOp, userOpHash
                );
                unpackedValidationData = unpackedValidationData._intersectValidationData(currentValidationData);
                // if any return an authorizer value other than 0 or 1, execution MUST revert
                if (unpackedValidationData.authorizer != address(0) && unpackedValidationData.authorizer != address(1))
                {
                    revert InvalidAuthorizer();
                }
            }
            if (nextHook.pack() == SENTINEL_BYTES21) {
                break;
            }
            startHook = nextHook;
        }
        return unpackedValidationData;
    }

    function _checkFromEPOrOwnerOrSelf() internal view {
        // all need to go through validation first, which means being initiated by the owner or account
        if (
            msg.sender != address(entryPoint) && msg.sender != WalletStorageV1Lib.getLayout().owner
                && msg.sender != address(this)
        ) {
            revert UnauthorizedCaller();
        }
    }

    /**
     * @dev For EOA owner, run ecrecover. For smart contract owner, run 1271 staticcall.
     */
    function _verifySignature(address owner, bytes32 hash, bytes memory signature) internal view returns (bool) {
        // EOA owner (ECDSA)
        // if the signature (personal sign) is signed over userOpHash.toEthSignedMessageHash (prepended with
        // 'x\x19Ethereum Signed Message:\n32'), then we recover using userOpHash.toEthSignedMessageHash;
        // or if the signature (typed data sign) is signed over userOpHash directly, then we recover userOpHash directly
        (address recovered, ECDSA.RecoverError error,) = hash.toEthSignedMessageHash().tryRecover(signature);
        if (error == ECDSA.RecoverError.NoError && recovered == owner) {
            return true;
        }
        (recovered, error,) = hash.tryRecover(signature);
        if (error == ECDSA.RecoverError.NoError && recovered == owner) {
            return true;
        }
        if (SignatureChecker.isValidERC1271SignatureNow(owner, hash, signature)) {
            // smart contract owner.isValidSignature should be smart enough to sign over the non-modified hash or over
            // the hash that is modified in the way owner would expect
            return true;
        }
        return false;
    }
}
