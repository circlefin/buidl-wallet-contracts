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

import {
    EIP1271_INVALID_SIGNATURE,
    EIP1271_VALID_SIGNATURE,
    PLUGIN_AUTHOR,
    PLUGIN_VERSION_1,
    SIG_VALIDATION_FAILED,
    SIG_VALIDATION_SUCCEEDED
} from "../../../../../../common/Constants.sol";
import {InvalidValidationFunctionId, UnauthorizedCaller} from "../../../../shared/common/Errors.sol";
import "../../../common/PluginManifest.sol";
import "../../../common/Structs.sol";
import {IPluginManager} from "../../../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../../interfaces/IStandardExecutor.sol";
import {BasePlugin} from "../../BasePlugin.sol";

import {ISingleOwnerPlugin} from "./ISingleOwnerPlugin.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @dev Single owner plugin which is forked from OZ's Ownable. This plugin allows MSCA to be owned by an EOA or another
 * smart contract (which supports 1271).
 *      ERC4337's bundler validation rules (canonical mempool) forbid the opcodes with different outputs between the
 * simulation and execution.
 *      Meanwhile, bundler validation rules enforce storage access rules that allows the entity to use sender's
 * associated storage.
 *      When staked, an entity is also allowed to use its own associated storage.
 *      If the owner is a smart contract, the validation should not use any banned opcodes and violate any storage
 * rules.
 *      If the owner uses a storage slot not associated with itself, then the validation would fail.
 */
contract SingleOwnerPlugin is BasePlugin, ISingleOwnerPlugin, IERC1271 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Single Owner Plugin";
    string constant TRANSFER_OWNERSHIP = "Transfer_Ownership";
    // MSCA => owner
    mapping(address => address) internal _mscaOwners;

    error NoOwnerForMSCA(address account);

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current msg.sender.
     */
    function transferOwnership(address newOwner) external {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Returns the address of the current msg.sender.
     */
    function getOwner() external view returns (address) {
        return _mscaOwners[msg.sender];
    }

    /**
     * @dev Returns the address of the account.
     */
    function getOwnerOf(address account) external view returns (address) {
        return _mscaOwners[account];
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        if (_verifySignature(hash, signature)) {
            return EIP1271_VALID_SIGNATURE;
        }
        return EIP1271_INVALID_SIGNATURE;
    }

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {
        _transferOwnership(abi.decode(data, (address)));
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata data) external override {
        (data);
        _transferOwnership(address(0));
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256 validationData)
    {
        if (functionId != uint8(FunctionId.USER_OP_VALIDATION_OWNER)) {
            revert InvalidValidationFunctionId(functionId);
        }
        if (_verifySignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_SUCCEEDED;
        }
        return SIG_VALIDATION_FAILED;
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        view
        override
    {
        (value, data);
        if (functionId != uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)) {
            revert InvalidValidationFunctionId(functionId);
        }
        // the sender should be the owner of the account or itself
        // msg.sender is MSCA
        if (sender == _mscaOwners[msg.sender] || sender == msg.sender) {
            return;
        }
        revert UnauthorizedCaller();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        manifest.executionFunctions = new bytes4[](4);
        manifest.executionFunctions[0] = this.transferOwnership.selector;
        manifest.executionFunctions[1] = this.getOwner.selector;
        manifest.executionFunctions[2] = this.getOwnerOf.selector;
        manifest.executionFunctions[3] = this.isValidSignature.selector;

        ManifestFunction memory userOpValidationAssociatedFunction =
            ManifestFunction(ManifestAssociatedFunctionType.SELF, uint8(FunctionId.USER_OP_VALIDATION_OWNER), 0);
        // the following function calls (from entry point) should be gated by the userOpValidationAssociatedFunction
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](6);
        // plugin functions
        manifest.userOpValidationFunctions[0] =
            ManifestAssociatedFunction(this.transferOwnership.selector, userOpValidationAssociatedFunction);
        // native functions
        manifest.userOpValidationFunctions[1] =
            ManifestAssociatedFunction(IStandardExecutor.execute.selector, userOpValidationAssociatedFunction);
        manifest.userOpValidationFunctions[2] =
            ManifestAssociatedFunction(IStandardExecutor.executeBatch.selector, userOpValidationAssociatedFunction);
        manifest.userOpValidationFunctions[3] =
            ManifestAssociatedFunction(IPluginManager.installPlugin.selector, userOpValidationAssociatedFunction);
        manifest.userOpValidationFunctions[4] =
            ManifestAssociatedFunction(IPluginManager.uninstallPlugin.selector, userOpValidationAssociatedFunction);
        manifest.userOpValidationFunctions[5] =
            ManifestAssociatedFunction(UUPSUpgradeable.upgradeToAndCall.selector, userOpValidationAssociatedFunction);

        ManifestFunction memory runtimeValidationAssociatedFunction =
            ManifestFunction(ManifestAssociatedFunctionType.SELF, uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF), 0);
        ManifestFunction memory runtimeAlwaysAllowAssociatedFunction =
            ManifestFunction(ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW, 0, 0);
        // the following direct function calls (from EOA/SC) should be gated by the runtimeValidationAssociatedFunction
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](9);
        // plugin functions
        manifest.runtimeValidationFunctions[0] =
            ManifestAssociatedFunction(this.transferOwnership.selector, runtimeValidationAssociatedFunction);
        // native functions
        manifest.runtimeValidationFunctions[1] =
            ManifestAssociatedFunction(IStandardExecutor.execute.selector, runtimeValidationAssociatedFunction);
        manifest.runtimeValidationFunctions[2] =
            ManifestAssociatedFunction(IStandardExecutor.executeBatch.selector, runtimeValidationAssociatedFunction);
        manifest.runtimeValidationFunctions[3] =
            ManifestAssociatedFunction(IPluginManager.installPlugin.selector, runtimeValidationAssociatedFunction);
        manifest.runtimeValidationFunctions[4] =
            ManifestAssociatedFunction(IPluginManager.uninstallPlugin.selector, runtimeValidationAssociatedFunction);
        manifest.runtimeValidationFunctions[5] =
            ManifestAssociatedFunction(UUPSUpgradeable.upgradeToAndCall.selector, runtimeValidationAssociatedFunction);
        // always allow the following direct function calls (from EOA/SC)
        manifest.runtimeValidationFunctions[6] =
            ManifestAssociatedFunction(this.getOwner.selector, runtimeAlwaysAllowAssociatedFunction);
        manifest.runtimeValidationFunctions[7] =
            ManifestAssociatedFunction(this.getOwnerOf.selector, runtimeAlwaysAllowAssociatedFunction);
        manifest.runtimeValidationFunctions[8] =
            ManifestAssociatedFunction(this.isValidSignature.selector, runtimeAlwaysAllowAssociatedFunction);
        manifest.interfaceIds = new bytes4[](2);
        manifest.interfaceIds[0] = type(IERC1271).interfaceId;
        manifest.interfaceIds[1] = type(ISingleOwnerPlugin).interfaceId;
        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = PLUGIN_VERSION_1;
        metadata.author = PLUGIN_AUTHOR;

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.transferOwnership.selector,
            permissionDescription: TRANSFER_OWNERSHIP
        });
        return metadata;
    }

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISingleOwnerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal {
        address oldOwner = _mscaOwners[msg.sender];
        _mscaOwners[msg.sender] = newOwner;
        emit OwnershipTransferred(msg.sender, oldOwner, newOwner);
    }

    /**
     * @dev For EOA owner, run ecrecover. For smart contract owner, run 1271 staticcall.
     */
    function _verifySignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address owner = _mscaOwners[msg.sender];
        if (owner == address(0)) {
            revert NoOwnerForMSCA(msg.sender);
        }
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
