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

import {PaymasterUtils, UserOperationLib} from "../../../utils/PaymasterUtils.sol";

import {BasePaymaster, UserOperation} from "../../BasePaymaster.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * For sponsor mode, a signature is required from Circle. The purpose of signature is mostly used to allow Circle
 * to offer the gasless experience (free for end user) or other services.
 * In this mode, the paymaster uses external service to decide whether to pay for the UserOp.
 * The calling user must pass the UserOp to that external signer first, which performs whatever
 * off-chain verification before signing the UserOp.
 * The off-chain service could enable the user to pay for the gas cost with a credit card, subscription, or free, etc.
 * The paymaster verifies the external signer has signed the request in method _validatePaymasterUserOp().
 * getHash() returns a hash we're going to sign off-chain and validate on-chain.
 * Note that this signature is NOT a replacement for the account-specific signature:
 * - the paymaster checks a signature to agree to pay for gas.
 * - the account checks a signature prove identity and account ownership.
 * Since this contract is upgrable, we do not allow use either selfdestruct or delegatecall to prevent a malicious actor
 * from
 * attacking the logic contract.
 */
contract SponsorPaymaster is BasePaymaster {
    using EnumerableSet for EnumerableSet.AddressSet;
    using UserOperationLib for UserOperation;
    using PaymasterUtils for UserOperation;

    error VerifyingSignerAlreadyExists(address verifyingSigner);
    error VerifyingSignerDoesNotExist(address verifyingSigner);

    // trusted offline signers
    EnumerableSet.AddressSet private verifyingSigners;

    // constants still work for upgradable contracts because the compiler does not reserve storage slot
    // and every occurrence is replaced by the respective constant expression
    uint256 private constant TIMESTAMP_START = 20;
    uint256 private constant SIGNATURE_START = 84;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // for immutable values in implementations
    constructor(IEntryPoint _newEntryPoint) BasePaymaster(_newEntryPoint) {
        // lock the implementation contract so it can only be called from proxies
        _disableInitializers();
    }

    function initialize(address _newOwner, address[] calldata _verifyingSigners) public initializer {
        __BasePaymaster_init(_newOwner);

        uint256 length = _verifyingSigners.length;
        for (uint256 i = 0; i < length; i++) {
            if (!verifyingSigners.add(_verifyingSigners[i])) {
                revert VerifyingSignerAlreadyExists(_verifyingSigners[i]);
            }
        }
    }

    /**
     * Verify our external signer has signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params.
     * paymasterAndData[:20] : address(this)
     * paymasterAndData[20:84] : abi.encode(validUntil, validAfter)
     * paymasterAndData[84:] : signature
     */
    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        // unused
        (userOpHash, maxCost);

        (uint48 validUntil, uint48 validAfter, bytes memory signature) = parsePaymasterAndData(userOp.paymasterAndData);

        // calculate hash and check sig if applicable
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));

        // try recover the signer and verify if signer is a valid verifying signer
        // don't revert on signature failure: return SIG_VALIDATION_FAILED
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error != ECDSA.RecoverError.NoError || !verifyingSigners.contains(recovered)) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        // no need for other on-chain validation: entire UserOp should have been checked
        // by the external service prior to signing it.
        // no context returned because of no postOp activity
        return ("", _packValidationData(false, validUntil, validAfter));
    }

    /**
     * paymasterAndData[:20] : address(this)
     * paymasterAndData[20:84] : abi.encode(validUntil, validAfter)
     * paymasterAndData[84:] : signature
     */
    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        (validUntil, validAfter) = abi.decode(paymasterAndData[TIMESTAMP_START:SIGNATURE_START], (uint48, uint48));
        signature = paymasterAndData[SIGNATURE_START:];
    }

    /**
     * return the hash we're going to sign off-chain (and validate on-chain)
     * this method is called by the off-chain service, to sign the request.
     * it is called on-chain from the validatePaymasterUserOp, to validate the signature.
     * note that this signature covers all fields of the UserOperation, except the "paymasterAndData",
     * which will carry the signature itself.
     * struct UserOperation {
     *   address sender;
     *   uint256 nonce;
     *   bytes initCode;
     *   bytes callData;
     *   uint256 callGasLimit;
     *   uint256 verificationGasLimit;
     *   uint256 preVerificationGas;
     *   uint256 maxFeePerGas;
     *   uint256 maxPriorityFeePerGas;
     *   bytes paymasterAndData;
     *   bytes signature;
     * }
     */
    function getHash(UserOperation calldata userOp, uint48 validUntil, uint48 validAfter)
        public
        view
        returns (bytes32)
    {
        // can't use userOp.hash(), since it contains also the paymasterAndData itself.
        // EP manages nonce via NonceManager so senderNonce is redundant
        // packUpToPaymasterAndData already encodes userOp.nonce
        return keccak256(
            abi.encode(userOp.packUpToPaymasterAndData(), block.chainid, address(this), validUntil, validAfter)
        );
    }

    // add new verifying signers
    function addVerifyingSigners(address[] calldata _newVerifyingSigners) external onlyOwner whenNotPaused {
        uint256 length = _newVerifyingSigners.length;
        for (uint256 i = 0; i < length; i++) {
            if (!verifyingSigners.add(_newVerifyingSigners[i])) {
                revert VerifyingSignerAlreadyExists(_newVerifyingSigners[i]);
            }
        }
    }

    // remove existing verifying signers
    function removeVerifyingSigners(address[] calldata _verifyingSigners) external onlyOwner whenNotPaused {
        uint256 length = _verifyingSigners.length;
        for (uint256 i = 0; i < length; i++) {
            if (!verifyingSigners.remove(_verifyingSigners[i])) {
                revert VerifyingSignerDoesNotExist(_verifyingSigners[i]);
            }
        }
    }

    // get all verifying signers
    function getAllSigners() external view returns (address[] memory) {
        return verifyingSigners.values();
    }
}
