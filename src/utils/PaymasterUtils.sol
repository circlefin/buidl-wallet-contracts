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

/* solhint-disable reason-string */
/* solhint-disable no-inline-assembly */

import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

enum ChargeMode {
    GAS_ONLY, // paymaster will charge a network fee
    FREE, // paymaster will sponsor the transaction
    FEE_ONLY, // paymaster will charge a flat fee for its service
    FEE_AND_GAS // paymaster will charge both flat fee and network fee

}

/**
 * @dev In chainlink feed aggregator, ETH (Ξ) pairs (quote is Ξ) have 18 decimal of precisions, e.g. USDC/ETH;
 * Non-ETH (quote is not Ξ) pairs have 8 decimals of precisions, e.g. ETH/USDC.
 * For ETH/USDC,
 * 1. let ethToUSDCFxRate = latestRoundData.answer / 10**feedDecimals;
 * 2. let usdcCost = maxETHToBuy * ethToUSDCFxRate;
 * 3. let usdcCostInSubunits = usdcCost * 10**usdcDecimals
 * Now let's use the above formula to calculate the USDC token cost.
 * Let's assume ETH/USDC's latestRoundData.answer
 * (https://etherscan.io/address/0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419#readContract) is 211331000000 (note the link
 * is actually for ETH/USD),
 * let's also get maxETHToBuy (requiredPrefund) from https://aascan.org/, or you can calculate from totalGasLimit *
 * maxFeePerGas,
 * let's assume maxETHToBuy(requiredPrefund) is Ξ0.015 (15000000000000000), then apply step 1 ~ 3,
 * 1. ethToUSDCFxRate = 211331000000 / 10**8 = 2113.31;
 * 2. usdcCost = 0.015 * 2113.31 = 31.69965
 * 3. usdcCostInSubunits = 31.69965 * (10**6) = 31699650
 *
 * fxRate will be provided from an offchain price oracle that's aggregated from different exchanges.
 * For more details, please refer to https://docs.chain.link/data-feeds/price-feeds/addresses/?network=ethereum
 */
library PaymasterUtils {
    using UserOperationLib for PackedUserOperation;

    /**
     * struct PackedUserOperation {
     *   address sender;
     *   uint256 nonce;
     *   bytes initCode;
     *   bytes callData;
     *   bytes32 accountGasLimits;
     *   uint256 preVerificationGas;
     *   bytes32 gasFees;
     *   bytes paymasterAndData;
     *   bytes signature;
     * }
     */
    function packUpToPaymasterAndData(PackedUserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = userOp.getSender();
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        return abi.encode(sender, nonce, hashInitCode, hashCallData, accountGasLimits, preVerificationGas, gasFees);
    }

    /**
     * Keccak function over calldata.
     * @dev copy calldata into memory, do keccak and drop allocated memory. This is more efficient than letting solidity
     * do it.
     */
    function calldataKeccak(bytes calldata data) internal pure returns (bytes32 ret) {
        assembly {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }
}
