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

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";

import {IStakeManager} from "@account-abstraction/contracts/interfaces/IStakeManager.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * The paymaster must also have a deposit, which the entry point will charge UserOperation costs from.
 * The deposit (for paying gas fees) is separate from the stake (which is locked).
 * Note that this signature is NOT a replacement for the account-specific signature:
 * - the paymaster checks a signature to agree to pay for gas.
 * - the account checks a signature to prove identity and account ownership.
 * Since this contract is upgradable, we do not allow the use of either selfdestruct or delegatecall to prevent a malicious
 * actor from
 * destroying the logic contract.
 */
abstract contract BasePaymaster is
    IPaymaster,
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable
{
    // global entry point
    IEntryPoint public immutable entryPoint;
    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;

    /// @inheritdoc UUPSUpgradeable
    // The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
    // Authorize the owner to upgrade the contract.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    // for immutable values in implementations
    constructor(IEntryPoint _newEntryPoint) {
        entryPoint = _newEntryPoint;
        // lock the implementation contract so it can only be called from proxies
        _disableInitializers();
    }

    function __BasePaymaster_init(address _newOwner) internal onlyInitializing {
        __UUPSUpgradeable_init();
        __Ownable_init(_newOwner);
        __Pausable_init();
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        override
        whenNotPaused
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        virtual
        returns (bytes memory context, uint256 validationData);

    /// @inheritdoc IPaymaster
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external
        override
        whenNotPaused
    {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        virtual
    {}

    /**
     * add a deposit for this paymaster, used for paying for transaction fees
     */
    function deposit() public payable whenNotPaused {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * return current paymaster's deposit on the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * return current paymaster's full deposit&stake information on the entryPoint.
     */
    function getDepositInfo() public view returns (IStakeManager.DepositInfo memory info) {
        return entryPoint.getDepositInfo(address(this));
    }

    /**
     * add stake for this paymaster.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - the unstake delay for this paymaster. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) public payable onlyOwner whenNotPaused {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * unlock the stake, in order to withdraw it.
     * The paymaster can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() public onlyOwner whenNotPaused {
        entryPoint.unlockStake();
    }

    /**
     * withdraw the entire paymaster's stake.
     * stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) public onlyOwner whenNotPaused {
        entryPoint.withdrawStake(withdrawAddress);
    }

    /// validate the call is made from a valid entrypoint
    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "Sender not EntryPoint");
    }

    function pause() public onlyOwner whenNotPaused {
        _pause();
    }

    function unpause() public onlyOwner whenPaused {
        _unpause();
    }

    function withdrawTo(address payable withdrawAddress, uint256 amount) public onlyOwner whenNotPaused {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    /**
     * automatically deposit received native token to entrypoint
     */
    receive() external payable whenNotPaused {
        entryPoint.depositTo{value: msg.value}(address(this));
    }
}
