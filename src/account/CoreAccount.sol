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

import {DefaultCallbackHandler} from "../callback/DefaultCallbackHandler.sol";
import {InvalidLength, UnauthorizedCaller} from "../common/Errors.sol";
import {ExecutionUtils} from "../utils/ExecutionUtils.sol";
import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @dev Upgradable & ownable contract. One of the most common templates.
 * The actual nonce uniqueness is checked in the EntryPoint, thus the account doesn't
 * need to implement _validateNonce.
 * The account only needs to implement _validateSignature.
 * The account doesn't need to implement its own _payPrefund because paymaster is handling the gas logic.
 */
abstract contract CoreAccount is
    BaseAccount,
    DefaultCallbackHandler,
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    IERC1271
{
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
    IEntryPoint public immutable ENTRY_POINT_ADDRESS;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;

    event AccountReceivedNativeToken(address indexed sender, uint256 value);

    function _checkOwner() internal view override {
        // directly from EOA owner, or through the account itself (which gets redirected through execute())
        if (!(msg.sender == owner() || msg.sender == address(this))) {
            revert UnauthorizedCaller();
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    // for immutable values in implementations
    constructor(IEntryPoint _newEntryPoint) {
        ENTRY_POINT_ADDRESS = _newEntryPoint;
        // lock the implementation contract so it can only be called from proxies
        _disableInitializers();
    }

    // for mutable values in proxies
    // solhint-disable-next-line func-name-mixedcase
    function __CoreAccount_init(address _newOwner) internal onlyInitializing {
        __Ownable_init();
        transferOwnership(_newOwner);
        __Pausable_init();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT_ADDRESS;
    }

    /// @dev Please override this method
    // function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash) internal virtual returns (uint256
    // validationData);

    /**
     * @notice Consider 6492 when it's mature.
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view virtual returns (bytes4 magicValue);

    /**
     * @dev Execute a single transaction.
     */
    function execute(address dest, uint256 value, bytes calldata func) external whenNotPaused {
        _requireFromEntryPointOrOwner();
        ExecutionUtils.callAndRevert(dest, value, func);
    }

    /**
     * @dev Execute a sequence of batched transactions.
     */
    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func)
        external
        whenNotPaused
    {
        _requireFromEntryPointOrOwner();
        if (dest.length != func.length || dest.length != value.length) {
            revert InvalidLength();
        }
        for (uint256 i = 0; i < dest.length; i++) {
            ExecutionUtils.callAndRevert(dest[i], value[i], func[i]);
        }
    }

    /**
     * @dev Require the function call went through EntryPoint or owner.
     */
    function _requireFromEntryPointOrOwner() internal view {
        if (!(msg.sender == address(entryPoint()) || msg.sender == owner())) {
            revert UnauthorizedCaller();
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable whenNotPaused {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner whenNotPaused {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {
        emit AccountReceivedNativeToken(msg.sender, msg.value);
    }

    function pause() public onlyOwner whenNotPaused {
        _pause();
    }

    function unpause() public onlyOwner whenPaused {
        _unpause();
    }
}
