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

/**
 * @notice Throws when the caller is unexpected.
 */
error UnauthorizedCaller();

/**
 * @notice Throws when the selector is not found.
 */
error NotFoundSelector();

/**
 * @notice Throws when authorizer is invalid.
 */
error InvalidAuthorizer();

error InvalidValidationFunctionId(uint8 functionId);

error InvalidFunctionReference();

error ItemAlreadyExists();

error ItemDoesNotExist();

error InvalidLimit();

error InvalidExecutionFunction(bytes4 selector);

error InvalidInitializationInput();

error Create2FailedDeployment();

error InvalidLength();

error Unsupported();

error NotImplemented(bytes4 selector, uint8 functionId);

error InvalidItem();

// v2 NotImplemented
error NotImplementedFunction(bytes4 selector, uint32 entityId);

error SignatureInflation();
