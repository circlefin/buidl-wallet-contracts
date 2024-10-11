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

// validation by function selector
uint8 constant PER_SELECTOR_VALIDATION_FLAG = 0;

// global validation enabled
uint8 constant GLOBAL_VALIDATION_FLAG = 1;

// maximum number of validation hooks that can be installed, [0, 255) hooks, then validation function at
// RESERVED_VALIDATION_DATA_INDEX
uint8 constant MAX_VALIDATION_HOOKS = 255;

// index marking the start of the validation function data
uint8 constant RESERVED_VALIDATION_DATA_INDEX = 255;

// magic value for the Entity ID of direct call validation
uint32 constant DIRECT_CALL_VALIDATION_ENTITY_ID = type(uint32).max;
