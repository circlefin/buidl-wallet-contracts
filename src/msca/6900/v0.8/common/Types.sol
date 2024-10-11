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

// ModuleEntity is a packed representation of a module function
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________0000000000000000 // unused
type ModuleEntity is bytes24;

// ValidationConfig is a packed representation of a validation function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // Validation flags
// 0x__________________________________________________00000000000000 // unused
//
// Validation flags layout:
// 0b00000___ // unused
// 0b_____A__ // isGlobal
// 0b______B_ // isSignatureValidation
// 0b_______C // isUserOpValidation
type ValidationConfig is bytes25;

// HookConfig is a packed representation of a hook function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BBBBBBBB________________ // Entity ID
// 0x________________________________________________CC______________ // Hook Flags
//
// Hook flags layout:
// 0b00000___ // unused
// 0b_____A__ // hasPre (exec only)
// 0b______B_ // hasPost (exec only)
// 0b_______C // hook type (0 for exec, 1 for validation)
type HookConfig is bytes25;
