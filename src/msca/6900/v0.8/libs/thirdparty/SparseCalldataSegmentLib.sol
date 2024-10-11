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

import {RESERVED_VALIDATION_DATA_INDEX} from "../../common/Constants.sol";

// TODO: remove this when SparseCalldataSegmentLib is moved to modular account lib
// https://github.com/erc6900/modular-account-libs/issues/2
/// @title Sparse Calldata Segment Library
/// @notice Inspired by 6900 reference implementation for working with sparsely-packed calldata segments, identified
/// with an index.
/// @dev The first byte of each segment is the index of the segment.
/// To prevent accidental stack-to-deep errors, the body and index of the segment are extracted separately, rather
/// than inline as part of the tuple returned by `getNextSegment`.
library SparseCalldataSegmentLib {
    error NonCanonicalEncoding();
    error SegmentOutOfOrder();
    error ValidationSignatureSegmentMissing();

    /// @notice Splits out a segment of calldata, sparsely-packed.
    /// The expected format is:
    /// [uint32(len(segment0)), segment0, uint32(len(segment1)), segment1, ... uint32(len(segmentN)), segmentN]
    /// @param source The calldata to extract the segment from.
    /// @return segment The extracted segment. Using the above example, this would be segment0.
    /// @return remainder The remaining calldata. Using the above example,
    /// this would start at uint32(len(segment1)) and continue to the end at segmentN.
    function getNextSegment(bytes calldata source)
        internal
        pure
        returns (bytes calldata segment, bytes calldata remainder)
    {
        // The first 4 bytes hold the length of the segment, excluding the index.
        uint32 length = uint32(bytes4(source[:4]));

        // The offset of the remainder of the calldata.
        uint256 remainderOffset = 4 + length;

        // The segment is the next `length` + 1 bytes, to account for the index.
        // By convention, the first byte of each segment is the index of the segment.
        segment = source[4:remainderOffset];

        // The remainder is the rest of the calldata.
        remainder = source[remainderOffset:];
    }

    /// @notice Extracts the index from a segment.
    /// @dev The first byte of the segment is the index.
    /// @param segment The segment to extract the index from
    /// @return The index of the segment
    function getIndex(bytes calldata segment) internal pure returns (uint8) {
        return uint8(segment[0]);
    }

    /// @notice Extracts the body from a segment.
    /// @dev The body is the segment without the index.
    /// @param segment The segment to extract the body from
    /// @return The body of the segment.
    function getBody(bytes calldata segment) internal pure returns (bytes calldata) {
        return segment[1:];
    }

    /// @notice If the index of the next segment in the source equals the provided index, return the next body and
    /// advance the source by one segment.
    /// @dev Reverts if the index of the next segment is less than the provided index, or if the extracted segment
    /// has length 0.
    /// @param source The calldata to extract the segment from.
    /// @param index The index of the segment to extract.
    /// @return A tuple containing the extracted segment's body, or an empty buffer if the index is not found, and
    /// the remaining calldata.
    function advanceSegmentIfAtIndex(bytes calldata source, uint8 index)
        internal
        pure
        returns (bytes memory, bytes calldata)
    {
        // the index of the next segment in the source
        uint8 nextIndex = uint8(source[4]);
        if (nextIndex < index) {
            revert SegmentOutOfOrder();
        }
        if (nextIndex == index) {
            (bytes calldata segment, bytes calldata remainder) = getNextSegment(source);
            segment = getBody(segment);
            if (segment.length == 0) {
                revert NonCanonicalEncoding();
            }
            return (segment, remainder);
        }
        return ("", source);
    }

    /// @notice Extracts the final segment from the calldata.
    /// @dev The final segment must have an index equal to `RESERVED_VALIDATION_DATA_INDEX`.
    /// Reverts if the final segment is not found or if there is remaining calldata after the final segment.
    /// @param source The calldata to extract the final segment from.
    /// @return The body of the final segment.
    function getFinalSegment(bytes calldata source) internal pure returns (bytes calldata) {
        (bytes calldata segment, bytes calldata remainder) = getNextSegment(source);
        // a single byte index caps the total number of pre-validation hooks at 255
        if (getIndex(segment) != RESERVED_VALIDATION_DATA_INDEX) {
            revert ValidationSignatureSegmentMissing();
        }
        if (remainder.length != 0) {
            revert NonCanonicalEncoding();
        }
        return getBody(segment);
    }
}
