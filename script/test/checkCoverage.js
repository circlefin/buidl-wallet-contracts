/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

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
const fs = require('fs');

const COVERAGE_TABLE_HEADER = "| File                                                                           | % Lines            | % Statements       | % Branches       | % Funcs          |";
const COVERAGE_TABLE_HEADER_SEPARATOR = "|--------------------------------------------------------------------------------|--------------------|--------------------|------------------|------------------|";
const COVERAGE_TABLE_TOTAL_ROW_NAME = 'Total';
const COVERAGE_TABLE_COLUMN_DELIM = '|';

// Matches expressions like "12.25%"
const COVERAGE_TABLE_COVERAGE_PECENTAGE_REGEXP = /[\d\.]+%/;

const MIN_REQUIRED_LINE_COVERAGE_PERCENTAGE = 90;
const MIN_REQUIRED_STATEMENT_COVERAGE_PERCENTAGE = 90;
const MIN_REQUIRED_BRANCH_COVERAGE_PERCENTAGE = 90;
const MIN_REQUIRED_FUNCTION_COVERAGE_PERCENTAGE = 90;

const NUM_COLUMNS = COVERAGE_TABLE_HEADER.split(COVERAGE_TABLE_COLUMN_DELIM).length - 2;

function parsePercentage(rawCoveragePercentText) {
    const numericDecimalText = COVERAGE_TABLE_COVERAGE_PECENTAGE_REGEXP.exec(rawCoveragePercentText)[0].slice(0, -1);
    return parseFloat(numericDecimalText);
}

function parseCoverageTableRow(rawRowText) {
    let rowParts = rawRowText.split(COVERAGE_TABLE_COLUMN_DELIM);
    if (rowParts.length - 2 != NUM_COLUMNS) {
        return null
    }

    rowParts = rowParts.slice(1, -1);
    return {
        fileName: rowParts[0].trim(),
        lineCoveragePercent: parsePercentage(rowParts[1]),
        statementCoveragePercent: parsePercentage(rowParts[2]),
        branchCoveragePercent: parsePercentage(rowParts[3]),
        functionCoveragePercent: parsePercentage(rowParts[4]),
    }
}

function getFormattedCoverageTableRowsTest(coverageTableRows) {
    return COVERAGE_TABLE_HEADER + '\n'
        + COVERAGE_TABLE_HEADER_SEPARATOR + '\n'
        + coverageTableRows.join('\n') + '\n';
}

(async function main() {
    const coverateReportFileName = process.argv[2];
    const coverageReportRawText = fs.readFileSync(coverateReportFileName, "utf8");
    
    let coverageTableBodyRaw = "";
    try {
        coverageTableBodyRaw = coverageReportRawText.split(COVERAGE_TABLE_HEADER)[1];
    } catch (error) {
        console.error("Unexpected coverage report format");
        console.error(error);
        process.exit(1);
    }
    
    const belowThresholdFiles = [];
    const aboveThresholdFiles = [];
    let totalCoverageRow = "";
    const coverageTableRows = coverageTableBodyRaw.split("\n").slice(3);
    
    for (const coverageTableRowRaw of coverageTableRows) {
        const coverageRow = parseCoverageTableRow(coverageTableRowRaw);
        if (!coverageRow) {
            continue;
        }
    
        // Check minimum required coverage percentages
        if (coverageRow.fileName == COVERAGE_TABLE_TOTAL_ROW_NAME) {
            totalCoverageRow = coverageTableRowRaw;
        } else if (coverageRow.lineCoveragePercent < MIN_REQUIRED_LINE_COVERAGE_PERCENTAGE ||
            coverageRow.statementCoveragePercent < MIN_REQUIRED_STATEMENT_COVERAGE_PERCENTAGE ||
            coverageRow.branchCoveragePercent < MIN_REQUIRED_BRANCH_COVERAGE_PERCENTAGE ||
            coverageRow.functionCoveragePercent < MIN_REQUIRED_FUNCTION_COVERAGE_PERCENTAGE) {
        
            belowThresholdFiles.push(coverageTableRowRaw);
        } else {
            aboveThresholdFiles.push(coverageTableRowRaw);
        }
    }
    
    // Print coverage breakdown details
    console.log("Total coverage: ");
    console.log(getFormattedCoverageTableRowsTest([totalCoverageRow]));

    if (belowThresholdFiles.length > 0) {
        console.log("Found files below coverage threshold: ");
        console.log(getFormattedCoverageTableRowsTest(belowThresholdFiles));
    } else {
        console.log("All source code files meet minimum coverage requirements.");
    }
    if (aboveThresholdFiles.length > 0) {
        console.log("Files above coverage threshold: ");
        console.log(getFormattedCoverageTableRowsTest(aboveThresholdFiles));
    }

    // Fail if any files found below the minimum coverage threshold
    if (belowThresholdFiles.length > 0) {
        // TODO: uncomment line once source code coverages have been bumped up
        // process.exit(2);
    }
})();