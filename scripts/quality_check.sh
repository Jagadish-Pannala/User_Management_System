#!/bin/bash

# --- Configuration ---
TARGET_DIR="Backend"
TEST_DIR="tests"
MIN_COVERAGE=90
REPORT_DIR="quality_reports"

# Create report directory
mkdir -p $REPORT_DIR

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Starting Quality Checks..."

# 1. Autoflake
echo -e "\n[1/5] Running Autoflake..."
autoflake --in-place --remove-all-unused-imports --recursive $TARGET_DIR

# 2. Black (Formatting)
echo -e "\n[2/5] Checking Black..."
# This fixes the files automatically
echo "Formatting code with Black..."
black $TARGET_DIR
if [ $? -ne 0 ]; then echo -e "${RED}Black failed${NC}"; exit 1; fi

# 3. Flake8 (Linting)
echo -e "\n[3/5] Running Linter (Flake8)..."
# We run it and capture the output to a variable
FLAKE_OUTPUT=$(flake8 $TARGET_DIR --count --max-line-length=88 --extend-ignore=E203,E501 --statistics)
FLAKE_EXIT_CODE=$?

# Always save to the report file for Jenkins
echo "$FLAKE_OUTPUT" > $REPORT_DIR/flake8_report.txt

if [ $FLAKE_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Flake8 found the following issues:${NC}"
    # Print the errors so you can see them immediately
    echo "$FLAKE_OUTPUT"
    echo -e "\n${RED}How to fix:${NC}"
    echo "1. Look at the line numbers above (e.g., Backend/main.py:10)."
    echo "2. Fix the specific PEP8 violation listed."
    echo "3. Common fixes: Add missing docstrings, remove unused variables, or fix indentation."
    exit 1
fi

# 4. Bandit (Security)
echo -e "\n[4/5] Running Bandit Security Scan..."
# Run and capture output
BANDIT_OUTPUT=$(bandit -r $TARGET_DIR -ll -ii 2>&1)
BANDIT_EXIT_CODE=$?

# Save to report
echo "$BANDIT_OUTPUT" > $REPORT_DIR/security_report.txt

if [ $BANDIT_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Security vulnerabilities detected!${NC}"
    echo "$BANDIT_OUTPUT"
    echo -e "\n${RED}How to fix:${NC}"
    echo "1. Check for hardcoded passwords or keys."
    echo "2. Ensure SQL queries use parameters, not f-strings."
    echo "3. Use '# nosec' on a line if you are sure it is safe."
    exit 1
fi

# 5. Pytest (Coverage)
echo -e "\n[5/5] Running Tests (Gate: ${MIN_COVERAGE}%)..."
# Generates HTML report for your Jenkins 'publishHTML' step
pytest --cov=$TARGET_DIR $TEST_DIR \
       --cov-report=term-missing \
       --cov-report=html:$REPORT_DIR/coverage_html \
       --cov-fail-under=$MIN_COVERAGE

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}QUALITY GATE PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}QUALITY GATE FAILED${NC}"
    exit 1
fi
