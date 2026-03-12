#!/bin/bash
# secagent Docker Test Script
# Tests the Docker image to ensure it works correctly

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "==================================="
echo "secagent Docker Test Suite"
echo "==================================="
echo ""

# Test 1: Build the image
echo -e "${YELLOW}[Test 1/5] Building Docker image...${NC}"
docker build -t secagent:test . > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Image built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build image${NC}"
    exit 1
fi
echo ""

# Test 2: Check version
echo -e "${YELLOW}[Test 2/5] Testing version command...${NC}"
VERSION_OUTPUT=$(docker run --rm secagent:test version 2>&1)
if echo "$VERSION_OUTPUT" | grep -q "secagent version"; then
    echo -e "${GREEN}✓ Version command works${NC}"
    echo "  Output: $VERSION_OUTPUT"
else
    echo -e "${RED}✗ Version command failed${NC}"
    exit 1
fi
echo ""

# Test 3: Run doctor
echo -e "${YELLOW}[Test 3/5] Testing doctor command...${NC}"
DOCTOR_OUTPUT=$(docker run --rm secagent:test doctor 2>&1)
if echo "$DOCTOR_OUTPUT" | grep -q "SecAgent Doctor"; then
    echo -e "${GREEN}✓ Doctor command works${NC}"
    SCANNERS_AVAILABLE=$(echo "$DOCTOR_OUTPUT" | grep -c "available" || true)
    echo "  Scanners available: $SCANNERS_AVAILABLE"
else
    echo -e "${RED}✗ Doctor command failed${NC}"
    exit 1
fi
echo ""

# Test 4: Scan a test directory
echo -e "${YELLOW}[Test 4/5] Testing scan command...${NC}"
mkdir -p /tmp/secagent-test
echo 'print("hello")' > /tmp/secagent-test/test.py
SCAN_OUTPUT=$(docker run --rm -v /tmp/secagent-test:/app/project secagent:test scan --scanners semgrep . 2>&1)
if echo "$SCAN_OUTPUT" | grep -q "SecAgent Security Scan Report"; then
    echo -e "${GREEN}✓ Scan command works${NC}"
    FINDINGS=$(echo "$SCAN_OUTPUT" | grep "Findings:" || echo "Findings: 0")
    echo "  $FINDINGS"
else
    echo -e "${RED}✗ Scan command failed${NC}"
    exit 1
fi
rm -rf /tmp/secagent-test
echo ""

# Test 5: Test JSON output
echo -e "${YELLOW}[Test 5/5] Testing JSON output...${NC}"
JSON_OUTPUT=$(docker run --rm -v $(pwd):/app/project secagent:test scan --scanners gitleaks . --format json 2>&1)
if echo "$JSON_OUTPUT" | grep -q '"findings"'; then
    echo -e "${GREEN}✓ JSON output works${NC}"
else
    echo -e "${RED}✗ JSON output failed${NC}"
    exit 1
fi
echo ""

# Summary
echo "==================================="
echo -e "${GREEN}All tests passed!${NC}"
echo "==================================="
echo ""
echo "Docker image is ready to use:"
echo "  docker run --rm -v \$(pwd):/app/project secagent:test scan --all ."
echo ""
