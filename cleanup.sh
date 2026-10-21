#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Cleanup Script...${NC}"
echo "========================================================"

# Remove executable files
echo -e "Removing executable files..."
rm -f CertificateAuthority Alice Bob *.exe

# Remove generated key and parameter files
echo -e "Removing generated key and parameter files..."
rm -f Params.txt AliceKeys.txt BobKeys.txt AlicePublicKey.txt BobPublicKey.txt

# Remove generated signcryption files
echo -e "Removing generated signcryption files..."
rm -f Signcryption.txt SigncryptedMessage.txt Verification.txt DecryptedMessage.txt

# Remove any other temporary files that might be generated
echo -e "Removing any other temporary files..."
rm -f *.o *.tmp

echo -e "${GREEN}Cleanup completed successfully!${NC}"
echo "========================================================"
echo -e "The following files have been preserved:"
echo -e "- Source code files (KeyGen.c, Sign.c, Verify.c)"
echo -e "- Test vectors (Seed*.txt, Message*.txt)"
echo -e "- Parameter files (Parameters*.txt)"
echo -e "- Correct test files (Correct*.txt)"
echo -e "- Verification scripts (SimpleSigncryptionSolution.sh, ImprovedCompareWithCorrectFiles.sh)"
echo -e "- Cleanup script (cleanup.sh)"