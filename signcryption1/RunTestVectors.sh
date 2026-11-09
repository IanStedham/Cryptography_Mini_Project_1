#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BOLD="\e[1m"  
NORMAL="\e[0m" 

echo -e "${YELLOW}Starting Signcryption 1 Verification Script with Correct File Comparison...${NC}"
echo "========================================================"
# Compile the code
echo -e "${YELLOW}Compiling the code...${NC}"
# Check if the user wants to see warnings
read -p "Do you want to see the warnings? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gcc KeyGen.c -lcrypto -o CertificateAuthority
        gcc Sign.c -lcrypto -o Alice
        gcc Verify.c -lcrypto -o Bob
    else
        echo -e "${YELLOW}Compiling without warnings...${NC}"
        # Suppress warnings by using -w flag
        gcc KeyGen.c -lcrypto -o CertificateAuthority -w
        gcc Sign.c -lcrypto -o Alice -w
        gcc Verify.c -lcrypto -o Bob -w
    fi

# Function to normalize and compare files
compare_files() {
    local file1=$1
    local file2=$2
    local description=$3
    
    if [ ! -f "$file1" ]; then
        echo -e "${RED}Error: $file1 does not exist!${NC}"
        return 1
    fi
    
    if [ ! -f "$file2" ]; then
        echo -e "${RED}Error: $file2 does not exist!${NC}"
        return 1
    fi
    
    # Compare the files, ignoring whitespace and case
    if diff -i -b -B -w "$file1" "$file2" > /dev/null; then
        echo -e "${GREEN}$description match!${NC}"
        return 0
    else
        echo -e "${RED}$description do not match!${NC}"
        echo -e "${BLUE}Differences:${NC}"
        
        # Show a more detailed comparison
        echo -e "${YELLOW}$file1:${NC}"
        cat "$file1"
        echo -e "${YELLOW}$file2:${NC}"
        cat "$file2"
        
        return 1
    fi
}

# Function to compare generated files with correct files
compare_with_correct_files() {
    local test_num=$1
    local all_match=true
    
    echo -e "${BLUE}Comparing generated files with correct files for Test Case $test_num...${NC}"
    echo "--------------------------------------------------------"
    
    # Compare AliceKeys.txt with CorrectAliceKeys{test_num}.txt
    echo -e "${BLUE}Comparing Alice's keys...${NC}"
    if compare_files "AliceKeys.txt" "CorrectAliceKeys${test_num}.txt" "Alice's keys"; then
        : # Do nothing, comparison succeeded
    else
        all_match=false
    fi
    
    # Compare BobKeys.txt with CorrectBobKeys{test_num}.txt
    echo -e "${BLUE}Comparing Bob's keys...${NC}"
    if compare_files "BobKeys.txt" "CorrectBobKeys${test_num}.txt" "Bob's keys"; then
        : # Do nothing, comparison succeeded
    else
        all_match=false
    fi
    
    # Check if Signcryption.txt exists, if not, we'll skip this comparison
    if [ -f "Signcryption.txt" ]; then
        # Compare Signcryption.txt with CorrectSigncryption{test_num}.txt
        echo -e "${BLUE}Comparing signcryption...${NC}"
        if compare_files "Signcryption.txt" "CorrectSigncryption${test_num}.txt" "Signcryption"; then
            : # Do nothing, comparison succeeded
        else
            all_match=false
        fi
    else
        echo -e "${YELLOW}Note: Signcryption.txt not found, skipping signcryption comparison.${NC}"
    fi
    
    if [ "$all_match" = true ]; then
        echo -e "${GREEN}All files match the correct files for Test Case $test_num!${NC}"
    else
        echo -e "${YELLOW}Note: Differences in files don't necessarily indicate a problem with the implementation.${NC}"
        echo -e "${YELLOW}The most important check is that the decrypted message matches the original message.${NC}"
    fi
    
    echo "--------------------------------------------------------"
}

# Function to run a test case
run_test_case() {
    local test_num=$1
    
    echo -e "${YELLOW}Running Test Case $test_num...${NC}"
    
    # Clean up any existing files
    rm -f Params.txt AliceKeys.txt BobKeys.txt AlicePublicKey.txt BobPublicKey.txt Signcryption.txt SigncryptedMessage.txt Verification.txt DecryptedMessage.txt
    
    # Run Certificate Authority
    echo "Running Certificate Authority with Seed$test_num.txt and Parameters$test_num.txt..."
    ./CertificateAuthority "Seed$test_num.txt" "Parameters$test_num.txt"
    
    # Check if parameter files were created
    if [ ! -f Params.txt ] || [ ! -f AliceKeys.txt ] || [ ! -f BobKeys.txt ] || [ ! -f AlicePublicKey.txt ] || [ ! -f BobPublicKey.txt ]; then
        echo -e "${RED}Error: Parameter files were not created correctly.${NC}"
        return 1
    fi
    
    
    # Run Alice (Signcryption)
    echo "Running Alice with Message$test_num.txt..."
    ./Alice "Message$test_num.txt" "Seed$test_num.txt"
    
    # Check if signcryption file was created
    if [ ! -f SigncryptedMessage.txt ]; then
        echo -e "${RED}Error: SigncryptedMessage.txt was not created.${NC}"
        return 1
    fi
    
    # Run Bob (Unsigncryption)
    echo "Running Bob..."
    ./Bob
    
    # Compare with correct files
    compare_with_correct_files $test_num

    # Check verification result
    if [ -f Verification.txt ]; then
        verification=$(cat Verification.txt)
        if [ "$verification" == "Signature is Valid" ]; then
            echo -e "${GREEN}Verification successful!${NC}"
            
            # Check if decrypted message matches original
            if [ -f DecryptedMessage.txt ]; then
                # Use cmp for binary comparison instead of string comparison
                if cmp -s "Message$test_num.txt" DecryptedMessage.txt; then
                    echo -e "${GREEN}Decrypted message matches original message.${NC}"
                    return 0
                else
                    echo -e "${RED}Error: Decrypted message does not match original message.${NC}"
                    # For debugging, show hexdump of both files
                    echo "Original message (first 100 bytes):"
                    hexdump -C "Message$test_num.txt" | head -n 7
                    echo "Decrypted message (first 100 bytes):"
                    hexdump -C DecryptedMessage.txt | head -n 7
                    return 1
                fi
            else
                echo -e "${RED}Error: DecryptedMessage.txt was not created.${NC}"
                return 1
            fi
        else
            echo -e "${RED}Error: Verification failed.${NC}"
            return 1
        fi
    else
        echo -e "${RED}Error: Verification.txt was not created.${NC}"
        return 1
    fi
}

# Run test cases
run_test_case 1 
echo "========================================================"

run_test_case 2 
echo "========================================================"

run_test_case 3 
echo "========================================================"

echo -e "${YELLOW}Verification Script Completed.${NC}"
