#!/bin/bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


# run-acceptance-tests.sh
# Script to run acceptance tests with proper environment setup
# 
# This script should be run from the repository root

set -e  # Exit on any error

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Change to repository root
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO $(date '+%H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS $(date '+%H:%M:%S')]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING $(date '+%H:%M:%S')]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR $(date '+%H:%M:%S')]${NC} $1"
}

print_debug() {
    echo -e "${CYAN}[DEBUG $(date '+%H:%M:%S')]${NC} $1"
}

print_test_info() {
    echo -e "${BLUE}[TEST $(date '+%H:%M:%S')]${NC} $1"
}

# Check if setup was completed
check_setup() {
    if [ ! -f "setup-test-env.sh" ]; then
        print_error "setup-test-env.sh not found. Please run setup-podman-machine.sh first."
        exit 1
    fi
    
    if ! podman machine list | grep -q "running"; then
        print_error "Podman machine is not running. Please run setup-podman-machine.sh first."
        exit 1
    fi
}

# Source environment variables
setup_environment() {
    print_status "Setting up environment variables..."
    source setup-test-env.sh
    print_success "Environment variables loaded"
}

# Clean up any existing test resources
cleanup_test_resources() {
    print_status "Cleaning up existing test resources..."
    
    # Clean up any existing Kind clusters
    kind delete cluster --all 2>/dev/null || true
    
    # Clean up any existing testcontainers
    podman system prune -f 2>/dev/null || true
    
    print_success "Test resources cleaned up"
}

# Test version extraction logic
test_version_extraction() {
    print_debug "Testing version extraction logic..."
    
    if [ ! -f "dist/ec_darwin_arm64" ]; then
        print_error "CLI binary not found: dist/ec_darwin_arm64"
        return 1
    fi
    
    # Test the version command and extract version
    local version_output
    if version_output=$(./dist/ec_darwin_arm64 version --json 2>/dev/null); then
        print_debug "Version command output:"
        echo "$version_output" | while IFS= read -r line; do
            print_debug "  $line"
        done
        
        # Extract version using jq if available, otherwise use grep
        local extracted_version
        if command -v jq >/dev/null 2>&1; then
            extracted_version=$(echo "$version_output" | jq -r '.Version' 2>/dev/null)
        else
            extracted_version=$(echo "$version_output" | grep -o '"Version":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
        fi
        
        if [ -n "$extracted_version" ]; then
            print_debug "Extracted version: $extracted_version"
            print_debug "This would be set as EC_VERSION variable"
        else
            print_error "Failed to extract version from JSON output"
            return 1
        fi
    else
        print_error "Failed to run version command"
        return 1
    fi
}

# List all available tests from feature files
list_tests() {
    local feature_pattern="${1:-}"
    local scenario_pattern="${2:-}"
    
    print_status "Listing available features and scenarios..."
    
    # Check if features directory exists
    if [ ! -d "features" ]; then
        print_error "features directory not found in $(pwd)"
        exit 1
    fi
    
    local feature_count=0
    local scenario_count=0
    local current_feature=""
    local current_file=""
    
    # Find all .feature files
    local feature_files
    if [ -n "$feature_pattern" ]; then
        feature_files=$(find features -name "*.feature" -type f | grep -i "$feature_pattern" | sort)
    else
        feature_files=$(find features -name "*.feature" -type f | sort)
    fi
    
    if [ -z "$feature_files" ]; then
        print_warning "No feature files found matching pattern: ${feature_pattern:-'*'}"
        return 0
    fi
    
    echo
    
    # Parse each feature file
    while IFS= read -r feature_file; do
        if [ ! -f "$feature_file" ]; then
            continue
        fi
        
        current_file=$(basename "$feature_file")
        local feature_name=""
        local feature_description=""
        local show_this_feature=false
        local in_feature=false
        local next_line_is_description=false
        
        # Read the feature file line by line
        while IFS= read -r line || [ -n "$line" ]; do
            # Check for Feature: line
            if [[ "$line" =~ ^Feature:[[:space:]]*(.+) ]]; then
                feature_name="${BASH_REMATCH[1]}"
                feature_count=$((feature_count + 1))
                in_feature=true
                next_line_is_description=true
                
                # Check if we should show this feature
                if [ -z "$feature_pattern" ] || echo "$feature_name" | grep -qi "$feature_pattern"; then
                    show_this_feature=true
                    echo
                    echo -e "${GREEN}Feature:${NC} $feature_name"
                    echo -e "  ${CYAN}File:${NC} $current_file"
                fi
            # Check for description line (first non-empty line after Feature:)
            elif [ "$next_line_is_description" = true ] && [ "$in_feature" = true ]; then
                if [[ ! "$line" =~ ^[[:space:]]*$ ]] && [[ ! "$line" =~ ^[[:space:]]*(Background|Scenario|Given|When|Then|And|But) ]]; then
                    if [ "$show_this_feature" = true ]; then
                        echo -e "  ${CYAN}Description:${NC} $line"
                    fi
                    next_line_is_description=false
                fi
            # Check for Scenario: line
            elif [[ "$line" =~ ^[[:space:]]*Scenario:[[:space:]]*(.+) ]] && [ "$in_feature" = true ]; then
                local scenario_name="${BASH_REMATCH[1]}"
                scenario_count=$((scenario_count + 1))
                next_line_is_description=false
                
                # Show scenario if feature matches and scenario matches pattern
                if [ "$show_this_feature" = true ]; then
                    if [ -z "$scenario_pattern" ] || echo "$scenario_name" | grep -qi "$scenario_pattern"; then
                        echo -e "  ${YELLOW}  Scenario:${NC} $scenario_name"
                    fi
                fi
            elif [ "$next_line_is_description" = true ] && [[ "$line" =~ ^[[:space:]]*$ ]]; then
                # Empty line, continue looking for description
                continue
            else
                next_line_is_description=false
            fi
        done < "$feature_file"
    done <<< "$feature_files"
    
    echo
    echo
    print_success "Found $feature_count feature(s) and $scenario_count scenario(s)"
    echo
    print_status "To run a specific feature/scenario, use:"
    print_status "  $0 'FeatureName'                    # Run all scenarios in a feature"
    print_status "  $0 'FeatureName/ScenarioName'        # Run a specific scenario"
    print_status "  $0 'FeaturePattern'                  # Run features matching pattern"
    print_status "  $0 'FeaturePattern/ScenarioPattern' # Run scenarios matching pattern"
}

# Run specific test or all tests
run_tests() {
    local test_pattern="${1:-}"
    local parallel="${2:-1}"
    local timeout="${3:-60m}"
    
    print_status "Running acceptance tests..."
    print_status "Test pattern: ${test_pattern:-'all tests'}"
    print_status "Parallelism: $parallel"
    print_status "Timeout: $timeout"
    
    # Check current directory and environment
    print_debug "Current directory: $(pwd)"
    print_debug "Environment variables:"
    print_debug "  KIND_EXPERIMENTAL_PROVIDER=$KIND_EXPERIMENTAL_PROVIDER"
    print_debug "  TESTCONTAINERS_RYUK_DISABLED=$TESTCONTAINERS_RYUK_DISABLED"
    print_debug "  TESTCONTAINERS_HOST_OVERRIDE=$TESTCONTAINERS_HOST_OVERRIDE"
    print_debug "  DOCKER_HOST=$DOCKER_HOST"
    
    # Check if CLI binary exists and test version command
    print_debug "Checking CLI binary..."
    if [ -f "dist/ec_darwin_arm64" ]; then
        print_debug "CLI binary found: dist/ec_darwin_arm64"
        print_debug "Testing version command:"
        ./dist/ec_darwin_arm64 version --json 2>&1 | head -3 | while IFS= read -r line; do
            print_debug "  $line"
        done
        
        # Test version extraction logic
        test_version_extraction
    else
        print_error "CLI binary not found: dist/ec_darwin_arm64"
        print_debug "Available files in dist/:"
        ls -la dist/ 2>/dev/null || print_debug "  dist/ directory not found"
    fi
    
    # Check podman status
    print_debug "Podman machine status:"
    podman machine list
    print_debug "Podman system info:"
    podman system info | head -10
    
    # Check networks
    print_debug "Available networks:"
    podman network ls
    
    # Check if acceptance directory exists
    if [ ! -d "acceptance" ]; then
        print_error "acceptance directory not found in $(pwd)"
        exit 1
    fi
    
    cd acceptance
    print_debug "Changed to acceptance directory: $(pwd)"
    
    # Record start time
    local start_time=$(date +%s)
    print_test_info "Starting test execution at $(date)"
    
    if [ -n "$test_pattern" ]; then
        print_status "Running specific test: $test_pattern"
        print_debug "Command: go test -v -run \"$test_pattern\" -parallel $parallel -timeout $timeout ./..."
        
        # Run tests and capture output - let go test handle its own timeout
        go test -v -run "$test_pattern" -parallel "$parallel" -timeout "$timeout" ./... 2>&1 | while IFS= read -r line; do
            print_test_info "$line"
        done
    else
        print_status "Running all tests"
        print_debug "Command: go test -v -parallel $parallel -timeout $timeout ./..."
        
        # Run tests and capture output - let go test handle its own timeout
        go test -v -parallel "$parallel" -timeout "$timeout" ./... 2>&1 | while IFS= read -r line; do
            print_test_info "$line"
        done
    fi
    
    # Record end time and duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    print_test_info "Test execution completed in ${duration}s"
    
    # Check for any hanging processes
    print_debug "Checking for hanging processes..."
    ps aux | grep -E "(go test|kind|podman)" | grep -v grep || print_debug "No hanging processes found"
}

# Show usage information
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_PATTERN]"
    echo
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -l, --list [PATTERN]    List all available features and scenarios"
    echo "                          Pattern can be 'FeatureName' or 'FeatureName/ScenarioName'"
    echo "  -p, --parallel N        Set parallelism level (default: 1)"
    echo "  -t, --timeout DURATION  Set timeout (default: 60m)"
    echo "  -c, --cleanup           Clean up test resources before running"
    echo "  -d, --debug             Enable debug mode with verbose output"
    echo
    echo "TEST_PATTERN:"
    echo "  Optional pattern to run specific tests (e.g., 'FeatureName/ScenarioName')"
    echo
    echo "Examples:"
    echo "  $0 -l                                    # List all features and scenarios"
    echo "  $0 -l 'validate'                         # List features matching 'validate'"
    echo "  $0 -l 'validate_image/happy day'         # List specific scenario"
    echo "  $0                                       # Run all tests"
    echo "  $0 -p 2 -t 30m                          # Run with 2 parallel, 30min timeout"
    echo "  $0 'validate_image'                      # Run all scenarios in a feature"
    echo "  $0 'validate_image/happy day'            # Run a specific scenario"
    echo "  $0 -c 'validate_image'                   # Clean up and run feature"
    echo "  $0 -d 'validate_image/happy day'         # Run with debug output"
}

# Parse command line arguments
parse_args() {
    local cleanup=false
    local parallel=1
    local timeout="60m"
    local test_pattern=""
    local debug=false
    local list_only=false
    local list_pattern=""
    local list_feature_pattern=""
    local list_scenario_pattern=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -l|--list)
                list_only=true
                # Check if next argument is a pattern (not another option)
                if [[ $# -gt 1 ]] && [[ ! "$2" =~ ^- ]]; then
                    list_pattern="$2"
                    shift 2
                else
                    shift
                fi
                # Also check if there's a scenario pattern (Feature/Scenario format)
                if [[ -n "$list_pattern" ]] && [[ "$list_pattern" =~ ^([^/]+)/(.+)$ ]]; then
                    # Pattern contains /, so split it
                    list_feature_pattern="${BASH_REMATCH[1]}"
                    list_scenario_pattern="${BASH_REMATCH[2]}"
                else
                    list_feature_pattern="$list_pattern"
                    list_scenario_pattern=""
                fi
                ;;
            -p|--parallel)
                parallel="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -c|--cleanup)
                cleanup=true
                shift
                ;;
            -d|--debug)
                debug=true
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                # If we're listing, treat this as a pattern; otherwise as test pattern
                if [ "$list_only" = true ]; then
                    list_pattern="$1"
                else
                    test_pattern="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Set debug mode if requested
    if [ "$debug" = true ]; then
        print_debug "Debug mode enabled"
        set -x  # Enable bash debug mode
    fi
    
    # If listing, do that and exit
    if [ "$list_only" = true ]; then
        list_tests "$list_feature_pattern" "$list_scenario_pattern"
        exit 0
    fi
    
    # Run cleanup if requested
    if [ "$cleanup" = true ]; then
        cleanup_test_resources
    fi
    
    # Run tests
    run_tests "$test_pattern" "$parallel" "$timeout"
}

# Main execution
main() {
    # Check if we're just listing tests (quick check without full setup)
    for arg in "$@"; do
        if [[ "$arg" == "-l" ]] || [[ "$arg" == "--list" ]]; then
            echo "=========================================="
            echo "  Listing Acceptance Tests"
            echo "=========================================="
            echo
            
            # Skip setup for listing - it's not needed
            parse_args "$@"
            exit 0
        fi
    done
    
    echo "=========================================="
    echo "  Running Acceptance Tests"
    echo "=========================================="
    echo
    
    check_setup
    setup_environment
    
    # Parse arguments and run tests
    parse_args "$@"
    
    print_success "Test execution completed"
}

# Run main function with all arguments
main "$@"
