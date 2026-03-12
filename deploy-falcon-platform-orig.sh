#!/bin/bash

set -e

# Falcon Platform HELM Deployment Automation Script
# Based on: Falcon Platform-HELM Deployment_r2.pdf

echo "=========================================="
echo "Falcon Platform HELM Deployment Script"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to prompt for input with validation
prompt_input() {
    local var_name=$1
    local prompt_message=$2
    local is_secret=$3

    while true; do
        if [ "$is_secret" = "true" ]; then
            read -s -p "$prompt_message: " input_value
            echo ""
        else
            read -p "$prompt_message: " input_value
        fi

        if [ -n "$input_value" ]; then
            eval "$var_name='$input_value'"
            break
        else
            print_error "Value cannot be empty. Please try again."
        fi
    done
}

# Check if required tools are installed
check_prerequisites() {
    print_info "Checking prerequisites..."

    local missing_tools=()

    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi

    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi

    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_error "Please install missing tools and try again."
        exit 1
    fi

    print_info "All prerequisites met!"
}

# Collect user inputs
collect_inputs() {
    echo ""
    print_info "Collecting deployment information..."
    echo ""

    # Check if variables are already set in environment
    if [ -z "$FALCON_CLIENT_ID" ]; then
        prompt_input FALCON_CLIENT_ID "Enter Falcon API Client ID" false
    else
        print_info "Using FALCON_CLIENT_ID from environment"
    fi

    if [ -z "$FALCON_CLIENT_SECRET" ]; then
        prompt_input FALCON_CLIENT_SECRET "Enter Falcon API Client Secret" true
    else
        print_info "Using FALCON_CLIENT_SECRET from environment"
    fi

    if [ -z "$FALCON_CID" ]; then
        prompt_input FALCON_CID "Enter Falcon CID (with checksum)" false
    else
        print_info "Using FALCON_CID from environment"
    fi

    if [ -z "$CLUSTER_NAME" ]; then
        echo ""
        print_warn "Cluster Name Format Examples:"
        print_warn "  AKS: /subscriptions/<subscriptionID>/resourcegroups/<resourceGroup>/providers/microsoft.containerservice/managedclusters/<clusterName>"
        print_warn "  EKS: arn:aws:eks:<region>:<account>:cluster/<clusterName>"
        echo ""
        prompt_input CLUSTER_NAME "Enter Kubernetes Cluster Name" false
    else
        print_info "Using CLUSTER_NAME from environment"
    fi

    export FALCON_CLIENT_ID
    export FALCON_CLIENT_SECRET
    export FALCON_CID
    export CLUSTER_NAME
}

# Download falcon-container-sensor-pull script
download_script() {
    echo ""
    print_info "Step 1-2: Downloading falcon-container-sensor-pull.sh script..."

    curl -sSL -o falcon-container-sensor-pull.sh \
        "https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh"

    chmod +x falcon-container-sensor-pull.sh

    print_info "Script downloaded and made executable"
}

# Get pull token
get_pull_token() {
    echo ""
    print_info "Step 5-6: Getting registry pull token..."

    ENCODED_DOCKER_CONFIG=$(./falcon-container-sensor-pull.sh \
        -u "$FALCON_CLIENT_ID" \
        -s "$FALCON_CLIENT_SECRET" \
        --type falcon-sensor \
        --platform x86_64 \
        --get-pull-token)

    if [ -z "$ENCODED_DOCKER_CONFIG" ]; then
        print_error "Failed to get pull token"
        exit 1
    fi

    export ENCODED_DOCKER_CONFIG
    print_info "Pull token retrieved successfully"
}

# Get Falcon Sensor image tag
get_sensor_tag() {
    echo ""
    print_info "Step 8-10: Getting Falcon Sensor image tag..."

    export SENSOR_REGISTRY="registry.crowdstrike.com/falcon-sensor/release/falcon-sensor"

    # Get full output for debugging
    TAGS_OUTPUT=$(./falcon-container-sensor-pull.sh \
        -u "$FALCON_CLIENT_ID" \
        -s "$FALCON_CLIENT_SECRET" \
        --type falcon-sensor \
        --platform x86_64 \
        --list-tags 2>&1)

    # Extract just the version tag (filter out JSON and metadata, remove quotes and commas)
    SENSOR_IMAGE_TAG=$(echo "$TAGS_OUTPUT" | grep -v "^{" | grep -v "^}" | grep -v "^$" | grep -E '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | tr -d ' ",\t')

    if [ -z "$SENSOR_IMAGE_TAG" ]; then
        print_error "Failed to get Falcon Sensor image tag"
        print_error "Output was:"
        echo "$TAGS_OUTPUT"
        exit 1
    fi

    export SENSOR_IMAGE_TAG
    print_info "Falcon Sensor tag: $SENSOR_IMAGE_TAG"
}

# Get KAC image tag
get_kac_tag() {
    echo ""
    print_info "Step 11-13: Getting Falcon KAC image tag..."

    export KAC_REGISTRY="registry.crowdstrike.com/falcon-kac/release/falcon-kac"

    # Get full output for debugging
    TAGS_OUTPUT=$(./falcon-container-sensor-pull.sh \
        -u "$FALCON_CLIENT_ID" \
        -s "$FALCON_CLIENT_SECRET" \
        --type falcon-kac \
        --platform x86_64 \
        --list-tags 2>&1)

    # Extract just the version tag (filter out JSON and metadata, remove quotes and commas)
    KAC_IMAGE_TAG=$(echo "$TAGS_OUTPUT" | grep -v "^{" | grep -v "^}" | grep -v "^$" | grep -E '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | tr -d ' ",\t')

    if [ -z "$KAC_IMAGE_TAG" ]; then
        print_error "Failed to get KAC image tag"
        print_error "Output was:"
        echo "$TAGS_OUTPUT"
        exit 1
    fi

    export KAC_IMAGE_TAG
    print_info "Falcon KAC tag: $KAC_IMAGE_TAG"
}

# Get IAR image tag
get_iar_tag() {
    echo ""
    print_info "Step 14-16: Getting Falcon Image Analyzer image tag..."

    export IAR_REGISTRY="registry.crowdstrike.com/falcon-imageanalyzer/us-1/release/falcon-imageanalyzer"

    # Get full output for debugging
    TAGS_OUTPUT=$(./falcon-container-sensor-pull.sh \
        -u "$FALCON_CLIENT_ID" \
        -s "$FALCON_CLIENT_SECRET" \
        --type falcon-imageanalyzer \
        --platform x86_64 \
        --list-tags 2>&1)

    # Extract just the version tag (filter out JSON and metadata, remove quotes and commas)
    IAR_IMAGE_TAG=$(echo "$TAGS_OUTPUT" | grep -v "^{" | grep -v "^}" | grep -v "^$" | grep -E '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | tr -d ' ",\t')

    if [ -z "$IAR_IMAGE_TAG" ]; then
        print_error "Failed to get Image Analyzer image tag"
        print_error "Output was:"
        echo "$TAGS_OUTPUT"
        exit 1
    fi

    export IAR_IMAGE_TAG
    print_info "Falcon Image Analyzer tag: $IAR_IMAGE_TAG"
}

# Setup Helm repository
setup_helm_repo() {
    echo ""
    print_info "Step 18-19: Setting up Helm repository..."

    helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm
    helm repo update

    print_info "Helm repository added and updated"
}

# Install Falcon Platform
install_falcon_platform() {
    echo ""
    print_info "Step 20: Installing Falcon Platform via Helm..."
    echo ""

    print_info "Deployment Summary:"
    print_info "  Namespace: falcon-platform"
    print_info "  Sensor Tag: $SENSOR_IMAGE_TAG"
    print_info "  KAC Tag: $KAC_IMAGE_TAG"
    print_info "  IAR Tag: $IAR_IMAGE_TAG"
    print_info "  Cluster: $CLUSTER_NAME"
    echo ""

    read -p "Proceed with installation? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        print_warn "Installation cancelled by user"
        exit 0
    fi

    helm install falcon-platform crowdstrike/falcon-platform \
        --namespace falcon-platform \
        --create-namespace \
        --set createComponentNamespaces=true \
        --set global.falcon.cid="$FALCON_CID" \
        --set global.containerRegistry.configJSON="$ENCODED_DOCKER_CONFIG" \
        --set falcon-sensor.node.image.repository="$SENSOR_REGISTRY" \
        --set falcon-sensor.node.image.tag="$SENSOR_IMAGE_TAG" \
        --set falcon-kac.image.repository="$KAC_REGISTRY" \
        --set falcon-kac.image.tag="$KAC_IMAGE_TAG" \
        --set falcon-image-analyzer.deployment.enabled=true \
        --set falcon-image-analyzer.image.repository="$IAR_REGISTRY" \
        --set falcon-image-analyzer.image.tag="$IAR_IMAGE_TAG" \
        --set falcon-image-analyzer.crowdstrikeConfig.clusterName="$CLUSTER_NAME" \
        --set falcon-image-analyzer.crowdstrikeConfig.clientID="$FALCON_CLIENT_ID" \
        --set falcon-image-analyzer.crowdstrikeConfig.clientSecret="$FALCON_CLIENT_SECRET"

    print_info "Falcon Platform installation completed!"
}

# Verify deployment
verify_deployment() {
    echo ""
    print_info "Verifying deployment..."
    echo ""

    kubectl get pods -n falcon-platform

    echo ""
    print_info "Deployment verification complete!"
    print_info "Check pod status above to ensure all pods are running"
}

# Main execution
main() {
    check_prerequisites
    collect_inputs
    download_script
    get_pull_token
    get_sensor_tag
    get_kac_tag
    get_iar_tag
    setup_helm_repo
    install_falcon_platform
    verify_deployment

    echo ""
    echo "=========================================="
    print_info "Falcon Platform deployment completed successfully!"
    echo "=========================================="
    echo ""
    print_info "To check deployment status, run:"
    print_info "  kubectl get pods -n falcon-platform"
    print_info "  helm list -n falcon-platform"
    echo ""
}

# Run main function
main
