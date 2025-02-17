#!/bin/bash

set -euo pipefail

# configure script actions
DO_PREPARE_OS=true
DO_INSTALL_ENCLAVE=true
DO_INSTALL_NETDATA=true
DO_RESTRICT_ROOT=false
DO_UNATTENDED_UPGRADES=true

# variables
NEW_HOSTNAME="enclave-gw-vm01"
SSH_USERNAME="enclave"
SSH_PASSWD=""
SSH_KEY=""
NETDATA_CLOUD_CLAIM_TOKEN=""


# =========================================================================
# ASCII Art
PURPLE="\033[35m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[96m"
RED="\033[31m"
RESET="\033[0m"



echo -e "${PURPLE}______          _____                 "
echo "| ___ \        /  __ \                "
echo "| |_/ / __ ___ | /  \/ ___  _ __ ___  "
echo "|  __/ '__/ _ \\| |    / _ \\| '_ \` _ \` "
echo "| |  | | | (_) | \\__/\\ (_) | | | | | |"
echo "\\_|  |_|  \\___/ \\____/\\___/|_| |_| |_|"
echo -e "${RESET}\n"

# Ask the user how they want to proceed
echo -e "Enclave VPN Gateway setup V1.0.0.\nDefault parameters:"
echo -e "${CYAN}DO_PREPARE_OS=${YELLOW}$DO_PREPARE_OS"
echo -e "${CYAN}DO_INSTALL_ENCLAVE=${YELLOW}$DO_INSTALL_ENCLAVE"
echo -e "${CYAN}DO_INSTALL_NETDATA=${YELLOW}$DO_INSTALL_NETDATA"
echo -e "${CYAN}DO_RESTRICT_ROOT=${YELLOW}$DO_RESTRICT_ROOT"
echo -e "${CYAN}DO_UNATTENDED_UPGRADES=${YELLOW}$DO_UNATTENDED_UPGRADES"
echo -e "${CYAN}SSH_USERNAME=${YELLOW}$SSH_USERNAME"
echo -e "${CYAN}SSH_PASSWD=${YELLOW}******"
echo -e "${CYAN}SSH_KEY=${YELLOW}$SSH_KEY${RESET}"
echo -e ""
echo -n "Would you like to run the script with these parameters? (Y/N): "
read -r USER_CHOICE

case "$USER_CHOICE" in
    [Yy])
        echo "Proceeding with default parameters..."
        ;;
    [Nn])
        echo "Entering interactive setup..."
        echo -e "Configure script actions. Accepted values: ${CYAN}true${RESET} | ${CYAN}false${RESET}\n"

        variable_names=("DO_PREPARE_OS" "DO_INSTALL_ENCLAVE" "DO_INSTALL_NETDATA" "DO_UNATTENDED_UPGRADES")

        for interactiveVariable in "${variable_names[@]}"; do
        echo -n "$interactiveVariable: "
        read -r input_value
        # Validate input
        while [[ ! "$input_value" =~ ^(true|false)$ ]]; do
            echo -e "${RED}Invalid input. Please enter 'true' or 'false'.${RESET}"
            echo -n "$interactiveVariable: "
            read -r input_value
        done
        eval $(echo -n $interactiveVariable)=$input_value


    
        echo -e "$interactiveVariable has been set to ${CYAN}${!interactiveVariable}${RESET}.\n"
        done

        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# =========================================================================

