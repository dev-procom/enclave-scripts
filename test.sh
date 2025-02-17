#!/bin/bash

CurrentVersion=1.0.0
Author=ProCom

set -euo pipefail

# configure script actions
DO_PREPARE_OS=true
DO_INSTALL_ENCLAVE=true
DO_INSTALL_NETDATA=true
DO_INSTALL_POWERSHELL=true
DO_CONFIGURE_ENCLAVE=true
DO_RESTRICT_ROOT=false
DO_UNATTENDED_UPGRADES=true

# variables
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

# =========================================================================

echo -e "Enclave VPN Gateway setup V$CurrentVersion."
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root before proceeding."
  exit
fi

# Ask the user how they want to proceed
echo -e "Default parameters:\n${CYAN}DO_PREPARE_OS=${YELLOW}$DO_PREPARE_OS"
echo -e "${CYAN}DO_INSTALL_ENCLAVE=${YELLOW}$DO_INSTALL_ENCLAVE"
echo -e "${CYAN}DO_INSTALL_NETDATA=${YELLOW}$DO_INSTALL_NETDATA"
echo -e "${CYAN}DO_INSTALL_POWERSHELL=${YELLOW}$DO_INSTALL_POWERSHELL"
echo -e "${CYAN}DO_CONFIGURE_ENCLAVE=${YELLOW}$DO_CONFIGURE_ENCLAVE"
echo -e "${CYAN}DO_RESTRICT_ROOT=${YELLOW}$DO_RESTRICT_ROOT"
echo -e "${CYAN}DO_UNATTENDED_UPGRADES=${YELLOW}$DO_UNATTENDED_UPGRADES"
echo -e "${CYAN}SSH_USERNAME=${YELLOW}$SSH_USERNAME"
echo -e "${CYAN}SSH_PASSWD=${YELLOW}******"
echo -e "${CYAN}SSH_KEY=${YELLOW}$SSH_KEY${RESET}"
echo -e ""
echo -n "Would you like to run the script with these parameters? (Y/N): "
read -r USER_PARAM_CHOICE

case "$USER_PARAM_CHOICE" in
    [Yy])
        echo "Proceeding with default parameters..."
        ;;
    [Nn])
        echo "Entering interactive setup..."
        echo -e "Configuring script actions. Accepted values: ${CYAN}true${RESET} | ${CYAN}false${RESET}\n"

        variable_names=("DO_PREPARE_OS" "DO_INSTALL_ENCLAVE" "DO_INSTALL_NETDATA" "DO_UNATTENDED_UPGRADES" "DO_INSTALL_POWERSHELL" "DO_CONFIGURE_ENCLAVE")

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
# Providing extra information
if [ "$DO_PREPARE_OS" = "true" ]; then

    echo -ne "\nPlease provide the type of gateway:\n${CYAN}0${RESET}: Virtual Machine\n${CYAN}1${RESET}: Raspberry Pi\n\n... > "
    read -r USER_GATEWAY_TYPE  

    while [[ ! "$USER_GATEWAY_TYPE" =~ ^(0|1)$ ]]; do
            echo -e "${RED}Invalid input. Please try again.${RESET}"
            echo -ne "... > " && read -r USER_GATEWAY_TYPE  
        done 

    case "$USER_GATEWAY_TYPE" in
        [0])
            NEW_HOSTNAME="enclave-gw-vm01"
            ;;
        [1])
            NEW_HOSTNAME="enclave-gw-rp01"
            ;;
    esac
fi  

if [ "$DO_INSTALL_NETDATA" = "true" ]; then

    echo -ne "\n${CYAN}DO_INSTALL_NETDATA${RESET} was set to ${YELLOW}true${RESET}. Would you like to provide a cloud claim token? (Y/N): "
    read -r USER_PROVIDE_CLAIM_TOKEN

    while [[ ! "$USER_PROVIDE_CLAIM_TOKEN" =~ ^(Y|y|N|n)$ ]]; do
        echo -e "${RED}Invalid input. Please try again.${RESET}"
        echo -ne "\n${CYAN}DO_INSTALL_NETDATA${RESET} was set to ${YELLOW}true${RESET}. Would you like to provide a cloud claim token? (Y/N): "
        read -r USER_PROVIDE_CLAIM_TOKEN
    done 

    case "$USER_PROVIDE_CLAIM_TOKEN" in
        [Yy])
            echo -ne "Please provide the token: "
            read -r NETDATA_CLOUD_CLAIM_TOKEN
            ;;
        [Nn])
           echo "Proceeding without claim token."
            ;;
    esac

fi 

if [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

    if [ "$DO_INSTALL_ENCLAVE" = "false" ]; then
        echo -e "\n${YELLOW}Warning: ${RESET}Enclave configuration will be skipped!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}, but ${CYAN}DO_INSTALL_ENCLAVE${RESET} was set to ${YELLOW}false${RESET}!\n"
        DO_CONFIGURE_ENCLAVE=false
    
    elif [ "$DO_INSTALL_ENCLAVE" = "true" ]; then

        if [ "$DO_INSTALL_POWERSHELL" =  "true" ]; then
            echo -e "\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}. Extra information is required."

            while true; do
                echo -en "Please provide an Enclave Organisation ID (${CYAN}orgId${RESET}): "
                read -r orgId_input
                orgId=$(echo "$orgId_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' )

                echo -e "API Key set to ${CYAN}$orgId${RESET}."
                echo -en "Proceed? (Y/N): " && read -r confirmation_orgId
                if [[ "$confirmation_orgId" =~ ^[Yy]$ ]]; then
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the organisation ID.${RESET}"
                fi
            done

            while true; do
                echo -en "Please provide an Enclave API Key (${CYAN}apiKey${RESET}): "
                read -r apiKey_input
                apiKey=$(echo "$apiKey_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' )

                echo -e "API Key set to ${CYAN}$apiKey${RESET}."
                echo -en "Proceed? (Y/N): " && read -r confirmation_apiKey
                if [[ "$confirmation_apiKey" =~ ^[Yy]$ ]]; then
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the API Key.${RESET}"
                fi
            done

            while true; do
                echo -en "Please provide a simplified customer name (${CYAN}customerName${RESET}): "
                read -r customerName_input

                customerName=$(echo "$customerName_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
                customerName=${customerName:0:20}

                if [ -z "$customerName" ]; then
                    echo -e "${RED}Invalid input! Customer name cannot be empty. Please try again.${RESET}"
                    continue  # Restart the loop
                fi

                echo -e "Final customer name: ${CYAN}$customerName${RESET}"
                echo -en "Proceed? (Y/N): " && read -r confirmation_customerName

                if [[ "$confirmation_customerName" =~ ^[Yy]$ ]]; then
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the customer name.${RESET}"
                fi
            done

        else  echo -e "\n${YELLOW}Warning: ${RESET}Enclave configuration will be skipped!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}, but ${CYAN}DO_INSTALL_POWERSHELL${RESET} was set to ${YELLOW}false${RESET}!\n"
        fi

    else echo "An unexpected error occured. Please try again."
    fi
fi 
# =========================================================================



if [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

    if ! command -v enclave &> /dev/null; then
        echo "Error: Enclave is not installed or not found in your PATH!"
        exit 1  # Exit with a non-zero status to indicate failure
    fi

    if ! command -v pwsh &> /dev/null; then
        echo "Error: PowerShell (pwsh) is not installed or not found in your PATH!"
        exit 1  # Exit with a non-zero status to indicate failure
    fi

    #First pass through config, before enrolling a gateway system
    if [ -f "./configure-policy.ps1" ]; then
        pwsh -File ./configure-policy.ps1 -orgId "$orgId" -apiKey "$apiKey" -customerName "$customerName" -newHostname "$NEW_HOSTNAME"
    else
        echo "${RED}Error${RESET}: the PowerShell script was not found!"
    fi
    
fi