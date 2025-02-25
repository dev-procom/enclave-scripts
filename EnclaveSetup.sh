#!/bin/bash

CurrentVersion=1.0.0
Author=ProCom


set -euo pipefail

# SSH (wordt niet gebruikt?)
DO_RESTRICT_ROOT=false
SSH_USERNAME="enclave"
SSH_PASSWD=""
SSH_KEY=""

# configure script actions
DO_PREPARE_OS=true
DO_INSTALL_ENCLAVE=true
DO_INSTALL_NETDATA=true
DO_CONNECT_NETDATA=false
DO_UNATTENDED_UPGRADES=true

# configure Enclave actions, only if DO_INSTALL_ENCLAVE is true
DO_INSTALL_POWERSHELL=true
DO_CONFIGURE_ENCLAVE=true
DO_AUTODISCOVER_SUBNET=true
DO_RESTRICT_SUBNET=false

# variables
NETDATA_CLOUD_CLAIM_TOKEN=""

# =========================================================================
# ASCII Art
PURPLE="\033[35m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[96m"
RED="\033[31m"
GRAY="\033[90m"
RESET="\033[0m"


clear
echo -e "${PURPLE}______          _____                 "
echo "| ___ \        /  __ \                "
echo "| |_/ / __ ___ | /  \/ ___  _ __ ___  "
echo "|  __/ '__/ _ \\| |    / _ \\| '_ \` _ \` "
echo "| |  | | | (_) | \\__/\\ (_) | | | | | |"
echo "\\_|  |_|  \\___/ \\____/\\___/|_| |_| |_|"
echo -e "${RESET}\n"

# =========================================================================

variable_names=(
    "DO_PREPARE_OS"
    "DO_INSTALL_ENCLAVE"
    "DO_INSTALL_NETDATA"
    "DO_CONNECT_NETDATA"
    "DO_UNATTENDED_UPGRADES"
    "DO_INSTALL_POWERSHELL" 
    "DO_CONFIGURE_ENCLAVE"
    "DO_AUTODISCOVER_SUBNET"
    "DO_RESTRICT_SUBNET"
    )


echo -e "Enclave VPN Gateway setup V$CurrentVersion."
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run this script as root before proceeding.${RESET}\n"
  exit
fi


# Ask the user how they want to proceed
echo -e "Default parameters:\n"
for interactiveVariable in "${variable_names[@]}"; do
    echo -e "${CYAN}$interactiveVariable=${YELLOW}$(eval echo \$$interactiveVariable)"
done
    echo -en "${RESET}\nWould you like to run the script with the default parameters? (Y/N): "
    read -r USER_PARAM_CHOICE

case "$USER_PARAM_CHOICE" in
    [Yy])
        echo "Proceeding with default parameters..."
        ;;
    [Nn])
        echo -e "\nEntering interactive setup..."
        echo -e "Configuring script actions. Accepted values: ${CYAN}true${RESET} | ${CYAN}false${RESET}"

        for interactiveVariable in "${variable_names[@]}"; do
            echo -en "\n$interactiveVariable: ${CYAN}"
            read -r input_value && echo -en "${RESET}"
            # Validate input
            while [[ ! "$input_value" =~ ^(true|false)$ ]]; do
                echo -e "${RED}Invalid input. Please enter 'true' or 'false'.${RESET}\n"
                echo -en "$interactiveVariable: ${CYAN}"
                read -r input_value && echo -en "${RESET}"
            done
            eval $(echo -n $interactiveVariable)=$input_value
            echo -e "$interactiveVariable has been set to ${CYAN}${!interactiveVariable}${RESET}."
        done
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# =========================================================================

# Collecting extra information

#if [ "$DO_PREPARE_OS" = "true" ]; then
#fi  

if [ "$DO_CONNECT_NETDATA" = "true" ]; then

    echo -ne "\n${CYAN}DO_CONNECT_NETDATA${RESET} was set to ${YELLOW}true${RESET}. Please provide a cloud claim token: "
    read -r NETDATA_CLOUD_CLAIM_TOKEN

    #while [[ ! "$USER_PROVIDE_CLAIM_TOKEN" =~ ^(Y|y|N|n)$ ]]; do
    #    echo -e "${RED}Invalid input. Please try again.${RESET}"
    #    echo -ne "\n${CYAN}DO_INSTALL_NETDATA${RESET} was set to ${YELLOW}true${RESET}. Would you like to provide a cloud claim token? (Y/N): "
    #    read -r USER_PROVIDE_CLAIM_TOKEN
    #done 

    #case "$USER_PROVIDE_CLAIM_TOKEN" in
    #    [Yy])
    #        echo -ne "Please provide the token: "
    #        read -r NETDATA_CLOUD_CLAIM_TOKEN
    #       ;;
    #    [Nn])
    #      echo "Proceeding without claim token."
    #       ;;
    #esac

fi 

if [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

    if [ "$DO_INSTALL_ENCLAVE" = "false" ]; then
        echo -e "\n${YELLOW}Warning: ${RESET}Enclave configuration will be skipped!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}, but ${CYAN}DO_INSTALL_ENCLAVE${RESET} was set to ${YELLOW}false${RESET}!\n"
        DO_CONFIGURE_ENCLAVE=false
    
    elif [ "$DO_INSTALL_ENCLAVE" = "true" ]; then

        echo -ne "\nPlease provide the type of gateway:\n${CYAN}[0]${RESET} Virtual Machine\n${CYAN}[1]${RESET} Raspberry Pi\n\n... > "
        read -r USER_GATEWAY_TYPE  

        while [[ ! "$USER_GATEWAY_TYPE" =~ ^(0|1)$ ]]; do
            echo -e "${RED}Invalid input. Please try again.${RESET}"
            echo -ne "... > " && read -r USER_GATEWAY_TYPE  
        done 

        case "$USER_GATEWAY_TYPE" in
            [0])
                NewHostname="enclave-gw-vm01"
                ;;
            [1])
                NewHostname="enclave-gw-rp01"
                ;;
        esac



        if [ "$DO_INSTALL_POWERSHELL" =  "true" ]; then
            echo -e "\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}. Extra information is required."

            while true; do
                echo -en "\nPlease provide an Enclave Organisation ID (${CYAN}orgId${RESET}): "
                read -r orgId_input
                orgId=$(echo "$orgId_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' )

                echo -en "Organisation ID set to ${CYAN}$orgId${RESET}. Confirm? (Y/N): " && read -r confirmation_orgId
                if [[ "$confirmation_orgId" =~ ^[Yy]$ ]]; then
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the organisation ID.${RESET}"
                fi
            done

            while true; do
                echo -en "\nPlease provide an Enclave API Key (${CYAN}apiKey${RESET}): "
                read -r apiKey
                #apiKey=$(echo "$apiKey_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' )

                echo -en "API Key set to ${CYAN}$apiKey${RESET}. Confirm? (Y/N): " && read -r confirmation_apiKey

                if [[ "$confirmation_apiKey" =~ ^[Yy]$ ]]; then
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the API Key.${RESET}"
                fi
            done

            while true; do
                echo -en "\nPlease provide a simplified customer name (${CYAN}customerName${RESET}): "
                read -r customerName_input

                customerName=$(echo "$customerName_input" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
                customerName=${customerName:0:20}

                if [ -z "$customerName" ]; then
                    echo -e "${RED}Invalid input! Customer name cannot be empty. Please try again.${RESET}"
                    continue  # Restart the loop
                fi

                echo -en "Customer name: ${CYAN}$customerName${RESET}. Confirm? (Y/N): " && read -r confirmation_customerName

                if [[ "$confirmation_customerName" =~ ^[Yy]$ ]]; then
                    echo -e "\n"
                    break  # Exit loop if user confirms
                else
                    echo -e "${RED}Please re-enter the customer name.${RESET}"
                fi
            done

        else  echo -e "\n${YELLOW}Warning: ${RESET}Enclave configuration will be skipped!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}true${RESET}, but ${CYAN}DO_INSTALL_POWERSHELL${RESET} was set to ${YELLOW}false${RESET}!"
        fi

    else echo "${RED}Error: ${RESET}An unexpected error occured. Please try again."
    fi
fi 

if [ "$DO_AUTODISCOVER_SUBNET" = "true" ]; then

    discoverSubnet="autodiscover"
    discoverSubnetDesc="Autodiscover LAN"

fi

if [ "$DO_AUTODISCOVER_SUBNET" = "false" ]; then

    if [ "$DO_CONFIGURE_ENCLAVE" = "false" ]; then
        echo -e "\n${YELLOW}Warning: ${RESET}Cannot configure gateway subnet!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}false${RESET}."

    elif [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

        # Function to check if the input is in valid IP/subnet format
        validate_gateway_network() {
            local gw_network="$1"
                
            # Regular expression to match an IP address with subnet (CIDR format)
            # Ensures IP ends with .0 (e.g., 192.168.1.0)
            if [[ "$gw_network" =~ ^([0-9]{1,3}\.){3}0/([0-9]{1,2})$ ]]; then
                # Extract the IP and subnet mask
                local ip=$(echo "$gw_network" | cut -d '/' -f1)
                local subnet=$(echo "$gw_network" | cut -d '/' -f2)
                    
                # Validate IP is in the range 0.0.0.0 to 255.255.255.255
                IFS='.' read -r -a ip_parts <<< "$ip"
                for part in "${ip_parts[@]}"; do
                    if (( part < 0 || part > 255 )); then
                        echo -e "${RED}Error: ${RESET}Invalid IP address range!"
                        return 1
                    fi
                done
                    
                # Validate subnet mask is between 0 and 32
                if (( subnet < 0 || subnet > 32 )); then
                    echo -e "${RED}Error: ${RESET}Invalid subnet mask!"
                    return 1
                fi
                
                return 0
            else
                return 1
            fi
        }

        #Choose network and confirm
        while true; do
            echo -en "\nEnter the network that will be routed over the gateway. (e.g. 192.168.1.0/24): "
            read discoverSubnet

            # Validate input, if it's correct, break the loop
            if validate_gateway_network "$discoverSubnet"; then
                echo -en "Network ${CYAN}$discoverSubnet${RESET} is ${GREEN}valid${RESET}!\nProceed with these settings? (Y/N): "
                read -r confirmation_discoverSubnet
                    if [[ "$confirmation_discoverSubnet" =~ ^[Yy]$ ]]; then
                        break  # Exit loop if user confirms
                    else
                        echo -e "${YELLOW}Warning: ${RESET}Please re-enter the network."
                    fi
            else   
                echo -e "${YELLOW}Warning: ${RESET}Invalid format. Please enter the IP in ${CYAN}xxx.xxx.xxx.0/xx${RESET} format."
            fi
        done 

        #Choose description and confirm
        while true; do
            echo -en "\nSet a description for the network ${CYAN}$discoverSubnet${RESET}: "
            read discoverSubnetDesc

                echo -en "Description will be set to: ${CYAN}$discoverSubnetDesc${RESET}. Confirm? (Y/N): "
                read -r confirmation_discoverSubnetDesc
                    if [[ "$confirmation_discoverSubnetDesc" =~ ^[Yy]$ ]]; then
                        break  # Exit loop if user confirms
                    else
                        echo -e "${YELLOW}Warning: ${RESET}Please re-enter the description."
                    fi
        done 



    else echo "${RED}Error: ${RESET}An unexpected error occured. Please try again."
    fi
fi

if [ "$DO_RESTRICT_SUBNET" = "false" ]; then

    restrictedSubnet="none"
    restrictedSubnetDesc="Set automatically through API."

fi

if [ "$DO_RESTRICT_SUBNET" = "true" ]; then

    if [ "$DO_CONFIGURE_ENCLAVE" = "false" ]; then
        echo -e "\n${YELLOW}Warning: ${RESET}Cannot configure restricted routes!\n${CYAN}DO_CONFIGURE_ENCLAVE${RESET} was set to ${YELLOW}false${RESET}."

    elif [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

        # Function to check if the input is in valid IP/subnet format
        validate_ip_subnet() {
            local ip_subnet="$1"
            
            # Regular expression to match an IP address with subnet (CIDR format)
            if [[ "$ip_subnet" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]]; then
                # Extract the IP and subnet mask
                local ip=$(echo "$ip_subnet" | cut -d '/' -f1)
                local subnet=$(echo "$ip_subnet" | cut -d '/' -f2)
                
                # Validate IP is in the range 0.0.0.0 to 255.255.255.255
                IFS='.' read -r -a ip_parts <<< "$ip"
                for part in "${ip_parts[@]}"; do
                    if (( part < 0 || part > 255 )); then
                        echo -e "${RED}Error: ${RESET}Invalid IP address range!"
                        return 1
                    fi
                done
                
                # Validate subnet mask is between 0 and 32
                if (( subnet < 0 || subnet > 32 )); then
                    echo -e "${RED}Error: ${RESET}Invalid subnet mask!"
                    return 1
                fi
                
                return 0
            else
                return 1
            fi
        }

        # Prompt the user for the IP/Subnet in xxx.xxx.xxx.xxx/xx format
        while true; do
            echo -en "\nEnter the IP adress that will be routed exclusively through the gateway.\nYou can always change this through the web-portal. (e.g. 192.168.1.1/24): "
            read restrictedSubnet

            # Validate input, if it's correct, break the loop
            if validate_ip_subnet "$restrictedSubnet"; then
                echo -en "Subnet ${CYAN}$restrictedSubnet${RESET} is ${GREEN}valid${RESET}!\nProceed with these settings? (Y/N): "
                read -r confirmation_restrictedSubnet
                    if [[ "$confirmation_restrictedSubnet" =~ ^[Yy]$ ]]; then
                        break  # Exit loop if user confirms
                    else
                        echo -e "${YELLOW}Warning: ${RESET}Please re-enter the subnet."
                    fi
            else   
                echo -e "${YELLOW}Warning: ${RESET}Invalid format. Please enter the IP in ${CYAN}xxx.xxx.xxx.xxx/xx${RESET} format."
            fi
        done

        while true; do
            echo -en "\nSet a description for the restricted IP ${CYAN}$restrictedSubnet${RESET}: "
            read restrictedSubnetDesc

                echo -en "Description will be set to: ${CYAN}$restrictedSubnetDesc${RESET}. Confirm? (Y/N): "
                read -r confirmation_restrictedSubnetDesc
                    if [[ "$confirmation_restrictedSubnetDesc" =~ ^[Yy]$ ]]; then
                        break  # Exit loop if user confirms
                    else
                        echo -e "${YELLOW}Warning: ${RESET}Please re-enter the description."
                    fi
        done 

    else echo "${RED}Error: ${RESET}An unexpected error occured. Please try again."    
    fi    
fi


# =======================Executing variables==============================

# Prepare OS (update)
if [ "$DO_PREPARE_OS" = "true" ]; then

    echo -e "\nUpdating and installing tooling ...\n${GRAY}"

    # Set noninteractive mode
    export DEBIAN_FRONTEND=noninteractive

    # Preconfigure debconf to automatically restart services without asking
    echo '* libraries/restart-without-asking boolean true' | debconf-set-selections

    apt update && apt upgrade -y
    apt install -y needrestart
    apt install -y gcc make tzdata jq iputils-ping net-tools iperf3 tcpdump telnet unzip wget screen software-properties-common gnupg speedtest-cli openssh-server

    sudo timedatectl set-ntp on
    sudo timedatectl set-timezone UTC

    sudo systemctl enable ssh 
    sudo systemctl start ssh 

    #if [ -n "$NewHostname" ]; then
#
    #    echo "Setting new hostname to $NewHostname ..."
#
    #    sed -i "s/$HOSTNAME/$NewHostname/g" /etc/hosts
    #    sed -i "s/$HOSTNAME/$NewHostname/g" /etc/hostname
    #   hostname $NewHostname
    #fi

    # Set language to Nederlands (Dutch)
    # TODO

    # Set keyboard layout to Belgian
    # TODO
fi

# install enclave
if [ "$DO_INSTALL_ENCLAVE" = "true" ]; then

    echo -e "\n${RESET}Installing Enclave packages...\n${GRAY}"

    sudo rm -f /usr/share/keyrings/enclave.gpg

    
    curl -fsSL https://packages.enclave.io/apt/enclave.stable.gpg | gpg --dearmor -o /usr/share/keyrings/enclave.gpg
    echo -e "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/enclave.gpg] https://packages.enclave.io/apt stable main" | tee /etc/apt/sources.list.d/enclave.stable.list
    
    apt update
    apt install -y enclave

fi

# setup netdata
if [ "$DO_INSTALL_NETDATA" = "true" ]; then

    echo -e "\n${RESET}Installing NetData Agent ...${GRAY}\n"

    if [ "$DO_CONNECT_NETDATA" = "true" ]; then

        apt install -y netdata
        wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && echo "y" | sh /tmp/netdata-kickstart.sh --stable-channel --claim-token  $NETDATA_CLOUD_CLAIM_TOKEN --claim-url https://app.netdata.cloud

    else

        echo -e "${YELLOW}Warning: ${RESET} ${CYAN}DO_CONNECT_NETDATA${RESET} was set to ${YELLOW}false${RESET}. Installing locally only."
        wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && echo "y" | sh /tmp/netdata-kickstart.sh --stable-channel

    fi
fi

# unattended upgrades
if [ "$DO_UNATTENDED_UPGRADES" = "true" ]; then

    echo -e "\n${RESET}Configuring unattended upgrades ...${GRAY}\n"

    # install unattended-upgrades
    apt install -y unattended-upgrades

    # accept the default option here
    dpkg-reconfigure --priority=low unattended-upgrades

    # configure unattended-upgrades
    cat <<-EOF | tee /etc/apt/apt.conf.d/50unattended-upgrades >/dev/null
    // Automatically upgrade packages from these (origin:archive) pairs
    //
    // Note that in Ubuntu security updates may pull in new dependencies
    // from non-security sources (e.g. chromium). By allowing the release
    // pocket these get automatically pulled in.
    Unattended-Upgrade::Allowed-Origins {
            "\${distro_id}:\${distro_codename}";
            "\${distro_id}:\${distro_codename}-security";
            // Extended Security Maintenance; doesn't necessarily exist for
            // every release and this system may not have it installed, but if
            // available, the policy for updates is such that unattended-upgrades
            // should also install from here by default.
            "\${distro_id}ESMApps:\${distro_codename}-apps-security";
            "\${distro_id}ESM:\${distro_codename}-infra-security";
    //      "\${distro_id}:\${distro_codename}-updates";
    //      "\${distro_id}:\${distro_codename}-proposed";
    //      "\${distro_id}:\${distro_codename}-backports";
    };

    // This option controls whether the development release of Ubuntu will be
    // upgraded automatically. Valid values are "true", "false", and "auto".
    Unattended-Upgrade::DevRelease "auto";

    // Never reboot automatically; we'll pull info out of the syslog to know
    // if a restart is required.
    Unattended-Upgrade::Automatic-Reboot "false";

    // Enable logging to syslog. Default is False
    Unattended-Upgrade::SyslogEnable "true";

    // Verbose logging
    // Unattended-Upgrade::Verbose "false";
EOF
fi

if [ "$DO_INSTALL_POWERSHELL" = "true" ]; then

    echo -e "\n${RESET}Installing Powershell for Ubuntu Systems ...${GRAY}\n"
    
    # .sh source 
    # https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.5

    # Prerequisites
    # Update the list of packages
    sudo apt-get update

    # Install pre-requisite packages.
    sudo apt-get install -y wget apt-transport-https software-properties-common

    # Get the version of Ubuntu
    source /etc/os-release

    # Download the Microsoft repository keys
    wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb

    # Register the Microsoft repository keys
    sudo dpkg -i packages-microsoft-prod.deb

    # Delete the Microsoft repository keys file
    rm packages-microsoft-prod.deb

    # Update the list of packages after we added packages.microsoft.com
    sudo apt-get update

    ###################################
    # Install PowerShell
    sudo apt-get install -y powershell
fi



if [ "$DO_CONFIGURE_ENCLAVE" = "true" ]; then

    echo -e "\n${RESET}Starting Enclave configuration${GRAY}"

    ConfigureScript="ConfigureEnclave.ps1"
    
    if ! command -v enclave &> /dev/null; then
        echo "${RED}Error: ${RESET}Enclave is not installed or not found in your PATH!"
        exit 1  # Exit with a non-zero status to indicate failure
    fi

    if ! command -v pwsh &> /dev/null; then
        echo "${RED}Error: ${RESET}PowerShell (pwsh) is not installed or not found in your PATH!"
        exit 1  # Exit with a non-zero status to indicate failure
    fi

    echo -e "${RESET}Loading PowerShell modules ..."

    #First pass through config, before enrolling a gateway system
    if [ -f "./$ConfigureScript" ]; then

        configureEnclave() {
            pwsh -File $ConfigureScript -orgId "$orgId" -apiKey "$apiKey" -customerName "$customerName" -newHostname "$NewHostname" -discoverSubnet "$discoverSubnet" -discoverSubnetDesc "$discoverSubnetDesc" -restrictedSubnet "$restrictedSubnet" -restrictedSubnetDesc "$restrictedSubnetDesc"
        }


        while true; do

            echo -e "\nStarting Powershell module${CYAN} [Preparing Enclave environment] ${GRAY}[1/2]${RESET}\n"

            configureEnclave

            EnrolmentkeyGateway=$(sed -n '1p' /tmp/variables.txt)
            exitCode=$(sed -n '2p' /tmp/variables.txt)

            rm /tmp/variables.txt &>/dev/null

            if [ "$exitCode" -eq 350020 ]; then
                echo -e "\nEnrolling new gateway system..."
                sudo enclave enroll $EnrolmentkeyGateway --force
                
            else
                # If exit code is not 350020, break out of loop (exit successfully)
                break
            fi
        done

        echo -e "\nStarting Powershell module${CYAN} [Enrolling gateway systems] ${GRAY}[2/2]${RESET}\n"
        configureEnclave
    
        echo -e "Enclave configuration complete."
    
    else
        echo -e "${RED}Error: ${RESET}the PowerShell script ${CYAN}$ConfigureScript${RESET} was not found!"
    fi
    
fi










