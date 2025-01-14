#!/bin/bash

set -euo pipefail

# =========================================================================

# configure script actions
DO_PREPARE_OS=true
DO_INSTALL_ENCLAVE=true
DO_INSTALL_NETDATA=true
DO_RESTRICT_ROOT=true
DO_UNATTENDED_UPGRADES=true

# variables
NEW_HOSTNAME=""
SSH_USERNAME="enclave"
SSH_PASSWD=""
SSH_KEY=""
NETDATA_CLOUD_CLAIM_TOKEN=""

# =========================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# update
if [ "$DO_PREPARE_OS" = "true" ]; then

    echo "Updating and installing tooling ..."

    # Set noninteractive mode
    export DEBIAN_FRONTEND=noninteractive

    # Preconfigure debconf to automatically restart services without asking
    echo '* libraries/restart-without-asking boolean true' | debconf-set-selections

    apt update && apt upgrade -y
    apt DEBIAN_FRONTEND=noninteractive install -y needrestart
    apt DEBIAN_FRONTEND=noninteractive install -y gcc make tzdata jq iputils-ping net-tools iperf3 tcpdump telnet unzip wget screen software-properties-common gnupg speedtest-cli openssh-server

    sudo timedatectl set-ntp on
    sudo timedatectl set-timezone UTC

    sudo systemctl enable ssh
    sudo systemctl start ssh

    if [ -n "$NEW_HOSTNAME" ]; then

        echo "Setting new hostname to $NEW_HOSTNAME ..."

        sed -i "s/$HOSTNAME/$NEW_HOSTNAME/g" /etc/hosts
        sed -i "s/$HOSTNAME/$NEW_HOSTNAME/g" /etc/hostname
        hostname $NEW_HOSTNAME
    fi

    # Set language to Nederlands (Dutch)
    # TODO

    # Set keyboard layout to Belgian
    # TODO
fi

# install enclave
if [ "$DO_INSTALL_ENCLAVE" = "true" ]; then

    curl -fsSL https://packages.enclave.io/apt/enclave.stable.gpg | gpg --dearmor -o /usr/share/keyrings/enclave.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/enclave.gpg] https://packages.enclave.io/apt stable main" | tee /etc/apt/sources.list.d/enclave.stable.list
    apt update

    apt install enclave

fi

# setup netdata
if [ "$DO_INSTALL_NETDATA" = "true" ]; then

    echo "Installing NetData Agent ..."

    if [ -z "$NETDATA_CLOUD_CLAIM_TOKEN" ]; then

        echo "Info: Cannot connect to the Netdata Cloud without a NETDATA_CLOUD_CLAIM_TOKEN. Installing locally only."
        wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/netdata-kickstart.sh --stable-channel

    else

        apt install -y netdata
        wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && sh /tmp/netdata-kickstart.sh --stable-channel --claim-token  $NETDATA_CLOUD_CLAIM_TOKEN --claim-url https://app.netdata.cloud

    fi

fi

# restrict root access
if [ "$DO_RESTRICT_ROOT" = "true" ]; then

    if [ -z "$SSH_USERNAME" ]; then
        echo "Error: SSH_USERNAME is required."
        exit 1
    fi

    if [ -n "$SSH_KEY" ]; then
        # Use SSH key for authentication
        echo "Restricting root access with SSH key..."

        useradd -m -d /home/$SSH_USERNAME -s /bin/bash $SSH_USERNAME

        mkdir -p /home/$SSH_USERNAME/.ssh

        echo "$SSH_KEY" | tee /home/$SSH_USERNAME/.ssh/authorized_keys >/dev/null

        chown -R $SSH_USERNAME:$SSH_USERNAME /home/$SSH_USERNAME/.ssh
        chmod 700 /home/$SSH_USERNAME/.ssh
        chmod 600 /home/$SSH_USERNAME/.ssh/authorized_keys
        usermod -a -G $SSH_USERNAME

        echo "$SSH_USERNAME ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/10-$SSH_USERNAME-users > /dev/null

    elif [ -n "$SSH_PASSWD" ]; then

        # Use password for authentication
        echo "Restricting root access with password..."

        useradd -m -d /home/$SSH_USERNAME -s /bin/bash $SSH_USERNAME
        echo "$SSH_USERNAME:$SSH_PASSWD" | chpasswd

        echo "$SSH_USERNAME ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/10-$SSH_USERNAME-users > /dev/null

    else

        echo "Error: Either SSH_KEY or SSH_PASSWD must be defined to restrict root access."
        exit 1

    fi

    # Disable root SSH login
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

    # Restart SSH service
    systemctl restart sshd

fi

# configure unattended-upgrades
if [ "$DO_UNATTENDED_UPGRADES" = "true" ]; then

    echo "Configuring unattended upgrades ..."

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
