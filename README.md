# How to use these scripts

The scripts in this repository are designed to aid the deployment of [enclave.io](https://enclave.io) agents.

## prepare-host.sh

You will need a Linux OS with SSH access to run this script.

1. Clone the repo (`git clone https://github.com/dev-procom/enclave-scripts`)

1. Mark the `prepare-host.sh` as executable (`chmod +x prepare-host.sh`)

1. Customise the variables at the top of the file as appropriate, and then run `./prepare-host.sh`

    1. `DO_PREPARE_OS`: Controls whether the script configures OS settings (e.g., updating packages). Set to true if system setup is needed, especially for fresh installations.

    1. `DO_INSTALL_ENCLAVE`: Manages the installation of Enclave (a secure overlay network). Enable this if Enclave is required on the host.

    1. `DO_INSTALL_NETDATA`: Enables Netdata installation, useful for real-time performance monitoring. Set this to true when monitoring the host system.

    1. `DO_RESTRICT_ROOT`: Controls restrictions on root SSH access for security purposes. Turn on to disable direct root logins, improving system protection.

    1. `DO_UNATTENDED_UPGRADES`: Enables automatic updates to keep the OS secure and up to date. Enable this for systems needing continuous security patching.

    ---

    Optional variables:

    - `NEW_HOSTNAME`: Specifies the new hostname for the system. Adjust this to reflect the system’s identity or role in the network.

    - `SSH_USERNAME`: Defines the SSH user created during setup. Change it to the desired username for secure, non-root system access.

    - `SSH_PASSWD`: Sets the password for the SSH user. Only adjust this if password-based SSH access is necessary (prefer SSH keys instead). If you set this variable, don't set `SSH_KEY`.

    - `SSH_KEY`: Provides the public SSH key for the user, enabling key-based login. Set this for secure access without relying on passwords. If you set this variable, don't set `SSH_PASSWD`.

    - `NETDATA_CLOUD_CLAIM_TOKEN`: Used for integrating the system with Netdata Cloud. Configure this when connecting the system to a centralized Cloud account rather than installing Netdata as a standalone deployment.`

## configure-policy.ps1

You will need, at a minimum an [enclave.io](https://enclave.io) API key, organisation ID, customer name and a PowerShell interpreter to run this script. To run the script from the PowerShell command prompt, use the following syntax:

```
.\configure-policy.ps1 -orgId "yourOrgId" -apiKey "yourApiKey" -customerName "customerName"
```

Parameters Explained:

`-orgId:` The Enclave organisation tenant ID.

`-apiKey:` Your API key / personal access token. If omitted, the script collects this value from the `ENCLAVE_API_KEY` environment variable where present.

`-customerName:` The customer's name to be used as a `tag-prefix`. Ensure this name is compliant with tag formatting rules (e.g. lower-case, hyphen-separated).

---

You should run this script once to create an enrolment key for a gateway system, and then again once the gateway system has been enrolled to enable the script to configure that new system to act as a gateway and attach it to policy.

This script is idempotent, meaning it can be safely run multiple times without causing unintended changes if the state is already configured. For example, resources will not be duplicated, and pre-existing configurations are preserved (unless updates are necessary).