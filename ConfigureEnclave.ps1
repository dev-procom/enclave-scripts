Param(
    [Parameter(Mandatory=$true)]
    [string]$orgId = "",

    [Parameter(Mandatory=$true)]
    [string]$apiKey = "",
    
    [Parameter(Mandatory=$true)]
    [string]$customerName = "",

    [Parameter(Mandatory=$true)]
    [string]$newHostname,

    [Parameter(Mandatory=$true)]
    [string]$discoverSubnet= "autodiscover",

    [Parameter(Mandatory=$true)]
    [string]$discoverSubnetDesc= "Set automatically through API.",

    [Parameter(Mandatory=$true)]
    [string]$restrictedSubnet= "none",

    [Parameter(Mandatory=$true)]
    [string]$restrictedSubnetDesc= "Set automatically through API."
)

 
$host.UI.RawUI.BackgroundColor = "Black"; Clear-Host #Set black bg
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($apiKey -eq "") {
    $apiKey = $env:ENCLAVE_API_KEY
}

if ($apiKey -eq "") {
    Write-Error "No API key provided; either specify the 'apiKey' argument, or set the ENCLAVE_API_KEY environment variable."
    return;
}

$currentDateTime = Get-Date -Format "yyyy-MM-dd"
$notes = "Auto-provisioned by API on $currentDateTime, do not delete."
$gatewaySystemId = ""

$headers = @{Authorization = "Bearer $apiKey"}
$contentType = "application/json";

# ------------

function Invoke-EnclaveApi {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $false)]
        [object]$Body
    )

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -ContentType $contentType -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10)
        } else {
            return Invoke-RestMethod -ContentType $contentType -Method $Method -Uri $Uri -Headers $headers
        }
    } catch {

        # Check if the exception has a response body
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            $reader.Close()

            # Display the response body only
           
            throw "`nFatal error: Request to $Uri failed!`nException: $($_.Exception.Message)`nDetails:`n$responseBody" 
             

        } else {
            throw "`nFatal error: Request to $Uri failed with error: $($_.Exception.Message). No further details."
        }
    }
}


#region Enrolment Keys

Write-Host "Creating enrolment keys..."

$currentTime = (Get-Date).ToUniversalTime()

$enrolmentKeys = @(
    @{
        description = "Gateway"
        type = "GeneralPurpose"
        approvalMode = "Automatic"
        notes = "$notes"
        usesRemaining = 1
        tags = @(
            "$NewHostname"
        )
        autoExpire = @{
            timeZoneId = "Etc/UTC"
            expiryDateTime = "$($currentTime.AddMinutes(30).ToString("yyyy-MM-ddTHH:mm"))"
            expiryAction = "Delete"
        }
    }
)

foreach ($enrolmentKey in $enrolmentKeys)
{
    $response = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/enrolment-keys?search=$($enrolmentKey.description)"

    if ($response.metadata.total -eq 0)
    {
        # create enrolment key
        Write-Host "  Creating enrolment key: " -ForegroundColor Gray -NoNewline
        Write-Host "$($enrolmentKey.description)" -ForegroundColor Cyan
        $response = Invoke-EnclaveApi -Method Post -Uri "https://api.enclave.io/org/$orgId/enrolment-keys" -Body $enrolmentKey 
    }
    else
    {
        Write-Host "Warning: " -ForegroundColor Yellow -NoNewline
        Write-Host "Skipping creation of enrolment key $($enrolmentKey.description): already exists!" -ForegroundColor Gray
        # update enrolment key
        # edit: no reason to update this key, it's going to automatically expire in one hour
        # $tagRef = $response.items[0].ref
        # Write-Host "  Refreshing enrolment key: $($enrolmentKey.description)"
        # $null = Invoke-EnclaveApi -Method Patch -Uri "https://api.enclave.io/org/$orgId/tags/$tagRef" -Body $tagsPatch
    }
}

#endregion

#region Tags
$tags = @(
    @{
        name = "$($customerName)-medewerkers"
        colour = "#00FF00"
    },
    @{
        name = "$($customerName)-externe-gebruikers"
        colour = "#FF0000"
    },
    @{
        name = "$NewHostname"
        colour = "#000000"
    }
)

Write-Host "Evaluating Tags..."

foreach ($tag in $tags)
{
    $tagsPatch = @{
        tag = "$($tag.name)"
        colour = "$($tag.colour)"
        notes = "$notes"
    }

    $response = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/tags?search=$($tag.name)"

    if ($response.metadata.total -eq 0)
    {
        # create tag
        Write-Host "  Creating tag: " -ForegroundColor Gray -NoNewline
        Write-Host "$($tag.name)" -ForegroundColor Cyan
        $null = Invoke-EnclaveApi -Method Post -Uri "https://api.enclave.io/org/$orgId/tags" -Body $tagsPatch
    }
    else
    {
        # update tag
        $tagRef = $response.items[0].ref
        Write-Host "  Refreshing tag: " -ForegroundColor Gray -NoNewline
        Write-Host "$($tag.name)" -ForegroundColor Cyan
        $null = Invoke-EnclaveApi -Method Patch -Uri "https://api.enclave.io/org/$orgId/tags/$tagRef" -Body $tagsPatch
    }
}
#endregion

#region Trust Requirements

Write-Host "Creating trust requirements..."

$trustRequirements = @(
    @{
        description = "Geographic IP location"
        type = "PublicIp"
        notes = $null
        settings = @{
            conditions = @(
                @{ type = "country"; isBlocked = "false"; value = "BE" }
                @{ type = "country"; isBlocked = "false"; value = "NL" }
                @{ type = "country"; isBlocked = "false"; value = "DE" }
                @{ type = "country"; isBlocked = "false"; value = "LU" }
                @{ type = "country"; isBlocked = "false"; value = "FR" }
                @{ type = "country"; isBlocked = "false"; value = "ES" }
            )
            configuration = @{}
        }
    }
)

foreach ($trustRequirement in $trustRequirements)
{
    $response = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/trust-requirements?search=$($trustRequirement.description)"

    if ($response.metadata.total -eq 0)
    {
        # Create trust requirement
        Write-Host "  Creating trust requirement: " -ForegroundColor Gray -NoNewline
        Write-Host "$($trustRequirement.description)" -ForegroundColor Cyan
        $response = Invoke-EnclaveApi -Method Post -Uri "https://api.enclave.io/org/$orgId/trust-requirements" -Body $trustRequirement
        $trustRequirementId = $response.id
    }
    else
    {
        # Trust requirement already exists, handle if updates are needed
        Write-Host "  Refreshing trust requirement: " -ForegroundColor Gray -NoNewline
        Write-Host "$($trustRequirement.description)" -ForegroundColor Cyan
        $trustRequirementId = $response.items[0].id
        $null = Invoke-EnclaveApi -Method Patch -Uri "https://api.enclave.io/org/$orgId/trust-requirements/$trustRequirementId" -Body $trustRequirement
    }
}
#endregion

#region Systems

Write-Host "Checking enrolled systems..."

# Search for systems enrolled using the Gateway key
$response = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/systems?search=key:Gateway"
$gatewaySystemId = $response.items[0].systemId
$gatewaySystemHostname = $response.items[0].hostname



if ($response.items.Count -gt 0)
{
    
    if ($discoverSubnet -eq 'autodiscover') {
    
    
    $enrolledGateway = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/systems/$gatewaySystemId"
    $discoverSubnet = $enrolledGateway.knownSubnets[0]

    }
    
    # Tag the system and enable it to act as gateway
    $systemPatch = @{
        gatewayRoutes = @(
            @{
                subnet = "$discoverSubnet"
                userEntered = $true
                weight = 0
                name = "$discoverSubnetDesc"
            }
        )
        tags = @("$newHostname")
    }

    Write-Host "  Refreshing system: " -ForegroundColor Gray -NoNewline
    Write-Host "$gatewaySystemId ($gatewaySystemHostname)" -ForegroundColor Cyan
    $null = Invoke-EnclaveApi -Method Patch -Uri "https://api.enclave.io/org/$orgId/systems/$gatewaySystemId" -Body $systemPatch

}

else
{
    $existingKey = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/enrolment-keys?search=Gateway"
 
    Write-Host "Warning: " -ForegroundColor Yellow -NoNewline
    Write-Host "There is currently no new gateway system enrolled." -ForegroundColor Gray
    Write-Host "`nPlease enroll at least one system using the following enrollment key.`nKey: " -NoNewline
    Write-Host "$($existingKey.items.key) " -ForegroundColor Cyan -NoNewline
    Write-Host "($($enrolmentKey.description))" 
    Write-Host "Valid until: " -NoNewline
    $utcString = $existingKey.items.autoExpire.expiryDateTime
    $utcDateTimeOffset = [DateTimeOffset]::Parse($utcString)
    $brusselsTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Romance Standard Time")
    $brusselsDateTime = [System.TimeZoneInfo]::ConvertTime($utcDateTimeOffset, $brusselsTimeZone)
    $brusselsDateTimeString = $brusselsDateTime.ToString("dd/MM/yyyy HH:mm")
    Write-Host "$brusselsDateTimeString`n`n" -ForegroundColor Cyan

    # Set environment variable for use in shell script
    [System.Environment]::SetEnvironmentVariable("EnrolmentkeyGateway", "$($existingKey.items.key)", [System.EnvironmentVariableTarget]::Process)

    exit 350020 #350020 - Specifieke exit code, regelt .sh behavior. (NO_GW_SYS)
}

#endregion

#region Policies

Write-Host "Configuring Policies..."

if ($RestrictedSubnet -eq "none") {
   
    $gatewayAllowedIpRanges = @()
    
} elseif ($RestrictedSubnet) {
    $gatewayAllowedIpRanges = @(
        @{
            ipRange = "$RestrictedSubnet"
            description = "$RestrictedSubnetDesc"
        }
    )
}


$policiesModel = @(
    @{
        type = "Gateway"
        description = "Gateway Access Policy"
        isEnabled = $true
        notes = "$notes"
        senderTags = @()
        acls = @(
            @{
                protocol = "Tcp"
                ports = "3389"
                description = "RDP"
            },
            @{
                protocol = "Tcp"
                ports = "3400"
                description = "RDS"
            },
            @{
                protocol = "Icmp"
                description = "Icmp"
            }
        )
        gateways = @()
        gatewayTrafficDirection = "Exit"
        gatewayAllowedIpRanges = $gatewayAllowedIpRanges
        gatewayPriority = "Balanced"
    }
)

if ($gatewaySystemId)
{
    $policiesModel[0].gateways += @{
        systemId = "$gatewaySystemId"
        routes = @("$discoverSubnet")
    }
}

if ($trustRequirementId)
{
    $policiesModel[0] += @{
        senderTrustRequirements = @($trustRequirementId)
    }
    
}

# Inject first two sender tags to the first policy
$policiesModel[0].senderTags += $tags[0].name, $tags[1].name

$response = Invoke-EnclaveApi -Method Get -Uri "https://api.enclave.io/org/$orgId/policies?include_disabled=true"

foreach ($policyModel in $policiesModel)
{
    # Tight match each returned policy against the model without relying on user configurable values like description
    $allMatchingPolicies = $response.items | Where-Object {
    
        $policyModelSubnets = if ($policyModel.gateways -ne $null -and $policyModel.gateways.Count -gt 0) {
            ($policyModel.gateways | ForEach-Object { $_.routes }) -join ','
        } else {
            $null
        }
        
        $apiSubnets = if ($_.gateways -ne $null -and $_.gateways.Count -gt 0) {
            ($_.gateways | ForEach-Object { $_.routes }) -join ','
        } else {
            $null
        }

        $typeMatch = ($_."type" -eq $policyModel.type)                                                      # match policy type
        $descriptionMatch = ($_."description" -eq $policyModel.description)                                 # match description
        $senderTagsMatch = (($_.senderTags.tag -join ',') -eq ($policyModel.senderTags -join ','))          # match sender tags
        $receiverTagsMatch = (($_.receiverTags.tag -join ',') -eq ($policyModel.receiverTags -join ','))    # match receiver tags

        # conditionally match subnets defined
        if ($policyModelSubnets -ne $null) {
            $subnetMatch = ($apiSubnets -eq $policyModelSubnets)
        } else {
            $subnetMatch = $true
        }

        # combine all match conditions
        $typeMatch -and
        $senderTagsMatch -and
        $receiverTagsMatch -and
        $subnetMatch -or
        $descriptionMatch
    }

    if ($null -ne $allMatchingPolicies)
    {
        $policyCount = @($allMatchingPolicies).Count

        if ($policyCount -ne 1)
        {
            Write-Host "  Multiple ($policyCount) policies found which match the definition for the '$($policyModel.description)' policy. Please review, will not alter existing policy set."

            foreach ($item in $allMatchingPolicies)
            {
                Write-Host "    - #$($item.id): $($item.description)"
            }
            continue
        }

        $matchedPolicy = $allMatchingPolicies[0]

        # update policy
        Write-Host "  Refreshing policy: #$($matchedPolicy.id) " -ForegroundColor Gray -NoNewline
        Write-Host "$($matchedPolicy.description)" -ForegroundColor Cyan
        $null = Invoke-EnclaveApi -Method Patch -Uri "https://api.enclave.io/org/$orgId/policies/$($matchedPolicy.id)" -Body $policyModel
    }
    else 
    {
        # create policy
        Write-Host "  Creating policy: " -ForegroundColor Gray -NoNewline
        Write-Host "$($policyModel.description)" -ForegroundColor Cyan
        $null = Invoke-EnclaveApi -Method Post -Uri "https://api.enclave.io/org/$orgId/policies" -Body $policyModel
    }
}
#endregion

Write-Host "`nConfiguration OK!`n`n----`n`n"
Read-Host "Press Enter to exit"