# AADJ-DummyObject-Sync - Saqib Sabir - 2022-12-14 
#
# Script to connect to AzureAD and pull all Autopilot devcies and create 'dummy' computer objects in specified OU
# and then run certificates hash synch to query all domain CA's and locate certificate hash and add to altSecurityIdentities attribute
#
# This script has been pulled together from the work of:
# 
#  1. Andrew Blackburn @ sysmansquad  - https://sysmansquad.com/2021/04/27/working-around-nps-limitations-for-aadj-windows-devices/
#     - connecting to Azure AD, synching computer objects to Autopilot devices (only)
#
#  2. tcppapi  - https://github.com/tcppapi/AADx509Sync
#     - certificate hash syncing 
#
#
#  Script requires a enterpise app created in Azure AD with the following api permission single permission (granted for the whole tenant)
#  Microsoft Graph ->  DeviceManagementServiceConfig.Read.All  ->  Application ->  Read Microsoft Intune configuration
#  Create a client secret in the app and use this to run the script. 
#
#  NOTE: The script in the format below will not remove computer objects in AD that have been deleted from Intune (Autopilot), it 
#         will only show what it would delete. Remove -WhatIf once you are comfortable with this workflow and have verified the remove 
#         operations are only performed in the OU you specified
#
#
# Run format: 
# .\AADJ-DummyObject-Sync.ps1 -TenantId "your-tenant-id-here" -ClientId "your-app-id-here" -ClientSecret "your-app-secret-here" -NameMap
# 

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory=$True)] [String] $TenantId = "",
    [Parameter(Mandatory=$True)] [String] $ClientId = "",
    [Parameter(Mandatory=$True)] [String] $ClientSecret = "",
    [Parameter(Mandatory=$False)] [Switch] $NameMap
)


# Set the OU for computer object creation
$orgUnit = "OU=AAD-DummyComputers,OU=Domain Users,DC=mytest-domain,DC=net"

# Set the certificate path for name mapping - pull from a client certificate under 'issuer' and match the format below
# NOT REQUIRED -  if you using secure binding SHA hash sync 
$certPath = "X509:<I>DC=net,DC=mytest-domian,CN=RootCA<S>CN="


# Get NuGet
Get-PackageProvider -Name "NuGet" -Force | Out-Null

# Get WindowsAutopilotIntune module (and dependencies)
$module = Import-Module WindowsAutopilotIntune -PassThru -ErrorAction Ignore
if (-not $module) {
    Write-Output "Installing module WindowsAutopilotIntune"
    Install-Module WindowsAutopilotIntune -Force
}
Import-Module WindowsAutopilotIntune -Scope Global

# Get PSPKI module (and dependencies)
$module = Import-Module PSPKI -PassThru -ErrorAction Ignore
if (-not $module) {
    Write-Output "Installing module PSPKI"
    Install-Module PSPKI -Force
}
Import-Module PSPKI -Scope Global
   
# Import Active Directory Module - error if not installed
# Needs to be installed manually via Server Manager if missing
# or run following PS command  "Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online" 
try{
    Import-Module ActiveDirectory
    $Modules = Get-Module
    if(!($Modules.Name -Contains "ActiveDirectory") ) {
        Write-Error "<SETUP> Error detecting required modules after import - ensure 'ActiveDirectory' module is installed on your system"
    }
}
catch{  
    Write-Error "$($_.Exception.Message)" 
    Write-Error "<SETUP> Error importing required modules - ensure 'ActiveDirectory' and 'PSPKI' modules are installed on your system"
}


# Connect to MSGraph with application credentials
Connect-MSGraphApp -Tenant $TenantId -AppId $ClientId -AppSecret $ClientSecret

# Pull latest Autopilot device information
$AutopilotDevices = Get-AutopilotDevice | Select-Object azureActiveDirectoryDeviceId


# Create new Autopilot device objects in AD while skipping already existing computer objects
foreach ($Device in $AutopilotDevices) {
    if (Get-ADComputer -Filter "Name -eq ""$($Device.azureActiveDirectoryDeviceId)""" -SearchBase $orgUnit -ErrorAction SilentlyContinue) {
        Write-Output "Skipping $($Device.azureActiveDirectoryDeviceId) because it already exists. "
    } else {
        # Create new AD computer object
        try {
            New-ADComputer -Name "$($Device.azureActiveDirectoryDeviceId)" -SAMAccountName "$($Device.azureActiveDirectoryDeviceId.Substring(0,15))`$" -ServicePrincipalNames "HOST/$($Device.azureActiveDirectoryDeviceId)" -Path $orgUnit 
            Write-Output "Computer object created. ($($Device.azureActiveDirectoryDeviceId))"
        } catch {
            Write-Error "Error. Skipping computer object creation."
        }
        
        <#
        #  Perform WEAK name mapping - commented out as we don't want weak mapping
        try {
            Set-ADComputer -Identity "$($Device.azureActiveDirectoryDeviceId.Substring(0,15))" -Add @{'altSecurityIdentities'="$($certPath)$($Device.azureActiveDirectoryDeviceId)"}
            Write-Output "Name mapping for computer object done. ($($certPath)$($Device.azureActiveDirectoryDeviceId))"
        } catch {
            Write-Error "Error. Skipping name mapping."
        }
        #>
    }
}

# Reverse the process and remove any dummmy computer objects in AD that are no longer in Autopilot
$DummyDevices = Get-ADComputer -Filter * -SearchBase $orgUnit | Select-Object Name, SAMAccountName
foreach ($DummyDevice in $DummyDevices) {
    if ($AutopilotDevices.azureActiveDirectoryDeviceId -contains $DummyDevice.Name) {
         Write-Output "$($DummyDevice.Name) exists in Autopilot."
    } else {
        Write-Output "$($DummyDevice.Name) does not exist in Autopilot. Removing..."
        Remove-ADComputer -Identity $DummyDevice.SAMAccountName -Confirm:$False -WhatIf
        ## Remove -WhatIf once you are comfortable with this workflow and have verified the remove operations are only performed in the OU you specified
    }
   
}

##################################################################################################################################################################

Write-Output "<CERT> Starting certificate hash sync..."
Clear-Variable IssuedCerts -ErrorAction SilentlyContinue
try{
    foreach($CAHost in (Get-CertificationAuthority).ComputerName){
        Write-Output "<CERT> Getting all issued certs from '$CAHost'..."
        $IssuedRaw = Get-IssuedRequest -CertificationAuthority $CAHost -Property RequestID,ConfigString,CommonName,CertificateHash,RawCertificate
        $IssuedCerts += $IssuedRaw | Select-Object -Property RequestID,ConfigString,CommonName,CertificateHash,@{
            name='SANPrincipalName';
            expression={
                ($(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,[Convert]::FromBase64String($_.RawCertificate))).Extensions | `
                ? {$_.Oid.FriendlyName -eq "Subject Alternative Name"}).Format(0) -match "^(.*)(Principal Name=)([^,]*)(,?)(.*)$" | Out-Null;
                if($matches.GetEnumerator() |? Value -eq "Principal Name=") {
                    $n = ($matches.GetEnumerator() |? Value -eq "Principal Name=").Name +1;
                    $matches[$n]
                }
            }
        }
    }
}
catch{  Write-Output "Error - $($_.Exception.Message)" 
        Write-Output "<CERT> Error getting issued certificates from ADCS servers"
}
try { 
    Write-Output "<CERT> Getting AD objects..."
    $AADx509Devs = Get-ADComputer -Filter '(objectClass -eq "computer")' -SearchBase $orgUnit -Property Name,altSecurityIdentities
}
catch{  
    Write-Output "$($_.Exception.Message)" 
    Write-Output  "<CERT> Error getting AADx509 computers for hash sync"
}
foreach($dev in $AADx509Devs){
    $certs = $IssuedCerts |? SANPrincipalName -Like "host/$($dev.Name)"
    if($certs) {
        $a = @()
        $b = @()
        foreach($cert in $certs){
            $hash = ($cert.CertificateHash) -Replace '\s',''
            $a += "X509:<SHA1-PUKEY>$hash"
            $b += "($($cert.ConfigString)-$($cert.RequestID))$hash"
        }
        [Array]::Reverse($a)
        try{
            if(!((-Join $dev.altSecurityIdentities) -eq (-Join $a))){
                [Array]::Reverse($a)
                $ht = @{"altSecurityIdentities"=$a}
                Write-Output "<CERT> Mapping AADx509 computer '$($dev.Name)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
                Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($dev.Name)')" | Set-ADComputer -Add $ht
            }
        }
        catch{  
            Write-Output "$($_.Exception.Message)" 
            Write-Output "<CERT> Error mapping AADx509 computer object '$($dev.Name)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
        }
    }
}

Write-Output "<CERT> Certificate hash sync completed"




