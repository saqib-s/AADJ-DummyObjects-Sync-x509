 AADJ-DummyObjects-Sync-x509
 Script to pull AADJ devices and create dummy computer objects and synchronize them with certificate hash's
 
 AADJ-DummyObject-Sync - Saqib Sabir - 2022-12-14 

2025-04 Update!! Breaking change, this script was created to work with WindowsAutopilotIntune module version 5.0, the newer version have a breaking change.
This scripts needs to be update to work without the WindowsAutopilotIntune module, as we can gran the autopilot device ids from MSGraph directly.


 Script to connect to AzureAD and pull all Autopilot devcies and create 'dummy' computer objects in specified OU
 and then run certificates hash synch to query all domain CA's and locate certificate hash and add to altSecurityIdentities attribute

 This script has been pulled together from the work of:
 
  1. Andrew Blackburn @ sysmansquad  - https://sysmansquad.com/2021/04/27/working-around-nps-limitations-for-aadj-windows-devices/
     - connecting to Azure AD, synching computer objects to Autopilot devices (only)

  2. tcppapi  - https://github.com/tcppapi/AADx509Sync
     - certificate hash syncing 


  Script requires a enterpise app created in Azure AD with the following api permission single permission (granted for the whole tenant)
  Microsoft Graph ->  DeviceManagementServiceConfig.Read.All  ->  Application ->  Read Microsoft Intune configuration
  Create a client secret in the app and use this to run the script. 

  NOTE: The script in the format below will not remove computer objects in AD that have been deleted from Intune (Autopilot), it 
         will only show what it would delete. Remove -WhatIf once you are comfortable with this workflow and have verified the remove 
         operations are only performed in the OU you specified


 Run format: 
 .\AADJ-DummyObject-Sync.ps1 -TenantId "your-tenant-id-here" -ClientId "your-app-id-here" -ClientSecret "your-app-secret-here" -NameMap
 
