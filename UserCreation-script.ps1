<# 
.DESCRIPTION
 
Created on: 05/04/2020 11:00
Modified on: 02/16/2021 15:33
Created by: Ruben Ruiz
Filename: User-Creation.ps1 
 
.SYNOPSIS
This script provides a standard on-boarding method for user account creation. 
  
The script does the following; 
1. Creating O365 Mailbox and Active Directory for user
2. Setting Active Directory user fields  
3. Adding Active Directory Security Groups
4. Active Directory sync
 
.NOTES 
 
Here are all the bases covered in this script:
1. All user accounts created/re-activated in this script are fed by a csv file supplied from Workday
2. Any user that needs a new user account and mailbox will be created under the XYZAM domain
3. This script will apply different security groups based on Full-time/Part-time status
4. Any condition that does not satisfy rule 4, the user will then inherit a base set of established security groups essential for ALL XYZ employees.
5. If a user is a rehire, the script will look to see if an account already exists in Active Directory for the supplied Workday username,
    If the account is already enabled, nothing will happen and the user will be skipped.
    If the user is disabled, it will re-enable the user.
    If the user exists in the Central domain, it will move the account to the XYZAM domain
6. All new user creation accounts and rehires (that are not already enabled) will be moved here: XYZAM.XYZ.org/XYZ beta/Departments
7. If the user account already exists, the script will not run for this user and an email will be sent to ruben.ruiz@XYZ.com from servicedesk@XYZ.com informing them about this case
8. After all user accounts are processed, the script will kick off an Azure AD sync cycle so that the creation can be processed promptly.
 
#>
$LogFileName = Get-Date -Format 'yyyyMMdd_HHmmss'
Start-Transcript -path "C:\scripts\Workday-User-Creation\Logs\$($LogFileName).txt" -append

#######################################################################################################
############################################## Functions ##############################################
function Set-FTorPTuser {
    Set-ADUserFields
    if ($empStatus -eq "Full time") { 
        Set-FTGenericSecurityGroups
    }
    else {
        Set-PTGenericSecurityGroups
    } 
}

function Get-UserDetails {
    Write-Host "Gathering $($sam) user account details prior to onboarding"
    try {
        $Script:userProps = Get-ADUser -Identity $sam -Server $alphaDC -Properties * -ErrorAction Stop
    }
    catch {
        $Script:userProps = Get-ADUser -Identity $sam -Server $betaDC -Properties *
    }
}

function Write-GoodEmailServiceDesk {
    Write-Host "$($name) account successfully created - Notifying Service Desk via Email" -ForegroundColor Green
    $msg = new-object Net.Mail.MailMessage 
    $smtp = new-object Net.Mail.SmtpClient("smtp.XYZ.com")
    $msg.From = "ServiceDesk@XYZ.com"
    $msg.To.Add("XYZ-sd@XYZ.com")
    $msg.subject = "Account successfully created for $($name)" 
    $msg.body = "This email is to inform you that the account for $($name) has been successfully created in the onboarding script. Please add O365 Distribution groups for the user in about 30 min - 1hr." 
    $smtp.Send($msg)
}

function Write-ErrorReportEmailServiceDesk ($errorVar) {
    Write-Host "$($name) account will NOT be created - errors found - Notifying Service Desk via Email" -ForegroundColor Red
    $msg = new-object Net.Mail.MailMessage 
    $smtp = new-object Net.Mail.SmtpClient("smtp.XYZ.com")
    $msg.From = "ServiceDesk@XYZ.com"
    $msg.To.Add("XYZ-sd@XYZ.com")
    $msg.To.Add("ServiceDesk@XYZ.com")
    $msg.subject = "Error creating new hire account for $($name) - Please Review" 
    $msg.body = "This email is to inform you that the account for $($name) was not created in the onboarding script. Reason: `n $errorVar"
    $smtp.Send($msg)
}

function New-UserMailbox {
    write-host "Step 1. Creating O365 Mailbox and Active Directory" -ForegroundColor Yellow
    try {
        New-RemoteMailbox -Name $name -Password (ConvertTo-SecureString -String "R@nD0mP@$$w0rD" -AsPlainText -Force) -UserPrincipalName $userUPN -Alias $alias -DisplayName $displayName -FirstName $firstName -LastName $lastName -OnPremisesOrganizationalUnit $OU -ResetPasswordOnNextLogon $true -SamAccountName $sam -ErrorAction Stop
        Write-GoodEmailServiceDesk
        Start-Sleep -Seconds 30
        $userDN = (Get-ADUser -Filter "sAMAccountName -eq '$sam'" -Server $alphaDC).distinguishedName
        Get-UserDetails
        Set-FTorPTuser
    } catch [System.Management.Automation.RemoteException] { 
        Write-ErrorReportEmailServiceDesk($error[0])
        return
    } catch {
        Write-ErrorReportEmailServiceDesk($error[0])
        return
    }
}

function Reactivate-UserMailbox {
    try {
        Set-ADUser -Identity $userDN -Server $userDC -Enabled $True -ErrorAction Stop
        Set-ADAccountPassword -Identity $userDN -Server $userDC -Reset -NewPassword (ConvertTo-SecureString -String "R@nD0mP@$$w0rD" -AsPlainText -Force)
        Get-UserDetails
        Write-GoodEmailServiceDesk
        $rehireSuccess = $true
    } catch {
        Write-ErrorReportEmailServiceDesk($error[0])
    }

    if ($rehireSuccess -eq $true) {
        Set-FTorPTuser
        Move-OU
        Enable-GAL
        Enable-ExchangeMailboxSettings
        Disable-ExchangeAutoResponse
    }
}

function Set-ADUserFields {
    write-host "Step 2. Setting Active Directory user fields" -ForegroundColor Yellow

    try {
        Set-ADUser -Identity $sam -Server $alphaDC -Company $company -Department $department -Description $title -Title $title -Office $location -ErrorAction Stop
    } catch {
        Set-ADUser -Identity $sam -Server $betaDC -Company $company -Department $department -Description $title -Title $title -Office $location
    }

    #### Loop to attempt to set AD Manager by Workday provided username or possibly display Name for either alpha or beta manager
    $count = 0
    $success = $false
    do {
        try {
            Write-Host "Attempting to set Active Directory fields"
            Set-ADUser -Identity $sam -Server $alphaDC -Manager ((Get-ADUser -Identity $managerUsername -Server $alphaDC -ErrorAction Stop).distinguishedName) -ErrorAction Stop
            Write-Host "Successfully set Active Directory fields" -ForegroundColor Green
            $success = $true
        }
        catch {
            try {
                Write-Host "Attempting to set Active Directory fields"
                Set-ADObject -Identity $userProps.distinguishedName -Add @{manager = ((Get-ADUser -Identity $managerUsername -Server $betaDC -ErrorAction Stop).distinguishedName) } -ErrorAction Stop
                $success = $true
                Write-Host "Successfully set Active Directory fields" -ForegroundColor Green  
            }
            Catch {
                try {
                    Write-Host "Attempting to set Active Directory fields"
                    Set-ADObject -Identity $userProps.distinguishedName -Add @{manager = ((Get-ADUser -Filter "Name -eq '$managerDisplayName'" -Server $alphaDC -ErrorAction Stop).distinguishedName) } -ErrorAction Stop
                    Write-Host "Successfully set Active Directory fields" -ForegroundColor Green
                    $success = $true
                }
                Catch {
                    Try {
                        Write-Host "Attempting to set Active Directory fields"
                        Set-ADObject -Identity $userProps.distinguishedName -Add @{manager = ((Get-ADUser -Filter "Name -eq '$managerDisplayName'" -Server $betaDC -ErrorAction Stop).distinguishedName) } -ErrorAction Stop
                        $success = $true
                        Write-Host "Successfully set Active Directory fields" -ForegroundColor Green 
                    }
                    Catch {
                        Try {
                            Write-Host "Attempting to set Active Directory fields"
                            Set-ADObject -Identity $userProps.distinguishedName -Add @{manager = ((Get-ADUser -Filter "Mail -eq '$managerEmail'" -Server $alphaDC -ErrorAction Stop).distinguishedName) } -ErrorAction Stop
                            $success = $true
                            Write-Host "Successfully set Active Directory fields" -ForegroundColor Green 
                        }
                        Catch {
                            Try {
                                Write-Host "Attempting to set Active Directory fields"
                                Set-ADObject -Identity $userProps.distinguishedName -Add @{manager = ((Get-ADUser -Filter "Mail -eq '$managerEmail'" -Server $betaDC -ErrorAction Stop).distinguishedName) } -ErrorAction Stop
                                $success = $true
                                Write-Host "Successfully set Active Directory fields" -ForegroundColor Green 
                            }
                            Catch {
                                Write-Host "Unable to Set Active Directory fields, trying again" -ForegroundColor Red
                                return
                            }
                        }
                    }
                }
            }
        }
        Start-Sleep -Seconds 5 
        $count ++
    } until ($count -eq 5 -or $success)
}

function Set-PTGenericSecurityGroups {
    # Adding AD Security Groups for user
    write-host "Step 3. Adding Active Directory Security Groups" -ForegroundColor Yellow 
    $alphaADGroups = "XYZAM - GSuite", "XYZAM - Office 365 F1 Users", "XYZAM - Slack Users", "XYZAM - Okta Office 365", "XYZAM - Workspace One"
    for ($i = 0; $i -lt $alphaADGroups.length; $i++) {
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf $alphaADGroups[$i]
    }
    $orgADGroups = @("XYZ - VPN Users")
    for ($i = 0; $i -lt $orgADGroups.length; $i++) {
        $group = Get-ADGroup $orgADGroups[$i] -Server $orgDC
        Set-ADObject -identity $group.ObjectGUID -Add @{member = $userProps.distinguishedName } -server $orgDC
    }
    if ($department -eq 'Data Operations') {
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf 'XYZAM - Stringer-Write'
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf 'XYZAM - Stringer-Read'
    }
}

function Set-FTGenericSecurityGroups {
    # Adding AD Security Groups for user
    write-host "Step 3. Adding Active Directory Security Groups" -ForegroundColor Yellow 
    $alphaADGroups = "XYZAM - GSuite", "XYZAM - Office 365 Users", "XYZAM - Slack Users", "XYZAM - Okta Office 365", "XYZAM-OKTA", "XYZAM - Workspace One"
    for ($i = 0; $i -lt $alphaADGroups.length; $i++) {
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf $alphaADGroups[$i]
    }
    $orgADGroups = @("XYZ - VPN Users")
    for ($i = 0; $i -lt $orgADGroups.length; $i++) {
        $group = Get-ADGroup $orgADGroups[$i] -Server $orgDC
        Set-ADObject -identity $group.ObjectGUID -Add @{member = $userProps.distinguishedName } -server $orgDC
    }
    if ($department -eq 'Data Operations') {
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf 'XYZAM - Stringer-Write'
        Add-ADPrincipalGroupMembership -Identity $sam -MemberOf 'XYZAM - Stringer-Read'
    }
}

function Get-ManagerOU {
    try {
        $Script:OU = Get-ADUser -Identity $managerUsername -Properties * -Server $alphaDC -ErrorAction Stop | select distinguishedName | ForEach-Object { $_ -replace '^.+?(?<!\\),', '' -replace '}', '' }
    } catch {
            try {
                $Script:OU = Get-ADUser -Identity ((Get-ADUser -Filter "Name -eq '$managerDisplayName'" -Server $alphaDC -ErrorAction Stop).distinguishedName) -ErrorAction Stop | select distinguishedName | ForEach-Object { $_ -replace '^.+?(?<!\\),', '' -replace '}', '' }
            } catch {
                $Script:OU = "OU=Departments,OU=XYZ beta,DC=XYZAM,DC=XYZ,DC=org"
            }
    }
}

function Move-OU {
    try {
        Move-ADObject -Identity ((Get-ADUser -Identity $sam -Server $alphaDC -ErrorAction Stop).distinguishedName) -ErrorAction Stop -TargetPath $OU
    } catch {
        # Moves beta AD user from Central domain to OU in XYZAM (could be manager's OU or general OU specified in Get-ManagerOU)
        Move-ADObject -Identity (Get-ADUser -Identity $betaUser -Server $betaDC) -TargetPath $OU -TargetServer $alphaDC
    }
}

function Start-AzureADSync {
    $azurePassword = Get-Content "\\XYZam.XYZ.org\Scripts\ADSync\passwords\password.txt" | ConvertTo-SecureString -Key (Get-Content "\\XYZam.XYZ.org\Scripts\ADSync\passwords\aes.key")
    $azureCred = New-Object System.Management.Automation.PSCredential ("XYZ-Org\azure_svcAccount", $azurePassword)
    $azureSession = New-PSSession XYZ-ADServer.XYZ.org -Credential $azureCred
    Invoke-Command -Session $azureSession -ScriptBlock { cd "C:\Users\azuresync"; Start-ADSyncSyncCycle -PolicyType delta } -ErrorAction Stop
    Remove-PSSession $azureSession
    Write-Host "Active Directory sucessfully synced" -BackgroundColor Green -ForegroundColor black
}

function Enable-GAL {
    Set-ADUser -Identity $sam -Replace @{msExchHideFromAddressLists = $False }
}

function Enable-ExchangeMailboxSettings {
    try {
        Set-CasMailbox -Identity $Script:userProps.mail -OWAEnabled $true -POPEnabled $true -ImapEnabled $true -ActiveSyncEnabled $true -ErrorAction Stop
    } catch {
        Set-CasMailbox -Identity $Script:userProps.mail -OWAEnabled $true -POPEnabled $true -ActiveSyncEnabled $true
    }
}

function Disable-ExchangeAutoResponse {
    Set-MailboxAutoReplyConfiguration -Identity $Script:userProps.mail -AutoReplyState disabled
}

function Connect-O365Exchange {
    $365ADMpassword = Get-Content "\\XYZam.XYZ.org\userdatafiles\HELPDESK\Scripts\UserCreation\passwords\o365_AES_PASSWORD_FILE.txt" | ConvertTo-SecureString -Key (Get-Content "\\XYZam.XYZ.org\Scripts\UserCreation\o365_AES_KEY_FILE.key")
    $365ADMcredential = New-Object System.Management.Automation.PSCredential ("o365_svcAcct@XYZSymplSystems.onmicrosoft.com", $365ADMpassword)
    $Script:365session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $365ADMcredential -Authentication Basic -AllowRedirection -SessionOption $script:so
    Import-PSSession $Script:365session -AllowClobber -DisableNameChecking
}

function Connect-onPremExchange {
    $OrgADMpassword = Get-Content "\\XYZam.XYZ.org\userdatafiles\HELPDESK\Scripts\UserCreation\passwords\AES_PASSWORD_FILE.txt" | ConvertTo-SecureString -Key (Get-Content "\\XYZam.XYZ.org\Scripts\UserCreation\AES_KEY_FILE.key")
    $OrgADMcredential = New-Object System.Management.Automation.PSCredential ("XYZ-Org\svc_newhire", $OrgADMpassword)
    $Script:onPremExch = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://alpha-mb101.XYZam.XYZ.org/PowerShell/ -Authentication Kerberos -Credential $OrgADMcredential -SessionOption $script:so
    Import-PSSession -Session $Script:onPremExch -AllowClobber -DisableNameChecking
}

#######################################################################################################
############################################## Script #################################################

$alphaDC = "alpha-dc1.XYZam.XYZ.org"
$betaDC = "beta-dc1.central.XYZ.org"
$orgDC = "org-dc1.XYZ.org"
$userDC = $null

# Connect to On-Prem Exchange
$so = New-PSSessionOption -IdleTimeout 600000
$onPremExch = $null
Connect-onPremExchange

# Connect to O365 Exchange
$365session = $null
Connect-O365Exchange

# Looping through new hire accounts in CSV
Get-Content -Path ("C:\scripts\Workday-User-Creation\Workday-NewHireReports\" + ( (gci -path C:\scripts\Workday-User-Creation\Workday-NewHireReports\ | sort LastWriteTime | select -last 1 | select Name -ExpandProperty Name)) ) | ConvertFrom-Csv | ForEach-Object {

    # Gathering user details from CSV 
    $firstName = $_.preferredFirstName
    $lastName = $_.lastName
    $alias = $_.userName
    $sam = $_.userName
    $displayName = $_.lastName + ", " + $_.preferredFirstName
    $name = $displayName
    $userUPN = $_.userName + "@XYZ.com"
    $userProps = $null
    $title = $_.businessTitle
    $managerUsername = $_.managerUsername
    $managerDisplayName = $_.managerLastName + ", " + $_.managerFirstName
    $managerEmail = $_.managerEmail
    Get-ManagerOU
    $company = $_.company
    $department = $_.department
    $location = $_.location
    $empStatus = $_.timeType
    $rehire = $_.isRehire

    # 30 days prior to today's date (used for duplicate username email logic below)
    $When = ((Get-Date).AddDays(-30)).Date

    # Checking if user account already exists in XYZAM or Central DCs, if so, assign their DC to the userDC variable
    if ([bool](Get-ADUser -Filter "sAMAccountName -eq '$sam'" -Server $alphaDC)) {
        $userDC = $alphaDC
    } elseif ([bool](Get-ADUser -Filter "sAMAccountName -eq '$sam'" -Server $betaDC)) {
        $userDC = $betaDC
    } else {
        $userDC = $null
    }

    if ($userDC -ne $null) {
        # Retrieving the distinguished name of the user account that exists in Active Directory
        $userDN = (Get-ADUser -Filter "sAMAccountName -eq '$sam'" -Server $userDC).distinguishedName
        Write-Host "User's Distinguished Name is $($userDN), SAM Account Name is $($sam) and Domain Controller is $($userDC)" -ForegroundColor Green
        # Checking to see if the account is enabled
        if ([bool](Get-ADUser -Identity $userDN -Server $userDC).enabled) {
            if ($rehire -eq '1' -And [bool]((Get-ADUser -Identity $userDN -Server $userDC -properties Modified | select -ExpandProperty Modified ) -ge $When)) {
                # User is a rehire and was modified in the past 30 days, skipping this user account creation as the report includes the same account to be processed daily for at least 14 days and possibly more.
                return
            } elseif ($rehire -eq '1') {
                # User is a rehire and was modified longer than 30 days ago. Generating email to inform Service Desk
                Write-ErrorReportEmailServiceDesk("$($sam) account is already enabled yet the report sent today by XYZSymplSystems@myworkday.com specified this user as a 'rehire'. `n For context, Workday supplies a 'username' field in the report that is not always associated directly with the Active Directory SAM Account Name, although it is a goal to have these usernames directly associated with each other. It is possible that the user that is enabled with the SAM of $($sam) has a different Workday username and that the username from Workday for which we are trying to re-onboard for the 'rehire' may have a different SAM account name than the one that Workday is looking for. Here are the steps which you should take to confirm that this is the correct user that is already enabled or if we need to take further action: `n 1. Look in Active Directory for the $($displayName) and see if you find two users that share the same name. If one of them is disabled, note the SAM account name of that account and note down the SAM of the other as well. `n 2. If there was only one account and it was enabled already, it is possible that this script may have run previously or someone manually re-enabled this user. If that is the case and you know that someone re-enabled the account, you can disregard this email and consider the account done. Otherwise, email the Workday admins and let them know what happened. `n 3. If step 1 is true and there was another disabled account, mention to workday that the username they provided most likely coinsided with the SAM account name of the enabled account that shares the same name as the person that we are trying to re-onboard (the disabled account). Let them know what the disabled account's SAM is and to update the report to match the SAM of the disabled account so that it gets reactivated appropriately. `n 4. You can wait for 8:15AM tomorrow for the script to run again with hopefully the new SAM updated in the report from Workday or you can manually run the powershell script located on the server along with editing the CSV yourself.")
            } elseif ($rehire -eq '0' -And [bool]((Get-ADUser -Identity $userDN -Server $userDC -properties created | select -ExpandProperty created) -ge $When)) {
                # User is a rehire and was created in the past 30 days, skipping this user account creation as the report includes the same account to be processed daily for at least 14 days and possibly more.
                return
            } elseif ($rehire -eq '0') {
                # User is NOT a rehire but the SAM exists in the system and is enabled so this is a different user. Need to let Service Desk investigate whether if disabled, to delete the old account
                # so that this new account gets that username or if it's an enabled account, service desk notifies Workday to provide another username!
                Write-ErrorReportEmailServiceDesk("$($sam) account is already enabled yet the report sent today by XYZSymplSystems@myworkday.com specified this user is NOT a 'rehire'. `n For context, Workday supplies a 'username' field in the report that is not always associated directly with the Active Directory SAM Account Name, although it is a goal to have these usernames directly associated with each other. It is possible that the user that is enabled with the SAM of $($sam) has a different Workday username and that the username from Workday included in the report for which we are trying to onboard for the 'new hire' is already in use by the enabled user account as their SAM. Here are the steps which you should take to confirm that this is the correct user that is already enabled or if we need to take further action: `n 1. Look in Active Directory for the $($sam) and see if you find that that user is enabled and is different than the one that we are trying to onboard (i.e., different title, department, etc.). If the user is different, notify the Workday admins now and let them know that they need to supply another SAM account name for the new hire or adjust the Workday username of the current enabled user to match the SAM. `n 2. If there was only one account and it was enabled already and you believe it is the same account that you are trying to onboard (i.e. same title, department, etc), it is possible that this script may have run previously or someone manually re-enabled this user. If that is the case and you know that someone re-enabled the account, you can disregard this email and consider the account done. Otherwise, email the Workday admins and let them know what happened. `n 3. You can wait for 8:15AM tomorrow for the script to run again with hopefully the new SAM updated in the report from Workday or you can manually run the powershell script located on the server along with editing the CSV yourself.")
            }
        } elseif ([bool](Get-ADUser -Identity $userDN -Server $userDC).enabled -eq $false) {
            if ($rehire -eq '1') {
                Reactivate-UserMailbox
            } else {
                Write-ErrorReportEmailServiceDesk("$($sam) account exists in Active Directory and is a disabled account yet the report sent today by XYZSymplSystems@myworkday.com specified this user is NOT a 'rehire'. `n For context, Workday supplies a 'username' field in the report that is not always associated directly with the Active Directory SAM Account Name, although it is a goal to have these usernames directly associated with each other. It is possible that the user that is disabled with the SAM of $($sam) may need to be deleted so that the new hire can take this username (on consultation of manager) or that you need to let Workday know to provide another Workday username so that we can give the new hire a different SAM account name. Here are the steps which you should take: `n 1. Look in Active Directory for the $($sam) and see if you find that that user is disabled and is different than the one that we are trying to onboard (i.e., different title, department, etc.). If the user is different, notify the Workday admins now and let them know that they need to supply another SAM account name for the new hire or let your manager know if we should delete the disabled account so that the username is used for the new hire. `n 2. You can wait for 8:15AM tomorrow for the script to run again with hopefully the new SAM updated in the report from Workday or you can manually run the powershell script located on the server along with editing the CSV yourself.")
            }
        }
    } elseif ($rehire -eq '1') {
        # Account does not exist in Active Directory but Workday wants us to re-onboard a disabled account?
        Write-ErrorReportEmailServiceDesk("$($sam) is listed as a rehire in the new hire report but the account does not exist in Active Directory. Locate the actual SamAccountName of the display name of this user and let Workday know that it is that username that needs to be listed in the report for the rehire to take effect if applicable.")
    } else {
        # Account does not exist in Active Directory, Creating a new one now.
        New-UserMailbox
    }

    # Clear all variables
    $firstName = $lastName = $alias = $sam = $displayName = $name = $userUPN = $title = $managerUsername = $OU = $company = $department = $location = $rehire = $empStatus = $managerDisplayName = $userDN = $userDC = $userProps = $userSuccess = $rehireSuccess = $null
}

# # Performing an Active Directory Azure sync
write-host "Step 4. Performing AD Azure Sync" -ForegroundColor Yellow
Start-AzureADSync

# # Remove all Sessions
Get-PSSession | Remove-PSSession
$365session | Remove-PSSession
$onPremExch | Remove-PSSession

Stop-Transcript