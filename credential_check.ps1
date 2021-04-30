<#
.SYNOPSIS
This Powershell script is designed to be run on a supported (by Microsoft) Windows host. It checks for the most common issues that may prevent successful credentialed scans by Nessus.

.DESCRIPTION
This script checks for the following items:
 - Local Admin User/Group Requirements
 - Ensure Remote Shares are Available (Client or Server)
 - Windows Remote Registry Service Should be Enabled or Manual
 - Windows Server Service Must be Enabled
 - WMI Service Must be Enabled
 - Users must authenticate as themselves, not Guest
 - Minimum Windows Firewall Checks
   - Windows Management Instrumentation (DCOM-In)
   - Windows Management Instrumentation (WMI-In)
   - Windows Management Instrumentation (ASync-In)
   - File and Printer Sharing (SMB-In)
Windows 10 > 1709 Auth Issues (SPN Validation)
Symantec Endpoint Scan Blocking
UAC Remote Auth Token Validation

Note:
 - This should be run with administrative privileges in the x64 Powershell console/construct.
 - The PowerShell Execution Policies may have to be changed to allow the script to run
 - No changes are made to the target system. Review the output and manually make any changes required.
 - This script MUST BE EDITED to provide the usernames of the account(s) authorized to run the Nessus check.
 - This script may not identify all issues that prevent successful credentialed scans, but highlights the most common ones. If you have suggestions for additional checks, please log an issue.
 - This script may identify settings that do not need to be adjusted due to other system configurations. Where known, these details are called out in the notes of the check; please review them carefully.
 
This tool is not an officially supported Tenable project.

Use of this tool is subject to the terms and conditions identified in the license, and is not subject to any license agreement you may have with Tenable.

.PARAMETER ScanningAccounts
Specifies the scanning accounts being used. Can accept multiple values comma separated

.EXAMPLE
.\credential_check.ps1 -ScanningAccounts "vuln_scan"

Runs an assessment given the following account is authorized for vulnerability assessments:
Local User: "vuln_scan"

.EXAMPLE
.\credential_check.ps1 -ScanningAccounts "vuln_scan","DOMAIN\vuln_scan","DOMAIN\Vuln Scanning Group"

Runs an assessment given the following accounts are authorized for vulnerability assessments:
Local User: "vuln_scan"
Domain User: "DOMAIN\vuln_scan"
Domain User Group: "DOMAIN\Vuln Scanning Group"

.EXAMPLE
Push the output to a file so you have a standalone report.
.\credential_check.ps1 -ScanningAccounts "vuln_scan" *> Nessus_Credential_Check_Status.txt

.EXAMPLE
Run the script on a remote system. This assumes Remote PowerShell Management is configured properly and working.
Invoke-Command -ComputerName 203.0.113.5 -FilePath .\credential_check.ps1 -ScanningAccounts "vuln_scan"

.LINK
For more information, please see: https://github.com/tecnobabble/nessus_win_cred_test
#>

param([Parameter(ParameterSetName = 'Default')][array]$ScanningAccounts)

$ErrorActionPreference = 'stop'

$checks = @(
    @{
        check_type  = 'registry'
        description = 'Enable Remote File Shares - Server'
        reg_key     = 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
        reg_name    = 'AutoShareServer'
        reg_value   = 1
        options     = 'can_be_null'
        info        = "Remote file shares, like C$, and ADMIN$ are required for proper remote credentialed Nessus scans. These are
        enabled by default. Nessus can be configured to attempt to automatically enable these shares during the scan and 
        disable them when complete with the 'Enable Administrative Shares' feature in the scan policy; however this is not the 
        default setting."
        solution    = "Remove the 'AutoShareServer' registry key from the location below or change the value to '1'.  For 
        client systems, this key is 'AutoShareWks'.
      
      HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"
        see_also    = 'https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows
        https://support.microsoft.com/en-us/help/842715/overview-of-problems-that-may-occur-when-administrative-shares-are-mis'
    }
    @{
        check_type  = 'registry'
        description = 'Enable Remote File Shares - Client'
        reg_key     = 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
        reg_name    = 'AutoShareWks'
        reg_value   = 1
        options     = 'can_be_null'
        info        = "Remote file shares, like C$, and ADMIN$ are required for proper remote credentialed Nessus scans. These are enabled 
        by default. Nessus can be configured to attempt to automatically enable these shares during the scan and disable them 
        when complete with the 'Enable Administrative Shares' feature in the scan policy; however this is not the default 
        setting."
        solution    = "Remove the 'AutoShareWks' registry key from the location below or change the value to '1'. For server 
        systems, this key is 'AutoShareServer'.
      
      HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"
        see_also    = 'https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows
        https://support.microsoft.com/en-us/help/842715/overview-of-problems-that-may-occur-when-administrative-shares-are-mis'
    }
    @{
        check_type  = 'registry'
        description = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local 
        users authenticate as themselves'"
        reg_key     = 'Registry::HKEY_LOCAL_MACHINE\System\Currentcontrolset\Control\Lsa'
        reg_name    = 'ForceGuest'
        reg_value   = 0
        options     = 'can_not_be_null'
        info        = "This policy setting determines how network logons that use local accounts are authenticated. The Classic 
        option allows precise control over access to resources, including the ability to assign different types of access to 
        different users for the same resource. This must be set to Classic for Nessus to have appropriate permissions to 
        authenticate."
        solution    = "To establish the recommended configuration via GP, set the following UI path to Classic - local users 
        authenticate as themselves:
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and 
security model for local accounts"
        see_also    = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-sharing-and-security-model-for-local-accounts
        https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm'
    }
    @{
        check_type  = 'service'
        description = "'Windows Management Instrumentation' Service must be set to Automatic"
        serv_name   = 'Winmgmt'
        serv_status = 'Auto'
        info        = "The 'Windows Management Instrumentation' service enables WMI calls and is used for multiple plugin checks as well as essential Windows internals and must 
        be enabled."
        solution    = "To establish the recommended configuration via GP, set the 'Windows Management Instrumentation' service startup mode to Automatic:
    
    Computer Configuration\Windows Settings\Security Settings\System Services\Windows Management Insrumentation - Set the startup mode to Automatic"
        see_also    = 'https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm'
    }
    @{
        check_type  = 'service'
        description = "'Server' Service must be set to Automatic"
        serv_name   = 'LanmanServer'
        serv_status = 'Auto'
        info        = "The 'Server' service enables remote administrative access to the local system and must be enabled."
        solution    = "To establish the recommended configuration via GP, set the 'Server' service startup mode to Automatic:
    
    Computer Configuration\Windows Settings\Security Settings\System Services\Server - Set the startup mode to Automatic"
        see_also    = 'https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm'
    }
    @{
        check_type   = 'service'
        description  = "'Remote Registry' Service should be set to Automatic or Manual"
        serv_name    = 'RemoteRegistry'
        serv_status  = 'Auto'
        serv_status2 = 'Manual'
        info         = "The Remote Registry service should be enabled (it is disabled by default). It can be enabled to 'Automatic' for continuing audits or enabled as part of the scan policy. Using plugin IDs 42897 and 42898 (enabled in the scan policy), Nessus can enable the service just for the duration of the scan, however the service should not be 'Disabled' for this to function consistently across all Windows platforms."
        solution     = "To establish the recommended configuration via GP, set the 'Remote Registry' service startup mode to Automatic or Manual:
    Computer Configuration\Windows Settings\Security Settings\System Services\Server - Set the startup mode to Automatic or Manual"
        see_also     = 'https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm'    
    }
    @{
        check_type   = 'powershell'
        description  = 'Ensure the proper user/group is in the local Administrator user group.'
        ps_check     = '(Get-WMIObject Win32_Group -Filter "Name=''Administrators''").GetRelated("Win32_UserAccount") | Where-Object {$_.Domain -eq [Environment]::MachineName} | Select -exp Name; (Get-WMIObject Win32_Group -Filter "Name=''Administrators''").GetRelated("Win32_Group") | Where-Object {$_.Domain -eq [Environment]::MachineName} | Select -exp Name; (Get-WMIObject Win32_Group -Filter "Name=''Administrators''").GetRelated("Win32_UserAccount") | Where-Object {$_.Domain -ne [Environment]::MachineName} | Select -exp Caption; (Get-WMIObject Win32_Group -Filter "Name=''Administrators''").GetRelated("Win32_Group") | Where-Object {$_.Domain -ne [Environment]::MachineName} | Select -exp Caption'
        ps_result    = $ScanningAccounts
        info         = "To perform a successful remote authenticated scan, Nessus must use an account that is a member of the local Administrators group. The script MUST be edited to include the authorized administrator username or group."
        solution     = "Add the proper user to the local administrator group on the system either locally or via GP."
        see_also     = 'https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm'
    }
    @{
        check_type   = 'custom'
        description  = 'Windows 10 > 1709 - Server SPN Validation Enabled'
        info         = "On Windows 10 hosts, release 1709 and above, there have been reported issues with enabling Server SPN validation and credentialed Nessus scans."
        solution     = "There are several options to resolve, detailed in the Tenable Community link below.  Note that disabling SPN validation may be against hardening requirements of you environment and this is not a recommendation to resolve the issue."
        see_also     = "https://community.tenable.com/s/article/Authentication-Issues-for-Windows-10-Version-1709-and-above
        https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-server-spn-target-name-validation-level"
        custom_check = @(
            try { $SPN_Validation = (Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters -Name SMBServerNameHardeningLevel).SMBServerNameHardeningLevel }
            catch { $SPN_Validation = 0 }
            $OS_Name = (gcim Win32_OperatingSystem | Select-Object Name).Name
            $OS_Release = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" -Name ReleaseID).ReleaseID
            If ((( $SPN_Validation -eq 1) -Or ($SPN_Validation -eq 2)) -And ($OS_Name -Match "Windows 10") -And ($OS_Release -ge 1709) ) {"1"}
            Else {"0"}
            )
    }
    @{
        check_type   = 'custom'
        description  = "Is Symantec Endpoint Protection Installed?"
        info         = "Symantec Endpoint Protection appears to be installed.  Note that in it's default configuration, it may interfere with remote credentialed Nessus Scans."
        solution     = "Review the Tenable Community link below for instructions on how to resolve this potential issue."
        see_also     = "https://community.tenable.com/s/article/Symantec-Endpoint-Protection-interfering-with-Nessus-authenticated-scans"
        custom_check = @(
            $Is_SEP_Installed = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object -FilterScript {$_.DisplayName -Match 'Symantec Endpoint Protection'}).DisplayName
            If ($Is_SEP_Installed -Match "Symantec Endpoint Protection") {"1"}
            Else {"0"}
            )
    }
    @{
        check_type   = 'firewall'
        description  = "Windows Firewall Configuration"
        custom_check = @(
            $FWService     = (Get-Service | ?{$_.Name -eq "mpssvc"});
            $FWDcomInName  = "Windows Management Instrumentation (DCOM-In)"
            $FWWmiInName   = "Windows Management Instrumentation (WMI-In)"
            $FWASyncInName = "Windows Management Instrumentation (ASync-In)"
            $FWSMBInName   = "File and Printer Sharing (SMB-In)"
            $fwIssueFound  = 0
            $FWService | %{
            If($_.Status -eq "Running"){ 
                $FWProfiles = (Get-NetFirewallProfile);
                $FWProfiles | %{
                If($_.Enabled -eq 1){
                    $FWDcomInStatus    = get-netfirewallrule -DisplayName $FWDcomInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
                    $FWDcomInAllStatus = get-netfirewallrule -DisplayName $FWDcomInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
                    If(!$FWDcomInStatus -And !$FWDcomInAllStatus ) {"The $($_.Name) profile doesn't have $FWDcomInName enabled. This is required."; $fwIssueFound = 1}
                    
                    $FWWmiInStatus     = get-netfirewallrule -DisplayName $FWWmiInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
                    $FWWmiInAllStatus  = get-netfirewallrule -DisplayName $FWWmiInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
                    If(!$FWWmiInStatus -And !$FWWmiInAllStatus) {"The $($_.Name) profile doesn't have $FWWmiInName enabled. This is required."; $fwIssueFound = 1}
                    
                    $FWASyncInStatus    = get-netfirewallrule -DisplayName $FWASyncInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
                    $FWASyncInAllStatus = get-netfirewallrule -DisplayName $FWASyncInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
                    If(!$FWASyncInStatus -And !$FWASyncInAllStatus) {"The $($_.Name) profile doesn't have $FWASyncInName enabled. This is required."; $fwIssueFound = 1}
                    
                    $FWSMBInStatus     = get-netfirewallrule -DisplayName $FWSMBInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
                    $FWSMBInAllStatus  = get-netfirewallrule -DisplayName $FWSMBInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
                    If(!$FWSMBInStatus -And !$FWSMBInAllStatus) {Write-Host "The $($_.Name) profile doesn't have $FWSMBInName enabled. This is required."; $fwIssueFound = 1}
                }
                #Else{
                #    Write-Host "The Windows Firewall $($_.Name) profile is disabled; skipping checks."
                #} 
                }
                If($fwIssueFound -ne 1 ) {Write-Host "No changes needed. Correct configuration." }
                Else {Write-Host "Note: This is auditing the minimum required built-in firewall rules as described in the documentation below. 
It does not check for custom rules or third-party firewall configurations. As such, the results above should 
be validated with the action taken to allow Nessus through the local firewall."
                    Write-Host 
                    Write-Host "https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm"}
            }
            Else{
                Write-Host "The $($_.DisplayName) service is stopped; skipping checks."
                }
            }
            )
    }
    @{
        check_type   = 'custom'
        description  = "LocalAccountTokenFilterPolicy (UAC Only)"
        info         = "If UAC is enabled, then disable it for remotely authenticated administrators."
        solution     = "Windows User Account Control (UAC) must be disabled (not recommended for Domain member servers), or a specific registry setting should be changed to allow remote admin user command execution under certain circumstances.
        
        With UAC enabled, when a user in another domain is a member of the Administrators group on the local computer, the user cannot connect to the local computer remotely with Administrator privileges. By default, remote connections from other domains run with only standard user privilege tokens. However, you can use the LocalAccountTokenFilterPolicy registry entry to change the default behavior and allow remote users who are members of the Administrators group to run with Administrator privileges.  This setting may not be necessary for domain bound systems where the authenticating remote account is part of the same domain.
      
        For systems that are not domain bound, this setting (LocalAccountTokenFilterPolicy) is required to allow local administrator accounts to elevate permissions remotely.
      
        To turn off UAC completely, open the Control Panel, select User Accounts and then set Turn User Account Control to Off.
      
        Alternatively, you can add a new registry DWORD named LocalAccountTokenFilterPolicy and set its value to '1'. This key must be created in the registry at the following location: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy"
        see_also     = "https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm,
        https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows,
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7,
        https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings"
        custom_check = @(
            try { $UAC_Enabled = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA).EnableLUA }
            catch { $UAC_Enabled = 0 }
            try { $UAC_Remote_Admin = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy).LocalAccountTokenFilterPolicy }
            catch { $UAC_Remote_Admin = 0 }
            If ((( $UAC_Enabled -eq 1) -And ($UAC_Remote_Admin -ne 1))) {"1"}
            Else {"0"}
            )
    }
)

function Compare-TENBFirewall {
    Invoke-Command -ScriptBlock {$check.custom_check}
}

function Compare-TENBCustom {
    $Result = Invoke-Command -ScriptBlock {$check.custom_check}
    If ($Result -eq 0) {Write-Host "No changes needed. Correct configuration."}
    Else {
            Write-Warning -Message "$warning_message"
    }
}

function Compare-TENBPowerShell {
    Try { $Result = Invoke-Expression $check.ps_check }
    Catch
     { Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
     
     $warning_message"
     Write-Warning -Message "The current status is `"$Result`""     }
    Finally { 
        $good_check = 0
        Foreach ($i in $check.ps_result)
        {
            $ei = [regex]::Escape($i)
            If ($Result -Match $ei) {Write-Host "$i is configured correctly."; $good_check = 1}
        }
        Write-Host ""
        If ($good_check -eq 1) {Write-Host "No changes needed. Correct configuration."}
        Else {
            Write-Warning -Message "$warning_message"
            Write-Warning -Message "The current status is `"$Result`""
            Write-Warning -Message "The correct setting should be one of:"
            Write-Host ""
            Write-Host ($check.ps_result | Out-String) -ForegroundColor yellow -BackgroundColor black
        }
    }
}

function Compare-TENBRegistry {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $registryPath,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $keyName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $keyValue
    )
    $good_check = 0
    Try { $Result = (Get-ItemProperty $registryPath -Name $keyName).$keyName }
    Catch [System.Management.Automation.PSArgumentException]
     { If ($($check.options) -eq 'can_be_null') {Write-Host "No changes needed. Correct configuration."; $good_check = 1; Return }
     Else { Write-Warning -Message "$warning_message" Write-Warning -Message "The current status is `"$Result`""; Continue }}
    Catch [System.Management.Automation.ItemNotFoundException]
     { Write-Warning -Message "$warning_message" Write-Warning -Message "The current status is `"$Result`""; Continue }
    Catch
     { Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
     
     $warning_message"
     Write-Warning -Message "The current status is `"$Result`""     }
    Finally { 
        If ($Result -eq $($check.reg_value)) {Write-Host "No changes needed. Correct configuration."}
        Elseif ($Result -ne $($check.reg_value) -and ($good_check -ne 1)) {Write-Warning -Message "$warning_message"; Write-Warning -Message "The current status is `"$Result`""}
    }
}

function Compare-TENBService {
    Try { $Result = (Get-WmiObject -Query "Select StartMode from Win32_Service Where Name='$($check.serv_name)'").StartMode}
    Catch { 
     "$Result"
     Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
     
     $warning_message"
     Write-Warning -Message "The current status is `"$Result`""}
    Finally {        
        If ($Result -eq $($check.serv_status)) {Write-Host "No changes needed. Correct configuration."}
        Elseif ($($check.serv_status2))
            {If ($Result -eq $($check.serv_status2)) {Write-Host "No changes needed. Correct configuration."} 
            Else 
            {Write-Warning -Message "$warning_message"
            Write-Warning -Message "The current status is `"$Result`""}}
        Else 
            {Write-Warning -Message "$warning_message"
            Write-Warning -Message "The current status is `"$Result`""}
    }
}

#####  Start the actual walkthrough and checks
$local_host = [Environment]::MachineName
$local_domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
Write-Host "Report for $local_host, part of $local_domain"
Write-Host

foreach ($check in $checks)
{
    $warning_message = "The check for `"$($check.description)`" failed.
    
    $($check.info)
    
    To Fix:
    $($check.solution)
    
    For more information:
    $($check.see_also)
    "
    Write-Host "--------------------------------------------------------"
    Write-Host "Checking `"$($check.description)`""
    Write-Host

    Switch ($check.check_type)
    {
        'registry' {Compare-TENBRegistry $check.reg_key $check.reg_name $check.reg_value}
        'service' {Compare-TENBService}
        'powershell' {Compare-TENBPowerShell}
        'custom' {Compare-TENBCustom}
        'firewall' {Compare-TENBFirewall}
    }#end Switch check.check_type
    Write-Host "--------------------------------------------------------"
    Write-Host
}#end foreach check in checks
