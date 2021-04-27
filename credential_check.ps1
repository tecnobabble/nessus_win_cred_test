

####
# !!! THIS MUST BE DONE TO ENSURE ACCURATE VALIDATION !!!
#
# Define the scanning accounts being used.  If any of the defined accounts/groups are in the local Administrators group, the check will pass and
# and note which accounts are present.  If none of the accounts are present, the check will fail.
#
# Examples:
# Local User: "vuln_scan"
# Domain User: "DOMAIN\vuln_scan"
# Domain User Group: "DOMAIN\Vuln Scanning Group"
#
####

# Edit the accounts in the line below.
$Scanning_Accounts = "vuln_scan","DOMAIN\vuln_scanner","DOMAIN\Vuln Scanning Group"


# DO NOT EDIT BELOW THIS POINT
###################################3
$ErrorActionPreference = "stop"

$checks = @(
	@{
		check_type 	= 'registry'
		description = "Enable Remote File Shares - Server"
		reg_key 	= 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
		reg_name 	= 'AutoShareServer'
		reg_value 	= 1
		options 	= 'can_be_null'
		info 		= "Remote file shares, like C$, and ADMIN$ are required for proper remote credentialed Nessus scans. These are
		enabled by default. Nessus can be configured to attempt to automatically enable these shares during the scan and 
		disable them when complete with the 'Enable Administrative Shares' feature in the scan policy; however this is not the 
		default setting."
		solution 	= "Remove the 'AutoShareServer' registry key from the location below or change the value to '1'.  For 
		client systems, this key is 'AutoShareWks'.
      
      HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"
		see_also 	= "https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows
		https://support.microsoft.com/en-us/help/842715/overview-of-problems-that-may-occur-when-administrative-shares-are-mis"
	}
	@{
		check_type	= 'registry'
		description = "Enable Remote File Shares - Client"
		info        = "Remote file shares, like C$, and ADMIN$ are required for proper remote credentialed Nessus scans. These are enabled 
		by default. Nessus can be configured to attempt to automatically enable these shares during the scan and disable them 
		when complete with the 'Enable Administrative Shares' feature in the scan policy; however this is not the default 
		setting."
		solution 	= "Remove the 'AutoShareWks' registry key from the location below or change the value to '1'. For server 
		systems, this key is 'AutoShareServer'.
      
      HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"
		see_also 	= "https://community.tenable.com/s/article/Troubleshooting-Credential-scanning-on-Windows
		https://support.microsoft.com/en-us/help/842715/overview-of-problems-that-may-occur-when-administrative-shares-are-mis"
		reg_name    = "AutoShareWks"
		reg_key    	= "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters"
		reg_value 	= 1
		options  	= 'can_be_null'
	}
	@{
		check_type  = 'registry'
		description = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local 
		users authenticate as themselves'"
		info  		= "This policy setting determines how network logons that use local accounts are authenticated. The Classic 
		option allows precise control over access to resources, including the ability to assign different types of access to 
		different users for the same resource. This must be set to Classic for Nessus to have appropriate permissions to 
		authenticate."
		solution    = "To establish the recommended configuration via GP, set the following UI path to Classic - local users 
		authenticate as themselves:
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and 
security model for local accounts"
		see_also    = "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-sharing-and-security-model-for-local-accounts
		https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm"
		reg_name   	= "ForceGuest"
		reg_key     = "Registry::HKEY_LOCAL_MACHINE\System\Currentcontrolset\Control\Lsa"
		reg_value   = 0
		options    	= 'can_not_be_null'
	}
	@{
		check_type  = 'service'
		description = "'Windows Management Instrumentation' Service must be set to Automatic"
		info     	= "The 'Windows Management Instrumentation' service enables WMI calls and is used for multiple plugin checks as well as essential Windows internals and must 
		be enabled."
		solution  	= "To establish the recommended configuration via GP, set the 'Windows Management Instrumentation' service startup mode to Automatic:
	
	Computer Configuration\Windows Settings\Security Settings\System Services\Windows Management Insrumentation - Set the startup mode to Automatic"
		see_also    = "https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm"
		
		serv_status = "Auto"
		serv_name  	= "Winmgmt"
	}
	@{
		check_type  = 'service'
		description = "'Server' Service must be set to Automatic"
		info     	= "The 'Server' service enables remote administrative access to the local system and must be enabled."
		solution  	= "To establish the recommended configuration via GP, set the 'Server' service startup mode to Automatic:
	
	Computer Configuration\Windows Settings\Security Settings\System Services\Server - Set the startup mode to Automatic"
		see_also 	= "https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm"
		serv_status = "Auto"
		serv_name  	= "LanmanServer"
	}
	@{
		check_type  = 'service'
		description = "'Remote Registry' Service should be set to Automatic or Manual"
		info      	= "The Remote Registry service should be enabled (it is disabled by default). It can be enabled to 'Automatic' for continuing audits or enabled as part of the scan policy. Using plugin IDs 42897 and 42898 (enabled in the scan policy), Nessus can enable the service just for the duration of the scan, however the service should not be 'Disabled' for this to function consistently across all Windows platforms."
		solution    = "To establish the recommended configuration via GP, set the 'Remote Registry' service startup mode to Automatic or Manual:
	Computer Configuration\Windows Settings\Security Settings\System Services\Server - Set the startup mode to Automatic or Manual"
		see_also   	= "https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm"
		serv_status = "Auto"
		serv_status2 = "Manual"
		serv_name   = "RemoteRegistry"
		
	}
	@{
		check_type  = 'powershell'
		description = "Ensure the proper user/group is in the local Administrator user group."
		info      	= "To perform a successful remote authenticated scan, Nessus must use an account that is a member of the local Administrators group. This script MUST BE EDITED to include the authorized administrator username or group."
		solution    = "Add the proper user to the local administrator group on the system either locally or via GP."
		see_also   	= "https://docs.tenable.com/nessus/Content/EnableWindowsLoginsForLocalAndRemoteAudits.htm"
		ps_check 	= '(Get-WMIObject Win32_Group -Filter "Name=''Administrators''").GetRelated("Win32_UserAccount").Name'
		ps_result	= $Scanning_Accounts
	}
	@{
		check_type  = 'custom'
		description = "Windows 10 > 1709 - Server SPN Validation Enabled"
		info      	= "On Windows 10 hosts, release 1709 and above, there have been reported issues with enabling Server SPN validation and credentialed Nessus scans."
		solution    = "There are several options to resolve, detailed in the Tenable Community link below.  Note that disabling SPN validation may be against hardening requirements of you environment and this is not a recommendation to resolve the issue."
		see_also   	= "https://community.tenable.com/s/article/Authentication-Issues-for-Windows-10-Version-1709-and-above
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
		check_type  = 'custom'
		description = "Is Symantec Endpoint Protection Installed?"
		info      	= "Symantec Endpoint Protection appears to be installed.  Note that in it's default configuration, it may interfere with remote credentialed Nessus Scans."
		solution    = "Review the Tenable Community link below for instructions on how to resolve this potential issue."
		see_also   	= "https://community.tenable.com/s/article/Symantec-Endpoint-Protection-interfering-with-Nessus-authenticated-scans"
		custom_check = @(
			$Is_SEP_Installed = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object -FilterScript {$_.DisplayName -Match 'Symantec Endpoint Protection'}).DisplayName
			If ($Is_SEP_Installed -Match "Symantec Endpoint Protection") {"1"}
			Else {"0"}
			)
	}
	@{
		check_type  = 'firewall'
		description = "Windows Firewall Configuration"
		custom_check = @(
			$FWService = (Get-Service | ?{$_.Name -eq "mpssvc"});
			$FWDcomInName = "Windows Management Instrumentation (DCOM-In)"
			$FWWmiInName = "Windows Management Instrumentation (WMI-In)"
			$FWASyncInName = "Windows Management Instrumentation (ASync-In)"
			$FWSMBInName = "File and Printer Sharing (SMB-In)"
			$fwIssueFound = 0
			$FWService | %{
			If($_.Status -eq "Running"){ 
				$FWProfiles = (Get-NetFirewallProfile);
				$FWProfiles | %{
				If($_.Enabled -eq 1){
					$FWDcomInStatus = get-netfirewallrule -DisplayName $FWDcomInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
					$FWDcomInAllStatus = get-netfirewallrule -DisplayName $FWDcomInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
					If(!$FWDcomInStatus -And !$FWDcomInAllStatus ) {"The $($_.Name) profile doesn't have $FWDcomInName enabled. This is required."; $fwIssueFound = 1}
					
					$FWWmiInStatus = get-netfirewallrule -DisplayName $FWWmiInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
					$FWWmiInAllStatus = get-netfirewallrule -DisplayName $FWWmiInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
					If(!$FWWmiInStatus -And !$FWWmiInAllStatus) {"The $($_.Name) profile doesn't have $FWWmiInName enabled. This is required."; $fwIssueFound = 1}
					
					$FWASyncInStatus = get-netfirewallrule -DisplayName $FWASyncInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
					$FWASyncInAllStatus = get-netfirewallrule -DisplayName $FWASyncInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
					If(!$FWASyncInStatus -And !$FWASyncInAllStatus) {"The $($_.Name) profile doesn't have $FWASyncInName enabled. This is required."; $fwIssueFound = 1}
					
					$FWSMBInStatus = get-netfirewallrule -DisplayName $FWSMBInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Profile -eq $($_.Name) | Where Action -Match Allow | Where Enabled -eq True
					$FWSMBInAllStatus = get-netfirewallrule -DisplayName $FWSMBInName -PolicyStore ActiveStore | Where Direction -eq Inbound | Where Action -Match Allow | Where Enabled -eq True
					If(!$FWSMBInStatus -And !$FWSMBInAllStatus) {"The $($_.Name) profile doesn't have $FWSMBInName enabled. This is required."; $fwIssueFound = 1}
				}
				#Else{
				#	"The Windows Firewall $($_.Name) profile is disabled; skipping checks."
				#} 
				}
				If($fwIssueFound -ne 1 ) { "No changes needed. Correct configuration." }
				Else {"Note: This is auditing the minimum required built-in firewall rules as described in the documentation below. 
It does not check for custom rules or third-party firewall configurations. As such, the results above should 
be validated with the action taken to allow Nessus through the local firewall."
					""
					"https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm"}
			}
			Else{
				"The $($_.DisplayName) service is stopped; skipping checks."
				}
			}

			)
	}
)


function Compare-TENBFirewall {
	Invoke-Command -ScriptBlock {$check.custom_check}
}

function Compare-TENBCustom {
	$Result = Invoke-Command -ScriptBlock {$check.custom_check}
	If ($Result -eq 0) {"No changes needed. Correct configuration."}
	Else {
			Write-Warning -Message "$warning_message"
	}
}

function Compare-TENBPowerShell {
	Try { $Result = Invoke-Expression $check.ps_check }
	Catch
	 { Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
	 
	 $warning_message"
	 Write-Warning -Message "The current status is `"$Result`""	 }
	Finally { 
	    $good_check = 0
	    Foreach ($i in $check.ps_result)
		{
			$ei = [regex]::Escape($i)
			If ($Result -Match $ei) {Write-Host "$i is configured correctly."; $good_check = 1}
			#Else {"$i is not configured."}
		}
		Write-Host ""
		If ($good_check -eq 1) {"No changes needed. Correct configuration."}
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
	 { If ($($check.options) -eq 'can_be_null') {"No changes needed. Correct configuration."; $good_check = 1; Return }
	 Else { Write-Warning -Message "$warning_message" Write-Warning -Message "The current status is `"$Result`""; Continue }}
	Catch [System.Management.Automation.ItemNotFoundException]
	 { Write-Warning -Message "$warning_message" Write-Warning -Message "The current status is `"$Result`""; Continue }
	Catch
	 { Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
	 
	 $warning_message"
	 Write-Warning -Message "The current status is `"$Result`""	 }
	Finally { 
		If ($Result -eq $($check.reg_value)) {"No changes needed. Correct configuration."}
		Elseif ($Result -ne $($check.reg_value) -and ($good_check -ne 1)) {Write-Warning -Message "$warning_message"; Write-Warning -Message "The current status is `"$Result`""}
	}
}

function Compare-TENBService {
	Try { $Result = (Get-WmiObject -Query "Select StartMode from Win32_Service Where Name='$($check.serv_name)'").StartMode}
	Catch
	 { 
	 "$Result"
	 Write-Warning -Message "Something really weird happened.  You probably need to both fix this (below) and notify the dev of this script. 
	 
	 $warning_message"
	 Write-Warning -Message "The current status is `"$Result`""}
	Finally {		
		If ($Result -eq $($check.serv_status)) {"No changes needed. Correct configuration."}
		Elseif ($($check.serv_status2))
			{If ($Result -eq $($check.serv_status2)) {"No changes needed. Correct configuration."} 
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
Write-Host ""


foreach ($check in $checks){
	$warning_message = "The check for `"$($check.description)`" failed.
	
	$($check.info)
	
	To Fix:
	$($check.solution)
	
	For more information:
	$($check.see_also)
	"
	Write-Host "--------------------------------------------------------"
	Write-Host "Checking `"$($check.description)`""
	Write-Host ""
	if ($check.check_type -eq 'registry') {
		Compare-TENBRegistry $check.reg_key $check.reg_name $check.reg_value
		}
	Elseif ($check.check_type -eq 'service') {
		Compare-TENBService
		}
	Elseif ($check.check_type -eq 'powershell') {
		Compare-TENBPowerShell
		}
	Elseif ($check.check_type -eq 'custom') {
		Compare-TENBCustom
		}
	Elseif ($check.check_type -eq 'firewall') {
		Compare-TENBFirewall
		}
	Write-Host "--------------------------------------------------------"
	Write-Host ""
}
