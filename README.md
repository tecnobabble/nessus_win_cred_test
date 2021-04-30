# Nessus Credentialed Readiness Check

This Powershell script is designed to be run on a supported (by Microsoft) Windows host.  It checks for the most common issues that may prevent successful credentialed scans by Nessus.  

## Notes
* This should be run with administrative privileges in the x64 Powershell console/construct.  
* The [PowerShell Execution Policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1) may have to be changed to allow the script to run   
* No changes are made to the target system.  Review the output and manually make any changes required.  
* You must pass the usernames of the account(s) authorized to run the Nessus check in order to run the assessment.
    * If a user/group is nested, pass the top level group expected to be on the target system.   
* This script may not identify all issues that prevent successful credentialed scans, but highlights the most common ones.  If you have suggestions for additional checks, please log an issue. 
* This script may identify settings that do not need to be adjusted due to other system configurations. Where known, these details are called out in the notes of the check; please review them carefully.  

## Included Checks
* Local Admin User/Group Requirements  
* Ensure Remote Shares are Available (Client or Server)   
* Windows Remote Registry Service Should be Enabled or Manual  
* Windows Server Service Must be Enabled  
* WMI Service Must be Enabled  
* Users must authenticate as themselves, not Guest  
* Minimum Windows Firewall Checks  
    * Windows Management Instrumentation (DCOM-In)  
    * Windows Management Instrumentation (WMI-In)  
    * Windows Management Instrumentation (ASync-In)  
    * File and Printer Sharing (SMB-In)  
* Windows 10 > 1709 Auth Issues (SPN Validation)  
* Symantec Endpoint Scan Blocking
* UAC Remote Auth Token Validation  

## Usage
* Get help (similar to this doc)  
`get-help .\credential_check.ps1 -full`

* Open an administrative PowerShell prompt and run the 'credential_check.ps1' script locally. This will output the result to the PowerShell prompt.  
`.\credential_check.ps1 -ScanningAccounts "vuln_scan"`

* Runs an assessment given the following accounts are authorized for vulnerability assessments:  
    * Local User: "vuln_scan"  
    * Domain User: "DOMAIN\vuln_scan"  
    * Domain User Group: "DOMAIN\Vuln Scanning Group"  

    `.\credential_check.ps1 -ScanningAccounts "vuln_scan","DOMAIN\vuln_scan","DOMAIN\Vuln Scanning Group"`

* Push the output to a file so you have a standalone report.  
`.\credential_check.ps1 -ScanningAccounts "vuln_scan" *> Nessus_Credential_Check_Status.txt`

* Open an administrative PowerShell prompt and run the script on a remote system.  This assumes [Remote PowerShell Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) is configured properly and working.  
`Invoke-Command -ComputerName 203.0.113.5 -FilePath .\credential_check.ps1 -ScanningAccounts "vuln_scan"`

## Important
This tool is not an officially supported Tenable project.

Use of this tool is subject to the terms and conditions identified below, and is not subject to any license agreement you may have with Tenable.

## License

GNU General Public License v3.0; see LICENSE
