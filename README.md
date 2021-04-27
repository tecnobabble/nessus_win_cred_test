# Nessus Credentialed Readiness Check

This Powershell script is designed to be run on a supported (by Microsoft) Windows host.  It checks for the most common issues that will prevent successful credentialed scans by Nessus.  

## Notes
* This should be run with administrative privileges in the x64 Powershell console/construct.  
* No changes are made to the target system.  Review the output and manually make any changes required.  
* This script MUST BE EDITED to provide the usernames of the account(s) authorized to run the Nessus check.  
* This script may not identify all issues that prevent successful credentialed scans, but highlights the most common ones.  If you have suggestions for additional checks, please log an issue.  


## Important
This tool is not an officially supported Tenable project.

Use of this tool is subject to the terms and conditions identified below, and is not subject to any license agreement you may have with Tenable.

## License

GNU General Public License v3.0; see LICENSE
