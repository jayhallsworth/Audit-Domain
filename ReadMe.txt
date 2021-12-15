<#
.NAME
  Audit-Domain

.SYNOPSIS

  Performs an audit on an Active Directory Domain, DNS and DHCP and reports key configuration settings in to a main text file and several supporting files.

.SYNTAX
  This script is intended to be run on a Domain Controller in a PowerShell window
  PowerShell should be run as Administrator as modules will need to be loaded
  It is recomended that the script file (and its supporting file) be coppied to a folder on C-Drive called PS (MD C:\PS)
  Change the PowerShell Working Directory to this folder (CD C:\PS)

  In preparation, the "OtherDNS-servers.txt" file should be edited and the hostname of all other DNS Servers in the domain be listed, one per line

  .\Audit-Domain.ps1


.DESCRIPTION

  .




.PARAMETER <Parameter_Name>

  .



.INPUTS

  Supporting Input Files: 
	 - Get-NoSettingsGPO.ps1
	 - Get-ServerDNS.ps1
	 - Get-UnlinkedGPO.ps1
	 - OtherDNS-servers.txt - Add hostnames or IP Addresses of other DNS Servers in the organisation



.OUTPUTS
	Output Files are stored in a Subfolder called DomainAudit_Date
	The main output file is called "DomainAudit_ClientName_Date.txt"
	Several other supporting Text / CSV Files are created, including:
	 - ActiveUsers.txt
	 - PasswordNeverExpires.txt
	 - SecurityGroups.txt
	 - dcdiag_SERVERNAME.txt (Multiple Files - 1 Per DC)
	 - GPOReportsAll.html
	 - DNS_Server_FullDetails.txt




.NOTES

  Author:         Jay Hallsworth
  Creation Date:  17th April 2018

  Version:        r2.0
  Editor:         Jay Hallsworth
  Modified Date:  9th March 2019
  Purpose/Change: Code Review & Tidy
  

.EXAMPLE

  .\Audit-Domain.ps1

#>
